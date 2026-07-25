use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::stream::StreamExt;
use rand::Rng;

use crate::aethernoize::AetherNoizeConfig;
use crate::error::{AetherError, Result};
use crate::prober::IpScan;
use crate::wireguard;

#[derive(Debug, Clone, Copy)]
pub struct WgProbeResult {
    pub ip: IpAddr,
    pub port: u16,
    pub rtt: Duration,
}

#[derive(Debug, Clone, Copy)]
struct ConfirmedWgResult {
    probe: WgProbeResult,
    successes: usize,
    attempts: usize,
    score: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WgScanMode {
    Turbo,
    Balanced,
    Thorough,
    Stealth,
    Ironclad,
}

impl WgScanMode {
    pub fn parse(value: &str) -> WgScanMode {
        match value.trim().to_lowercase().as_str() {
            "turbo" | "fast" => WgScanMode::Turbo,
            "thorough" | "deep" | "pro" => WgScanMode::Thorough,
            "stealth" | "quiet" => WgScanMode::Stealth,
            "ironclad" | "real" | "verify" | "guaranteed" => WgScanMode::Ironclad,
            _ => WgScanMode::Balanced,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            WgScanMode::Turbo => "turbo",
            WgScanMode::Balanced => "balanced",
            WgScanMode::Thorough => "thorough",
            WgScanMode::Stealth => "stealth",
            WgScanMode::Ironclad => "ironclad",
        }
    }

    fn strategy(&self) -> WgStrategy {
        match self {
            WgScanMode::Turbo => WgStrategy {
                concurrency: 16,
                per_probe_timeout: Duration::from_secs(5),
                overall_deadline: Duration::from_secs(25),
                settle_after_target: Duration::ZERO,
                target_successes: 1,
                early_exit_first: true,
                sample_per_cidr: 32,
                finalists: 1,
                finalist_attempts: 1,
                include_compatibility: false,
                compatibility_ports: 0,
            },
            WgScanMode::Balanced => WgStrategy {
                concurrency: 12,
                per_probe_timeout: Duration::from_secs(7),
                overall_deadline: Duration::from_secs(70),
                settle_after_target: Duration::from_secs(4),
                target_successes: 10,
                early_exit_first: false,
                sample_per_cidr: 72,
                finalists: 5,
                finalist_attempts: 3,
                include_compatibility: false,
                compatibility_ports: 0,
            },
            WgScanMode::Thorough => WgStrategy {
                concurrency: 14,
                per_probe_timeout: Duration::from_secs(9),
                overall_deadline: Duration::from_secs(150),
                settle_after_target: Duration::from_secs(8),
                target_successes: 28,
                early_exit_first: false,
                sample_per_cidr: 160,
                finalists: 8,
                finalist_attempts: 3,
                include_compatibility: true,
                compatibility_ports: 12,
            },
            WgScanMode::Stealth => WgStrategy {
                concurrency: 3,
                per_probe_timeout: Duration::from_secs(10),
                overall_deadline: Duration::from_secs(120),
                settle_after_target: Duration::from_secs(8),
                target_successes: 6,
                early_exit_first: false,
                sample_per_cidr: 48,
                finalists: 4,
                finalist_attempts: 3,
                include_compatibility: false,
                compatibility_ports: 0,
            },
            WgScanMode::Ironclad => WgStrategy {
                concurrency: 8,
                per_probe_timeout: Duration::from_secs(10),
                overall_deadline: Duration::from_secs(150),
                settle_after_target: Duration::from_secs(6),
                target_successes: 12,
                early_exit_first: false,
                sample_per_cidr: 96,
                finalists: 4,
                finalist_attempts: 3,
                include_compatibility: true,
                compatibility_ports: 4,
            },
        }
    }
}

const WG_IRONCLAD_HTTP_TIMEOUT: Duration = Duration::from_secs(10);
const FAILED_CONFIRMATION_PENALTY: Duration = Duration::from_millis(250);

struct WgStrategy {
    concurrency: usize,
    per_probe_timeout: Duration,
    overall_deadline: Duration,
    settle_after_target: Duration,
    target_successes: usize,
    early_exit_first: bool,
    sample_per_cidr: usize,
    finalists: usize,
    finalist_attempts: usize,
    include_compatibility: bool,
    compatibility_ports: usize,
}

#[derive(Clone)]
pub struct WgProbe {
    pub private_key: Arc<[u8; 32]>,
    pub peer_public_key: Arc<[u8; 32]>,
    pub client_id: [u8; 3],
    pub local_ipv4: Ipv4Addr,
    pub aethernoize: AetherNoizeConfig,
    pub ports: Vec<u16>,
    pub ip: IpScan,
}

pub async fn hunt_best_wg_endpoint(
    probe: &WgProbe,
    mode: WgScanMode,
) -> Result<WgProbeResult> {
    hunt_best_wg_endpoint_excluding(probe, mode, None).await
}

pub async fn hunt_best_wg_endpoint_excluding(
    probe: &WgProbe,
    mode: WgScanMode,
    excluded_peer: Option<SocketAddr>,
) -> Result<WgProbeResult> {
    let mut strategy = mode.strategy();
    strategy.concurrency = crate::sysprofile::cap_concurrency(strategy.concurrency);
    let mut effective_ip = probe.ip;
    if probe.ip.want_v6() && !crate::prober::host_has_ipv6().await {
        if probe.ip.want_v4() {
            log::warn!("[-] host has no IPv6 route; falling back to IPv4-only scan");
            effective_ip = IpScan::V4;
        } else {
            return Err(AetherError::NoCleanEndpoint);
        }
    }

    let candidates = build_wg_candidates(&strategy, &probe.ports, effective_ip, excluded_peer);
    log::info!(
        "[*] wireguard scan mode={} ip={} candidates={} concurrency={} per_probe={:?} budget={:?} target={} finalists={} confirmations={} excluded_range={}",
        mode.label(),
        effective_ip.label(),
        candidates.len(),
        strategy.concurrency,
        strategy.per_probe_timeout,
        strategy.overall_deadline,
        strategy.target_successes,
        strategy.finalists,
        strategy.finalist_attempts,
        excluded_peer
            .map(|peer| endpoint_group(peer.ip()))
            .unwrap_or_else(|| "none".to_string()),
    );

    let stream = futures::stream::iter(candidates.into_iter().map(|(ip, port)| {
        verify_one_wg(
            probe,
            ip,
            port,
            strategy.per_probe_timeout,
            false,
        )
    }))
    .buffer_unordered(strategy.concurrency);
    tokio::pin!(stream);

    let deadline = Instant::now() + strategy.overall_deadline;
    let mut successful = Vec::new();
    let mut settle_until: Option<Instant> = None;

    loop {
        let effective_deadline = settle_until
            .map(|settle| settle.min(deadline))
            .unwrap_or(deadline);
        let remaining = effective_deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }

        tokio::select! {
            item = stream.next() => {
                match item {
                    None => break,
                    Some(None) => continue,
                    Some(Some(result)) => {
                        log::info!(
                            "[+] wg candidate ok {}:{} rtt={:?}",
                            result.ip,
                            result.port,
                            result.rtt
                        );
                        if strategy.early_exit_first {
                            return Ok(result);
                        }
                        successful.push(result);
                        if successful.len() >= strategy.target_successes
                            && settle_until.is_none()
                        {
                            if strategy.settle_after_target.is_zero() {
                                break;
                            }
                            settle_until = Some(Instant::now() + strategy.settle_after_target);
                        }
                    }
                }
            }
            _ = tokio::time::sleep(remaining) => break,
        }
    }

    if successful.is_empty() {
        return Err(AetherError::NoCleanEndpoint);
    }

    successful.sort_by_key(|result| result.rtt);
    let discovery_best = successful[0];
    let finalists = diverse_finalists(successful, strategy.finalists);
    let real_http_confirmation = mode == WgScanMode::Ironclad;
    let confirmation_concurrency = strategy.concurrency.min(finalists.len()).max(1);

    log::info!(
        "[*] confirming {} wireguard finalists with {} measurements each{}",
        finalists.len(),
        strategy.finalist_attempts,
        if real_http_confirmation {
            " using end-to-end HTTP"
        } else {
            ""
        }
    );

    let confirmations = futures::stream::iter(finalists.into_iter().map(|candidate| {
        confirm_candidate(
            probe,
            candidate,
            strategy.per_probe_timeout,
            strategy.finalist_attempts,
            real_http_confirmation,
        )
    }))
    .buffer_unordered(confirmation_concurrency);
    tokio::pin!(confirmations);

    let mut confirmed = Vec::new();
    while let Some(result) = confirmations.next().await {
        if let Some(result) = result {
            log::info!(
                "[+] wg finalist {}:{} median={:?} reliability={}/{} score={:?}",
                result.probe.ip,
                result.probe.port,
                result.probe.rtt,
                result.successes,
                result.attempts,
                result.score
            );
            confirmed.push(result);
        }
    }

    if confirmed.is_empty() {
        if real_http_confirmation {
            return Err(AetherError::NoCleanEndpoint);
        }
        return Ok(discovery_best);
    }

    confirmed.sort_by(|left, right| {
        left.score
            .cmp(&right.score)
            .then_with(|| left.probe.rtt.cmp(&right.probe.rtt))
            .then_with(|| right.successes.cmp(&left.successes))
    });
    let selected = confirmed[0];
    log::info!(
        "[+] best wg endpoint {}:{} median_rtt={:?} reliability={}/{} score={:?}",
        selected.probe.ip,
        selected.probe.port,
        selected.probe.rtt,
        selected.successes,
        selected.attempts,
        selected.score
    );
    Ok(selected.probe)
}

async fn confirm_candidate(
    probe: &WgProbe,
    candidate: WgProbeResult,
    timeout: Duration,
    attempts: usize,
    real_http: bool,
) -> Option<ConfirmedWgResult> {
    let attempts = attempts.max(1);
    let required_successes = attempts / 2 + 1;
    let mut samples = Vec::with_capacity(attempts);

    if !real_http {
        samples.push(candidate.rtt);
    }
    let start_attempt = if real_http { 0 } else { 1 };
    for _ in start_attempt..attempts {
        if let Some(result) =
            verify_one_wg(probe, candidate.ip, candidate.port, timeout, real_http).await
        {
            samples.push(result.rtt);
        }
    }

    if samples.len() < required_successes {
        return None;
    }

    samples.sort();
    let median = samples[samples.len() / 2];
    let jitter = samples
        .last()
        .copied()
        .unwrap_or(median)
        .saturating_sub(samples.first().copied().unwrap_or(median));
    let failures = attempts.saturating_sub(samples.len()) as u32;
    let failure_penalty = FAILED_CONFIRMATION_PENALTY
        .checked_mul(failures)
        .unwrap_or(Duration::MAX);
    let score = median
        .checked_add(jitter / 2)
        .and_then(|value| value.checked_add(failure_penalty))
        .unwrap_or(Duration::MAX);

    Some(ConfirmedWgResult {
        probe: WgProbeResult {
            ip: candidate.ip,
            port: candidate.port,
            rtt: median,
        },
        successes: samples.len(),
        attempts,
        score,
    })
}

async fn verify_one_wg(
    probe: &WgProbe,
    ip: IpAddr,
    port: u16,
    timeout: Duration,
    real_http: bool,
) -> Option<WgProbeResult> {
    let peer = SocketAddr::new(ip, port);
    let (rtt, session) = match wireguard::verify_endpoint_keep_session(
        peer,
        *probe.private_key,
        *probe.peer_public_key,
        probe.client_id,
        probe.local_ipv4,
        &probe.aethernoize,
        timeout,
        Some(25),
    )
    .await
    {
        Ok(value) => value,
        Err(error) => {
            log::trace!("wg probe {ip}:{port} -> {error}");
            return None;
        }
    };

    if !real_http {
        return Some(WgProbeResult { ip, port, rtt });
    }

    let params = crate::tunnelping::WgPingParams {
        local_ipv4: probe.local_ipv4,
        local_ipv6: "::1".parse().unwrap(),
        aethernoize: probe.aethernoize.clone(),
    };
    match crate::tunnelping::wg_http_ping_established(
        session,
        &params,
        WG_IRONCLAD_HTTP_TIMEOUT,
    )
    .await
    {
        Ok(http_rtt) => Some(WgProbeResult {
            ip,
            port,
            rtt: http_rtt,
        }),
        Err(error) => {
            log::trace!("[-] ironclad wg {ip}:{port} failed real HTTP check: {error}");
            None
        }
    }
}

fn diverse_finalists(
    mut successful: Vec<WgProbeResult>,
    requested: usize,
) -> Vec<WgProbeResult> {
    successful.sort_by_key(|result| result.rtt);
    let wanted = requested.max(1).min(successful.len());
    let mut selected = Vec::with_capacity(wanted);
    let mut selected_endpoints = HashSet::new();
    let mut selected_groups = HashSet::new();

    for result in &successful {
        let group = endpoint_group(result.ip);
        if selected_groups.insert(group)
            && selected_endpoints.insert((result.ip, result.port))
        {
            selected.push(*result);
            if selected.len() == wanted {
                return selected;
            }
        }
    }

    for result in successful {
        if selected_endpoints.insert((result.ip, result.port)) {
            selected.push(result);
            if selected.len() == wanted {
                break;
            }
        }
    }
    selected
}

fn endpoint_group(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(ip) => {
            let octets = ip.octets();
            format!("{}.{}.{}.0/24", octets[0], octets[1], octets[2])
        }
        IpAddr::V6(ip) => {
            let segments = ip.segments();
            format!("{:x}:{:x}:{:x}::/48", segments[0], segments[1], segments[2])
        }
    }
}

fn same_endpoint_group(left: IpAddr, right: IpAddr) -> bool {
    endpoint_group(left) == endpoint_group(right)
}

fn build_wg_candidates(
    strategy: &WgStrategy,
    configured_ports: &[u16],
    ip: IpScan,
    excluded_peer: Option<SocketAddr>,
) -> Vec<(IpAddr, u16)> {
    let ports = selected_ports(strategy, configured_ports);
    let v4_prefixes = selected_v4_prefixes(strategy);
    let v6_prefixes = selected_v6_prefixes(strategy);
    let mut groups: Vec<Vec<IpAddr>> = Vec::new();

    if ip.want_v4() {
        for prefix in v4_prefixes {
            groups.push(
                sample_cidr_v4(&prefix, strategy.sample_per_cidr)
                    .into_iter()
                    .map(IpAddr::V4)
                    .collect(),
            );
        }
    }
    if ip.want_v6() {
        for prefix in v6_prefixes {
            groups.push(
                sample_cidr_v6(&prefix, strategy.sample_per_cidr)
                    .into_iter()
                    .map(IpAddr::V6)
                    .collect(),
            );
        }
    }

    let mut output = Vec::new();
    let mut seen = HashSet::new();
    let excluded_ip = excluded_peer.map(|peer| peer.ip());

    let mut anchors = Vec::new();
    if ip.want_v4() {
        anchors.extend(
            wireguard::WG_SEEDS_V4
                .iter()
                .filter_map(|value| value.parse::<IpAddr>().ok()),
        );
    }
    if ip.want_v6() {
        anchors.extend(
            wireguard::WG_SEEDS_V6
                .iter()
                .filter_map(|value| value.parse::<IpAddr>().ok()),
        );
    }
    for address in anchors {
        if excluded_ip
            .map(|excluded| same_endpoint_group(address, excluded))
            .unwrap_or(false)
        {
            continue;
        }
        for &port in &ports {
            if seen.insert((address, port)) {
                output.push((address, port));
            }
        }
    }

    let max_len = groups.iter().map(Vec::len).max().unwrap_or(0);
    for port_offset in 0..ports.len() {
        for index in 0..max_len {
            for group in &groups {
                let Some(address) = group.get(index).copied() else {
                    continue;
                };
                if excluded_ip
                    .map(|excluded| same_endpoint_group(address, excluded))
                    .unwrap_or(false)
                {
                    continue;
                }
                let port = ports[(index + port_offset) % ports.len()];
                if seen.insert((address, port)) {
                    output.push((address, port));
                }
            }
        }
    }
    output
}

fn selected_ports(strategy: &WgStrategy, configured: &[u16]) -> Vec<u16> {
    let configured: HashSet<u16> = configured.iter().copied().filter(|port| *port > 0).collect();
    let mut output = wireguard::WG_PRIMARY_PORTS
        .iter()
        .copied()
        .filter(|port| configured.is_empty() || configured.contains(port))
        .collect::<Vec<_>>();
    if output.is_empty() {
        output.extend_from_slice(wireguard::WG_PRIMARY_PORTS);
    }
    if strategy.compatibility_ports > 0 {
        for &port in wireguard::WG_PORTS {
            if !output.contains(&port)
                && (configured.is_empty() || configured.contains(&port))
                && output.len()
                    < wireguard::WG_PRIMARY_PORTS.len() + strategy.compatibility_ports
            {
                output.push(port);
            }
        }
    }
    output
}

fn selected_v4_prefixes(strategy: &WgStrategy) -> Vec<String> {
    let mut output = wireguard::WG_PRIMARY_PREFIXES_V4
        .iter()
        .map(|value| (*value).to_string())
        .collect::<Vec<_>>();
    if strategy.include_compatibility {
        for prefix in wireguard::WG_PREFIXES_V4 {
            if !output.iter().any(|existing| existing == prefix) {
                output.push((*prefix).to_string());
            }
        }
        append_extra_cidrs(&mut output, "AETHER_WG_EXTRA_CIDRS", false);
    }
    output
}

fn selected_v6_prefixes(strategy: &WgStrategy) -> Vec<String> {
    let mut output = wireguard::WG_PRIMARY_PREFIXES_V6
        .iter()
        .map(|value| (*value).to_string())
        .collect::<Vec<_>>();
    if strategy.include_compatibility {
        for prefix in wireguard::WG_PREFIXES_V6 {
            if !output.iter().any(|existing| existing == prefix) {
                output.push((*prefix).to_string());
            }
        }
        append_extra_cidrs(&mut output, "AETHER_WG_EXTRA_CIDRS", true);
    }
    output
}

fn append_extra_cidrs(output: &mut Vec<String>, env_name: &str, ipv6: bool) {
    let Ok(value) = std::env::var(env_name) else {
        return;
    };
    for cidr in value
        .split(|character: char| matches!(character, ',' | ';' | ' '))
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        let valid = if ipv6 {
            parse_cidr_v6(cidr).is_some()
        } else {
            parse_cidr_v4(cidr).is_some()
        };
        if valid && !output.iter().any(|existing| existing == cidr) {
            output.push(cidr.to_string());
        }
    }
}

fn parse_cidr_v4(cidr: &str) -> Option<(u32, u8)> {
    let (ip, prefix) = cidr.split_once('/')?;
    let prefix: u8 = prefix.parse().ok()?;
    if prefix > 32 {
        return None;
    }
    let address = u32::from(ip.parse::<Ipv4Addr>().ok()?);
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    Some((address & mask, prefix))
}

fn sample_cidr_v4(cidr: &str, count: usize) -> Vec<Ipv4Addr> {
    let (base, prefix) = match parse_cidr_v4(cidr) {
        Some(value) => value,
        None => return Vec::new(),
    };
    let host_bits = 32u32.saturating_sub(prefix as u32);
    let size = if host_bits >= 32 {
        u32::MAX
    } else {
        1u32 << host_bits
    };
    if size <= 2 {
        return vec![Ipv4Addr::from(base)];
    }

    let usable = size - 2;
    let wanted = (count as u32).min(usable);
    let mut chosen = HashSet::with_capacity(wanted as usize);
    let mut output = Vec::with_capacity(wanted as usize);
    let mut rng = rand::thread_rng();
    while (output.len() as u32) < wanted {
        let offset = 1 + rng.gen_range(0..usable);
        if chosen.insert(offset) {
            output.push(Ipv4Addr::from(base + offset));
        }
    }
    output
}

fn parse_cidr_v6(cidr: &str) -> Option<(u128, u8)> {
    let (ip, prefix) = cidr.split_once('/')?;
    let prefix: u8 = prefix.parse().ok()?;
    if prefix > 128 {
        return None;
    }
    let address = u128::from(ip.parse::<Ipv6Addr>().ok()?);
    let mask = if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    };
    Some((address & mask, prefix))
}

fn sample_cidr_v6(cidr: &str, count: usize) -> Vec<Ipv6Addr> {
    let (base, prefix) = match parse_cidr_v6(cidr) {
        Some(value) => value,
        None => return Vec::new(),
    };
    let host_bits = 128u32.saturating_sub(prefix as u32);
    if host_bits == 0 {
        return vec![Ipv6Addr::from(base)];
    }
    let mask = if host_bits >= 128 {
        u128::MAX
    } else {
        (1u128 << host_bits) - 1
    };
    let mut rng = rand::thread_rng();
    (0..count)
        .map(|_| {
            let random = ((rng.gen::<u64>() as u128) << 64) | rng.gen::<u64>() as u128;
            Ipv6Addr::from(base | (random & mask))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_groups_are_range_stable() {
        assert!(same_endpoint_group(
            "162.159.193.1".parse().unwrap(),
            "162.159.193.250".parse().unwrap()
        ));
        assert!(!same_endpoint_group(
            "162.159.192.1".parse().unwrap(),
            "162.159.193.1".parse().unwrap()
        ));
    }

    #[test]
    fn balanced_uses_only_official_ports() {
        let strategy = WgScanMode::Balanced.strategy();
        assert_eq!(
            selected_ports(&strategy, wireguard::WG_PORTS),
            wireguard::WG_PRIMARY_PORTS
        );
    }
}
