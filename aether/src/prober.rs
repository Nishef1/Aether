use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::stream::StreamExt;
use rand::Rng;

use crate::error::{AetherError, Result};
use crate::noize::NoizeConfig;
use crate::quic;

// Cloudflare's documented MASQUE ingress ranges are deliberately kept separate
// from legacy/proven compatibility ranges. Broad Cloudflare CDN ranges are not
// scanned by default because they mostly produce unrelated certificates and
// expensive false-positive TLS handshakes.
pub const MASQUE_CIDRS_V4: &[&str] = &[
    "162.159.192.0/24", // consumer WARP ingress
    "162.159.197.0/24", // documented MASQUE ingress
    "162.159.198.0/24", // proven consumer compatibility range
];

const MASQUE_COMPAT_CIDRS_V4: &[&str] = &[
    "162.159.193.0/24",
    "162.159.195.0/24",
    "162.159.196.0/24",
    "162.159.204.0/24",
];

pub const MASQUE_SEEDS: &[&str] = &[
    "162.159.192.1",
    "162.159.197.1",
    "162.159.198.1",
    "162.159.198.2",
];

const MASQUE_COMPAT_SEEDS: &[&str] = &[
    "162.159.193.1",
    "162.159.195.1",
    "162.159.196.1",
];

// HTTP/3 uses UDP and may use the documented fallback ports. HTTP/2 uses the
// documented TCP fallback on 443 only; probing every UDP fallback as TCP wastes
// time and data without improving selection.
pub const MASQUE_PORTS: &[u16] = &[443, 500, 1701, 4500, 4443, 8443, 8095];
pub const MASQUE_H2_PORTS: &[u16] = &[443];

pub const MASQUE_CIDRS_V6: &[&str] = &["2606:4700:102::/48"];
const MASQUE_COMPAT_CIDRS_V6: &[&str] = &["2606:4700:d0::/48", "2606:4700:d1::/48"];

pub const MASQUE_SEEDS_V6: &[&str] = &[
    "2606:4700:102::a29f:c001",
    "2606:4700:102::a29f:c002",
];

const MASQUE_COMPAT_SEEDS_V6: &[&str] = &[
    "2606:4700:d0::a29f:c602",
    "2606:4700:d1::a29f:c602",
    "2606:4700:d0::a29f:c601",
];

#[derive(Debug, Clone, Copy)]
pub struct ProbeResult {
    pub ip: IpAddr,
    pub port: u16,
    pub rtt: Duration,
}

#[derive(Debug, Clone, Copy)]
struct ConfirmedResult {
    probe: ProbeResult,
    successes: usize,
    attempts: usize,
    jitter: Duration,
    score: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum RangeKey {
    V4(u32),
    V6(u128),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpScan {
    V4,
    V6,
    Both,
}

impl IpScan {
    pub fn parse(value: &str) -> IpScan {
        match value.trim().to_lowercase().as_str() {
            "6" | "v6" | "ipv6" => IpScan::V6,
            "both" | "all" | "dual" => IpScan::Both,
            _ => IpScan::V4,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            IpScan::V4 => "ipv4",
            IpScan::V6 => "ipv6",
            IpScan::Both => "dual-stack",
        }
    }

    pub fn want_v4(&self) -> bool {
        matches!(self, IpScan::V4 | IpScan::Both)
    }

    pub fn want_v6(&self) -> bool {
        matches!(self, IpScan::V6 | IpScan::Both)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanMode {
    Turbo,
    Balanced,
    Thorough,
    Stealth,
    Ironclad,
}

impl ScanMode {
    pub fn parse(value: &str) -> ScanMode {
        match value.trim().to_lowercase().as_str() {
            "turbo" | "fast" => ScanMode::Turbo,
            "thorough" | "deep" | "pro" => ScanMode::Thorough,
            "stealth" | "quiet" => ScanMode::Stealth,
            "ironclad" | "real" | "verify" | "guaranteed" => ScanMode::Ironclad,
            _ => ScanMode::Balanced,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            ScanMode::Turbo => "turbo",
            ScanMode::Balanced => "balanced",
            ScanMode::Thorough => "thorough",
            ScanMode::Stealth => "stealth",
            ScanMode::Ironclad => "ironclad",
        }
    }

    fn strategy(&self) -> Strategy {
        match self {
            ScanMode::Turbo => Strategy {
                // Android auto H2 latency window: wait briefly after the first
                // verified gateway so Auto can choose the lowest-latency result
                // without turning a normal connection into a long scan.
                concurrency: 20,
                per_probe_timeout: Duration::from_secs(4),
                overall_deadline: Duration::from_secs(8),
                settle_after_target: Duration::from_millis(650),
                target_successes: 1,
                early_exit_first: false,
                sample_per_cidr: 24,
                finalists: 4,
                finalist_attempts: 1,
                secondary_port_passes: 0,
                include_compat_ranges: false,
            },
            ScanMode::Balanced => Strategy {
                concurrency: 20,
                per_probe_timeout: Duration::from_secs(5),
                overall_deadline: Duration::from_secs(50),
                settle_after_target: Duration::from_secs(4),
                target_successes: 12,
                early_exit_first: false,
                sample_per_cidr: 64,
                finalists: 6,
                finalist_attempts: 3,
                secondary_port_passes: 1,
                include_compat_ranges: false,
            },
            ScanMode::Thorough => Strategy {
                concurrency: 24,
                per_probe_timeout: Duration::from_secs(7),
                overall_deadline: Duration::from_secs(100),
                settle_after_target: Duration::from_secs(8),
                target_successes: 28,
                early_exit_first: false,
                sample_per_cidr: 128,
                finalists: 10,
                finalist_attempts: 3,
                secondary_port_passes: 2,
                include_compat_ranges: true,
            },
            ScanMode::Stealth => Strategy {
                concurrency: 3,
                per_probe_timeout: Duration::from_secs(10),
                overall_deadline: Duration::from_secs(120),
                settle_after_target: Duration::from_secs(12),
                target_successes: 6,
                early_exit_first: false,
                sample_per_cidr: 48,
                finalists: 4,
                finalist_attempts: 3,
                secondary_port_passes: 0,
                include_compat_ranges: false,
            },
            ScanMode::Ironclad => Strategy {
                concurrency: 4,
                per_probe_timeout: Duration::from_secs(12),
                overall_deadline: Duration::from_secs(140),
                settle_after_target: Duration::from_secs(8),
                target_successes: 6,
                early_exit_first: false,
                sample_per_cidr: 64,
                finalists: 4,
                finalist_attempts: 3,
                secondary_port_passes: 1,
                include_compat_ranges: true,
            },
        }
    }
}

const IRONCLAD_TCPING_TIMEOUT: Duration = Duration::from_secs(10);
const FAILED_CONFIRMATION_PENALTY: Duration = Duration::from_millis(250);

struct Strategy {
    concurrency: usize,
    per_probe_timeout: Duration,
    overall_deadline: Duration,
    settle_after_target: Duration,
    target_successes: usize,
    early_exit_first: bool,
    sample_per_cidr: usize,
    finalists: usize,
    finalist_attempts: usize,
    secondary_port_passes: usize,
    include_compat_ranges: bool,
}

#[derive(Clone)]
pub struct MasqueProbe {
    pub sni: String,
    pub authority: String,
    pub path: String,
    pub cert_pem: Arc<[u8]>,
    pub key_pem: Arc<[u8]>,
    pub ech_config_list: Option<Arc<[u8]>>,
    pub noize: NoizeConfig,
    pub ports: Vec<u16>,
    pub ip: IpScan,
    pub local_ipv4: Ipv4Addr,
}

pub async fn host_has_ipv6() -> bool {
    match tokio::net::UdpSocket::bind("[::]:0").await {
        Ok(socket) => socket
            .connect("[2606:4700:102::a29f:c001]:443")
            .await
            .is_ok(),
        Err(_) => false,
    }
}

pub async fn hunt_best_gateway(probe: &MasqueProbe, mode: ScanMode) -> Result<ProbeResult> {
    let mut strategy = mode.strategy();
    strategy.concurrency = crate::sysprofile::cap_concurrency(strategy.concurrency);
    let timeout = strategy.per_probe_timeout;
    let mut effective_ip = probe.ip;

    if probe.ip.want_v6() && !host_has_ipv6().await {
        if probe.ip.want_v4() {
            log::warn!("[-] host has no IPv6 route; falling back to IPv4-only scan");
            effective_ip = IpScan::V4;
        } else {
            log::warn!("[-] host has no IPv6 route; IPv6 scan needs native IPv6 connectivity");
            return Err(AetherError::NoCleanEndpoint);
        }
    }

    let active_ports = active_ports(probe);
    let candidates = build_candidates(&strategy, &active_ports, effective_ip);
    let range_count = candidate_range_count(&candidates);

    log::info!(
        "[*] scan mode={} ip={} ranges={} candidates={} ports={:?} concurrency={} per_probe={:?} budget={:?} target={} finalists={} confirmations={}",
        mode.label(),
        effective_ip.label(),
        range_count,
        candidates.len(),
        active_ports,
        strategy.concurrency,
        strategy.per_probe_timeout,
        strategy.overall_deadline,
        strategy.target_successes,
        strategy.finalists,
        strategy.finalist_attempts,
    );

    let ironclad = mode == ScanMode::Ironclad;
    let stream = futures::stream::iter(
        candidates
            .into_iter()
            .map(|(ip, port)| verify_one(probe, ip, port, timeout, ironclad)),
    )
    .buffer_unordered(strategy.concurrency);
    tokio::pin!(stream);

    let deadline = Instant::now() + strategy.overall_deadline;
    let mut successful = Vec::new();
    let mut completed = 0usize;
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
                let Some(item) = item else { break };
                completed = completed.saturating_add(1);
                let Some(result) = item else { continue };

                log::info!(
                    "[+] candidate ok {}:{} rtt={:?}",
                    result.ip,
                    result.port,
                    result.rtt
                );

                if strategy.early_exit_first {
                    return Ok(result);
                }

                successful.push(result);

                if strategy.target_successes > 0
                    && successful.len() >= strategy.target_successes
                    && settle_until.is_none()
                {
                    log::info!(
                        "[+] reached discovery target of {} gateways across {} ranges; observing for {:?}",
                        strategy.target_successes,
                        result_range_count(&successful),
                        strategy.settle_after_target
                    );
                    if strategy.settle_after_target.is_zero() {
                        break;
                    }
                    settle_until = Some(Instant::now() + strategy.settle_after_target);
                }
            }
            _ = tokio::time::sleep(remaining) => break,
        }
    }

    log::info!(
        "[*] discovery completed attempts={} successes={} successful_ranges={}",
        completed,
        successful.len(),
        result_range_count(&successful)
    );

    if successful.is_empty() {
        return Err(AetherError::NoCleanEndpoint);
    }

    successful.sort_by_key(|result| result.rtt);
    let discovery_best = successful[0];
    let finalists = select_diverse_finalists(successful, strategy.finalists);

    log::info!(
        "[*] confirming {} range-diverse finalists with {} total measurements each",
        finalists.len(),
        strategy.finalist_attempts
    );

    let confirmation_concurrency = strategy.concurrency.min(finalists.len()).max(1);
    let confirmation_stream = futures::stream::iter(finalists.into_iter().map(|candidate| {
        confirm_candidate(
            probe,
            candidate,
            timeout,
            ironclad,
            strategy.finalist_attempts,
        )
    }))
    .buffer_unordered(confirmation_concurrency);
    tokio::pin!(confirmation_stream);

    let mut confirmed = Vec::new();
    while let Some(result) = confirmation_stream.next().await {
        if let Some(result) = result {
            log::info!(
                "[+] finalist {}:{} median={:?} jitter={:?} reliability={}/{} score={:?}",
                result.probe.ip,
                result.probe.port,
                result.probe.rtt,
                result.jitter,
                result.successes,
                result.attempts,
                result.score
            );
            confirmed.push(result);
        }
    }

    if confirmed.is_empty() {
        log::warn!(
            "[-] no finalist passed repeated confirmation; using discovery best {}:{} rtt={:?}",
            discovery_best.ip,
            discovery_best.port,
            discovery_best.rtt
        );
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
        "[+] best gateway {}:{} median_rtt={:?} jitter={:?} reliability={}/{} score={:?}",
        selected.probe.ip,
        selected.probe.port,
        selected.probe.rtt,
        selected.jitter,
        selected.successes,
        selected.attempts,
        selected.score
    );
    Ok(selected.probe)
}

fn active_ports(probe: &MasqueProbe) -> Vec<u16> {
    let preferred = if crate::masque_h2::enabled() {
        MASQUE_H2_PORTS
    } else {
        MASQUE_PORTS
    };
    let allowed: HashSet<u16> = probe.ports.iter().copied().filter(|port| *port != 0).collect();
    let mut output = preferred
        .iter()
        .copied()
        .filter(|port| allowed.is_empty() || allowed.contains(port))
        .collect::<Vec<_>>();
    if output.is_empty() {
        output.extend_from_slice(preferred);
    }
    output
}

fn select_diverse_finalists(mut successful: Vec<ProbeResult>, limit: usize) -> Vec<ProbeResult> {
    successful.sort_by_key(|result| result.rtt);
    let limit = limit.max(1).min(successful.len());
    let mut output = Vec::with_capacity(limit);
    let mut selected_endpoints = HashSet::new();
    let mut selected_ranges = HashSet::new();

    for result in &successful {
        if selected_ranges.insert(range_key(result.ip))
            && selected_endpoints.insert((result.ip, result.port))
        {
            output.push(*result);
            if output.len() == limit {
                return output;
            }
        }
    }

    for result in successful {
        if selected_endpoints.insert((result.ip, result.port)) {
            output.push(result);
            if output.len() == limit {
                break;
            }
        }
    }
    output
}

async fn confirm_candidate(
    probe: &MasqueProbe,
    candidate: ProbeResult,
    timeout: Duration,
    ironclad: bool,
    attempts: usize,
) -> Option<ConfirmedResult> {
    let attempts = attempts.max(1);
    let required_successes = attempts / 2 + 1;
    let mut samples = Vec::with_capacity(attempts);
    samples.push(candidate.rtt);

    for _ in 1..attempts {
        if let Some(result) = verify_one(probe, candidate.ip, candidate.port, timeout, ironclad).await
        {
            samples.push(result.rtt);
        }
    }

    let successes = samples.len();
    if successes < required_successes {
        log::info!(
            "[-] finalist {}:{} rejected after repeated confirmation ({}/{})",
            candidate.ip,
            candidate.port,
            successes,
            attempts
        );
        return None;
    }

    samples.sort();
    let median = samples[samples.len() / 2];
    let jitter = samples
        .last()
        .copied()
        .unwrap_or(median)
        .saturating_sub(samples.first().copied().unwrap_or(median));
    let failures = attempts.saturating_sub(successes) as u32;
    let failure_penalty = FAILED_CONFIRMATION_PENALTY
        .checked_mul(failures)
        .unwrap_or(Duration::MAX);
    let jitter_penalty = duration_half(jitter);
    let score = median
        .checked_add(failure_penalty)
        .and_then(|value| value.checked_add(jitter_penalty))
        .unwrap_or(Duration::MAX);

    Some(ConfirmedResult {
        probe: ProbeResult {
            ip: candidate.ip,
            port: candidate.port,
            rtt: median,
        },
        successes,
        attempts,
        jitter,
        score,
    })
}

async fn verify_one(
    probe: &MasqueProbe,
    ip: IpAddr,
    port: u16,
    timeout: Duration,
    ironclad: bool,
) -> Option<ProbeResult> {
    if ironclad {
        let params = crate::tunnelping::MasquePingParams {
            peer: SocketAddr::new(ip, port),
            sni: probe.sni.clone(),
            authority: probe.authority.clone(),
            path: probe.path.clone(),
            cert_pem: probe.cert_pem.to_vec(),
            key_pem: probe.key_pem.to_vec(),
            noize: probe.noize.clone(),
            local_ipv4: probe.local_ipv4,
            local_ipv4_str: probe.local_ipv4.to_string(),
            local_ipv6_str: String::new(),
        };
        return match crate::tunnelping::masque_http_ping(&params, IRONCLAD_TCPING_TIMEOUT).await {
            Ok(rtt) => Some(ProbeResult { ip, port, rtt }),
            Err(error) => {
                log::trace!("[-] ironclad {ip}:{port} failed real HTTP check: {error}");
                None
            }
        };
    }

    if crate::masque_h2::enabled() {
        let config = crate::masque_h2::H2TunnelConfig {
            peer: SocketAddr::new(ip, port),
            sni: probe.sni.clone(),
            authority: probe.authority.clone(),
            path: probe.path.clone(),
            cert_pem: probe.cert_pem.to_vec(),
            key_pem: probe.key_pem.to_vec(),
            local_ipv4: probe.local_ipv4,
            quiet: true,
            pin_endpoint: true,
            expected_pins: crate::consts::MASQUE_PINS
                .iter()
                .map(|pin| pin.to_vec())
                .collect(),
        };
        return match crate::masque_h2::verify_h2(&config, timeout).await {
            Ok(rtt) => Some(ProbeResult { ip, port, rtt }),
            Err(error) => {
                log::trace!("h2 probe {ip}:{port} -> {error}");
                None
            }
        };
    }

    let params = quic::VerifyParams {
        peer: SocketAddr::new(ip, port),
        sni: probe.sni.clone(),
        authority: probe.authority.clone(),
        path: probe.path.clone(),
        cert_pem: probe.cert_pem.to_vec(),
        key_pem: probe.key_pem.to_vec(),
        ech_config_list: probe.ech_config_list.as_ref().map(|value| value.to_vec()),
        noize: probe.noize.clone(),
        timeout,
        local_ipv4: probe.local_ipv4,
    };

    match quic::verify_masque(&params).await {
        Ok(rtt) => Some(ProbeResult { ip, port, rtt }),
        Err(error) => {
            log::trace!("probe {ip}:{port} -> {error}");
            None
        }
    }
}

fn build_candidates(strategy: &Strategy, ports: &[u16], ip: IpScan) -> Vec<(IpAddr, u16)> {
    let ports = dedupe_ports(ports, 443);
    let primary_port = ports[0];
    let mut anchors = Vec::new();
    let mut pool = Vec::new();

    if ip.want_v4() {
        for seed in MASQUE_SEEDS {
            if let Ok(address) = seed.parse::<Ipv4Addr>() {
                anchors.push(IpAddr::V4(address));
            }
        }
        if strategy.include_compat_ranges {
            for seed in MASQUE_COMPAT_SEEDS {
                if let Ok(address) = seed.parse::<Ipv4Addr>() {
                    anchors.push(IpAddr::V4(address));
                }
            }
        }

        let ranges = configured_v4_ranges(strategy.include_compat_ranges);
        let sampled = ranges
            .iter()
            .map(|range| sample_cidr_v4(range, strategy.sample_per_cidr))
            .collect::<Vec<_>>();
        interleave_v4(&sampled, &mut pool);
    }

    if ip.want_v6() {
        for seed in MASQUE_SEEDS_V6 {
            if let Ok(address) = seed.parse::<Ipv6Addr>() {
                anchors.push(IpAddr::V6(address));
            }
        }
        if strategy.include_compat_ranges {
            for seed in MASQUE_COMPAT_SEEDS_V6 {
                if let Ok(address) = seed.parse::<Ipv6Addr>() {
                    anchors.push(IpAddr::V6(address));
                }
            }
        }

        let ranges = configured_v6_ranges(strategy.include_compat_ranges);
        let sampled = ranges
            .iter()
            .map(|range| sample_cidr_v6(range, strategy.sample_per_cidr))
            .collect::<Vec<_>>();
        interleave_v6(&sampled, &mut pool);
    }

    let mut output = Vec::new();
    let mut seen = HashSet::new();

    for port in &ports {
        for address in &anchors {
            if seen.insert((*address, *port)) {
                output.push((*address, *port));
            }
        }
    }

    for address in &pool {
        if seen.insert((*address, primary_port)) {
            output.push((*address, primary_port));
        }
    }

    let secondary_ports = ports.iter().copied().skip(1).collect::<Vec<_>>();
    if !secondary_ports.is_empty() {
        for pass in 0..strategy.secondary_port_passes {
            for (index, address) in pool.iter().enumerate() {
                let port = secondary_ports[(index + pass) % secondary_ports.len()];
                if seen.insert((*address, port)) {
                    output.push((*address, port));
                }
            }
        }
    }

    output
}

fn configured_v4_ranges(include_compat: bool) -> Vec<String> {
    let mut ranges = MASQUE_CIDRS_V4
        .iter()
        .map(|value| (*value).to_string())
        .collect::<Vec<_>>();
    if include_compat {
        ranges.extend(
            MASQUE_COMPAT_CIDRS_V4
                .iter()
                .map(|value| (*value).to_string()),
        );
        ranges.extend(extra_ranges("AETHER_MASQUE_EXTRA_CIDRS", false));
    }
    ranges
}

fn configured_v6_ranges(include_compat: bool) -> Vec<String> {
    let mut ranges = MASQUE_CIDRS_V6
        .iter()
        .map(|value| (*value).to_string())
        .collect::<Vec<_>>();
    if include_compat {
        ranges.extend(
            MASQUE_COMPAT_CIDRS_V6
                .iter()
                .map(|value| (*value).to_string()),
        );
        ranges.extend(extra_ranges("AETHER_MASQUE_EXTRA_CIDRS", true));
    }
    ranges
}

fn extra_ranges(name: &str, ipv6: bool) -> Vec<String> {
    std::env::var(name)
        .ok()
        .into_iter()
        .flat_map(|value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|entry| !entry.is_empty())
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .filter(|entry| {
            if ipv6 {
                parse_cidr_v6(entry)
                    .map(|(_, prefix)| prefix >= 32)
                    .unwrap_or(false)
            } else {
                parse_cidr_v4(entry)
                    .map(|(_, prefix)| prefix >= 20)
                    .unwrap_or(false)
            }
        })
        .collect()
}

fn dedupe_ports(ports: &[u16], fallback: u16) -> Vec<u16> {
    let mut seen = HashSet::new();
    let output = ports
        .iter()
        .copied()
        .filter(|port| *port != 0 && seen.insert(*port))
        .collect::<Vec<_>>();
    if output.is_empty() {
        vec![fallback]
    } else {
        output
    }
}

fn interleave_v4(groups: &[Vec<Ipv4Addr>], output: &mut Vec<IpAddr>) {
    let max_len = groups.iter().map(Vec::len).max().unwrap_or(0);
    for index in 0..max_len {
        for group in groups {
            if let Some(address) = group.get(index) {
                output.push(IpAddr::V4(*address));
            }
        }
    }
}

fn interleave_v6(groups: &[Vec<Ipv6Addr>], output: &mut Vec<IpAddr>) {
    let max_len = groups.iter().map(Vec::len).max().unwrap_or(0);
    for index in 0..max_len {
        for group in groups {
            if let Some(address) = group.get(index) {
                output.push(IpAddr::V6(*address));
            }
        }
    }
}

fn candidate_range_count(candidates: &[(IpAddr, u16)]) -> usize {
    candidates
        .iter()
        .map(|(ip, _)| range_key(*ip))
        .collect::<HashSet<_>>()
        .len()
}

fn result_range_count(results: &[ProbeResult]) -> usize {
    results
        .iter()
        .map(|result| range_key(result.ip))
        .collect::<HashSet<_>>()
        .len()
}

fn range_key(ip: IpAddr) -> RangeKey {
    match ip {
        IpAddr::V4(address) => RangeKey::V4(u32::from(address) & 0xffff_ff00),
        IpAddr::V6(address) => RangeKey::V6(u128::from(address) & (u128::MAX << 80)),
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
    if host_bits == 0 {
        return vec![Ipv4Addr::from(base)];
    }
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
    let mut rng = rand::thread_rng();
    let mut chosen = HashSet::with_capacity(wanted as usize);
    let mut output = Vec::with_capacity(wanted as usize);

    while (output.len() as u32) < wanted {
        let offset = 1 + rng.gen_range(0..usable);
        if chosen.insert(offset) {
            output.push(Ipv4Addr::from(base.saturating_add(offset)));
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
    let host_mask = if host_bits >= 128 {
        u128::MAX
    } else {
        (1u128 << host_bits) - 1
    };
    let mut rng = rand::thread_rng();
    let mut chosen = HashSet::with_capacity(count);
    let mut output = Vec::with_capacity(count);

    while output.len() < count {
        let host = rng.gen::<u128>() & host_mask;
        if chosen.insert(host) {
            output.push(Ipv6Addr::from(base | host));
        }
    }
    output
}

fn duration_half(value: Duration) -> Duration {
    let nanos = (value.as_nanos() / 2).min(u64::MAX as u128) as u64;
    Duration::from_nanos(nanos)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finalists_cover_distinct_ranges_before_duplicates() {
        let results = vec![
            ProbeResult {
                ip: "162.159.198.10".parse().unwrap(),
                port: 443,
                rtt: Duration::from_millis(10),
            },
            ProbeResult {
                ip: "162.159.198.11".parse().unwrap(),
                port: 443,
                rtt: Duration::from_millis(11),
            },
            ProbeResult {
                ip: "162.159.197.10".parse().unwrap(),
                port: 443,
                rtt: Duration::from_millis(20),
            },
        ];
        let selected = select_diverse_finalists(results, 2);
        assert_eq!(result_range_count(&selected), 2);
    }

    #[test]
    fn invalid_extra_ranges_are_rejected() {
        assert!(parse_cidr_v4("162.159.197.0/24").is_some());
        assert!(parse_cidr_v4("162.159.197.0/33").is_none());
        assert!(parse_cidr_v6("2606:4700:102::/48").is_some());
    }
}
