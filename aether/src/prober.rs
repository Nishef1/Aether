use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::stream::StreamExt;
use rand::Rng;

use crate::error::{AetherError, Result};
use crate::noize::NoizeConfig;
use crate::quic;

pub const MASQUE_CIDRS_V4: &[&str] = &[
    "162.159.36.0/24",
    "162.159.46.0/24",
    "162.159.192.0/24",
    "162.159.193.0/24",
    "162.159.195.0/24",
    "162.159.196.0/24",
    "162.159.197.0/24",
    "162.159.198.0/24",
    "162.159.204.0/24",
    "172.65.251.0/24",
    "188.114.96.0/24",
    "188.114.97.0/24",
    "188.114.98.0/24",
    "188.114.99.0/24",
];

pub const MASQUE_SEEDS: &[&str] = &[
    "162.159.198.2",
    "162.159.198.1",
    "162.159.192.1",
    "162.159.193.1",
    "162.159.195.1",
    "162.159.196.1",
];

pub const MASQUE_PORTS: &[u16] = &[443, 500, 1701, 4443, 8443, 8095];

pub const MASQUE_CIDRS_V6: &[&str] = &[
    "2606:4700:d0::/48",
    "2606:4700:d1::/48",
    "2606:4700:102::/48",
];

pub const MASQUE_SEEDS_V6: &[&str] = &[
    "2606:4700:d0::a29f:c602",
    "2606:4700:d1::a29f:c602",
    "2606:4700:d0::a29f:c601",
    "2606:4700:d0::a29f:c001",
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
    score: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpScan {
    V4,
    V6,
    Both,
}

impl IpScan {
    pub fn parse(s: &str) -> IpScan {
        match s.trim().to_lowercase().as_str() {
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
    pub fn parse(s: &str) -> ScanMode {
        match s.trim().to_lowercase().as_str() {
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
                concurrency: 24,
                per_probe_timeout: Duration::from_millis(4000),
                overall_deadline: Duration::from_secs(25),
                settle_after_target: Duration::ZERO,
                target_successes: 1,
                early_exit_first: true,
                full_subnet: false,
                sample_per_cidr: 48,
                finalists: 1,
                finalist_attempts: 1,
            },
            ScanMode::Balanced => Strategy {
                concurrency: 20,
                per_probe_timeout: Duration::from_millis(5000),
                overall_deadline: Duration::from_secs(60),
                settle_after_target: Duration::from_secs(4),
                target_successes: 12,
                early_exit_first: false,
                full_subnet: false,
                sample_per_cidr: 96,
                finalists: 5,
                finalist_attempts: 3,
            },
            ScanMode::Thorough => Strategy {
                concurrency: 24,
                per_probe_timeout: Duration::from_millis(7000),
                overall_deadline: Duration::from_secs(120),
                settle_after_target: Duration::from_secs(8),
                target_successes: 32,
                early_exit_first: false,
                full_subnet: false,
                sample_per_cidr: 160,
                finalists: 8,
                finalist_attempts: 3,
            },
            ScanMode::Stealth => Strategy {
                concurrency: 3,
                per_probe_timeout: Duration::from_millis(10000),
                overall_deadline: Duration::from_secs(120),
                settle_after_target: Duration::from_secs(10),
                target_successes: 8,
                early_exit_first: false,
                full_subnet: false,
                sample_per_cidr: 64,
                finalists: 4,
                finalist_attempts: 3,
            },
            ScanMode::Ironclad => Strategy {
                concurrency: 4,
                per_probe_timeout: Duration::from_millis(12000),
                overall_deadline: Duration::from_secs(150),
                settle_after_target: Duration::from_secs(8),
                target_successes: 6,
                early_exit_first: false,
                full_subnet: false,
                sample_per_cidr: 96,
                finalists: 4,
                finalist_attempts: 3,
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
    full_subnet: bool,
    sample_per_cidr: usize,
    finalists: usize,
    finalist_attempts: usize,
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
        Ok(sock) => sock.connect("[2606:4700:d0::a29f:c001]:443").await.is_ok(),
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

    let candidates = build_candidates(&strategy, &probe.ports, effective_ip);

    log::info!(
        "[*] scan mode={} ip={} candidates={} ports={:?} concurrency={} per_probe={:?} budget={:?} target={} finalists={} confirmations={}",
        mode.label(),
        effective_ip.label(),
        candidates.len(),
        probe.ports,
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
    let mut settle_until: Option<Instant> = None;

    loop {
        let effective_deadline = settle_until
            .map(|settle| settle.min(deadline))
            .unwrap_or(deadline);
        let remaining = effective_deadline.saturating_duration_since(Instant::now());

        if remaining.is_zero() {
            if successful.is_empty() {
                log::warn!("[-] scan deadline reached with no gateway");
            } else if settle_until.is_some() {
                log::info!("[+] discovery settle window completed; confirming finalists");
            } else {
                log::warn!("[-] scan deadline reached; confirming discovered gateways");
            }
            break;
        }

        tokio::select! {
            item = stream.next() => {
                match item {
                    None => break,
                    Some(None) => continue,
                    Some(Some(result)) => {
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
                                "[+] reached discovery target of {} gateways; observing for {:?} before confirmation",
                                strategy.target_successes,
                                strategy.settle_after_target
                            );

                            if strategy.settle_after_target.is_zero() {
                                break;
                            }
                            settle_until = Some(Instant::now() + strategy.settle_after_target);
                        }
                    }
                }
            }
            _ = tokio::time::sleep(remaining) => {
                if successful.is_empty() {
                    log::warn!("[-] scan deadline reached with no gateway");
                } else {
                    log::info!("[+] discovery window completed; confirming finalists");
                }
                break;
            }
        }
    }

    if successful.is_empty() {
        return Err(AetherError::NoCleanEndpoint);
    }

    successful.sort_by_key(|result| result.rtt);
    let discovery_best = successful[0];
    let finalist_count = strategy.finalists.max(1).min(successful.len());
    let finalists = successful
        .into_iter()
        .take(finalist_count)
        .collect::<Vec<_>>();

    log::info!(
        "[*] confirming {} finalist gateways with {} total measurements each",
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
                "[+] finalist {}:{} median={:?} reliability={}/{} score={:?}",
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
        log::warn!(
            "[-] no finalist passed repeated confirmation; falling back to discovery best {}:{} rtt={:?}",
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
        "[+] best gateway {}:{} median_rtt={:?} reliability={}/{} score={:?}",
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
        if let Some(result) =
            verify_one(probe, candidate.ip, candidate.port, timeout, ironclad).await
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
    let failures = attempts.saturating_sub(successes) as u32;
    let penalty = FAILED_CONFIRMATION_PENALTY
        .checked_mul(failures)
        .unwrap_or(Duration::MAX);
    let score = median.checked_add(penalty).unwrap_or(Duration::MAX);

    Some(ConfirmedResult {
        probe: ProbeResult {
            ip: candidate.ip,
            port: candidate.port,
            rtt: median,
        },
        successes,
        attempts,
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
            Ok(rtt) => {
                log::info!(
                    "[+] ironclad verified {ip}:{port} real http round trip rtt={:?}",
                    rtt
                );
                Some(ProbeResult { ip, port, rtt })
            }
            Err(error) => {
                log::trace!("[-] ironclad {ip}:{port} failed real http check: {error}");
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
    let primary = ports.first().copied().unwrap_or(443);
    let mut candidates = Vec::new();
    let mut seen = HashSet::new();

    let seeds: Vec<Ipv4Addr> = MASQUE_SEEDS
        .iter()
        .filter_map(|seed| seed.parse().ok())
        .collect();
    let seeds_v6: Vec<Ipv6Addr> = MASQUE_SEEDS_V6
        .iter()
        .filter_map(|seed| seed.parse().ok())
        .collect();

    if ip.want_v4() {
        for address in &seeds {
            if seen.insert((IpAddr::V4(*address), primary)) {
                candidates.push((IpAddr::V4(*address), primary));
            }
        }

        let cidr_hosts: Vec<Vec<Ipv4Addr>> = MASQUE_CIDRS_V4
            .iter()
            .map(|cidr| {
                if strategy.full_subnet {
                    enumerate_cidr_v4(cidr)
                } else {
                    sample_cidr_v4(cidr, strategy.sample_per_cidr)
                }
            })
            .collect();
        let max_length = cidr_hosts.iter().map(Vec::len).max().unwrap_or(0);
        for index in 0..max_length {
            for hosts in &cidr_hosts {
                if let Some(address) = hosts.get(index) {
                    if seen.insert((IpAddr::V4(*address), primary)) {
                        candidates.push((IpAddr::V4(*address), primary));
                    }
                }
            }
        }
    }

    if ip.want_v6() {
        for address in &seeds_v6 {
            if seen.insert((IpAddr::V6(*address), primary)) {
                candidates.push((IpAddr::V6(*address), primary));
            }
        }

        let per_cidr = if strategy.sample_per_cidr == 0 {
            96
        } else {
            strategy.sample_per_cidr
        };
        let cidr_hosts: Vec<Vec<Ipv6Addr>> = MASQUE_CIDRS_V6
            .iter()
            .map(|cidr| sample_cidr_v6(cidr, per_cidr, MASQUE_CIDRS_V4))
            .collect();
        let max_length = cidr_hosts.iter().map(Vec::len).max().unwrap_or(0);
        for index in 0..max_length {
            for hosts in &cidr_hosts {
                if let Some(address) = hosts.get(index) {
                    if seen.insert((IpAddr::V6(*address), primary)) {
                        candidates.push((IpAddr::V6(*address), primary));
                    }
                }
            }
        }
    }

    if ip.want_v4() {
        for address in &seeds {
            for &port in ports {
                if port != primary && seen.insert((IpAddr::V4(*address), port)) {
                    candidates.push((IpAddr::V4(*address), port));
                }
            }
        }
    }

    if ip.want_v6() {
        for address in &seeds_v6 {
            for &port in ports {
                if port != primary && seen.insert((IpAddr::V6(*address), port)) {
                    candidates.push((IpAddr::V6(*address), port));
                }
            }
        }
    }

    candidates
}

fn parse_cidr_v4(cidr: &str) -> Option<(u32, u8)> {
    let (ip, prefix) = cidr.split_once('/')?;
    Some((
        u32::from(ip.parse::<Ipv4Addr>().ok()?),
        prefix.parse().ok()?,
    ))
}

fn enumerate_cidr_v4(cidr: &str) -> Vec<Ipv4Addr> {
    let (base, prefix) = match parse_cidr_v4(cidr) {
        Some(value) => value,
        None => return Vec::new(),
    };
    let host_bits = 32u32.saturating_sub(prefix as u32);
    if host_bits == 0 {
        return vec![Ipv4Addr::from(base)];
    }
    if host_bits > 12 {
        return Vec::new();
    }
    let size = 1u32 << host_bits;
    (1..size.saturating_sub(1))
        .map(|offset| Ipv4Addr::from(base + offset))
        .collect()
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
    let mut random = rand::thread_rng();
    let mut chosen = HashSet::with_capacity(wanted as usize);
    let mut addresses = Vec::with_capacity(wanted as usize);

    while (addresses.len() as u32) < wanted {
        let offset = 1 + random.gen_range(0..usable);
        if chosen.insert(offset) {
            addresses.push(Ipv4Addr::from(base + offset));
        }
    }

    addresses
}

fn parse_cidr_v6(cidr: &str) -> Option<(u128, u8)> {
    let (ip, prefix) = cidr.split_once('/')?;
    Some((
        u128::from(ip.parse::<Ipv6Addr>().ok()?),
        prefix.parse().ok()?,
    ))
}

fn sample_cidr_v6(cidr: &str, count: usize, v4_cidrs: &[&str]) -> Vec<Ipv6Addr> {
    let (base, prefix) = match parse_cidr_v6(cidr) {
        Some(value) => value,
        None => return Vec::new(),
    };
    if 128u32.saturating_sub(prefix as u32) == 0 {
        return vec![Ipv6Addr::from(base)];
    }

    let v4_ranges: Vec<(u32, u8)> = v4_cidrs
        .iter()
        .filter_map(|cidr| parse_cidr_v4(cidr))
        .collect();
    let mut random = rand::thread_rng();
    let mut addresses = Vec::with_capacity(count);

    for _ in 0..count {
        let embedded = if v4_ranges.is_empty() {
            random.gen::<u32>() as u128
        } else {
            let (network, prefix) = v4_ranges[random.gen_range(0..v4_ranges.len())];
            let host_bits = 32u32.saturating_sub(prefix as u32);
            let host = if host_bits == 0 {
                0
            } else {
                random.gen::<u32>() & ((1u32 << host_bits) - 1)
            };
            (network | host) as u128
        };
        addresses.push(Ipv6Addr::from(base | embedded));
    }

    addresses
}
