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
                concurrency: 12,
                per_probe_timeout: Duration::from_millis(5000),
                overall_deadline: Duration::from_secs(30),
                quiet_after_first: Duration::from_secs(0),
                target_successes: 1,
                early_exit_first: true,
                full_subnet: false,
                sample_per_cidr: 40,
            },
            WgScanMode::Balanced => WgStrategy {
                concurrency: 8,
                per_probe_timeout: Duration::from_millis(7000),
                overall_deadline: Duration::from_secs(80),
                quiet_after_first: Duration::from_secs(12),
                target_successes: 5,
                early_exit_first: false,
                full_subnet: false,
                sample_per_cidr: 120,
            },
            WgScanMode::Thorough => WgStrategy {
                concurrency: 10,
                per_probe_timeout: Duration::from_millis(9000),
                overall_deadline: Duration::from_secs(250),
                quiet_after_first: Duration::from_secs(25),
                target_successes: 0,
                early_exit_first: false,
                full_subnet: true,
                sample_per_cidr: 0,
            },
            WgScanMode::Stealth => WgStrategy {
                concurrency: 3,
                per_probe_timeout: Duration::from_millis(10000),
                overall_deadline: Duration::from_secs(150),
                quiet_after_first: Duration::from_secs(20),
                target_successes: 3,
                early_exit_first: false,
                full_subnet: false,
                sample_per_cidr: 50,
            },
            WgScanMode::Ironclad => WgStrategy {
                concurrency: 4,
                per_probe_timeout: Duration::from_millis(15000),
                overall_deadline: Duration::from_secs(180),
                quiet_after_first: Duration::from_secs(15),
                target_successes: 3,
                early_exit_first: false,
                full_subnet: false,
                sample_per_cidr: 120,
            },
        }
    }
}

const WG_IRONCLAD_TCPING_TIMEOUT: Duration = Duration::from_secs(10);

struct WgStrategy {
    concurrency: usize,
    per_probe_timeout: Duration,
    overall_deadline: Duration,
    quiet_after_first: Duration,
    target_successes: usize,
    early_exit_first: bool,
    full_subnet: bool,
    sample_per_cidr: usize,
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
    let mut strategy = mode.strategy();
    strategy.concurrency = crate::sysprofile::cap_concurrency(strategy.concurrency);
    let timeout = strategy.per_probe_timeout;
    let mut effective_ip = probe.ip;
    if probe.ip.want_v6() && !crate::prober::host_has_ipv6().await {
        if probe.ip.want_v4() {
            log::warn!("[-] host has no IPv6 route; falling back to IPv4-only scan");
            effective_ip = IpScan::V4;
        } else {
            log::warn!("[-] host has no IPv6 route; IPv6 scan needs native IPv6 connectivity");
            return Err(AetherError::NoCleanEndpoint);
        }
    }
    let candidates = build_wg_candidates(&strategy, &probe.ports, effective_ip);

    log::info!(
        "[*] wireguard scan mode={} ip={} candidates={} ports={:?} concurrency={} per_probe={:?} budget={:?}",
        mode.label(),
        effective_ip.label(),
        candidates.len(),
        probe.ports,
        strategy.concurrency,
        strategy.per_probe_timeout,
        strategy.overall_deadline,
    );

    let ironclad = mode == WgScanMode::Ironclad;

    let stream = futures::stream::iter(
        candidates
            .into_iter()
            .map(|(ip, port)| verify_one_wg(probe, ip, port, timeout, ironclad)),
    )
    .buffer_unordered(strategy.concurrency);
    tokio::pin!(stream);

    let deadline = Instant::now() + strategy.overall_deadline;
    let mut best: Option<WgProbeResult> = None;
    let mut found = 0usize;
    let mut quiet_until: Option<Instant> = None;

    loop {
        let effective_deadline = match quiet_until {
            Some(quiet) => quiet.min(deadline),
            None => deadline,
        };
        let remaining = effective_deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            if best.is_some() {
                if quiet_until.is_some() {
                    log::info!("[+] no new endpoints recently, finalizing selection");
                } else {
                    log::warn!("[-] scan deadline reached");
                }
            } else {
                log::warn!("[-] scan deadline reached with no endpoint");
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
                            "[+] wg candidate ok {}:{} rtt={:?}",
                            result.ip,
                            result.port,
                            result.rtt
                        );
                        if strategy.early_exit_first {
                            return Ok(result);
                        }
                        best = Some(match best {
                            Some(current) if current.rtt <= result.rtt => current,
                            _ => result,
                        });
                        found += 1;

                        if strategy.target_successes > 0
                            && found >= strategy.target_successes
                            && quiet_until.is_none()
                        {
                            log::info!(
                                "[+] reached target of {} endpoints, selecting best",
                                strategy.target_successes
                            );
                            if !strategy.quiet_after_first.is_zero() {
                                quiet_until = Some(Instant::now() + strategy.quiet_after_first);
                            } else {
                                break;
                            }
                        }
                    }
                }
            }
            _ = tokio::time::sleep(remaining) => {
                if best.is_some() {
                    if quiet_until.is_some() {
                        log::info!("[+] no new endpoints recently, finalizing selection");
                    } else {
                        log::warn!("[-] scan deadline reached");
                    }
                } else {
                    log::warn!("[-] scan deadline reached with no endpoint");
                }
                break;
            }
        }
    }

    match best {
        Some(result) => {
            log::info!(
                "[+] best wg endpoint {}:{} rtt={:?}",
                result.ip,
                result.port,
                result.rtt
            );
            Ok(result)
        }
        None => Err(AetherError::NoCleanEndpoint),
    }
}

async fn verify_one_wg(
    probe: &WgProbe,
    ip: IpAddr,
    port: u16,
    timeout: Duration,
    ironclad: bool,
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
        None,
    )
    .await
    {
        Ok(value) => value,
        Err(error) => {
            log::trace!("wg probe {ip}:{port} -> {error}");
            return None;
        }
    };

    if !ironclad {
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
        WG_IRONCLAD_TCPING_TIMEOUT,
    )
    .await
    {
        Ok(http_rtt) => {
            log::info!(
                "[+] ironclad verified wg {ip}:{port} real http round trip rtt={http_rtt:?}"
            );
            Some(WgProbeResult {
                ip,
                port,
                rtt: http_rtt,
            })
        }
        Err(error) => {
            log::trace!("[-] ironclad wg {ip}:{port} failed real http check: {error}");
            None
        }
    }
}

fn build_wg_candidates(
    strategy: &WgStrategy,
    ports: &[u16],
    ip: IpScan,
) -> Vec<(IpAddr, u16)> {
    let ports: Vec<u16> = {
        let mut seen_ports = HashSet::new();
        let deduped: Vec<u16> = ports
            .iter()
            .copied()
            .filter(|port| *port != 0 && seen_ports.insert(*port))
            .collect();
        if deduped.is_empty() {
            vec![2408]
        } else {
            deduped
        }
    };

    let mut anchors: Vec<IpAddr> = Vec::new();
    let mut pool: Vec<IpAddr> = Vec::new();

    if ip.want_v4() {
        for seed in wireguard::WG_SEEDS_V4 {
            if let Ok(address) = seed.parse::<Ipv4Addr>() {
                anchors.push(IpAddr::V4(address));
            }
        }
        let cidr_hosts: Vec<Vec<Ipv4Addr>> = wireguard::WG_PREFIXES_V4
            .iter()
            .map(|cidr| {
                if strategy.full_subnet {
                    enumerate_cidr_v4(cidr)
                } else {
                    sample_cidr_v4(cidr, strategy.sample_per_cidr)
                }
            })
            .collect();
        let max_len = cidr_hosts.iter().map(Vec::len).max().unwrap_or(0);
        for index in 0..max_len {
            for hosts in &cidr_hosts {
                if let Some(address) = hosts.get(index) {
                    pool.push(IpAddr::V4(*address));
                }
            }
        }
    }

    if ip.want_v6() {
        for seed in wireguard::WG_SEEDS_V6 {
            if let Ok(address) = seed.parse::<Ipv6Addr>() {
                anchors.push(IpAddr::V6(address));
            }
        }
        let per_cidr = if strategy.sample_per_cidr == 0 {
            80
        } else {
            strategy.sample_per_cidr
        };
        let cidr_hosts: Vec<Vec<Ipv6Addr>> = wireguard::WG_PREFIXES_V6
            .iter()
            .map(|cidr| sample_cidr_v6(cidr, per_cidr, wireguard::WG_PREFIXES_V4))
            .collect();
        let max_len = cidr_hosts.iter().map(Vec::len).max().unwrap_or(0);
        for index in 0..max_len {
            for hosts in &cidr_hosts {
                if let Some(address) = hosts.get(index) {
                    pool.push(IpAddr::V6(*address));
                }
            }
        }
    }

    let mut output = Vec::new();
    let mut seen = HashSet::new();

    // Known anchor IPs are cheap and valuable. Test every configured port on them
    // before expanding into sampled ranges.
    for port in &ports {
        for address in &anchors {
            if seen.insert((*address, *port)) {
                output.push((*address, *port));
            }
        }
    }

    // Interleave the full IP × port product by rotating the starting port for each
    // address. This avoids the old bug where each IP was paired with only one port,
    // while still preventing the scanner from spending its entire deadline on one IP.
    for port_offset in 0..ports.len() {
        for (index, address) in pool.iter().enumerate() {
            let port = ports[(index + port_offset) % ports.len()];
            if seen.insert((*address, port)) {
                output.push((*address, port));
            }
        }
    }

    output
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
    let mut rng = rand::thread_rng();
    let mut chosen = HashSet::with_capacity(wanted as usize);
    let mut output = Vec::with_capacity(wanted as usize);

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

fn sample_cidr_v6(cidr: &str, count: usize, v4_cidrs: &[&str]) -> Vec<Ipv6Addr> {
    let (base, prefix) = match parse_cidr_v6(cidr) {
        Some(value) => value,
        None => return Vec::new(),
    };
    if 128u32.saturating_sub(prefix as u32) == 0 {
        return vec![Ipv6Addr::from(base)];
    }

    let v4: Vec<(u32, u8)> = v4_cidrs
        .iter()
        .filter_map(|cidr| parse_cidr_v4(cidr))
        .collect();
    let mut rng = rand::thread_rng();
    let mut output = Vec::with_capacity(count);
    for _ in 0..count {
        let embedded = if v4.is_empty() {
            rng.gen::<u32>() as u128
        } else {
            let (network, prefix) = v4[rng.gen_range(0..v4.len())];
            let host_bits = 32u32.saturating_sub(prefix as u32);
            let host_mask = match host_bits {
                0 => 0,
                32 => u32::MAX,
                bits => (1u32 << bits) - 1,
            };
            (network | (rng.gen::<u32>() & host_mask)) as u128
        };
        output.push(Ipv6Addr::from(base | embedded));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_strategy() -> WgStrategy {
        WgStrategy {
            concurrency: 1,
            per_probe_timeout: Duration::from_secs(1),
            overall_deadline: Duration::from_secs(1),
            quiet_after_first: Duration::ZERO,
            target_successes: 1,
            early_exit_first: true,
            full_subnet: false,
            sample_per_cidr: 1,
        }
    }

    #[test]
    fn candidates_cover_each_anchor_port_combination() {
        let candidates = build_wg_candidates(&test_strategy(), &[2408, 500], IpScan::V4);
        for seed in wireguard::WG_SEEDS_V4 {
            let ip = IpAddr::V4(seed.parse().unwrap());
            assert!(candidates.contains(&(ip, 2408)));
            assert!(candidates.contains(&(ip, 500)));
        }
    }

    #[test]
    fn cidr_parsers_normalize_network_addresses_and_reject_bad_prefixes() {
        assert_eq!(
            parse_cidr_v4("192.0.2.123/24"),
            Some((u32::from(Ipv4Addr::new(192, 0, 2, 0)), 24))
        );
        assert!(parse_cidr_v4("192.0.2.1/33").is_none());
        assert!(parse_cidr_v6("2001:db8::1/129").is_none());
    }
}
