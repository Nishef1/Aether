#![allow(dead_code)]
mod account;
mod aethernoize;
mod cli;
mod config;
mod consts;
mod dns;
mod error;
mod fragment;
mod lastconn;
mod masque;
mod masque_h2;
mod netstack;
mod noize;
mod prober;
mod quic;
mod socks;
mod sysprofile;
mod tls;
mod tunnelping;
mod wg_prober;
mod wireguard;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use error::{AetherError, Result};

const TUNNEL_MTU: usize = 1280;
const INNER_MTU: usize = 1200;
const DEFAULT_CONFIG: &str = "aether.toml";

fn parse_local_v4(value: &str) -> Result<Ipv4Addr> {
    let raw = value.split('/').next().unwrap_or(value).trim();
    let address: Ipv4Addr = raw
        .parse()
        .map_err(|_| AetherError::Other(format!("invalid IPv4 identity address '{value}'")))?;
    if address.is_unspecified() {
        return Err(AetherError::Other(format!(
            "unspecified IPv4 identity address '{value}'"
        )));
    }
    Ok(address)
}

fn bounded_env_duration(
    name: &str,
    default_seconds: u64,
    minimum_seconds: u64,
    maximum_seconds: u64,
) -> Duration {
    let seconds = std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .map(|value| value.clamp(minimum_seconds, maximum_seconds))
        .unwrap_or(default_seconds.clamp(minimum_seconds, maximum_seconds));
    Duration::from_secs(seconds)
}

#[tokio::main]
async fn main() -> Result<()> {
    cli::parse_and_apply()?;

    let level = std::env::var("AETHER_LOG_LEVEL")
        .ok()
        .map(|value| value.trim().to_lowercase())
        .filter(|value| {
            matches!(
                value.as_str(),
                "error" | "warn" | "info" | "debug" | "trace"
            )
        })
        .unwrap_or_else(|| "info".to_string());
    let default_filter = format!("info,aether={level}");
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(default_filter))
        .format_timestamp_millis()
        .init();

    log::info!("Aether v{}", env!("CARGO_PKG_VERSION"));
    sysprofile::log_summary();
    install_netstack_panic_guard();

    let listen: SocketAddr = match std::env::var("AETHER_SOCKS") {
        Ok(value) => value
            .parse()
            .map_err(|_| AetherError::Other(format!("invalid SOCKS listen address '{value}'")))?,
        Err(_) => "127.0.0.1:1819".parse().unwrap(),
    };

    let base_config =
        std::env::var("AETHER_CONFIG").unwrap_or_else(|_| DEFAULT_CONFIG.to_string());

    let protocol = if std::env::var("AETHER_PEER").is_ok()
        || std::env::var("AETHER_WG_PEER").is_ok()
    {
        match std::env::var("AETHER_PROTOCOL") {
            Ok(value) => Protocol::parse(&value),
            Err(_) => Protocol::Masque,
        }
    } else {
        select_protocol().await
    };

    match protocol {
        Protocol::Masque => {
            select_masque_transport().await;
            let config_path = masque_config_path(&base_config);
            let identity = load_or_provision_masque(&config_path).await?;
            log::info!(
                "[+] identity ready: device={} ipv4={} ipv6={}",
                identity.device_id,
                identity.ipv4,
                identity.ipv6
            );
            parse_local_v4(&identity.ipv4)?;
            let ech = resolve_ech().await;
            let last_connection_path = lastconn_path(&config_path);
            run_masque(identity, ech, listen, last_connection_path).await
        }
        Protocol::WireGuard => {
            let config_path = warp_config_path(&base_config);
            let identity = load_or_provision_warp(&config_path).await?;
            log::info!(
                "[+] identity ready: device={} ipv4={} ipv6={}",
                identity.device_id,
                identity.ipv4,
                identity.ipv6
            );
            parse_local_v4(&identity.ipv4)?;
            let last_connection_path = lastconn_path(&config_path);
            run_wireguard(identity, listen, last_connection_path).await
        }
        Protocol::WarpInWarp => {
            if INNER_MTU >= TUNNEL_MTU {
                return Err(AetherError::Other(format!(
                    "inner MTU {INNER_MTU} must be lower than outer MTU {TUNNEL_MTU}"
                )));
            }
            let primary_path = warp_config_path(&base_config);
            let secondary_path = derive_sibling_path(&primary_path, "secondary");
            let primary = load_or_provision_warp(&primary_path).await?;
            let secondary = load_or_provision_warp(&secondary_path).await?;
            parse_local_v4(&primary.ipv4)?;
            parse_local_v4(&secondary.ipv4)?;
            log::info!(
                "[+] outer device={} ipv4={} | inner device={} ipv4={}",
                primary.device_id,
                primary.ipv4,
                secondary.device_id,
                secondary.ipv4
            );
            run_gool(primary, secondary, listen).await
        }
    }
}

async fn run_gool(
    primary: account::Identity,
    secondary: account::Identity,
    listen: SocketAddr,
) -> Result<()> {
    let mut last_peer: Option<SocketAddr> = None;
    let mut consecutive_failures: u32 = 0;
    const MAX_CONSECUTIVE_FAILURES: u32 = 2;

    loop {
        let cached_peer = if consecutive_failures < MAX_CONSECUTIVE_FAILURES {
            last_peer
        } else {
            if let Some(peer) = last_peer {
                log::warn!(
                    "[-] outer endpoint {peer} failed {consecutive_failures} times in a row; blacklisting and rescanning"
                );
            }
            None
        };

        let peer = match cached_peer {
            Some(peer) => peer,
            None => match select_peer(&primary, Protocol::WireGuard).await {
                Ok(peer) => {
                    consecutive_failures = 0;
                    peer
                }
                Err(error) => {
                    log::warn!(
                        "[-] no usable outer WARP endpoint found: {error}; rescanning shortly"
                    );
                    tokio::time::sleep(wg_reconnect_delay()).await;
                    continue;
                }
            },
        };

        log::info!("[+] using cloudflare edge {peer} (outer)");
        last_peer = Some(peer);

        match run_warp_in_warp(primary.clone(), secondary.clone(), peer, listen).await {
            Ok(()) => log::warn!("[-] gool tunnel closed; reconnecting"),
            Err(error) => log::warn!("[-] gool tunnel ended: {error}; reconnecting"),
        }
        consecutive_failures = consecutive_failures.saturating_add(1);
        tokio::time::sleep(wg_reconnect_delay()).await;
    }
}

fn install_netstack_panic_guard() {
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let from_netstack = info
            .location()
            .map(|location| location.file().contains("smoltcp"))
            .unwrap_or(false);
        if from_netstack {
            log::warn!("[netstack] smoltcp panic captured; stack task will stop: {info}");
        } else {
            default_hook(info);
        }
    }));
}

fn noize_config() -> noize::NoizeConfig {
    let profile = std::env::var("AETHER_NOIZE").unwrap_or_else(|_| "firewall".to_string());
    log::info!("[+] obfuscation profile: {profile}");
    noize::from_profile(&profile)
}

fn aethernoize_config() -> aethernoize::AetherNoizeConfig {
    let profile = std::env::var("AETHER_NOIZE").unwrap_or_else(|_| "balanced".to_string());
    log::info!("[+] aethernoize profile: {profile}");
    aethernoize::from_profile(&profile)
}

fn warp_config_path(base: &str) -> String {
    if let Ok(path) = std::env::var("AETHER_WG_CONFIG") {
        return path;
    }
    base.to_string()
}

fn masque_config_path(base: &str) -> String {
    if let Ok(path) = std::env::var("AETHER_MASQUE_CONFIG") {
        return path;
    }
    derive_sibling_path(base, "masque")
}

fn derive_sibling_path(base: &str, suffix: &str) -> String {
    let directory_end = base
        .rfind(|character| character == '/' || character == '\\')
        .map(|index| index + 1)
        .unwrap_or(0);
    match base[directory_end..].rfind('.') {
        Some(relative) => {
            let dot = directory_end + relative;
            format!("{}-{}{}", &base[..dot], suffix, &base[dot..])
        }
        None => format!("{base}-{suffix}"),
    }
}

async fn load_or_provision_warp(config_path: &str) -> Result<account::Identity> {
    if let Some(identity) = config::load(config_path)? {
        log::info!("[+] loaded existing warp identity from {config_path}");
        return Ok(identity);
    }

    log::info!("[+] no warp identity found; provisioning dedicated wireguard account");
    let identity =
        account::provision_wg(consts::DEFAULT_MODEL, consts::DEFAULT_LOCALE, None).await?;
    config::save(config_path, &identity)?;
    log::info!("[+] provisioned and saved new warp identity to {config_path}");
    Ok(identity)
}

async fn load_or_provision_masque(config_path: &str) -> Result<account::Identity> {
    if let Some(identity) = config::load(config_path)? {
        log::info!("[+] loaded existing masque identity from {config_path}");
        if identity.has_masque_credentials() {
            return Ok(identity);
        }
        log::info!("[+] masque identity missing credentials; enrolling masque key");
        let (cert_pem, key_pem) = account::ensure_masque_enrolled(&identity).await?;
        let identity = account::Identity {
            cert_pem,
            key_pem,
            ..identity
        };
        config::save(config_path, &identity)?;
        return Ok(identity);
    }

    log::info!("[+] no masque identity found; provisioning dedicated masque account");
    let identity =
        account::provision_wg(consts::DEFAULT_MODEL, consts::DEFAULT_LOCALE, None).await?;
    let (cert_pem, key_pem) = account::ensure_masque_enrolled(&identity).await?;
    let identity = account::Identity {
        cert_pem,
        key_pem,
        ..identity
    };
    config::save(config_path, &identity)?;
    log::info!("[+] provisioned and saved new masque identity to {config_path}");
    Ok(identity)
}

async fn select_peer(identity: &account::Identity, protocol: Protocol) -> Result<SocketAddr> {
    let forced_peer = match protocol {
        Protocol::Masque => std::env::var("AETHER_PEER").ok(),
        Protocol::WireGuard | Protocol::WarpInWarp => std::env::var("AETHER_WG_PEER")
            .ok()
            .or_else(|| std::env::var("AETHER_PEER").ok()),
    };

    if let Some(value) = forced_peer {
        let peer: SocketAddr = value
            .parse()
            .map_err(|_| AetherError::Other(format!("bad peer address {value}")))?;
        log::info!("[+] using forced peer {peer} (probe skipped)");
        return Ok(peer);
    }

    log::info!("[+] selected protocol: {}", protocol.label());
    let mode_string = select_scan_mode_str().await;
    let ip_mode = select_ip_version().await;
    let local_ipv4 = parse_local_v4(&identity.ipv4)?;

    match protocol {
        Protocol::Masque => {
            log::info!("[*] hunting for a working MASQUE gateway (deep connect-ip verification)");
            let mode = prober::ScanMode::parse(&mode_string);
            let probe = prober::MasqueProbe {
                sni: consts::CONNECT_SNI.to_string(),
                authority: quic::default_authority().to_string(),
                path: quic::default_path().to_string(),
                cert_pem: std::sync::Arc::from(identity.cert_pem.clone()),
                key_pem: std::sync::Arc::from(identity.key_pem.clone()),
                ech_config_list: None,
                noize: noize_config(),
                ports: prober::MASQUE_PORTS.to_vec(),
                ip: ip_mode,
                local_ipv4,
            };

            let best = prober::hunt_best_gateway(&probe, mode).await?;
            log::info!(
                "[+] selected MASQUE gateway {}:{} (rtt {:?})",
                best.ip,
                best.port,
                best.rtt
            );
            Ok(SocketAddr::new(best.ip, best.port))
        }
        Protocol::WireGuard | Protocol::WarpInWarp => {
            log::info!("[*] hunting for a working WireGuard endpoint (handshake + data-plane verification)");
            let mode = wg_prober::WgScanMode::parse(&mode_string);
            let private_key = identity.private_key_bytes()?;
            let peer_public_key = identity.peer_public_key_bytes()?;

            let probe = wg_prober::WgProbe {
                private_key: std::sync::Arc::new(private_key),
                peer_public_key: std::sync::Arc::new(peer_public_key),
                client_id: identity.client_id,
                local_ipv4,
                aethernoize: aethernoize_config(),
                ports: wireguard::WG_PORTS.to_vec(),
                ip: ip_mode,
            };

            let best = wg_prober::hunt_best_wg_endpoint(&probe, mode).await?;
            log::info!(
                "[+] selected WireGuard endpoint {}:{} (rtt {:?})",
                best.ip,
                best.port,
                best.rtt
            );
            Ok(SocketAddr::new(best.ip, best.port))
        }
    }
}

async fn resolve_ech() -> Option<Vec<u8>> {
    match std::env::var("AETHER_ECH") {
        Ok(value) if value.eq_ignore_ascii_case("auto") => match dns::fetch_ech_config().await {
            Ok(raw) => {
                log::info!("[+] fetched ECHConfigList automatically ({} bytes)", raw.len());
                Some(raw)
            }
            Err(error) => {
                log::warn!("[-] ECH auto-fetch failed ({error}); continuing without ECH");
                None
            }
        },
        Ok(base64) if !base64.is_empty() => match tls::decode_ech_config_list(&base64) {
            Ok(value) => {
                log::info!("[+] using ECHConfigList from AETHER_ECH");
                Some(value)
            }
            Err(error) => {
                log::warn!("[-] bad AETHER_ECH: {error}; continuing without ECH");
                None
            }
        },
        _ => {
            log::info!("[+] ECH disabled (warp masque endpoint does not accept ECH); SNI sent in cleartext");
            None
        }
    }
}

fn masque_reconnect_delay() -> Duration {
    bounded_env_duration("AETHER_MASQUE_RECONNECT_SECS", 2, 1, 60)
}

async fn hunt_masque_peer(
    identity: &account::Identity,
    mode_string: &str,
    ip_mode: prober::IpScan,
) -> Result<SocketAddr> {
    log::info!("[*] hunting for a working MASQUE gateway (deep connect-ip + data-plane verification)");
    let mode = prober::ScanMode::parse(mode_string);
    let probe = prober::MasqueProbe {
        sni: consts::CONNECT_SNI.to_string(),
        authority: quic::default_authority().to_string(),
        path: quic::default_path().to_string(),
        cert_pem: std::sync::Arc::from(identity.cert_pem.clone()),
        key_pem: std::sync::Arc::from(identity.key_pem.clone()),
        ech_config_list: None,
        noize: noize_config(),
        ports: prober::MASQUE_PORTS.to_vec(),
        ip: ip_mode,
        local_ipv4: parse_local_v4(&identity.ipv4)?,
    };

    let best = prober::hunt_best_gateway(&probe, mode).await?;
    log::info!(
        "[+] selected MASQUE gateway {}:{} (rtt {:?})",
        best.ip,
        best.port,
        best.rtt
    );
    Ok(SocketAddr::new(best.ip, best.port))
}

fn lastconn_path(config_path: &str) -> String {
    derive_sibling_path(config_path, "lastconn")
}

async fn quick_verify_masque_peer(identity: &account::Identity, peer: SocketAddr) -> bool {
    let local_ipv4 = match parse_local_v4(&identity.ipv4) {
        Ok(address) => address,
        Err(error) => {
            log::warn!("[-] cannot verify cached MASQUE peer: {error}");
            return false;
        }
    };

    let verify_params = quic::VerifyParams {
        peer,
        sni: consts::CONNECT_SNI.to_string(),
        authority: quic::default_authority().to_string(),
        path: quic::default_path().to_string(),
        cert_pem: identity.cert_pem.clone(),
        key_pem: identity.key_pem.clone(),
        ech_config_list: None,
        noize: noize_config(),
        timeout: Duration::from_secs(5),
        local_ipv4,
    };

    if masque_h2::enabled() {
        let config = masque_h2::H2TunnelConfig {
            peer: masque_h2::h2_peer(peer),
            sni: consts::CONNECT_SNI.to_string(),
            authority: quic::default_authority().to_string(),
            path: quic::default_path().to_string(),
            cert_pem: identity.cert_pem.clone(),
            key_pem: identity.key_pem.clone(),
            local_ipv4,
            quiet: true,
            pin_endpoint: true,
            expected_pins: consts::MASQUE_PINS.iter().map(|pin| pin.to_vec()).collect(),
        };
        return masque_h2::verify_h2(&config, Duration::from_secs(5))
            .await
            .is_ok();
    }

    quic::verify_masque(&verify_params).await.is_ok()
}

async fn want_quick_reconnect(cached: &lastconn::LastConnection) -> bool {
    match std::env::var("AETHER_QUICK_RECONNECT").as_deref() {
        Ok("1") | Ok("true") | Ok("yes") | Ok("on") => return true,
        Ok("0") | Ok("false") | Ok("no") | Ok("off") => return false,
        _ => {}
    }

    let answer = prompt_line(&format!(
        "\nLast working gateway: {} (profile '{}')\nReconnect to it now without rescanning? [Y/n]: ",
        cached.peer, cached.profile
    ))
    .await;

    !matches!(
        answer.as_deref(),
        Some(value) if value.eq_ignore_ascii_case("n") || value.eq_ignore_ascii_case("no")
    )
}

async fn run_masque(
    identity: account::Identity,
    ech: Option<Vec<u8>>,
    listen: SocketAddr,
    last_connection_path: String,
) -> Result<()> {
    let forced = std::env::var("AETHER_PEER").ok();
    let mut quick_peer: Option<SocketAddr> = None;

    if forced.is_none() {
        if let Some(cached) = lastconn::load(&last_connection_path) {
            if let Ok(peer) = cached.peer.parse::<SocketAddr>() {
                if want_quick_reconnect(&cached).await {
                    log::info!("[*] verifying cached gateway {peer} before reuse");
                    if quick_verify_masque_peer(&identity, peer).await {
                        log::info!("[+] cached gateway {peer} still works; skipping scan");
                        quick_peer = Some(peer);
                    } else {
                        log::warn!("[-] cached gateway {peer} no longer works; scanning fresh");
                    }
                }
            }
        }
    }

    let (mode_string, ip_mode) = if forced.is_some() || quick_peer.is_some() {
        (String::new(), prober::IpScan::V4)
    } else {
        (select_scan_mode_str().await, select_ip_version().await)
    };

    let mut last_good_peer: Option<SocketAddr> = None;

    loop {
        let peer = if let Some(peer) = quick_peer.take() {
            peer
        } else {
            let retried = match last_good_peer {
                Some(peer) => {
                    log::info!("[*] retrying last known-good gateway {peer} before rescanning");
                    if quick_verify_masque_peer(&identity, peer).await {
                        Some(peer)
                    } else {
                        log::warn!(
                            "[-] last known-good gateway {peer} no longer responds; rescanning"
                        );
                        None
                    }
                }
                None => None,
            };

            match retried {
                Some(peer) => peer,
                None => match &forced {
                    Some(value) => value
                        .parse::<SocketAddr>()
                        .map_err(|_| AetherError::Other(format!("bad peer address {value}")))?,
                    None => match hunt_masque_peer(&identity, &mode_string, ip_mode).await {
                        Ok(peer) => peer,
                        Err(error) => {
                            log::warn!(
                                "[-] no usable MASQUE gateway found: {error}; rescanning shortly"
                            );
                            tokio::time::sleep(masque_reconnect_delay()).await;
                            continue;
                        }
                    },
                },
            }
        };

        log::info!("[+] using cloudflare edge {peer}");
        if forced.is_none() {
            let profile =
                std::env::var("AETHER_NOIZE").unwrap_or_else(|_| "firewall".to_string());
            lastconn::save(&last_connection_path, &peer.to_string(), &profile);
        }
        last_good_peer = Some(peer);

        match run_masque_tunnel(&identity, peer, ech.clone(), listen).await {
            Ok(()) => log::warn!("[-] MASQUE tunnel closed; reconnecting"),
            Err(error) => log::warn!("[-] MASQUE tunnel ended: {error}; reconnecting"),
        }
        tokio::time::sleep(masque_reconnect_delay()).await;
    }
}

async fn run_masque_tunnel(
    identity: &account::Identity,
    peer: SocketAddr,
    ech: Option<Vec<u8>>,
    listen: SocketAddr,
) -> Result<()> {
    let local_ipv4 = parse_local_v4(&identity.ipv4)?;
    let (channels, internals) = quic::channels();

    let config = quic::TunnelConfig {
        peer,
        sni: consts::CONNECT_SNI.to_string(),
        authority: quic::default_authority().to_string(),
        path: quic::default_path().to_string(),
        cert_pem: identity.cert_pem.clone(),
        key_pem: identity.key_pem.clone(),
        ech_config_list: ech,
        noize: noize_config(),
        local_ipv4,
        quiet: false,
    };

    let quic::Channels {
        outbound_tx,
        inbound_rx,
        ctrl_tx,
    } = channels;
    let stack = netstack::spawn(
        &identity.ipv4,
        &identity.ipv6,
        TUNNEL_MTU,
        inbound_rx,
        outbound_tx,
    )?;
    let _control = ctrl_tx;

    let (address_tx, mut address_rx) = tokio::sync::mpsc::channel::<quic::AssignedAddr>(8);
    let address_stack = stack.clone();
    let address_task = tokio::spawn(async move {
        while let Some(address) = address_rx.recv().await {
            let result = match address.ip {
                IpAddr::V4(ipv4) => address_stack
                    .set_addrs(Some((ipv4, address.prefix)), None)
                    .await,
                IpAddr::V6(ipv6) => address_stack
                    .set_addrs(None, Some((ipv6, address.prefix)))
                    .await,
            };
            if let Err(error) = result {
                log::warn!("[-] failed to sync edge address into netstack: {error}");
            }
        }
    });

    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel::<()>();
    let mut tunnel_task = if masque_h2::enabled() {
        let h2_config = masque_h2::H2TunnelConfig {
            peer: masque_h2::h2_peer(peer),
            sni: consts::CONNECT_SNI.to_string(),
            authority: quic::default_authority().to_string(),
            path: quic::default_path().to_string(),
            cert_pem: identity.cert_pem.clone(),
            key_pem: identity.key_pem.clone(),
            local_ipv4,
            quiet: false,
            pin_endpoint: true,
            expected_pins: consts::MASQUE_PINS.iter().map(|pin| pin.to_vec()).collect(),
        };
        log::info!(
            "[+] MASQUE transport: HTTP/2 (TCP) to {}",
            h2_config.peer
        );
        tokio::spawn(masque_h2::run(
            h2_config,
            internals,
            Some(address_tx),
            Some(ready_tx),
        ))
    } else {
        log::info!("[+] MASQUE transport: HTTP/3 (QUIC) to {peer}");
        tokio::spawn(quic::run(
            config,
            internals,
            Some(address_tx),
            Some(ready_tx),
        ))
    };

    if ready_rx.await.is_err() {
        let result = (&mut tunnel_task).await;
        address_task.abort();
        return match result {
            Ok(Ok(())) => Err(AetherError::Other(
                "tunnel exited before validation".into(),
            )),
            Ok(Err(error)) => Err(AetherError::Other(format!(
                "tunnel failed before validation: {error}"
            ))),
            Err(error) => Err(AetherError::Other(format!(
                "tunnel task join error: {error}"
            ))),
        };
    }

    let socks_stack = stack.clone();
    let mut socks_task = tokio::spawn(async move {
        log::info!("[+] socks5 server listening on {listen}");
        socks::serve(listen, socks_stack).await
    });

    let result = tokio::select! {
        tunnel = &mut tunnel_task => flatten_runtime_task("MASQUE tunnel", tunnel),
        socks = &mut socks_task => flatten_runtime_task("SOCKS server", socks),
    };
    tunnel_task.abort();
    socks_task.abort();
    address_task.abort();
    result
}

fn wg_keepalive_secs() -> u16 {
    std::env::var("AETHER_WG_KEEPALIVE")
        .ok()
        .and_then(|value| value.parse::<u16>().ok())
        .map(|value| value.clamp(1, 120))
        .unwrap_or(5)
}

fn wg_profile_candidates() -> Vec<(String, aethernoize::AetherNoizeConfig)> {
    let primary = std::env::var("AETHER_NOIZE").unwrap_or_else(|_| "balanced".to_string());
    log::info!("[+] aethernoize primary profile: {primary}");

    let mut names = vec![primary.clone()];
    if std::env::var("AETHER_WG_NO_PROFILE_RETRY").is_err() {
        for fallback in ["balanced", "aggressive", "light", "off"] {
            if !names
                .iter()
                .any(|name| name.eq_ignore_ascii_case(fallback))
            {
                names.push(fallback.to_string());
            }
        }
    }

    names
        .into_iter()
        .map(|name| {
            let config = aethernoize::from_profile(&name);
            (name, config)
        })
        .collect()
}

async fn hunt_wg_peer_with_profile(
    identity: &account::Identity,
    mode_string: &str,
    ip_mode: prober::IpScan,
    profile: aethernoize::AetherNoizeConfig,
) -> Result<SocketAddr> {
    let mode = wg_prober::WgScanMode::parse(mode_string);
    let probe = wg_prober::WgProbe {
        private_key: std::sync::Arc::new(identity.private_key_bytes()?),
        peer_public_key: std::sync::Arc::new(identity.peer_public_key_bytes()?),
        client_id: identity.client_id,
        local_ipv4: parse_local_v4(&identity.ipv4)?,
        aethernoize: profile,
        ports: wireguard::WG_PORTS.to_vec(),
        ip: ip_mode,
    };

    let best = wg_prober::hunt_best_wg_endpoint(&probe, mode).await?;
    Ok(SocketAddr::new(best.ip, best.port))
}

fn wg_reconnect_delay() -> Duration {
    bounded_env_duration("AETHER_WG_RECONNECT_SECS", 2, 1, 60)
}

async fn hunt_wg_peer(
    identity: &account::Identity,
    candidates: &[(String, aethernoize::AetherNoizeConfig)],
    mode_string: &str,
    ip_mode: prober::IpScan,
) -> Result<(SocketAddr, aethernoize::AetherNoizeConfig, String)> {
    let multiple_profiles = candidates.len() > 1;
    for (name, profile) in candidates {
        log::info!(
            "[*] hunting for a working WireGuard endpoint (handshake + data-plane verification, aethernoize='{name}')"
        );
        match hunt_wg_peer_with_profile(identity, mode_string, ip_mode, profile.clone()).await {
            Ok(peer) => {
                log::info!(
                    "[+] selected WireGuard endpoint {peer} using aethernoize profile '{name}'"
                );
                return Ok((peer, profile.clone(), name.clone()));
            }
            Err(error) => {
                if multiple_profiles {
                    log::warn!(
                        "[-] profile '{name}' found no data-plane endpoint: {error}; trying next profile"
                    );
                } else {
                    log::warn!(
                        "[-] profile '{name}' found no data-plane endpoint: {error}"
                    );
                }
            }
        }
    }
    Err(AetherError::NoCleanEndpoint)
}

async fn run_wireguard(
    identity: account::Identity,
    listen: SocketAddr,
    last_connection_path: String,
) -> Result<()> {
    let candidates = wg_profile_candidates();
    let forced = std::env::var("AETHER_WG_PEER")
        .ok()
        .or_else(|| std::env::var("AETHER_PEER").ok());

    let private_key = identity.private_key_bytes()?;
    let peer_public_key = identity.peer_public_key_bytes()?;
    let local_ipv4 = parse_local_v4(&identity.ipv4)?;

    let mut quick: Option<(SocketAddr, aethernoize::AetherNoizeConfig, String)> = None;
    if forced.is_none() {
        if let Some(cached) = lastconn::load(&last_connection_path) {
            if let Ok(peer) = cached.peer.parse::<SocketAddr>() {
                if want_quick_reconnect(&cached).await {
                    let profile = aethernoize::from_profile(&cached.profile);
                    log::info!("[*] verifying cached WireGuard endpoint {peer} before reuse");
                    match wireguard::verify_endpoint(
                        peer,
                        private_key,
                        peer_public_key,
                        identity.client_id,
                        local_ipv4,
                        &profile,
                        Duration::from_secs(6),
                        Some(wg_keepalive_secs()),
                    )
                    .await
                    {
                        Ok(round_trip) => {
                            log::info!(
                                "[+] cached endpoint {peer} still works (rtt {round_trip:?}); skipping scan"
                            );
                            quick = Some((peer, profile, cached.profile.clone()));
                        }
                        Err(error) => {
                            log::warn!(
                                "[-] cached endpoint {peer} no longer works ({error}); scanning fresh"
                            );
                        }
                    }
                }
            }
        }
    }

    let (mode_string, ip_mode) = if forced.is_some() || quick.is_some() {
        (String::new(), prober::IpScan::V4)
    } else {
        (select_scan_mode_str().await, select_ip_version().await)
    };

    let mut last_good: Option<(SocketAddr, aethernoize::AetherNoizeConfig, String)> = None;
    let mut consecutive_failures: u32 = 0;
    const MAX_CONSECUTIVE_FAILURES: u32 = 2;

    loop {
        let (peer, profile, profile_name) = if let Some(quick_value) = quick.take() {
            quick_value
        } else {
            let retried = if consecutive_failures >= MAX_CONSECUTIVE_FAILURES {
                if let Some((peer, _, _)) = &last_good {
                    log::warn!(
                        "[-] endpoint {peer} failed {consecutive_failures} times in a row; blacklisting and rescanning"
                    );
                }
                None
            } else {
                match &last_good {
                    Some((peer, profile, _)) => {
                        log::info!(
                            "[*] retrying last known-good WireGuard endpoint {peer} before rescanning"
                        );
                        match wireguard::verify_endpoint(
                            *peer,
                            private_key,
                            peer_public_key,
                            identity.client_id,
                            local_ipv4,
                            profile,
                            Duration::from_secs(6),
                            Some(wg_keepalive_secs()),
                        )
                        .await
                        {
                            Ok(_) => last_good.clone(),
                            Err(error) => {
                                log::warn!(
                                    "[-] last known-good endpoint {peer} no longer responds ({error}); rescanning"
                                );
                                None
                            }
                        }
                    }
                    None => None,
                }
            };

            match retried {
                Some(value) => value,
                None => {
                    if let Some(value) = &forced {
                        let peer: SocketAddr = value.parse().map_err(|_| {
                            AetherError::Other(format!("bad peer address {value}"))
                        })?;
                        log::info!("[+] using forced peer {peer} (probe skipped)");

                        let mut chosen = None;
                        for (name, profile) in &candidates {
                            log::info!(
                                "[*] testing forced peer {peer} with aethernoize profile '{name}'"
                            );
                            match wireguard::verify_endpoint(
                                peer,
                                private_key,
                                peer_public_key,
                                identity.client_id,
                                local_ipv4,
                                profile,
                                Duration::from_secs(10),
                                Some(wg_keepalive_secs()),
                            )
                            .await
                            {
                                Ok(round_trip) => {
                                    log::info!(
                                        "[+] profile '{name}' passed handshake + data-plane (rtt {round_trip:?})"
                                    );
                                    chosen = Some((peer, profile.clone(), name.clone()));
                                    break;
                                }
                                Err(error) => {
                                    log::warn!(
                                        "[-] profile '{name}' failed on forced peer: {error}"
                                    );
                                }
                            }
                        }
                        chosen.ok_or(AetherError::NoCleanEndpoint)?
                    } else {
                        match hunt_wg_peer(&identity, &candidates, &mode_string, ip_mode).await {
                            Ok(value) => value,
                            Err(error) => {
                                log::warn!(
                                    "[-] no usable WireGuard endpoint found: {error}; rescanning shortly"
                                );
                                tokio::time::sleep(wg_reconnect_delay()).await;
                                continue;
                            }
                        }
                    }
                }
            }
        };

        log::info!("[+] using cloudflare edge {peer}");
        if forced.is_none() {
            lastconn::save(&last_connection_path, &peer.to_string(), &profile_name);
        }

        let same_peer = last_good
            .as_ref()
            .map(|(known_peer, _, _)| *known_peer)
            == Some(peer);
        if !same_peer {
            consecutive_failures = 0;
        }
        last_good = Some((peer, profile.clone(), profile_name));

        match run_wireguard_tunnel(identity.clone(), peer, profile, listen).await {
            Ok(()) => log::warn!("[-] WireGuard tunnel closed; reconnecting"),
            Err(error) => log::warn!("[-] WireGuard tunnel ended: {error}; reconnecting"),
        }
        consecutive_failures = consecutive_failures.saturating_add(1);
        tokio::time::sleep(wg_reconnect_delay()).await;
    }
}

fn wg_tunnel_validate_timeout() -> Duration {
    bounded_env_duration("AETHER_WG_VALIDATE_SECS", 10, 1, 120)
}

async fn run_wireguard_tunnel(
    identity: account::Identity,
    peer: SocketAddr,
    aethernoize: aethernoize::AetherNoizeConfig,
    listen: SocketAddr,
) -> Result<()> {
    let private_key = identity.private_key_bytes()?;
    let peer_public_key = identity.peer_public_key_bytes()?;
    let local_ipv4 = parse_local_v4(&identity.ipv4)?;

    log::info!(
        "[*] validating WireGuard tunnel with {peer} (handshake + data-plane) before exposing socks5..."
    );
    let (_, session) = wireguard::verify_endpoint_keep_session(
        peer,
        private_key,
        peer_public_key,
        identity.client_id,
        local_ipv4,
        &aethernoize,
        wg_tunnel_validate_timeout(),
        Some(wg_keepalive_secs()),
    )
    .await
    .map_err(|error| AetherError::Other(format!("tunnel failed validation: {error}")))?;
    log::info!("[+] wireguard tunnel validated (end-to-end data confirmed); exposing socks5");

    let (outbound_tx, outbound_rx) =
        tokio::sync::mpsc::channel(sysprofile::channel_capacity());
    let (inbound_tx, inbound_rx) =
        tokio::sync::mpsc::channel(sysprofile::channel_capacity());
    let tunnel = wireguard::WgTunnel::from_established(
        session,
        std::sync::Arc::new(aethernoize),
        inbound_tx,
        local_ipv4,
    );
    let stack = netstack::spawn(
        &identity.ipv4,
        &identity.ipv6,
        TUNNEL_MTU,
        inbound_rx,
        outbound_tx,
    )?;

    let mut tunnel_task = tokio::spawn(tunnel.run(outbound_rx));
    let socks_stack = stack.clone();
    let mut socks_task = tokio::spawn(async move {
        log::info!("[+] socks5 server listening on {listen}");
        socks::serve(listen, socks_stack).await
    });

    let result = tokio::select! {
        tunnel = &mut tunnel_task => flatten_runtime_task("WireGuard tunnel", tunnel),
        socks = &mut socks_task => flatten_runtime_task("SOCKS server", socks),
    };
    tunnel_task.abort();
    socks_task.abort();
    result
}

struct RunningWireGuard {
    stack: netstack::StackHandle,
    task: tokio::task::JoinHandle<Result<()>>,
}

impl Drop for RunningWireGuard {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn establish_wg(
    identity: &account::Identity,
    peer: SocketAddr,
    mtu: usize,
    obfuscate: bool,
    keepalive: u16,
    label: &'static str,
) -> Result<RunningWireGuard> {
    let private_key = identity.private_key_bytes()?;
    let peer_public_key = identity.peer_public_key_bytes()?;
    let local_ipv4 = parse_local_v4(&identity.ipv4)?;

    let profile = if obfuscate {
        aethernoize_config()
    } else {
        aethernoize::from_profile("off")
    };

    log::info!(
        "[*] [{label}] validating WireGuard tunnel with {peer} (handshake + data-plane)..."
    );
    let (_, session) = wireguard::verify_endpoint_keep_session(
        peer,
        private_key,
        peer_public_key,
        identity.client_id,
        local_ipv4,
        &profile,
        wg_tunnel_validate_timeout(),
        Some(keepalive.clamp(1, 120)),
    )
    .await
    .map_err(|error| {
        AetherError::Other(format!("[{label}] tunnel failed validation: {error}"))
    })?;
    log::info!("[+] [{label}] wireguard tunnel validated (end-to-end data confirmed)");

    let (outbound_tx, outbound_rx) =
        tokio::sync::mpsc::channel(sysprofile::channel_capacity());
    let (inbound_tx, inbound_rx) =
        tokio::sync::mpsc::channel(sysprofile::channel_capacity());
    let tunnel = wireguard::WgTunnel::from_established(
        session,
        std::sync::Arc::new(profile),
        inbound_tx,
        local_ipv4,
    );
    let stack = netstack::spawn(
        &identity.ipv4,
        &identity.ipv6,
        mtu,
        inbound_rx,
        outbound_tx,
    )?;
    let task = tokio::spawn(tunnel.run(outbound_rx));

    Ok(RunningWireGuard { stack, task })
}

struct UdpForwarder {
    local_address: SocketAddr,
    upload_task: tokio::task::JoinHandle<Result<()>>,
    download_task: tokio::task::JoinHandle<Result<()>>,
}

impl Drop for UdpForwarder {
    fn drop(&mut self) {
        self.upload_task.abort();
        self.download_task.abort();
    }
}

async fn spawn_udp_forwarder(
    outer: &netstack::StackHandle,
    remote: SocketAddr,
) -> Result<UdpForwarder> {
    let socket = std::sync::Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await?);
    let local_address = socket.local_addr()?;

    let udp = outer.open_udp().await?;
    let (udp_sender, mut udp_receiver) = udp.into_split();
    let inner_peer: std::sync::Arc<tokio::sync::Mutex<Option<SocketAddr>>> =
        std::sync::Arc::new(tokio::sync::Mutex::new(None));

    let upload_socket = socket.clone();
    let upload_peer = inner_peer.clone();
    let upload_task = tokio::spawn(async move {
        let mut buffer = vec![0u8; 65_535];
        loop {
            let (read, from) = upload_socket.recv_from(&mut buffer).await?;
            {
                let mut peer = upload_peer.lock().await;
                match *peer {
                    Some(expected) if expected != from => {
                        log::debug!(
                            "gool forwarder ignored unexpected inner UDP sender {from}"
                        );
                        continue;
                    }
                    None => *peer = Some(from),
                    _ => {}
                }
            }
            udp_sender
                .send_to(remote, buffer[..read].to_vec())
                .await?;
        }
        #[allow(unreachable_code)]
        Ok::<(), AetherError>(())
    });

    let download_socket = socket.clone();
    let download_peer = inner_peer.clone();
    let download_task = tokio::spawn(async move {
        while let Some((_source, data)) = udp_receiver.recv().await {
            let destination = *download_peer.lock().await;
            if let Some(destination) = destination {
                download_socket.send_to(&data, destination).await?;
            }
        }
        Err::<(), AetherError>(AetherError::Other(
            "gool outer UDP forwarder channel closed".into(),
        ))
    });

    Ok(UdpForwarder {
        local_address,
        upload_task,
        download_task,
    })
}

async fn run_warp_in_warp(
    primary: account::Identity,
    secondary: account::Identity,
    peer: SocketAddr,
    listen: SocketAddr,
) -> Result<()> {
    log::info!("[*] establishing outer WARP tunnel to {peer}...");
    let mut outer = establish_wg(
        &primary,
        peer,
        TUNNEL_MTU,
        true,
        wg_keepalive_secs(),
        "outer",
    )
    .await?;

    let mut forwarder = spawn_udp_forwarder(&outer.stack, peer).await?;
    log::info!(
        "[+] inner endpoint tunneled through outer warp via {}",
        forwarder.local_address
    );

    log::info!("[*] establishing inner WARP tunnel (warp-in-warp)...");
    let mut inner = establish_wg(
        &secondary,
        forwarder.local_address,
        INNER_MTU,
        false,
        20,
        "inner",
    )
    .await?;

    let socks_stack = inner.stack.clone();
    let mut socks_task = tokio::spawn(async move {
        log::info!("[+] socks5 server listening on {listen}");
        socks::serve(listen, socks_stack).await
    });

    let result = tokio::select! {
        outer_result = &mut outer.task => {
            flatten_runtime_task("gool outer tunnel", outer_result)
        }
        upload_result = &mut forwarder.upload_task => {
            flatten_runtime_task("gool forwarder upload", upload_result)
        }
        download_result = &mut forwarder.download_task => {
            flatten_runtime_task("gool forwarder download", download_result)
        }
        inner_result = &mut inner.task => {
            flatten_runtime_task("gool inner tunnel", inner_result)
        }
        socks_result = &mut socks_task => {
            flatten_runtime_task("gool SOCKS server", socks_result)
        }
    };

    socks_task.abort();
    result
}

fn flatten_runtime_task(
    label: &str,
    result: std::result::Result<Result<()>, tokio::task::JoinError>,
) -> Result<()> {
    match result {
        Ok(Ok(())) => Err(AetherError::Other(format!(
            "{label} ended unexpectedly"
        ))),
        Ok(Err(error)) => Err(AetherError::Other(format!("{label}: {error}"))),
        Err(error) => Err(AetherError::Other(format!(
            "{label} task failed: {error}"
        ))),
    }
}

async fn prompt_line(prompt: &str) -> Option<String> {
    use std::io::IsTerminal;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    if !std::io::stdin().is_terminal() {
        return None;
    }

    let mut stdout = tokio::io::stdout();
    let _ = stdout.write_all(prompt.as_bytes()).await;
    let _ = stdout.flush().await;

    let mut line = String::new();
    let mut reader = BufReader::new(tokio::io::stdin());
    match reader.read_line(&mut line).await {
        Ok(0) | Err(_) => None,
        Ok(_) => Some(line.trim().to_string()),
    }
}

const SCAN_MODE_PROMPT: &str = "\nScan mode:\n  [1] turbo     (fast, first hit)\n  [2] balanced  (default)\n  [3] thorough  (deep, best ping)\n  [4] stealth   (quiet, patient)\n  [5] ironclad  (real tunnel + real HTTP check per candidate, guaranteed working)\nChoose [1-5] (default 2): ";

async fn select_scan_mode() -> prober::ScanMode {
    if let Ok(value) = std::env::var("AETHER_SCAN") {
        return prober::ScanMode::parse(&value);
    }

    match prompt_line(SCAN_MODE_PROMPT).await.as_deref() {
        Some("1") => prober::ScanMode::Turbo,
        Some("3") => prober::ScanMode::Thorough,
        Some("4") => prober::ScanMode::Stealth,
        Some("5") => prober::ScanMode::Ironclad,
        _ => prober::ScanMode::Balanced,
    }
}

async fn select_scan_mode_str() -> String {
    if let Ok(value) = std::env::var("AETHER_SCAN") {
        return value;
    }

    match prompt_line(SCAN_MODE_PROMPT).await.as_deref() {
        Some("1") => "turbo".to_string(),
        Some("3") => "thorough".to_string(),
        Some("4") => "stealth".to_string(),
        Some("5") => "ironclad".to_string(),
        _ => "balanced".to_string(),
    }
}

async fn select_protocol() -> Protocol {
    if let Ok(value) = std::env::var("AETHER_PROTOCOL") {
        return Protocol::parse(&value);
    }

    let answer = prompt_line(
        "\nProtocol:\n  [1] MASQUE (modern, QUIC/H3, default)\n  [2] WireGuard (classic, faster)\n  [3] WARP-in-WARP / gool\nChoose [1-3] (default 1): ",
    )
    .await;

    match answer.as_deref() {
        Some("2") => Protocol::WireGuard,
        Some("3") => Protocol::WarpInWarp,
        _ => Protocol::Masque,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Protocol {
    Masque,
    WireGuard,
    WarpInWarp,
}

impl Protocol {
    fn parse(value: &str) -> Protocol {
        match value.trim().to_lowercase().as_str() {
            "wg" | "wireguard" => Protocol::WireGuard,
            "gool" | "wiw" | "warp-in-warp" | "warpinwarp" => Protocol::WarpInWarp,
            _ => Protocol::Masque,
        }
    }

    fn label(&self) -> &'static str {
        match self {
            Protocol::Masque => "MASQUE",
            Protocol::WireGuard => "WireGuard",
            Protocol::WarpInWarp => "WARP-in-WARP (gool)",
        }
    }
}

async fn select_masque_transport() {
    if std::env::var("AETHER_MASQUE_HTTP2").is_ok()
        || std::env::var("AETHER_PEER").is_ok()
    {
        return;
    }

    let answer = prompt_line(
        "\nMASQUE transport:\n  [1] HTTP/3 (QUIC)  (default; fastest handshake, best on healthy UDP networks)\n  [2] HTTP/2 (TCP)   (looks like ordinary HTTPS; use if UDP/QUIC is blocked or throttled)\nChoose [1-2] (default 1): ",
    )
    .await;

    if matches!(answer.as_deref(), Some("2")) {
        std::env::set_var("AETHER_MASQUE_HTTP2", "1");
    }
}

async fn select_ip_version() -> prober::IpScan {
    if let Ok(value) = std::env::var("AETHER_IP") {
        return prober::IpScan::parse(&value);
    }

    let answer = prompt_line(
        "\nIP version to scan:\n  [1] IPv4 (default)\n  [2] IPv6\n  [3] Both\nChoose [1-3] (default 1): ",
    )
    .await;

    match answer.as_deref() {
        Some("2") => prober::IpScan::V6,
        Some("3") => prober::IpScan::Both,
        _ => prober::IpScan::V4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_ipv4_parser_accepts_cidr_and_rejects_invalid_values() {
        assert_eq!(
            parse_local_v4("172.16.0.2/32").unwrap(),
            Ipv4Addr::new(172, 16, 0, 2)
        );
        assert!(parse_local_v4("invalid").is_err());
        assert!(parse_local_v4("0.0.0.0/32").is_err());
    }

    #[test]
    fn inner_mtu_stays_below_outer_mtu() {
        assert!(INNER_MTU < TUNNEL_MTU);
    }
}
