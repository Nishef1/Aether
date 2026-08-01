use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use boring::pkey::PKey;
use boring::ssl::{SslConnector, SslMethod, SslVersion};
use boring::x509::X509;
use bytes::Bytes;
use http::Method;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};

use crate::consts;
use crate::error::{AetherError, Result};
use crate::fragment::{FragmentConfig, FragmentingStream};
use crate::masque::{self, Capsule, CapsuleParser};
use crate::quic::{AssignedAddr, Control, Internals};
use crate::sysprofile::{self, Tier};
use crate::tls;

const H2_ALPN: &[u8] = b"\x02h2";
const CHROME_GROUPS: &str = "P-256:X25519:P-384";

const H2_WINDOW_MIN_BYTES: u32 = 64 * 1024;
const H2_WINDOW_MAX_BYTES: u32 = 64 * 1024 * 1024;
const H2_SEND_BUFFER_MIN_BYTES: usize = 64 * 1024;
const H2_SEND_BUFFER_MAX_BYTES: usize = 16 * 1024 * 1024;
const H2_MAX_HEADER_LIST_BYTES: u32 = 64 * 1024;
const DEFAULT_HEALTH_INTERVAL_SECS: u64 = 20;
const DEFAULT_HEALTH_TIMEOUT_SECS: u64 = 20;
const DEFAULT_HEALTH_FAILURES: u32 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct H2FlowControl {
    stream_window: u32,
    connection_window: u32,
    send_buffer: usize,
}

fn h2_defaults(tier: Tier) -> H2FlowControl {
    match tier {
        Tier::Low => H2FlowControl {
            stream_window: 1024 * 1024,
            connection_window: 2 * 1024 * 1024,
            send_buffer: 512 * 1024,
        },
        Tier::Medium => H2FlowControl {
            stream_window: 4 * 1024 * 1024,
            connection_window: 8 * 1024 * 1024,
            send_buffer: 1024 * 1024,
        },
        Tier::High => H2FlowControl {
            stream_window: 8 * 1024 * 1024,
            connection_window: 16 * 1024 * 1024,
            send_buffer: 2 * 1024 * 1024,
        },
    }
}

fn parse_bounded_u32(value: Option<&str>, default: u32, min: u32, max: u32) -> u32 {
    value
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .map(|parsed| parsed.clamp(min as u64, max as u64) as u32)
        .unwrap_or(default.clamp(min, max))
}

fn parse_bounded_usize(value: Option<&str>, default: usize, min: usize, max: usize) -> usize {
    value
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .map(|parsed| parsed.clamp(min as u64, max as u64) as usize)
        .unwrap_or(default.clamp(min, max))
}

fn h2_flow_control() -> H2FlowControl {
    let defaults = h2_defaults(sysprofile::tuning().tier);
    let stream_override = std::env::var("AETHER_MASQUE_H2_STREAM_WINDOW_BYTES").ok();
    let connection_override =
        std::env::var("AETHER_MASQUE_H2_CONNECTION_WINDOW_BYTES").ok();
    let send_buffer_override = std::env::var("AETHER_MASQUE_H2_SEND_BUFFER_BYTES").ok();

    let stream_window = parse_bounded_u32(
        stream_override.as_deref(),
        defaults.stream_window,
        H2_WINDOW_MIN_BYTES,
        H2_WINDOW_MAX_BYTES,
    );
    let connection_window = parse_bounded_u32(
        connection_override.as_deref(),
        defaults.connection_window,
        stream_window,
        H2_WINDOW_MAX_BYTES,
    );
    let send_buffer = parse_bounded_usize(
        send_buffer_override.as_deref(),
        defaults.send_buffer,
        H2_SEND_BUFFER_MIN_BYTES,
        H2_SEND_BUFFER_MAX_BYTES,
    );

    H2FlowControl {
        stream_window,
        connection_window,
        send_buffer,
    }
}

fn h2_client_builder(flow: H2FlowControl) -> h2::client::Builder {
    let mut builder = h2::client::Builder::new();
    builder
        .enable_push(false)
        .max_header_list_size(H2_MAX_HEADER_LIST_BYTES)
        .initial_window_size(flow.stream_window)
        .initial_connection_window_size(flow.connection_window)
        .max_send_buffer_size(flow.send_buffer);
    builder
}

struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

pub struct H2TunnelConfig {
    pub peer: SocketAddr,
    pub sni: String,
    pub authority: String,
    pub path: String,
    pub cert_pem: Vec<u8>,
    pub key_pem: Vec<u8>,
    pub local_ipv4: Ipv4Addr,
    pub quiet: bool,
    pub pin_endpoint: bool,
    pub expected_pins: Vec<Vec<u8>>,
}

fn log_or_debug(quiet: bool, message: String) {
    if quiet {
        log::debug!("{message}");
    } else {
        log::info!("{message}");
    }
}

fn data_check_enabled() -> bool {
    std::env::var("AETHER_MASQUE_NO_DATA_CHECK").is_err()
}

fn validation_timeout() -> Duration {
    let secs = std::env::var("AETHER_MASQUE_VALIDATE_SECS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .map(|value| value.clamp(1, 120))
        .unwrap_or(10);
    Duration::from_secs(secs)
}

const DATA_PROBE_REQUIRED_SUCCESSES: u32 = 2;

fn h2_keepalive_interval() -> Duration {
    let secs = std::env::var("AETHER_MASQUE_H2_KEEPALIVE_SECS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .map(|value| value.clamp(5, 300))
        .unwrap_or(DEFAULT_HEALTH_INTERVAL_SECS);
    Duration::from_secs(secs)
}

fn h2_keepalive_timeout() -> Duration {
    let secs = std::env::var("AETHER_MASQUE_H2_KEEPALIVE_TIMEOUT_SECS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .map(|value| value.clamp(1, 120))
        .unwrap_or(DEFAULT_HEALTH_TIMEOUT_SECS);
    Duration::from_secs(secs)
}

fn h2_health_failures() -> u32 {
    std::env::var("AETHER_MASQUE_HEALTH_FAILURES")
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .map(|value| value.clamp(1, 10))
        .unwrap_or(DEFAULT_HEALTH_FAILURES)
}

fn h2_keepalive_budget(timeout: Duration, failures: u32) -> Duration {
    timeout.saturating_mul(failures).max(Duration::from_secs(5))
}

pub fn enabled() -> bool {
    match std::env::var("AETHER_MASQUE_HTTP2") {
        Ok(value) => {
            let value = value.trim().to_lowercase();
            value == "1"
                || value == "true"
                || value == "h2"
                || value == "yes"
                || value == "on"
        }
        Err(_) => false,
    }
}

pub fn h2_peer(quic_peer: SocketAddr) -> SocketAddr {
    if let Ok(value) = std::env::var("AETHER_MASQUE_H2_PEER") {
        if let Ok(address) = value.trim().parse::<SocketAddr>() {
            return address;
        }
    }
    quic_peer
}

fn build_tls(cfg: &H2TunnelConfig) -> Result<boring::ssl::ConnectConfiguration> {
    let mut builder =
        SslConnector::builder(SslMethod::tls()).map_err(|error| AetherError::Tls(error.to_string()))?;

    builder
        .set_min_proto_version(Some(SslVersion::TLS1_2))
        .map_err(|error| AetherError::Tls(error.to_string()))?;
    builder
        .set_max_proto_version(Some(SslVersion::TLS1_3))
        .map_err(|error| AetherError::Tls(error.to_string()))?;

    builder.set_grease_enabled(true);

    let groups = std::env::var("AETHER_TLS_GROUPS").ok();
    let groups = groups
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(CHROME_GROUPS);
    builder
        .set_curves_list(groups)
        .map_err(|error| AetherError::Tls(error.to_string()))?;

    builder
        .set_alpn_protos(H2_ALPN)
        .map_err(|error| AetherError::Tls(error.to_string()))?;

    let cert = X509::from_pem(&cfg.cert_pem).map_err(|error| AetherError::Tls(error.to_string()))?;
    let key = PKey::private_key_from_pem(&cfg.key_pem)
        .map_err(|error| AetherError::Tls(error.to_string()))?;
    builder
        .set_certificate(&cert)
        .map_err(|error| AetherError::Tls(error.to_string()))?;
    builder
        .set_private_key(&key)
        .map_err(|error| AetherError::Tls(error.to_string()))?;

    let pin_refs: Vec<&[u8]> = cfg.expected_pins.iter().map(|pin| pin.as_slice()).collect();
    tls::install_verification(&mut *builder, cfg.pin_endpoint, &pin_refs)?;

    let connector = builder.build();
    let mut config = connector
        .configure()
        .map_err(|error| AetherError::Tls(error.to_string()))?;

    let use_pin_verification = cfg.pin_endpoint && !cfg.expected_pins.is_empty();
    config.set_verify_hostname(!use_pin_verification);
    config.set_use_server_name_indication(true);

    Ok(config)
}

fn build_connect_request(cfg: &H2TunnelConfig) -> Result<http::Request<()>> {
    let authority = format!("{}:443", cfg.authority);
    let uri = format!("https://{authority}");
    http::Request::builder()
        .method(Method::CONNECT)
        .uri(uri)
        .header("cf-connect-proto", consts::CF_CONNECT_PROTOCOL)
        .header("pq-enabled", "false")
        .header("user-agent", "")
        .body(())
        .map_err(|error| AetherError::Masque(format!("build request: {error}")))
}

pub async fn verify_h2(cfg: &H2TunnelConfig, timeout: Duration) -> Result<Duration> {
    let start = Instant::now();
    let data_check = data_check_enabled();

    let attempt = async {
        let tls_config = build_tls(cfg)?;
        let tcp = TcpStream::connect(cfg.peer).await.map_err(AetherError::Io)?;
        tcp.set_nodelay(true).map_err(AetherError::Io)?;
        let fragment = FragmentingStream::new(tcp, FragmentConfig::from_env());
        let tls = tokio_boring::connect(tls_config, &cfg.sni, fragment)
            .await
            .map_err(|error| AetherError::Tls(format!("h2 tls handshake: {error}")))?;
        let flow = h2_flow_control();
        let h2_builder = h2_client_builder(flow);
        let (h2, connection) = h2_builder
            .handshake(tls)
            .await
            .map_err(|error| AetherError::Masque(format!("h2 handshake: {error}")))?;
        let driver = tokio::spawn(async move {
            let _ = connection.await;
        });
        let mut h2 = h2
            .ready()
            .await
            .map_err(|error| AetherError::Masque(format!("h2 ready: {error}")))?;
        let request = build_connect_request(cfg)?;
        let (response_future, mut send_stream) = h2
            .send_request(request, false)
            .map_err(|error| AetherError::Masque(format!("send_request: {error}")))?;
        let response = response_future
            .await
            .map_err(|error| AetherError::Masque(format!("await response: {error}")))?;
        let status = response.status();
        if !status.is_success() {
            driver.abort();
            return Err(AetherError::Masque(format!(
                "h2 connect-ip status {}",
                status.as_u16()
            )));
        }

        if !data_check {
            driver.abort();
            return Ok(());
        }

        let mut recv_body = response.into_body();
        let mut capsules = CapsuleParser::new();
        let probe = masque::build_dns_probe_packet(cfg.local_ipv4);
        let framed = masque::encode_datagram_capsule(&probe);
        if let Err(error) = send_capsule(&mut send_stream, Bytes::from(framed)).await {
            driver.abort();
            return Err(error);
        }

        let mut probe_successes: u32 = 0;

        loop {
            match futures::future::poll_fn(|context| recv_body.poll_data(context)).await {
                Some(Ok(chunk)) => {
                    recv_body
                        .flow_control()
                        .release_capacity(chunk.len())
                        .map_err(|error| {
                            AetherError::Masque(format!("h2 release capacity: {error}"))
                        })?;
                    capsules.push(&chunk);
                    loop {
                        match capsules.next() {
                            Ok(Some(Capsule::Datagram(_))) => {
                                probe_successes += 1;
                                if probe_successes >= DATA_PROBE_REQUIRED_SUCCESSES {
                                    driver.abort();
                                    return Ok(());
                                }
                                let framed = masque::encode_datagram_capsule(&probe);
                                if let Err(error) =
                                    send_capsule(&mut send_stream, Bytes::from(framed)).await
                                {
                                    driver.abort();
                                    return Err(error);
                                }
                            }
                            Ok(Some(_)) => continue,
                            Ok(None) => break,
                            Err(error) => {
                                driver.abort();
                                return Err(AetherError::Masque(format!(
                                    "malformed h2 capsule stream: {error}"
                                )));
                            }
                        }
                    }
                }
                Some(Err(error)) => {
                    driver.abort();
                    return Err(AetherError::Masque(format!("h2 body: {error}")));
                }
                None => {
                    driver.abort();
                    return Err(AetherError::Masque(
                        "h2 stream closed before data confirmation".into(),
                    ));
                }
            }
        }
    };

    match tokio::time::timeout(timeout, attempt).await {
        Ok(Ok(())) => Ok(start.elapsed()),
        Ok(Err(error)) => Err(error),
        Err(_) => Err(AetherError::Other("h2 verify timeout".into())),
    }
}

pub async fn run(
    cfg: H2TunnelConfig,
    internals: Internals,
    addr_tx: Option<mpsc::Sender<AssignedAddr>>,
    ready_tx: Option<oneshot::Sender<()>>,
) -> Result<()> {
    let (mut outbound_rx, inbound_tx, mut ctrl_rx) = internals.into_parts();
    let quiet = cfg.quiet;
    let data_check = data_check_enabled();
    let probe_packet = masque::build_dns_probe_packet(cfg.local_ipv4);
    let mut ready_tx = ready_tx;
    let mut ready_fired = false;
    let mut validate_successes: u32 = 0;

    let tls_config = build_tls(&cfg)?;

    log_or_debug(quiet, format!("[h2] connecting tcp to {}", cfg.peer));
    let tcp = TcpStream::connect(cfg.peer).await.map_err(AetherError::Io)?;
    tcp.set_nodelay(true).map_err(AetherError::Io)?;

    let fragment_config = FragmentConfig::from_env();
    if fragment_config.enabled {
        log_or_debug(
            quiet,
            format!(
                "[h2] fragmenting client hello: size={}..{} delay={}..{}ms",
                fragment_config.size_min,
                fragment_config.size_max,
                fragment_config.delay_min_ms,
                fragment_config.delay_max_ms
            ),
        );
    }
    let fragment = FragmentingStream::new(tcp, fragment_config);

    let tls = tokio_boring::connect(tls_config, &cfg.sni, fragment)
        .await
        .map_err(|error| AetherError::Tls(format!("h2 tls handshake: {error}")))?;
    log_or_debug(
        quiet,
        format!(
            "[h2] tls established; alpn={}",
            String::from_utf8_lossy(tls.ssl().selected_alpn_protocol().unwrap_or(b""))
        ),
    );

    let flow = h2_flow_control();
    log_or_debug(
        quiet,
        format!(
            "[h2] flow control: stream={}KB connection={}KB send-buffer={}KB",
            flow.stream_window / 1024,
            flow.connection_window / 1024,
            flow.send_buffer / 1024
        ),
    );
    let h2_builder = h2_client_builder(flow);
    let (h2, mut connection) = h2_builder
        .handshake(tls)
        .await
        .map_err(|error| AetherError::Masque(format!("h2 handshake: {error}")))?;

    let mut ping_pong = connection
        .ping_pong()
        .ok_or_else(|| AetherError::Masque("h2 connection does not support ping".into()))?;

    let driver_handle = tokio::spawn(async move {
        if let Err(error) = connection.await {
            log::debug!("[h2] connection driver ended: {error}");
        }
    });
    let _driver_guard = AbortOnDrop(driver_handle);

    let mut h2 = h2
        .ready()
        .await
        .map_err(|error| AetherError::Masque(format!("h2 ready: {error}")))?;

    let request = build_connect_request(&cfg)?;
    let (response_future, mut send_stream) = h2
        .send_request(request, false)
        .map_err(|error| AetherError::Masque(format!("send_request: {error}")))?;
    log_or_debug(
        quiet,
        format!("[h2] connect-ip request sent to {}", cfg.authority),
    );

    let response = response_future
        .await
        .map_err(|error| AetherError::Masque(format!("await response: {error}")))?;
    let status = response.status();
    log_or_debug(
        quiet,
        format!("[h2] connect-ip status: {}", status.as_u16()),
    );
    if !status.is_success() {
        return Err(AetherError::Masque(format!(
            "h2 connect-ip status {}",
            status.as_u16()
        )));
    }

    let mut recv_body = response.into_body();
    let mut capsules = CapsuleParser::new();

    let mut validate_deadline: Option<Instant> = None;
    if data_check {
        let framed = masque::encode_datagram_capsule(&probe_packet);
        send_capsule(&mut send_stream, Bytes::from(framed)).await?;
        validate_deadline = Some(Instant::now() + validation_timeout());
        log_or_debug(
            quiet,
            "[h2] validating data-plane (end-to-end probe) before exposing socks5".to_string(),
        );
    } else if !ready_fired {
        ready_fired = true;
        if let Some(tx) = ready_tx.take() {
            let _ = tx.send(());
        }
    }

    let mut probe_interval = tokio::time::interval(Duration::from_millis(700));
    probe_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    let keepalive_period = h2_keepalive_interval();
    let mut keepalive_interval = tokio::time::interval(keepalive_period);
    keepalive_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut awaiting_pong = false;
    let mut pong_deadline: Option<Instant> = None;
    let keepalive_timeout = h2_keepalive_timeout();
    let health_failures = h2_health_failures();
    let keepalive_budget = h2_keepalive_budget(keepalive_timeout, health_failures);
    log::debug!(
        "[h2] health interval={keepalive_period:?} response-budget={keepalive_budget:?} failures={health_failures}"
    );

    loop {
        if data_check && !ready_fired {
            if let Some(deadline) = validate_deadline {
                if Instant::now() >= deadline {
                    log::warn!(
                        "[h2] data-plane validation timed out; edge accepts control but drops traffic"
                    );
                    let _ = send_stream.send_data(Bytes::new(), true);
                    return Err(AetherError::Masque(
                        "h2 data-plane validation timeout (CONNECT-IP accepted, no traffic)".into(),
                    ));
                }
            }
        }

        if let Some(deadline) = pong_deadline {
            if Instant::now() >= deadline {
                log::warn!(
                    "[h2] no PING response within {:?} ({} health periods); connection is stalled",
                    keepalive_budget,
                    health_failures
                );
                let _ = send_stream.send_data(Bytes::new(), true);
                return Err(AetherError::Masque("h2 keepalive timeout".into()));
            }
        }

        tokio::select! {
            biased;

            _ = keepalive_interval.tick(), if ready_fired && !awaiting_pong => {
                match ping_pong.send_ping(h2::Ping::opaque()) {
                    Ok(()) => {
                        awaiting_pong = true;
                        pong_deadline = Some(Instant::now() + keepalive_budget);
                        log::debug!("[h2] keepalive ping sent");
                    }
                    Err(error) => {
                        return Err(AetherError::Masque(format!(
                            "h2 keepalive ping could not be scheduled: {error}"
                        )));
                    }
                }
            }

            pong = std::future::poll_fn(|context| ping_pong.poll_pong(context)), if awaiting_pong => {
                match pong {
                    Ok(_) => {
                        awaiting_pong = false;
                        pong_deadline = None;
                        log::debug!("[h2] keepalive pong received");
                    }
                    Err(error) => {
                        log::warn!("[h2] keepalive ping failed: {error}");
                        let _ = send_stream.send_data(Bytes::new(), true);
                        return Err(AetherError::Masque(format!("h2 keepalive: {error}")));
                    }
                }
            }

            _ = probe_interval.tick(), if data_check && !ready_fired => {
                let framed = masque::encode_datagram_capsule(&probe_packet);
                if let Err(error) = send_capsule(&mut send_stream, Bytes::from(framed)).await {
                    return Err(AetherError::Masque(format!(
                        "h2 data-plane probe resend failed: {error}"
                    )));
                }
            }

            ctrl = ctrl_rx.recv() => {
                match ctrl {
                    Some(Control::Close) | None => {
                        let _ = send_stream.send_data(Bytes::new(), true);
                        log_or_debug(quiet, "[h2] closing tunnel".to_string());
                        return Ok(());
                    }
                    Some(Control::Migrate) => {
                        log::debug!("[h2] migration request ignored: TCP transport cannot migrate paths");
                    }
                }
            }

            packet = outbound_rx.recv() => {
                match packet {
                    Some(ip_packet) => {
                        let framed = masque::encode_datagram_capsule(&ip_packet);
                        send_capsule(&mut send_stream, Bytes::from(framed)).await?;
                    }
                    None => {
                        let _ = send_stream.send_data(Bytes::new(), true);
                        return Ok(());
                    }
                }
            }

            data = futures::future::poll_fn(|context| recv_body.poll_data(context)) => {
                match data {
                    Some(Ok(chunk)) => {
                        recv_body
                            .flow_control()
                            .release_capacity(chunk.len())
                            .map_err(|error| {
                                AetherError::Masque(format!("h2 release capacity: {error}"))
                            })?;
                        capsules.push(&chunk);
                        let got_data = drain_capsules(&mut capsules, &inbound_tx, &addr_tx);
                        if got_data && !ready_fired {
                            validate_successes += 1;
                            log::debug!(
                                "[h2] data-plane round-trip {}/{} confirmed",
                                validate_successes,
                                DATA_PROBE_REQUIRED_SUCCESSES
                            );
                            if validate_successes >= DATA_PROBE_REQUIRED_SUCCESSES {
                                ready_fired = true;
                                validate_deadline = None;
                                if let Some(tx) = ready_tx.take() {
                                    let _ = tx.send(());
                                }
                                log_or_debug(
                                    quiet,
                                    "[h2] tunnel validated (end-to-end data confirmed); exposing socks5"
                                        .to_string(),
                                );
                            } else {
                                let framed = masque::encode_datagram_capsule(&probe_packet);
                                send_capsule(&mut send_stream, Bytes::from(framed)).await?;
                            }
                        }
                    }
                    Some(Err(error)) => {
                        log::warn!("[h2] recv body error: {error}");
                        return Err(AetherError::Masque(format!("h2 body: {error}")));
                    }
                    None => {
                        return Err(AetherError::Masque(
                            "h2 server closed CONNECT-IP stream".into(),
                        ));
                    }
                }
            }
        }
    }
}

async fn send_capsule(send: &mut h2::SendStream<Bytes>, data: Bytes) -> Result<()> {
    let len = data.len();
    if len == 0 {
        return Ok(());
    }

    send.reserve_capacity(len);
    while send.capacity() < len {
        match futures::future::poll_fn(|context| send.poll_capacity(context)).await {
            Some(Ok(_)) => {}
            Some(Err(error)) => {
                return Err(AetherError::Masque(format!("h2 capacity: {error}")));
            }
            None => return Err(AetherError::Masque("h2 stream closed".into())),
        }
    }

    send.send_data(data, false)
        .map_err(|error| AetherError::Masque(format!("h2 send_data: {error}")))?;
    Ok(())
}

fn drain_capsules(
    capsules: &mut CapsuleParser,
    inbound_tx: &mpsc::Sender<Vec<u8>>,
    addr_tx: &Option<mpsc::Sender<AssignedAddr>>,
) -> bool {
    let mut delivered = false;
    loop {
        match capsules.next() {
            Ok(Some(Capsule::Datagram(payload))) => {
                let packet = match masque::strip_datagram_context(&payload) {
                    Some(packet) => packet,
                    None => {
                        log::trace!("[h2] discarding a datagram that is not an ip packet");
                        continue;
                    }
                };
                delivered = true;
                match inbound_tx.try_send(packet) {
                    Ok(()) => {}
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        log::trace!("[h2] inbound queue full, dropping datagram");
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => return delivered,
                }
            }
            Ok(Some(Capsule::AddressAssign(addrs))) => {
                for address in addrs {
                    if let Some(ip) = bytes_to_ip(address.ip_version, &address.address) {
                        log::info!("[h2] edge assigned {}/{}", ip, address.prefix_len);
                        if let Some(tx) = addr_tx {
                            let _ = tx.try_send(AssignedAddr {
                                ip,
                                prefix: address.prefix_len,
                            });
                        }
                    }
                }
            }
            Ok(Some(Capsule::RouteAdvertisement(routes))) => {
                log::info!("[h2] received {} route advertisements", routes.len());
            }
            Ok(Some(_)) => {}
            Ok(None) => break,
            Err(error) => {
                log::trace!("[h2] capsule parse: {error}");
                break;
            }
        }
    }
    delivered
}

fn bytes_to_ip(version: u8, bytes: &[u8]) -> Option<IpAddr> {
    match version {
        4 if bytes.len() == 4 => {
            Some(IpAddr::V4([bytes[0], bytes[1], bytes[2], bytes[3]].into()))
        }
        6 if bytes.len() == 16 => {
            let mut value = [0u8; 16];
            value.copy_from_slice(bytes);
            Some(IpAddr::V6(value.into()))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_window_parser_uses_clamped_defaults_and_overrides() {
        assert_eq!(parse_bounded_u32(None, 1024, 64, 4096), 1024);
        assert_eq!(parse_bounded_u32(Some("invalid"), 1024, 64, 4096), 1024);
        assert_eq!(parse_bounded_u32(Some("1"), 1024, 64, 4096), 64);
        assert_eq!(parse_bounded_u32(Some("9999"), 1024, 64, 4096), 4096);
        assert_eq!(parse_bounded_u32(Some(" 2048 "), 1024, 64, 4096), 2048);
        assert_eq!(parse_bounded_u32(None, 32, 64, 4096), 64);
        assert_eq!(parse_bounded_u32(None, 8192, 64, 4096), 4096);
        assert_eq!(parse_bounded_usize(None, 32, 64, 4096), 64);
    }

    #[test]
    fn resource_tiers_scale_flow_control_without_unbounded_memory() {
        let low = h2_defaults(Tier::Low);
        let medium = h2_defaults(Tier::Medium);
        let high = h2_defaults(Tier::High);

        assert!(low.stream_window < medium.stream_window);
        assert!(medium.stream_window < high.stream_window);
        assert!(low.connection_window >= low.stream_window);
        assert!(medium.connection_window >= medium.stream_window);
        assert!(high.connection_window >= high.stream_window);
        assert!(high.connection_window <= H2_WINDOW_MAX_BYTES);
        assert!(high.send_buffer <= H2_SEND_BUFFER_MAX_BYTES);
    }

    #[test]
    fn health_failure_budget_is_bounded_and_predictable() {
        assert_eq!(
            h2_keepalive_budget(Duration::from_secs(20), 3),
            Duration::from_secs(60)
        );
        assert_eq!(
            h2_keepalive_budget(Duration::from_secs(1), 1),
            Duration::from_secs(5)
        );
    }
}
