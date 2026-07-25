use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use rand::Rng;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex};

use crate::aethernoize::{self, AetherNoizeConfig};
use crate::error::{AetherError, Result};

const TIMER_TICK: Duration = Duration::from_millis(250);
const MAX_PACKET: usize = 65536;
const DEFAULT_WG_HEALTH_INTERVAL_SECS: u64 = 3;
const DEFAULT_WG_STALE_SECS: u64 = 15;
const DEFAULT_WG_STARTUP_SECS: u64 = 30;

const WG_MSG_TYPE_MIN: u8 = 1;
const WG_MSG_TYPE_MAX: u8 = 4;

fn inject_client_id(packet: &mut [u8], client_id: &[u8; 3]) {
    if packet.len() < 4 {
        return;
    }
    if packet[0] < WG_MSG_TYPE_MIN || packet[0] > WG_MSG_TYPE_MAX {
        return;
    }
    packet[1..4].copy_from_slice(client_id);
}

fn strip_client_id(packet: &mut [u8]) {
    if packet.len() < 4 {
        return;
    }
    if packet[0] < WG_MSG_TYPE_MIN || packet[0] > WG_MSG_TYPE_MAX {
        return;
    }
    packet[1..4].copy_from_slice(&[0u8; 3]);
}

#[derive(Clone)]
pub struct WgConfig {
    pub local_private_key: [u8; 32],
    pub peer_public_key: [u8; 32],
    pub peer_endpoint: SocketAddr,
    pub local_ipv4: Ipv4Addr,
    pub local_ipv6: Ipv6Addr,
    pub client_id: [u8; 3],
    pub preshared_key: Option<[u8; 32]>,
    pub persistent_keepalive: Option<u16>,
    pub aethernoize: Arc<AetherNoizeConfig>,
}

pub struct WgTunnel {
    tunn: Arc<Mutex<Box<Tunn>>>,
    sock: Arc<UdpSocket>,
    peer: SocketAddr,
    inbound_tx: mpsc::Sender<Vec<u8>>,
    pub obf_sent: Arc<Mutex<bool>>,
    pub aethernoize: Arc<AetherNoizeConfig>,
    pub client_id: [u8; 3],
    pub local_ipv4: Ipv4Addr,
    established: bool,
}

pub struct EstablishedSession {
    tunn: Arc<Mutex<Box<Tunn>>>,
    sock: Arc<UdpSocket>,
    peer: SocketAddr,
    client_id: [u8; 3],
}

impl WgTunnel {
    pub async fn new(cfg: WgConfig, inbound_tx: mpsc::Sender<Vec<u8>>) -> Result<Self> {
        let bind_addr = if cfg.peer_endpoint.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };

        let sock = UdpSocket::bind(bind_addr).await?;
        sock.connect(cfg.peer_endpoint).await?;

        let local_secret = StaticSecret::from(cfg.local_private_key);
        let peer_public = PublicKey::from(cfg.peer_public_key);
        let preshared = cfg.preshared_key;

        let tunn = Tunn::new(
            local_secret,
            peer_public,
            preshared,
            cfg.persistent_keepalive,
            0,
            None,
        )
        .map_err(|error| AetherError::Other(format!("wireguard tunnel init: {error}")))?;

        Ok(Self {
            tunn: Arc::new(Mutex::new(Box::new(tunn))),
            sock: Arc::new(sock),
            peer: cfg.peer_endpoint,
            inbound_tx,
            obf_sent: Arc::new(Mutex::new(false)),
            aethernoize: cfg.aethernoize.clone(),
            client_id: cfg.client_id,
            local_ipv4: cfg.local_ipv4,
            established: false,
        })
    }

    pub fn from_established(
        session: EstablishedSession,
        aethernoize: Arc<AetherNoizeConfig>,
        inbound_tx: mpsc::Sender<Vec<u8>>,
        local_ipv4: Ipv4Addr,
    ) -> Self {
        Self {
            tunn: session.tunn,
            sock: session.sock,
            peer: session.peer,
            inbound_tx,
            obf_sent: Arc::new(Mutex::new(true)),
            aethernoize,
            client_id: session.client_id,
            local_ipv4,
            established: true,
        }
    }

    pub async fn run(self, mut outbound_rx: mpsc::Receiver<Vec<u8>>) -> Result<()> {
        let sock_r = self.sock.clone();
        let sock_w = self.sock.clone();
        let sock_t = self.sock.clone();
        let sock_h = self.sock.clone();
        let tunn_r = self.tunn.clone();
        let tunn_w = self.tunn.clone();
        let tunn_t = self.tunn.clone();
        let tunn_h = self.tunn.clone();
        let inbound_tx = self.inbound_tx.clone();
        let obf_sent = self.obf_sent.clone();
        let aethernoize = self.aethernoize.clone();
        let aethernoize_r = self.aethernoize.clone();
        let aethernoize_t = self.aethernoize.clone();
        let client_id = self.client_id;
        let client_id_r = self.client_id;
        let client_id_h = self.client_id;
        let peer = self.peer;
        let local_ipv4 = self.local_ipv4;

        let last_valid_rx: Arc<StdMutex<Instant>> = Arc::new(StdMutex::new(Instant::now()));
        let last_valid_rx_r = last_valid_rx.clone();
        let last_valid_rx_h = last_valid_rx.clone();
        let ever_received = Arc::new(AtomicBool::new(self.established));
        let ever_received_r = ever_received.clone();
        let ever_received_h = ever_received.clone();
        let started_at = Instant::now();

        let recv_task = tokio::spawn(async move {
            let mut buffer = vec![0u8; MAX_PACKET];
            let mut temporary = vec![0u8; MAX_PACKET];
            loop {
                let read = sock_r.recv(&mut buffer).await.map_err(|error| {
                    AetherError::Other(format!("wireguard receive failed: {error}"))
                })?;
                strip_client_id(&mut buffer[..read]);
                let mut tunn = tunn_r.lock().await;
                match tunn.decapsulate(None, &buffer[..read], &mut temporary) {
                    TunnResult::Done => {
                        mark_valid_rx(&last_valid_rx_r, &ever_received_r);
                        drop(tunn);
                        aethernoize::send_post_handshake_junk(
                            &sock_r,
                            peer,
                            &aethernoize_r,
                        )
                        .await;
                    }
                    TunnResult::Err(error) => {
                        log::trace!("decapsulate error: {error:?}");
                    }
                    TunnResult::WriteToNetwork(packet) => {
                        mark_valid_rx(&last_valid_rx_r, &ever_received_r);
                        let mut packet = packet.to_vec();
                        inject_client_id(&mut packet, &client_id_r);
                        drop(tunn);
                        sock_r.send(&packet).await.map_err(|error| {
                            AetherError::Other(format!(
                                "wireguard handshake response send failed: {error}"
                            ))
                        })?;
                        aethernoize::send_post_handshake_junk(
                            &sock_r,
                            peer,
                            &aethernoize_r,
                        )
                        .await;
                    }
                    TunnResult::WriteToTunnelV4(packet, _)
                    | TunnResult::WriteToTunnelV6(packet, _) => {
                        mark_valid_rx(&last_valid_rx_r, &ever_received_r);
                        let packet = packet.to_vec();
                        drop(tunn);
                        inbound_tx.send(packet).await.map_err(|_| {
                            AetherError::Other("wireguard netstack input channel closed".into())
                        })?;
                        aethernoize::send_post_handshake_junk(
                            &sock_r,
                            peer,
                            &aethernoize_r,
                        )
                        .await;
                    }
                }
            }
            #[allow(unreachable_code)]
            Ok::<(), AetherError>(())
        });

        let send_task = tokio::spawn(async move {
            let mut output = vec![0u8; MAX_PACKET];
            while let Some(ip_packet) = outbound_rx.recv().await {
                let mut tunn = tunn_w.lock().await;
                match tunn.encapsulate(&ip_packet, &mut output) {
                    TunnResult::Done => {}
                    TunnResult::Err(error) => {
                        log::trace!("encapsulate error: {error:?}");
                    }
                    TunnResult::WriteToNetwork(packet) => {
                        let mut packet = packet.to_vec();
                        inject_client_id(&mut packet, &client_id);
                        drop(tunn);

                        {
                            let mut sent = obf_sent.lock().await;
                            if !*sent && aethernoize.is_enabled() {
                                *sent = true;
                                drop(sent);
                                aethernoize::apply_obfuscation(
                                    &sock_w,
                                    peer,
                                    &aethernoize,
                                )
                                .await;
                            }
                        }

                        sock_w.send(&packet).await.map_err(|error| {
                            AetherError::Other(format!("wireguard send failed: {error}"))
                        })?;
                    }
                    TunnResult::WriteToTunnelV4(_, _)
                    | TunnResult::WriteToTunnelV6(_, _) => {}
                }
            }
            Err::<(), AetherError>(AetherError::Other(
                "wireguard outbound channel closed".into(),
            ))
        });

        let timer_task = tokio::spawn(async move {
            let mut interval = tokio::time::interval(TIMER_TICK);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let mut temporary = vec![0u8; MAX_PACKET];
            loop {
                interval.tick().await;
                let mut tunn = tunn_t.lock().await;
                if let TunnResult::WriteToNetwork(packet) = tunn.update_timers(&mut temporary) {
                    let mut packet = packet.to_vec();
                    inject_client_id(&mut packet, &client_id);
                    drop(tunn);

                    if aethernoize_t.is_enabled() {
                        aethernoize::send_keepalive_junk(&sock_t, &aethernoize_t).await;
                    }
                    sock_t.send(&packet).await.map_err(|error| {
                        AetherError::Other(format!("wireguard timer send failed: {error}"))
                    })?;
                }
            }
            #[allow(unreachable_code)]
            Ok::<(), AetherError>(())
        });

        let stale_timeout = wg_stale_timeout();
        let startup_timeout = wg_startup_timeout();
        let health_interval = wg_healthcheck_interval();
        let health_task = tokio::spawn(async move {
            let mut interval = tokio::time::interval(health_interval);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let probe = build_dataplane_probe(local_ipv4);
            let mut output = vec![0u8; MAX_PACKET];
            loop {
                interval.tick().await;

                let received = ever_received_h.load(Ordering::Relaxed);
                let idle = valid_rx_idle(&last_valid_rx_h);
                if !received && started_at.elapsed() >= startup_timeout {
                    log::warn!(
                        "[wg] no valid response from peer {} during startup window {:?}",
                        peer,
                        startup_timeout
                    );
                    return Err::<(), AetherError>(AetherError::Other(
                        "wireguard startup timeout: no valid peer response".into(),
                    ));
                }
                if received && idle >= stale_timeout {
                    log::warn!(
                        "[wg] no valid data from peer {} in {:?}; tunnel considered dead",
                        peer,
                        idle
                    );
                    return Err::<(), AetherError>(AetherError::Other(
                        "wireguard tunnel stale: no valid data from peer".into(),
                    ));
                }

                let mut tunn = tunn_h.lock().await;
                send_dataplane_probe(
                    &sock_h,
                    &mut tunn,
                    &client_id_h,
                    &probe,
                    &mut output,
                )
                .await?;
            }
        });

        let recv_abort = recv_task.abort_handle();
        let send_abort = send_task.abort_handle();
        let timer_abort = timer_task.abort_handle();
        let health_abort = health_task.abort_handle();

        let result = tokio::select! {
            result = recv_task => flatten_task_result("receive", result),
            result = send_task => flatten_task_result("send", result),
            result = timer_task => flatten_task_result("timer", result),
            result = health_task => flatten_task_result("health", result),
        };

        recv_abort.abort();
        send_abort.abort();
        timer_abort.abort();
        health_abort.abort();

        result
    }
}

fn flatten_task_result(
    name: &str,
    result: std::result::Result<Result<()>, tokio::task::JoinError>,
) -> Result<()> {
    match result {
        Ok(Ok(())) => Err(AetherError::Other(format!(
            "wireguard {name} task ended unexpectedly"
        ))),
        Ok(Err(error)) => Err(error),
        Err(error) => Err(AetherError::Other(format!(
            "wireguard {name} task failed: {error}"
        ))),
    }
}

fn mark_valid_rx(last_valid_rx: &StdMutex<Instant>, ever_received: &AtomicBool) {
    if let Ok(mut last) = last_valid_rx.lock() {
        *last = Instant::now();
    }
    ever_received.store(true, Ordering::Relaxed);
}

fn valid_rx_idle(last_valid_rx: &StdMutex<Instant>) -> Duration {
    last_valid_rx
        .lock()
        .map(|last| last.elapsed())
        .unwrap_or(Duration::MAX)
}

fn bounded_env_secs(name: &str, default: u64, min: u64, max: u64) -> Duration {
    let seconds = std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .map(|value| value.clamp(min, max))
        .unwrap_or(default.clamp(min, max));
    Duration::from_secs(seconds)
}

fn wg_healthcheck_interval() -> Duration {
    bounded_env_secs(
        "AETHER_WG_HEALTH_INTERVAL_SECS",
        DEFAULT_WG_HEALTH_INTERVAL_SECS,
        1,
        60,
    )
}

fn wg_stale_timeout() -> Duration {
    let configured = bounded_env_secs(
        "AETHER_WG_STALE_SECS",
        DEFAULT_WG_STALE_SECS,
        6,
        300,
    );
    configured.max(wg_healthcheck_interval().saturating_mul(2))
}

fn wg_startup_timeout() -> Duration {
    bounded_env_secs(
        "AETHER_WG_STARTUP_SECS",
        DEFAULT_WG_STARTUP_SECS,
        10,
        300,
    )
}

fn build_dns_query() -> Vec<u8> {
    let id: u16 = rand::random();
    let mut query = Vec::with_capacity(32);
    query.extend_from_slice(&id.to_be_bytes());
    query.extend_from_slice(&[0x01, 0x00]);
    query.extend_from_slice(&[0x00, 0x01]);
    query.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    for label in ["cloudflare", "com"] {
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0x00);
    query.extend_from_slice(&[0x00, 0x01]);
    query.extend_from_slice(&[0x00, 0x01]);
    query
}

fn ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut index = 0;
    while index + 1 < header.len() {
        sum += u16::from_be_bytes([header[index], header[index + 1]]) as u32;
        index += 2;
    }
    if index < header.len() {
        sum += (header[index] as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn build_dataplane_probe(source: Ipv4Addr) -> Vec<u8> {
    let dns = build_dns_query();
    let udp_len = 8 + dns.len();
    let total_len = 20 + udp_len;
    let mut packet = Vec::with_capacity(total_len);
    packet.push(0x45);
    packet.push(0x00);
    packet.extend_from_slice(&(total_len as u16).to_be_bytes());
    let id: u16 = rand::random();
    packet.extend_from_slice(&id.to_be_bytes());
    packet.extend_from_slice(&[0x00, 0x00]);
    packet.push(64);
    packet.push(17);
    packet.extend_from_slice(&[0x00, 0x00]);
    packet.extend_from_slice(&source.octets());
    packet.extend_from_slice(&Ipv4Addr::new(8, 8, 8, 8).octets());
    let checksum = ipv4_checksum(&packet[0..20]);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());
    let source_port: u16 = rand::thread_rng().gen_range(20000..60000);
    packet.extend_from_slice(&source_port.to_be_bytes());
    packet.extend_from_slice(&53u16.to_be_bytes());
    packet.extend_from_slice(&(udp_len as u16).to_be_bytes());
    packet.extend_from_slice(&[0x00, 0x00]);
    packet.extend_from_slice(&dns);
    packet
}

async fn send_dataplane_probe(
    sock: &UdpSocket,
    tunn: &mut Tunn,
    client_id: &[u8; 3],
    probe: &[u8],
    output: &mut [u8],
) -> Result<()> {
    match tunn.encapsulate(probe, output) {
        TunnResult::WriteToNetwork(packet) => {
            let mut packet = packet.to_vec();
            inject_client_id(&mut packet, client_id);
            sock.send(&packet).await?;
        }
        TunnResult::Err(error) => {
            return Err(AetherError::Other(format!(
                "dataplane encapsulation failed: {error:?}"
            )));
        }
        TunnResult::Done => {
            return Err(AetherError::Other(
                "dataplane probe produced no network packet".into(),
            ));
        }
        TunnResult::WriteToTunnelV4(_, _)
        | TunnResult::WriteToTunnelV6(_, _) => {
            return Err(AetherError::Other(
                "dataplane probe was routed to tunnel unexpectedly".into(),
            ));
        }
    }
    Ok(())
}

const DATAPLANE_REQUIRED_SUCCESSES: u32 = 2;
const DATAPLANE_PROBE_GAP: Duration = Duration::from_millis(600);
const DATAPLANE_RESEND_INTERVAL: Duration = Duration::from_millis(700);

async fn verify_dataplane(
    sock: &UdpSocket,
    tunn: &mut Tunn,
    client_id: &[u8; 3],
    local_ipv4: Ipv4Addr,
    start: Instant,
    deadline: Instant,
) -> Result<Duration> {
    let probe = build_dataplane_probe(local_ipv4);
    let mut output = vec![0u8; MAX_PACKET];
    let mut recv_buffer = vec![0u8; MAX_PACKET];
    let mut temporary = vec![0u8; MAX_PACKET];

    let mut successes: u32 = 0;
    send_dataplane_probe(sock, tunn, client_id, &probe, &mut output).await?;
    let mut resend_at = Instant::now() + DATAPLANE_RESEND_INTERVAL;

    loop {
        let now = Instant::now();
        if now >= deadline {
            log::debug!(
                "[wg] dataplane verify timed out ({}/{} confirmations)",
                successes,
                DATAPLANE_REQUIRED_SUCCESSES
            );
            return Err(AetherError::Other("dataplane timeout".into()));
        }
        if now >= resend_at {
            send_dataplane_probe(sock, tunn, client_id, &probe, &mut output).await?;
            resend_at = now + DATAPLANE_RESEND_INTERVAL;
        }
        let wait = deadline
            .saturating_duration_since(now)
            .min(resend_at.saturating_duration_since(now));

        tokio::select! {
            result = sock.recv(&mut recv_buffer) => {
                let read = result?;
                strip_client_id(&mut recv_buffer[..read]);
                match tunn.decapsulate(None, &recv_buffer[..read], &mut temporary) {
                    TunnResult::WriteToTunnelV4(_, _)
                    | TunnResult::WriteToTunnelV6(_, _) => {
                        successes += 1;
                        log::debug!(
                            "[wg] dataplane round-trip {}/{} confirmed in {:?}",
                            successes,
                            DATAPLANE_REQUIRED_SUCCESSES,
                            start.elapsed()
                        );
                        if successes >= DATAPLANE_REQUIRED_SUCCESSES {
                            let elapsed = start.elapsed();
                            log::debug!("[wg] dataplane ok in {elapsed:?}");
                            return Ok(elapsed);
                        }
                        resend_at = Instant::now() + DATAPLANE_PROBE_GAP;
                    }
                    TunnResult::WriteToNetwork(packet) => {
                        let mut packet = packet.to_vec();
                        inject_client_id(&mut packet, client_id);
                        sock.send(&packet).await?;
                    }
                    TunnResult::Err(error) => {
                        log::trace!("[wg] dataplane decapsulation error: {error:?}");
                    }
                    TunnResult::Done => {}
                }
            }
            _ = tokio::time::sleep(wait) => {}
        }
    }
}

pub async fn verify_endpoint(
    peer: SocketAddr,
    private_key: [u8; 32],
    peer_public: [u8; 32],
    client_id: [u8; 3],
    local_ipv4: Ipv4Addr,
    aethernoize: &AetherNoizeConfig,
    timeout: Duration,
    keepalive: Option<u16>,
) -> Result<Duration> {
    let (elapsed, _session) = verify_endpoint_keep_session(
        peer,
        private_key,
        peer_public,
        client_id,
        local_ipv4,
        aethernoize,
        timeout,
        keepalive,
    )
    .await?;
    Ok(elapsed)
}

pub async fn verify_endpoint_keep_session(
    peer: SocketAddr,
    private_key: [u8; 32],
    peer_public: [u8; 32],
    client_id: [u8; 3],
    local_ipv4: Ipv4Addr,
    aethernoize: &AetherNoizeConfig,
    timeout: Duration,
    keepalive: Option<u16>,
) -> Result<(Duration, EstablishedSession)> {
    let data_check = std::env::var("AETHER_WG_NO_DATA_CHECK").is_err();
    log::trace!(
        "[wg] verify {} obf={} data_check={}",
        peer,
        aethernoize.is_enabled(),
        data_check
    );

    let bind = if peer.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let sock = UdpSocket::bind(bind).await?;
    sock.connect(peer).await?;

    let start = Instant::now();
    let deadline = start + timeout;

    if aethernoize.is_enabled() {
        aethernoize::apply_obfuscation(&sock, peer, aethernoize).await;
    }

    let local_secret = StaticSecret::from(private_key);
    let peer_key = PublicKey::from(peer_public);

    let mut tunn = Tunn::new(
        local_secret,
        peer_key,
        None,
        Some(keepalive.unwrap_or(25).clamp(1, 120)),
        0,
        None,
    )
    .map_err(|error| AetherError::Other(format!("tunnel init: {error}")))?;

    let mut output = vec![0u8; MAX_PACKET];
    let mut recv_buffer = vec![0u8; MAX_PACKET];
    let mut temporary = vec![0u8; MAX_PACKET];

    match tunn.encapsulate(&[], &mut output) {
        TunnResult::WriteToNetwork(packet) => {
            let mut packet = packet.to_vec();
            inject_client_id(&mut packet, &client_id);
            log::trace!("[wg] sending init {} bytes to {}", packet.len(), peer);
            sock.send(&packet).await?;
        }
        other => {
            log::warn!("[wg] unexpected initial encapsulation result: {other:?}");
            return Err(AetherError::Other("handshake init failed".into()));
        }
    }

    let mut attempts = 0;
    loop {
        if Instant::now() >= deadline {
            log::trace!("[wg] timeout after {attempts} receive attempts");
            return Err(AetherError::Other("verify timeout".into()));
        }

        let remaining = deadline.saturating_duration_since(Instant::now());

        tokio::select! {
            result = sock.recv(&mut recv_buffer) => {
                attempts += 1;
                let read = result?;
                log::trace!("[wg] recv {read} bytes (attempt {attempts})");
                strip_client_id(&mut recv_buffer[..read]);

                match tunn.decapsulate(None, &recv_buffer[..read], &mut temporary) {
                    TunnResult::Done => {
                        let elapsed = start.elapsed();
                        log::trace!("[wg] handshake done in {elapsed:?}");
                        if data_check {
                            let dataplane_elapsed = verify_dataplane(
                                &sock,
                                &mut tunn,
                                &client_id,
                                local_ipv4,
                                start,
                                deadline,
                            )
                            .await?;
                            return Ok((
                                dataplane_elapsed,
                                EstablishedSession {
                                    tunn: Arc::new(Mutex::new(Box::new(tunn))),
                                    sock: Arc::new(sock),
                                    peer,
                                    client_id,
                                },
                            ));
                        }
                        return Ok((
                            elapsed,
                            EstablishedSession {
                                tunn: Arc::new(Mutex::new(Box::new(tunn))),
                                sock: Arc::new(sock),
                                peer,
                                client_id,
                            },
                        ));
                    }
                    TunnResult::WriteToNetwork(packet) => {
                        let mut packet = packet.to_vec();
                        inject_client_id(&mut packet, &client_id);
                        log::trace!("[wg] sending response {} bytes", packet.len());
                        sock.send(&packet).await?;
                        let elapsed = start.elapsed();
                        log::trace!("[wg] handshake success in {elapsed:?}");
                        if data_check {
                            let dataplane_elapsed = verify_dataplane(
                                &sock,
                                &mut tunn,
                                &client_id,
                                local_ipv4,
                                start,
                                deadline,
                            )
                            .await?;
                            return Ok((
                                dataplane_elapsed,
                                EstablishedSession {
                                    tunn: Arc::new(Mutex::new(Box::new(tunn))),
                                    sock: Arc::new(sock),
                                    peer,
                                    client_id,
                                },
                            ));
                        }
                        return Ok((
                            elapsed,
                            EstablishedSession {
                                tunn: Arc::new(Mutex::new(Box::new(tunn))),
                                sock: Arc::new(sock),
                                peer,
                                client_id,
                            },
                        ));
                    }
                    TunnResult::Err(error) => {
                        log::trace!("[wg] decapsulation error: {error:?}");
                    }
                    other => {
                        log::trace!("[wg] unexpected decapsulation result: {other:?}");
                    }
                }
            }
            _ = tokio::time::sleep(remaining) => {
                log::trace!("[wg] verification wait timed out");
                return Err(AetherError::Other("verify timeout".into()));
            }
        }
    }
}

pub const WG_PREFIXES_V4: &[&str] = &[
    "162.159.192.0/24",
    "162.159.195.0/24",
    "188.114.96.0/24",
    "188.114.97.0/24",
    "188.114.98.0/24",
    "188.114.99.0/24",
];

pub const WG_PREFIXES_V6: &[&str] = &["2606:4700:d0::/64", "2606:4700:d1::/64"];

pub const WG_PORTS: &[u16] = &[
    500, 854, 859, 864, 878, 880, 890, 891, 894, 903, 908, 928, 934, 939, 942, 943, 945,
    946, 955, 968, 987, 988, 1002, 1010, 1014, 1018, 1070, 1074, 1180, 1387, 1701,
    1843, 2371, 2408, 2506, 3138, 3476, 3581, 3854, 4177, 4198, 4233, 4500, 5279,
    5956, 7103, 7152, 7156, 7281, 7559, 8319, 8742, 8854, 8886,
];

pub const WG_SEEDS_V4: &[&str] = &[
    "162.159.192.1",
    "162.159.195.1",
    "188.114.96.1",
    "188.114.97.1",
];

pub const WG_SEEDS_V6: &[&str] = &[
    "2606:4700:d0::a29f:c001",
    "2606:4700:d1::a29f:c001",
    "2606:4700:d0::a29f:c301",
    "2606:4700:d0::bc72:6001",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_id_is_only_applied_to_wireguard_message_types() {
        let mut handshake = [1, 0, 0, 0, 9];
        inject_client_id(&mut handshake, &[7, 8, 9]);
        assert_eq!(&handshake[1..4], &[7, 8, 9]);
        strip_client_id(&mut handshake);
        assert_eq!(&handshake[1..4], &[0, 0, 0]);

        let mut junk = [0x41, 1, 2, 3, 4];
        inject_client_id(&mut junk, &[7, 8, 9]);
        assert_eq!(&junk[1..4], &[1, 2, 3]);
    }

    #[test]
    fn health_timeouts_are_bounded() {
        assert!(wg_stale_timeout() >= wg_healthcheck_interval().saturating_mul(2));
        assert!(wg_startup_timeout() >= Duration::from_secs(10));
    }
}
