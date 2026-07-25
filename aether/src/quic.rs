use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use quiche::h3;
use quiche::h3::NameValue;
use rand::RngCore;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};

use crate::masque::{self, CapsuleParser};
use crate::noize::{self, NoizeConfig};
use crate::tls::{self, TlsParams};
use crate::{consts, error::AetherError, error::Result};

const MAX_DATAGRAM_SIZE: usize = 1350;
const DEFAULT_HEALTH_INTERVAL_SECS: u64 = 20;

fn net_queue() -> usize {
    crate::sysprofile::channel_capacity()
}

fn parse_bounded_u64(value: Option<&str>, default: u64, min: u64, max: u64) -> u64 {
    value
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .map(|parsed| parsed.clamp(min, max))
        .unwrap_or(default.clamp(min, max))
}

fn env_bounded_u64(name: &str, default: u64, min: u64, max: u64) -> u64 {
    let value = std::env::var(name).ok();
    parse_bounded_u64(value.as_deref(), default, min, max)
}

async fn bind_udp_fast(bind_addr: SocketAddr) -> Result<UdpSocket> {
    use socket2::{Domain, Socket, Type};
    let domain = if bind_addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let sock = Socket::new(domain, Type::DGRAM, None).map_err(AetherError::Io)?;
    sock.set_nonblocking(true).map_err(AetherError::Io)?;

    let buf_size = crate::sysprofile::udp_socket_buf_bytes();
    if let Err(error) = sock.set_recv_buffer_size(buf_size) {
        log::debug!("unable to set UDP receive buffer to {buf_size}: {error}");
    }
    if let Err(error) = sock.set_send_buffer_size(buf_size) {
        log::debug!("unable to set UDP send buffer to {buf_size}: {error}");
    }

    sock.bind(&bind_addr.into()).map_err(AetherError::Io)?;
    UdpSocket::from_std(sock.into()).map_err(AetherError::Io)
}

#[derive(Debug, Clone)]
pub enum Control {
    Migrate,
    Close,
}

#[derive(Debug, Clone)]
pub struct AssignedAddr {
    pub ip: IpAddr,
    pub prefix: u8,
}

#[derive(Debug, Clone)]
pub struct TunnelConfig {
    pub peer: SocketAddr,
    pub sni: String,
    pub authority: String,
    pub path: String,
    pub cert_pem: Vec<u8>,
    pub key_pem: Vec<u8>,
    pub ech_config_list: Option<Vec<u8>>,
    pub noize: NoizeConfig,
    pub local_ipv4: Ipv4Addr,
    pub quiet: bool,
}

fn validation_timeout() -> Duration {
    Duration::from_secs(env_bounded_u64(
        "AETHER_MASQUE_VALIDATE_SECS",
        10,
        1,
        120,
    ))
}

fn health_interval() -> Duration {
    Duration::from_secs(env_bounded_u64(
        "AETHER_MASQUE_HEALTH_INTERVAL_SECS",
        DEFAULT_HEALTH_INTERVAL_SECS,
        5,
        300,
    ))
}

fn data_check_enabled() -> bool {
    std::env::var("AETHER_MASQUE_NO_DATA_CHECK").is_err()
}

fn parse_h3_status(value: &[u8]) -> Result<u16> {
    let text = std::str::from_utf8(value)
        .map_err(|_| AetherError::Masque("malformed HTTP/3 :status value".into()))?;
    text.parse::<u16>()
        .map_err(|_| AetherError::Masque(format!("malformed HTTP/3 :status '{text}'")))
}

const DATA_PROBE_REQUIRED_SUCCESSES: u32 = 2;

pub struct Channels {
    pub outbound_tx: mpsc::Sender<Vec<u8>>,
    pub inbound_rx: mpsc::Receiver<Vec<u8>>,
    pub ctrl_tx: mpsc::Sender<Control>,
}

pub fn channels() -> (Channels, Internals) {
    let (outbound_tx, outbound_rx) = mpsc::channel(net_queue());
    let (inbound_tx, inbound_rx) = mpsc::channel(net_queue());
    let (ctrl_tx, ctrl_rx) = mpsc::channel(16);

    (
        Channels {
            outbound_tx,
            inbound_rx,
            ctrl_tx,
        },
        Internals {
            outbound_rx,
            inbound_tx,
            ctrl_rx,
        },
    )
}

pub struct Internals {
    outbound_rx: mpsc::Receiver<Vec<u8>>,
    inbound_tx: mpsc::Sender<Vec<u8>>,
    ctrl_rx: mpsc::Receiver<Control>,
}

impl Internals {
    pub fn into_parts(
        self,
    ) -> (
        mpsc::Receiver<Vec<u8>>,
        mpsc::Sender<Vec<u8>>,
        mpsc::Receiver<Control>,
    ) {
        (self.outbound_rx, self.inbound_tx, self.ctrl_rx)
    }
}

type NetPacket = (SocketAddr, SocketAddr, Vec<u8>);

fn bind_addr_for(peer: &SocketAddr) -> SocketAddr {
    if peer.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    }
}

fn random_scid() -> [u8; 16] {
    let mut scid = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut scid);
    scid
}

#[derive(Default)]
struct ReaderGuard {
    handles: Vec<tokio::task::JoinHandle<()>>,
}

impl ReaderGuard {
    fn push(&mut self, handle: tokio::task::JoinHandle<()>) {
        self.handles.push(handle);
    }
}

impl Drop for ReaderGuard {
    fn drop(&mut self) {
        for handle in self.handles.drain(..) {
            handle.abort();
        }
    }
}

fn spawn_reader(
    sock: Arc<UdpSocket>,
    local: SocketAddr,
    tx: mpsc::Sender<NetPacket>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            match sock.recv_from(&mut buf).await {
                Ok((n, from)) => {
                    log::trace!("recv {n} bytes from {from}");
                    if tx.send((local, from, buf[..n].to_vec())).await.is_err() {
                        break;
                    }
                }
                Err(error) => {
                    log::debug!("recv error: {error}");
                    break;
                }
            }
        }
    })
}

pub async fn run(
    cfg: TunnelConfig,
    mut internals: Internals,
    addr_tx: Option<mpsc::Sender<AssignedAddr>>,
    ready_tx: Option<oneshot::Sender<()>>,
) -> Result<()> {
    let peer = cfg.peer;
    let quiet = cfg.quiet;
    let data_check = data_check_enabled();
    let probe_packet = masque::build_dns_probe_packet(cfg.local_ipv4);
    let mut ready_tx = ready_tx;
    let mut ready_fired = false;
    let mut connect_accepted = false;
    let mut validate_deadline: Option<Instant> = None;
    let mut validate_successes: u32 = 0;

    let init_sock = bind_udp_fast(bind_addr_for(&peer)).await?;
    let local = init_sock.local_addr()?;
    let init_sock = Arc::new(init_sock);

    let (net_tx, mut net_rx) = mpsc::channel::<NetPacket>(net_queue());

    let mut sockets: HashMap<SocketAddr, Arc<UdpSocket>> = HashMap::new();
    sockets.insert(local, init_sock.clone());
    let mut readers = ReaderGuard::default();
    readers.push(spawn_reader(init_sock, local, net_tx.clone()));

    let mut config = tls::build_config(&TlsParams {
        cert_pem: &cfg.cert_pem,
        key_pem: &cfg.key_pem,
        pin_endpoint: true,
        expected_pins: consts::MASQUE_PINS,
    })?;

    let mut current_ech = cfg.ech_config_list.clone();

    let scid_bytes = random_scid();
    let scid = quiche::ConnectionId::from_ref(&scid_bytes);
    let mut conn = quiche::connect(Some(&cfg.sni), &scid, local, peer, &mut config)?;

    if let Some(ref ech) = current_ech {
        tls::inject_ech(&mut conn, ech)?;
        log::info!("ech config injected ({} bytes)", ech.len());
    }

    let h3_config = h3::Config::new()?;
    let mut h3_conn: Option<h3::Connection> = None;
    let mut req_stream: Option<u64> = None;
    let mut capsules = CapsuleParser::new();
    let mut established_ever = false;
    let mut ech_retried = false;

    if let Some(sock) = sockets.get(&local) {
        noize::pre_handshake(sock.as_ref(), peer, &cfg.noize).await;
    }

    flush(&mut conn, &sockets).await?;

    let mut out_buf = vec![0u8; 65535];
    let keepalive_period = health_interval();
    log::debug!("masque H3 keepalive interval: {keepalive_period:?}");
    let mut keepalive_interval = tokio::time::interval(keepalive_period);
    keepalive_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    let mut probe_interval = tokio::time::interval(Duration::from_millis(700));
    probe_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        if data_check && connect_accepted && !ready_fired {
            if let Some(deadline) = validate_deadline {
                if Instant::now() >= deadline {
                    log::warn!(
                        "[-] masque data-plane validation timed out; edge {peer} accepts control but drops traffic"
                    );
                    let _ = conn.close(true, 0x00, b"validation-timeout");
                    return Err(AetherError::Masque(
                        "data-plane validation timeout (CONNECT-IP accepted, no traffic)".into(),
                    ));
                }
            }
        }

        let timeout = conn.timeout();

        tokio::select! {
            biased;

            _ = keepalive_interval.tick() => {
                if conn.is_established() {
                    if let Err(error) = conn.send_ack_eliciting() {
                        log::debug!("keepalive ping failed: {error}");
                    }
                }
            }

            _ = probe_interval.tick(), if data_check && connect_accepted && !ready_fired => {
                if let Some(stream_id) = req_stream {
                    match masque::encode_ip_datagram(stream_id, &probe_packet) {
                        Ok(framed) => {
                            if let Err(error) = conn.dgram_send(&framed) {
                                log::trace!("data-plane probe send: {error}");
                            }
                        }
                        Err(error) => log::trace!("data-plane probe encode: {error}"),
                    }
                }
            }

            Some((to_local, from, mut data)) = net_rx.recv() => {
                let mut header_buf = data.clone();
                if let Ok(header) = quiche::Header::from_slice(&mut header_buf, quiche::MAX_CONN_ID_LEN) {
                    log::trace!(
                        "recv {} bytes type={:?} version=0x{:x} from {}",
                        data.len(),
                        header.ty,
                        header.version,
                        from
                    );
                }
                let info = quiche::RecvInfo { from, to: to_local };
                if let Err(error) = conn.recv(&mut data, info) {
                    log::trace!("recv error: {error}");
                }
            }

            ctrl = internals.ctrl_rx.recv() => {
                match ctrl {
                    Some(Control::Migrate) => {
                        if let Err(error) = do_migrate(
                            &mut conn,
                            peer,
                            &mut sockets,
                            &net_tx,
                            &mut readers,
                        ).await {
                            log::warn!("migration failed: {error}");
                        }
                    }
                    Some(Control::Close) | None => {
                        let _ = conn.close(true, 0x00, b"bye");
                    }
                }
            }

            packet = internals.outbound_rx.recv() => {
                match packet {
                    Some(ip_packet) if connect_accepted => {
                        if let Some(stream_id) = req_stream {
                            match masque::encode_ip_datagram(stream_id, &ip_packet) {
                                Ok(framed) => {
                                    if let Err(error) = conn.dgram_send(&framed) {
                                        log::trace!("dgram_send: {error}");
                                    }
                                }
                                Err(error) => log::trace!("encap: {error}"),
                            }
                        }
                    }
                    Some(_) => {
                        log::trace!("discarded outbound packet before CONNECT-IP acceptance");
                    }
                    None => {
                        let _ = conn.close(true, 0x00, b"eof");
                    }
                }
            }

            _ = sleep_opt(timeout) => {
                conn.on_timeout();
            }
        }

        if conn.is_established() && h3_conn.is_none() {
            established_ever = true;
            log_or_debug(
                quiet,
                format!(
                    "quic handshake established; alpn={}",
                    String::from_utf8_lossy(conn.application_proto())
                ),
            );
            let mut h3_connection = h3::Connection::with_transport(&mut conn, &h3_config)?;
            let headers = masque::connect_ip_request(&cfg.authority, &cfg.path);
            let stream_id = h3_connection.send_request(&mut conn, &headers, false)?;
            log_or_debug(
                quiet,
                format!("connect-ip request sent on stream {stream_id}"),
            );
            req_stream = Some(stream_id);
            h3_conn = Some(h3_connection);
        }

        if let (Some(h3_connection), Some(stream_id)) = (h3_conn.as_mut(), req_stream) {
            let accepted_now = poll_h3(
                &mut conn,
                h3_connection,
                stream_id,
                &mut capsules,
                &addr_tx,
                quiet,
            )?;

            if accepted_now && !connect_accepted {
                connect_accepted = true;
                if data_check {
                    validate_deadline = Some(Instant::now() + validation_timeout());
                    let framed = masque::encode_ip_datagram(stream_id, &probe_packet)?;
                    conn.dgram_send(&framed).map_err(AetherError::Quic)?;
                    log_or_debug(
                        quiet,
                        "[*] CONNECT-IP accepted; validating masque data-plane before exposing socks5"
                            .to_string(),
                    );
                } else if !ready_fired {
                    ready_fired = true;
                    if let Some(tx) = ready_tx.take() {
                        let _ = tx.send(());
                    }
                    log_or_debug(
                        quiet,
                        "[+] CONNECT-IP accepted; data-plane validation disabled; exposing socks5"
                            .to_string(),
                    );
                }
            }
        }

        let got_data = drain_datagrams(
            &mut conn,
            req_stream,
            &internals.inbound_tx,
            &mut out_buf,
        )
        .await?;

        if connect_accepted && got_data && !ready_fired {
            validate_successes += 1;
            log::debug!(
                "[*] masque data-plane round-trip {}/{} confirmed",
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
                    "[+] masque tunnel validated (end-to-end data confirmed); exposing socks5"
                        .to_string(),
                );
            }
        }

        flush(&mut conn, &sockets).await?;

        if conn.is_closed() {
            if !established_ever && !ech_retried && current_ech.is_some() {
                if let Some(retry) = tls::extract_ech_retry_configs(&mut conn) {
                    log::warn!(
                        "ech_required: retrying handshake with server retry_configs ({} bytes)",
                        retry.len()
                    );
                    ech_retried = true;
                    current_ech = Some(retry);

                    let scid_bytes = random_scid();
                    let scid = quiche::ConnectionId::from_ref(&scid_bytes);
                    conn = quiche::connect(Some(&cfg.sni), &scid, local, peer, &mut config)?;
                    if let Some(ref ech) = current_ech {
                        tls::inject_ech(&mut conn, ech)?;
                    }

                    h3_conn = None;
                    req_stream = None;
                    capsules = CapsuleParser::new();
                    connect_accepted = false;
                    validate_deadline = None;
                    validate_successes = 0;
                    flush(&mut conn, &sockets).await?;
                    continue;
                }
            }

            log_or_debug(quiet, format!("connection closed: {:?}", conn.stats()));
            if let Some(error) = conn.peer_error() {
                log_or_debug(
                    quiet,
                    format!(
                        "peer closed: code=0x{:x} app={} reason={}",
                        error.error_code,
                        error.is_app,
                        String::from_utf8_lossy(&error.reason)
                    ),
                );
            }
            if let Some(error) = conn.local_error() {
                log_or_debug(
                    quiet,
                    format!(
                        "local closed: code=0x{:x} app={} reason={}",
                        error.error_code,
                        error.is_app,
                        String::from_utf8_lossy(&error.reason)
                    ),
                );
            }

            if !ready_fired {
                return Err(AetherError::Masque(
                    "HTTP/3 connection closed before tunnel readiness".into(),
                ));
            }
            return Ok(());
        }
    }
}

async fn sleep_opt(timeout: Option<Duration>) {
    match timeout {
        Some(duration) => tokio::time::sleep(duration).await,
        None => std::future::pending::<()>().await,
    }
}

fn log_or_debug(quiet: bool, message: String) {
    if quiet {
        log::debug!("{message}");
    } else {
        log::info!("{message}");
    }
}

fn poll_h3(
    conn: &mut quiche::Connection,
    h3_connection: &mut h3::Connection,
    req_stream: u64,
    capsules: &mut CapsuleParser,
    addr_tx: &Option<mpsc::Sender<AssignedAddr>>,
    quiet: bool,
) -> Result<bool> {
    let mut body = vec![0u8; 65535];
    let mut accepted = false;

    loop {
        match h3_connection.poll(conn) {
            Ok((stream_id, h3::Event::Headers { list, .. })) if stream_id == req_stream => {
                for header in &list {
                    if header.name() != b":status" {
                        continue;
                    }

                    let status = parse_h3_status(header.value())?;
                    log_or_debug(quiet, format!("connect-ip status: {status}"));
                    if (200..300).contains(&status) {
                        accepted = true;
                    } else if status >= 200 {
                        return Err(AetherError::Masque(format!(
                            "connect-ip status {status}"
                        )));
                    }
                }
            }
            Ok((_stream_id, h3::Event::Headers { .. })) => {}

            Ok((stream_id, h3::Event::Data)) => {
                if stream_id != req_stream {
                    continue;
                }
                while let Ok(read) = h3_connection.recv_body(conn, stream_id, &mut body) {
                    if read == 0 {
                        break;
                    }
                    capsules.push(&body[..read]);
                }
                drain_capsules(capsules, addr_tx)?;
            }

            Ok((stream_id, h3::Event::Finished)) if stream_id == req_stream => {
                return Err(AetherError::Masque(
                    "CONNECT-IP stream finished unexpectedly".into(),
                ));
            }
            Ok((stream_id, h3::Event::Reset(code))) if stream_id == req_stream => {
                return Err(AetherError::Masque(format!(
                    "CONNECT-IP stream reset with code {code}"
                )));
            }
            Ok(_) => {}

            Err(h3::Error::Done) => break,
            Err(error) => return Err(AetherError::H3(error)),
        }
    }

    Ok(accepted)
}

fn drain_capsules(
    capsules: &mut CapsuleParser,
    addr_tx: &Option<mpsc::Sender<AssignedAddr>>,
) -> Result<()> {
    loop {
        match capsules.next() {
            Ok(Some(masque::Capsule::AddressAssign(addrs))) => {
                for address in addrs {
                    if let Some(ip) = bytes_to_ip(address.ip_version, &address.address) {
                        log::info!("edge assigned {}/{}", ip, address.prefix_len);
                        if let Some(tx) = addr_tx {
                            let _ = tx.try_send(AssignedAddr {
                                ip,
                                prefix: address.prefix_len,
                            });
                        }
                    }
                }
            }
            Ok(Some(masque::Capsule::RouteAdvertisement(routes))) => {
                log::info!("received {} route advertisements", routes.len());
            }
            Ok(Some(_)) => {}
            Ok(None) => break,
            Err(error) => {
                return Err(AetherError::Masque(format!(
                    "malformed capsule stream: {error}"
                )));
            }
        }
    }
    Ok(())
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

async fn drain_datagrams(
    conn: &mut quiche::Connection,
    req_stream: Option<u64>,
    inbound_tx: &mpsc::Sender<Vec<u8>>,
    buf: &mut [u8],
) -> Result<bool> {
    let stream_id = match req_stream {
        Some(stream_id) => stream_id,
        None => return Ok(false),
    };

    let mut delivered = false;
    loop {
        match conn.dgram_recv(buf) {
            Ok(read) => match masque::decode_ip_datagram(&buf[..read], stream_id) {
                Ok(Some(ip_packet)) => {
                    delivered = true;
                    if inbound_tx.send(ip_packet).await.is_err() {
                        return Ok(delivered);
                    }
                }
                Ok(None) => {}
                Err(error) => {
                    return Err(AetherError::Masque(format!(
                        "malformed HTTP/3 datagram: {error}"
                    )));
                }
            },
            Err(quiche::Error::Done) => break,
            Err(error) => return Err(AetherError::Quic(error)),
        }
    }
    Ok(delivered)
}

async fn flush(
    conn: &mut quiche::Connection,
    sockets: &HashMap<SocketAddr, Arc<UdpSocket>>,
) -> Result<()> {
    let mut out = vec![0u8; MAX_DATAGRAM_SIZE];

    loop {
        match conn.send(&mut out) {
            Ok((write, send_info)) => {
                let socket = sockets.get(&send_info.from).ok_or_else(|| {
                    AetherError::Other(format!(
                        "no UDP socket is registered for QUIC path {}",
                        send_info.from
                    ))
                })?;
                socket.send_to(&out[..write], send_info.to).await?;
            }
            Err(quiche::Error::Done) => break,
            Err(error) => return Err(AetherError::Quic(error)),
        }
    }

    Ok(())
}

async fn do_migrate(
    conn: &mut quiche::Connection,
    peer: SocketAddr,
    sockets: &mut HashMap<SocketAddr, Arc<UdpSocket>>,
    net_tx: &mpsc::Sender<NetPacket>,
    readers: &mut ReaderGuard,
) -> Result<()> {
    if conn.available_dcids() == 0 {
        return Err(AetherError::Other("no spare dcids for migration".into()));
    }

    let new_sock = bind_udp_fast(bind_addr_for(&peer)).await?;
    let new_local = new_sock.local_addr()?;
    let new_sock = Arc::new(new_sock);

    sockets.insert(new_local, new_sock.clone());
    readers.push(spawn_reader(new_sock, new_local, net_tx.clone()));

    conn.probe_path(new_local, peer)?;
    let sequence = conn.migrate_source(new_local)?;
    log::info!("migrated to local {new_local} (path seq {sequence})");

    Ok(())
}

pub fn default_authority() -> &'static str {
    "cloudflareaccess.com"
}

pub fn default_path() -> &'static str {
    "/"
}

pub fn default_sni() -> &'static str {
    consts::CONNECT_SNI
}

#[derive(Clone)]
pub struct VerifyParams {
    pub peer: SocketAddr,
    pub sni: String,
    pub authority: String,
    pub path: String,
    pub cert_pem: Vec<u8>,
    pub key_pem: Vec<u8>,
    pub ech_config_list: Option<Vec<u8>>,
    pub noize: NoizeConfig,
    pub timeout: Duration,
    pub local_ipv4: Ipv4Addr,
}

pub async fn verify_masque(params: &VerifyParams) -> Result<Duration> {
    let bind: SocketAddr = if params.peer.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
    let sock = bind_udp_fast(bind).await?;
    sock.connect(params.peer).await?;
    let local = sock.local_addr()?;

    let mut config = tls::build_config(&TlsParams {
        cert_pem: &params.cert_pem,
        key_pem: &params.key_pem,
        pin_endpoint: true,
        expected_pins: consts::MASQUE_PINS,
    })?;

    let scid_bytes = random_scid();
    let scid = quiche::ConnectionId::from_ref(&scid_bytes);
    let mut conn = quiche::connect(
        Some(&params.sni),
        &scid,
        local,
        params.peer,
        &mut config,
    )?;

    if let Some(ref ech) = params.ech_config_list {
        let _ = tls::inject_ech(&mut conn, ech);
    }

    let h3_config = h3::Config::new()?;
    let mut h3_conn: Option<h3::Connection> = None;
    let mut req_stream: Option<u64> = None;

    let data_check = data_check_enabled();
    let probe_packet = masque::build_dns_probe_packet(params.local_ipv4);
    let mut connect_ip_ok = false;
    let mut last_probe = Instant::now();
    let mut datagram_buf = vec![0u8; 65535];
    let mut probe_successes: u32 = 0;

    let start = Instant::now();
    let deadline = start + params.timeout;

    noize::pre_handshake(&sock, params.peer, &params.noize).await;
    flush_connected(&mut conn, &sock).await?;

    let mut buf = vec![0u8; 65535];

    loop {
        if Instant::now() >= deadline {
            return Err(AetherError::Other("verify timeout".into()));
        }

        let wait = match conn.timeout() {
            Some(timeout) => timeout.min(remaining(deadline)),
            None => remaining(deadline),
        };
        let wait = if connect_ip_ok {
            wait.min(Duration::from_millis(250))
        } else {
            wait
        };

        tokio::select! {
            result = sock.recv(&mut buf) => {
                match result {
                    Ok(read) => {
                        let mut header_buf = buf[..read].to_vec();
                        if let Ok(header) = quiche::Header::from_slice(
                            &mut header_buf,
                            quiche::MAX_CONN_ID_LEN,
                        ) {
                            log::trace!(
                                "verify recv {} bytes type={:?} version=0x{:x} from {}",
                                read,
                                header.ty,
                                header.version,
                                params.peer
                            );
                        }
                        let info = quiche::RecvInfo {
                            from: params.peer,
                            to: local,
                        };
                        if let Err(error) = conn.recv(&mut buf[..read], info) {
                            log::trace!("verify recv error from {}: {error}", params.peer);
                        }
                    }
                    Err(error) => return Err(AetherError::Io(error)),
                }
            }
            _ = tokio::time::sleep(wait) => {
                conn.on_timeout();
            }
        }

        if conn.is_established() && h3_conn.is_none() {
            let mut h3_connection = h3::Connection::with_transport(&mut conn, &h3_config)?;
            let headers = masque::connect_ip_request(&params.authority, &params.path);
            let stream_id = h3_connection.send_request(&mut conn, &headers, false)?;
            req_stream = Some(stream_id);
            h3_conn = Some(h3_connection);
        }

        if let (Some(h3_connection), Some(stream_id)) = (h3_conn.as_mut(), req_stream) {
            loop {
                match h3_connection.poll(&mut conn) {
                    Ok((event_stream, h3::Event::Headers { list, .. }))
                        if event_stream == stream_id =>
                    {
                        for header in &list {
                            if header.name() != b":status" {
                                continue;
                            }

                            let status = parse_h3_status(header.value())?;
                            if (200..300).contains(&status) {
                                if !data_check {
                                    return Ok(start.elapsed());
                                }
                                connect_ip_ok = true;
                                let framed = masque::encode_ip_datagram(
                                    stream_id,
                                    &probe_packet,
                                )?;
                                conn.dgram_send(&framed).map_err(AetherError::Quic)?;
                                last_probe = Instant::now();
                            } else if status >= 200 {
                                return Err(AetherError::Masque(format!(
                                    "connect-ip status {status}"
                                )));
                            }
                        }
                    }
                    Ok((event_stream, h3::Event::Finished))
                        if event_stream == stream_id =>
                    {
                        return Err(AetherError::Masque(
                            "CONNECT-IP stream finished during verification".into(),
                        ));
                    }
                    Ok((event_stream, h3::Event::Reset(code)))
                        if event_stream == stream_id =>
                    {
                        return Err(AetherError::Masque(format!(
                            "CONNECT-IP stream reset during verification with code {code}"
                        )));
                    }
                    Ok(_) => {}
                    Err(h3::Error::Done) => break,
                    Err(error) => return Err(AetherError::H3(error)),
                }
            }
        }

        if connect_ip_ok {
            if last_probe.elapsed() >= Duration::from_millis(700) {
                if let Some(stream_id) = req_stream {
                    let framed = masque::encode_ip_datagram(stream_id, &probe_packet)?;
                    conn.dgram_send(&framed).map_err(AetherError::Quic)?;
                }
                last_probe = Instant::now();
            }

            if let Some(stream_id) = req_stream {
                loop {
                    match conn.dgram_recv(&mut datagram_buf) {
                        Ok(read) => match masque::decode_ip_datagram(
                            &datagram_buf[..read],
                            stream_id,
                        ) {
                            Ok(Some(_)) => {
                                probe_successes += 1;
                                if probe_successes >= DATA_PROBE_REQUIRED_SUCCESSES {
                                    return Ok(start.elapsed());
                                }
                                let framed = masque::encode_ip_datagram(
                                    stream_id,
                                    &probe_packet,
                                )?;
                                conn.dgram_send(&framed).map_err(AetherError::Quic)?;
                                last_probe = Instant::now();
                            }
                            Ok(None) => {}
                            Err(error) => {
                                return Err(AetherError::Masque(format!(
                                    "malformed HTTP/3 datagram during verification: {error}"
                                )));
                            }
                        },
                        Err(quiche::Error::Done) => break,
                        Err(error) => return Err(AetherError::Quic(error)),
                    }
                }
            }
        }

        flush_connected(&mut conn, &sock).await?;

        if conn.is_closed() {
            return Err(AetherError::Other(
                "closed before data-plane confirmation".into(),
            ));
        }
    }
}

fn remaining(deadline: Instant) -> Duration {
    deadline.saturating_duration_since(Instant::now())
}

async fn flush_connected(conn: &mut quiche::Connection, sock: &UdpSocket) -> Result<()> {
    let mut out = vec![0u8; MAX_DATAGRAM_SIZE];
    loop {
        match conn.send(&mut out) {
            Ok((write, _info)) => {
                sock.send(&out[..write]).await?;
            }
            Err(quiche::Error::Done) => break,
            Err(error) => return Err(AetherError::Quic(error)),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_health_parser_clamps_defaults_and_overrides() {
        assert_eq!(parse_bounded_u64(None, 20, 5, 300), 20);
        assert_eq!(parse_bounded_u64(Some("invalid"), 20, 5, 300), 20);
        assert_eq!(parse_bounded_u64(Some("1"), 20, 5, 300), 5);
        assert_eq!(parse_bounded_u64(Some("999"), 20, 5, 300), 300);
        assert_eq!(parse_bounded_u64(None, 1, 5, 300), 5);
    }

    #[test]
    fn h3_status_parser_accepts_numeric_values_and_rejects_malformed_values() {
        assert_eq!(parse_h3_status(b"200").unwrap(), 200);
        assert_eq!(parse_h3_status(b"204").unwrap(), 204);
        assert!(parse_h3_status(b"ok").is_err());
        assert!(parse_h3_status(&[0xff]).is_err());
    }
}
