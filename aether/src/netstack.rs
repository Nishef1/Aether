use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Instant as StdInstant;

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Checksum, Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::{Duration as SmolDuration, Instant};
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint, Ipv4Address, Ipv6Address};
use tokio::sync::{mpsc, oneshot};

use crate::error::{AetherError, Result};

fn tcp_buf() -> usize {
    crate::sysprofile::netstack_tcp_buf_bytes()
}

fn udp_buf() -> usize {
    crate::sysprofile::netstack_udp_buf_bytes()
}

fn udp_meta() -> usize {
    match crate::sysprofile::tuning().tier {
        crate::sysprofile::Tier::Low => 32,
        crate::sysprofile::Tier::Medium => 64,
        crate::sysprofile::Tier::High => 128,
    }
}

fn app_queue() -> usize {
    crate::sysprofile::channel_capacity()
}

fn max_tcp_pending() -> usize {
    tcp_buf().saturating_mul(4).max(64 * 1024)
}

fn udp_idle_timeout() -> std::time::Duration {
    let seconds = std::env::var("AETHER_NETSTACK_UDP_IDLE_SECS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .map(|value| value.clamp(30, 3600))
        .unwrap_or(300);
    std::time::Duration::from_secs(seconds)
}

const MAX_INGEST_PER_TICK: usize = 512;
const MAX_RECV_CHUNKS: usize = 128;
const TCP_SOCKET_TIMEOUT_SECS: u64 = 30;
const MIN_TUNNEL_MTU: usize = 576;
const MAX_TUNNEL_MTU: usize = 65_535;

pub struct StackDevice {
    rx: VecDeque<Vec<u8>>,
    tx: VecDeque<Vec<u8>>,
    mtu: usize,
}

impl StackDevice {
    fn new(mtu: usize) -> Self {
        Self {
            rx: VecDeque::new(),
            tx: VecDeque::new(),
            mtu,
        }
    }
}

pub struct StackRxToken(Vec<u8>);

pub struct StackTxToken<'a> {
    queue: &'a mut VecDeque<Vec<u8>>,
    mtu: usize,
}

impl RxToken for StackRxToken {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, function: F) -> R {
        function(&self.0)
    }
}

impl<'a> TxToken for StackTxToken<'a> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, function: F) -> R {
        let mut buffer = vec![0u8; len];
        let result = function(&mut buffer);
        if len <= self.mtu && self.queue.len() < app_queue() {
            self.queue.push_back(buffer);
        } else {
            log::debug!(
                "netstack dropped generated packet: len={len} mtu={} tx_queue={}",
                self.mtu,
                self.queue.len()
            );
        }
        result
    }
}

impl Device for StackDevice {
    type RxToken<'a> = StackRxToken;
    type TxToken<'a> = StackTxToken<'a>;

    fn receive(&mut self, _time: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let packet = self.rx.pop_front()?;
        Some((
            StackRxToken(packet),
            StackTxToken {
                queue: &mut self.tx,
                mtu: self.mtu,
            },
        ))
    }

    fn transmit(&mut self, _time: Instant) -> Option<Self::TxToken<'_>> {
        Some(StackTxToken {
            queue: &mut self.tx,
            mtu: self.mtu,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ip;
        capabilities.max_transmission_unit = self.mtu;
        capabilities.checksum.ipv4 = Checksum::Tx;
        capabilities.checksum.tcp = Checksum::Tx;
        capabilities.checksum.udp = Checksum::Tx;
        capabilities
    }
}

type OpenTcpResp = oneshot::Sender<std::result::Result<TcpConn, String>>;
type OpenUdpResp = oneshot::Sender<std::result::Result<UdpConn, String>>;

pub enum Cmd {
    OpenTcp { dst: SocketAddr, resp: OpenTcpResp },
    OpenUdp { resp: OpenUdpResp },
    SetAddrs {
        v4: Option<(Ipv4Addr, u8)>,
        v6: Option<(Ipv6Addr, u8)>,
    },
}

pub enum DataIn {
    Tcp(usize, Vec<u8>),
    TcpClose(usize),
    Udp(usize, SocketAddr, Vec<u8>),
    UdpClose(usize),
}

pub struct TcpConn {
    pub id: usize,
    pub from_stack: mpsc::Receiver<Vec<u8>>,
    data_in: mpsc::Sender<DataIn>,
}

impl TcpConn {
    pub async fn send(&self, data: Vec<u8>) -> Result<()> {
        self.data_in
            .send(DataIn::Tcp(self.id, data))
            .await
            .map_err(|_| AetherError::Other("netstack closed".into()))
    }

    pub async fn close(&self) {
        let _ = self.data_in.send(DataIn::TcpClose(self.id)).await;
    }

    pub fn into_split(self) -> (TcpSender, mpsc::Receiver<Vec<u8>>) {
        (
            TcpSender {
                id: self.id,
                data_in: self.data_in,
            },
            self.from_stack,
        )
    }
}

pub struct TcpSender {
    id: usize,
    data_in: mpsc::Sender<DataIn>,
}

impl TcpSender {
    pub async fn send(&self, data: Vec<u8>) -> Result<()> {
        self.data_in
            .send(DataIn::Tcp(self.id, data))
            .await
            .map_err(|_| AetherError::Other("netstack closed".into()))
    }

    pub async fn close(&self) {
        let _ = self.data_in.send(DataIn::TcpClose(self.id)).await;
    }
}

pub struct UdpConn {
    pub id: usize,
    pub from_stack: mpsc::Receiver<(SocketAddr, Vec<u8>)>,
    data_in: mpsc::Sender<DataIn>,
}

impl UdpConn {
    pub async fn send_to(&self, dst: SocketAddr, data: Vec<u8>) -> Result<()> {
        self.data_in
            .send(DataIn::Udp(self.id, dst, data))
            .await
            .map_err(|_| AetherError::Other("netstack closed".into()))
    }

    pub async fn close(&self) {
        let _ = self.data_in.send(DataIn::UdpClose(self.id)).await;
    }

    pub fn into_split(self) -> (UdpSender, mpsc::Receiver<(SocketAddr, Vec<u8>)>) {
        (
            UdpSender {
                id: self.id,
                data_in: self.data_in,
            },
            self.from_stack,
        )
    }
}

pub struct UdpSender {
    id: usize,
    data_in: mpsc::Sender<DataIn>,
}

impl UdpSender {
    pub async fn send_to(&self, dst: SocketAddr, data: Vec<u8>) -> Result<()> {
        self.data_in
            .send(DataIn::Udp(self.id, dst, data))
            .await
            .map_err(|_| AetherError::Other("netstack closed".into()))
    }

    pub async fn close(&self) {
        let _ = self.data_in.send(DataIn::UdpClose(self.id)).await;
    }
}

#[derive(Clone)]
pub struct StackHandle {
    cmd_tx: mpsc::Sender<Cmd>,
}

impl StackHandle {
    pub async fn open_tcp(&self, dst: SocketAddr) -> Result<TcpConn> {
        let (response_tx, response_rx) = oneshot::channel();
        self.cmd_tx
            .send(Cmd::OpenTcp {
                dst,
                resp: response_tx,
            })
            .await
            .map_err(|_| AetherError::Other("netstack closed".into()))?;
        response_rx
            .await
            .map_err(|_| AetherError::Other("netstack dropped".into()))?
            .map_err(AetherError::Other)
    }

    pub async fn open_udp(&self) -> Result<UdpConn> {
        let (response_tx, response_rx) = oneshot::channel();
        self.cmd_tx
            .send(Cmd::OpenUdp { resp: response_tx })
            .await
            .map_err(|_| AetherError::Other("netstack closed".into()))?;
        response_rx
            .await
            .map_err(|_| AetherError::Other("netstack dropped".into()))?
            .map_err(AetherError::Other)
    }

    pub async fn set_addrs(
        &self,
        v4: Option<(Ipv4Addr, u8)>,
        v6: Option<(Ipv6Addr, u8)>,
    ) -> Result<()> {
        validate_prefixes(v4, v6)?;
        self.cmd_tx
            .send(Cmd::SetAddrs { v4, v6 })
            .await
            .map_err(|_| AetherError::Other("netstack closed".into()))
    }
}

struct TcpState {
    handle: SocketHandle,
    to_app: mpsc::Sender<Vec<u8>>,
    from_stack_rx: Option<mpsc::Receiver<Vec<u8>>>,
    connect_resp: Option<OpenTcpResp>,
    pending: Vec<u8>,
    established: bool,
    half_closed: bool,
}

struct UdpState {
    handle: SocketHandle,
    to_app: mpsc::Sender<(SocketAddr, Vec<u8>)>,
    last_activity: StdInstant,
}

pub struct NetStack {
    iface: Interface,
    device: StackDevice,
    sockets: SocketSet<'static>,
    tcp_conns: HashMap<usize, TcpState>,
    udp_conns: HashMap<usize, UdpState>,
    next_id: usize,
    next_port: u16,
    data_in_tx: mpsc::Sender<DataIn>,
}

fn strip_cidr(value: &str) -> &str {
    match value.split_once('/') {
        Some((ip, _)) => ip,
        None => value,
    }
}

fn to_ip_address(ip: IpAddr) -> IpAddress {
    match ip {
        IpAddr::V4(address) => IpAddress::Ipv4(Ipv4Address::from(address)),
        IpAddr::V6(address) => IpAddress::Ipv6(Ipv6Address::from(address)),
    }
}

fn to_ip_endpoint(address: SocketAddr) -> IpEndpoint {
    IpEndpoint::new(to_ip_address(address.ip()), address.port())
}

fn cidr_prefix(value: &str) -> Option<u8> {
    value
        .split_once('/')
        .and_then(|(_, prefix)| prefix.parse().ok())
}

fn parse_v4(value: &str) -> Result<Option<(Ipv4Addr, u8)>> {
    if value.is_empty() {
        return Ok(None);
    }
    let ip: Ipv4Addr = strip_cidr(value)
        .parse()
        .map_err(|_| AetherError::Other(format!("bad ipv4 {value}")))?;
    let prefix = cidr_prefix(value).unwrap_or(32);
    if prefix > 32 {
        return Err(AetherError::Other(format!("bad ipv4 prefix {value}")));
    }
    Ok(Some((ip, prefix)))
}

fn parse_v6(value: &str) -> Result<Option<(Ipv6Addr, u8)>> {
    if value.is_empty() {
        return Ok(None);
    }
    let ip: Ipv6Addr = strip_cidr(value)
        .parse()
        .map_err(|_| AetherError::Other(format!("bad ipv6 {value}")))?;
    let prefix = cidr_prefix(value).unwrap_or(128);
    if prefix > 128 {
        return Err(AetherError::Other(format!("bad ipv6 prefix {value}")));
    }
    Ok(Some((ip, prefix)))
}

fn validate_prefixes(
    v4: Option<(Ipv4Addr, u8)>,
    v6: Option<(Ipv6Addr, u8)>,
) -> Result<()> {
    if v4.is_some_and(|(_, prefix)| prefix > 32) {
        return Err(AetherError::Other("invalid IPv4 prefix".into()));
    }
    if v6.is_some_and(|(_, prefix)| prefix > 128) {
        return Err(AetherError::Other("invalid IPv6 prefix".into()));
    }
    Ok(())
}

fn routable_prefix_v4(prefix: u8) -> u8 {
    if prefix >= 31 {
        24
    } else {
        prefix
    }
}

fn routable_prefix_v6(prefix: u8) -> u8 {
    if prefix >= 127 {
        64
    } else {
        prefix
    }
}

fn apply_addrs(
    iface: &mut Interface,
    v4: Option<(Ipv4Addr, u8)>,
    v6: Option<(Ipv6Addr, u8)>,
) {
    iface.update_ip_addrs(|addresses| {
        addresses.clear();
        if let Some((ip, prefix)) = v4 {
            if addresses
                .push(IpCidr::new(
                    IpAddress::Ipv4(Ipv4Address::from(ip)),
                    routable_prefix_v4(prefix),
                ))
                .is_err()
            {
                log::warn!("netstack IPv4 address table is full");
            }
        }
        if let Some((ip, prefix)) = v6 {
            if addresses
                .push(IpCidr::new(
                    IpAddress::Ipv6(Ipv6Address::from(ip)),
                    routable_prefix_v6(prefix),
                ))
                .is_err()
            {
                log::warn!("netstack IPv6 address table is full");
            }
        }
    });

    let routes = iface.routes_mut();
    routes.remove_default_ipv4_route();
    routes.remove_default_ipv6_route();

    if let Some((ip, _)) = v4 {
        let octets = ip.octets();
        let host = if octets[3] == 1 { 2 } else { 1 };
        let gateway = Ipv4Address::new(octets[0], octets[1], octets[2], host);
        if routes.add_default_ipv4_route(gateway).is_err() {
            log::warn!("netstack IPv4 route table is full");
        }
    }
    if let Some((ip, _)) = v6 {
        let mut octets = ip.octets();
        octets[15] = if octets[15] == 1 { 2 } else { 1 };
        if routes
            .add_default_ipv6_route(Ipv6Address::from(octets))
            .is_err()
        {
            log::warn!("netstack IPv6 route table is full");
        }
    }
}

fn endpoint_to_socketaddr(endpoint: IpEndpoint) -> SocketAddr {
    let ip = match endpoint.addr {
        IpAddress::Ipv4(address) => IpAddr::V4(address.into()),
        IpAddress::Ipv6(address) => IpAddr::V6(address.into()),
    };
    SocketAddr::new(ip, endpoint.port)
}

pub fn spawn(
    ipv4: &str,
    ipv6: &str,
    mtu: usize,
    inbound_rx: mpsc::Receiver<Vec<u8>>,
    outbound_tx: mpsc::Sender<Vec<u8>>,
) -> Result<StackHandle> {
    if !(MIN_TUNNEL_MTU..=MAX_TUNNEL_MTU).contains(&mtu) {
        return Err(AetherError::Other(format!(
            "invalid netstack MTU {mtu}; expected {MIN_TUNNEL_MTU}..={MAX_TUNNEL_MTU}"
        )));
    }

    let mut device = StackDevice::new(mtu);
    let config = Config::new(HardwareAddress::Ip);
    let mut iface = Interface::new(config, &mut device, Instant::now());

    let v4 = parse_v4(ipv4)?;
    let v6 = parse_v6(ipv6)?;
    validate_prefixes(v4, v6)?;
    apply_addrs(&mut iface, v4, v6);

    let (cmd_tx, cmd_rx) = mpsc::channel(256);
    let (data_in_tx, data_in_rx) = mpsc::channel(app_queue());

    let stack = NetStack {
        iface,
        device,
        sockets: SocketSet::new(Vec::new()),
        tcp_conns: HashMap::new(),
        udp_conns: HashMap::new(),
        next_id: 1,
        next_port: 49152,
        data_in_tx: data_in_tx.clone(),
    };

    tokio::spawn(async move {
        if let Err(error) = run(stack, cmd_rx, data_in_rx, inbound_rx, outbound_tx).await {
            log::warn!("netstack stopped: {error}");
        }
    });

    Ok(StackHandle { cmd_tx })
}

fn alloc_port(port: &mut u16) -> u16 {
    let allocated = *port;
    *port = if allocated >= 65000 {
        49152
    } else {
        allocated + 1
    };
    allocated
}

async fn run(
    mut stack: NetStack,
    mut cmd_rx: mpsc::Receiver<Cmd>,
    mut data_in_rx: mpsc::Receiver<DataIn>,
    mut inbound_rx: mpsc::Receiver<Vec<u8>>,
    outbound_tx: mpsc::Sender<Vec<u8>>,
) -> Result<()> {
    loop {
        let now = Instant::now();
        let poll_outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            stack
                .iface
                .poll(now, &mut stack.device, &mut stack.sockets);
        }));
        if poll_outcome.is_err() {
            return Err(AetherError::Other(
                "smoltcp panicked while polling; refusing to continue with corrupted state".into(),
            ));
        }
        service_tcp(&mut stack).await;
        service_udp(&mut stack).await;
        flush_tx(&mut stack, &outbound_tx).await?;

        let delay = stack
            .iface
            .poll_delay(Instant::now(), &stack.sockets)
            .map(|duration| std::time::Duration::from_micros(duration.total_micros()));

        tokio::select! {
            biased;

            maybe = inbound_rx.recv() => {
                match maybe {
                    Some(packet) => {
                        if packet.len() <= MAX_TUNNEL_MTU {
                            stack.device.rx.push_back(packet);
                        } else {
                            log::debug!("netstack dropped oversized inbound packet");
                        }
                        let mut count = 0;
                        while count < MAX_INGEST_PER_TICK {
                            match inbound_rx.try_recv() {
                                Ok(packet) => {
                                    if packet.len() <= MAX_TUNNEL_MTU {
                                        stack.device.rx.push_back(packet);
                                    }
                                    count += 1;
                                }
                                Err(_) => break,
                            }
                        }
                    }
                    None => {
                        return Err(AetherError::Other(
                            "tunnel input channel closed".into(),
                        ));
                    }
                }
            }

            maybe = cmd_rx.recv() => {
                match maybe {
                    Some(command) => handle_cmd(&mut stack, command),
                    None => return Ok(()),
                }
            }

            maybe = data_in_rx.recv() => {
                match maybe {
                    Some(data) => {
                        handle_data(&mut stack, data);
                        while let Ok(more) = data_in_rx.try_recv() {
                            handle_data(&mut stack, more);
                        }
                    }
                    None => {
                        return Err(AetherError::Other(
                            "netstack application input channel closed".into(),
                        ));
                    }
                }
            }

            _ = sleep_opt(delay) => {}
        }
    }
}

async fn sleep_opt(delay: Option<std::time::Duration>) {
    match delay {
        Some(duration) => tokio::time::sleep(duration).await,
        None => std::future::pending::<()>().await,
    }
}

fn handle_cmd(stack: &mut NetStack, command: Cmd) {
    match command {
        Cmd::OpenTcp { dst, resp } => {
            let receive_buffer = tcp::SocketBuffer::new(vec![0u8; tcp_buf()]);
            let transmit_buffer = tcp::SocketBuffer::new(vec![0u8; tcp_buf()]);
            let mut socket = tcp::Socket::new(receive_buffer, transmit_buffer);
            socket.set_nagle_enabled(false);
            socket.set_timeout(Some(SmolDuration::from_secs(TCP_SOCKET_TIMEOUT_SECS)));

            let local_port = alloc_port(&mut stack.next_port);
            let remote = to_ip_endpoint(dst);

            if let Err(error) = socket.connect(stack.iface.context(), remote, local_port) {
                let _ = resp.send(Err(format!("connect: {error:?}")));
                return;
            }

            let handle = stack.sockets.add(socket);
            let id = stack.next_id;
            stack.next_id = stack.next_id.wrapping_add(1).max(1);

            let (to_app_tx, to_app_rx) = mpsc::channel(app_queue());

            stack.tcp_conns.insert(
                id,
                TcpState {
                    handle,
                    to_app: to_app_tx,
                    from_stack_rx: Some(to_app_rx),
                    connect_resp: Some(resp),
                    pending: Vec::new(),
                    established: false,
                    half_closed: false,
                },
            );
        }
        Cmd::OpenUdp { resp } => {
            let receive_metadata = vec![udp::PacketMetadata::EMPTY; udp_meta()];
            let transmit_metadata = vec![udp::PacketMetadata::EMPTY; udp_meta()];
            let receive_buffer = udp::PacketBuffer::new(receive_metadata, vec![0u8; udp_buf()]);
            let transmit_buffer = udp::PacketBuffer::new(transmit_metadata, vec![0u8; udp_buf()]);
            let mut socket = udp::Socket::new(receive_buffer, transmit_buffer);

            let local_port = alloc_port(&mut stack.next_port);
            if let Err(error) = socket.bind(local_port) {
                let _ = resp.send(Err(format!("bind: {error:?}")));
                return;
            }

            let handle = stack.sockets.add(socket);
            let id = stack.next_id;
            stack.next_id = stack.next_id.wrapping_add(1).max(1);

            let (to_app_tx, to_app_rx) = mpsc::channel(app_queue());
            stack.udp_conns.insert(
                id,
                UdpState {
                    handle,
                    to_app: to_app_tx,
                    last_activity: StdInstant::now(),
                },
            );

            let connection = UdpConn {
                id,
                from_stack: to_app_rx,
                data_in: stack.data_in_tx.clone(),
            };
            let _ = resp.send(Ok(connection));
        }
        Cmd::SetAddrs { v4, v6 } => {
            if let Err(error) = validate_prefixes(v4, v6) {
                log::warn!("ignored invalid edge address assignment: {error}");
                return;
            }
            apply_addrs(&mut stack.iface, v4, v6);
            log::info!("netstack addresses synchronized from edge capsule");
        }
    }
}

fn handle_data(stack: &mut NetStack, data: DataIn) {
    match data {
        DataIn::Tcp(id, data) => {
            let mut abort = None;
            if let Some(state) = stack.tcp_conns.get_mut(&id) {
                if state.pending.len().saturating_add(data.len()) > max_tcp_pending() {
                    log::warn!(
                        "netstack TCP pending queue exceeded {} bytes; aborting connection {id}",
                        max_tcp_pending()
                    );
                    state.pending.clear();
                    state.half_closed = true;
                    abort = Some(state.handle);
                } else {
                    state.pending.extend_from_slice(&data);
                }
            }
            if let Some(handle) = abort {
                stack.sockets.get_mut::<tcp::Socket>(handle).abort();
            }
        }
        DataIn::TcpClose(id) => {
            if let Some(state) = stack.tcp_conns.get_mut(&id) {
                state.half_closed = true;
            }
        }
        DataIn::Udp(id, destination, data) => {
            if let Some(state) = stack.udp_conns.get_mut(&id) {
                state.last_activity = StdInstant::now();
                let socket = stack.sockets.get_mut::<udp::Socket>(state.handle);
                if let Err(error) = socket.send_slice(&data, to_ip_endpoint(destination)) {
                    log::debug!("netstack UDP send dropped for {destination}: {error}");
                }
            }
        }
        DataIn::UdpClose(id) => {
            if let Some(state) = stack.udp_conns.remove(&id) {
                stack.sockets.remove(state.handle);
            }
        }
    }
}

async fn service_tcp(stack: &mut NetStack) {
    let ids: Vec<usize> = stack.tcp_conns.keys().copied().collect();

    for id in ids {
        let handle = match stack.tcp_conns.get(&id) {
            Some(state) => state.handle,
            None => continue,
        };

        let socket_state = stack.sockets.get_mut::<tcp::Socket>(handle).state();
        let data_in_tx = stack.data_in_tx.clone();

        if !stack.tcp_conns[&id].established && socket_state == tcp::State::Established {
            if let Some(state) = stack.tcp_conns.get_mut(&id) {
                state.established = true;
                if let (Some(response), Some(receiver)) =
                    (state.connect_resp.take(), state.from_stack_rx.take())
                {
                    let connection = TcpConn {
                        id,
                        from_stack: receiver,
                        data_in: data_in_tx.clone(),
                    };
                    let _ = response.send(Ok(connection));
                }
            }
        }

        if !stack.tcp_conns[&id].established
            && matches!(socket_state, tcp::State::Closed | tcp::State::TimeWait)
        {
            if let Some(state) = stack.tcp_conns.get_mut(&id) {
                if let Some(response) = state.connect_resp.take() {
                    let _ = response.send(Err("connection refused or timed out".into()));
                }
            }
            stack.sockets.remove(handle);
            stack.tcp_conns.remove(&id);
            continue;
        }

        {
            let socket = stack.sockets.get_mut::<tcp::Socket>(handle);
            if socket.can_send() {
                let state = stack.tcp_conns.get_mut(&id).unwrap();
                if !state.pending.is_empty() {
                    match socket.send_slice(&state.pending) {
                        Ok(sent) if sent > 0 => {
                            state.pending.drain(0..sent);
                        }
                        Ok(_) => {}
                        Err(error) => {
                            log::debug!("netstack TCP send failed for connection {id}: {error}");
                            socket.abort();
                        }
                    }
                }
            }
        }

        {
            let pending_empty = stack.tcp_conns[&id].pending.is_empty();
            let half_closed = stack.tcp_conns[&id].half_closed;
            if half_closed && pending_empty {
                stack.sockets.get_mut::<tcp::Socket>(handle).close();
            }
        }

        let mut chunks = Vec::new();
        {
            let socket = stack.sockets.get_mut::<tcp::Socket>(handle);
            while socket.can_recv() && chunks.len() < MAX_RECV_CHUNKS {
                match socket.recv(|buffer| {
                    let data = buffer.to_vec();
                    (data.len(), data)
                }) {
                    Ok(data) if !data.is_empty() => chunks.push(data),
                    _ => break,
                }
            }
        }

        let to_app = stack.tcp_conns[&id].to_app.clone();
        let mut app_gone = false;
        for chunk in chunks {
            if to_app.send(chunk).await.is_err() {
                app_gone = true;
                break;
            }
        }
        if app_gone {
            stack.sockets.get_mut::<tcp::Socket>(handle).abort();
        }

        let final_state = stack.sockets.get_mut::<tcp::Socket>(handle).state();
        if matches!(final_state, tcp::State::CloseWait) {
            stack.sockets.get_mut::<tcp::Socket>(handle).close();
        }
        if matches!(final_state, tcp::State::Closed)
            && stack.tcp_conns[&id].established
        {
            stack.sockets.remove(handle);
            stack.tcp_conns.remove(&id);
        }
    }
}

async fn service_udp(stack: &mut NetStack) {
    let ids: Vec<usize> = stack.udp_conns.keys().copied().collect();
    let idle_timeout = udp_idle_timeout();

    for id in ids {
        let handle = match stack.udp_conns.get(&id) {
            Some(state) => state.handle,
            None => continue,
        };

        if stack.udp_conns[&id].last_activity.elapsed() >= idle_timeout {
            let state = stack.udp_conns.remove(&id).unwrap();
            stack.sockets.remove(state.handle);
            log::debug!("expired idle netstack UDP association {id}");
            continue;
        }

        let mut packets = Vec::new();
        {
            let socket = stack.sockets.get_mut::<udp::Socket>(handle);
            while socket.can_recv() && packets.len() < MAX_RECV_CHUNKS {
                match socket.recv() {
                    Ok((data, metadata)) => {
                        packets.push((
                            endpoint_to_socketaddr(metadata.endpoint),
                            data.to_vec(),
                        ));
                    }
                    Err(_) => break,
                }
            }
        }

        if !packets.is_empty() {
            if let Some(state) = stack.udp_conns.get_mut(&id) {
                state.last_activity = StdInstant::now();
            }
        }

        let to_app = stack.udp_conns[&id].to_app.clone();
        let mut app_gone = false;
        for packet in packets {
            if to_app.send(packet).await.is_err() {
                app_gone = true;
                break;
            }
        }
        if app_gone {
            if let Some(state) = stack.udp_conns.remove(&id) {
                stack.sockets.remove(state.handle);
            }
        }
    }
}

async fn flush_tx(
    stack: &mut NetStack,
    outbound_tx: &mpsc::Sender<Vec<u8>>,
) -> Result<()> {
    while let Some(packet) = stack.device.tx.pop_front() {
        outbound_tx
            .send(packet)
            .await
            .map_err(|_| AetherError::Other("tunnel output channel closed".into()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_parsers_reject_invalid_prefixes() {
        assert!(parse_v4("172.16.0.2/32").is_ok());
        assert!(parse_v4("172.16.0.2/33").is_err());
        assert!(parse_v6("2606:4700::1/128").is_ok());
        assert!(parse_v6("2606:4700::1/129").is_err());
    }

    #[test]
    fn mtu_bounds_reject_invalid_values() {
        assert!(!(MIN_TUNNEL_MTU..=MAX_TUNNEL_MTU).contains(&0));
        assert!((MIN_TUNNEL_MTU..=MAX_TUNNEL_MTU).contains(&1280));
    }
}
