use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Semaphore;

use crate::error::{AetherError, Result};
use crate::netstack::StackHandle;

const VER: u8 = 0x05;
const AUTH_NONE: u8 = 0x00;
const AUTH_UNACCEPTABLE: u8 = 0xff;
const CMD_CONNECT: u8 = 0x01;
const CMD_UDP_ASSOCIATE: u8 = 0x03;
const ATYP_V4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_V6: u8 = 0x04;
const REP_OK: u8 = 0x00;
const REP_GENERAL: u8 = 0x01;
const REP_NOT_SUPPORTED: u8 = 0x07;
const NEGOTIATION_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);
const DNS_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug)]
enum Target {
    Ip(IpAddr),
    Domain(String),
}

fn max_clients() -> usize {
    match crate::sysprofile::tuning().tier {
        crate::sysprofile::Tier::Low => 64,
        crate::sysprofile::Tier::Medium => 256,
        crate::sysprofile::Tier::High => 512,
    }
}

pub async fn serve(listen: SocketAddr, stack: StackHandle) -> Result<()> {
    let listener = TcpListener::bind(listen).await?;
    log::info!("socks5 listening on {listen}");
    let bind_ip = listen.ip();
    let permits = Arc::new(Semaphore::new(max_clients()));

    loop {
        let (sock, peer) = listener.accept().await?;
        let permit = match permits.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                log::warn!("socks client limit reached; rejecting {peer}");
                drop(sock);
                continue;
            }
        };
        let stack = stack.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(error) = handle_client(sock, stack, bind_ip).await {
                log::debug!("socks client {peer} ended: {error}");
            }
        });
    }
}

async fn handle_client(mut sock: TcpStream, stack: StackHandle, bind_ip: IpAddr) -> Result<()> {
    tokio::time::timeout(NEGOTIATION_TIMEOUT, handshake(&mut sock))
        .await
        .map_err(|_| AetherError::Other("socks greeting timeout".into()))??;

    let (cmd, target, port) = tokio::time::timeout(NEGOTIATION_TIMEOUT, async {
        let mut head = [0u8; 4];
        sock.read_exact(&mut head).await?;
        if head[0] != VER {
            return Err(AetherError::Other("bad socks version".into()));
        }
        if head[2] != 0 {
            return Err(AetherError::Other("bad socks reserved byte".into()));
        }

        let (target, port) = read_target(&mut sock, head[3]).await?;
        Ok::<_, AetherError>((head[1], target, port))
    })
    .await
    .map_err(|_| AetherError::Other("socks request timeout".into()))??;

    match cmd {
        CMD_CONNECT => handle_connect(sock, stack, target, port).await,
        CMD_UDP_ASSOCIATE => handle_udp_associate(sock, stack, bind_ip).await,
        _ => {
            reply(&mut sock, REP_NOT_SUPPORTED).await?;
            Err(AetherError::Other("unsupported socks command".into()))
        }
    }
}

async fn handshake(sock: &mut TcpStream) -> Result<()> {
    let mut prefix = [0u8; 2];
    sock.read_exact(&mut prefix).await?;
    if prefix[0] != VER {
        return Err(AetherError::Other("bad greeting version".into()));
    }
    let method_count = prefix[1] as usize;
    if method_count == 0 {
        sock.write_all(&[VER, AUTH_UNACCEPTABLE]).await?;
        return Err(AetherError::Other("empty authentication method list".into()));
    }

    let mut methods = vec![0u8; method_count];
    sock.read_exact(&mut methods).await?;
    if !methods.contains(&AUTH_NONE) {
        sock.write_all(&[VER, AUTH_UNACCEPTABLE]).await?;
        return Err(AetherError::Other(
            "client does not support unauthenticated SOCKS".into(),
        ));
    }
    sock.write_all(&[VER, AUTH_NONE]).await?;
    Ok(())
}

async fn read_target(sock: &mut TcpStream, address_type: u8) -> Result<(Target, u16)> {
    let target = match address_type {
        ATYP_V4 => {
            let mut bytes = [0u8; 4];
            sock.read_exact(&mut bytes).await?;
            Target::Ip(IpAddr::V4(Ipv4Addr::from(bytes)))
        }
        ATYP_V6 => {
            let mut bytes = [0u8; 16];
            sock.read_exact(&mut bytes).await?;
            Target::Ip(IpAddr::V6(bytes.into()))
        }
        ATYP_DOMAIN => {
            let mut length = [0u8; 1];
            sock.read_exact(&mut length).await?;
            if length[0] == 0 {
                return Err(AetherError::Other("empty domain name".into()));
            }
            let mut name = vec![0u8; length[0] as usize];
            sock.read_exact(&mut name).await?;
            let name = String::from_utf8(name)
                .map_err(|_| AetherError::Other("domain name is not valid UTF-8".into()))?;
            validate_dns_name(&name)?;
            Target::Domain(name)
        }
        _ => return Err(AetherError::Other("bad address type".into())),
    };

    let mut port = [0u8; 2];
    sock.read_exact(&mut port).await?;
    let port = u16::from_be_bytes(port);
    if port == 0 {
        return Err(AetherError::Other("zero destination port".into()));
    }
    Ok((target, port))
}

async fn reply(sock: &mut TcpStream, code: u8) -> Result<()> {
    sock.write_all(&[VER, code, 0x00, ATYP_V4, 0, 0, 0, 0, 0, 0])
        .await?;
    Ok(())
}

async fn reply_bound(sock: &mut TcpStream, bound: SocketAddr) -> Result<()> {
    let mut buffer = vec![VER, REP_OK, 0x00];
    match bound.ip() {
        IpAddr::V4(address) => {
            buffer.push(ATYP_V4);
            buffer.extend_from_slice(&address.octets());
        }
        IpAddr::V6(address) => {
            buffer.push(ATYP_V6);
            buffer.extend_from_slice(&address.octets());
        }
    }
    buffer.extend_from_slice(&bound.port().to_be_bytes());
    sock.write_all(&buffer).await?;
    Ok(())
}

async fn resolve(stack: &StackHandle, target: Target) -> Result<IpAddr> {
    match target {
        Target::Ip(ip) => Ok(ip),
        Target::Domain(name) => {
            if let Ok(ip) = name.parse::<IpAddr>() {
                return Ok(ip);
            }
            dns_resolve(stack, &name).await
        }
    }
}

pub(crate) async fn dns_resolve(stack: &StackHandle, name: &str) -> Result<IpAddr> {
    validate_dns_name(name)?;
    match dns_query(stack, name, 1).await {
        Ok(address) => Ok(address),
        Err(a_error) => dns_query(stack, name, 28)
            .await
            .map_err(|aaaa_error| {
                AetherError::Other(format!(
                    "DNS resolution failed for {name}: A={a_error}; AAAA={aaaa_error}"
                ))
            }),
    }
}

async fn dns_query(stack: &StackHandle, name: &str, query_type: u16) -> Result<IpAddr> {
    let udp = stack.open_udp().await?;
    let server: SocketAddr = "1.1.1.1:53".parse().unwrap();
    let (query_id, query) = build_dns_query(name, query_type)?;
    udp.send_to(server, query).await?;

    let (sender, mut from_stack) = udp.into_split();
    let response = tokio::time::timeout(DNS_TIMEOUT, from_stack.recv()).await;
    sender.close().await;

    let response = response
        .map_err(|_| AetherError::Other("dns timeout".into()))?
        .ok_or_else(|| AetherError::Other("dns channel closed".into()))?;
    if response.0.ip() != server.ip() || response.0.port() != server.port() {
        return Err(AetherError::Other(format!(
            "unexpected DNS responder {}",
            response.0
        )));
    }

    parse_dns_answer(&response.1, query_id, query_type)
        .ok_or_else(|| AetherError::Other(format!("no requested DNS record for {name}")))
}

fn validate_dns_name(name: &str) -> Result<()> {
    let name = name.trim_end_matches('.');
    if name.is_empty() || name.len() > 253 {
        return Err(AetherError::Other("invalid DNS name length".into()));
    }
    for label in name.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(AetherError::Other("invalid DNS label length".into()));
        }
    }
    Ok(())
}

fn build_dns_query(name: &str, query_type: u16) -> Result<(u16, Vec<u8>)> {
    validate_dns_name(name)?;
    let name = name.trim_end_matches('.');
    let mut query = Vec::with_capacity(32 + name.len());
    let id: u16 = rand::random();
    query.extend_from_slice(&id.to_be_bytes());
    query.extend_from_slice(&[0x01, 0x00]);
    query.extend_from_slice(&[0x00, 0x01]);
    query.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    for label in name.split('.') {
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0x00);
    query.extend_from_slice(&query_type.to_be_bytes());
    query.extend_from_slice(&[0x00, 0x01]);
    Ok((id, query))
}

fn parse_dns_answer(response: &[u8], expected_id: u16, query_type: u16) -> Option<IpAddr> {
    if response.len() < 12 {
        return None;
    }
    if u16::from_be_bytes([response[0], response[1]]) != expected_id {
        return None;
    }
    let flags = u16::from_be_bytes([response[2], response[3]]);
    if flags & 0x8000 == 0 || flags & 0x000f != 0 {
        return None;
    }

    let question_count = u16::from_be_bytes([response[4], response[5]]) as usize;
    let answer_count = u16::from_be_bytes([response[6], response[7]]) as usize;
    let mut position = 12;

    for _ in 0..question_count {
        position = skip_name(response, position)?;
        position = position.checked_add(4)?;
        if position > response.len() {
            return None;
        }
    }

    for _ in 0..answer_count {
        position = skip_name(response, position)?;
        if position + 10 > response.len() {
            return None;
        }
        let record_type = u16::from_be_bytes([response[position], response[position + 1]]);
        let record_class = u16::from_be_bytes([response[position + 2], response[position + 3]]);
        let data_length =
            u16::from_be_bytes([response[position + 8], response[position + 9]]) as usize;
        position += 10;
        if position + data_length > response.len() {
            return None;
        }
        if record_class == 1 && record_type == query_type {
            match (record_type, data_length) {
                (1, 4) => {
                    return Some(IpAddr::V4(Ipv4Addr::new(
                        response[position],
                        response[position + 1],
                        response[position + 2],
                        response[position + 3],
                    )));
                }
                (28, 16) => {
                    let mut bytes = [0u8; 16];
                    bytes.copy_from_slice(&response[position..position + 16]);
                    return Some(IpAddr::V6(bytes.into()));
                }
                _ => {}
            }
        }
        position += data_length;
    }
    None
}

fn skip_name(buffer: &[u8], mut position: usize) -> Option<usize> {
    let start = position;
    loop {
        let length = *buffer.get(position)?;
        if length & 0xc0 == 0xc0 {
            if position + 1 >= buffer.len() {
                return None;
            }
            return Some(position + 2);
        }
        if length & 0xc0 != 0 || length > 63 {
            return None;
        }
        if length == 0 {
            return Some(position + 1);
        }
        position = position.checked_add(1 + length as usize)?;
        if position > buffer.len() || position.saturating_sub(start) > 255 {
            return None;
        }
    }
}

async fn handle_connect(
    mut sock: TcpStream,
    stack: StackHandle,
    target: Target,
    port: u16,
) -> Result<()> {
    let ip = match resolve(&stack, target).await {
        Ok(ip) => ip,
        Err(error) => {
            let _ = reply(&mut sock, REP_GENERAL).await;
            return Err(error);
        }
    };

    let destination = SocketAddr::new(ip, port);
    let connection = match tokio::time::timeout(CONNECT_TIMEOUT, stack.open_tcp(destination)).await {
        Ok(Ok(connection)) => connection,
        Ok(Err(error)) => {
            let _ = reply(&mut sock, REP_GENERAL).await;
            return Err(error);
        }
        Err(_) => {
            let _ = reply(&mut sock, REP_GENERAL).await;
            return Err(AetherError::Other(format!(
                "TCP connect timeout for {destination}"
            )));
        }
    };

    reply_bound(&mut sock, "0.0.0.0:0".parse().unwrap()).await?;

    let (sender, mut from_stack) = connection.into_split();
    let (mut reader, mut writer) = sock.into_split();

    let upload = tokio::spawn(async move {
        let mut buffer = vec![0u8; 16384];
        loop {
            match reader.read(&mut buffer).await {
                Ok(0) => {
                    sender.close().await;
                    return Ok::<(), AetherError>(());
                }
                Ok(read) => {
                    sender.send(buffer[..read].to_vec()).await?;
                }
                Err(error) => {
                    sender.close().await;
                    return Err(AetherError::Io(error));
                }
            }
        }
    });

    let download_result = async {
        while let Some(chunk) = from_stack.recv().await {
            writer.write_all(&chunk).await?;
        }
        writer.shutdown().await?;
        Ok::<(), AetherError>(())
    }
    .await;

    upload.abort();
    download_result
}

async fn handle_udp_associate(
    mut sock: TcpStream,
    stack: StackHandle,
    bind_ip: IpAddr,
) -> Result<()> {
    let relay = UdpSocket::bind(SocketAddr::new(bind_ip, 0)).await?;
    let relay_address = relay.local_addr()?;
    reply_bound(&mut sock, relay_address).await?;

    let udp = stack.open_udp().await?;
    let (sender, mut from_stack) = udp.into_split();

    let mut client: Option<SocketAddr> = None;
    let mut client_buffer = vec![0u8; 65535];
    let mut control_buffer = [0u8; 256];

    let result = loop {
        tokio::select! {
            result = relay.recv_from(&mut client_buffer) => {
                let (read, from) = match result {
                    Ok(value) => value,
                    Err(error) => break Err(AetherError::Io(error)),
                };
                match client {
                    Some(expected) if expected != from => {
                        log::debug!("ignoring UDP packet from unexpected SOCKS client {from}");
                        continue;
                    }
                    None => client = Some(from),
                    _ => {}
                }

                if let Some((target, (port, payload))) = parse_udp_request(&client_buffer[..read]) {
                    let destination = match target {
                        Target::Ip(ip) => SocketAddr::new(ip, port),
                        Target::Domain(name) => match dns_resolve(&stack, &name).await {
                            Ok(ip) => SocketAddr::new(ip, port),
                            Err(error) => {
                                log::debug!("UDP domain resolution failed: {error}");
                                continue;
                            }
                        },
                    };
                    if let Err(error) = sender.send_to(destination, payload).await {
                        break Err(error);
                    }
                }
            }

            maybe = from_stack.recv() => {
                let (source, data) = match maybe {
                    Some(value) => value,
                    None => break Err(AetherError::Other("UDP netstack channel closed".into())),
                };
                if let Some(client_address) = client {
                    let packet = build_udp_reply(source, &data);
                    if let Err(error) = relay.send_to(&packet, client_address).await {
                        break Err(AetherError::Io(error));
                    }
                }
            }

            result = sock.read(&mut control_buffer) => {
                match result {
                    Ok(0) => break Ok(()),
                    Ok(_) => {}
                    Err(error) => break Err(AetherError::Io(error)),
                }
            }
        }
    };

    sender.close().await;
    result
}

fn parse_udp_request(buffer: &[u8]) -> Option<(Target, (u16, Vec<u8>))> {
    if buffer.len() < 4 || buffer[0] != 0 || buffer[1] != 0 || buffer[2] != 0 {
        return None;
    }
    let address_type = buffer[3];
    let mut position = 4;
    let target = match address_type {
        ATYP_V4 => {
            if buffer.len() < position + 4 {
                return None;
            }
            let ip = Ipv4Addr::new(
                buffer[position],
                buffer[position + 1],
                buffer[position + 2],
                buffer[position + 3],
            );
            position += 4;
            Target::Ip(IpAddr::V4(ip))
        }
        ATYP_V6 => {
            if buffer.len() < position + 16 {
                return None;
            }
            let mut bytes = [0u8; 16];
            bytes.copy_from_slice(&buffer[position..position + 16]);
            position += 16;
            Target::Ip(IpAddr::V6(bytes.into()))
        }
        ATYP_DOMAIN => {
            let length = *buffer.get(position)? as usize;
            position += 1;
            if length == 0 || buffer.len() < position + length {
                return None;
            }
            let name = String::from_utf8(buffer[position..position + length].to_vec()).ok()?;
            validate_dns_name(&name).ok()?;
            position += length;
            Target::Domain(name)
        }
        _ => return None,
    };

    if buffer.len() < position + 2 {
        return None;
    }
    let port = u16::from_be_bytes([buffer[position], buffer[position + 1]]);
    if port == 0 {
        return None;
    }
    position += 2;
    Some((target, (port, buffer[position..].to_vec())))
}

fn build_udp_reply(source: SocketAddr, data: &[u8]) -> Vec<u8> {
    let mut packet = vec![0x00, 0x00, 0x00];
    match source.ip() {
        IpAddr::V4(address) => {
            packet.push(ATYP_V4);
            packet.extend_from_slice(&address.octets());
        }
        IpAddr::V6(address) => {
            packet.push(ATYP_V6);
            packet.extend_from_slice(&address.octets());
        }
    }
    packet.extend_from_slice(&source.port().to_be_bytes());
    packet.extend_from_slice(data);
    packet
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_names_reject_empty_and_oversized_labels() {
        assert!(validate_dns_name("example.com").is_ok());
        assert!(validate_dns_name("").is_err());
        assert!(validate_dns_name(&format!("{}.com", "a".repeat(64))).is_err());
    }

    #[test]
    fn udp_request_rejects_fragmentation_and_zero_ports() {
        assert!(parse_udp_request(&[0, 0, 1, ATYP_V4, 1, 1, 1, 1, 0, 53]).is_none());
        assert!(parse_udp_request(&[0, 0, 0, ATYP_V4, 1, 1, 1, 1, 0, 0]).is_none());
    }
}
