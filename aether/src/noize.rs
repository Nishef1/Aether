use std::net::SocketAddr;
use std::time::Duration;

use rand::{Rng, RngCore};
use tokio::net::UdpSocket;

const MAX_JUNK_PACKETS: usize = 32;
const MIN_JUNK_SIZE: usize = 1;
const MAX_JUNK_SIZE: usize = 1200;
const MAX_SIGNATURE_BYTES: usize = 2048;
const MAX_JUNK_INTERVAL: Duration = Duration::from_millis(100);

#[derive(Debug, Clone)]
pub struct NoizeConfig {
    pub jc_before_hs: usize,
    pub jc_after_i1: usize,
    pub jmin: usize,
    pub jmax: usize,
    pub i1: Option<String>,
    pub i2: Option<String>,
    pub junk_interval: Duration,
}

impl NoizeConfig {
    pub fn off() -> Self {
        Self {
            jc_before_hs: 0,
            jc_after_i1: 0,
            jmin: 0,
            jmax: 0,
            i1: None,
            i2: None,
            junk_interval: Duration::ZERO,
        }
    }

    pub fn firewall() -> Self {
        Self {
            jc_before_hs: 2,
            jc_after_i1: 2,
            jmin: 48,
            jmax: 190,
            i1: Some("<b 0d0a0d0a><t><r 24>".to_string()),
            i2: Some("<r 48>".to_string()),
            junk_interval: Duration::from_millis(4),
        }
    }

    pub fn gfw() -> Self {
        Self {
            jc_before_hs: 2,
            jc_after_i1: 1,
            jmin: 64,
            jmax: 256,
            i1: Some("<b 0d0a0d0a><t><r 24>".to_string()),
            i2: Some("<r 32>".to_string()),
            junk_interval: Duration::from_millis(5),
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.jc_before_hs > 0 || self.jc_after_i1 > 0 || self.i1.is_some()
    }

    fn bounded_counts(&self) -> (usize, usize) {
        (
            self.jc_before_hs.min(MAX_JUNK_PACKETS),
            self.jc_after_i1.min(MAX_JUNK_PACKETS),
        )
    }

    fn bounded_interval(&self) -> Duration {
        self.junk_interval.min(MAX_JUNK_INTERVAL)
    }
}

pub fn from_profile(name: &str) -> NoizeConfig {
    match name {
        "off" | "none" => NoizeConfig::off(),
        "gfw" => NoizeConfig::gfw(),
        _ => NoizeConfig::firewall(),
    }
}

fn junk_packet(config: &NoizeConfig) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let low = config.jmin.clamp(MIN_JUNK_SIZE, MAX_JUNK_SIZE);
    let high = config
        .jmax
        .clamp(MIN_JUNK_SIZE, MAX_JUNK_SIZE)
        .max(low);
    let size = rng.gen_range(low..=high);
    let mut buffer = vec![0u8; size];
    rng.fill_bytes(&mut buffer);
    buffer
}

fn parse_cps(spec: &str) -> Vec<u8> {
    let mut output = Vec::new();
    let bytes = spec.as_bytes();
    let mut index = 0;
    while index < bytes.len() && output.len() < MAX_SIGNATURE_BYTES {
        if bytes[index] != b'<' {
            index += 1;
            continue;
        }
        let end = match spec[index..].find('>') {
            Some(relative) => index + relative,
            None => break,
        };
        let inner = spec[index + 1..end].trim();
        let mut parts = inner.splitn(2, char::is_whitespace);
        let tag = parts.next().unwrap_or("");
        let data = parts.next().unwrap_or("").trim();

        match tag {
            "b" => {
                let hex: String = data.chars().filter(|value| !value.is_whitespace()).collect();
                if let Ok(decoded) = hex::decode(&hex) {
                    let remaining = MAX_SIGNATURE_BYTES.saturating_sub(output.len());
                    output.extend_from_slice(&decoded[..decoded.len().min(remaining)]);
                }
            }
            "t" => {
                let timestamp = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|duration| duration.as_secs() as u32)
                    .unwrap_or(0);
                output.extend_from_slice(&timestamp.to_be_bytes());
            }
            "n" => {
                let nonce: u64 = rand::random();
                output.extend_from_slice(&nonce.to_be_bytes());
            }
            "r" => {
                let requested: usize = data.parse().unwrap_or(0);
                let remaining = MAX_SIGNATURE_BYTES.saturating_sub(output.len());
                let length = requested.min(MAX_SIGNATURE_BYTES).min(remaining);
                if length > 0 {
                    let mut random = vec![0u8; length];
                    rand::thread_rng().fill_bytes(&mut random);
                    output.extend_from_slice(&random);
                }
            }
            _ => {}
        }

        output.truncate(MAX_SIGNATURE_BYTES);
        index = end + 1;
    }
    output
}

async fn send_packet(
    socket: &UdpSocket,
    peer: SocketAddr,
    packet: &[u8],
    label: &str,
) -> bool {
    match socket.send_to(packet, peer).await {
        Ok(written) => {
            log::trace!("{label} sent {written} bytes");
            true
        }
        Err(error) => {
            log::debug!("{label} send failed: {error}");
            false
        }
    }
}

pub async fn pre_handshake(socket: &UdpSocket, peer: SocketAddr, config: &NoizeConfig) {
    if !config.is_enabled() {
        return;
    }

    let (before_count, after_count) = config.bounded_counts();
    let interval = config.bounded_interval();
    log::trace!("sending {before_count} bounded junk packets before handshake");

    for index in 0..before_count {
        let packet = junk_packet(config);
        if !send_packet(socket, peer, &packet, &format!("junk[{index}]")).await {
            return;
        }
        if !interval.is_zero() {
            tokio::time::sleep(interval).await;
        }
    }

    if let Some(signature) = &config.i1 {
        let packet = parse_cps(signature);
        if !packet.is_empty() {
            if !send_packet(socket, peer, &packet, "signature i1").await {
                return;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    }

    for index in 0..after_count {
        let packet = junk_packet(config);
        if !send_packet(
            socket,
            peer,
            &packet,
            &format!("junk_after[{index}]"),
        )
        .await
        {
            return;
        }
        if !interval.is_zero() {
            tokio::time::sleep(interval).await;
        }
    }

    if let Some(signature) = &config.i2 {
        let packet = parse_cps(signature);
        if !packet.is_empty() {
            let _ = send_packet(socket, peer, &packet, "signature i2").await;
        }
    }

    log::trace!("obfuscation pre-handshake complete");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn junk_sizes_and_signatures_are_bounded() {
        let mut config = NoizeConfig::firewall();
        config.jmin = 0;
        config.jmax = usize::MAX;
        let packet = junk_packet(&config);
        assert!((MIN_JUNK_SIZE..=MAX_JUNK_SIZE).contains(&packet.len()));
        assert_eq!(parse_cps("<r 999999>").len(), MAX_SIGNATURE_BYTES);
    }

    #[test]
    fn packet_counts_are_bounded() {
        let mut config = NoizeConfig::firewall();
        config.jc_before_hs = usize::MAX;
        config.jc_after_i1 = usize::MAX;
        assert_eq!(config.bounded_counts(), (MAX_JUNK_PACKETS, MAX_JUNK_PACKETS));
    }
}
