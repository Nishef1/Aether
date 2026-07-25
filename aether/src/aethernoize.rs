use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rand::{Rng, RngCore};
use regex::Regex;
use tokio::net::UdpSocket;

const MAX_TRACKED_SOCKETS: usize = 1024;

static POST_HANDSHAKE_SENT: OnceLock<Mutex<HashSet<SocketAddr>>> = OnceLock::new();
static KEEPALIVE_ACTIVE: OnceLock<Mutex<HashSet<SocketAddr>>> = OnceLock::new();

#[derive(Debug, Clone)]
pub struct AetherNoizeConfig {
    pub i1: Option<String>,
    pub i2: Option<String>,
    pub i3: Option<String>,
    pub i4: Option<String>,
    pub i5: Option<String>,
    pub jc: usize,
    pub jc_before_hs: usize,
    pub jc_after_i1: usize,
    pub jc_after_hs: usize,
    pub jmin: usize,
    pub jmax: usize,
    pub junk_interval: Duration,
    pub handshake_delay: Duration,
    pub allow_zero_size: bool,
}

impl AetherNoizeConfig {
    pub fn off() -> Self {
        Self {
            i1: None,
            i2: None,
            i3: None,
            i4: None,
            i5: None,
            jc: 0,
            jc_before_hs: 0,
            jc_after_i1: 0,
            jc_after_hs: 0,
            jmin: 0,
            jmax: 0,
            junk_interval: Duration::ZERO,
            handshake_delay: Duration::ZERO,
            allow_zero_size: false,
        }
    }

    pub fn light() -> Self {
        Self {
            i1: Some("<b 0d0a0d0a><t><r 20-32>".to_string()),
            i2: Some("<rc 24-48>".to_string()),
            i3: None,
            i4: None,
            i5: None,
            jc: 4,
            jc_before_hs: 2,
            jc_after_i1: 1,
            jc_after_hs: 1,
            jmin: 48,
            jmax: 190,
            junk_interval: Duration::from_millis(3),
            handshake_delay: Duration::from_millis(5),
            allow_zero_size: false,
        }
    }

    pub fn balanced() -> Self {
        Self {
            i1: Some("<b 0d0a0d0a><t><rc 20-40>".to_string()),
            i2: Some("<b 504f5354><rd 10-20><rc 20-30>".to_string()),
            i3: Some("<r 30-50>".to_string()),
            i4: None,
            i5: None,
            jc: 6,
            jc_before_hs: 3,
            jc_after_i1: 2,
            jc_after_hs: 1,
            jmin: 64,
            jmax: 256,
            junk_interval: Duration::from_millis(2),
            handshake_delay: Duration::from_millis(8),
            allow_zero_size: false,
        }
    }

    pub fn aggressive() -> Self {
        Self {
            i1: Some("<b 0d0a0d0a><t><rc 40-64>".to_string()),
            i2: Some("<b 504f5354><t><rd 15-30><rc 30-50>".to_string()),
            i3: Some("<b 474554><rc 40-60>".to_string()),
            i4: Some("<r 60-100>".to_string()),
            i5: Some("<c><rd 20-40>".to_string()),
            jc: 10,
            jc_before_hs: 4,
            jc_after_i1: 3,
            jc_after_hs: 3,
            jmin: 80,
            jmax: 384,
            junk_interval: Duration::from_millis(1),
            handshake_delay: Duration::from_millis(12),
            allow_zero_size: false,
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.jc > 0 || self.i1.is_some()
    }
}

pub fn from_profile(name: &str) -> AetherNoizeConfig {
    match name {
        "off" | "none" => AetherNoizeConfig::off(),
        "light" => AetherNoizeConfig::light(),
        "aggressive" | "heavy" => AetherNoizeConfig::aggressive(),
        _ => AetherNoizeConfig::balanced(),
    }
}

fn parse_range(data: &str) -> usize {
    let mut parts = data.split('-');
    if let (Some(min_str), Some(max_str)) = (parts.next(), parts.next()) {
        let min: usize = min_str.trim().parse().unwrap_or(0);
        let max: usize = max_str.trim().parse().unwrap_or(0);
        if max > min && min > 0 {
            return rand::thread_rng().gen_range(min..=max).min(2048);
        }
    }
    data.trim().parse().unwrap_or(0).min(2048)
}

pub fn parse_cps(spec: &str) -> Vec<u8> {
    let mut out = Vec::new();

    let tag_regex = Regex::new(r"<([a-z]+)\s*([^>]*)>").unwrap();

    for cap in tag_regex.captures_iter(spec) {
        let tag_type = cap.get(1).map_or("", |value| value.as_str());
        let tag_data = cap.get(2).map_or("", |value| value.as_str()).trim();

        match tag_type {
            "b" => {
                let hex_str: String = tag_data.chars().filter(|value| !value.is_whitespace()).collect();
                let clean = hex_str
                    .strip_prefix("0x")
                    .or_else(|| hex_str.strip_prefix("0X"))
                    .unwrap_or(&hex_str);
                if let Ok(decoded) = hex::decode(clean) {
                    out.extend_from_slice(&decoded);
                }
            }
            "t" => {
                let timestamp = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|duration| duration.as_secs() as u32)
                    .unwrap_or(0);
                out.extend_from_slice(&timestamp.to_be_bytes());
            }
            "c" => {
                let counter = (SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|duration| duration.as_secs())
                    .unwrap_or(0)
                    % 0xFFFFFFFF) as u32;
                out.extend_from_slice(&counter.to_be_bytes());
            }
            "r" => {
                let len = parse_range(tag_data);
                if len > 0 {
                    let mut random = vec![0u8; len];
                    rand::thread_rng().fill_bytes(&mut random);
                    out.extend_from_slice(&random);
                }
            }
            "rc" => {
                let len = parse_range(tag_data);
                if len > 0 {
                    let chars = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
                    let mut random = vec![0u8; len];
                    for byte in random.iter_mut() {
                        *byte = chars[rand::thread_rng().gen_range(0..chars.len())];
                    }
                    out.extend_from_slice(&random);
                }
            }
            "rd" => {
                let len = parse_range(tag_data);
                if len > 0 {
                    let chars = b"0123456789";
                    let mut random = vec![0u8; len];
                    for byte in random.iter_mut() {
                        *byte = chars[rand::thread_rng().gen_range(0..chars.len())];
                    }
                    out.extend_from_slice(&random);
                }
            }
            _ => {}
        }
    }

    out
}

fn wrap_ikev2(payload: &[u8]) -> Vec<u8> {
    if payload.is_empty() {
        return payload.to_vec();
    }

    let mut initiator_spi = [0u8; 8];
    let mut responder_spi = [0u8; 8];

    if payload.len() >= 8 {
        initiator_spi.copy_from_slice(&payload[..8]);
    } else {
        rand::thread_rng().fill_bytes(&mut initiator_spi);
    }
    rand::thread_rng().fill_bytes(&mut responder_spi);

    let total_length = 28u32 + 24 + payload.len() as u32;
    let sa_payload_length = 24u16 + payload.len() as u16;

    let mut header = Vec::with_capacity(total_length as usize);

    header.extend_from_slice(&initiator_spi);
    header.extend_from_slice(&responder_spi);
    header.push(0x21);
    header.push(0x20);
    header.push(0x22);
    header.push(0x08);
    header.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    header.extend_from_slice(&total_length.to_be_bytes());

    header.push(0x00);
    header.push(0x00);
    header.extend_from_slice(&sa_payload_length.to_be_bytes());

    header.extend_from_slice(&[
        0x00, 0x00, 0x00, 0x14, 0x01, 0x01, 0x00, 0x04, 0x03, 0x00, 0x00, 0x08, 0x01, 0x00,
        0x00, 0x0c, 0x00, 0x00, 0x00, 0x00,
    ]);

    header.extend_from_slice(payload);
    header
}

fn generate_junk(cfg: &AetherNoizeConfig) -> Vec<u8> {
    let (min_size, max_size) = match (cfg.jmin, cfg.jmax) {
        (0, 0) if cfg.allow_zero_size => return vec![],
        (0, 0) => return vec![0x00],
        (min, 0) if !cfg.allow_zero_size => (min.max(1), min.max(1)),
        (min, max) if !cfg.allow_zero_size => (min.max(1), max.max(min)),
        (min, max) => (min, max.max(min)),
    };

    let size = if max_size == min_size {
        min_size
    } else {
        rand::thread_rng().gen_range(min_size..=max_size)
    };

    if size == 0 {
        return if cfg.allow_zero_size {
            vec![]
        } else {
            vec![0x00]
        };
    }

    let mut junk = vec![0u8; size];
    rand::thread_rng().fill_bytes(&mut junk);
    junk
}

async fn send_connected(sock: &UdpSocket, packet: &[u8]) -> bool {
    match sock.send(packet).await {
        Ok(_) => true,
        Err(error) => {
            log::debug!("aethernoize send failed: {error}");
            false
        }
    }
}

fn insert_bounded_once(
    state: &'static OnceLock<Mutex<HashSet<SocketAddr>>>,
    address: SocketAddr,
) -> bool {
    let state = state.get_or_init(|| Mutex::new(HashSet::new()));
    match state.lock() {
        Ok(mut tracked) => {
            if tracked.len() >= MAX_TRACKED_SOCKETS {
                tracked.clear();
            }
            tracked.insert(address)
        }
        Err(_) => false,
    }
}

fn remove_tracked(
    state: &'static OnceLock<Mutex<HashSet<SocketAddr>>>,
    address: SocketAddr,
) {
    if let Some(state) = state.get() {
        if let Ok(mut tracked) = state.lock() {
            tracked.remove(&address);
        }
    }
}

pub async fn apply_obfuscation(sock: &UdpSocket, _peer: SocketAddr, cfg: &AetherNoizeConfig) {
    if !cfg.is_enabled() {
        return;
    }

    if let Some(ref i1) = cfg.i1 {
        let payload = parse_cps(i1);
        if !payload.is_empty() {
            let framed = wrap_ikev2(&payload);
            if !send_connected(sock, &framed).await {
                return;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    }

    for _ in 0..cfg.jc_after_i1 {
        let junk = generate_junk(cfg);
        if !send_connected(sock, &junk).await {
            return;
        }
        if !cfg.junk_interval.is_zero() {
            tokio::time::sleep(cfg.junk_interval).await;
        }
    }

    for _ in 0..cfg.jc_before_hs {
        let junk = generate_junk(cfg);
        if !send_connected(sock, &junk).await {
            return;
        }
        if !cfg.junk_interval.is_zero() {
            tokio::time::sleep(cfg.junk_interval).await;
        }
    }

    for signature in [&cfg.i2, &cfg.i3, &cfg.i4, &cfg.i5].iter() {
        if let Some(spec) = signature {
            let packet = parse_cps(spec);
            if !packet.is_empty() {
                if !send_connected(sock, &packet).await {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        }
    }

    if !cfg.handshake_delay.is_zero() {
        tokio::time::sleep(cfg.handshake_delay).await;
    }
}

pub async fn send_post_handshake_junk(
    sock: &UdpSocket,
    _peer: SocketAddr,
    cfg: &AetherNoizeConfig,
) {
    if cfg.jc_after_hs == 0 {
        return;
    }

    let Ok(local_address) = sock.local_addr() else {
        return;
    };
    if !insert_bounded_once(&POST_HANDSHAKE_SENT, local_address) {
        return;
    }

    for _ in 0..cfg.jc_after_hs {
        let junk = generate_junk(cfg);
        if !send_connected(sock, &junk).await {
            return;
        }
        if !cfg.junk_interval.is_zero() {
            tokio::time::sleep(cfg.junk_interval).await;
        }
    }
}

pub async fn send_keepalive_junk(sock: &UdpSocket, cfg: &AetherNoizeConfig) {
    if !cfg.is_enabled() {
        return;
    }

    let Ok(local_address) = sock.local_addr() else {
        return;
    };
    if !insert_bounded_once(&KEEPALIVE_ACTIVE, local_address) {
        log::trace!("aethernoize keepalive junk already active for {local_address}");
        return;
    }

    let base = cfg.jc_before_hs.max(1);
    let extra = rand::thread_rng().gen_range(0..=base);
    let count = base + extra;

    for _ in 0..count {
        let mut junk = generate_junk(cfg);
        if let Some(first) = junk.first_mut() {
            if (1..=4).contains(first) {
                *first = first.wrapping_add(0x40);
            }
        }
        if !send_connected(sock, &junk).await {
            break;
        }

        let jitter = rand::thread_rng().gen_range(0..=8);
        let gap = cfg.junk_interval + Duration::from_millis(jitter);
        if !gap.is_zero() {
            tokio::time::sleep(gap).await;
        }
    }

    remove_tracked(&KEEPALIVE_ACTIVE, local_address);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_range_is_bounded() {
        assert_eq!(parse_range("999999"), 2048);
        assert_eq!(parse_range("0"), 0);
    }

    #[test]
    fn cps_output_never_exceeds_per_tag_limit() {
        let output = parse_cps("<r 4096><rc 4096><rd 4096>");
        assert_eq!(output.len(), 2048 * 3);
    }
}
