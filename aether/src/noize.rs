use std::net::SocketAddr;
use std::time::Duration;

use rand::Rng;
use rand::RngExt;
use tokio::net::UdpSocket;

#[derive(Debug, Clone, PartialEq, Eq)]
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

    pub fn light() -> Self {
        Self {
            jc_before_hs: 1,
            jc_after_i1: 0,
            jmin: 32,
            jmax: 96,
            i1: Some("<b 0d0a0d0a><t><r 12-20>".to_string()),
            i2: None,
            junk_interval: Duration::from_millis(3),
        }
    }

    /// Conservative MASQUE cover traffic for ordinary restrictive firewalls.
    /// Keep this as the MASQUE default: it adds diversity without the larger
    /// burst sizes used by the censorship-focused profiles.
    pub fn firewall() -> Self {
        Self {
            jc_before_hs: 2,
            jc_after_i1: 1,
            jmin: 48,
            jmax: 176,
            i1: Some("<b 0d0a0d0a><t><n><r 16-28>".to_string()),
            i2: Some("<r 32-56>".to_string()),
            junk_interval: Duration::from_millis(4),
        }
    }

    /// General-purpose profile with wider packet-size variance than firewall.
    pub fn balanced() -> Self {
        Self {
            jc_before_hs: 2,
            jc_after_i1: 2,
            jmin: 56,
            jmax: 224,
            i1: Some("<t><n><r 20-36>".to_string()),
            i2: Some("<b 504f5354><r 40-64>".to_string()),
            junk_interval: Duration::from_millis(3),
        }
    }

    /// Heavier profile intended for networks doing aggressive UDP/DPI filtering.
    /// It intentionally uses a different signature family and slower spacing
    /// instead of being an alias for `aggressive`.
    pub fn gfw() -> Self {
        Self {
            jc_before_hs: 3,
            jc_after_i1: 2,
            jmin: 72,
            jmax: 320,
            i1: Some("<n><t><r 28-52>".to_string()),
            i2: Some("<b 47455420><n><r 48-80>".to_string()),
            junk_interval: Duration::from_millis(5),
        }
    }

    /// Maximum built-in MASQUE cover traffic. This remains opt-in because the
    /// extra packets and delay can cost battery and connection setup time.
    pub fn aggressive() -> Self {
        Self {
            jc_before_hs: 4,
            jc_after_i1: 3,
            jmin: 88,
            jmax: 448,
            i1: Some("<n><t><r 40-72>".to_string()),
            i2: Some("<b 504f5354><n><r 72-112>".to_string()),
            junk_interval: Duration::from_millis(2),
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.jc_before_hs > 0 || self.jc_after_i1 > 0 || self.i1.is_some()
    }
}

pub fn from_profile(name: &str) -> NoizeConfig {
    match name.trim().to_ascii_lowercase().as_str() {
        "off" | "none" => NoizeConfig::off(),
        "light" => NoizeConfig::light(),
        "firewall" => NoizeConfig::firewall(),
        "balanced" => NoizeConfig::balanced(),
        "gfw" => NoizeConfig::gfw(),
        "aggressive" | "heavy" => NoizeConfig::aggressive(),
        _ => NoizeConfig::firewall(),
    }
}

fn parse_range(data: &str) -> usize {
    let mut parts = data.split('-');
    if let (Some(min_str), Some(max_str)) = (parts.next(), parts.next()) {
        let min: usize = min_str.trim().parse().unwrap_or(0);
        let max: usize = max_str.trim().parse().unwrap_or(0);
        if max >= min && min > 0 {
            return if max == min {
                min.min(2048)
            } else {
                rand::rng().random_range(min..=max).min(2048)
            };
        }
    }
    data.trim().parse().unwrap_or(0).min(2048)
}

fn junk_packet(cfg: &NoizeConfig) -> Vec<u8> {
    let mut rng = rand::rng();
    let (lo, hi) = if cfg.jmax > cfg.jmin && cfg.jmin > 0 {
        (cfg.jmin, cfg.jmax)
    } else {
        (40, 90)
    };
    let size = rng.random_range(lo..=hi);
    let mut buf = vec![0u8; size];
    rand::rng().fill_bytes(&mut buf);
    buf
}

fn parse_cps(spec: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let bytes = spec.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'<' {
            i += 1;
            continue;
        }
        let end = match spec[i..].find('>') {
            Some(e) => i + e,
            None => break,
        };
        let inner = spec[i + 1..end].trim();
        let mut parts = inner.splitn(2, char::is_whitespace);
        let tag = parts.next().unwrap_or("");
        let data = parts.next().unwrap_or("").trim();

        match tag {
            "b" => {
                let hexstr: String = data.chars().filter(|c| !c.is_whitespace()).collect();
                if let Ok(decoded) = hex::decode(&hexstr) {
                    out.extend_from_slice(&decoded);
                }
            }
            "t" => {
                let ts = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as u32)
                    .unwrap_or(0);
                out.extend_from_slice(&ts.to_be_bytes());
            }
            "n" => {
                let nonce: u64 = rand::random();
                out.extend_from_slice(&nonce.to_be_bytes());
            }
            "r" => {
                let len = parse_range(data);
                if len > 0 {
                    let mut r = vec![0u8; len];
                    rand::rng().fill_bytes(&mut r);
                    out.extend_from_slice(&r);
                }
            }
            _ => {}
        }

        i = end + 1;
    }
    out
}

pub async fn pre_handshake(sock: &UdpSocket, peer: SocketAddr, cfg: &NoizeConfig) {
    if !cfg.is_enabled() {
        return;
    }

    log::trace!("sending {} junk packets before handshake", cfg.jc_before_hs);

    for i in 0..cfg.jc_before_hs {
        let pkt = junk_packet(cfg);
        match sock.send_to(&pkt, peer).await {
            Ok(n) => log::trace!("junk[{i}] sent {n} bytes"),
            Err(e) => log::debug!("junk[{i}] send failed: {e}"),
        }
        if !cfg.junk_interval.is_zero() {
            tokio::time::sleep(cfg.junk_interval).await;
        }
    }

    if let Some(i1) = &cfg.i1 {
        let pkt = parse_cps(i1);
        if !pkt.is_empty() {
            match sock.send_to(&pkt, peer).await {
                Ok(n) => log::trace!("signature i1 sent {n} bytes"),
                Err(e) => log::debug!("signature i1 send failed: {e}"),
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    }

    for i in 0..cfg.jc_after_i1 {
        let pkt = junk_packet(cfg);
        match sock.send_to(&pkt, peer).await {
            Ok(n) => log::trace!("junk_after[{i}] sent {n} bytes"),
            Err(e) => log::debug!("junk_after[{i}] send failed: {e}"),
        }
        if !cfg.junk_interval.is_zero() {
            tokio::time::sleep(cfg.junk_interval).await;
        }
    }

    if let Some(i2) = &cfg.i2 {
        let pkt = parse_cps(i2);
        if !pkt.is_empty() {
            match sock.send_to(&pkt, peer).await {
                Ok(n) => log::trace!("signature i2 sent {n} bytes"),
                Err(e) => log::debug!("signature i2 send failed: {e}"),
            }
        }
    }

    log::trace!("obfuscation pre-handshake complete");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app_profiles() -> [NoizeConfig; 6] {
        [
            from_profile("off"),
            from_profile("light"),
            from_profile("firewall"),
            from_profile("balanced"),
            from_profile("gfw"),
            from_profile("aggressive"),
        ]
    }

    #[test]
    fn every_profile_the_app_offers_maps_to_a_distinct_config() {
        let profiles = app_profiles();
        for left in 0..profiles.len() {
            for right in (left + 1)..profiles.len() {
                assert_ne!(
                    profiles[left], profiles[right],
                    "profiles at indexes {left} and {right} unexpectedly alias"
                );
            }
        }
    }

    #[test]
    fn every_enabled_profile_has_bounded_random_cover_traffic() {
        for cfg in app_profiles().into_iter().filter(NoizeConfig::is_enabled) {
            assert!(cfg.jmin > 0);
            assert!(cfg.jmax >= cfg.jmin);
            let packet = junk_packet(&cfg);
            assert!((cfg.jmin..=cfg.jmax).contains(&packet.len()));
        }
    }

    #[test]
    fn cps_random_ranges_are_bounded() {
        for _ in 0..32 {
            let packet = parse_cps("<b 0102><r 12-20>");
            assert!((14..=22).contains(&packet.len()));
        }
    }

    #[test]
    fn aliases_and_case_normalization_remain_compatible() {
        assert_eq!(from_profile("none"), from_profile("off"));
        assert_eq!(from_profile("heavy"), from_profile("aggressive"));
        assert_eq!(from_profile(" GFW "), from_profile("gfw"));
    }

    #[test]
    fn unknown_profile_keeps_the_masque_firewall_default() {
        assert_eq!(from_profile("something-else"), from_profile("firewall"));
    }
}
