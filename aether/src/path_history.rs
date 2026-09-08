use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::net::{SocketAddr, UdpSocket};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

pub const HISTORY_CAP: usize = 32;
const FRESHNESS_WINDOW_MS: u64 = 24 * 60 * 60 * 1000;
const FNV_OFFSET: u64 = 0xcbf29ce484222325;
const FNV_PRIME: u64 = 0x100000001b3;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PathTransport {
    MasqueH3,
    MasqueH2,
    WireGuard,
    Gool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathObservation {
    pub peer: SocketAddr,
    pub transport: PathTransport,
    #[serde(default)]
    pub profile: String,
    #[serde(default)]
    pub successes: u32,
    #[serde(default)]
    pub failures: u32,
    #[serde(default)]
    pub last_seen_ms: u64,
    #[serde(default)]
    pub last_success_ms: u64,
    #[serde(default)]
    pub last_failure_ms: u64,
    #[serde(default)]
    pub rtt_ms: Option<u32>,
    #[serde(default)]
    pub jitter_ms: Option<u32>,
    #[serde(default)]
    pub quality_score: Option<u8>,
}

impl PathObservation {
    pub fn confidence(&self) -> f32 {
        ((self.successes + self.failures) as f32 / 8.0).min(1.0)
    }

    pub fn reliability(&self) -> f32 {
        let total = self.successes + self.failures;
        if total == 0 {
            0.0
        } else {
            self.successes as f32 / total as f32
        }
    }

    pub fn score_at(&self, now_ms: u64) -> f32 {
        let age = now_ms.saturating_sub(self.last_seen_ms);
        let freshness = 1.0 - (age as f32 / FRESHNESS_WINDOW_MS as f32).min(1.0);
        let latency_penalty = self
            .rtt_ms
            .map(|rtt| (rtt as f32 / 1000.0).min(1.0))
            .unwrap_or(0.0);
        let jitter_penalty = self
            .jitter_ms
            .map(|jitter| (jitter as f32 / 500.0).min(1.0))
            .unwrap_or(0.0);
        let quality = self
            .quality_score
            .map(|value| value as f32 / 100.0)
            .unwrap_or(0.5);

        (self.reliability() * 0.38
            + self.confidence() * 0.18
            + freshness * 0.16
            + quality * 0.28
            - latency_penalty * 0.06
            - jitter_penalty * 0.04)
            .max(0.0)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PathHistory {
    #[serde(default)]
    pub network_key: String,
    #[serde(default)]
    pub paths: Vec<PathObservation>,
}

impl PathHistory {
    pub fn rank(&self) -> Vec<&PathObservation> {
        let now = now_ms();
        let mut out: Vec<_> = self.paths.iter().collect();
        out.sort_by(|left, right| {
            right
                .score_at(now)
                .partial_cmp(&left.score_at(now))
                .unwrap_or(Ordering::Equal)
                .then_with(|| right.last_seen_ms.cmp(&left.last_seen_ms))
        });
        out
    }

    pub fn record_success(
        &mut self,
        peer: SocketAddr,
        transport: PathTransport,
        profile: &str,
        rtt_ms: Option<u32>,
        quality_score: Option<u8>,
    ) {
        let now = now_ms();
        let path = self.ensure(peer, transport, profile, now);
        path.successes = path.successes.saturating_add(1);
        path.last_seen_ms = now;
        path.last_success_ms = now;
        path.rtt_ms = rtt_ms.or(path.rtt_ms);
        path.quality_score = quality_score.or(path.quality_score);
        self.compact();
    }

    pub fn record_failure(&mut self, peer: SocketAddr, transport: PathTransport, profile: &str) {
        let now = now_ms();
        let path = self.ensure(peer, transport, profile, now);
        path.failures = path.failures.saturating_add(1);
        path.last_seen_ms = now;
        path.last_failure_ms = now;
        self.compact();
    }

    fn ensure(
        &mut self,
        peer: SocketAddr,
        transport: PathTransport,
        profile: &str,
        now: u64,
    ) -> &mut PathObservation {
        if let Some(index) = self.paths.iter().position(|path| {
            path.peer == peer && path.transport == transport && path.profile == profile
        }) {
            return &mut self.paths[index];
        }

        self.paths.push(PathObservation {
            peer,
            transport,
            profile: profile.to_string(),
            successes: 0,
            failures: 0,
            last_seen_ms: now,
            last_success_ms: 0,
            last_failure_ms: 0,
            rtt_ms: None,
            jitter_ms: None,
            quality_score: None,
        });
        self.paths.last_mut().expect("path was just inserted")
    }

    fn compact(&mut self) {
        let now = now_ms();
        self.paths.sort_by(|left, right| {
            right
                .score_at(now)
                .partial_cmp(&left.score_at(now))
                .unwrap_or(Ordering::Equal)
                .then_with(|| right.last_seen_ms.cmp(&left.last_seen_ms))
        });
        self.paths.truncate(HISTORY_CAP);
    }
}

pub fn load(path: &str) -> PathHistory {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|text| toml::from_str::<PathHistory>(&text).ok())
        .unwrap_or_default()
}

pub fn save(path: &str, history: &PathHistory) {
    let Ok(text) = toml::to_string_pretty(history) else {
        log::debug!("[path-history] failed to encode {path}");
        return;
    };

    let tmp = format!("{path}.tmp");
    if let Err(error) = std::fs::write(&tmp, text) {
        log::debug!("[path-history] failed to write {tmp}: {error}");
        return;
    }

    if let Err(error) = std::fs::rename(&tmp, path) {
        // Windows cannot replace an existing file with rename. Falling back to
        // a direct write keeps this optional optimization from blocking startup.
        if let Ok(text) = toml::to_string_pretty(history) {
            if let Err(write_error) = std::fs::write(path, text) {
                log::debug!(
                    "[path-history] failed to replace {path}: {error}; direct write also failed: {write_error}"
                );
            }
        }
        let _ = std::fs::remove_file(&tmp);
    }
}

pub fn record_success_file(
    path: &str,
    network_key: &str,
    peer: SocketAddr,
    transport: PathTransport,
    profile: &str,
    rtt_ms: Option<u32>,
    quality_score: Option<u8>,
) {
    let mut history = load(path);
    if history.network_key != network_key {
        history = PathHistory {
            network_key: network_key.to_string(),
            paths: Vec::new(),
        };
    }
    history.record_success(peer, transport, profile, rtt_ms, quality_score);
    save(path, &history);
}

pub fn record_failure_file(
    path: &str,
    network_key: &str,
    peer: SocketAddr,
    transport: PathTransport,
    profile: &str,
) {
    let mut history = load(path);
    if history.network_key != network_key {
        history = PathHistory {
            network_key: network_key.to_string(),
            paths: Vec::new(),
        };
    }
    history.record_failure(peer, transport, profile);
    save(path, &history);
}

fn stable_hash(input: &str) -> u64 {
    input
        .as_bytes()
        .iter()
        .fold(FNV_OFFSET, |hash, byte| (hash ^ u64::from(*byte)).wrapping_mul(FNV_PRIME))
}

fn routed_local_ip(target: &str, bind: &str) -> Option<String> {
    let socket = UdpSocket::bind(bind).ok()?;
    socket.connect(target).ok()?;
    Some(socket.local_addr().ok()?.ip().to_string())
}

fn local_route_material() -> Vec<String> {
    let mut out = Vec::new();
    if let Some(ip) = routed_local_ip("1.1.1.1:53", "0.0.0.0:0") {
        out.push(format!("src4={ip}"));
    }
    if let Some(ip) = routed_local_ip("[2606:4700:4700::1111]:53", "[::]:0") {
        out.push(format!("src6={ip}"));
    }
    out
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn platform_route_material() -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(text) = std::fs::read_to_string("/proc/net/route") {
        for line in text.lines().skip(1) {
            let fields: Vec<_> = line.split_whitespace().collect();
            if fields.len() >= 3 && fields[1] == "00000000" {
                out.push(format!("v4:{}:{}", fields[0], fields[2]));
            }
        }
    }
    if let Ok(text) = std::fs::read_to_string("/proc/net/ipv6_route") {
        for line in text.lines() {
            let fields: Vec<_> = line.split_whitespace().collect();
            if fields.len() >= 10
                && fields[0] == "00000000000000000000000000000000"
                && fields[1] == "00"
            {
                out.push(format!("v6:{}:{}", fields[fields.len() - 1], fields[4]));
            }
        }
    }
    out
}

#[cfg(target_os = "macos")]
fn platform_route_material() -> Vec<String> {
    let Ok(output) = Command::new("route").args(["-n", "get", "default"]).output() else {
        return Vec::new();
    };
    let text = String::from_utf8_lossy(&output.stdout);
    let mut out = Vec::new();
    for line in text.lines().map(str::trim) {
        if let Some(value) = line.strip_prefix("gateway:") {
            out.push(format!("gateway={}", value.trim()));
        } else if let Some(value) = line.strip_prefix("interface:") {
            out.push(format!("interface={}", value.trim()));
        }
    }
    out
}

#[cfg(windows)]
fn platform_route_material() -> Vec<String> {
    let Ok(output) = Command::new("route").args(["print", "-4"]).output() else {
        return Vec::new();
    };
    let text = String::from_utf8_lossy(&output.stdout);
    text.lines()
        .filter_map(|line| {
            let fields: Vec<_> = line.split_whitespace().collect();
            (fields.len() >= 4 && fields[0] == "0.0.0.0" && fields[1] == "0.0.0.0")
                .then(|| format!("v4:{}:{}", fields[2], fields[3]))
        })
        .collect()
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    windows
)))]
fn platform_route_material() -> Vec<String> {
    Vec::new()
}

fn detected_network_key() -> Option<String> {
    let mut material = platform_route_material();
    material.extend(local_route_material());
    material.sort();
    material.dedup();
    if material.is_empty() {
        return None;
    }
    Some(format!("route-v1:{:016x}", stable_hash(&material.join("|"))))
}

pub fn network_key_from_env() -> String {
    std::env::var("AETHER_NETWORK_KEY")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .or_else(detected_network_key)
        // Do not share persistent winners across unknown underlays. A
        // process-scoped key preserves correctness at the cost of replay only.
        .unwrap_or_else(|| format!("unknown-process:{}", std::process::id()))
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_path(tag: &str) -> String {
        let mut path = std::env::temp_dir();
        path.push(format!("aether-path-history-{tag}-{}.toml", std::process::id()));
        let _ = std::fs::remove_file(&path);
        path.to_string_lossy().to_string()
    }

    #[test]
    fn reliable_fresh_path_beats_failed_path() {
        let now = now_ms();
        let good = PathObservation {
            peer: "1.1.1.1:443".parse().unwrap(),
            transport: PathTransport::MasqueH2,
            profile: "firewall".into(),
            successes: 6,
            failures: 1,
            last_seen_ms: now,
            last_success_ms: now,
            last_failure_ms: 0,
            rtt_ms: Some(140),
            jitter_ms: Some(12),
            quality_score: Some(88),
        };
        let bad = PathObservation {
            peer: "1.0.0.1:443".parse().unwrap(),
            transport: PathTransport::MasqueH2,
            profile: "firewall".into(),
            successes: 1,
            failures: 5,
            last_seen_ms: now,
            last_success_ms: now,
            last_failure_ms: now,
            rtt_ms: Some(80),
            jitter_ms: Some(10),
            quality_score: Some(35),
        };
        assert!(good.score_at(now) > bad.score_at(now));
    }

    #[test]
    fn history_is_bounded() {
        let mut history = PathHistory::default();
        for index in 1..=64u16 {
            history.record_success(
                format!("10.0.0.1:{}", 1000 + index).parse().unwrap(),
                PathTransport::WireGuard,
                "balanced",
                Some(index as u32),
                Some(80),
            );
        }
        assert_eq!(history.paths.len(), HISTORY_CAP);
    }

    #[test]
    fn repeated_observations_update_one_tuple() {
        let mut history = PathHistory::default();
        let peer = "1.1.1.1:443".parse().unwrap();
        history.record_success(peer, PathTransport::MasqueH3, "firewall", Some(100), Some(90));
        history.record_failure(peer, PathTransport::MasqueH3, "firewall");
        assert_eq!(history.paths.len(), 1);
        assert_eq!(history.paths[0].successes, 1);
        assert_eq!(history.paths[0].failures, 1);
    }

    #[test]
    fn file_helpers_reset_when_network_context_changes() {
        let path = tmp_path("network");
        let peer: SocketAddr = "1.1.1.1:443".parse().unwrap();
        record_success_file(
            &path,
            "wifi-a",
            peer,
            PathTransport::MasqueH3,
            "firewall",
            Some(100),
            Some(90),
        );
        assert_eq!(load(&path).paths.len(), 1);
        record_failure_file(
            &path,
            "wifi-b",
            peer,
            PathTransport::MasqueH3,
            "firewall",
        );
        let reloaded = load(&path);
        assert_eq!(reloaded.network_key, "wifi-b");
        assert_eq!(reloaded.paths.len(), 1);
        assert_eq!(reloaded.paths[0].successes, 0);
        assert_eq!(reloaded.paths[0].failures, 1);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn stable_hash_does_not_expose_route_material() {
        let material = "v4:wlan0:0101A8C0|src4=192.168.1.7";
        let fingerprint = format!("route-v1:{:016x}", stable_hash(material));
        assert!(!fingerprint.contains("192.168"));
        assert!(!fingerprint.contains("wlan0"));
    }
}
