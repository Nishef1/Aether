use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

/// How many recently-working endpoints are remembered for the fast path.
pub const RECENT_CAP: usize = 8;
const FAILURE_CAP: usize = 16;
const FAILURE_COOLDOWN_SECS: [u64; 4] = [30, 120, 300, 600];

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FailedEndpoint {
    pub peer: String,
    #[serde(default)]
    pub failures: u32,
    #[serde(default)]
    pub last_failure_ms: u64,
    #[serde(default)]
    pub cooldown_until_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LastConnection {
    pub peer: String,
    #[serde(default)]
    pub profile: String,
    /// Most-recent-first ring of working `ip:port`s. Old files simply lack
    /// it and load as empty, so this stays backward compatible.
    #[serde(default)]
    pub recent: Vec<String>,
    /// Persistent negative knowledge for recent peers. This is intentionally
    /// small and additive so old lastconn files continue to deserialize.
    #[serde(default)]
    pub failed: Vec<FailedEndpoint>,
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

pub fn load(path: &str) -> Option<LastConnection> {
    let text = std::fs::read_to_string(path).ok()?;
    toml::from_str(&text).ok()
}

fn persist(path: &str, conn: &LastConnection) {
    match toml::to_string_pretty(conn) {
        Ok(text) => {
            if let Err(e) = std::fs::write(path, text) {
                log::debug!("[lastconn] failed to save {path}: {e}");
            }
        }
        Err(e) => log::debug!("[lastconn] failed to encode: {e}"),
    }
}

pub fn save(path: &str, peer: &str, profile: &str) {
    let mut conn = load(path).unwrap_or_default();
    conn.peer = peer.to_string();
    conn.profile = profile.to_string();
    conn.recent.retain(|p| p != peer);
    conn.recent.insert(0, peer.to_string());
    conn.recent.truncate(RECENT_CAP);
    conn.failed.retain(|entry| entry.peer != peer);
    conn.failed
        .sort_by_key(|entry| std::cmp::Reverse(entry.last_failure_ms));
    conn.failed.truncate(FAILURE_CAP);
    persist(path, &conn);
}

/// Record a failed fast-path verification and persist a bounded exponential
/// cooldown. Fresh scans are still allowed to rediscover the endpoint later.
pub fn record_failure(path: &str, peer: SocketAddr) {
    let mut conn = load(path).unwrap_or_default();
    let peer = peer.to_string();
    let now = now_ms();

    if let Some(entry) = conn.failed.iter_mut().find(|entry| entry.peer == peer) {
        entry.failures = entry.failures.saturating_add(1);
        entry.last_failure_ms = now;
        let index = (entry.failures.saturating_sub(1) as usize).min(FAILURE_COOLDOWN_SECS.len() - 1);
        entry.cooldown_until_ms = now.saturating_add(FAILURE_COOLDOWN_SECS[index] * 1000);
    } else {
        conn.failed.push(FailedEndpoint {
            peer,
            failures: 1,
            last_failure_ms: now,
            cooldown_until_ms: now.saturating_add(FAILURE_COOLDOWN_SECS[0] * 1000),
        });
    }

    conn.failed
        .sort_by_key(|entry| std::cmp::Reverse(entry.last_failure_ms));
    conn.failed.truncate(FAILURE_CAP);
    persist(path, &conn);
}

fn is_cooled(cached: &LastConnection, peer: SocketAddr, now: u64) -> bool {
    cached
        .failed
        .iter()
        .find(|entry| entry.peer == peer.to_string())
        .map(|entry| entry.cooldown_until_ms > now)
        .unwrap_or(false)
}

/// Parsed, most-recent-first candidates for the reconnect fast path. Peers in
/// an active persisted cooldown are skipped, but remain eligible for a later
/// full scan after the cooldown expires.
pub fn recent_peers(cached: &LastConnection) -> Vec<SocketAddr> {
    recent_peers_at(cached, now_ms())
}

fn recent_peers_at(cached: &LastConnection, now: u64) -> Vec<SocketAddr> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for raw in std::iter::once(&cached.peer).chain(cached.recent.iter()) {
        if let Ok(addr) = raw.parse::<SocketAddr>() {
            if seen.insert(addr) && !is_cooled(cached, addr, now) {
                out.push(addr);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_path(tag: &str) -> String {
        let mut p = std::env::temp_dir();
        p.push(format!("aether-lastconn-test-{tag}-{}.toml", std::process::id()));
        let _ = std::fs::remove_file(&p);
        p.to_string_lossy().to_string()
    }

    #[test]
    fn save_builds_a_most_recent_first_ring() {
        let path = tmp_path("ring");
        save(&path, "1.1.1.1:443", "gfw");
        save(&path, "1.0.0.1:443", "gfw");
        save(&path, "1.1.1.1:443", "gfw");
        let loaded = load(&path).expect("saved file must load");
        assert_eq!(loaded.peer, "1.1.1.1:443", "peer stays the latest");
        assert_eq!(loaded.recent, vec!["1.1.1.1:443", "1.0.0.1:443"]);
        assert!(loaded.failed.is_empty());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn ring_is_capped_and_deduped() {
        let path = tmp_path("cap");
        for i in 0..20u8 {
            save(&path, &format!("10.0.0.{i}:443"), "balanced");
        }
        let loaded = load(&path).expect("saved file must load");
        assert_eq!(loaded.recent.len(), RECENT_CAP);
        assert_eq!(loaded.recent[0], "10.0.0.19:443");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn old_files_without_recent_or_failed_still_load() {
        let path = tmp_path("legacy");
        std::fs::write(&path, "peer = \"1.1.1.1:443\"\nprofile = \"gfw\"\n").unwrap();
        let loaded = load(&path).expect("legacy file must load");
        assert_eq!(loaded.peer, "1.1.1.1:443");
        assert!(loaded.recent.is_empty());
        assert!(loaded.failed.is_empty());
        assert_eq!(recent_peers(&loaded), vec!["1.1.1.1:443".parse().unwrap()]);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn recent_peers_skips_garbage_dupes_and_active_cooldown() {
        let peer: SocketAddr = "1.1.1.1:443".parse().unwrap();
        let cached = LastConnection {
            peer: "not-an-addr".to_string(),
            profile: String::new(),
            recent: vec![peer.to_string(), peer.to_string(), "1.0.0.1:443".to_string()],
            failed: vec![FailedEndpoint {
                peer: peer.to_string(),
                failures: 2,
                last_failure_ms: 1_000,
                cooldown_until_ms: 10_000,
            }],
        };
        assert_eq!(
            recent_peers_at(&cached, 5_000),
            vec!["1.0.0.1:443".parse().unwrap()]
        );
        assert_eq!(
            recent_peers_at(&cached, 10_001),
            vec![peer, "1.0.0.1:443".parse().unwrap()]
        );
    }

    #[test]
    fn failure_cooldown_grows_and_success_clears_it() {
        let path = tmp_path("failure");
        save(&path, "1.1.1.1:443", "gfw");
        let peer: SocketAddr = "1.1.1.1:443".parse().unwrap();
        record_failure(&path, peer);
        let first = load(&path).unwrap();
        assert_eq!(first.failed.len(), 1);
        assert_eq!(first.failed[0].failures, 1);
        let first_until = first.failed[0].cooldown_until_ms;

        record_failure(&path, peer);
        let second = load(&path).unwrap();
        assert_eq!(second.failed[0].failures, 2);
        assert!(second.failed[0].cooldown_until_ms > first_until);

        save(&path, &peer.to_string(), "gfw");
        let recovered = load(&path).unwrap();
        assert!(recovered.failed.is_empty());
        let _ = std::fs::remove_file(&path);
    }
}
