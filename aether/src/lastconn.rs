use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

#[path = "path_history.rs"]
mod path_history;
use path_history::PathTransport;

/// How many recently-working endpoints are remembered for the fast path.
pub const RECENT_CAP: usize = 8;
const FAILURE_CAP: usize = 16;
const FAILURE_COOLDOWN_SECS: [u64; 4] = [30, 120, 300, 600];
const PENDING_FAST_PATH_TTL_MS: u64 = 15 * 60 * 1000;

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
    /// Underlay fingerprint that owns every positive/negative observation in
    /// this file. Legacy files leave it blank and are intentionally not replayed
    /// until a new success scopes them to the current network.
    #[serde(default)]
    pub network_key: String,
    /// Most-recent-first ring of working `ip:port`s. Old files simply lack
    /// it and load as empty, so this stays backward compatible.
    #[serde(default)]
    pub recent: Vec<String>,
    /// Persistent negative knowledge for recent peers. This is intentionally
    /// small and additive so old lastconn files continue to deserialize.
    #[serde(default)]
    pub failed: Vec<FailedEndpoint>,
    /// Ordered fast-path candidates offered to the current quick reconnect.
    /// `save()` resolves this against the eventual winner so only candidates
    /// that were actually tried before the winner accrue a failure cooldown.
    #[serde(default)]
    pub pending_fast_path: Vec<String>,
    #[serde(default)]
    pub pending_fast_path_ms: u64,
    /// Runtime-only origin used to find the matching PathHistory file.
    #[serde(skip)]
    source_path: String,
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

fn history_path(path: &str) -> String {
    format!("{path}.history")
}

fn env_truthy(key: &str) -> bool {
    std::env::var(key)
        .ok()
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

fn active_transport() -> PathTransport {
    match std::env::var("AETHER_PROTOCOL")
        .unwrap_or_else(|_| "masque".to_string())
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "wg" | "wireguard" => PathTransport::WireGuard,
        "gool" | "wiw" | "warp-in-warp" | "warpinwarp" => PathTransport::Gool,
        _ if env_truthy("AETHER_MASQUE_HTTP2") => PathTransport::MasqueH2,
        _ => PathTransport::MasqueH3,
    }
}

pub fn load(path: &str) -> Option<LastConnection> {
    let text = std::fs::read_to_string(path).ok()?;
    let mut conn: LastConnection = toml::from_str(&text).ok()?;
    conn.source_path = path.to_string();
    Some(conn)
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

fn scoped_connection(path: &str) -> LastConnection {
    let network_key = path_history::network_key_from_env();
    let mut conn = load(path).unwrap_or_default();
    if conn.network_key != network_key {
        conn = LastConnection {
            network_key,
            source_path: path.to_string(),
            ..Default::default()
        };
    } else {
        conn.source_path = path.to_string();
    }
    conn
}

fn record_history_success(path: &str, peer: &str, profile: &str) {
    let Ok(peer) = peer.parse::<SocketAddr>() else {
        return;
    };
    path_history::record_success_file(
        &history_path(path),
        &path_history::network_key_from_env(),
        peer,
        active_transport(),
        profile,
        None,
        None,
    );
}

fn record_history_failure(path: &str, peer: SocketAddr, profile: &str) {
    path_history::record_failure_file(
        &history_path(path),
        &path_history::network_key_from_env(),
        peer,
        active_transport(),
        profile,
    );
}

fn apply_failure(conn: &mut LastConnection, peer: SocketAddr, now: u64) {
    let peer_text = peer.to_string();
    if let Some(entry) = conn.failed.iter_mut().find(|entry| entry.peer == peer_text) {
        entry.failures = entry.failures.saturating_add(1);
        entry.last_failure_ms = now;
        let index =
            (entry.failures.saturating_sub(1) as usize).min(FAILURE_COOLDOWN_SECS.len() - 1);
        entry.cooldown_until_ms = now.saturating_add(FAILURE_COOLDOWN_SECS[index] * 1000);
    } else {
        conn.failed.push(FailedEndpoint {
            peer: peer_text,
            failures: 1,
            last_failure_ms: now,
            cooldown_until_ms: now.saturating_add(FAILURE_COOLDOWN_SECS[0] * 1000),
        });
    }
}

fn resolve_pending_fast_path(conn: &mut LastConnection, winner: &str, now: u64) -> Vec<SocketAddr> {
    let pending = std::mem::take(&mut conn.pending_fast_path);
    let pending_at = std::mem::take(&mut conn.pending_fast_path_ms);
    if pending.is_empty()
        || pending_at == 0
        || now.saturating_sub(pending_at) > PENDING_FAST_PATH_TTL_MS
    {
        return Vec::new();
    }

    // Fast-path callers verify candidates strictly in this recorded order and
    // stop at the first success. Therefore every entry before a cached winner
    // failed. If the eventual winner is not in this list, the reconnect ring
    // was exhausted and a fresh scan won, so every pending cached peer failed.
    let failed_len = pending
        .iter()
        .position(|candidate| candidate == winner)
        .unwrap_or(pending.len());
    let mut failed = Vec::new();
    for candidate in pending.into_iter().take(failed_len) {
        if let Ok(peer) = candidate.parse::<SocketAddr>() {
            apply_failure(conn, peer, now);
            failed.push(peer);
        }
    }
    failed
}

pub fn save(path: &str, peer: &str, profile: &str) {
    let mut conn = scoped_connection(path);
    let now = now_ms();
    let previous_profile = conn.profile.clone();
    let failed_fast_path = resolve_pending_fast_path(&mut conn, peer, now);

    conn.peer = peer.to_string();
    conn.profile = profile.to_string();
    conn.recent.retain(|p| p != peer);
    conn.recent.insert(0, peer.to_string());
    conn.recent.truncate(RECENT_CAP);
    // A successful full tunnel always clears any old cooldown for its winner.
    conn.failed.retain(|entry| entry.peer != peer);
    conn.failed
        .sort_by_key(|entry| std::cmp::Reverse(entry.last_failure_ms));
    conn.failed.truncate(FAILURE_CAP);
    persist(path, &conn);

    let failed_profile = if previous_profile.trim().is_empty() {
        profile
    } else {
        &previous_profile
    };
    for failed in failed_fast_path {
        record_history_failure(path, failed, failed_profile);
    }
    record_history_success(path, peer, profile);
}

/// Record a failed fast-path verification and persist a bounded exponential
/// cooldown. Fresh scans are still allowed to rediscover the endpoint later.
pub fn record_failure(path: &str, peer: SocketAddr) {
    let mut conn = scoped_connection(path);
    let now = now_ms();
    apply_failure(&mut conn, peer, now);

    conn.failed
        .sort_by_key(|entry| std::cmp::Reverse(entry.last_failure_ms));
    conn.failed.truncate(FAILURE_CAP);
    let profile = conn.profile.clone();
    persist(path, &conn);
    record_history_failure(path, peer, &profile);
}

fn is_cooled(cached: &LastConnection, peer: SocketAddr, now: u64) -> bool {
    cached
        .failed
        .iter()
        .find(|entry| entry.peer == peer.to_string())
        .map(|entry| entry.cooldown_until_ms > now)
        .unwrap_or(false)
}

fn diversity_bucket(peer: SocketAddr) -> String {
    match peer.ip() {
        std::net::IpAddr::V4(ip) => {
            let octets = ip.octets();
            format!("v4:{:02x}{:02x}{:02x}", octets[0], octets[1], octets[2])
        }
        std::net::IpAddr::V6(ip) => {
            let octets = ip.octets();
            format!(
                "v6:{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                octets[0], octets[1], octets[2], octets[3], octets[4], octets[5]
            )
        }
    }
}

/// Preserve the strongest winner at index zero, then prefer different /24
/// (IPv4) or /48 (IPv6) failure domains before retrying another peer from the
/// same bucket. No candidate is dropped and score order is preserved within
/// each pass.
fn diversify_ranked(peers: Vec<SocketAddr>) -> Vec<SocketAddr> {
    let mut iter = peers.into_iter();
    let Some(first) = iter.next() else {
        return Vec::new();
    };

    let mut out = vec![first];
    let mut seen_buckets = HashSet::from([diversity_bucket(first)]);
    let mut deferred = Vec::new();
    for peer in iter {
        if seen_buckets.insert(diversity_bucket(peer)) {
            out.push(peer);
        } else {
            deferred.push(peer);
        }
    }
    out.extend(deferred);
    out
}

/// Parsed candidates for the reconnect fast path. Active cooldowns are removed,
/// then paths observed on this network are ordered by persistent quality/history;
/// unseen peers retain their original recent-first order.
pub fn recent_peers(cached: &LastConnection) -> Vec<SocketAddr> {
    let now = now_ms();
    let out = recent_peers_at(cached, now);

    if !cached.source_path.is_empty() {
        let mut pending = cached.clone();
        if env_truthy("AETHER_QUICK_RECONNECT") && !out.is_empty() {
            // Explicit non-interactive quick reconnect: remember exactly what
            // the verifier is about to try, in order.
            pending.pending_fast_path = out.iter().map(ToString::to_string).collect();
            pending.pending_fast_path_ms = now;
            persist(&cached.source_path, &pending);
        } else if !pending.pending_fast_path.is_empty() || pending.pending_fast_path_ms != 0 {
            // A later fresh/interactive connection proves any older in-flight
            // attempt was abandoned. Clear it before a future save can mistake
            // cancellation for failed network evidence.
            pending.pending_fast_path.clear();
            pending.pending_fast_path_ms = 0;
            persist(&cached.source_path, &pending);
        }
    }

    out
}

fn recent_peers_at(cached: &LastConnection, now: u64) -> Vec<SocketAddr> {
    let current_network = path_history::network_key_from_env();
    if !cached.source_path.is_empty() && cached.network_key != current_network {
        return Vec::new();
    }

    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for raw in std::iter::once(&cached.peer).chain(cached.recent.iter()) {
        if let Ok(addr) = raw.parse::<SocketAddr>() {
            if seen.insert(addr) && !is_cooled(cached, addr, now) {
                out.push(addr);
            }
        }
    }

    if cached.source_path.is_empty() {
        return diversify_ranked(out);
    }

    let history = path_history::load(&history_path(&cached.source_path));
    if history.network_key != current_network {
        return diversify_ranked(out);
    }

    let transport = active_transport();
    let order: HashMap<SocketAddr, usize> = history
        .rank()
        .into_iter()
        .filter(|path| path.transport == transport)
        .enumerate()
        .map(|(index, path)| (path.peer, index))
        .collect();

    out.sort_by_key(|peer| order.get(peer).copied().unwrap_or(usize::MAX));
    diversify_ranked(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_path(tag: &str) -> String {
        let mut p = std::env::temp_dir();
        p.push(format!("aether-lastconn-test-{tag}-{}.toml", std::process::id()));
        let _ = std::fs::remove_file(&p);
        let _ = std::fs::remove_file(format!("{}.history", p.to_string_lossy()));
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
        assert!(!loaded.network_key.is_empty());
        assert!(loaded.failed.is_empty());
        assert!(loaded.pending_fast_path.is_empty());
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(history_path(&path));
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
        let _ = std::fs::remove_file(history_path(&path));
    }

    #[test]
    fn old_files_load_but_are_not_replayed_across_unknown_networks() {
        let path = tmp_path("legacy");
        std::fs::write(&path, "peer = \"1.1.1.1:443\"\nprofile = \"gfw\"\n").unwrap();
        let loaded = load(&path).expect("legacy file must load");
        assert_eq!(loaded.peer, "1.1.1.1:443");
        assert!(loaded.network_key.is_empty());
        assert!(loaded.recent.is_empty());
        assert!(loaded.failed.is_empty());
        assert!(loaded.pending_fast_path.is_empty());
        assert!(recent_peers(&loaded).is_empty());
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
            ..Default::default()
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
    fn rescue_order_prefers_distinct_failure_domains_without_dropping_peers() {
        let peers: Vec<SocketAddr> = [
            "10.0.0.1:443",
            "10.0.0.2:443",
            "10.0.1.1:443",
            "[2606:4700:4700::1]:443",
            "10.0.0.3:443",
        ]
        .into_iter()
        .map(|value| value.parse().unwrap())
        .collect();
        let diversified = diversify_ranked(peers.clone());
        assert_eq!(diversified[0], peers[0], "best winner must stay first");
        assert_eq!(diversified.len(), peers.len());
        assert_eq!(diversified[1], peers[2]);
        assert_eq!(diversified[2], peers[3]);
        assert!(diversified[3..].contains(&peers[1]));
        assert!(diversified[3..].contains(&peers[4]));
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
        let _ = std::fs::remove_file(history_path(&path));
    }

    #[test]
    fn pending_fast_path_marks_only_failed_prefix_before_cached_winner() {
        let path = tmp_path("pending-prefix");
        save(&path, "1.1.1.1:443", "firewall");
        save(&path, "1.0.0.1:443", "firewall");
        save(&path, "9.9.9.9:443", "firewall");

        let mut cached = load(&path).unwrap();
        cached.pending_fast_path = vec![
            "9.9.9.9:443".into(),
            "1.0.0.1:443".into(),
            "1.1.1.1:443".into(),
        ];
        cached.pending_fast_path_ms = now_ms();
        persist(&path, &cached);

        save(&path, "1.0.0.1:443", "firewall");
        let resolved = load(&path).unwrap();
        assert_eq!(resolved.failed.len(), 1);
        assert_eq!(resolved.failed[0].peer, "9.9.9.9:443");
        assert!(resolved.pending_fast_path.is_empty());
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(history_path(&path));
    }

    #[test]
    fn pending_fast_path_marks_all_cached_candidates_when_fresh_scan_wins() {
        let path = tmp_path("pending-fresh");
        save(&path, "1.1.1.1:443", "firewall");
        let mut cached = load(&path).unwrap();
        cached.pending_fast_path = vec!["1.1.1.1:443".into(), "1.0.0.1:443".into()];
        cached.pending_fast_path_ms = now_ms();
        persist(&path, &cached);

        save(&path, "8.8.8.8:443", "firewall");
        let resolved = load(&path).unwrap();
        assert_eq!(resolved.failed.len(), 2);
        assert!(resolved.failed.iter().any(|entry| entry.peer == "1.1.1.1:443"));
        assert!(resolved.failed.iter().any(|entry| entry.peer == "1.0.0.1:443"));
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(history_path(&path));
    }

    #[test]
    fn abandoned_pending_fast_path_expires_without_false_failures() {
        let mut cached = LastConnection {
            pending_fast_path: vec!["1.1.1.1:443".into()],
            pending_fast_path_ms: 1_000,
            ..Default::default()
        };
        let failed = resolve_pending_fast_path(
            &mut cached,
            "8.8.8.8:443",
            1_000 + PENDING_FAST_PATH_TTL_MS + 1,
        );
        assert!(failed.is_empty());
        assert!(cached.pending_fast_path.is_empty());
        assert_eq!(cached.pending_fast_path_ms, 0);
    }

    #[test]
    fn save_records_history_for_the_current_network() {
        let path = tmp_path("history");
        std::env::set_var("AETHER_NETWORK_KEY", "test-network");
        save(&path, "1.1.1.1:443", "firewall");
        let history = path_history::load(&history_path(&path));
        assert_eq!(history.network_key, "test-network");
        assert_eq!(history.paths.len(), 1);
        assert_eq!(history.paths[0].successes, 1);
        let last = load(&path).unwrap();
        assert_eq!(last.network_key, "test-network");
        std::env::remove_var("AETHER_NETWORK_KEY");
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(history_path(&path));
    }

    #[test]
    fn zero_value_http2_env_stays_on_h3() {
        std::env::set_var("AETHER_PROTOCOL", "masque");
        std::env::set_var("AETHER_MASQUE_HTTP2", "0");
        assert_eq!(active_transport(), PathTransport::MasqueH3);
        std::env::set_var("AETHER_MASQUE_HTTP2", "1");
        assert_eq!(active_transport(), PathTransport::MasqueH2);
        std::env::remove_var("AETHER_PROTOCOL");
        std::env::remove_var("AETHER_MASQUE_HTTP2");
    }
}
