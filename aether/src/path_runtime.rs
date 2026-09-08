use std::net::SocketAddr;

use crate::path_history::{self, PathTransport};

fn history_path(lastconn_path: &str) -> String {
    format!("{lastconn_path}.history")
}

pub fn record_verified(
    lastconn_path: &str,
    peer: SocketAddr,
    transport: PathTransport,
    profile: &str,
    rtt_ms: Option<u32>,
    quality_score: Option<u8>,
) {
    path_history::record_success_file(
        &history_path(lastconn_path),
        &path_history::network_key_from_env(),
        peer,
        transport,
        profile,
        rtt_ms,
        quality_score,
    );
}

pub fn record_failed(
    lastconn_path: &str,
    peer: SocketAddr,
    transport: PathTransport,
    profile: &str,
) {
    path_history::record_failure_file(
        &history_path(lastconn_path),
        &path_history::network_key_from_env(),
        peer,
        transport,
        profile,
    );
}

pub fn ranked_peers(
    lastconn_path: &str,
    transport: PathTransport,
    profile: &str,
) -> Vec<SocketAddr> {
    let network = path_history::network_key_from_env();
    let history = path_history::load(&history_path(lastconn_path));
    if history.network_key != network {
        return Vec::new();
    }

    history
        .rank()
        .into_iter()
        .filter(|path| path.transport == transport && (profile.is_empty() || path.profile == profile))
        .map(|path| path.peer)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn history_file_is_a_sibling_of_lastconn() {
        assert_eq!(history_path("aether-lastconn.toml"), "aether-lastconn.toml.history");
    }
}
