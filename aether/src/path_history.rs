use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

pub const HISTORY_CAP: usize = 32;
const FRESHNESS_WINDOW_MS: u64 = 24 * 60 * 60 * 1000;

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
        let quality = self.quality_score.map(|value| value as f32 / 100.0).unwrap_or(0.5);

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

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
