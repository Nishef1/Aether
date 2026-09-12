use std::env;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AdaptiveNetworkDefaults {
    masque_startup_secs: u16,
    h2_keepalive_secs: u16,
    h2_keepalive_timeout_secs: u16,
    wg_stale_secs: u16,
    wg_endpoint_cooldown_secs: u16,
    probe_jitter_ms: u16,
}

/// Runtime defaults derived from the user's scan intent.
///
/// These values tune failure detection and probe pacing only. They do not
/// weaken end-to-end validation and they never replace an explicit environment
/// or CLI override. This keeps the mode useful as a policy while preserving an
/// escape hatch for expert deployments.
fn defaults_for_scan(mode: &str) -> Option<AdaptiveNetworkDefaults> {
    let defaults = match mode.trim().to_ascii_lowercase().as_str() {
        // Interactive/gaming: fail a dead path quickly, keep H2 liveness tight,
        // and never add artificial delay to the first-healthy search.
        "turbo" => AdaptiveNetworkDefaults {
            masque_startup_secs: 20,
            h2_keepalive_secs: 10,
            h2_keepalive_timeout_secs: 15,
            wg_stale_secs: 10,
            wg_endpoint_cooldown_secs: 180,
            probe_jitter_ms: 0,
        },
        // General-purpose baseline: enough tolerance for mobile jitter without
        // letting failed endpoints dominate repeated scans.
        "balanced" => AdaptiveNetworkDefaults {
            masque_startup_secs: 30,
            h2_keepalive_secs: 15,
            h2_keepalive_timeout_secs: 20,
            wg_stale_secs: 12,
            wg_endpoint_cooldown_secs: 300,
            probe_jitter_ms: 10,
        },
        // Coverage matters more than speed. Failed endpoints become eligible
        // again sooner because a deep sweep should not permanently narrow the
        // candidate pool during changing network conditions.
        "thorough" => AdaptiveNetworkDefaults {
            masque_startup_secs: 45,
            h2_keepalive_secs: 15,
            h2_keepalive_timeout_secs: 25,
            wg_stale_secs: 18,
            wg_endpoint_cooldown_secs: 120,
            probe_jitter_ms: 20,
        },
        // Low-observability mode: fewer timing signatures and much less churn.
        // Longer liveness windows avoid turning a transient pause into another
        // conspicuous reconnect/scan cycle.
        "stealth" => AdaptiveNetworkDefaults {
            masque_startup_secs: 60,
            h2_keepalive_secs: 25,
            h2_keepalive_timeout_secs: 35,
            wg_stale_secs: 25,
            wg_endpoint_cooldown_secs: 600,
            probe_jitter_ms: 200,
        },
        // Real data-plane verification is intentionally expensive, so allow a
        // little more startup time while keeping dead-path detection bounded.
        "ironclad" => AdaptiveNetworkDefaults {
            masque_startup_secs: 45,
            h2_keepalive_secs: 15,
            h2_keepalive_timeout_secs: 20,
            wg_stale_secs: 15,
            wg_endpoint_cooldown_secs: 300,
            probe_jitter_ms: 30,
        },
        _ => return None,
    };

    Some(defaults)
}

fn set_default(key: &str, value: impl ToString) {
    // Empty UTF-8 values are equivalent to "not configured" in the consumers,
    // so let adaptive policy repair those as well. Non-UTF-8 values are treated
    // as deliberate and left untouched.
    match env::var(key) {
        Ok(existing) if !existing.trim().is_empty() => return,
        Err(env::VarError::NotUnicode(_)) => return,
        _ => {}
    }

    env::set_var(key, value.to_string());
}

/// Apply mode-derived runtime defaults after CLI flags have been parsed.
/// Explicit flags/environment values win because `set_default` only fills
/// missing values.
pub(super) fn apply_for_configured_scan() {
    let Ok(mode) = env::var("AETHER_SCAN") else {
        return;
    };
    let Some(defaults) = defaults_for_scan(&mode) else {
        return;
    };

    set_default("AETHER_MASQUE_STARTUP_SECS", defaults.masque_startup_secs);
    set_default(
        "AETHER_MASQUE_H2_KEEPALIVE_SECS",
        defaults.h2_keepalive_secs,
    );
    set_default(
        "AETHER_MASQUE_H2_KEEPALIVE_TIMEOUT_SECS",
        defaults.h2_keepalive_timeout_secs,
    );
    set_default("AETHER_WG_STALE_SECS", defaults.wg_stale_secs);
    set_default(
        "AETHER_WG_ENDPOINT_COOLDOWN_SECS",
        defaults.wg_endpoint_cooldown_secs,
    );
    set_default("AETHER_PROBE_JITTER_MS", defaults.probe_jitter_ms);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn turbo_is_the_fail_fast_policy() {
        let turbo = defaults_for_scan("turbo").unwrap();
        let balanced = defaults_for_scan("balanced").unwrap();

        assert!(turbo.masque_startup_secs < balanced.masque_startup_secs);
        assert!(turbo.h2_keepalive_secs < balanced.h2_keepalive_secs);
        assert_eq!(turbo.probe_jitter_ms, 0);
    }

    #[test]
    fn stealth_reduces_probe_and_reconnect_churn() {
        let stealth = defaults_for_scan("STEALTH").unwrap();
        let balanced = defaults_for_scan("balanced").unwrap();

        assert!(stealth.probe_jitter_ms > balanced.probe_jitter_ms);
        assert!(stealth.wg_stale_secs > balanced.wg_stale_secs);
        assert!(stealth.wg_endpoint_cooldown_secs > balanced.wg_endpoint_cooldown_secs);
        assert!(stealth.h2_keepalive_timeout_secs > stealth.h2_keepalive_secs);
    }

    #[test]
    fn thorough_keeps_the_candidate_pool_recoverable() {
        let thorough = defaults_for_scan(" thorough ").unwrap();
        let balanced = defaults_for_scan("balanced").unwrap();

        assert!(thorough.masque_startup_secs > balanced.masque_startup_secs);
        assert!(thorough.wg_endpoint_cooldown_secs < balanced.wg_endpoint_cooldown_secs);
    }

    #[test]
    fn unknown_mode_gets_no_synthetic_policy() {
        assert_eq!(defaults_for_scan("custom"), None);
    }
}