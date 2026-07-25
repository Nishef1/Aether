use std::env;

const USAGE: &str = "\
Usage: aether [OPTIONS]

Connection:
  --bind <addr>            local SOCKS5 listen address (default 127.0.0.1:1819)
  --quick-reconnect        auto-accept reconnecting with the last known working gateway
  --no-quick-reconnect     always scan fresh, ignore any saved last-connection gateway
  -4                       scan/connect over IPv4 only (default)
  -6                       scan/connect over IPv6 only
  --dual                   scan/connect over both IPv4 and IPv6
  --peer <ip:port>         force a MASQUE/WireGuard peer, skip scanning
  --wg-peer <ip:port>      force a WireGuard peer (warp-in-warp outer), skip scanning

Protocol:
  --masque                 use MASQUE over QUIC/HTTP-3 (default)
  --wg, --wireguard        use classic WireGuard
  --gool, --wiw            use WARP-in-WARP (wireguard tunneled in wireguard)

Scan mode:
  --scan <mode>            turbo | balanced | thorough | stealth
  --turbo                  shortcut for --scan turbo
  --balanced               shortcut for --scan balanced
  --thorough               shortcut for --scan thorough
  --stealth                shortcut for --scan stealth
  --ironclad               shortcut for --scan ironclad (real tunnel + real HTTP check per candidate)

Obfuscation:
  --noize <profile>        obfuscation profile (off, light/firewall, balanced, gfw/aggressive, ...)

MASQUE transport:
  --masque-transport <m>   auto | h3 | h2 (explicit modes never prompt)
  --h3, --http3, --quic    force HTTP/3 (QUIC), skip transport prompt
  --h2, --http2            force HTTP/2 (TCP), skip transport prompt
  --h2-peer <ip:port>      override the peer used for the HTTP/2 transport
  --ech <auto|base64>      enable Encrypted Client Hello
  --no-data-check          skip end-to-end data-plane validation for all transports
  --validate-secs <n>      seconds to wait for MASQUE data validation (1-120, default 10)
  --health-interval <n>    seconds between MASQUE health probes (5-300)
  --health-timeout <n>     seconds allowed for a MASQUE health response (1-120)
  --health-failures <n>    missed MASQUE health periods before failure (1-10)
  --reconnect-secs <n>     base delay before MASQUE reconnect (1-60, default 2)
  --fragment               fragment the TLS ClientHello on the HTTP/2 transport
  --fragment-size <n|a-b>  fragment size in bytes (1-4096, default 16-32)
  --fragment-delay <n|a-b> delay between fragments in ms (0-100, default 2-10)

WireGuard:
  --keepalive <n>          persistent keepalive interval in seconds (1-120, default 5)
  --wg-validate-secs <n>   data-plane validation deadline (1-120, default 10)
  --wg-health-interval <n> health probe interval (1-60, default 3)
  --wg-stale-secs <n>      valid-data silence before reconnect (6-300, default 15)
  --wg-startup-secs <n>    startup window for first valid peer response (10-300, default 30)
  --wg-reconnect-secs <n>  base delay before WireGuard reconnect (1-60, default 2)
  --no-profile-retry       don't retry other obfuscation profiles during scan

Netstack:
  --udp-idle-secs <n>      idle UDP association lifetime (30-3600, default 300)

Config files:
  --config <path>          base identity config path (default aether.toml)
  --wg-config <path>       identity config path for WireGuard
  --masque-config <path>   identity config path for MASQUE

Advanced:
  --tls-groups <list>      TLS key share groups, e.g. \"P-256:X25519:P-384\"
  --perf <low|medium|high> force a resource profile instead of auto-detecting from cpu/ram
                           (low: routers/small boards, medium: typical desktop, high: servers)
  --log-level <level>      error | warn | info | debug | trace (default info)
                           info: connection stages, validation, reconnects, retries
                           debug: adds per-tunnel internals useful for troubleshooting
                           trace: everything, including per-packet noise
  --verbose                shortcut for --log-level debug (RUST_LOG overrides both)

  -v, --version            show version and exit
  -h, --help               show this help and exit
";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MasqueTransportChoice {
    Auto,
    Http3,
    Http2,
}

impl MasqueTransportChoice {
    fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "auto" => Some(Self::Auto),
            "h3" | "http3" | "quic" => Some(Self::Http3),
            "h2" | "http2" => Some(Self::Http2),
            _ => None,
        }
    }
}

pub fn parse_and_apply() -> crate::error::Result<()> {
    let args: Vec<String> = env::args().skip(1).collect();
    let mut index = 0;

    while index < args.len() {
        let argument = args[index].as_str();

        macro_rules! next_value {
            () => {{
                index += 1;
                args.get(index).ok_or_else(|| {
                    crate::error::AetherError::Other(format!(
                        "{argument} requires a value"
                    ))
                })?
            }};
        }

        match argument {
            "-v" | "--version" => {
                println!("aether {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            "-h" | "--help" => {
                print!("{USAGE}");
                std::process::exit(0);
            }

            "--bind" => set("AETHER_SOCKS", next_value!()),
            "--quick-reconnect" => set("AETHER_QUICK_RECONNECT", "1"),
            "--no-quick-reconnect" => set("AETHER_QUICK_RECONNECT", "0"),

            "-4" => set("AETHER_IP", "v4"),
            "-6" => set("AETHER_IP", "v6"),
            "--dual" => set("AETHER_IP", "both"),
            "--ip" => set("AETHER_IP", next_value!()),

            "--peer" => set("AETHER_PEER", next_value!()),
            "--wg-peer" => set("AETHER_WG_PEER", next_value!()),

            "--masque" => set("AETHER_PROTOCOL", "masque"),
            "--wg" | "--wireguard" => set("AETHER_PROTOCOL", "wg"),
            "--gool" | "--wiw" => set("AETHER_PROTOCOL", "gool"),
            "--protocol" => set("AETHER_PROTOCOL", next_value!()),

            "--scan" => set("AETHER_SCAN", next_value!()),
            "--turbo" => set("AETHER_SCAN", "turbo"),
            "--balanced" => set("AETHER_SCAN", "balanced"),
            "--thorough" => set("AETHER_SCAN", "thorough"),
            "--stealth" => set("AETHER_SCAN", "stealth"),
            "--ironclad" => set("AETHER_SCAN", "ironclad"),

            "--noize" => set("AETHER_NOIZE", next_value!()),

            "--masque-transport" => apply_masque_transport(next_value!())?,
            "--h3" | "--http3" | "--quic" => apply_masque_transport("h3")?,
            "--h2" | "--http2" => apply_masque_transport("h2")?,
            "--h2-peer" => set("AETHER_MASQUE_H2_PEER", next_value!()),
            "--ech" => set("AETHER_ECH", next_value!()),
            "--no-data-check" => {
                set("AETHER_MASQUE_NO_DATA_CHECK", "1");
                set("AETHER_WG_NO_DATA_CHECK", "1");
            }
            "--validate-secs" => set_bounded_u64(
                "AETHER_MASQUE_VALIDATE_SECS",
                next_value!(),
                argument,
                1,
                120,
            )?,
            "--health-interval" => {
                let value = bounded_u64(next_value!(), argument, 5, 300)?.to_string();
                set("AETHER_MASQUE_HEALTH_INTERVAL_SECS", &value);
                set("AETHER_MASQUE_H2_KEEPALIVE_SECS", &value);
            }
            "--health-timeout" => {
                let value = bounded_u64(next_value!(), argument, 1, 120)?.to_string();
                set("AETHER_MASQUE_HEALTH_TIMEOUT_SECS", &value);
                set("AETHER_MASQUE_H2_KEEPALIVE_TIMEOUT_SECS", &value);
            }
            "--health-failures" => set_bounded_u64(
                "AETHER_MASQUE_HEALTH_FAILURES",
                next_value!(),
                argument,
                1,
                10,
            )?,
            "--reconnect-secs" => set_bounded_u64(
                "AETHER_MASQUE_RECONNECT_SECS",
                next_value!(),
                argument,
                1,
                60,
            )?,
            "--fragment" => set("AETHER_MASQUE_H2_FRAGMENT", "1"),
            "--fragment-size" => {
                let value = bounded_range(next_value!(), argument, 1, 4096)?;
                set("AETHER_MASQUE_H2_FRAGMENT_SIZE", &value);
            }
            "--fragment-delay" => {
                let value = bounded_range(next_value!(), argument, 0, 100)?;
                set("AETHER_MASQUE_H2_FRAGMENT_DELAY", &value);
            }

            "--keepalive" => set_bounded_u64(
                "AETHER_WG_KEEPALIVE",
                next_value!(),
                argument,
                1,
                120,
            )?,
            "--wg-validate-secs" => set_bounded_u64(
                "AETHER_WG_VALIDATE_SECS",
                next_value!(),
                argument,
                1,
                120,
            )?,
            "--wg-health-interval" => set_bounded_u64(
                "AETHER_WG_HEALTH_INTERVAL_SECS",
                next_value!(),
                argument,
                1,
                60,
            )?,
            "--wg-stale-secs" => set_bounded_u64(
                "AETHER_WG_STALE_SECS",
                next_value!(),
                argument,
                6,
                300,
            )?,
            "--wg-startup-secs" => set_bounded_u64(
                "AETHER_WG_STARTUP_SECS",
                next_value!(),
                argument,
                10,
                300,
            )?,
            "--wg-reconnect-secs" => set_bounded_u64(
                "AETHER_WG_RECONNECT_SECS",
                next_value!(),
                argument,
                1,
                60,
            )?,
            "--no-profile-retry" => set("AETHER_WG_NO_PROFILE_RETRY", "1"),

            "--udp-idle-secs" => set_bounded_u64(
                "AETHER_NETSTACK_UDP_IDLE_SECS",
                next_value!(),
                argument,
                30,
                3600,
            )?,

            "--config" => set("AETHER_CONFIG", next_value!()),
            "--wg-config" => set("AETHER_WG_CONFIG", next_value!()),
            "--masque-config" => set("AETHER_MASQUE_CONFIG", next_value!()),

            "--tls-groups" => set("AETHER_TLS_GROUPS", next_value!()),
            "--perf" => set("AETHER_PERF_PROFILE", next_value!()),
            "--log-level" => set("AETHER_LOG_LEVEL", next_value!()),
            "--verbose" => set("AETHER_LOG_LEVEL", "debug"),

            other => {
                return Err(crate::error::AetherError::Other(format!(
                    "unknown option '{other}'\n\n{USAGE}"
                )));
            }
        }

        index += 1;
    }

    Ok(())
}

fn apply_masque_transport(value: &str) -> crate::error::Result<()> {
    let choice = MasqueTransportChoice::parse(value).ok_or_else(|| {
        crate::error::AetherError::Other(format!(
            "invalid MASQUE transport '{value}'; expected auto, h3, or h2"
        ))
    })?;

    match choice {
        MasqueTransportChoice::Auto => env::remove_var("AETHER_MASQUE_HTTP2"),
        MasqueTransportChoice::Http3 => set("AETHER_MASQUE_HTTP2", "0"),
        MasqueTransportChoice::Http2 => set("AETHER_MASQUE_HTTP2", "1"),
    }

    Ok(())
}

fn bounded_u64(
    value: &str,
    option: &str,
    minimum: u64,
    maximum: u64,
) -> crate::error::Result<u64> {
    let parsed = value.parse::<u64>().map_err(|_| {
        crate::error::AetherError::Other(format!(
            "{option} expects an integer between {minimum} and {maximum}; got '{value}'"
        ))
    })?;
    if !(minimum..=maximum).contains(&parsed) {
        return Err(crate::error::AetherError::Other(format!(
            "{option} expects a value between {minimum} and {maximum}; got {parsed}"
        )));
    }
    Ok(parsed)
}

fn bounded_range(
    value: &str,
    option: &str,
    minimum: u64,
    maximum: u64,
) -> crate::error::Result<String> {
    let (left, right) = match value.split_once('-') {
        Some((left, right)) => (
            bounded_u64(left.trim(), option, minimum, maximum)?,
            bounded_u64(right.trim(), option, minimum, maximum)?,
        ),
        None => {
            let value = bounded_u64(value.trim(), option, minimum, maximum)?;
            (value, value)
        }
    };
    let (low, high) = if left <= right {
        (left, right)
    } else {
        (right, left)
    };
    if low == high {
        Ok(low.to_string())
    } else {
        Ok(format!("{low}-{high}"))
    }
}

fn set_bounded_u64(
    key: &str,
    value: &str,
    option: &str,
    minimum: u64,
    maximum: u64,
) -> crate::error::Result<()> {
    let value = bounded_u64(value, option, minimum, maximum)?.to_string();
    set(key, &value);
    Ok(())
}

fn set(key: &str, value: &str) {
    env::set_var(key, value);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_documented_masque_transport_modes_and_aliases() {
        assert_eq!(
            MasqueTransportChoice::parse("auto"),
            Some(MasqueTransportChoice::Auto)
        );
        assert_eq!(
            MasqueTransportChoice::parse("H3"),
            Some(MasqueTransportChoice::Http3)
        );
        assert_eq!(
            MasqueTransportChoice::parse("quic"),
            Some(MasqueTransportChoice::Http3)
        );
        assert_eq!(
            MasqueTransportChoice::parse("http2"),
            Some(MasqueTransportChoice::Http2)
        );
        assert_eq!(MasqueTransportChoice::parse("invalid"), None);
    }

    #[test]
    fn bounded_seconds_reject_invalid_and_out_of_range_values() {
        assert_eq!(bounded_u64("5", "--health-interval", 5, 300).unwrap(), 5);
        assert!(bounded_u64("0", "--health-interval", 5, 300).is_err());
        assert!(bounded_u64("301", "--health-interval", 5, 300).is_err());
        assert!(bounded_u64("not-a-number", "--health-interval", 5, 300).is_err());
    }

    #[test]
    fn fragment_ranges_are_validated_and_normalized() {
        assert_eq!(bounded_range("32-16", "--fragment-size", 1, 4096).unwrap(), "16-32");
        assert!(bounded_range("0-16", "--fragment-size", 1, 4096).is_err());
        assert!(bounded_range("1-101", "--fragment-delay", 0, 100).is_err());
    }
}
