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
  --no-data-check          skip the end-to-end data-plane validation
  --validate-secs <n>      seconds to wait for data-plane validation (default 10)
  --reconnect-secs <n>     delay before reconnecting after a tunnel drop (default 2)
  --fragment               fragment the TLS ClientHello on the HTTP/2 transport
  --fragment-size <n|a-b>  fragment chunk size in bytes (default 16-32)
  --fragment-delay <n|a-b> delay between fragments in ms (default 2-10)

WireGuard:
  --keepalive <n>          persistent keepalive interval in seconds (default 5)
  --no-profile-retry       don't retry other obfuscation profiles during scan

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
    let mut i = 0;

    while i < args.len() {
        let arg = args[i].as_str();

        macro_rules! next_value {
            () => {{
                i += 1;
                args.get(i).ok_or_else(|| {
                    crate::error::AetherError::Other(format!("{arg} requires a value"))
                })?
            }};
        }

        match arg {
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
            "--validate-secs" => set("AETHER_MASQUE_VALIDATE_SECS", next_value!()),
            "--reconnect-secs" => set("AETHER_MASQUE_RECONNECT_SECS", next_value!()),
            "--fragment" => set("AETHER_MASQUE_H2_FRAGMENT", "1"),
            "--fragment-size" => set("AETHER_MASQUE_H2_FRAGMENT_SIZE", next_value!()),
            "--fragment-delay" => set("AETHER_MASQUE_H2_FRAGMENT_DELAY", next_value!()),

            "--keepalive" => set("AETHER_WG_KEEPALIVE", next_value!()),
            "--no-profile-retry" => set("AETHER_WG_NO_PROFILE_RETRY", "1"),

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

        i += 1;
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
}
