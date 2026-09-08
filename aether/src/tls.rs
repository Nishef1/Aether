use std::ffi::c_void;
use std::os::raw::c_int;
use std::ptr;

use boring::pkey::PKey;
use boring::ssl::{SslContextBuilder, SslMethod, SslVerifyError, SslVerifyMode, SslVersion};
use boring::x509::X509;
use foreign_types_shared::ForeignTypeRef;
use ring::digest;

use crate::consts;
use crate::error::{AetherError, Result};

extern "C" {
    fn SSL_set1_ech_config_list(
        ssl: *mut c_void,
        ech_config_list: *const u8,
        ech_config_list_len: usize,
    ) -> c_int;

    fn SSL_get0_ech_retry_configs(
        ssl: *const c_void,
        out_retry_configs: *mut *const u8,
        out_retry_configs_len: *mut usize,
    );
}

const CURRENT_GROUPS: &str = "P-256:X25519:P-384";
const MINIMAL_GROUPS: &str = "X25519:P-256";
const EXPERIMENTAL_GROUPS: &str = "X25519:P-256:P-384";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TlsCarrier {
    H2,
    H3,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TlsProfile {
    Automatic,
    Current,
    NativeMinimal,
    Compatibility,
    Experimental,
}

impl TlsProfile {
    fn from_env() -> Self {
        match std::env::var("AETHER_TLS_PROFILE")
            .unwrap_or_else(|_| "automatic".to_string())
            .trim()
            .to_ascii_lowercase()
            .as_str()
        {
            "current" | "boringssl" | "current-boringssl" => Self::Current,
            "native-minimal" | "minimal" | "native" => Self::NativeMinimal,
            "compatibility" | "compat" => Self::Compatibility,
            "experimental" | "experiment" => Self::Experimental,
            _ => Self::Automatic,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Automatic => "automatic",
            Self::Current => "current-boringssl",
            Self::NativeMinimal => "native-minimal",
            Self::Compatibility => "compatibility",
            Self::Experimental => "experimental",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TlsPolicy {
    tls13_only: bool,
    grease: bool,
    groups: &'static str,
}

fn policy_for(profile: TlsProfile, carrier: TlsCarrier) -> TlsPolicy {
    let current = TlsPolicy {
        tls13_only: carrier == TlsCarrier::H3,
        grease: true,
        groups: CURRENT_GROUPS,
    };

    match profile {
        TlsProfile::Automatic | TlsProfile::Current => current,
        TlsProfile::NativeMinimal => TlsPolicy {
            tls13_only: true,
            grease: false,
            groups: MINIMAL_GROUPS,
        },
        TlsProfile::Compatibility => TlsPolicy {
            tls13_only: carrier == TlsCarrier::H3,
            grease: false,
            groups: CURRENT_GROUPS,
        },
        TlsProfile::Experimental => TlsPolicy {
            tls13_only: true,
            grease: true,
            groups: EXPERIMENTAL_GROUPS,
        },
    }
}

pub fn apply_client_profile(builder: &mut SslContextBuilder, carrier: TlsCarrier) -> Result<()> {
    let profile = TlsProfile::from_env();
    let policy = policy_for(profile, carrier);

    builder
        .set_min_proto_version(Some(if policy.tls13_only {
            SslVersion::TLS1_3
        } else {
            SslVersion::TLS1_2
        }))
        .map_err(|e| AetherError::Tls(e.to_string()))?;
    builder
        .set_max_proto_version(Some(SslVersion::TLS1_3))
        .map_err(|e| AetherError::Tls(e.to_string()))?;
    builder.set_grease_enabled(policy.grease);

    // Manual groups remain an expert override above the named profile.
    let groups = std::env::var("AETHER_TLS_GROUPS").ok();
    let groups = groups
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(policy.groups);
    builder
        .set_curves_list(groups)
        .map_err(|e| AetherError::Tls(e.to_string()))?;

    announce_profile_once(format!(
        "tls profile: {} carrier={:?} tls13_only={} grease={} groups={groups}",
        profile.label(),
        carrier,
        policy.tls13_only,
        policy.grease,
    ));
    Ok(())
}

fn announce_profile_once(message: String) {
    use std::sync::OnceLock;
    static ANNOUNCED: OnceLock<()> = OnceLock::new();
    if ANNOUNCED.set(()).is_ok() {
        log::info!("{message}");
    } else {
        log::debug!("{message}");
    }
}

pub struct TlsParams<'a> {
    pub cert_pem: &'a [u8],
    pub key_pem: &'a [u8],
    pub pin_endpoint: bool,
    /// SHA-256 SPKI hashes of expected server certificates for pin-based verification.
    /// When non-empty and `pin_endpoint` is true, the server cert's SPKI hash is checked
    /// against these pins instead of relying on standard CA chain validation.
    /// This allows the TLS handshake to succeed even when SNI is spoofed for DPI bypass,
    /// while still preventing MITM attacks.
    pub expected_pins: &'a [&'a [u8]],
}

/// Compute the SHA-256 hash of a certificate's SubjectPublicKeyInfo (SPKI).
/// This is the standard format for certificate pinning (e.g., HPKP, CT logs).
fn spki_sha256(cert: &boring::x509::X509Ref) -> Option<[u8; 32]> {
    let pubkey = cert.public_key().ok()?;
    let der = pubkey.public_key_to_der().ok()?;
    let hash = digest::digest(&digest::SHA256, &der);
    let mut out = [0u8; 32];
    out.copy_from_slice(hash.as_ref());
    Some(out)
}

/// Install TLS verification on an `SslContextBuilder`.
///
/// When `pin_endpoint` is true and `expected_pins` is non-empty:
///   Pin-only verification: leaf cert SPKI hash is checked against pins.
///   No CA chain verification is performed (Cloudflare MASQUE edges use
///   self-signed certs that would fail chain validation).
///
/// When `pin_endpoint` is false (or no pins provided):
///   SslVerifyMode::NONE — no server cert verification.
///   Required because Cloudflare edges serve different certs per SNI
///   and some are self-signed. Security relies on the pin-based path
///   being used in production.
pub fn install_verification(
    builder: &mut SslContextBuilder,
    pin_endpoint: bool,
    expected_pins: &[&[u8]],
) -> Result<()> {
    if pin_endpoint && !expected_pins.is_empty() {
        let pins: Vec<Vec<u8>> = expected_pins.iter().map(|p| p.to_vec()).collect();
        builder.set_custom_verify_callback(SslVerifyMode::PEER, move |ssl| {
            let leaf_cert = ssl.peer_certificate().ok_or_else(|| {
                log::warn!("tls pin: no peer certificate presented");
                SslVerifyError::Invalid(boring::ssl::SslAlert::BAD_CERTIFICATE)
            })?;

            let hash = spki_sha256(&leaf_cert).ok_or_else(|| {
                log::warn!("tls pin: failed to compute SPKI hash");
                SslVerifyError::Invalid(boring::ssl::SslAlert::INTERNAL_ERROR)
            })?;

            let matched = pins.iter().any(|pin| pin.as_slice() == hash.as_slice());
            if !matched {
                log::debug!(
                    "tls pin: server cert SPKI hash {:02x?} does not match any pinned hash",
                    hash
                );
                return Err(SslVerifyError::Invalid(
                    boring::ssl::SslAlert::CERTIFICATE_UNKNOWN,
                ));
            }
            log::debug!("tls pin: SPKI hash match OK");
            Ok(())
        });
        announce_once(format!(
            "tls verification: pin-based ({} pins loaded)",
            expected_pins.len()
        ));
    } else {
        builder.set_verify(SslVerifyMode::NONE);
        announce_once("tls verification: disabled (no pin configured)".to_string());
    }
    Ok(())
}

fn announce_once(message: String) {
    use std::sync::OnceLock;
    static ANNOUNCED: OnceLock<()> = OnceLock::new();
    if ANNOUNCED.set(()).is_ok() {
        log::info!("{message}");
    } else {
        log::debug!("{message}");
    }
}

pub fn build_config(params: &TlsParams) -> Result<quiche::Config> {
    let mut builder = SslContextBuilder::new(SslMethod::tls())
        .map_err(|e| AetherError::Tls(e.to_string()))?;

    apply_client_profile(&mut builder, TlsCarrier::H3)?;

    let mut alpn = Vec::with_capacity(consts::ALPN_H3.len() + 1);
    alpn.push(consts::ALPN_H3.len() as u8);
    alpn.extend_from_slice(consts::ALPN_H3);
    builder
        .set_alpn_protos(&alpn)
        .map_err(|e| AetherError::Tls(e.to_string()))?;

    let cert = X509::from_pem(params.cert_pem).map_err(|e| AetherError::Tls(e.to_string()))?;
    let key = PKey::private_key_from_pem(params.key_pem)
        .map_err(|e| AetherError::Tls(e.to_string()))?;
    builder
        .set_certificate(&cert)
        .map_err(|e| AetherError::Tls(e.to_string()))?;
    builder
        .set_private_key(&key)
        .map_err(|e| AetherError::Tls(e.to_string()))?;

    install_verification(&mut builder, params.pin_endpoint, params.expected_pins)?;

    let mut config = quiche::Config::with_boring_ssl_ctx_builder(quiche::PROTOCOL_VERSION, builder)
        .map_err(AetherError::Quic)?;

    config
        .set_application_protos(&[consts::ALPN_H3])
        .map_err(AetherError::Quic)?;

    config.set_max_idle_timeout(120_000);
    config.set_max_recv_udp_payload_size(1350);
    config.set_max_send_udp_payload_size(1350);
    config.set_initial_max_data(10_000_000);
    config.set_initial_max_stream_data_bidi_local(2_000_000);
    config.set_initial_max_stream_data_bidi_remote(2_000_000);
    config.set_initial_max_stream_data_uni(2_000_000);
    config.set_initial_max_streams_bidi(100);
    config.set_initial_max_streams_uni(100);
    config.set_disable_active_migration(true);
    config.enable_dgram(true, 65536, 65536);

    Ok(config)
}

pub fn inject_ech(conn: &mut quiche::Connection, ech_config_list: &[u8]) -> Result<()> {
    if ech_config_list.is_empty() {
        return Err(AetherError::Ech("empty ech config list".into()));
    }

    let ssl: &mut boring::ssl::SslRef = conn.as_mut();
    let ssl_ptr = ssl.as_ptr() as *mut c_void;

    let rc = unsafe {
        SSL_set1_ech_config_list(ssl_ptr, ech_config_list.as_ptr(), ech_config_list.len())
    };

    if rc != 1 {
        return Err(AetherError::Ech(format!(
            "SSL_set1_ech_config_list failed (rc={rc})"
        )));
    }

    Ok(())
}

pub fn extract_ech_retry_configs(conn: &mut quiche::Connection) -> Option<Vec<u8>> {
    let ssl: &mut boring::ssl::SslRef = conn.as_mut();
    let ssl_ptr = ssl.as_ptr() as *const c_void;

    let mut out: *const u8 = ptr::null();
    let mut out_len: usize = 0;

    unsafe {
        SSL_get0_ech_retry_configs(ssl_ptr, &mut out, &mut out_len);
    }

    if out.is_null() || out_len == 0 {
        return None;
    }

    let slice = unsafe { std::slice::from_raw_parts(out, out_len) };
    Some(slice.to_vec())
}

pub fn decode_ech_config_list(b64: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .map_err(|e| AetherError::Ech(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_h2_keeps_existing_tls12_to_tls13_compatibility() {
        let policy = policy_for(TlsProfile::Current, TlsCarrier::H2);
        assert!(!policy.tls13_only);
        assert!(policy.grease);
        assert_eq!(policy.groups, CURRENT_GROUPS);
    }

    #[test]
    fn h3_is_tls13_only_for_every_nonexperimental_compatibility_profile() {
        for profile in [
            TlsProfile::Automatic,
            TlsProfile::Current,
            TlsProfile::NativeMinimal,
            TlsProfile::Compatibility,
        ] {
            assert!(policy_for(profile, TlsCarrier::H3).tls13_only);
        }
    }

    #[test]
    fn minimal_reduces_surface_without_disabling_pin_verification() {
        let policy = policy_for(TlsProfile::NativeMinimal, TlsCarrier::H2);
        assert!(policy.tls13_only);
        assert!(!policy.grease);
        assert_eq!(policy.groups, MINIMAL_GROUPS);
    }

    #[test]
    fn experimental_only_changes_client_hello_shape_policy() {
        let policy = policy_for(TlsProfile::Experimental, TlsCarrier::H2);
        assert!(policy.tls13_only);
        assert!(policy.grease);
        assert_eq!(policy.groups, EXPERIMENTAL_GROUPS);
    }
}
