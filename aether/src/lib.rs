//! Embeddable entry point for mobile and other in-process Aether hosts.
//!
//! The CLI remains the canonical implementation. Including it here keeps the
//! network stack, protocol selection, enrollment and reconnect behavior in one
//! source of truth while exposing a stable host function for Android.

include!("main.rs");

/// Runs Aether using the same environment-based configuration as the CLI.
///
/// This function blocks until the tunnel exits. Mobile hosts should call it on
/// a dedicated native thread and request shutdown through the host lifecycle.
pub fn run_embedded() -> anyhow::Result<()> {
    main().map_err(anyhow::Error::from)
}
