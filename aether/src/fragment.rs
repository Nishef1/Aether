use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use rand::RngExt;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaskMode {
    Off,
    LegacyTcpFragment,
    /// Deterministic TCP write boundaries over the cleartext TLS ClientHello.
    /// This does not rewrite TLS records; it only changes how their bytes are
    /// presented to the socket.
    ClientHelloTcpSplit,
    /// Best-effort TCP split preset inspired by the public Patterniha finalMask
    /// layout. It deliberately remains experimental because Xray's packet
    /// matcher/maxSplit semantics are not identical to an AsyncWrite stream.
    PatternihaExperimental,
}

impl MaskMode {
    fn from_env() -> Self {
        if let Ok(value) = std::env::var("AETHER_MASQUE_H2_MASK") {
            return match value.trim().to_ascii_lowercase().as_str() {
                "off" | "0" | "false" | "none" => Self::Off,
                "legacy" | "fragment" | "tcp-fragment" => Self::LegacyTcpFragment,
                "clienthello" | "clienthello-split" | "tlshello" => Self::ClientHelloTcpSplit,
                "patterniha" | "patterniha-experimental" => Self::PatternihaExperimental,
                _ => Self::Off,
            };
        }

        // Backward compatibility: existing GUI/CLI profiles only know the old
        // boolean fragment switch, so enabling it keeps exactly the old random
        // TCP-fragment behavior until a mask mode is explicitly selected.
        if std::env::var("AETHER_MASQUE_H2_FRAGMENT")
            .map(|value| is_truthy(&value))
            .unwrap_or(false)
        {
            Self::LegacyTcpFragment
        } else {
            Self::Off
        }
    }

    fn deterministic_splits(self) -> &'static [usize] {
        match self {
            Self::ClientHelloTcpSplit => &[5, 94, 1],
            // The second pair mirrors the additional first-packet split used by
            // the published preset as closely as this stream layer can without
            // pretending to implement Xray's packet classifier.
            Self::PatternihaExperimental => &[5, 94, 1, 109, 1],
            _ => &[],
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct FragmentConfig {
    pub enabled: bool,
    pub mode: MaskMode,
    pub size_min: usize,
    pub size_max: usize,
    pub delay_min_ms: u64,
    pub delay_max_ms: u64,
}

impl FragmentConfig {
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            mode: MaskMode::Off,
            size_min: 1,
            size_max: 1,
            delay_min_ms: 0,
            delay_max_ms: 0,
        }
    }

    pub fn from_env() -> Self {
        let mode = MaskMode::from_env();
        let (size_min, size_max) = parse_range(
            &std::env::var("AETHER_MASQUE_H2_FRAGMENT_SIZE").unwrap_or_default(),
            (16, 32),
        );
        let (delay_min_ms, delay_max_ms) = parse_range(
            &std::env::var("AETHER_MASQUE_H2_FRAGMENT_DELAY").unwrap_or_default(),
            (2, 10),
        );

        let size_min = size_min.max(1) as usize;
        let size_max = (size_max.max(size_min as u64)) as usize;

        Self {
            enabled: mode != MaskMode::Off,
            mode,
            size_min,
            size_max,
            delay_min_ms,
            delay_max_ms: delay_max_ms.max(delay_min_ms),
        }
    }

    fn pick_legacy_chunk_len(&self, remaining: usize) -> usize {
        let hi = self.size_max.max(1).min(remaining);
        let lo = self.size_min.max(1).min(hi);
        if lo >= hi {
            hi
        } else {
            rand::rng().random_range(lo..=hi)
        }
    }

    fn pick_delay(&self) -> Duration {
        if self.delay_max_ms == 0 {
            return Duration::ZERO;
        }
        let ms = if self.delay_max_ms <= self.delay_min_ms {
            self.delay_min_ms
        } else {
            rand::rng().random_range(self.delay_min_ms..=self.delay_max_ms)
        };
        Duration::from_millis(ms)
    }

    fn chunk_len(&self, remaining: usize, split_index: usize) -> usize {
        match self.mode {
            MaskMode::Off => remaining,
            MaskMode::LegacyTcpFragment => self.pick_legacy_chunk_len(remaining),
            MaskMode::ClientHelloTcpSplit | MaskMode::PatternihaExperimental => self
                .mode
                .deterministic_splits()
                .get(split_index)
                .copied()
                .unwrap_or(remaining)
                .max(1)
                .min(remaining),
        }
    }

    fn delay_after_split(&self, split_index: usize) -> Duration {
        match self.mode {
            MaskMode::Off => Duration::ZERO,
            MaskMode::LegacyTcpFragment => self.pick_delay(),
            // Plain deterministic ClientHello splitting changes write boundaries
            // only; it does not add timing noise unless the legacy mode is used.
            MaskMode::ClientHelloTcpSplit => Duration::ZERO,
            // The public experimental preset includes a 1 ms delay in its
            // first-packet stage. Apply that only after entering the second pair.
            MaskMode::PatternihaExperimental if split_index >= 3 => Duration::from_millis(1),
            MaskMode::PatternihaExperimental => Duration::ZERO,
        }
    }
}

fn is_truthy(v: &str) -> bool {
    matches!(
        v.trim().to_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

fn parse_range(spec: &str, default: (u64, u64)) -> (u64, u64) {
    let spec = spec.trim();
    if spec.is_empty() {
        return default;
    }
    match spec.split_once('-') {
        Some((a, b)) => {
            let lo = a.trim().parse().unwrap_or(default.0);
            let hi = b.trim().parse().unwrap_or(default.1);
            if hi < lo {
                (hi, lo)
            } else {
                (lo, hi)
            }
        }
        None => {
            let v = spec.parse().unwrap_or(default.0);
            (v, v)
        }
    }
}

pub struct FragmentingStream<S> {
    inner: S,
    cfg: FragmentConfig,
    fragmenting: bool,
    split_index: usize,
    pending_delay: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl<S> FragmentingStream<S> {
    pub fn new(inner: S, cfg: FragmentConfig) -> Self {
        Self {
            inner,
            fragmenting: cfg.enabled,
            cfg,
            split_index: 0,
            pending_delay: None,
        }
    }
}

impl<S> AsyncRead for FragmentingStream<S>
where
    S: AsyncRead + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        // Once the server starts answering, the ClientHello phase is over. Do
        // not fragment application traffic or subsequent TLS records.
        this.fragmenting = false;
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S> AsyncWrite for FragmentingStream<S>
where
    S: AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        if buf.is_empty() || !this.fragmenting {
            return Pin::new(&mut this.inner).poll_write(cx, buf);
        }

        if let Some(sleep) = this.pending_delay.as_mut() {
            match sleep.as_mut().poll(cx) {
                Poll::Ready(()) => this.pending_delay = None,
                Poll::Pending => return Poll::Pending,
            }
        }

        let split_index = this.split_index;
        let chunk_len = this.cfg.chunk_len(buf.len(), split_index);
        match Pin::new(&mut this.inner).poll_write(cx, &buf[..chunk_len]) {
            Poll::Ready(Ok(n)) => {
                if n > 0 {
                    this.split_index = this.split_index.saturating_add(1);
                    let delay = this.cfg.delay_after_split(split_index);
                    if !delay.is_zero() {
                        this.pending_delay = Some(Box::pin(tokio::time::sleep(delay)));
                    }
                }
                Poll::Ready(Ok(n))
            }
            other => other,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn old_fragment_switch_still_selects_legacy_mode() {
        std::env::remove_var("AETHER_MASQUE_H2_MASK");
        std::env::set_var("AETHER_MASQUE_H2_FRAGMENT", "1");
        let cfg = FragmentConfig::from_env();
        std::env::remove_var("AETHER_MASQUE_H2_FRAGMENT");
        assert_eq!(cfg.mode, MaskMode::LegacyTcpFragment);
        assert!(cfg.enabled);
    }

    #[test]
    fn explicit_off_beats_the_legacy_boolean() {
        std::env::set_var("AETHER_MASQUE_H2_FRAGMENT", "1");
        std::env::set_var("AETHER_MASQUE_H2_MASK", "off");
        let cfg = FragmentConfig::from_env();
        std::env::remove_var("AETHER_MASQUE_H2_FRAGMENT");
        std::env::remove_var("AETHER_MASQUE_H2_MASK");
        assert_eq!(cfg.mode, MaskMode::Off);
        assert!(!cfg.enabled);
    }

    #[test]
    fn clienthello_split_uses_deterministic_boundaries_then_releases_the_rest() {
        let cfg = FragmentConfig {
            enabled: true,
            mode: MaskMode::ClientHelloTcpSplit,
            size_min: 16,
            size_max: 32,
            delay_min_ms: 2,
            delay_max_ms: 10,
        };
        assert_eq!(cfg.chunk_len(512, 0), 5);
        assert_eq!(cfg.chunk_len(507, 1), 94);
        assert_eq!(cfg.chunk_len(413, 2), 1);
        assert_eq!(cfg.chunk_len(412, 3), 412);
    }

    #[test]
    fn patterniha_preset_is_explicitly_bounded_to_clienthello_writes() {
        let cfg = FragmentConfig {
            enabled: true,
            mode: MaskMode::PatternihaExperimental,
            size_min: 16,
            size_max: 32,
            delay_min_ms: 2,
            delay_max_ms: 10,
        };
        let expected = [5, 94, 1, 109, 1];
        for (index, size) in expected.into_iter().enumerate() {
            assert_eq!(cfg.chunk_len(512, index), size);
        }
        assert_eq!(cfg.chunk_len(512, expected.len()), 512);
    }
}
