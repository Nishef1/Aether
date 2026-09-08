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
    /// Best-effort deterministic TCP write boundaries over the cleartext TLS
    /// ClientHello. This does not rewrite TLS records; it only controls how
    /// bytes offered by the TLS implementation are forwarded to the socket.
    ClientHelloTcpSplit,
    /// Best-effort TCP split preset inspired by the public Patterniha finalMask
    /// layout. It deliberately remains experimental because Xray's packet
    /// matcher/maxSplit semantics are not identical to an AsyncWrite stream.
    PatternihaExperimental,
}

impl MaskMode {
    fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "off" | "0" | "false" | "none" => Some(Self::Off),
            "legacy" | "fragment" | "tcp-fragment" => Some(Self::LegacyTcpFragment),
            "clienthello" | "clienthello-split" | "tlshello" => Some(Self::ClientHelloTcpSplit),
            "patterniha" | "patterniha-experimental" => Some(Self::PatternihaExperimental),
            _ => None,
        }
    }

    fn from_env() -> Self {
        if let Ok(value) = std::env::var("AETHER_MASQUE_H2_MASK") {
            return Self::parse(&value).unwrap_or(Self::Off);
        }

        // Android's compatibility bridge predates the explicit mask field. It
        // can carry deterministic modes through the already-stable
        // --fragment-size string without changing the Kotlin/native ABI.
        if let Ok(value) = std::env::var("AETHER_MASQUE_H2_FRAGMENT_SIZE") {
            if matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "clienthello" | "clienthello-split" | "tlshello" | "patterniha" | "patterniha-experimental"
            ) {
                return Self::parse(&value).unwrap_or(Self::Off);
            }
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

    fn is_deterministic(self) -> bool {
        matches!(
            self,
            Self::ClientHelloTcpSplit | Self::PatternihaExperimental
        )
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

    fn deterministic_split_len(&self, split_index: usize) -> Option<usize> {
        self.mode
            .deterministic_splits()
            .get(split_index)
            .copied()
            .map(|value| value.max(1))
    }

    fn delay_after_split(&self, split_index: usize) -> Duration {
        match self.mode {
            MaskMode::Off => Duration::ZERO,
            MaskMode::LegacyTcpFragment => self.pick_delay(),
            MaskMode::ClientHelloTcpSplit => Duration::ZERO,
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
    /// Bytes still required to complete the current deterministic split.
    /// AsyncWrite permits short writes, so advancing the split index after any
    /// successful write would shift all later boundaries under backpressure.
    split_remaining: usize,
    pending_delay: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl<S> FragmentingStream<S> {
    pub fn new(inner: S, cfg: FragmentConfig) -> Self {
        Self {
            inner,
            fragmenting: cfg.enabled,
            cfg,
            split_index: 0,
            split_remaining: 0,
            pending_delay: None,
        }
    }

    fn complete_split(&mut self, split_index: usize) {
        self.split_index = self.split_index.saturating_add(1);
        self.split_remaining = 0;

        let delay = self.cfg.delay_after_split(split_index);
        if !delay.is_zero() {
            self.pending_delay = Some(Box::pin(tokio::time::sleep(delay)));
        }

        if self.cfg.mode.is_deterministic()
            && self
                .cfg
                .deterministic_split_len(self.split_index)
                .is_none()
        {
            // The requested mask sequence is complete. Forward the rest of the
            // ClientHello in the TLS implementation's natural write pattern.
            self.fragmenting = false;
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
        this.split_remaining = 0;
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
        let deterministic = this.cfg.mode.is_deterministic();
        let chunk_len = if deterministic {
            if this.split_remaining == 0 {
                let Some(target) = this.cfg.deterministic_split_len(split_index) else {
                    this.fragmenting = false;
                    return Pin::new(&mut this.inner).poll_write(cx, buf);
                };
                this.split_remaining = target;
            }
            this.split_remaining.min(buf.len())
        } else {
            this.cfg.pick_legacy_chunk_len(buf.len())
        };

        match Pin::new(&mut this.inner).poll_write(cx, &buf[..chunk_len]) {
            Poll::Ready(Ok(n)) => {
                if n == 0 {
                    return Poll::Ready(Ok(0));
                }

                if deterministic {
                    this.split_remaining = this.split_remaining.saturating_sub(n);
                    if this.split_remaining == 0 {
                        this.complete_split(split_index);
                    }
                } else {
                    // Legacy mode intentionally treats every successful socket
                    // write as a fragment, including an underlying short write.
                    this.complete_split(split_index);
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
    use tokio::io::AsyncWriteExt;

    fn clear_mask_env() {
        std::env::remove_var("AETHER_MASQUE_H2_MASK");
        std::env::remove_var("AETHER_MASQUE_H2_FRAGMENT");
        std::env::remove_var("AETHER_MASQUE_H2_FRAGMENT_SIZE");
    }

    #[test]
    fn old_fragment_switch_still_selects_legacy_mode() {
        clear_mask_env();
        std::env::set_var("AETHER_MASQUE_H2_FRAGMENT", "1");
        let cfg = FragmentConfig::from_env();
        clear_mask_env();
        assert_eq!(cfg.mode, MaskMode::LegacyTcpFragment);
        assert!(cfg.enabled);
    }

    #[test]
    fn explicit_off_beats_the_legacy_boolean() {
        clear_mask_env();
        std::env::set_var("AETHER_MASQUE_H2_FRAGMENT", "1");
        std::env::set_var("AETHER_MASQUE_H2_MASK", "off");
        let cfg = FragmentConfig::from_env();
        clear_mask_env();
        assert_eq!(cfg.mode, MaskMode::Off);
        assert!(!cfg.enabled);
    }

    #[test]
    fn android_bridge_sentinel_selects_deterministic_mode() {
        clear_mask_env();
        std::env::set_var("AETHER_MASQUE_H2_FRAGMENT", "1");
        std::env::set_var("AETHER_MASQUE_H2_FRAGMENT_SIZE", "clienthello");
        let clienthello = FragmentConfig::from_env();
        assert_eq!(clienthello.mode, MaskMode::ClientHelloTcpSplit);

        std::env::set_var("AETHER_MASQUE_H2_FRAGMENT_SIZE", "patterniha");
        let patterniha = FragmentConfig::from_env();
        clear_mask_env();
        assert_eq!(patterniha.mode, MaskMode::PatternihaExperimental);
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
        assert_eq!(cfg.deterministic_split_len(0), Some(5));
        assert_eq!(cfg.deterministic_split_len(1), Some(94));
        assert_eq!(cfg.deterministic_split_len(2), Some(1));
        assert_eq!(cfg.deterministic_split_len(3), None);
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
            assert_eq!(cfg.deterministic_split_len(index), Some(size));
        }
        assert_eq!(cfg.deterministic_split_len(expected.len()), None);
    }

    #[derive(Default)]
    struct ShortWriter {
        bytes: Vec<u8>,
        writes: Vec<usize>,
        max_per_write: usize,
    }

    impl AsyncWrite for ShortWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let n = buf.len().min(self.max_per_write.max(1));
            self.bytes.extend_from_slice(&buf[..n]);
            self.writes.push(n);
            Poll::Ready(Ok(n))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn deterministic_split_progress_survives_underlying_short_writes() {
        let cfg = FragmentConfig {
            enabled: true,
            mode: MaskMode::ClientHelloTcpSplit,
            size_min: 16,
            size_max: 32,
            delay_min_ms: 0,
            delay_max_ms: 0,
        };
        let inner = ShortWriter {
            max_per_write: 2,
            ..ShortWriter::default()
        };
        let mut stream = FragmentingStream::new(inner, cfg);
        let payload = vec![0x16; 128];
        stream.write_all(&payload).await.unwrap();

        assert_eq!(stream.inner.bytes, payload);
        assert_eq!(stream.split_index, 3);
        assert_eq!(stream.split_remaining, 0);
        assert!(!stream.fragmenting);
    }
}
