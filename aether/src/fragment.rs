use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use rand::RngExt;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

const PATTERNIHA_TLS_FIRST_PAYLOAD: usize = 104;
const PATTERNIHA_TCP_FIRST_WRITE: usize = 114;
const PATTERNIHA_TCP_MAX_SPLITS: usize = 11;
const PATTERNIHA_TCP_DELAY_MS: u64 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaskMode {
    Off,
    LegacyTcpFragment,
    /// Deterministic TCP write boundaries during the ClientHello phase. This
    /// compatibility mode does not rewrite TLS record headers.
    ClientHelloTcpSplit,
    /// Two-stage compatibility preset derived from the current public
    /// Patterniha finalMask layout: reshape the first TLS handshake record,
    /// then slice the resulting first TCP write with a bounded split count.
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
            _ => &[],
        }
    }

    fn is_simple_deterministic(self) -> bool {
        matches!(self, Self::ClientHelloTcpSplit)
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

    fn delay_after_split(&self, _split_index: usize) -> Duration {
        match self.mode {
            MaskMode::Off => Duration::ZERO,
            MaskMode::LegacyTcpFragment => self.pick_delay(),
            MaskMode::ClientHelloTcpSplit => Duration::ZERO,
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

fn append_tls_record(out: &mut Vec<u8>, header_prefix: &[u8], payload: &[u8]) {
    debug_assert!(header_prefix.len() >= 3);
    debug_assert!(payload.len() <= u16::MAX as usize);
    out.extend_from_slice(&header_prefix[..3]);
    out.push(((payload.len() >> 8) & 0xff) as u8);
    out.push((payload.len() & 0xff) as u8);
    out.extend_from_slice(payload);
}

/// Reproduce the current Patterniha tlshello stage below the TLS library.
///
/// The first complete handshake record is rewritten as:
///   empty record, 104-byte record, then one-byte records until exhausted.
/// A single zero delay means all shaped records are handed to the TCP stage as
/// one write. Data after the first TLS record is kept byte-for-byte.
fn patterniha_shape_first_tls_write(buf: &[u8]) -> Option<Vec<u8>> {
    if buf.len() <= 5 || buf[0] != 22 {
        return None;
    }
    let record_len = 5 + ((usize::from(buf[3]) << 8) | usize::from(buf[4]));
    if record_len < 5 || buf.len() < record_len {
        return None;
    }

    let payload = &buf[5..record_len];
    let first_len = PATTERNIHA_TLS_FIRST_PAYLOAD.min(payload.len());
    let remaining = payload.len().saturating_sub(first_len);
    let mut out = Vec::with_capacity(buf.len().saturating_add(10 + remaining.saturating_mul(5)));

    // `lengths: ["0", "104", "1"]` in tlshello mode deliberately emits an
    // empty TLS record for the first zero-length segment. This mirrors Xray's
    // current finalMask semantics instead of silently clamping zero to one.
    append_tls_record(&mut out, buf, &[]);
    append_tls_record(&mut out, buf, &payload[..first_len]);

    let mut offset = first_len;
    while offset < payload.len() {
        append_tls_record(&mut out, buf, &payload[offset..offset + 1]);
        offset += 1;
    }

    out.extend_from_slice(&buf[record_len..]);
    Some(out)
}

fn patterniha_tcp_chunk_len(split_index: usize, remaining: usize) -> usize {
    if remaining == 0 {
        return 0;
    }
    if split_index == 0 {
        return PATTERNIHA_TCP_FIRST_WRITE.min(remaining);
    }
    if split_index + 1 >= PATTERNIHA_TCP_MAX_SPLITS {
        return remaining;
    }
    1.min(remaining)
}

#[derive(Debug)]
struct PatternPendingWrite {
    bytes: Vec<u8>,
    offset: usize,
    original_len: usize,
    split_index: usize,
    split_remaining: usize,
}

impl PatternPendingWrite {
    fn new(input: &[u8]) -> Self {
        Self {
            bytes: patterniha_shape_first_tls_write(input).unwrap_or_else(|| input.to_vec()),
            offset: 0,
            original_len: input.len(),
            split_index: 0,
            split_remaining: 0,
        }
    }

    fn done(&self) -> bool {
        self.offset >= self.bytes.len()
    }
}

pub struct FragmentingStream<S> {
    inner: S,
    cfg: FragmentConfig,
    fragmenting: bool,
    split_index: usize,
    /// Bytes still required to complete the current simple deterministic split.
    /// AsyncWrite permits short writes, so advancing the split index after any
    /// successful write would shift all later boundaries under backpressure.
    split_remaining: usize,
    pending_delay: Option<Pin<Box<tokio::time::Sleep>>>,
    pattern_pending: Option<PatternPendingWrite>,
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
            pattern_pending: None,
        }
    }

    fn complete_split(&mut self, split_index: usize) {
        self.split_index = self.split_index.saturating_add(1);
        self.split_remaining = 0;

        let delay = self.cfg.delay_after_split(split_index);
        if !delay.is_zero() {
            self.pending_delay = Some(Box::pin(tokio::time::sleep(delay)));
        }

        if self.cfg.mode.is_simple_deterministic()
            && self
                .cfg
                .deterministic_split_len(self.split_index)
                .is_none()
        {
            // The requested simple split sequence is complete. Forward the
            // remaining ClientHello bytes in the TLS implementation's natural
            // write pattern.
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
        // not alter application traffic or subsequent TLS records.
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

        if this.cfg.mode == MaskMode::PatternihaExperimental {
            if this.pattern_pending.is_none() {
                this.pattern_pending = Some(PatternPendingWrite::new(buf));
            }

            loop {
                if let Some(sleep) = this.pending_delay.as_mut() {
                    match sleep.as_mut().poll(cx) {
                        Poll::Ready(()) => this.pending_delay = None,
                        Poll::Pending => return Poll::Pending,
                    }
                }

                if this.pattern_pending.as_ref().is_some_and(PatternPendingWrite::done) {
                    let consumed = this
                        .pattern_pending
                        .take()
                        .map(|pending| pending.original_len)
                        .unwrap_or(buf.len());
                    this.fragmenting = false;
                    return Poll::Ready(Ok(consumed));
                }

                let (result, completed_chunk) = {
                    let (inner, pending_slot) = (&mut this.inner, &mut this.pattern_pending);
                    let pending = pending_slot
                        .as_mut()
                        .expect("pattern write exists while compatibility mask is active");
                    let remaining = pending.bytes.len().saturating_sub(pending.offset);
                    if pending.split_remaining == 0 {
                        pending.split_remaining =
                            patterniha_tcp_chunk_len(pending.split_index, remaining);
                    }
                    let chunk_len = pending.split_remaining.min(remaining);
                    if chunk_len == 0 {
                        (Poll::Ready(Ok(0)), false)
                    } else {
                        let start = pending.offset;
                        let end = start + chunk_len;
                        match Pin::new(inner).poll_write(cx, &pending.bytes[start..end]) {
                            Poll::Ready(Ok(n)) => {
                                if n > 0 {
                                    pending.offset = pending.offset.saturating_add(n);
                                    pending.split_remaining = pending.split_remaining.saturating_sub(n);
                                }
                                (Poll::Ready(Ok(n)), n > 0 && pending.split_remaining == 0)
                            }
                            Poll::Ready(Err(error)) => (Poll::Ready(Err(error)), false),
                            Poll::Pending => (Poll::Pending, false),
                        }
                    }
                };

                match result {
                    Poll::Ready(Ok(0)) => return Poll::Ready(Ok(0)),
                    Poll::Ready(Ok(_)) => {
                        if completed_chunk {
                            if let Some(pending) = this.pattern_pending.as_mut() {
                                pending.split_index = pending.split_index.saturating_add(1);
                            }
                            this.pending_delay = Some(Box::pin(tokio::time::sleep(
                                Duration::from_millis(PATTERNIHA_TCP_DELAY_MS),
                            )));
                        }
                        // Continue until the underlying writer blocks or the
                        // requested transformed write has been completely sent.
                    }
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Pending => return Poll::Pending,
                }
            }
        }

        if let Some(sleep) = this.pending_delay.as_mut() {
            match sleep.as_mut().poll(cx) {
                Poll::Ready(()) => this.pending_delay = None,
                Poll::Pending => return Poll::Pending,
            }
        }

        let split_index = this.split_index;
        let deterministic = this.cfg.mode.is_simple_deterministic();
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
    fn clienthello_split_uses_existing_deterministic_boundaries() {
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

    fn tls_handshake_record(payload_len: usize) -> Vec<u8> {
        let mut record = vec![22, 3, 3, ((payload_len >> 8) & 0xff) as u8, (payload_len & 0xff) as u8];
        record.extend((0..payload_len).map(|index| (index % 251) as u8));
        record
    }

    fn tls_record_lengths(bytes: &[u8]) -> Vec<usize> {
        let mut lengths = Vec::new();
        let mut offset = 0;
        while offset + 5 <= bytes.len() {
            if bytes[offset] != 22 {
                break;
            }
            let len = (usize::from(bytes[offset + 3]) << 8) | usize::from(bytes[offset + 4]);
            if offset + 5 + len > bytes.len() {
                break;
            }
            lengths.push(len);
            offset += 5 + len;
        }
        lengths
    }

    #[test]
    fn patterniha_tls_stage_preserves_zero_104_then_one_byte_semantics() {
        let input = tls_handshake_record(108);
        let shaped = patterniha_shape_first_tls_write(&input).unwrap();
        assert_eq!(tls_record_lengths(&shaped), vec![0, 104, 1, 1, 1, 1]);
    }

    #[test]
    fn patterniha_tls_stage_preserves_trailing_records_byte_for_byte() {
        let mut input = tls_handshake_record(104);
        let trailing = [23, 3, 3, 0, 2, 0xaa, 0xbb];
        input.extend_from_slice(&trailing);
        let shaped = patterniha_shape_first_tls_write(&input).unwrap();
        assert!(shaped.ends_with(&trailing));
    }

    #[test]
    fn patterniha_tcp_stage_is_bounded_to_eleven_writes() {
        let mut remaining = 300;
        let mut chunks = Vec::new();
        for split_index in 0..PATTERNIHA_TCP_MAX_SPLITS {
            let chunk = patterniha_tcp_chunk_len(split_index, remaining);
            chunks.push(chunk);
            remaining = remaining.saturating_sub(chunk);
            if remaining == 0 {
                break;
            }
        }
        assert_eq!(chunks[0], 114);
        assert_eq!(&chunks[1..10], &[1; 9]);
        assert_eq!(chunks[10], 177);
        assert_eq!(remaining, 0);
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

    #[tokio::test]
    async fn patterniha_mode_rewrites_first_tls_record_and_survives_short_writes() {
        let cfg = FragmentConfig {
            enabled: true,
            mode: MaskMode::PatternihaExperimental,
            size_min: 16,
            size_max: 32,
            delay_min_ms: 0,
            delay_max_ms: 0,
        };
        let inner = ShortWriter {
            max_per_write: 17,
            ..ShortWriter::default()
        };
        let mut stream = FragmentingStream::new(inner, cfg);
        let input = tls_handshake_record(108);
        let expected = patterniha_shape_first_tls_write(&input).unwrap();
        stream.write_all(&input).await.unwrap();

        assert_eq!(stream.inner.bytes, expected);
        assert!(!stream.fragmenting);
        assert!(stream.pattern_pending.is_none());
    }
}
