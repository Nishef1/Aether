use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use rand::Rng;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

const DEFAULT_FRAGMENT_SIZE: (u64, u64) = (16, 32);
const DEFAULT_FRAGMENT_DELAY_MS: (u64, u64) = (2, 10);
const MIN_FRAGMENT_SIZE: u64 = 1;
const MAX_FRAGMENT_SIZE: u64 = 4096;
const MAX_FRAGMENT_DELAY_MS: u64 = 100;

#[derive(Debug, Clone, Copy)]
pub struct FragmentConfig {
    pub enabled: bool,
    pub size_min: usize,
    pub size_max: usize,
    pub delay_min_ms: u64,
    pub delay_max_ms: u64,
}

impl FragmentConfig {
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            size_min: 1,
            size_max: 1,
            delay_min_ms: 0,
            delay_max_ms: 0,
        }
    }

    pub fn from_env() -> Self {
        let enabled = std::env::var("AETHER_MASQUE_H2_FRAGMENT")
            .map(|value| is_truthy(&value))
            .unwrap_or(false);

        let (size_min, size_max) = parse_bounded_range(
            &std::env::var("AETHER_MASQUE_H2_FRAGMENT_SIZE").unwrap_or_default(),
            DEFAULT_FRAGMENT_SIZE,
            MIN_FRAGMENT_SIZE,
            MAX_FRAGMENT_SIZE,
        );
        let (delay_min_ms, delay_max_ms) = parse_bounded_range(
            &std::env::var("AETHER_MASQUE_H2_FRAGMENT_DELAY").unwrap_or_default(),
            DEFAULT_FRAGMENT_DELAY_MS,
            0,
            MAX_FRAGMENT_DELAY_MS,
        );

        Self {
            enabled,
            size_min: size_min as usize,
            size_max: size_max as usize,
            delay_min_ms,
            delay_max_ms,
        }
    }

    fn pick_chunk_len(&self, remaining: usize) -> usize {
        let high = self.size_max.max(1).min(remaining);
        let low = self.size_min.max(1).min(high);
        if low >= high {
            high
        } else {
            rand::thread_rng().gen_range(low..=high)
        }
    }

    fn pick_delay(&self) -> Duration {
        if self.delay_max_ms == 0 {
            return Duration::ZERO;
        }
        let milliseconds = if self.delay_max_ms <= self.delay_min_ms {
            self.delay_min_ms
        } else {
            rand::thread_rng().gen_range(self.delay_min_ms..=self.delay_max_ms)
        };
        Duration::from_millis(milliseconds)
    }
}

fn is_truthy(value: &str) -> bool {
    matches!(
        value.trim().to_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

fn parse_bounded_range(
    spec: &str,
    default: (u64, u64),
    minimum: u64,
    maximum: u64,
) -> (u64, u64) {
    let spec = spec.trim();
    let parsed = if spec.is_empty() {
        default
    } else {
        match spec.split_once('-') {
            Some((left, right)) => {
                let low = left.trim().parse().unwrap_or(default.0);
                let high = right.trim().parse().unwrap_or(default.1);
                if high < low {
                    (high, low)
                } else {
                    (low, high)
                }
            }
            None => {
                let value = spec.parse().unwrap_or(default.0);
                (value, value)
            }
        }
    };

    let low = parsed.0.clamp(minimum, maximum);
    let high = parsed.1.clamp(minimum, maximum).max(low);
    (low, high)
}

pub struct FragmentingStream<S> {
    inner: S,
    config: FragmentConfig,
    fragmenting: bool,
    pending_delay: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl<S> FragmentingStream<S> {
    pub fn new(inner: S, config: FragmentConfig) -> Self {
        Self {
            inner,
            fragmenting: config.enabled,
            config,
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
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        // TLS has entered the response phase. Do not fragment application data or
        // later TLS records after the initial client flight.
        this.fragmenting = false;
        this.pending_delay = None;
        Pin::new(&mut this.inner).poll_read(context, buffer)
    }
}

impl<S> AsyncWrite for FragmentingStream<S>
where
    S: AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        if buffer.is_empty() || !this.fragmenting {
            return Pin::new(&mut this.inner).poll_write(context, buffer);
        }

        if let Some(sleep) = this.pending_delay.as_mut() {
            match sleep.as_mut().poll(context) {
                Poll::Ready(()) => this.pending_delay = None,
                Poll::Pending => return Poll::Pending,
            }
        }

        let chunk_len = this.config.pick_chunk_len(buffer.len());
        match Pin::new(&mut this.inner).poll_write(context, &buffer[..chunk_len]) {
            Poll::Ready(Ok(written)) => {
                if written > 0 {
                    let delay = this.config.pick_delay();
                    if !delay.is_zero() {
                        this.pending_delay = Some(Box::pin(tokio::time::sleep(delay)));
                    }
                }
                Poll::Ready(Ok(written))
            }
            other => other,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(context)
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(context)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranges_are_sorted_and_clamped() {
        assert_eq!(
            parse_bounded_range("32-16", DEFAULT_FRAGMENT_SIZE, 1, 4096),
            (16, 32)
        );
        assert_eq!(
            parse_bounded_range("0-999999", DEFAULT_FRAGMENT_SIZE, 1, 4096),
            (1, 4096)
        );
        assert_eq!(
            parse_bounded_range("invalid", DEFAULT_FRAGMENT_SIZE, 1, 4096),
            (16, 16)
        );
    }
}
