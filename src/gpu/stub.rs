//! No-op GPU backend for every target that is not `aarch64-apple-darwin` with
//! the `metal` feature. Zero dependencies, no Metal symbols, no GPU code in the
//! binary at all — which doubles as the rollback lever
//! `cargo build --release --no-default-features`.

use crate::gpu::GpuStatus;

use super::{GpuDisableReason, GpuHealth, SeedBlock};
use crossbeam_channel::Sender;
use std::sync::Arc;

/// Mirror of `metal::probe`. Always unavailable; the TUI renders the reason.
pub fn probe() -> GpuStatus {
    GpuStatus::Unavailable(
        "Metal PBKDF2 offload requires Apple Silicon macOS and the `metal` feature".to_string(),
    )
}

/// No Metal on this target. The same public surface, all no-ops.
pub struct GpuEngine;

impl GpuEngine {
    pub fn probe() -> GpuStatus {
        probe()
    }

    /// Hangs the channel up immediately and records why, so a caller that
    /// ignored `probe()` degrades to CPU-only at once instead of waiting
    /// forever for blocks that can never arrive.
    pub fn start(tx: Sender<Box<SeedBlock>>, health: Arc<GpuHealth>) -> GpuEngine {
        drop(tx);
        health.raise(GpuDisableReason::NotSupported);
        GpuEngine
    }

    pub fn status(&self) -> GpuStatus {
        probe()
    }

    pub fn signal_stop(&self) {}

    /// There is no thread, so there is nothing to wait for.
    pub fn is_finished(&self) -> bool {
        true
    }

    pub fn reap(self) {
        debug_assert!(
            self.is_finished(),
            "reap() joins the producer thread: calling it before is_finished() can hang the UI \
             thread inside a wedged waitUntilCompleted, with the terminal still in raw mode. \
             Park the engine and reap it on a later pass instead."
        );
    }
}

#[cfg(test)]
mod tests {
    use super::probe;
    use crate::gpu::GpuStatus;

    #[test]
    fn probe_is_unavailable_without_the_metal_backend() {
        match probe() {
            GpuStatus::Unavailable(r) => assert!(r.contains("Apple Silicon")),
            other => panic!("the stub backend must be Unavailable, got {other:?}"),
        }
    }
}
