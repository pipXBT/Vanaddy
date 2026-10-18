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
        "built without Metal support (--no-default-features, or not aarch64-apple-darwin)"
            .to_string(),
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
    use super::*;

    #[test]
    fn probe_is_unavailable_without_the_metal_backend() {
        match probe() {
            GpuStatus::Unavailable(r) => assert!(r.contains("Metal")),
            other => panic!("the stub backend must be Unavailable, got {other:?}"),
        }
    }

    #[test]
    fn stub_probe_names_metal_in_its_reason() {
        // The reason string is rendered verbatim in the TUI config row. On macOS
        // ARM this build is a deliberate --no-default-features opt-out, not an
        // unsupported target, and a user staring at "not supported on this
        // target" on an M1 has no way to tell those two apart.
        let status = probe();
        let reason = match status {
            GpuStatus::Unavailable(r) => r,
            other => panic!("stub probe() must be Unavailable, got {other:?}"),
        };
        assert!(
            reason.contains("Metal"),
            "probe() reason must name Metal so a --no-default-features build is \
             distinguishable from an unsupported target, got: {reason}"
        );
        assert!(
            reason.contains("--no-default-features"),
            "probe() reason must name the flag that produced this build, got: {reason}"
        );
    }

    #[test]
    fn stub_engine_lifecycle_is_a_terminating_no_op() {
        // Milestone 6 calls signal_stop() then polls is_finished() from the UI
        // thread's 100 ms tick. A stub that never reports finished would park an
        // engine in App::gpu_engines forever and make start_search skip the GPU
        // on every subsequent run — on a build that has no GPU anyway, so nobody
        // would ever notice the leak.
        let (tx, _rx) = crossbeam_channel::bounded(super::super::CHANNEL_CAPACITY);
        let health = std::sync::Arc::new(super::super::GpuHealth::default());
        let engine = GpuEngine::start(tx, health);
        engine.signal_stop();
        assert!(engine.is_finished());
        engine.reap();
    }
}
