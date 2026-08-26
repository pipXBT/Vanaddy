//! No-op GPU backend. Compiled on every target that is not Apple Silicon with
//! the `metal` feature - and, until milestone 3 lands `metal.rs`, on every
//! target full stop. Zero dependencies, no Objective-C, no threads.

use super::GpuStatus;
use std::convert::Infallible;

/// The backend's probe entry point, as a *free* function: `src/gpu/mod.rs`
/// re-exports this one as `crate::gpu::probe`, which is the design spec's
/// `mod.rs` form (`pub use backend::{GpuEngine, probe};`). Milestone 3 swaps
/// this file for `metal.rs`, which defines the same free function, so the
/// re-export never changes shape.
pub fn probe() -> GpuStatus {
    GpuStatus::Unavailable("no Metal backend in this build".to_string())
}

/// Uninhabited by construction: on a target with no backend, a live engine must
/// be *impossible*, not merely unused. Every method below is therefore
/// statically unreachable and needs no panic.
pub struct GpuEngine {
    _never: Infallible,
}

impl GpuEngine {
    /// Delegates to the free `probe()` above. `self::` is the module path, not
    /// `Self::`, so this resolves to that function and is not recursion.
    pub fn probe() -> GpuStatus {
        self::probe()
    }

    pub fn status(&self) -> GpuStatus {
        match self._never {}
    }

    pub fn signal_stop(&self) {
        match self._never {}
    }

    pub fn is_finished(&self) -> bool {
        match self._never {}
    }

    pub fn reap(self) {
        match self._never {}
    }
}
