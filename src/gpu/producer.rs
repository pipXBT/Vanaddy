//! The GPU producer thread: fill -> dispatch -> audit -> carve -> send.
//!
//! Everything in this file that does not name a Metal type is compiled on every
//! target, so the fault plumbing, the `ring` audit, the block carving and the
//! panic guard are unit-tested on Linux and under `--no-default-features` too.
//! Only `producer()` itself is `cfg`-gated.

use super::{GpuDisableReason, GpuError, GpuStatus};
use std::sync::Mutex;

/// Funnel every backend failure into the one sticky reason the UI reports.
///
/// This is a ONE-LINE DELEGATE to `impl From<GpuError> for GpuDisableReason`
/// (`src/gpu/mod.rs`, Task 3.2) on purpose: that impl is what `?` already uses,
/// so writing the match again here would give the fault-classification table
/// two copies free to drift. This wrapper exists only so `producer()` can say
/// `.map_err(reason_from)` at call sites where `?` cannot convert, and so the
/// tests below pin the mapping from inside this module.
///
/// Milestone 3 must therefore land before Milestone 4: Task 3.2 is where the
/// `From` impl comes from, and without it this function does not compile.
///
/// `SaltTooLong` has no `GpuDisableReason` twin because it is a programming
/// error in the caller, not a property of the device: it can only fire if a
/// future chain feeds a salt longer than `pbkdf2_lanes::MAX_SALT_LEN` (107),
/// so the `From` impl degrades it to `BadConfig`
/// carrying both the offending length and the limit.
pub(crate) fn reason_from(e: GpuError) -> GpuDisableReason {
    GpuDisableReason::from(e)
}

/// Poison-immune write. The UI thread reads this cell every 100 ms; a worker
/// that panicked while holding the lock must not make the GPU status
/// permanently unreadable, so a poisoned lock is recovered, never unwrapped.
pub(crate) fn set_status(cell: &Mutex<GpuStatus>, next: GpuStatus) {
    match cell.lock() {
        Ok(mut guard) => *guard = next,
        Err(poisoned) => *poisoned.into_inner() = next,
    }
}

/// Poison-immune read. Same reasoning as `set_status`.
pub(crate) fn read_status(cell: &Mutex<GpuStatus>) -> GpuStatus {
    match cell.lock() {
        Ok(guard) => guard.clone(),
        Err(poisoned) => poisoned.into_inner().clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_gpu_error_maps_to_its_disable_reason() {
        assert_eq!(reason_from(GpuError::NoDevice), GpuDisableReason::NoDevice);
        assert_eq!(
            reason_from(GpuError::ShaderCompile("bad token".into())),
            GpuDisableReason::ShaderCompile("bad token".into())
        );
        assert_eq!(
            reason_from(GpuError::PipelineCreate("no function".into())),
            GpuDisableReason::PipelineCreate("no function".into())
        );
        assert_eq!(
            reason_from(GpuError::BufferAlloc),
            GpuDisableReason::BufferAlloc
        );
        assert_eq!(
            reason_from(GpuError::BadConfig("tg 0".into())),
            GpuDisableReason::BadConfig("tg 0".into())
        );
        assert_eq!(
            reason_from(GpuError::CommandBuffer {
                status: 5,
                message: "IOAF code 3".into()
            }),
            GpuDisableReason::CommandBuffer {
                status: 5,
                message: "IOAF code 3".into()
            }
        );
    }

    #[test]
    fn salt_too_long_becomes_a_bad_config_naming_the_length() {
        match reason_from(GpuError::SaltTooLong { len: 200 }) {
            GpuDisableReason::BadConfig(m) => {
                assert!(
                    m.contains("200"),
                    "message must name the offending length, got {m:?}"
                );
                assert!(m.contains("107"), "message must name the limit, got {m:?}");
            }
            other => panic!("expected BadConfig, got {other:?}"),
        }
    }

    #[test]
    fn status_read_and_write_survive_a_poisoned_lock() {
        let cell = Mutex::new(GpuStatus::Initializing);

        let prev_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _held = cell.lock().unwrap();
            panic!("poison the lock while holding it");
        }));
        std::panic::set_hook(prev_hook);
        assert!(
            cell.is_poisoned(),
            "the setup must actually poison the mutex"
        );

        set_status(
            &cell,
            GpuStatus::Running {
                device: "Apple M1".into(),
            },
        );
        assert_eq!(
            read_status(&cell),
            GpuStatus::Running {
                device: "Apple M1".into()
            },
            "a poisoned status cell must still be readable and writable"
        );
    }
}
