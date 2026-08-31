//! The GPU producer thread: fill -> dispatch -> audit -> carve -> send.
//!
//! Everything in this file that does not name a Metal type is compiled on every
//! target, so the fault plumbing, the `ring` audit, the block carving and the
//! panic guard are unit-tested on Linux and under `--no-default-features` too.
//! Only `producer()` itself is `cfg`-gated.

use super::{GpuDisableReason, GpuError, GpuStatus, AUDITS_PER_WAVE};
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

/// Re-derive `indices` of a finished wave with `ring` and compare.
///
/// A wrong GPU seed cannot reach the CSV — the `Verified` token gate stops that
/// — but it can silently waste the search: the counter climbs while up to ~55%
/// of it is noise. This is the only detector for that, so a disagreement is a
/// hard, sticky fault, never a retry.
///
/// `ring` is the reference because `crate::seed::derive_seed` (src/seed.rs:8)
/// is what every pinned vector in CLAUDE.md already pins.
pub(crate) fn audit_wave(
    entropy: &[[u8; 16]],
    seeds: &[[u8; 64]],
    indices: &[usize],
) -> Result<(), GpuDisableReason> {
    for &i in indices {
        if i >= entropy.len() || i >= seeds.len() {
            return Err(GpuDisableReason::AuditMismatch { index: i });
        }
        let m = bip39::Mnemonic::from_entropy(&entropy[i], bip39::Language::English)
            .map_err(|_| GpuDisableReason::AuditMismatch { index: i })?;
        if crate::seed::derive_seed(&m) != seeds[i] {
            return Err(GpuDisableReason::AuditMismatch { index: i });
        }
    }
    Ok(())
}

/// `AUDITS_PER_WAVE` RANDOM indices into a wave of `wave` candidates.
///
/// Random, not a stride: a fixed stride equal to the block size samples the
/// same `tid` on every wave forever and is blind to every tid-dependent kernel
/// bug — exactly the bug class the per-thread indexing (`states + tid`,
/// `seeds + 64*tid`) can produce.
pub(crate) fn audit_indices<R: rand::Rng>(rng: &mut R, wave: usize) -> [usize; AUDITS_PER_WAVE] {
    assert!(wave > 0, "cannot audit an empty wave");
    std::array::from_fn(|_| rng.gen_range(0..wave))
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

    /// Deterministic wave of `n` candidates whose seeds are the CORRECT `ring`
    /// seeds for their entropy, so any mutation the tests make is the only
    /// disagreement present.
    fn honest_wave(n: usize) -> (Vec<[u8; 16]>, Vec<[u8; 64]>) {
        let mut entropy = Vec::with_capacity(n);
        let mut seeds = Vec::with_capacity(n);
        for i in 0..n {
            let mut e = [0u8; 16];
            e[..8].copy_from_slice(&(i as u64).to_be_bytes());
            let m = bip39::Mnemonic::from_entropy(&e, bip39::Language::English)
                .expect("16 bytes is always a valid 12-word entropy");
            seeds.push(crate::seed::derive_seed(&m));
            entropy.push(e);
        }
        (entropy, seeds)
    }

    #[test]
    fn audit_wave_accepts_ring_derived_seeds() {
        let (entropy, seeds) = honest_wave(8);
        assert_eq!(audit_wave(&entropy, &seeds, &[0, 3, 5, 7]), Ok(()));
    }

    #[test]
    fn audit_wave_rejects_one_flipped_seed_bit() {
        let (entropy, mut seeds) = honest_wave(8);
        seeds[3][63] ^= 0x01;
        assert_eq!(
            audit_wave(&entropy, &seeds, &[0, 3, 5, 7]),
            Err(GpuDisableReason::AuditMismatch { index: 3 })
        );
    }

    #[test]
    fn audit_wave_ignores_corruption_at_unsampled_indices() {
        // Honest statement of the detector's limit: it is probabilistic, and a
        // bug confined to a handful of tids can survive a wave. This is the
        // reason the indices are re-drawn every wave rather than fixed.
        let (entropy, mut seeds) = honest_wave(8);
        seeds[6][0] ^= 0xFF;
        assert_eq!(audit_wave(&entropy, &seeds, &[0, 3, 5, 7]), Ok(()));
    }

    #[test]
    fn audit_wave_rejects_an_out_of_range_index() {
        let (entropy, seeds) = honest_wave(8);
        assert_eq!(
            audit_wave(&entropy, &seeds, &[9]),
            Err(GpuDisableReason::AuditMismatch { index: 9 })
        );
    }

    #[test]
    fn audit_indices_are_in_range_and_are_not_a_fixed_stride() {
        let mut rng = rand::thread_rng();
        let mut seen = std::collections::HashSet::new();
        for _ in 0..200 {
            let ix = audit_indices(&mut rng, 8_192);
            assert_eq!(ix.len(), AUDITS_PER_WAVE);
            for i in ix {
                assert!(i < 8_192, "index {i} out of range");
                seen.insert(i);
            }
        }
        // 800 draws from 8192 collapsing to one value has probability
        // 8192^-799; a fixed stride would produce exactly 4 distinct values.
        assert!(
            seen.len() > 4,
            "indices must vary across waves, saw {}",
            seen.len()
        );
    }
}
