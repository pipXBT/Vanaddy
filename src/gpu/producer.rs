//! The GPU producer thread: fill -> dispatch -> audit -> carve -> send.
//!
//! Everything in this file that does not name a Metal type is compiled on every
//! target, so the fault plumbing, the `ring` audit, the block carving and the
//! panic guard are unit-tested on Linux and under `--no-default-features` too.
//! Only `producer()` itself is `cfg`-gated.

use super::{
    GpuCandidate, GpuDisableReason, GpuError, GpuHealth, GpuStatus, SeedBlock, AUDITS_PER_WAVE,
    BLOCK,
};
use crossbeam_channel::{SendTimeoutError, Sender};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::Duration;

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
///
/// An out-of-range index or a `from_entropy` failure is a CALLER bug, not a
/// property of the device — `audit_indices` only ever draws `0..wave`, and 16
/// bytes is always valid 12-word BIP-39 entropy — so both degrade to
/// `BadConfig`, never `AuditMismatch`, following the same principle
/// `reason_from`'s doc comment states for `SaltTooLong` above: a programming
/// error must not be reported as a hardware fault the user goes on to debug.
pub(crate) fn audit_wave(
    entropy: &[[u8; 16]],
    seeds: &[[u8; 64]],
    indices: &[usize],
) -> Result<(), GpuDisableReason> {
    for &i in indices {
        if i >= entropy.len() || i >= seeds.len() {
            return Err(GpuDisableReason::BadConfig(format!(
                "audit index {i} is out of range for a wave of {} candidates",
                entropy.len().min(seeds.len())
            )));
        }
        let m =
            bip39::Mnemonic::from_entropy(&entropy[i], bip39::Language::English).map_err(|e| {
                GpuDisableReason::BadConfig(format!(
                    "audit index {i}: 16-byte entropy must always be valid BIP-39, got {e}"
                ))
            })?;
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

/// Carve a finished wave into `seeds.len() / BLOCK` blocks and hand them to the
/// workers. Returns `false` when the wave loop must stop: the producer's stop
/// flag, a self-disable, or the receiver side hanging up.
///
/// The `zip` below is the ONE place entropy and seeds meet. Nothing downstream
/// may reorder, filter or sort — see `SeedBlock::with_capacity`.
///
/// Backpressure is a 100 ms `send_timeout` RETRY, never a drop. A full queue
/// means the CPU workers are the binding constraint, and self-throttling to
/// exactly the rate they can absorb is the correct response; `blocks_dropped`
/// therefore stays 0 by construction. `send` is never called bare and never
/// unwrapped: a `Disconnected` is a clean exit, not a panic on a background
/// thread writing a backtrace across the Ratatui frame.
pub(crate) fn carve_and_send(
    tx: &Sender<Box<SeedBlock>>,
    entropy: &[[u8; 16]],
    seeds: &[[u8; 64]],
    stop: &AtomicBool,
    health: &GpuHealth,
) -> bool {
    debug_assert_eq!(entropy.len(), seeds.len());
    for (e_chunk, s_chunk) in entropy.chunks_exact(BLOCK).zip(seeds.chunks_exact(BLOCK)) {
        let mut block = Box::new(SeedBlock::with_capacity(BLOCK));
        for (e, s) in e_chunk.iter().zip(s_chunk.iter()) {
            block.push(GpuCandidate {
                entropy: *e,
                seed: *s,
            });
        }
        let mut pending = Some(block);
        while let Some(b) = pending.take() {
            if stop.load(Ordering::Relaxed) || health.disable.load(Ordering::Relaxed) {
                drop(b);
                return false;
            }
            match tx.send_timeout(b, Duration::from_millis(100)) {
                Ok(()) => {}
                Err(SendTimeoutError::Timeout(b)) => pending = Some(b),
                Err(SendTimeoutError::Disconnected(b)) => {
                    drop(b);
                    return false;
                }
            }
        }
    }
    true
}

/// Raise the calling thread to `QOS_CLASS_USER_INITIATED`.
///
/// Without this macOS may schedule the producer on an E-core, where the ~4.1 ms
/// of per-wave phrase generation and packing stretches proportionally and the
/// GPU starves waiting for its next wave of keys. Returns 0 on success, else an
/// errno — the caller ignores it, because a demoted producer is slow, not wrong.
///
/// `QOS_CLASS_USER_INITIATED = 0x19` and the signature
/// `int pthread_set_qos_class_self_np(qos_class_t, int)` are from
/// `<sys/qos.h>` and `<pthread/qos.h>`; `qos_class_t` is an `unsigned int` enum.
#[cfg(target_os = "macos")]
pub(crate) fn set_thread_qos_user_initiated() -> i32 {
    const QOS_CLASS_USER_INITIATED: u32 = 0x19;
    extern "C" {
        fn pthread_set_qos_class_self_np(qos_class: u32, relative_priority: i32) -> i32;
    }
    // SAFETY: a libSystem call taking two scalars, valid on any thread, with no
    // pointer arguments and no ownership transfer.
    unsafe { pthread_set_qos_class_self_np(QOS_CLASS_USER_INITIATED, 0) }
}

/// No QoS classes off macOS; the producer runs at the default priority.
#[cfg(not(target_os = "macos"))]
pub(crate) fn set_thread_qos_user_initiated() -> i32 {
    0
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
        // An out-of-range index can only come from a caller bug -
        // `audit_indices` never draws outside `0..wave` - so this must be
        // reported as `BadConfig`, not `AuditMismatch`: a real device fault
        // and a programming error must not share a reason, or the reason
        // stops telling anyone what to go debug.
        let (entropy, seeds) = honest_wave(8);
        match audit_wave(&entropy, &seeds, &[9]) {
            Err(GpuDisableReason::BadConfig(m)) => {
                assert!(
                    m.contains('9'),
                    "message must name the bad index, got {m:?}"
                );
                assert!(
                    m.contains('8'),
                    "message must name the wave length, got {m:?}"
                );
            }
            other => panic!("expected BadConfig, got {other:?}"),
        }
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

    /// A fresh, clean health cell. `GpuHealth`'s `reason` field is private to
    /// `crate::gpu`, and this module is a descendant of it, so the literal is
    /// legal here and needs no constructor on the type itself.
    fn fresh_health() -> GpuHealth {
        GpuHealth {
            disable: std::sync::atomic::AtomicBool::new(false),
            reason: std::sync::OnceLock::new(),
            seeds_delivered: std::sync::atomic::AtomicU64::new(0),
            blocks_dropped: std::sync::atomic::AtomicU64::new(0),
            verify_rejections: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// `n` candidates whose entropy and seed both encode their index, so a
    /// re-ordering or a mis-pairing anywhere in the carve is detectable.
    fn marked_wave(n: usize) -> (Vec<[u8; 16]>, Vec<[u8; 64]>) {
        let mut entropy = vec![[0u8; 16]; n];
        let mut seeds = vec![[0u8; 64]; n];
        for i in 0..n {
            entropy[i][..8].copy_from_slice(&(i as u64).to_be_bytes());
            seeds[i][..8].copy_from_slice(&(i as u64).to_be_bytes());
            seeds[i][56..].copy_from_slice(&(i as u64).to_be_bytes());
        }
        (entropy, seeds)
    }

    #[test]
    fn carve_and_send_delivers_sixteen_blocks_of_512_in_pairing_order() {
        let (tx, rx) = crossbeam_channel::bounded(super::super::CHANNEL_CAPACITY);
        let stop = AtomicBool::new(false);
        let health = fresh_health();
        let (entropy, seeds) = marked_wave(8_192);

        assert!(carve_and_send(&tx, &entropy, &seeds, &stop, &health));

        for c in 0..16 {
            let block = rx
                .try_recv()
                .unwrap_or_else(|e| panic!("block {c} missing: {e}"));
            assert_eq!(block.len(), BLOCK, "block {c} is not {BLOCK} candidates");
            let cands = block.chunks(BLOCK).next().expect("one full chunk");
            for (j, cand) in cands.iter().enumerate() {
                let want = (c * BLOCK + j) as u64;
                assert_eq!(
                    u64::from_be_bytes(cand.entropy[..8].try_into().unwrap()),
                    want,
                    "block {c} slot {j}: entropy out of order"
                );
                assert_eq!(
                    u64::from_be_bytes(cand.seed[..8].try_into().unwrap()),
                    want,
                    "block {c} slot {j}: seed paired with the wrong entropy"
                );
            }
        }
        assert!(rx.try_recv().is_err(), "exactly 16 blocks, no more");
    }

    #[test]
    fn carve_and_send_reports_false_when_the_receiver_hung_up() {
        let (tx, rx) = crossbeam_channel::bounded::<Box<SeedBlock>>(super::super::CHANNEL_CAPACITY);
        drop(rx);
        let stop = AtomicBool::new(false);
        let health = fresh_health();
        let (entropy, seeds) = marked_wave(8_192);

        let started = std::time::Instant::now();
        assert!(!carve_and_send(&tx, &entropy, &seeds, &stop, &health));
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "Disconnected must be immediate, took {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn carve_and_send_retries_under_backpressure_and_exits_on_stop() {
        // Capacity 2 and nobody draining: the third block hits the 100 ms
        // timeout branch and must be RETRIED, never dropped.
        let (tx, _rx) = crossbeam_channel::bounded(2);
        let stop = AtomicBool::new(false);
        let health = fresh_health();
        let (entropy, seeds) = marked_wave(8_192);

        let started = std::time::Instant::now();
        let finished = std::thread::scope(|s| {
            s.spawn(|| {
                std::thread::sleep(Duration::from_millis(300));
                stop.store(true, Ordering::Relaxed);
            });
            carve_and_send(&tx, &entropy, &seeds, &stop, &health)
        });

        assert!(!finished, "must report stop");
        assert!(
            started.elapsed() >= Duration::from_millis(300),
            "must have blocked, not dropped"
        );
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "must notice stop within one timeout, took {:?}",
            started.elapsed()
        );
        assert_eq!(
            health.blocks_dropped.load(Ordering::Relaxed),
            0,
            "backpressure throttles, it never discards"
        );
    }

    #[test]
    fn carve_and_send_exits_immediately_when_health_is_already_disabled() {
        let (tx, rx) = crossbeam_channel::bounded(super::super::CHANNEL_CAPACITY);
        let stop = AtomicBool::new(false);
        let health = fresh_health();
        health.raise(GpuDisableReason::AuditMismatch { index: 5_183 });
        let (entropy, seeds) = marked_wave(8_192);

        let started = std::time::Instant::now();
        assert!(!carve_and_send(&tx, &entropy, &seeds, &stop, &health));
        assert!(
            rx.try_recv().is_err(),
            "a disabled GPU must deliver nothing"
        );
        assert!(started.elapsed() < std::time::Duration::from_millis(500));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn qos_call_promotes_the_calling_thread_to_user_initiated() {
        // On a fresh thread so the harness thread's QoS is not mutated under
        // the other tests running in parallel.
        let class = std::thread::spawn(|| {
            assert_eq!(
                set_thread_qos_user_initiated(),
                0,
                "pthread_set_qos_class_self_np returned a non-zero errno"
            );
            extern "C" {
                fn pthread_self() -> *mut core::ffi::c_void;
                fn pthread_get_qos_class_np(
                    thread: *mut core::ffi::c_void,
                    qos_class: *mut u32,
                    relative_priority: *mut i32,
                ) -> i32;
            }
            let mut class: u32 = 0;
            let mut rel: i32 = 0;
            // SAFETY: both pointers are valid, non-null, and correctly typed
            // (`qos_class_t` is an `unsigned int` enum, `pthread_t` a pointer).
            let rc = unsafe { pthread_get_qos_class_np(pthread_self(), &mut class, &mut rel) };
            assert_eq!(rc, 0, "pthread_get_qos_class_np returned {rc}");
            class
        })
        .join()
        .expect("probe thread panicked");

        assert_eq!(
            class, 0x19,
            "expected QOS_CLASS_USER_INITIATED (0x19), got {class:#x}"
        );
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn qos_call_is_an_infallible_no_op_off_macos() {
        assert_eq!(set_thread_qos_user_initiated(), 0);
    }
}
