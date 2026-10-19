//! The GPU producer thread: fill -> dispatch -> audit -> carve -> send.
//!
//! Everything in this file that does not name a Metal type is compiled on every
//! target, so the fault plumbing, the `ring` audit, the block carving and the
//! panic guard are unit-tested on Linux and under `--no-default-features` too.
//! Only `producer()` itself is `cfg`-gated.
//!
//! `producer()` is the only production caller of everything else here, so on
//! the stub leg the whole file is dead outside its tests.
#![cfg_attr(
    not(all(target_os = "macos", target_arch = "aarch64", feature = "metal")),
    allow(dead_code)
)]

use super::{
    GpuCandidate, GpuDisableReason, GpuHealth, GpuStatus, SeedBlock, AUDITS_PER_WAVE, BLOCK,
};
use crossbeam_channel::{SendTimeoutError, Sender};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

/// Poison-immune write. The UI thread reads this cell every 100 ms; a worker
/// that panicked while holding the lock must not make the GPU status
/// permanently unreadable, so a poisoned lock is recovered, never unwrapped.
pub(crate) fn set_status(cell: &Mutex<GpuStatus>, next: GpuStatus) {
    *cell.lock().unwrap_or_else(PoisonError::into_inner) = next;
}

/// Poison-immune read. Same reasoning as `set_status`.
pub(crate) fn read_status(cell: &Mutex<GpuStatus>) -> GpuStatus {
    cell.lock().unwrap_or_else(PoisonError::into_inner).clone()
}

/// Re-derive `indices` of a finished wave with `ring` and compare.
///
/// A wrong GPU seed cannot reach the CSV — the `verify_gpu` gate stops that
/// — but it can silently waste the search: the counter climbs while up to ~55%
/// of it is noise. This is the only detector for that, so a disagreement is a
/// hard, sticky fault, never a retry.
///
/// `ring` is the reference because `crate::seed::derive_seed` (src/seed.rs:8)
/// is what every pinned vector in CLAUDE.md already pins.
///
/// `indices` come from `audit_indices`, which only draws `0..wave`, and 16
/// bytes is always valid 12-word entropy, so a bad index or entropy is a caller
/// bug: it panics, and `run_guarded` turns that into `Panicked`.
pub(crate) fn audit_wave(
    entropy: &[[u8; 16]],
    seeds: &[[u8; 64]],
    indices: &[usize],
) -> Result<(), GpuDisableReason> {
    for &i in indices {
        let m = bip39::Mnemonic::from_entropy(&entropy[i], bip39::Language::English)
            .expect("16 bytes is always valid 12-word BIP-39 entropy");
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
/// exactly the rate they can absorb is the correct response. `send` is never
/// called bare and never unwrapped: a `Disconnected` is a clean exit, not a
/// panic on a background thread writing a backtrace across the Ratatui frame.
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
        loop {
            if stop.load(Ordering::Relaxed) || health.disable.load(Ordering::Relaxed) {
                return false;
            }
            match tx.send_timeout(block, Duration::from_millis(100)) {
                Ok(()) => break,
                Err(SendTimeoutError::Timeout(b)) => block = b,
                Err(SendTimeoutError::Disconnected(_)) => return false,
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
#[cfg(all(target_os = "macos", target_arch = "aarch64", feature = "metal"))]
pub(crate) fn set_thread_qos_user_initiated() -> i32 {
    const QOS_CLASS_USER_INITIATED: u32 = 0x19;
    extern "C" {
        fn pthread_set_qos_class_self_np(qos_class: u32, relative_priority: i32) -> i32;
    }
    // SAFETY: a libSystem call taking two scalars, valid on any thread, with no
    // pointer arguments and no ownership transfer.
    unsafe { pthread_set_qos_class_self_np(QOS_CLASS_USER_INITIATED, 0) }
}

/// Sets `finished` on every exit path — clean return, `?` bail, or unwind.
///
/// `stop_search` must never join the GPU thread (a wedged `waitUntilCompleted`
/// would hang the UI thread forever with the terminal in raw mode), so the app
/// reaps by polling `is_finished()`. A flag set only at the end of a function
/// would strand a panicked engine as un-reapable forever.
struct FinishGuard(Arc<AtomicBool>);

impl Drop for FinishGuard {
    fn drop(&mut self) {
        // Release: pairs with the Acquire in `GpuEngine::is_finished`, so a UI
        // thread that observes `finished` is guaranteed to observe the fault
        // `run_guarded` raised into `health` just before this store.
        self.0.store(true, Ordering::Release);
    }
}

/// The GPU thread body wrapper.
///
/// A Rust unwind becomes `GpuDisableReason::Panicked` in `health` rather than a
/// backtrace printed across the Ratatui frame in raw mode. `catch_unwind`
/// catches Rust unwinds ONLY — an Objective-C exception is uncatchable and
/// aborts the process, which is exactly why the backend never calls
/// `setMathMode` and clamps the threadgroup size to the pipeline's own
/// `maxTotalThreadsPerThreadgroup`.
///
/// `AssertUnwindSafe` is correct here rather than lazy: nothing the body
/// touches is read again after it unwinds. `health` is atomics plus a set-once
/// `OnceLock`, the channel `Sender` is dropped with the body, and the Metal
/// objects are created inside the body and die with it.
pub(crate) fn run_guarded<F>(health: &GpuHealth, finished: Arc<AtomicBool>, body: F)
where
    F: FnOnce() -> Result<(), GpuDisableReason>,
{
    let _guard = FinishGuard(finished);
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(body)) {
        Ok(Ok(())) => {}
        Ok(Err(reason)) => health.raise(reason),
        Err(_) => health.raise(GpuDisableReason::Panicked),
    }
    // `_guard` drops HERE, after `raise`. Do not reorder.
}

/// The wave loop. Runs on the `vanaddy-gpu` thread and owns every Metal object
/// in the process — nothing Metal-shaped ever crosses a thread boundary, which
/// `objc2`'s `Send`/`Sync` bounds enforce at compile time.
///
/// `tx` is taken BY VALUE: dropping it on return hangs up the channel, which is
/// the second, independent wake path for the workers alongside the stop flag.
#[cfg(all(target_os = "macos", target_arch = "aarch64", feature = "metal"))]
pub(crate) fn producer(
    tx: Sender<Box<SeedBlock>>,
    stop: &AtomicBool,
    health: &GpuHealth,
    status: &Mutex<GpuStatus>,
) -> Result<(), GpuDisableReason> {
    use super::backend::MetalPbkdf2;
    use super::pack::{pack_key_block, KeyBlock, BIP39_SALT_BLOCK};
    use super::{selftest, Schedule, WAVE};
    use bip39::{Language, Mnemonic, MnemonicType};
    use zeroize::Zeroizing;

    // QoS so macOS does not demote this thread to an E-core, where the ~4.1 ms
    // of per-wave phrase generation and packing stretches proportionally and
    // the GPU starves waiting for keys. Slow, not wrong — so the result is
    // deliberately ignored.
    let _ = set_thread_qos_user_initiated();

    // Device, library compile (~60-95 ms cold) and pipelines, all HERE, on this
    // thread, never the UI thread.
    let mut engine = MetalPbkdf2::new().map_err(GpuDisableReason::Backend)?;
    if stop.load(Ordering::Relaxed) {
        return Ok(());
    }

    // ~300 ms: 154 ms of GPU plus 133 ms of `ring`. Nothing is published to the
    // workers until it passes.
    //
    // `stop` is threaded IN, not just checked around the call: the spec's
    // termination table requires the flag to be observed between the
    // self-test's phases, and a `signal_stop()` during startup must not go
    // unseen for the whole ~300 ms. The schedule is threaded THROUGH, not
    // dropped: `self_test`'s chunk-schedule invariance check — the property the
    // entire resumable-wave design rests on — passes vacuously if every call it
    // makes runs the production schedule.
    selftest::self_test(stop, |phrases, iters, schedule| {
        engine.derive_with_schedule(phrases, iters, schedule)
    })
    .map_err(GpuDisableReason::SelfTest)?;
    if stop.load(Ordering::Relaxed) {
        return Ok(());
    }
    set_status(
        status,
        GpuStatus::Running {
            device: engine.device_name(),
        },
    );

    // 8192 x 16 B of raw entropy - the most valuable object in the process.
    // Zeroizing, and overwritten in place every wave, so the resident backlog
    // is one wave (~600 ms) rather than the whole run.
    let mut entropy: Zeroizing<Vec<[u8; 16]>> = Zeroizing::new(vec![[0u8; 16]; WAVE]);
    let mut keys: Zeroizing<Vec<KeyBlock>> = Zeroizing::new(vec![KeyBlock([0u64; 16]); WAVE]);
    let mut rng = rand::thread_rng();

    while !stop.load(Ordering::Relaxed) && !health.disable.load(Ordering::Relaxed) {
        // 1. Fill. Measured: Mnemonic::new 0.527 us + pack 0.495 us -> ~4.1 ms
        //    per ~600 ms wave = 0.7% of one core. ONE thread is ample; NO Rayon
        //    par_iter, which would put these allocations on the very threads
        //    whose PBKDF2 is the CPU-side throughput.
        //    `Mnemonic::new` is the SAME entropy source the CPU path uses at
        //    src/chains/evm.rs:59 — thread-local, OS-seeded ChaCha12. Nothing
        //    counter-derived may ever appear here.
        for (i, (e, k)) in entropy.iter_mut().zip(keys.iter_mut()).enumerate() {
            if i % 512 == 0 && stop.load(Ordering::Relaxed) {
                return Ok(());
            }
            let m = Mnemonic::new(MnemonicType::Words12, Language::English);
            e.copy_from_slice(m.entropy());
            *k = pack_key_block(m.phrase().as_bytes());
        }

        // 2-3. Dispatch the wave. `Ok(None)` means the backend saw `stop` at a
        //      command-buffer boundary and abandoned it; there is deliberately
        //      no partial-success shape, because a partly-iterated wave yields
        //      wrong-but-plausible seeds.
        let seeds = match engine
            .run_wave(
                &keys,
                &BIP39_SALT_BLOCK,
                crate::seed::PBKDF2_ROUNDS,
                Schedule::Production,
                stop,
            )
            .map_err(GpuDisableReason::Backend)?
        {
            Some(seeds) => seeds,
            None => return Ok(()),
        };

        // 4. Audit AUDITS_PER_WAVE RANDOM indices against `ring`.
        audit_wave(&entropy, seeds, &audit_indices(&mut rng, WAVE))?;

        // 5. Carve + send. `false` == stop, self-disable, or hang-up.
        if !carve_and_send(&tx, &entropy, seeds, stop, health) {
            return Ok(());
        }

        // 6. The backend wipes keys/states/seeds; `entropy` and `keys` are
        //    overwritten by the next fill and zeroized on drop, so the last
        //    wave's plaintext dies with this function.
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::gpu::GpuError;

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

    /// Accepts honest `ring` seeds, rejects one flipped bit at a sampled index,
    /// and — the honest statement of the detector's limit — ignores corruption
    /// at an unsampled one: it is probabilistic, and a bug confined to a
    /// handful of tids can survive a wave. This is the reason the indices are
    /// re-drawn every wave rather than fixed.
    #[test]
    fn audit_wave_checks_only_the_sampled_indices() {
        let cases = [
            (None, Ok(())),
            (
                Some((3, 63, 0x01)),
                Err(GpuDisableReason::AuditMismatch { index: 3 }),
            ),
            (Some((6, 0, 0xFF)), Ok(())),
        ];
        for (flip, want) in cases {
            let (entropy, mut seeds) = honest_wave(8);
            if let Some((i, byte, mask)) = flip {
                seeds[i][byte] ^= mask;
            }
            assert_eq!(
                audit_wave(&entropy, &seeds, &[0, 3, 5, 7]),
                want,
                "{flip:?}"
            );
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
        let health = GpuHealth::default();
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
        let health = GpuHealth::default();
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
        let health = GpuHealth::default();
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
    }

    #[test]
    fn carve_and_send_exits_immediately_when_health_is_already_disabled() {
        let (tx, rx) = crossbeam_channel::bounded(super::super::CHANNEL_CAPACITY);
        let stop = AtomicBool::new(false);
        let health = GpuHealth::default();
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

    #[cfg(all(target_os = "macos", target_arch = "aarch64", feature = "metal"))]
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

    /// A clean return, a fault return and an unwind all set `finished` (or
    /// the UI can never reap), and the exact reason — `Panicked` for the
    /// unwind — survives to the UI.
    #[test]
    fn run_guarded_finishes_and_reports_the_exact_reason() {
        type Body = fn() -> Result<(), GpuDisableReason>;
        let cases: [(&str, Body, Option<GpuDisableReason>); 3] = [
            ("clean", || Ok(()), None),
            (
                "fault",
                || Err(GpuDisableReason::AuditMismatch { index: 5_183 }),
                Some(GpuDisableReason::AuditMismatch { index: 5_183 }),
            ),
            (
                "panic",
                || panic!("simulated kernel-side unwrap"),
                Some(GpuDisableReason::Panicked),
            ),
        ];
        let prev_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        for (label, body, want) in cases {
            let health = GpuHealth::default();
            let finished = Arc::new(AtomicBool::new(false));
            run_guarded(&health, finished.clone(), body);
            assert!(
                finished.load(Ordering::Acquire),
                "{label}: finished not set"
            );
            assert_eq!(
                health.disable.load(Ordering::Relaxed),
                want.is_some(),
                "{label}: disable flag"
            );
            assert_eq!(health.take_reason(), want, "{label}: reason");
        }
        std::panic::set_hook(prev_hook);
    }

    #[test]
    fn the_fault_is_visible_to_anyone_who_sees_finished() {
        // The ordering Milestone 6's drain_matches depends on: seeing
        // `finished` implies seeing `disable`, so a fault never looks like an
        // unexplained quiet death. This test polls `finished` directly rather
        // than `.join()`-ing first: `join()` is itself a full synchronisation
        // edge, so it would pass even if `FinishGuard::drop` used `Relaxed` or
        // the store ran before `health.raise` -- moving the store above the
        // `match` in `run_guarded` must turn this test red.
        let health = Arc::new(GpuHealth::default());
        let finished = Arc::new(AtomicBool::new(false));
        let h = health.clone();
        let f = finished.clone();
        let handle = std::thread::spawn(move || {
            run_guarded(&h, f, || {
                Err(GpuDisableReason::Backend(GpuError::BufferAlloc))
            });
        });

        while !finished.load(Ordering::Acquire) {
            std::hint::spin_loop();
        }
        assert!(health.disable.load(Ordering::Relaxed));
        assert_eq!(
            health.take_reason(),
            Some(GpuDisableReason::Backend(GpuError::BufferAlloc))
        );
        handle
            .join()
            .expect("guarded thread must not propagate a panic");
    }
}

#[cfg(all(test, target_os = "macos", target_arch = "aarch64", feature = "metal"))]
mod gpu_tests {
    use super::*;
    use crate::gpu::{BLOCK, CHANNEL_CAPACITY, WAVE};
    use rayon::prelude::*;
    use std::time::{Duration, Instant};

    /// The explicit `VANADDY_NO_GPU=1` skip, loud on stderr.
    fn no_gpu() -> bool {
        let skip = std::env::var_os("VANADDY_NO_GPU").is_some();
        if skip {
            eprintln!("SKIP: VANADDY_NO_GPU is set");
        }
        skip
    }

    /// Consume three full waves and re-derive EVERY seed with `ring`.
    ///
    /// 3 x 8192 = 24,576 candidates. Run with --release: in a debug build the
    /// per-wave fill is slow enough to starve the GPU and the test drags.
    #[test]
    fn producer_delivers_three_waves_whose_every_seed_matches_ring() {
        if no_gpu() {
            return;
        }
        let (tx, rx) = crossbeam_channel::bounded(CHANNEL_CAPACITY);
        let stop = AtomicBool::new(false);
        let health = GpuHealth::default();
        let status = Mutex::new(GpuStatus::Initializing);

        let want = 3 * (WAVE / BLOCK);
        let mut blocks: Vec<Box<SeedBlock>> = Vec::with_capacity(want);

        let no_device = std::thread::scope(|s| {
            let worker = s.spawn(|| producer(tx, &stop, &health, &status));
            let deadline = Instant::now() + Duration::from_secs(180);
            while blocks.len() < want && !worker.is_finished() {
                assert!(
                    Instant::now() < deadline,
                    "only {} of {want} blocks in 180 s (status {:?}, reason {:?})",
                    blocks.len(),
                    read_status(&status),
                    health.take_reason()
                );
                if let Ok(b) = rx.recv_timeout(Duration::from_millis(250)) {
                    blocks.push(b);
                }
            }
            stop.store(true, Ordering::Relaxed);
            let outcome = worker.join().expect("producer must not panic");
            if outcome == Err(GpuDisableReason::Backend(crate::gpu::GpuError::NoDevice)) {
                return true;
            }
            assert_eq!(outcome, Ok(()), "producer returned a fault");
            false
        });
        if no_device {
            eprintln!("SKIP: no Metal device on this machine");
            return;
        }

        assert!(
            matches!(read_status(&status), GpuStatus::Running { .. }),
            "the producer must publish Running once the self-test passes, saw {:?}",
            read_status(&status)
        );
        assert_eq!(health.take_reason(), None, "no fault may have been raised");

        let failures: Vec<String> = blocks
            .par_iter()
            .enumerate()
            .flat_map(|(bi, b)| {
                let cands = b.chunks(BLOCK).next().expect("one full chunk");
                cands
                    .iter()
                    .enumerate()
                    .filter_map(|(ci, c)| {
                        let m = match bip39::Mnemonic::from_entropy(
                            &c.entropy,
                            bip39::Language::English,
                        ) {
                            Ok(m) => m,
                            Err(e) => {
                                return Some(format!("block {bi} cand {ci}: bad entropy: {e}"))
                            }
                        };
                        let want = crate::seed::derive_seed(&m);
                        if want != c.seed {
                            return Some(format!(
                                "block {bi} cand {ci}: phrase {:?}\n  gpu  {}\n  ring {}",
                                m.phrase(),
                                hex::encode(c.seed),
                                hex::encode(want)
                            ));
                        }
                        None
                    })
                    .collect::<Vec<_>>()
            })
            .collect();

        assert!(
            failures.is_empty(),
            "{} of {} GPU seeds disagree with ring:\n{}",
            failures.len(),
            3 * WAVE,
            failures.join("\n")
        );
        for (bi, b) in blocks.iter().enumerate() {
            assert_eq!(b.len(), BLOCK, "block {bi} is not {BLOCK} candidates");
        }
    }

    use crate::gpu::GpuEngine;
    use std::sync::Arc;

    /// Block until the engine reports finished, or fail with a bounded message.
    fn await_finished(engine: &GpuEngine, bound: Duration, what: &str) -> Duration {
        let started = Instant::now();
        while !engine.is_finished() {
            assert!(
                started.elapsed() < bound,
                "{what}: producer still running after {:?} (bound {bound:?})",
                started.elapsed()
            );
            std::thread::sleep(Duration::from_millis(2));
        }
        started.elapsed()
    }

    #[test]
    fn signal_stop_finishes_the_producer_within_200ms() {
        if no_gpu() {
            return;
        }
        let (tx, rx) = crossbeam_channel::bounded(CHANNEL_CAPACITY);
        let health = Arc::new(GpuHealth::default());
        let engine = GpuEngine::start(tx, health.clone());

        // Wait for the first block: that puts the ~95 ms shader compile and the
        // ~300 ms self-test behind us, so the 135 ms steady-state termination
        // bound is the one under test.
        let first = rx
            .recv_timeout(Duration::from_secs(180))
            .expect("no block within 180 s of start");
        drop(first);

        engine.signal_stop();
        let took = await_finished(&engine, Duration::from_millis(200), "signal_stop");
        engine.reap();

        assert!(
            !health.disable.load(Ordering::Relaxed),
            "a clean stop must not disable the GPU"
        );
        assert_eq!(health.take_reason(), None);
        eprintln!("signal_stop -> finished in {took:?}");
    }

    #[test]
    fn dropping_the_receiver_exits_the_producer_cleanly() {
        if no_gpu() {
            return;
        }
        let (tx, rx) = crossbeam_channel::bounded(CHANNEL_CAPACITY);
        let health = Arc::new(GpuHealth::default());
        let engine = GpuEngine::start(tx, health.clone());

        let first = rx
            .recv_timeout(Duration::from_secs(180))
            .expect("no block within 180 s of start");
        drop(first);

        // Hang up WITHOUT ever setting the stop flag: `Disconnected` is the
        // second, independent wake path, and losing either must not hang.
        drop(rx);

        // Up to one full wave (~600 ms) may already be in flight before the
        // producer next touches the channel.
        await_finished(&engine, Duration::from_secs(5), "receiver drop");
        engine.reap();

        assert!(
            !health.disable.load(Ordering::Relaxed),
            "a clean hang-up is not a fault: the CPU search may simply have stopped"
        );
        assert_eq!(health.take_reason(), None, "no panic, no fault");
    }

    #[test]
    fn status_reports_disabled_once_health_carries_a_reason() {
        if no_gpu() {
            return;
        }
        let (tx, rx) = crossbeam_channel::bounded(CHANNEL_CAPACITY);
        let health = Arc::new(GpuHealth::default());
        let engine = GpuEngine::start(tx, health.clone());

        let first = rx
            .recv_timeout(Duration::from_secs(180))
            .expect("no block within 180 s of start");
        drop(first);
        assert!(matches!(engine.status(), GpuStatus::Running { .. }));

        health.raise(GpuDisableReason::AuditMismatch { index: 5_183 });
        assert_eq!(
            engine.status(),
            GpuStatus::Disabled(GpuDisableReason::AuditMismatch { index: 5_183 }),
            "a raised fault must win over the last published status"
        );

        engine.signal_stop();
        await_finished(&engine, Duration::from_secs(5), "post-fault stop");
        engine.reap();
    }

    /// MEASUREMENT, not a gate. Run it under CPU load (Task 4.8 Step 4) when
    /// the kernel, the wave geometry or the machine changes, then run Step 5
    /// to fold the result into `EVM_GPU_SEEDS_PER_SEC`:
    ///
    ///   cargo test --release gpu_seed_rate_end_to_end -- --ignored --nocapture
    ///
    /// Three independent 10 s windows, not one 30 s window: a single sample
    /// cannot tell "this machine does 13,800/s" from "this machine got one
    /// lucky window". The floor (3,000 seeds/s) is the observed
    /// compositor-contention floor, not the target: below it means something
    /// is broken; a spread above 15% between the three windows means the run
    /// was not clean (compositor busy, thermal throttling) and must be
    /// re-run with the display otherwise quiescent. This test never edits the
    /// constant itself.
    #[test]
    #[ignore = "measurement; run with --release --nocapture, see Task 4.8 Step 4"]
    fn gpu_seed_rate_end_to_end() {
        if no_gpu() {
            return;
        }
        let (tx, rx) = crossbeam_channel::bounded(CHANNEL_CAPACITY);
        let health = Arc::new(GpuHealth::default());
        let engine = GpuEngine::start(tx, health.clone());

        // Discard the first block: it hides the ~95 ms shader compile and the
        // ~300 ms self-test, which are startup cost, not steady-state rate.
        let first = match rx.recv_timeout(Duration::from_secs(180)) {
            Ok(b) => b,
            Err(e) => {
                if engine.status()
                    == GpuStatus::Disabled(GpuDisableReason::Backend(
                        crate::gpu::GpuError::NoDevice,
                    ))
                {
                    eprintln!("SKIP: no Metal device on this machine");
                    engine.signal_stop();
                    await_finished(&engine, Duration::from_secs(5), "no-device skip");
                    engine.reap();
                    return;
                }
                panic!("no block within 180 s of start: {e}");
            }
        };
        drop(first);

        let mut rates = Vec::with_capacity(3);
        for window_ix in 0..3 {
            let window = Duration::from_secs(10);
            let started = Instant::now();
            let mut blocks = 0u64;
            while started.elapsed() < window {
                if rx.recv_timeout(Duration::from_millis(500)).is_ok() {
                    blocks += 1;
                }
            }
            let secs = started.elapsed().as_secs_f64();
            let rate = (blocks as f64) * (BLOCK as f64) / secs;
            eprintln!(
                "window {window_ix}: {rate:.0} seeds/s ({blocks} blocks x {BLOCK} over {secs:.1}s)"
            );
            rates.push(rate);
        }

        engine.signal_stop();
        await_finished(&engine, Duration::from_secs(5), "measurement stop");
        engine.reap();

        let min = rates.iter().cloned().fold(f64::INFINITY, f64::min);
        let max = rates.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
        let mean = rates.iter().sum::<f64>() / rates.len() as f64;
        let spread = (max - min) / mean;
        eprintln!(
            "\nEVM_GPU_SEEDS_PER_SEC measured: {mean:.0} seeds/s (mean of 3 x 10s windows, \
             spread {:.1}%)\ncurrent constant: {:.0}\n",
            spread * 100.0,
            crate::gpu::EVM_GPU_SEEDS_PER_SEC
        );
        assert!(
            min > 3_000.0,
            "delivered rate {min:.0}/s is below the compositor-contention floor; \
             something is wrong with the pipeline, not just busy"
        );
        assert!(
            spread < 0.15,
            "run-to-run spread {:.1}% exceeds 15% -- the display was not quiescent \
             or the machine was thermally throttling; re-run",
            spread * 100.0
        );
        assert_eq!(
            health.take_reason(),
            None,
            "no fault during the measurement"
        );
    }
}
