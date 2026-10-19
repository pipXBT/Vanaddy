//! GPU offload of BIP-39 PBKDF2-HMAC-SHA512 (c = 2048, salt "mnemonic", dkLen = 64).
//! Apple Silicon + Metal only; every other target builds `stub.rs`.
//! The GPU is a *seed accelerator*: never a source of entropy, never a source of
//! truth. Every GPU-sourced match is re-derived with `ring` before it can exist.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::OnceLock;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub mod kernel_src;
pub mod pack;
pub mod selftest;

pub use selftest::SelfTestError;

#[cfg_attr(
    all(target_os = "macos", target_arch = "aarch64", feature = "metal"),
    path = "metal.rs"
)]
#[cfg_attr(
    not(all(target_os = "macos", target_arch = "aarch64", feature = "metal")),
    path = "stub.rs"
)]
pub(crate) mod backend;
pub(crate) mod producer;

pub use backend::probe;
pub use backend::GpuEngine;

pub const WAVE: usize = 8_192; // candidates per GPU wave
pub const BLOCK: usize = 512; // candidates per channel message (16/wave)
pub const CHANNEL_CAPACITY: usize = 32; // 2 waves of blocks
pub const ITERS_PER_DISPATCH: u32 = 8; // 2047 = 255*8 + 7 -> 256 dispatches
pub const DISPATCHES_PER_COMMAND_BUFFER: usize = 4; // -> 8.8 ms per command buffer
pub const PIPELINE_DEPTH: usize = 3; // command buffers in flight, within a wave
pub const MAX_THREADS_PER_THREADGROUP: usize = 256; // 384 measured 13% SLOWER on M1
pub const AUDITS_PER_WAVE: usize = 4; // RANDOM indices, not a fixed stride

// The producer carves a wave into whole blocks, the channel holds exactly two
// waves of them, and a block tiles the threadgroup clamp exactly.
const _: () = assert!(WAVE.is_multiple_of(BLOCK));
const _: () = assert!(CHANNEL_CAPACITY == 2 * (WAVE / BLOCK));
const _: () = assert!(BLOCK.is_multiple_of(MAX_THREADS_PER_THREADGROUP));
const _: () = assert!(AUDITS_PER_WAVE < WAVE);
// U_1 comes from the prologue, so PBKDF2_ROUNDS - 1 follow-up iterations
// remain; they must cut into a whole number of command buffers.
const _: () = assert!(
    ((crate::seed::PBKDF2_ROUNDS - 1).div_ceil(ITERS_PER_DISPATCH) as usize)
        .is_multiple_of(DISPATCHES_PER_COMMAND_BUFFER)
);

/// Measured end-to-end delivery rate: seeds handed to the workers per
/// wall-second, under CPU load — NOT the idle solo kernel peak (14,768/s).
/// Measured on Apple M1, 2026-08-31, under an 8-thread CPU search with the
/// display otherwise quiescent (see /tmp/vanaddy-rate/measured.txt and Task
/// 4.8 Step 4). The measured rate (14,276/s) was within 5% of this constant,
/// so the value is unchanged from its provisional carry-over — only this
/// comment's provenance is new.
///
/// `App::estimated_rate` uses this for the PRE-search ETA only; once a search
/// is running the ETA switches to the live counter, which is automatically
/// correct because GPU candidates increment the same counter. The displayed
/// GPU rate in the stats pane must likewise be measured per wave, never
/// modelled from this: mid-run collapse to 3,000-7,000 seeds/s under compositor
/// load is reproducible, and a modelled rate would lie by up to 4x.
///
/// On Apple Silicon other than the machine above this is an ESTIMATE, not a
/// measurement: the PRE-search ETA will be wrong until re-measured on that
/// device (spec risk 7).
///
/// Re-measure with:
///   cargo test --release gpu_seed_rate_end_to_end -- --ignored --nocapture
pub const EVM_GPU_SEEDS_PER_SEC: f64 = 13_600.0;

/// Every way the GPU backend can fail. One shape for all of them, because
/// there is exactly one response: raise it as a sticky `GpuDisableReason`,
/// drop the wave, and let the CPU search continue at full CPU-only rate.
/// There is deliberately no partial-success variant.
#[derive(Debug, Clone, PartialEq)]
pub enum GpuError {
    /// `MTLCreateSystemDefaultDevice()` returned nil.
    NoDevice,
    /// `newLibraryWithSource:` failed; carries the Metal compiler diagnostic.
    ShaderCompile(String),
    /// A kernel function was missing, or pipeline creation failed.
    PipelineCreate(String),
    /// A queue, command buffer, encoder, or `MTLBuffer` allocation returned nil.
    BufferAlloc,
    /// The host asked the backend for something it will not do.
    BadConfig(String),
    /// A command buffer finished as anything other than Completed-with-nil-error.
    CommandBuffer { status: i64, message: String },
}

/// A command buffer is acceptable **only** when it reports Completed (status 4)
/// AND its `error()` is nil. Anything else discards the whole wave.
///
/// Split out as a pure function so this rule is tested on every platform, not
/// only on a machine with a GPU. Without it, a mid-wave GPU reset — macOS
/// resets a hung GPU after ~5 s and `waitUntilCompleted` returns rather than
/// hanging — silently drops 8 of 2048 U-iterations, and finalize writes a `T`
/// that is the XOR of only 2,039 values: a wrong-but-plausible seed with
/// nothing surfaced anywhere.
pub fn classify_command_buffer_status(
    status: i64,
    message: Option<String>,
) -> Result<(), GpuError> {
    const COMPLETED: i64 = 4;
    if status == COMPLETED && message.is_none() {
        return Ok(());
    }
    Err(GpuError::CommandBuffer {
        status,
        message: message.unwrap_or_else(|| format!("command buffer finished with status {status}")),
    })
}

impl GpuError {
    /// Bare variant name, for the TUI's narrow GPU columns.
    pub fn label(&self) -> &'static str {
        match self {
            GpuError::NoDevice => "NoDevice",
            GpuError::ShaderCompile(_) => "ShaderCompile",
            GpuError::PipelineCreate(_) => "PipelineCreate",
            GpuError::BufferAlloc => "BufferAlloc",
            GpuError::BadConfig(_) => "BadConfig",
            GpuError::CommandBuffer { .. } => "CommandBuffer",
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum GpuStatus {
    /// not aarch64-macos, no device, or --no-default-features
    Unavailable(String),
    /// `probe()` succeeded: a device exists, but no GPU thread has been started
    /// yet. This is the pre-search resting state and the one `gpu_effective()`
    /// checks before `start_search` spawns the producer.
    Ready {
        device: String,
    },
    /// thread spawned; compiling + self-testing
    Initializing,
    Running {
        device: String,
    },
    /// sticky for the process
    Disabled(GpuDisableReason),
}

#[derive(Clone, Debug, PartialEq)]
pub enum GpuDisableReason {
    NotSupported,
    UserOff,
    /// Any backend failure: device, compile, pipeline, allocation, config, or
    /// a command buffer that did not finish Completed-with-nil-error.
    Backend(GpuError),
    SelfTest(SelfTestError),
    /// The in-wave random ring audit disagreed.
    AuditMismatch {
        index: usize,
    },
    /// A GPU-sourced candidate that MATCHED failed the verify gate.
    VerifyMismatch {
        address: String,
    },
    Panicked,
}

/// One GPU-produced candidate. POD + Copy: no allocation on the hot path.
/// `entropy`, not the phrase - the worker rebuilds the phrase itself with
/// `Mnemonic::from_entropy`, so the String written to the CSV is always
/// produced by trusted CPU code.
#[derive(Clone, Copy, Zeroize)]
pub struct GpuCandidate {
    pub entropy: [u8; 16],
    /// UNTRUSTED until re-derived. Used only to *filter*.
    pub seed: [u8; 64],
}

/// A run of candidates handed to one Rayon worker. Deliberately NO mutating API
/// beyond `push` during construction: phrase <-> seed pairing is established by
/// exactly one zip in the producer and must never be re-ordered, filtered or
/// sorted afterwards.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SeedBlock(Vec<GpuCandidate>);

impl SeedBlock {
    /// Build-then-freeze: the ONLY way a block gains candidates. Producer and
    /// tests only, hence `pub(crate)` - this is the visibility every downstream
    /// milestone consumes, so it is fixed here and never re-declared. There is
    /// deliberately no `remove`, `sort`, `retain` or `iter_mut`: the entropy
    /// <-> seed pairing established by the single `zip` in the producer must
    /// never be re-ordered afterwards.
    pub(crate) fn with_capacity(n: usize) -> Self {
        SeedBlock(Vec::with_capacity(n))
    }
    pub(crate) fn push(&mut self, candidate: GpuCandidate) {
        assert!(
            self.0.len() < self.0.capacity(),
            "SeedBlock::push would reallocate: the old buffer holds live seed material and \
             is freed without zeroizing. Blocks are built with with_capacity(BLOCK) and must \
             receive at most BLOCK candidates."
        );
        self.0.push(candidate);
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    pub fn chunks(&self, n: usize) -> std::slice::Chunks<'_, GpuCandidate> {
        self.0.chunks(n)
    }
}

pub type GpuRx = crossbeam_channel::Receiver<Box<SeedBlock>>;

/// Shared, lock-free-on-the-read-path health cell. Never a `Mutex` on the UI
/// path: `drain_matches` reads this from the render loop every 100 ms, and a
/// worker that panicked while holding a `Mutex` would poison it and turn a GPU
/// fault into a UI-thread `unwrap` panic inside raw mode.
#[derive(Default)]
pub struct GpuHealth {
    pub disable: AtomicBool,
    /// Set-once, so the FIRST fault is the one reported. A later, derivative
    /// failure (the producer noticing `disable` and exiting) must not overwrite
    /// the root cause. `OnceLock` also cannot be poisoned.
    reason: OnceLock<GpuDisableReason>,
    pub seeds_delivered: AtomicU64,
}

impl GpuHealth {
    /// Publish the reason BEFORE flipping the flag. Callers elsewhere may keep
    /// loading `disable` `Relaxed` (19+ producer/worker sites only care whether
    /// to keep draining, never touch the reason) - the ordering this needs is
    /// established on the READ side, in `take_reason`'s own internal `Acquire`
    /// load, not here. See that function's doc comment for why that's enough.
    pub fn raise(&self, r: GpuDisableReason) {
        let _ = self.reason.set(r);
        self.disable.store(true, Ordering::Release);
    }

    /// Clones; does NOT consume. Never unwraps a lock. Named `take_reason` per
    /// the design spec even though it leaves the reason in place - the UI reads
    /// it on every 100 ms tick.
    pub fn take_reason(&self) -> Option<GpuDisableReason> {
        // Acquire, paired with `raise`'s Release store of `disable`. Atomic
        // coherence means a thread that has already observed `disable == true`
        // by ANY load - including a Relaxed one elsewhere - also observes
        // `true` here, so this load synchronises-with `raise` and the reason
        // set before that store is guaranteed visible. This is why callers may
        // keep loading `disable` Relaxed: the ordering is established on this
        // side.
        let _ = self.disable.load(Ordering::Acquire);
        self.reason.get().cloned()
    }
}

/// `App` owns a `GpuEngine` and hands `SeedBlock`s to Rayon workers, so a
/// refactor that smuggled an Objective-C type into either must fail to compile
/// here rather than at the point of use.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<GpuEngine>();
    assert_send_sync::<SeedBlock>();
    assert_send_sync::<GpuHealth>();
};

/// How one wave's 2047 U-iterations are cut into dispatches.
///
/// `Production` is the measured schedule. The other two exist so the self-test
/// and `gpu_chunk_schedule_invariance` can prove that the resumable kernel's
/// output does not depend on where the wave is cut — the single property that
/// makes `PIPELINE_DEPTH` command buffers in flight over one `states` buffer
/// safe. Metal ordering guarantees are relied on here: command buffers on one
/// queue execute in commit order, and dispatches inside one serial compute
/// encoder are barriered. Both are documented and were verified empirically.
/// Do NOT reach for `MTLFence` speculatively; add it only if this test fails.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Schedule {
    /// `ITERS_PER_DISPATCH` per dispatch, `DISPATCHES_PER_COMMAND_BUFFER` per
    /// command buffer: 2047 = 255*8 + 7 → 256 dispatches, 64 command buffers,
    /// ~8.8 ms each.
    Production,
    /// An explicit sequence; the last entry repeats if more dispatches are
    /// needed, so `Irregular(&[r])` is a uniform `r` per dispatch and
    /// `Irregular(&[2047])` the one-shot case. One dispatch per command buffer.
    Irregular(&'static [u32]),
}

impl Schedule {
    /// Iterations for the `n`-th iterate dispatch of a wave (0-based), before
    /// clamping to what remains.
    pub fn iters_for(&self, n: usize) -> u32 {
        match self {
            Schedule::Production => ITERS_PER_DISPATCH,
            Schedule::Irregular(steps) => {
                if steps.is_empty() {
                    ITERS_PER_DISPATCH
                } else {
                    steps[n.min(steps.len() - 1)].max(1)
                }
            }
        }
    }

    /// One dispatch per command buffer for the non-production schedules, so an
    /// irregular cut also spreads across the depth-3 ring — which is where a
    /// mis-ordered command buffer would show up.
    pub fn dispatches_per_command_buffer(&self) -> usize {
        match self {
            Schedule::Production => DISPATCHES_PER_COMMAND_BUFFER,
            _ => 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backend_probe_reports_ready_or_unavailable() {
        match probe() {
            GpuStatus::Unavailable(reason) => assert!(!reason.is_empty()),
            GpuStatus::Ready { device } => assert!(!device.is_empty()),
            other => panic!("probe() must be Ready or Unavailable, got {other:?}"),
        }
    }

    #[test]
    fn seed_block_preserves_order_and_chunks_without_reordering() {
        let mut b = SeedBlock::with_capacity(BLOCK);
        assert!(b.is_empty());
        for i in 0..BLOCK {
            b.push(GpuCandidate {
                entropy: [i as u8; 16],
                seed: [(i / 2) as u8; 64],
            });
        }
        assert_eq!(b.len(), BLOCK);
        assert_eq!(b.chunks(64).count(), 8);
        let flat: Vec<u8> = b
            .chunks(64)
            .flat_map(|c| c.iter().map(|x| x.entropy[0]))
            .collect();
        let want: Vec<u8> = (0..BLOCK).map(|i| i as u8).collect();
        assert_eq!(flat, want);
        assert_eq!(b.chunks(64).nth(1).unwrap()[0].seed, [32u8; 64]);
    }

    #[test]
    fn seed_block_zeroizes_its_candidates() {
        let mut b = SeedBlock::with_capacity(2);
        b.push(GpuCandidate {
            entropy: [0xAB; 16],
            seed: [0xCD; 64],
        });
        b.push(GpuCandidate {
            entropy: [0xEF; 16],
            seed: [0x12; 64],
        });
        // Capture the backing buffer BEFORE zeroizing: `b` was built with
        // `with_capacity(2)` and holds exactly 2 candidates, so len == capacity
        // and every byte in this range is initialized, non-zero data.
        let ptr = b.0.as_ptr() as *const u8;
        let byte_len = b.0.capacity() * core::mem::size_of::<GpuCandidate>();
        b.zeroize();
        assert_eq!(b.len(), 0);
        assert!(b.is_empty());
        // A bare `Vec::clear()` would make the two asserts above pass too, so
        // they alone don't prove zeroization. Read the raw bytes back to prove
        // the buffer itself was wiped, not just logically emptied.
        //
        // SAFETY: `b`'s allocation is still alive (dropping `b` happens after
        // this statement) and unchanged - `Zeroize::zeroize` wipes and clears
        // in place, it never reallocates or frees. `ptr`/`byte_len` were
        // captured while the buffer held exactly `capacity()` initialized
        // `GpuCandidate`s, so the whole range stays in-bounds and initialized
        // for the entire read.
        let bytes = unsafe { core::slice::from_raw_parts(ptr, byte_len) };
        assert!(
            bytes.iter().all(|&byte| byte == 0),
            "zeroize left non-zero bytes in SeedBlock's backing buffer"
        );
    }

    #[test]
    #[should_panic(expected = "would reallocate")]
    fn seed_block_push_panics_before_reallocating() {
        let mut b = SeedBlock::with_capacity(1);
        b.push(GpuCandidate {
            entropy: [0u8; 16],
            seed: [0u8; 64],
        });
        // Second push exceeds the reserved capacity: without a guard this would
        // reallocate and free the old (unzeroized) buffer.
        b.push(GpuCandidate {
            entropy: [1u8; 16],
            seed: [1u8; 64],
        });
    }

    #[test]
    fn raise_records_the_first_reason_and_never_overwrites_it() {
        let h = GpuHealth::default();
        assert!(!h.disable.load(Ordering::Relaxed));
        assert_eq!(h.take_reason(), None);
        h.raise(GpuDisableReason::AuditMismatch { index: 5183 });
        h.raise(GpuDisableReason::Panicked);
        assert!(h.disable.load(Ordering::Relaxed));
        assert_eq!(
            h.take_reason(),
            Some(GpuDisableReason::AuditMismatch { index: 5183 })
        );
    }

    #[test]
    fn take_reason_does_not_consume_the_reason() {
        let h = GpuHealth::default();
        let r = GpuDisableReason::Backend(GpuError::NoDevice);
        h.raise(r.clone());
        assert_eq!(h.take_reason(), Some(r.clone()));
        assert_eq!(h.take_reason(), Some(r));
    }

    /// MTLCommandBufferStatusCompleted == 4 with no error object is the only
    /// success. Completed WITH an error fails, and NotEnqueued(0), Enqueued(1),
    /// Committed(2), Scheduled(3), Error(5) all fail even with no error object —
    /// a wave that is merely `Scheduled` has not written `seeds`.
    #[test]
    fn command_buffer_status_is_ok_only_when_completed_with_no_error() {
        let err = |status, message: String| Err(GpuError::CommandBuffer { status, message });
        let mut cases = vec![
            (4i64, None, Ok(())),
            (4, Some("IOAF code 4"), err(4, "IOAF code 4".to_string())),
        ];
        for status in [0i64, 1, 2, 3, 5, 99] {
            let message = format!("command buffer finished with status {status}");
            cases.push((status, None, err(status, message)));
        }
        for (status, message, want) in cases {
            assert_eq!(
                classify_command_buffer_status(status, message.map(String::from)),
                want,
                "status {status}, message {message:?}"
            );
        }
    }
}
