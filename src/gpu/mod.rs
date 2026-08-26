//! GPU offload of BIP-39 PBKDF2-HMAC-SHA512 (c = 2048, salt "mnemonic", dkLen = 64).
//! Apple Silicon + Metal only; every other target builds `stub.rs`.
//! The GPU is a *seed accelerator*: never a source of entropy, never a source of
//! truth. Every GPU-sourced match is re-derived with `ring` before it can exist.

// Nothing outside this module consumes it yet - `App` and `main()` wire it up in
// milestone 6. Remove this attribute then.
#![allow(dead_code)]

use zeroize::{Zeroize, ZeroizeOnDrop};

pub mod selftest;

pub use selftest::SelfTestError;

// Milestone 3 replaces the line below with the spec's two `cfg_attr`s:
//     #[cfg_attr(all(target_os="macos", target_arch="aarch64", feature="metal"), path = "metal.rs")]
//     #[cfg_attr(not(all(target_os="macos", target_arch="aarch64", feature="metal")), path = "stub.rs")]
// Until `metal.rs` exists there is nothing for a `metal` feature to select, so
// declaring the feature now would only add an `unexpected_cfgs` warning.
#[path = "stub.rs"]
mod backend;

/// `main()` probes through the module, not the type, so milestone 6 does not
/// have to know which backend it got. This is the design spec's `mod.rs` form
/// (`pub use backend::{GpuEngine, probe};`) written from the start - rustfmt
/// sorts the braces to `{probe, GpuEngine}` - so milestone 3 only has to widen
/// `mod backend;` to `pub mod backend;` and swap the `#[path]` for the two
/// `cfg_attr`s. It never has to delete a wrapper.
pub use backend::{probe, GpuEngine};

pub const WAVE: usize = 8_192; // candidates per GPU wave
pub const BLOCK: usize = 512; // candidates per channel message (16/wave)
pub const CHANNEL_CAPACITY: usize = 32; // 2 waves of blocks
pub const ITERS_PER_DISPATCH: u32 = 8; // 2047 = 255*8 + 7 -> 256 dispatches
pub const DISPATCHES_PER_COMMAND_BUFFER: usize = 4; // -> 8.8 ms per command buffer
pub const PIPELINE_DEPTH: usize = 3; // command buffers in flight, within a wave
pub const MAX_THREADS_PER_THREADGROUP: usize = 256; // 384 measured 13% SLOWER on M1
pub const COMPRESSIONS_PER_SEED: u32 = 4_098; // 2 + 2 + 2*2047
pub const AUDITS_PER_WAVE: usize = 4; // RANDOM indices, not a fixed stride

/// Every fallible host-side GPU operation funnels through this. `Clone + Debug +
/// PartialEq` so a test can assert on the exact variant and a `GpuDisableReason`
/// carrying one can be rendered in the stats pane.
#[derive(Clone, Debug, PartialEq)]
pub enum GpuError {
    /// `salt.len() > pbkdf2_lanes::MAX_SALT_LEN`: `salt || INT(1) || 0x80 || len`
    /// would not fit the single 128-byte block the kernel is built around.
    SaltTooLong { len: usize },
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
    NoDevice,
    UserOff,
    ShaderCompile(String),
    PipelineCreate(String),
    BufferAlloc,
    BadConfig(String),
    SelfTest(SelfTestError),
    /// Command buffer status != Completed, or error() was set.
    CommandBuffer {
        status: i64,
        message: String,
    },
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
#[repr(C)]
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

/// `App` owns a `GpuEngine` and hands `SeedBlock`s to Rayon workers, so a
/// refactor that smuggled an Objective-C type into either must fail to compile
/// here rather than at the point of use.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<GpuEngine>();
    assert_send_sync::<SeedBlock>();
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wave_geometry_is_self_consistent() {
        // The producer carves a wave into whole blocks; a remainder would mean
        // either dropped candidates or a short final block.
        assert!(WAVE.is_multiple_of(BLOCK));
        assert_eq!(WAVE / BLOCK, 16);
        // The channel holds exactly two waves of blocks.
        assert_eq!(CHANNEL_CAPACITY, 2 * (WAVE / BLOCK));

        // U_1 comes from the prologue, so 2047 follow-up iterations remain. At
        // R = 8 that is 255 full dispatches plus a 7-iteration tail = 256, a
        // whole number of 4-dispatch command buffers.
        let follow_up = crate::seed::PBKDF2_ROUNDS - 1;
        assert_eq!(follow_up, 2047);
        let dispatches = follow_up.div_ceil(ITERS_PER_DISPATCH) as usize;
        assert_eq!(dispatches, 256);
        assert!(dispatches.is_multiple_of(DISPATCHES_PER_COMMAND_BUFFER));
        assert_eq!(PIPELINE_DEPTH, 3);

        // 2 prologue compressions (ipad, opad) + 2 for U_1 + 2 per follow-up.
        assert_eq!(COMPRESSIONS_PER_SEED, 2 + 2 + 2 * follow_up);

        // A block must tile the threadgroup clamp exactly.
        assert!(BLOCK.is_multiple_of(MAX_THREADS_PER_THREADGROUP));
        assert_eq!(AUDITS_PER_WAVE, 4);
        const { assert!(AUDITS_PER_WAVE < WAVE) };
    }

    #[test]
    fn stub_backend_reports_unavailable() {
        match GpuEngine::probe() {
            GpuStatus::Unavailable(reason) => assert!(!reason.is_empty()),
            other => panic!("stub backend must never report a usable GPU, got {other:?}"),
        }
        assert_eq!(probe(), GpuEngine::probe());
    }

    #[test]
    fn gpu_candidate_has_pinned_repr_c_layout() {
        // Milestone 3's Metal kernel reads this struct by raw byte offset. A
        // field reorder, width change, or a derive that isn't repr(C)-safe
        // would compile and pass every other test here, then only surface as
        // a plausible-but-wrong seed once the GPU path is wired up.
        assert_eq!(core::mem::size_of::<GpuCandidate>(), 80);
        assert_eq!(core::mem::align_of::<GpuCandidate>(), 1);
        assert_eq!(core::mem::offset_of!(GpuCandidate, entropy), 0);
        assert_eq!(core::mem::offset_of!(GpuCandidate, seed), 16);
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
    fn a_seed_block_crosses_a_thread_boundary_through_the_channel() {
        let (tx, rx) = crossbeam_channel::bounded::<Box<SeedBlock>>(CHANNEL_CAPACITY);
        let rx: GpuRx = rx;
        let producer = std::thread::spawn(move || {
            let mut b = SeedBlock::with_capacity(BLOCK);
            for i in 0..BLOCK {
                b.push(GpuCandidate {
                    entropy: [i as u8; 16],
                    seed: [7u8; 64],
                });
            }
            tx.send(Box::new(b)).expect("receiver is alive");
        });
        let got = rx.recv().expect("producer sent one block");
        producer.join().expect("producer thread did not panic");
        assert_eq!(got.len(), BLOCK);
        assert_eq!(got.chunks(64).next().unwrap()[3].entropy, [3u8; 16]);
    }
}
