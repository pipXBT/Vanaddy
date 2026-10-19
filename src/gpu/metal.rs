//! Metal backend. The only file in the tree that names an Objective-C type.
//!
//! Everything here is thread-confined by construction: `MTLBuffer`,
//! `MTLCommandBuffer` and `MTLCommandEncoder` are `!Send`/`!Sync` under objc2,
//! so the compiler — not a comment — enforces that a `MetalPbkdf2` is created,
//! used and dropped on one thread.

use crate::gpu::kernel_src::KERNEL_SRC;
use crate::gpu::pack::{pack_key_block, KeyBlock, BIP39_SALT_BLOCK};
use crate::gpu::{
    classify_command_buffer_status, GpuError, GpuStatus, Schedule, MAX_THREADS_PER_THREADGROUP,
    PIPELINE_DEPTH, WAVE,
};
use objc2::rc::{autoreleasepool, Retained};
use objc2::runtime::ProtocolObject;
use objc2_foundation::NSString;
use objc2_metal::{
    MTLBuffer, MTLCommandBuffer, MTLCommandEncoder, MTLCommandQueue, MTLCompileOptions,
    MTLComputeCommandEncoder, MTLComputePipelineState, MTLCreateSystemDefaultDevice, MTLDevice,
    MTLLanguageVersion, MTLLibrary, MTLResourceOptions, MTLSize,
};
use std::ptr::NonNull;
use std::sync::atomic::{AtomicBool, Ordering};
use zeroize::Zeroizing;

use super::producer::{producer, read_status, run_guarded, set_status};
use super::{GpuDisableReason, GpuHealth, SeedBlock};
use crossbeam_channel::Sender;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

// `MTLCreateSystemDefaultDevice` lives in CoreGraphics, which objc2-metal does
// not link for us.
#[link(name = "CoreGraphics", kind = "framework")]
extern "C" {}

/// Host mirror of the kernel's `struct Params { uint count, iters, finalize, _pad; }`.
#[repr(C)]
#[derive(Clone, Copy)]
struct Params {
    count: u32,
    /// U-iterations to advance in THIS dispatch. May be 0 (see the do-while in
    /// `run_wave`): PBKDF2 with c == 1 is T == U_1, already computed by the
    /// prologue, so the last dispatch only has to carry `finalize`.
    iters: u32,
    /// Nonzero => write the big-endian seed bytes for this candidate.
    finalize: u32,
    _pad: u32,
}

// The kernel indexes key blocks as `keyblocks + 16 * tid` over `ulong`, i.e. a
// 128-byte stride. If `KeyBlock` ever stops being exactly that, every candidate
// except tid 0 derives from the wrong key block.
const _: () = assert!(std::mem::size_of::<KeyBlock>() == 128);
const _: () = assert!(std::mem::size_of::<Params>() == 16);

type Cb = Retained<ProtocolObject<dyn MTLCommandBuffer>>;

type Buf = Retained<ProtocolObject<dyn MTLBuffer>>;

fn size1(width: usize) -> MTLSize {
    MTLSize {
        width,
        height: 1,
        depth: 1,
    }
}

/// ~1 ms device probe. Called ONCE from `main()`, BEFORE `enable_raw_mode()`,
/// so that a panic or any Metal stderr noise cannot land inside the alternate
/// screen.
pub fn probe() -> GpuStatus {
    match MTLCreateSystemDefaultDevice() {
        Some(device) => GpuStatus::Ready {
            device: device.name().to_string(),
        },
        None => GpuStatus::Unavailable("no Metal device on this system".to_string()),
    }
}

/// ONE set of buffers. No slot ring, no double buffering: `run_wave` takes
/// `&mut self` and blocks, so a second slot is unreachable, and advertising
/// "double-buffered" only invites an aliasing bug on `states`.
/// 1.00 + 2.00 + 0.50 = 3.50 MiB, not 7.0.
struct WaveBuffers {
    keys: Buf,   // WAVE * 128 B, StorageModeShared
    states: Buf, // WAVE * 256 B
    seeds: Buf,  // WAVE *  64 B
}

impl Drop for WaveBuffers {
    /// `keys` holds the zero-padded 12-word phrases themselves and `states`
    /// holds ipad/opad midstates, which are seed-equivalent. No command buffer
    /// is in flight here — `run_wave` waits on every one before returning — so
    /// this is safe to do unconditionally.
    fn drop(&mut self) {
        for (buf, len) in [
            (&self.keys, WAVE * 128),
            (&self.states, WAVE * 256),
            (&self.seeds, WAVE * 64),
        ] {
            unsafe { std::ptr::write_bytes(buf.contents().as_ptr() as *mut u8, 0, len) };
        }
    }
}

pub struct MetalPbkdf2 {
    device_name: String,
    queue: Retained<ProtocolObject<dyn MTLCommandQueue>>,
    prologue: Retained<ProtocolObject<dyn MTLComputePipelineState>>,
    iterate: Retained<ProtocolObject<dyn MTLComputePipelineState>>,
    bufs: WaveBuffers,
    tg: usize,
    /// Test-only fault injection. `Cell`, not `&mut self`, because
    /// `check_status` runs inside the autorelease-pool closure, which already
    /// holds shared borrows of the queue, the pipelines and the buffers.
    /// `MetalPbkdf2` is thread-confined (it holds `!Send` Metal objects), so
    /// `Cell` costs nothing.
    #[cfg(test)]
    fault_at_command_buffer: std::cell::Cell<Option<u32>>,
    #[cfg(test)]
    command_buffers_checked: std::cell::Cell<u32>,
}

impl MetalPbkdf2 {
    /// Device, queue, library (~60–95 ms cold, ~1.5 ms warm), both pipelines
    /// and all three buffers. Must be called on the thread that will use it.
    pub fn new() -> Result<MetalPbkdf2, GpuError> {
        let device = MTLCreateSystemDefaultDevice().ok_or(GpuError::NoDevice)?;
        let device_name = device.name().to_string();
        let queue = device.newCommandQueue().ok_or(GpuError::BufferAlloc)?;

        // Set ONLY the language version. Do NOT call setMathMode /
        // setFastMathEnabled: `setMathMode:` is macOS 15.0+ and objc2-metal
        // emits it with no availability guard, so on an M1 running
        // Ventura/Sonoma it raises NSInvalidArgumentException — an Objective-C
        // exception, which catch_unwind CANNOT catch — aborting the process
        // inside raw mode with the alternate screen still active. It is also
        // worthless here: SHA-512 is integer-only and MSL fast-math relaxes
        // IEEE-754 float semantics only.
        let options = MTLCompileOptions::new();
        options.setLanguageVersion(MTLLanguageVersion::Version3_0);
        let source = NSString::from_str(KERNEL_SRC);
        let library = device
            .newLibraryWithSource_options_error(&source, Some(&options))
            .map_err(|e| GpuError::ShaderCompile(e.localizedDescription().to_string()))?;

        let pipe = |name: &str| {
            let f = library
                .newFunctionWithName(&NSString::from_str(name))
                .ok_or_else(|| GpuError::PipelineCreate(format!("kernel `{name}` not found")))?;
            device
                .newComputePipelineStateWithFunction_error(&f)
                .map_err(|e| GpuError::PipelineCreate(e.localizedDescription().to_string()))
        };
        let prologue = pipe("pbkdf2_prologue")?;
        let iterate = pipe("pbkdf2_iterate")?;

        // One threadgroup size is used for BOTH pipelines, so take the widest
        // execution width and the tightest maximum. The final `.min(maxt)`
        // closes the case where `maxt < tew`, which would otherwise dispatch a
        // threadgroup larger than the pipeline permits — another uncatchable
        // Objective-C exception. The 256 clamp is a measured M1 result, not a
        // universal truth (384 measured 13% SLOWER here); VANADDY_GPU_TG
        // overrides it for tuning on other hardware.
        let tew = prologue
            .threadExecutionWidth()
            .max(iterate.threadExecutionWidth())
            .max(1);
        let maxt = prologue
            .maxTotalThreadsPerThreadgroup()
            .min(iterate.maxTotalThreadsPerThreadgroup());
        let want = std::env::var("VANADDY_GPU_TG")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(MAX_THREADS_PER_THREADGROUP);
        let tg = ((maxt.min(want) / tew).max(1) * tew).min(maxt);
        if tg == 0 {
            return Err(GpuError::PipelineCreate(format!(
                "threadgroup size 0 (tew={tew}, maxt={maxt})"
            )));
        }

        let make = |len: usize| {
            device
                .newBufferWithLength_options(len, MTLResourceOptions::StorageModeShared)
                .ok_or(GpuError::BufferAlloc)
        };
        let keys = make(WAVE * 128)?;
        let states = make(WAVE * 256)?;
        let seeds = make(WAVE * 64)?;

        Ok(MetalPbkdf2 {
            device_name,
            queue,
            prologue,
            iterate,
            bufs: WaveBuffers {
                keys,
                states,
                seeds,
            },
            tg,
            #[cfg(test)]
            fault_at_command_buffer: std::cell::Cell::new(None),
            #[cfg(test)]
            command_buffers_checked: std::cell::Cell::new(0),
        })
    }

    pub fn device_name(&self) -> String {
        self.device_name.clone()
    }

    /// Make the `nth` command-buffer status check of every subsequent wave
    /// report a synthetic `MTLCommandBufferStatusError` (5). The counter resets
    /// at the start of every `run_wave`, so `nth` is always relative to one
    /// wave — but the arming itself is sticky and is never cleared. That is the
    /// faithful model: a removed or wedged device does not heal between waves.
    /// A test wanting a single fault must clear the cell itself.
    #[cfg(test)]
    pub fn inject_command_buffer_fault(&self, nth: u32) {
        self.fault_at_command_buffer.set(Some(nth));
    }

    fn check_status(&self, cb: &ProtocolObject<dyn MTLCommandBuffer>) -> Result<(), GpuError> {
        #[cfg(test)]
        {
            let n = self.command_buffers_checked.get() + 1;
            self.command_buffers_checked.set(n);
            if self.fault_at_command_buffer.get() == Some(n) {
                return classify_command_buffer_status(
                    5,
                    Some("injected command-buffer fault".to_string()),
                );
            }
        }
        let status = cb.status().0 as i64;
        let message = cb.error().map(|e| e.localizedDescription().to_string());
        classify_command_buffer_status(status, message)
    }

    /// Wait on every outstanding command buffer in `ring`, THEN check status on
    /// each — never interleaved. Interleaving (wait, check, wait, check, ...)
    /// means a bad status on an early buffer would `?`-return before the later
    /// buffers are ever waited on, leaving them executing on the GPU while
    /// `WaveBuffers::Drop`'s "no command buffer is in flight here" assumption
    /// is violated on exactly that path. Every entry is drained (and the ring
    /// cleared to `None`) regardless of outcome, so this is safe to call from
    /// any early-return site. Returns the first error found, by ring position.
    fn drain_ring(&self, ring: &mut [Option<Cb>; PIPELINE_DEPTH]) -> Result<(), GpuError> {
        for cb in ring.iter().flatten() {
            cb.waitUntilCompleted();
        }
        let mut first_err = None;
        for slot in ring.iter_mut() {
            if let Some(cb) = slot.take() {
                if let Err(e) = self.check_status(&cb) {
                    first_err.get_or_insert(e);
                }
            }
        }
        first_err.map_or(Ok(()), Err)
    }

    /// Derive `keys.len()` seeds. `Ok(None)` means the wave was abandoned
    /// because `stop` was raised; the whole wave is discarded on any command
    /// buffer failure — there is deliberately no partial-success shape.
    ///
    /// The returned slice is EXACTLY `keys.len()` long and borrows `self`, so
    /// the next wave cannot overwrite seeds the caller still holds.
    pub fn run_wave(
        &mut self,
        keys: &[KeyBlock],
        salt_block: &[u64; 16],
        total_iters: u32,
        schedule: Schedule,
        stop: &AtomicBool,
    ) -> Result<Option<&[[u8; 64]]>, GpuError> {
        assert!(total_iters >= 1, "iterations must be at least 1"); // mirrors src/pbkdf2_lanes.rs:26
        if keys.is_empty() || keys.len() > WAVE {
            return Err(GpuError::BadConfig(format!(
                "wave takes 1..={WAVE} candidates, got {}",
                keys.len()
            )));
        }
        let count = keys.len() as u32;

        #[cfg(test)]
        self.command_buffers_checked.set(0);

        // Poison the seeds region so a missing finalize yields obvious garbage
        // rather than the PREVIOUS wave's still-valid 64-byte seed.
        unsafe {
            std::ptr::write_bytes(
                self.bufs.seeds.contents().as_ptr() as *mut u8,
                0xA5,
                WAVE * 64,
            )
        };
        // `KeyBlock` is #[repr(C, align(16))] over [u64; 16]: 128 bytes,
        // exactly the kernel's per-thread stride, and the u64s are already the
        // big-endian-decoded words the kernel expects, so the kernel contains
        // zero endianness code and the host does no byteswap.
        unsafe {
            std::ptr::copy_nonoverlapping(
                keys.as_ptr() as *const u8,
                self.bufs.keys.contents().as_ptr() as *mut u8,
                std::mem::size_of_val(keys),
            )
        };

        // 1 prologue command buffer: ipad/opad midstates and U_1, which the
        // kernel writes into BOTH states[i].u and states[i].t — so `states`
        // needs no clearing between waves.
        //
        // No `ring` exists yet at this point — nothing has been committed —
        // so an early return here can never leave a command buffer in flight;
        // this is the one wait/check site where a bare `?` is correct.
        autoreleasepool(|_| -> Result<(), GpuError> {
            let cb = self.queue.commandBuffer().ok_or(GpuError::BufferAlloc)?;
            let enc = cb.computeCommandEncoder().ok_or(GpuError::BufferAlloc)?;
            enc.setComputePipelineState(&self.prologue);
            let p = Params {
                count,
                iters: 0,
                finalize: 0,
                _pad: 0,
            };
            unsafe {
                enc.setBuffer_offset_atIndex(Some(&self.bufs.keys), 0, 0);
                enc.setBuffer_offset_atIndex(Some(&self.bufs.states), 0, 1);
                enc.setBytes_length_atIndex(NonNull::from(salt_block).cast(), 128, 2);
                enc.setBytes_length_atIndex(
                    NonNull::from(&p).cast(),
                    std::mem::size_of::<Params>(),
                    3,
                );
            }
            enc.dispatchThreads_threadsPerThreadgroup(size1(count as usize), size1(self.tg));
            enc.endEncoding();
            cb.commit();
            cb.waitUntilCompleted();
            self.check_status(&cb) // checked, not assumed
        })?;

        // do-while: ALWAYS at least one iterate dispatch, so total_iters == 1
        // still carries finalize=1. (Verified: c=1 via [iters=0, finalize=1]
        // matches the reference byte-for-byte — the loop no-ops and t = U_1.)
        let mut remaining = total_iters - 1; // 2047 for BIP-39
        let mut ring: [Option<Cb>; PIPELINE_DEPTH] = Default::default();
        let mut slot_ix = 0usize;
        let mut dispatch_ix = 0usize;
        let per_cb = schedule.dispatches_per_command_buffer();
        loop {
            if stop.load(Ordering::Relaxed) {
                // Drain-then-check the WHOLE ring, not just what happens to be
                // in `prev` below: up to PIPELINE_DEPTH command buffers can be
                // executing concurrently, and abandoning mid-drain on the
                // first bad status would leave the rest in flight.
                self.drain_ring(&mut ring)?;
                return Ok(None);
            }
            let prev = ring[slot_ix].take();
            // ONE AUTORELEASE POOL PER COMMAND BUFFER. Keep it — but not for
            // the reason originally written here. The spec predicted 1,861 B
            // leaked per command buffer without it (~700 MB/hour); that figure
            // is UNVERIFIED on this hardware. Removing this pool produced no
            // reproducible RSS difference at all — see
            // `gpu_rss_does_not_run_away_over_100k_dispatches` below for the
            // measurements — because objc2 routes `commandBuffer()` through
            // `retain_autoreleased`, which can often avoid the pool entirely.
            // That optimisation is best-effort, not guaranteed, so the pool is
            // still what bounds memory whenever it does not fire.
            // `prev` is moved in, so its release also happens inside the pool.
            let built = autoreleasepool(|_| -> Result<Cb, GpuError> {
                if let Some(prev) = prev {
                    prev.waitUntilCompleted();
                    self.check_status(&prev)?; // at EVERY wait, not just the last
                }
                let cb = self.queue.commandBuffer().ok_or(GpuError::BufferAlloc)?;
                // What makes the depth-3 ring safe on one shared `states` buffer
                // is Metal's automatic resource hazard tracking, which serialises
                // GPU-side access to it across the ring's command buffers on this
                // queue. That tracking applies here because `states` comes from
                // `device.newBufferWithLength_options` (device-direct allocation,
                // always hazard-tracked) rather than an `MTLHeap` — there is no
                // heap, fence, event, or concurrent dispatch anywhere in this
                // module to opt out of it. The ring's actual benefit is
                // overlapping HOST-side encode/submit latency with GPU execution,
                // not concurrent GPU execution of dependent work.
                //
                // Within one encoder — the `DISPATCHES_PER_COMMAND_BUFFER` loop
                // below, all against `enc` — a serial compute encoder additionally
                // auto-barriers between dispatches, but that covers only ordering
                // inside this one command buffer, not the three separate command
                // buffers the ring keeps in flight.
                let enc = cb.computeCommandEncoder().ok_or(GpuError::BufferAlloc)?;
                enc.setComputePipelineState(&self.iterate);
                unsafe {
                    enc.setBuffer_offset_atIndex(Some(&self.bufs.states), 0, 0);
                    enc.setBuffer_offset_atIndex(Some(&self.bufs.seeds), 0, 1);
                }
                for _ in 0..per_cb {
                    let iters = remaining.min(schedule.iters_for(dispatch_ix));
                    remaining -= iters;
                    dispatch_ix += 1;
                    let p = Params {
                        count,
                        iters,
                        finalize: (remaining == 0) as u32,
                        _pad: 0,
                    };
                    unsafe {
                        enc.setBytes_length_atIndex(
                            NonNull::from(&p).cast(),
                            std::mem::size_of::<Params>(),
                            2,
                        )
                    };
                    enc.dispatchThreads_threadsPerThreadgroup(
                        size1(count as usize),
                        size1(self.tg),
                    );
                    if remaining == 0 {
                        break;
                    }
                }
                enc.endEncoding();
                cb.commit();
                Ok(cb)
            });
            let cb = match built {
                Ok(cb) => cb,
                Err(e) => {
                    // `prev` (if it was the failure) already had
                    // `waitUntilCompleted` + `check_status` called on it above
                    // and is safely dropped. But up to PIPELINE_DEPTH - 1
                    // OTHER ring slots may still hold command buffers still
                    // executing on the GPU (this is exactly what pipelining
                    // means) — `ring[slot_ix]` is already `None` (taken into
                    // `prev`), so this only drains the genuinely outstanding
                    // ones. Their status is intentionally discarded: `e` is
                    // already the first-found error and there is no
                    // partial-success shape to report into, but every one of
                    // them still gets `waitUntilCompleted` + `check_status`
                    // so nothing returns with a command buffer in flight.
                    let _ = self.drain_ring(&mut ring);
                    return Err(e);
                }
            };
            // objc2's `Retained` IS the retain the Objective-C prototype had to
            // take by hand inside the pool: it is +1 owned, so moving it out
            // here keeps the command buffer alive past the pool drain.
            ring[slot_ix] = Some(cb);
            slot_ix = (slot_ix + 1) % PIPELINE_DEPTH;
            if remaining == 0 {
                break;
            }
        }
        // The host reads `seeds` only after EVERY command buffer of the wave
        // reports Completed.
        self.drain_ring(&mut ring)?;

        // SAFETY: `seeds` is WAVE * 64 bytes of StorageModeShared memory owned
        // by this engine; every command buffer of the wave has reported
        // Completed, so the GPU is no longer writing it; `[u8; 64]` has
        // alignment 1 and no invalid bit patterns; and the returned slice
        // borrows `&mut self` for its whole lifetime.
        let p = self.bufs.seeds.contents().as_ptr() as *const [u8; 64];
        let all: &[[u8; 64]] = unsafe { std::slice::from_raw_parts(p, WAVE) };
        // Slots >= count still hold 0xA5 poison and are never returned.
        Ok(Some(&all[..keys.len()]))
    }

    /// Raw read of one 64-byte slot of the `seeds` buffer, INCLUDING slots past
    /// the live count that `run_wave` refuses to return. Exists so
    /// `gpu_handles_ragged_counts` can prove that nothing wrote past the live
    /// count and the 0xA5 poison survived there — the only way to observe a
    /// slot the safe API deliberately hides.
    #[cfg(test)]
    pub fn raw_seed_slot(&self, i: usize) -> [u8; 64] {
        assert!(i < WAVE, "slot {i} is outside the {WAVE}-candidate wave");
        // SAFETY: `seeds` is WAVE * 64 bytes owned by this engine, no command
        // buffer is in flight (`run_wave` waits on every one before returning),
        // and `[u8; 64]` has alignment 1 and no invalid bit patterns.
        let p = self.bufs.seeds.contents().as_ptr() as *const [u8; 64];
        unsafe { *p.add(i) }
    }

    /// One wave under the measured production schedule.
    #[cfg(test)]
    pub fn derive(
        &mut self,
        phrases: &[&str],
        iters: u32,
    ) -> Result<Vec<Zeroizing<[u8; 64]>>, GpuError> {
        self.derive_with_schedule(phrases, iters, Schedule::Production)
    }

    /// One wave under an explicit dispatch schedule. The `Vec<KeyBlock>` holds
    /// the plaintext phrases, so it is `Zeroizing`.
    pub fn derive_with_schedule(
        &mut self,
        phrases: &[&str],
        iters: u32,
        schedule: Schedule,
    ) -> Result<Vec<Zeroizing<[u8; 64]>>, GpuError> {
        let keys: Zeroizing<Vec<KeyBlock>> = Zeroizing::new(
            phrases
                .iter()
                .map(|p| pack_key_block(p.as_bytes()))
                .collect(),
        );
        match self.run_wave(
            &keys,
            &BIP39_SALT_BLOCK,
            iters,
            schedule,
            &AtomicBool::new(false),
        )? {
            Some(seeds) => Ok(seeds.iter().map(|s| Zeroizing::new(*s)).collect()),
            None => Err(GpuError::BadConfig(
                "wave abandoned without a stop request".to_string(),
            )),
        }
    }
}

/// The only GPU handle `App` ever holds. Deliberately contains NO Objective-C
/// type: every Metal object lives and dies on the producer thread, and the
/// `assert_send_sync::<GpuEngine>()` assertion in `src/gpu/mod.rs` pins that so
/// a refactor cannot smuggle one into `App`.
pub struct GpuEngine {
    /// PRODUCER-ONLY stop flag, created here and shared with nothing else.
    /// NEVER `App::stop`: that is the flag every Rayon worker reads at
    /// src/chains/mod.rs:107, so a GPU self-disable that set it would silently
    /// end the entire search — the exact inverse of "keep searching on CPU".
    stop: Arc<AtomicBool>,
    finished: Arc<AtomicBool>,
    health: Arc<GpuHealth>,
    status: Arc<Mutex<GpuStatus>>,
    join: Option<JoinHandle<()>>,
}

impl GpuEngine {
    /// Returns IMMEDIATELY with status `Initializing`. Device creation, the
    /// ~60-95 ms cold library compile, pipeline build and the ~300 ms self-test
    /// all run on the spawned thread, so the UI never stalls on them.
    pub fn start(tx: Sender<Box<SeedBlock>>, health: Arc<GpuHealth>) -> GpuEngine {
        let stop = Arc::new(AtomicBool::new(false));
        let finished = Arc::new(AtomicBool::new(false));
        let status = Arc::new(Mutex::new(GpuStatus::Initializing));

        let t_stop = stop.clone();
        let t_finished = finished.clone();
        let t_health = health.clone();
        let t_status = status.clone();

        let join = std::thread::Builder::new()
            .name("vanaddy-gpu".into())
            .spawn(move || {
                run_guarded(&t_health, t_finished, || {
                    producer(tx, &t_stop, &t_health, &t_status)
                });
            })
            .ok();

        if join.is_none() {
            // Out of threads. Degrade exactly like every other failure: sticky
            // reason, GPU off, CPU search untouched.
            let reason = GpuDisableReason::Backend(GpuError::BadConfig(
                "could not spawn the vanaddy-gpu thread".into(),
            ));
            health.raise(reason.clone());
            set_status(&status, GpuStatus::Disabled(reason));
            finished.store(true, Ordering::Release);
        }

        GpuEngine {
            stop,
            finished,
            health,
            status,
            join,
        }
    }

    /// A raised fault wins over the last published status: a GPU that faulted
    /// must never keep reporting `Running` at 0/s.
    pub fn status(&self) -> GpuStatus {
        match self.health.take_reason() {
            Some(reason) => GpuStatus::Disabled(reason),
            None => read_status(&self.status),
        }
    }

    /// Sets the producer-only stop flag. NON-BLOCKING; never joins.
    ///
    /// `stop_search` calls this from the UI thread inside the render loop. A
    /// join here would stall the loop for the rest of a cold shader compile on
    /// an Enter-Ctrl+C-Enter sequence, and would block FOREVER if the GPU
    /// wedged inside `waitUntilCompleted` — leaving the terminal in raw mode
    /// with the alternate screen up and only `kill -9` as an exit.
    pub fn signal_stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }

    /// Acquire: pairs with the `FinishGuard`'s Release store, so seeing `true`
    /// guarantees the fault the producer raised just before it is also visible.
    pub fn is_finished(&self) -> bool {
        self.finished.load(Ordering::Acquire)
    }

    /// Joins the thread. Only call once `is_finished()` is true, or from the
    /// reaper at process exit where a wedged thread is accepted.
    pub fn reap(mut self) {
        debug_assert!(
            self.is_finished(),
            "reap() joins the producer thread: calling it before is_finished() can hang the UI \
             thread inside a wedged waitUntilCompleted, with the terminal still in raw mode. \
             Park the engine and reap it on a later pass instead."
        );
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

/// The skip helper. Absence must be LOUD where the backend actually ships.
///
/// This file is compiled only on `aarch64-apple-darwin` with the `metal`
/// feature, so on every other target these tests do not exist at all — that is
/// the graceful skip for CI and for other developers. Here, a test that returns
/// early passes, and an early return means the differential silently never ran.
/// So exactly two things skip: an explicit `VANADDY_NO_GPU=1`, and
/// `GpuError::NoDevice` (a genuinely headless machine). A shader that will not
/// compile, a pipeline that will not build, a buffer that will not allocate —
/// those are defects in code that ships on this target, and they panic.
#[cfg(test)]
pub(crate) fn gpu_for_test() -> Option<MetalPbkdf2> {
    if std::env::var_os("VANADDY_NO_GPU").is_some() {
        eprintln!("SKIP: VANADDY_NO_GPU is set");
        return None;
    }
    match MetalPbkdf2::new() {
        Ok(g) => Some(g),
        Err(GpuError::NoDevice) => {
            eprintln!("SKIP: no Metal device on this machine");
            None
        }
        Err(e) => panic!(
            "the Metal backend must be available on Apple Silicon: {e:?}\n\
             Set VANADDY_NO_GPU=1 to skip GPU tests deliberately."
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gpu::selftest::{ring_reference, CANONICAL_PHRASE, CANONICAL_SEED_HEX};
    use bip39::{Language, Mnemonic};
    use rand::{RngCore, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    /// The shortest possible 12-word English BIP-39 phrase: 11 × 3 letters + 11
    /// spaces + a 3-letter checksum word = 47 bytes.
    const SHORTEST_PHRASE: &str = "act act act act act act act act act act act box";
    /// The longest: 11 × 8 letters + 11 spaces + an 8-letter checksum word = 107
    /// bytes. `pack_key_block` zero-pads to 128, so this is the last length
    /// before the (absent) SHA-512 pre-hash path would be needed.
    const LONGEST_PHRASE: &str = "abstract abstract abstract abstract abstract abstract abstract abstract abstract abstract abstract attitude";

    /// `total_iters == 1` is the case the do-while exists for: PBKDF2 with
    /// c == 1 is T == U_1, already computed by the prologue, so the wave still
    /// needs one iterate dispatch purely to carry `finalize`.
    #[test]
    fn gpu_matches_ring_at_total_iters_1_2_3_16_2048() {
        let Some(mut gpu) = gpu_for_test() else {
            return;
        };
        let phrases = [CANONICAL_PHRASE, SHORTEST_PHRASE, LONGEST_PHRASE];
        for iters in [1u32, 2, 3, 16, 2048] {
            let out = gpu.derive(&phrases, iters).expect("wave");
            assert_eq!(out.len(), phrases.len());
            for (i, phrase) in phrases.iter().enumerate() {
                assert_eq!(
                    hex::encode(*out[i]),
                    hex::encode(ring_reference(phrase, iters)),
                    "iters={iters} index={i} phrase=`{phrase}` ({} bytes)",
                    phrase.len()
                );
            }
        }
    }

    /// The kernel is resumable: all live state is in `states`, so a wave can be
    /// split across arbitrarily many dispatches. If that were not exactly true,
    /// depth-3 pipelining over one `states` buffer would be unsound. Five
    /// schedules, two of them irregular, must be BIT-IDENTICAL. The second
    /// irregular schedule sums to less than 2047, so it also exercises the
    /// "last entry repeats" branch of `Schedule::iters_for` and the
    /// `.min(remaining)` clamp on the repeated, over-long tail.
    #[test]
    fn gpu_chunk_schedule_invariance() {
        let Some(mut gpu) = gpu_for_test() else {
            return;
        };
        let phrases = [CANONICAL_PHRASE, SHORTEST_PHRASE, LONGEST_PHRASE];
        let schedules = [
            ("one-shot", Schedule::Irregular(&[2047])),
            ("production R=8", Schedule::Production),
            ("irregular", Schedule::Irregular(&[1, 1000, 46, 1000])),
            ("R=1", Schedule::Irregular(&[1])),
            (
                "irregular repeat-tail",
                Schedule::Irregular(&[500, 500, 500]),
            ),
        ];
        for (label, schedule) in schedules {
            let out = gpu
                .derive_with_schedule(&phrases, crate::seed::PBKDF2_ROUNDS, schedule)
                .expect("wave");
            assert_eq!(out.len(), phrases.len());
            assert_eq!(hex::encode(*out[0]), CANONICAL_SEED_HEX, "schedule {label}");
            for (i, phrase) in phrases.iter().enumerate() {
                assert_eq!(
                    hex::encode(*out[i]),
                    hex::encode(ring_reference(phrase, crate::seed::PBKDF2_ROUNDS)),
                    "schedule {label} index {i}"
                );
            }
        }
    }

    /// 520 entries so the ragged-count test in Task 3.8 can ask for 513.
    const CORPUS_LEN: usize = 520;

    /// Deterministic differential corpus. ChaCha20, fixed seed: reproducible
    /// across machines and across `rand` minor releases.
    fn deterministic_corpus() -> Vec<Mnemonic> {
        let mut rng = ChaCha20Rng::seed_from_u64(0x5EED_1234);
        let mut out = Vec::with_capacity(CORPUS_LEN);
        out.push(Mnemonic::from_phrase(CANONICAL_PHRASE, Language::English).expect("canonical"));
        out.push(Mnemonic::from_phrase(SHORTEST_PHRASE, Language::English).expect("47-byte"));
        out.push(Mnemonic::from_phrase(LONGEST_PHRASE, Language::English).expect("107-byte"));
        while out.len() < CORPUS_LEN {
            // The canonical vector again at the LAST index of the 512-wave, so
            // a kernel that only ever writes tid 0 correctly cannot pass.
            if out.len() == 511 {
                out.push(
                    Mnemonic::from_phrase(CANONICAL_PHRASE, Language::English).expect("canonical"),
                );
                continue;
            }
            let mut e = [0u8; 16];
            rng.fill_bytes(&mut e);
            out.push(Mnemonic::from_entropy(&e, Language::English).expect("16 bytes is valid"));
        }
        out
    }

    #[test]
    fn deterministic_corpus_has_the_pinned_shape() {
        let c = deterministic_corpus();
        assert_eq!(c.len(), CORPUS_LEN);
        assert_eq!(c[0].phrase(), CANONICAL_PHRASE);
        assert_eq!(c[1].phrase().len(), 47);
        assert_eq!(c[2].phrase().len(), 107);
        assert_eq!(c[511].phrase(), CANONICAL_PHRASE);
        let lens: Vec<usize> = c.iter().map(|m| m.phrase().len()).collect();
        assert_eq!(*lens.iter().min().expect("non-empty"), 47);
        assert_eq!(*lens.iter().max().expect("non-empty"), 107);
    }

    /// P1, the seed-agreement property, over 512 phrases at once:
    ///   gpu.derive(p)[i] == derive_seed(p)          (ring, src/seed.rs:8)
    ///                    == derive_seeds::<4>(..)[k] (4-lane, src/seed.rs:23)
    #[test]
    fn gpu_ring_and_4lane_agree_over_512_deterministic_phrases() {
        let Some(mut gpu) = gpu_for_test() else {
            return;
        };
        let corpus = deterministic_corpus();
        let phrases: Vec<&str> = corpus[..512].iter().map(|m| m.phrase()).collect();
        let gpu_seeds = gpu
            .derive(&phrases, crate::seed::PBKDF2_ROUNDS)
            .expect("wave");
        assert_eq!(gpu_seeds.len(), 512);

        for (i, m) in corpus[..512].iter().enumerate() {
            let want = crate::seed::derive_seed(m);
            assert_eq!(
                hex::encode(*gpu_seeds[i]),
                hex::encode(want),
                "GPU vs ring at index {i}, phrase `{}`",
                m.phrase()
            );
        }

        for (chunk_ix, chunk) in corpus[..512].chunks(crate::pbkdf2_lanes::LANES).enumerate() {
            let lane_input: [Mnemonic; crate::pbkdf2_lanes::LANES] = std::array::from_fn(|k| {
                Mnemonic::from_phrase(chunk[k].phrase(), Language::English).expect("valid phrase")
            });
            let lanes = crate::seed::derive_seeds(&lane_input);
            for k in 0..crate::pbkdf2_lanes::LANES {
                let i = chunk_ix * crate::pbkdf2_lanes::LANES + k;
                assert_eq!(
                    hex::encode(*gpu_seeds[i]),
                    hex::encode(lanes[k]),
                    "GPU vs 4-lane at index {i}, phrase `{}`",
                    chunk[k].phrase()
                );
            }
        }
    }

    /// Counts chosen to straddle the threadgroup size (256), the SIMD width
    /// (32), and the channel block size (512). The trailing `513, 2` is
    /// deliberately appended out of order: it guarantees at least one wave
    /// (513) is immediately followed by a SMALLER one (2), independent of
    /// how the ascending run above it is edited. An ascending-only sequence
    /// cannot exercise a shrinking-count transition at all, and that
    /// transition is the only one `gpu_handles_ragged_counts` can use to catch
    /// a regression from "poison the whole buffer on every wave" to "only ever
    /// grow the poisoned region as counts increase" — see that test for why.
    const RAGGED_COUNTS: [usize; 11] = [1, 2, 31, 33, 255, 257, 511, 512, 513, 513, 2];

    /// Every ragged count returns EXACTLY `count` correct seeds, and a thread
    /// past the live count must not write. If it did, a later wave with a
    /// larger count would silently serve the previous wave's seed for those
    /// slots.
    ///
    /// The `n < prev_n` branch below is load-bearing, not defensive
    /// decoration: every count in `RAGGED_COUNTS` up to that point is
    /// ascending, so every slot the `[n, n+1, WAVE-1]` check reads was never
    /// written by any prior (necessarily smaller-or-equal) wave — it would
    /// read `0xA5` whether `run_wave` re-poisons the WHOLE buffer on every
    /// call (correct, what it does today) or only ever GROWS the poisoned
    /// region as the largest-seen count increases (a regression). Only a wave
    /// that is SMALLER than its predecessor can tell those two apart: the gap
    /// `[n, prev_n)` held the predecessor's real, validly computed seed bytes
    /// a moment ago, and only re-poisoning the whole buffer overwrites them.
    /// `RAGGED_COUNTS`'s trailing `513, 2` exists solely to trigger this
    /// branch once.
    #[test]
    fn gpu_handles_ragged_counts() {
        let Some(mut gpu) = gpu_for_test() else {
            return;
        };
        let corpus = deterministic_corpus();
        let phrases: Vec<&str> = corpus.iter().map(|m| m.phrase()).collect();
        let mut prev_n = 0usize;
        for n in RAGGED_COUNTS {
            let out = gpu
                .derive(&phrases[..n], crate::seed::PBKDF2_ROUNDS)
                .expect("wave");
            assert_eq!(out.len(), n, "run_wave must return EXACTLY count entries");
            for i in [0usize, n / 2, n - 1] {
                assert_eq!(
                    hex::encode(*out[i]),
                    hex::encode(crate::seed::derive_seed(&corpus[i])),
                    "n={n} index={i} phrase=`{}`",
                    corpus[i].phrase()
                );
            }
            for slot in [n, n + 1, crate::gpu::WAVE - 1] {
                assert_eq!(
                    gpu.raw_seed_slot(slot),
                    [0xA5u8; 64],
                    "slot {slot} was written by a wave of count {n}"
                );
            }
            if n < prev_n {
                for slot in n..prev_n {
                    assert_eq!(
                        gpu.raw_seed_slot(slot),
                        [0xA5u8; 64],
                        "slot {slot} still held wave-of-{prev_n}'s seed after a \
                         smaller wave of count {n} — the buffer was not fully \
                         re-poisoned"
                    );
                }
            }
            prev_n = n;
        }
    }

    /// Two identical waves must produce bit-identical seeds. A GPU that is
    /// racing on `states` — the failure mode depth-3 pipelining could
    /// introduce — shows up here as an intermittent difference.
    #[test]
    fn gpu_repeat_wave_is_bit_identical() {
        let Some(mut gpu) = gpu_for_test() else {
            return;
        };
        let corpus = deterministic_corpus();
        let phrases: Vec<&str> = corpus[..512].iter().map(|m| m.phrase()).collect();
        let first: Vec<String> = gpu
            .derive(&phrases, crate::seed::PBKDF2_ROUNDS)
            .expect("wave")
            .iter()
            .map(|s| hex::encode(**s))
            .collect();
        for round in 0..3 {
            let again: Vec<String> = gpu
                .derive(&phrases, crate::seed::PBKDF2_ROUNDS)
                .expect("wave")
                .iter()
                .map(|s| hex::encode(**s))
                .collect();
            assert_eq!(first, again, "wave {round} differed from the first");
        }
    }

    /// The whole wave is discarded on ANY command-buffer failure — there is no
    /// partial-success shape. Without this, a mid-wave GPU reset silently drops
    /// 8 of 2048 U-iterations and finalize writes a T that is the XOR of only
    /// 2,039 values.
    #[test]
    fn gpu_command_buffer_error_yields_err_not_partial_output() {
        let Some(mut gpu) = gpu_for_test() else {
            return;
        };

        // Baseline: the same wave succeeds with no fault injected.
        let good = gpu
            .derive(&[CANONICAL_PHRASE], crate::seed::PBKDF2_ROUNDS)
            .expect("wave");
        assert_eq!(hex::encode(*good[0]), CANONICAL_SEED_HEX);

        // Fault the 3rd status check of the next wave: one prologue plus two
        // iterate command buffers have already been accepted, so this is
        // squarely mid-wave, not at a boundary.
        gpu.inject_command_buffer_fault(3);
        match gpu.derive(&[CANONICAL_PHRASE], crate::seed::PBKDF2_ROUNDS) {
            Err(GpuError::CommandBuffer { status, message }) => {
                assert_eq!(status, 5);
                assert!(message.contains("injected"), "{message}");
            }
            Err(other) => panic!("wrong error: {other:?}"),
            Ok(seeds) => panic!(
                "a faulted wave produced {} seeds instead of an error",
                seeds.len()
            ),
        }
    }

    /// Resident set size in KiB, via `ps`. No dependency, and it measures what
    /// actually gets the process jetsammed.
    #[cfg(test)]
    fn rss_kib() -> u64 {
        let out = std::process::Command::new("ps")
            .args(["-o", "rss=", "-p", &std::process::id().to_string()])
            .output()
            .expect("ps");
        String::from_utf8_lossy(&out.stdout)
            .trim()
            .parse()
            .expect("ps printed a number")
    }

    /// General no-runaway-leak guard over a long dispatch run. `#[ignore]`d: ~65 s.
    ///
    /// Run it by hand with:
    ///   cargo test --release -- --ignored --nocapture gpu_rss_does_not_run_away
    ///
    /// Does NOT prove the per-command-buffer autorelease pool in `run_wave`
    /// is load-bearing: removing it measured deltas of +4080, +3296, -1856
    /// KiB across three runs, indistinguishable from four pool-intact deltas
    /// of -2560, -1056, -1728, -1696 KiB — no threshold separates the two.
    /// `queue.commandBuffer()` returns a `Retained<T>`; objc2's
    /// `retain_autoreleased` **can sometimes** avoid putting the object in
    /// the pool (a best-effort runtime handshake, not a guarantee — it needs
    /// specific inlining and callee cooperation, and falls back to a real
    /// autorelease when it doesn't fire), which plausibly explains a leak
    /// far smaller than the spec predicted without implying there is no
    /// autorelease traffic at all. Because the elision isn't guaranteed, the
    /// pool remains real insurance rather than decoration, even though this
    /// test cannot demonstrate its value on this hardware.
    #[test]
    #[ignore]
    fn gpu_rss_does_not_run_away_over_100k_dispatches() {
        let Some(mut gpu) = gpu_for_test() else {
            return;
        };
        let phrases: Vec<&str> = vec![CANONICAL_PHRASE; 512];

        // 30 warm-up waves so the baseline is taken after the allocator, the
        // Metal driver and the shader cache have all settled.
        for _ in 0..30 {
            gpu.derive(&phrases, crate::seed::PBKDF2_ROUNDS)
                .expect("wave");
        }
        let base = rss_kib();

        // 2047 = 255*8 + 7 → 256 iterate dispatches → 64 command buffers at 4
        // per buffer. 390 waves × (1 prologue + 64 iterate) = 25,350 command
        // buffers, 390 × 257 = 100,230 dispatches.
        let started = std::time::Instant::now();
        for _ in 0..390 {
            gpu.derive(&phrases, crate::seed::PBKDF2_ROUNDS)
                .expect("wave");
        }
        let end = rss_kib();
        eprintln!(
            "100,230 dispatches in {:.1}s: RSS {base} KiB -> {end} KiB (delta {} KiB)",
            started.elapsed().as_secs_f64(),
            end as i64 - base as i64
        );
        assert!(
            end.saturating_sub(base) < 8 * 1024,
            "RSS grew {} KiB over 100,230 dispatches — cause unknown, needs \
             investigation",
            end - base
        );
    }

    /// The long differential, and the gate the whole of Milestone 8 rests on.
    /// `#[ignore]`d: 1,000,000 candidates is ~15 minutes in a debug build.
    /// Every GPU seed is re-derived with `ring`; a mismatch prints the global
    /// index and the phrase so the single case replays on its own.
    ///
    ///   VANADDY_GPU_SOAK_N=1e7 cargo test -- --ignored --nocapture
    #[test]
    #[ignore = "soak; run with --ignored"]
    fn gpu_soak_matches_ring() {
        let Some(mut gpu) = gpu_for_test() else {
            return;
        };
        // f64 first: the documented invocation is `VANADDY_GPU_SOAK_N=1e7`, which
        // `usize` would reject. Unparseable, non-finite or < 1 falls back to the
        // default: a soak of zero candidates would green-light a broken kernel.
        let n = std::env::var("VANADDY_GPU_SOAK_N")
            .ok()
            .and_then(|s| s.trim().parse::<f64>().ok())
            .filter(|v| v.is_finite() && *v >= 1.0)
            .map_or(1_000_000, |v| v as usize);
        let started = std::time::Instant::now();
        let mut done = 0usize;
        while done < n {
            let take = crate::gpu::WAVE.min(n - done);
            let mnemonics: Vec<Mnemonic> = (0..take)
                .map(|_| Mnemonic::new(bip39::MnemonicType::Words12, Language::English))
                .collect();
            let phrases: Vec<&str> = mnemonics.iter().map(|m| m.phrase()).collect();
            let seeds = gpu
                .derive(&phrases, crate::seed::PBKDF2_ROUNDS)
                .expect("wave");
            assert_eq!(seeds.len(), take, "wave returned the wrong candidate count");
            for (i, m) in mnemonics.iter().enumerate() {
                let want = crate::seed::derive_seed(m);
                assert_eq!(
                    hex::encode(*seeds[i]),
                    hex::encode(want),
                    "soak mismatch at global index {}, phrase `{}`",
                    done + i,
                    m.phrase()
                );
            }
            done += take;
            eprintln!(
                "soak: {done}/{n} in {:.1}s",
                started.elapsed().as_secs_f64()
            );
        }
        eprintln!(
            "soak: {n} candidates, 0 mismatches, {:.1}s",
            started.elapsed().as_secs_f64()
        );
    }
}
