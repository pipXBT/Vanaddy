//! Metal backend. The only file in the tree that names an Objective-C type.
//!
//! Everything here is thread-confined by construction: `MTLBuffer`,
//! `MTLCommandBuffer` and `MTLCommandEncoder` are `!Send`/`!Sync` under objc2,
//! so the compiler — not a comment — enforces that a `MetalPbkdf2` is created,
//! used and dropped on one thread.

use crate::gpu::kernel_src::KERNEL_SRC;
use crate::gpu::{GpuError, GpuStatus, MAX_THREADS_PER_THREADGROUP, WAVE};
use objc2::rc::Retained;
use objc2::runtime::ProtocolObject;
use objc2_foundation::NSString;
use objc2_metal::{
    MTLBuffer, MTLCommandQueue, MTLCompileOptions, MTLComputePipelineState,
    MTLCreateSystemDefaultDevice, MTLDevice, MTLLanguageVersion, MTLLibrary, MTLResourceOptions,
};

// `MTLCreateSystemDefaultDevice` lives in CoreGraphics, which objc2-metal does
// not link for us.
#[link(name = "CoreGraphics", kind = "framework")]
extern "C" {}

type Buf = Retained<ProtocolObject<dyn MTLBuffer>>;

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
    tew: usize,
    maxt: usize,
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

        let mut pipes = Vec::new();
        for name in ["pbkdf2_prologue", "pbkdf2_iterate"] {
            let f = library
                .newFunctionWithName(&NSString::from_str(name))
                .ok_or_else(|| GpuError::PipelineCreate(format!("kernel `{name}` not found")))?;
            pipes.push(
                device
                    .newComputePipelineStateWithFunction_error(&f)
                    .map_err(|e| GpuError::PipelineCreate(e.localizedDescription().to_string()))?,
            );
        }
        let iterate = pipes.pop().expect("two pipelines built");
        let prologue = pipes.pop().expect("two pipelines built");

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
            tew,
            maxt,
        })
    }

    pub fn device_name(&self) -> String {
        self.device_name.clone()
    }

    pub fn threadgroup_size(&self) -> usize {
        self.tg
    }

    /// `(threadExecutionWidth, maxTotalThreadsPerThreadgroup)` as the device
    /// itself reported them, so tests can check `threadgroup_size()` against
    /// the hardware's own numbers instead of the constants the formula in
    /// `new()` is derived from.
    pub fn threadgroup_bounds(&self) -> (usize, usize) {
        (self.tew, self.maxt)
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

/// Compile-time proof that the `objc2-metal` surface `run_wave` (Task 3.4)
/// depends on resolved to the selector spellings and arities this file assumes.
/// Never called, never shipped in any meaningful sense — it exists so that a
/// binding mismatch fails here, naming the one selector that moved, instead of
/// inside the kernel work where it looks like a Metal bug.
#[allow(dead_code)]
fn objc2_surface_probe(
    q: &ProtocolObject<dyn objc2_metal::MTLCommandQueue>,
    pipe: &ProtocolObject<dyn MTLComputePipelineState>,
    buf: &ProtocolObject<dyn MTLBuffer>,
) {
    use objc2_metal::{MTLCommandBuffer, MTLCommandEncoder, MTLComputeCommandEncoder, MTLSize};

    let _: usize = pipe.threadExecutionWidth();
    let _: usize = pipe.maxTotalThreadsPerThreadgroup();
    let _: std::ptr::NonNull<std::ffi::c_void> = buf.contents();

    // Pin `autoreleasepool`'s closure arity and the shape of the pool argument.
    // Task 3.4 calls this three times and Task 3.3's own rationale names it as a
    // reason for choosing objc2 over metal-rs, so it belongs in this probe: if the
    // closure took no argument, or returned `()` only, 3.4 would not compile and the
    // failure would surface 300 lines into a task this probe exists to de-risk.
    let _: u32 = objc2::rc::autoreleasepool(|_pool| 0u32);

    let Some(cb) = q.commandBuffer() else { return };
    let _: i64 = cb.status().0 as i64;
    let _: Option<String> = cb.error().map(|e| e.localizedDescription().to_string());

    if let Some(enc) = cb.computeCommandEncoder() {
        enc.setComputePipelineState(pipe);
        let p: u32 = 0;
        unsafe {
            enc.setBuffer_offset_atIndex(Some(buf), 0, 0);
            enc.setBytes_length_atIndex(std::ptr::NonNull::from(&p).cast(), 4, 1);
        }
        enc.dispatchThreads_threadsPerThreadgroup(
            MTLSize {
                width: 1,
                height: 1,
                depth: 1,
            },
            MTLSize {
                width: 1,
                height: 1,
                depth: 1,
            },
        );
        enc.endEncoding();
    }
    cb.commit();
    cb.waitUntilCompleted();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gpu_device_opens_and_reports_a_name() {
        let Some(gpu) = gpu_for_test() else { return };
        assert!(
            !gpu.device_name().is_empty(),
            "MTLDevice reported an empty name"
        );
    }

    #[test]
    fn gpu_threadgroup_size_is_a_positive_multiple_of_the_execution_width() {
        let Some(gpu) = gpu_for_test() else { return };
        let tg = gpu.threadgroup_size();
        // Compare against the values the device actually reported, not against
        // constants this formula is derived from. `tg <= MAX_THREADS_PER_THREADGROUP`
        // and `tg % 32 == 0` are both TAUTOLOGIES of Step 4's
        //     tg = ((maxt.min(want) / tew).max(1) * tew).min(maxt)
        // when `want` is the constant and `tew` is 32 — they restate the formula
        // rather than testing it, and `tg > 0` is already guaranteed by the
        // `if tg == 0 { return Err(..) }` two lines above it in `new()`.
        let (tew, maxt) = gpu.threadgroup_bounds();
        assert!(tew > 0 && maxt > 0, "device reported tew={tew} maxt={maxt}");
        assert!(
            tg > 0 && tg <= maxt,
            "threadgroup {tg} must fit the device's own maxTotalThreadsPerThreadgroup {maxt}"
        );
        assert_eq!(
            tg % tew,
            0,
            "threadgroup {tg} is not a multiple of this device's execution width {tew}"
        );
        // The M1 perf clamp is a TUNING choice, not a hardware bound: this M1
        // reports maxTotalThreadsPerThreadgroup = 384, and 384 measured 13% SLOWER
        // than 256. Only assert the clamp when the override is absent — otherwise
        // `VANADDY_GPU_TG=512`, a tuning path this very brief documents, makes the
        // formula yield 384 and panics here. A test that fails on a documented
        // knob gets "fixed" by deleting the assertion, and this is the only
        // load-bearing one in the function.
        if std::env::var_os("VANADDY_GPU_TG").is_none() {
            assert!(
                tg <= MAX_THREADS_PER_THREADGROUP,
                "default threadgroup {tg} exceeds the measured M1 optimum clamp of \
                 {MAX_THREADS_PER_THREADGROUP} (384 measured 13% SLOWER here)"
            );
        }
    }

    #[test]
    fn probe_reports_a_ready_device() {
        if std::env::var_os("VANADDY_NO_GPU").is_some() {
            eprintln!("SKIP: VANADDY_NO_GPU is set");
            return;
        }
        match probe() {
            GpuStatus::Ready { device } => assert!(!device.is_empty()),
            GpuStatus::Unavailable(r) => eprintln!("SKIP: no Metal device ({r})"),
            other => panic!("probe() must return Ready or Unavailable, got {other:?}"),
        }
    }
}
