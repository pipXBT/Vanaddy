//! No-op GPU backend for every target that is not `aarch64-apple-darwin` with
//! the `metal` feature. Zero dependencies, no Metal symbols, no GPU code in the
//! binary at all — which doubles as the rollback lever
//! `cargo build --release --no-default-features`.

use crate::gpu::GpuStatus;

/// Mirror of `metal::probe`. Always unavailable; the TUI renders the reason.
pub fn probe() -> GpuStatus {
    GpuStatus::Unavailable(
        "Metal PBKDF2 offload requires Apple Silicon macOS and the `metal` feature".to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::probe;
    use crate::gpu::GpuStatus;

    #[test]
    fn probe_is_unavailable_without_the_metal_backend() {
        match probe() {
            GpuStatus::Unavailable(r) => assert!(r.contains("Apple Silicon")),
            other => panic!("the stub backend must be Unavailable, got {other:?}"),
        }
    }
}
