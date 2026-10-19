//! The Metal kernel source, embedded at compile time.
//!
//! Declared HERE — in a module compiled on every target — rather than inside
//! the `metal`-gated backend, so the source guards below run on Linux and
//! under `--no-default-features` as well. What they pin is a property of the
//! text, not of any GPU.

pub const KERNEL_SRC: &str = include_str!("pbkdf2_bip39.metal");

#[cfg(test)]
mod tests {
    use super::KERNEL_SRC;

    /// Every line of the kernel that mentions the identifier `tid`, exactly as
    /// it appears in the file.
    ///
    /// `thread_position_in_grid` is the GPU's per-thread lane id. Used as a
    /// slot offset it is correct and necessary; used as anything else it
    /// becomes key material. The bench scaffolding at `scratchpad/gpu/k2.metal:183`
    /// did exactly that (`ipad[i] = H0[i] ^ (ulong)tid`) — code of that shape
    /// passes every address test while making every wallet the tool ever emits
    /// recoverable from one 64-bit value. An exact-line allowlist is the point:
    /// any new use of `tid`, however innocent-looking, has to come through a
    /// deliberate edit to this list.
    const TID_ALLOWLIST: &[&str] = &[
        // Kernel parameter declarations — the only place the attribute appears.
        "uint tid [[thread_position_in_grid]])",
        // Bounds guard: threads past the live count of the wave do nothing.
        "if (tid >= p.count) return;",
        // Slot offsets: base + stride * tid, and nothing else.
        "device const ulong *kb = keyblocks + 16 * (ulong)tid;",
        "device Pbkdf2State *s = states + tid;",
        "device uchar *o = seeds + 64 * (ulong)tid;",
    ];

    /// True when `line` contains `tid` as a whole identifier (so `Pbkdf2State`
    /// and similar do not count).
    fn mentions_tid(line: &str) -> bool {
        line.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .any(|w| w == "tid")
    }

    /// Every thread is an independent PBKDF2 with zero cross-thread
    /// communication. Banning these four tokens eliminates the
    /// uninitialised-shared-memory and missing-barrier bug classes by
    /// construction rather than by review.
    #[test]
    fn kernel_source_bans_threadgroup_simd_barrier_atomic() {
        for banned in ["threadgroup", "simd_", "barrier", "atomic"] {
            assert!(
                !KERNEL_SRC.contains(banned),
                "banned `{banned}` present in src/gpu/pbkdf2_bip39.metal"
            );
        }
    }

    #[test]
    fn kernel_source_uses_tid_only_in_index_expressions() {
        let mut seen = 0usize;
        for (n, line) in KERNEL_SRC.lines().enumerate() {
            if !mentions_tid(line) {
                continue;
            }
            seen += 1;
            let t = line.trim();
            assert!(
                TID_ALLOWLIST.contains(&t),
                "src/gpu/pbkdf2_bip39.metal line {}: `{t}` uses `tid` outside the allowlist",
                n + 1
            );
        }
        assert_eq!(seen, 8, "expected exactly 8 lines mentioning `tid`");
        assert_eq!(
            KERNEL_SRC.matches("thread_position_in_grid").count(),
            2,
            "`thread_position_in_grid` may appear only in the two kernel parameter lists"
        );
    }

    #[test]
    fn kernel_source_declares_exactly_the_two_shipped_kernels() {
        assert_eq!(KERNEL_SRC.matches("kernel void ").count(), 2);
        assert!(KERNEL_SRC.contains("kernel void pbkdf2_prologue("));
        assert!(KERNEL_SRC.contains("kernel void pbkdf2_iterate("));
        assert!(
            !KERNEL_SRC.contains("pbkdf2_iterate_noacc"),
            "the measurement-only A/B kernel must not ship"
        );
    }
}
