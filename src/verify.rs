//! The proof token that gates `vanity_wallets.csv`.
//!
//! The GPU is a *seed accelerator*: never a source of entropy, never a source of
//! truth. Nothing reaches the CSV unless a `Verified` was minted for it, and only
//! this module can mint one.
//!
//! ## Limitations
//!
//! What this guarantees: a `Match` cannot be constructed anywhere in the crate
//! without a `Verified` minted by this module — there is no way to produce a
//! `Match` value at all without calling `Verified::cpu_reference()` (or a future
//! GPU-path minting function) first.
//!
//! What this does NOT guarantee: that the token corresponds to *this specific*
//! `Match`'s own `address`/`secret_hex`/`mnemonic`. `Verified` carries no binding
//! to the data it attests to, `Match::verified` is `pub`, and `Verified` is
//! `Copy` — so any code already holding a legitimately-minted token (which only
//! needs a shared `&Match` reference, thanks to `Copy`) could in principle copy
//! that token onto an unrelated, fabricated `Match` literal. Nothing in the type
//! system prevents this. No code in the tree does this today (as of Task 2.2,
//! the only mint site is `cpu_reference()`, called exactly once per genuine
//! CPU-derived match), but the gap is real and becomes more consequential once
//! a second mint site (the GPU path) exists and a batch loop could reuse one
//! candidate's token across others.
//!
//! Whether `Verified` should drop `Copy`, or bind to a fingerprint of the data
//! it attests to, is an open decision **deferred to Task 5.2** (where the GPU
//! path's `emit_gpu_match` mint site lands) rather than decided speculatively
//! here.

/// Proof that a Match's phrase re-derives to its address and secret via the
/// reference (`ring`) path — either because the CPU path produced it directly
/// (the CPU path IS the reference, per CLAUDE.md) or because a GPU-sourced
/// candidate was re-derived and agreed. The private unit field means only this
/// module can mint one, and a future CSV-writing call site that takes `&Match`
/// will be unable to receive a row without one, once that gate lands (Task
/// 2.5) — no such call site exists yet. See the module doc's Limitations
/// section above for what this token does and does not guarantee.
#[derive(Clone, Copy)]
pub struct Verified(());

impl Verified {
    /// The CPU path derives with `derive_seeds`/`derive_seed` and encodes from
    /// what it derived; there is nothing to cross-check it against that is more
    /// trusted than itself.
    pub(crate) fn cpu_reference() -> Self {
        Verified(())
    }
}

#[cfg(test)]
mod tests {
    /// Regression guard, not a driver: it passes the moment this file exists.
    /// Its job is to FAIL LATER, if someone widens the tuple field.
    ///
    /// A `compile_fail` doc test would be the natural spelling, but this crate is
    /// binary-only (no `lib.rs`, see CLAUDE.md), and `cargo test` never runs doc
    /// tests for a bin target — the doctest would silently never execute. So the
    /// property is pinned at the source level instead.
    #[test]
    fn verify_source_pins_the_private_field_declaration() {
        let src = include_str!("verify.rs");
        // The needles are assembled with concat! so that this test's OWN source
        // text does not contain them — otherwise both assertions would match
        // themselves and prove nothing.
        let declared = concat!("pub struct Verified(", "());");
        let forged = concat!("pub struct Verified(", "pub ");
        assert!(
            src.contains(declared),
            "Verified must keep exactly one PRIVATE unit field"
        );
        assert!(
            !src.contains(forged),
            "Verified's field must never become pub — any module could then forge a proof"
        );
    }
}
