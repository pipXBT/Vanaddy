//! The proof token that gates `vanity_wallets.csv`.
//!
//! The GPU is a *seed accelerator*: never a source of entropy, never a source of
//! truth. Nothing reaches the CSV unless a `Verified` was minted for it, and only
//! this module can mint one.

/// Proof that a Match's phrase re-derives to its address and secret via the
/// reference (`ring`) path — either because the CPU path produced it directly
/// (the CPU path IS the reference, per CLAUDE.md) or because a GPU-sourced
/// candidate was re-derived and agreed. The private unit field means only this
/// module can mint one, and `app::append_match_row` takes a `&Match`, which
/// cannot exist without one.
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
    fn verified_token_field_is_private_so_only_this_module_can_mint_one() {
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
