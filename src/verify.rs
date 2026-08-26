//! The proof token that gates `vanity_wallets.csv`.
//!
//! The GPU is a *seed accelerator*: never a source of entropy, never a source of
//! truth. Nothing reaches the CSV unless a `Verified` was minted for it, and only
//! this module can mint one.
//!
//! ## Limitations
//!
//! What this guarantees: every `Match` that exists carries a `Verified` that
//! was minted for it, and that token cannot be duplicated onto a different
//! `Match`. Neither `Match` nor `Verified` derives `Clone` or `Copy` — there is
//! no `.clone()` to call on either, and no implicit copy of a `Verified` out of
//! a shared `&Match`. `Verified`'s only field is a private unit, so the only way
//! to obtain a value of this type anywhere in the crate is to call
//! `Verified::cpu_reference()` or `Verified::gpu_reverified()`, both
//! `pub(crate)` and both defined in this module. Concretely: the forgery
//! `let mut fake = real.clone(); fake.address = "...".to_string();`, which
//! compiled and ran cleanly while `Match` derived `Clone`, no longer compiles
//! at all (`error[E0599]: no method named 'clone' found for struct
//! 'chains::Match'`).
//!
//! What this does NOT guarantee: `Verified` still carries no binding to the
//! data it attests to — the token proves "some CPU-reference derivation
//! happened," not "*this* `address`/`secret_hex`/`mnemonic` is what it
//! produced." And moving is still possible where cloning is not: code that
//! owns a `Match` outright (not just a `&Match`) could destructure it —
//! `let Match { verified, .. } = m;` — and move that `verified` into a
//! differently-built `Match` literal, since Rust permits a partial move out of
//! a non-`Copy` struct with no `Drop` impl. No code in the tree does this: both
//! mint sites (`search_cpu_step` in `chains/mod.rs`, `emit_gpu_match`) build
//! their `Match` immediately from a token obtained in the same expression, and
//! neither destructures an existing one. But it remains a deliberate act a
//! future maintainer could still write — unlike the accidental-looking
//! `.clone()` this change closes off entirely.

/// Proof that a Match's phrase re-derives to its address and secret via the
/// reference (`ring`) path — either because the CPU path produced it directly
/// (the CPU path IS the reference, per CLAUDE.md) or because a GPU-sourced
/// candidate was re-derived and agreed. The private unit field means only this
/// module can mint one, and `app::append_match_row(path: &Path, m: &Match)` —
/// the crate's single CSV-row writer — takes `&Match`, so it cannot receive a
/// row without one. See the module doc's Limitations
/// section above for what this token does and does not guarantee.
pub struct Verified(());

impl Verified {
    /// The CPU path derives with `derive_seeds`/`derive_seed` and encodes from
    /// what it derived; there is nothing to cross-check it against that is more
    /// trusted than itself.
    pub(crate) fn cpu_reference() -> Self {
        Verified(())
    }

    /// A GPU-sourced candidate that was re-derived by `verify_gpu` and agreed
    /// with the CPU reference. Named symmetrically with `cpu_reference` so
    /// every mint site is a distinct, greppable call: `grep -n
    /// 'cpu_reference\|gpu_reverified'` finds all of them.
    pub(crate) fn gpu_reverified() -> Self {
        Verified(())
    }
}

/// Re-derive a GPU-sourced candidate from its 16-byte entropy alone and confirm
/// it reproduces the address the GPU seed produced. `None` ⇒ reject.
///
/// NOTE the polarity: there is deliberately no `Option<bool>` and no
/// "unverifiable" arm. Every failure mode — unparseable entropy, bad checksum,
/// address disagreement — is a rejection. An earlier design mapped
/// `Some(true) | None => Some(Verified(()))`, meaning the token proved "verified
/// OR the verifier declared itself unable to check"; the idiomatic `.ok()?` in
/// any later edit then converts a corrupted phrase into a PASS, turning the gate
/// into a decoration on exactly the input it exists to catch.
pub fn verify_gpu<C: crate::chains::Bip39GpuChain>(
    entropy: &[u8; 16],
    gpu_addr: &C::AddressBytes,
) -> Option<(C::AddressBytes, C::SecretRaw, String, Verified)> {
    let m = bip39::Mnemonic::from_entropy(entropy, bip39::Language::English).ok()?;
    // ring::pbkdf2 (src/seed.rs:8) — the reference path, never the 4-lane NEON
    // path and never the GPU.
    let seed = crate::seed::derive_seed(&m);
    let (addr, secret) = C::from_gpu_seed(&seed);
    if addr.as_ref() != gpu_addr.as_ref() {
        return None;
    }
    // The phrase handed back is rebuilt here by trusted CPU code, so the String
    // that ends up in the CSV is never one the GPU thread touched.
    Some((
        addr,
        secret,
        m.phrase().to_string(),
        Verified::gpu_reverified(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chains::evm::Evm;
    use crate::chains::{Bip39GpuChain, Chain};
    use bip39::{Language, Mnemonic, MnemonicType};

    /// Deterministic entropy so a red build replays exactly. Every 16-byte array
    /// is valid BIP-39 entropy — the checksum is computed FROM it, not checked
    /// against it. `fixed_entropy(0)` is all zeros, i.e. "abandon … about".
    fn fixed_entropy(i: u8) -> [u8; 16] {
        let mut e = [0u8; 16];
        e[15] = i;
        e
    }

    /// Build what the GPU would have delivered, but with `ring` doing the PBKDF2.
    fn ring_candidate(i: u8) -> ([u8; 16], [u8; 20]) {
        let entropy = fixed_entropy(i);
        let m = Mnemonic::from_entropy(&entropy, Language::English).unwrap();
        let (addr, _sk) = Evm::from_gpu_seed(&crate::seed::derive_seed(&m));
        (entropy, addr)
    }

    /// Anchor the gate to external ground truth first: entropy = 16 zero bytes is
    /// the BIP-39 canonical phrase, whose m/44'/60'/0'/0/0 address is the pinned
    /// first MetaMask account.
    #[test]
    fn verify_gpu_accepts_the_bip39_canonical_vector() {
        let (entropy, gpu_addr) = ring_candidate(0);
        let (addr, secret, phrase, _proof) =
            verify_gpu::<Evm>(&entropy, &gpu_addr).expect("canonical vector must verify");
        assert_eq!(
            hex::encode(addr),
            "9858effd232b4033e47d90003d41ec34ecaeda94"
        );
        assert_eq!(
            phrase,
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        );
        assert!(Evm::verify(
            &Evm::encode_address(&addr),
            &Evm::encode_secret(&secret),
            &phrase
        ));
    }

    #[test]
    fn verify_gpu_accepts_a_real_candidate() {
        let (entropy, gpu_addr) = ring_candidate(37);
        let (addr, secret, phrase, _proof) =
            verify_gpu::<Evm>(&entropy, &gpu_addr).expect("an honest candidate must verify");
        assert_eq!(
            addr, gpu_addr,
            "the returned address is the CPU-derived one"
        );
        // The phrase handed back is rebuilt by trusted CPU code from the entropy,
        // and must round-trip to the same entropy.
        let round = Mnemonic::from_phrase(&phrase, Language::English).unwrap();
        assert_eq!(round.entropy(), &entropy[..]);
        assert!(Evm::verify(
            &Evm::encode_address(&addr),
            &Evm::encode_secret(&secret),
            &phrase
        ));
    }

    #[test]
    fn verify_gpu_rejects_flipped_address_nibble() {
        let (entropy, gpu_addr) = ring_candidate(9);
        let mut tampered = gpu_addr;
        tampered[0] ^= 0x10; // one nibble
        assert!(
            verify_gpu::<Evm>(&entropy, &tampered).is_none(),
            "a GPU address that does not re-derive must be REJECTED, never accepted"
        );
    }

    /// The mis-pairing case: entropy from candidate A, address from candidate B.
    /// This is the failure mode that a `zip` bug in the producer would produce,
    /// and it must not be able to reach the CSV.
    #[test]
    fn verify_gpu_rejects_entropy_from_a_different_candidate() {
        let (entropy_a, _addr_a) = ring_candidate(11);
        let (_entropy_b, addr_b) = ring_candidate(12);
        assert!(verify_gpu::<Evm>(&entropy_a, &addr_b).is_none());
    }

    #[test]
    fn verify_gpu_result_carries_a_usable_secret_for_the_returned_address() {
        let (entropy, gpu_addr) = ring_candidate(200);
        let (addr, secret, phrase, _proof) = verify_gpu::<Evm>(&entropy, &gpu_addr).unwrap();
        let (addr2, secret2) = Evm::from_gpu_seed(&crate::seed::derive_seed(
            &Mnemonic::from_phrase(&phrase, Language::English).unwrap(),
        ));
        assert_eq!(addr, addr2);
        assert_eq!(Evm::encode_secret(&secret), Evm::encode_secret(&secret2));
        let _ = MnemonicType::Words12; // keep the import honest
    }

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

    /// Regression guard, not a driver: it passes the moment this file exists.
    /// Its job is to FAIL LATER, if someone re-adds a `Clone`/`Copy` derive to
    /// `Verified` — that would let a caller holding one `&Match` copy its token
    /// onto a different, fabricated `Match`. See this module's `## Limitations`
    /// doc for the forgery this closes.
    ///
    /// A `compile_fail` doc test would be the natural spelling, but this crate
    /// is binary-only (no `lib.rs`, see CLAUDE.md), and `cargo test` never runs
    /// doc tests for a bin target — the doctest would silently never execute.
    /// So the property is pinned at the source level, like the test above.
    #[test]
    fn verified_source_pins_the_absence_of_a_forging_derive() {
        let src = include_str!("verify.rs");
        // concat! for the same anti-self-match reason as the test above: this
        // test's own source only ever spells the declaration across two
        // separate string literals, so `find` cannot match this call site —
        // only the real declaration.
        let decl = concat!("pub struct ", "Verified(());");
        assert_eq!(
            src.matches(decl).count(),
            1,
            "expected exactly one occurrence of Verified's declaration; the source may have \
             changed shape"
        );
        let at = src.find(decl).expect("Verified's declaration must exist");
        // Walk upward over the WHOLE contiguous run of attribute lines above
        // the declaration — not just the one line immediately above it — so a
        // derive stacked under an unrelated attribute (e.g. `#[repr(...)]`)
        // can't hide from this check. `contains`, not `starts_with`, so
        // `#[cfg_attr(test, derive(Clone))]` is caught too. Blank lines and
        // `//`/`///` line comments and `/* ... */` block comments (single- or
        // multi-line) are SKIPPED rather than stopping the walk (any of these
        // between the derive and the declaration must not hide it either) —
        // but a comment's own text is never inspected for "derive", only
        // lines starting with `#[` are, so a doc comment reflow (even one
        // that happens to say "derive" in prose, or a `/* */` block that
        // does) still can't fail this test. The walk stops only at the first
        // real code line.
        let mut forging_attr = None;
        let mut in_block_comment = false;
        for line in src[..at].lines().rev() {
            let line = line.trim();
            if in_block_comment {
                // Comment content is never inspected for "derive" — only the
                // opening delimiter, which ends the skip, is looked for.
                if line.contains("/*") {
                    in_block_comment = false;
                }
                continue;
            }
            if line.is_empty() || line.starts_with("//") {
                continue;
            }
            if let (Some(open), Some(close)) = (line.find("/*"), line.rfind("*/")) {
                if open < close {
                    continue; // self-contained /* ... */ on one line
                }
            }
            if line.ends_with("*/") {
                // The closing delimiter of a block comment that opened on an
                // earlier (higher, so later in this reverse walk) line.
                in_block_comment = true;
                continue;
            }
            if line.starts_with("#[") {
                if line.contains("derive") {
                    forging_attr = Some(line);
                    break;
                }
                continue;
            }
            break;
        }
        assert!(
            forging_attr.is_none(),
            "Verified must have no #[derive(...)] (directly or via cfg_attr) anywhere in the \
             attribute run above it (found: {forging_attr:?}). Clone or Copy would let a caller \
             duplicate a minted token onto unrelated data."
        );
    }
}
