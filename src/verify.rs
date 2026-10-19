//! The gate between the GPU and `vanity_wallets.csv`.
//!
//! The GPU is a *seed accelerator*: never a source of entropy, never a source of
//! truth. A GPU-sourced candidate becomes a `Match` (and so a CSV row) only in
//! `chains::emit_gpu_match`, and only when `verify_gpu` re-derived it on the CPU
//! from its entropy and the address agreed. `None` is a rejection.

use crate::chains::evm::Evm;

/// Re-derive a GPU-sourced candidate from its 16-byte entropy alone and confirm
/// it reproduces the address the GPU seed produced. `None` ⇒ reject.
///
/// Every failure mode — unparseable entropy, bad checksum, address
/// disagreement — is `None`. There is deliberately no "unverifiable" arm that
/// could turn a corrupted candidate into a pass.
pub fn verify_gpu(
    entropy: &[u8; 16],
    gpu_addr: &[u8; 20],
) -> Option<([u8; 20], secp256k1::SecretKey, String)> {
    let m = bip39::Mnemonic::from_entropy(entropy, bip39::Language::English).ok()?;
    // ring::pbkdf2 (src/seed.rs:8) — the reference path, never the 4-lane NEON
    // path and never the GPU.
    let seed = crate::seed::derive_seed(&m);
    let (addr, secret) = Evm::from_seed(&seed);
    if addr != *gpu_addr {
        return None;
    }
    // The phrase handed back is rebuilt here by trusted CPU code, so the String
    // that ends up in the CSV is never one the GPU thread touched.
    Some((addr, secret, m.phrase().to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chains::tests::{gpu_test_entropy, ring_seed_block};
    use crate::chains::Chain;
    use bip39::{Language, Mnemonic};

    /// Anchor the gate to external ground truth first: entropy = 16 zero bytes is
    /// the BIP-39 canonical phrase, whose m/44'/60'/0'/0/0 address is the pinned
    /// first MetaMask account.
    #[test]
    fn verify_gpu_accepts_the_bip39_canonical_vector() {
        let (_, addrs) = ring_seed_block(1);
        let (addr, secret, phrase) =
            verify_gpu(&gpu_test_entropy(0), &addrs[0]).expect("canonical vector must verify");
        assert_eq!(
            hex::encode(addr),
            "9858effd232b4033e47d90003d41ec34ecaeda94"
        );
        assert_eq!(phrase, crate::seed::CANONICAL_PHRASE);
        assert!(Evm::verify(
            &Evm::encode_address(&addr),
            &Evm::encode_secret(&secret),
            &phrase
        ));
    }

    #[test]
    fn verify_gpu_rejects_flipped_address_nibble() {
        let (_, addrs) = ring_seed_block(10);
        let mut tampered = addrs[9];
        tampered[0] ^= 0x10; // one nibble
        assert!(
            verify_gpu(&gpu_test_entropy(9), &tampered).is_none(),
            "a GPU address that does not re-derive must be REJECTED, never accepted"
        );
    }

    /// The mis-pairing case: entropy from candidate A, address from candidate B.
    /// This is the failure mode that a `zip` bug in the producer would produce,
    /// and it must not be able to reach the CSV.
    #[test]
    fn verify_gpu_rejects_entropy_from_a_different_candidate() {
        let (_, addrs) = ring_seed_block(13);
        assert!(verify_gpu(&gpu_test_entropy(11), &addrs[12]).is_none());
    }

    /// An honest candidate verifies, and what comes back is the CPU-derived
    /// address, a phrase that round-trips to the same entropy, and a secret that
    /// re-derives from that phrase.
    #[test]
    fn verify_gpu_result_carries_a_usable_secret_for_the_returned_address() {
        let (_, addrs) = ring_seed_block(38);
        let entropy = gpu_test_entropy(37);
        let (addr, secret, phrase) =
            verify_gpu(&entropy, &addrs[37]).expect("an honest candidate must verify");
        assert_eq!(
            addr, addrs[37],
            "the returned address is the CPU-derived one"
        );
        let round = Mnemonic::from_phrase(&phrase, Language::English).unwrap();
        assert_eq!(round.entropy(), &entropy[..]);
        assert!(Evm::verify(
            &Evm::encode_address(&addr),
            &Evm::encode_secret(&secret),
            &phrase
        ));
    }
}
