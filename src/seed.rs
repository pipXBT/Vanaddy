use crate::pbkdf2_lanes::{pbkdf2_hmac_sha512, ring_pbkdf2_sha512};
use bip39::Mnemonic;

/// BIP-39 PBKDF2 iteration count. `pub` so `crate::gpu` can dispatch the GPU
/// kernel for exactly the number of rounds the CPU reference uses.
pub const PBKDF2_ROUNDS: u32 = 2048;

/// BIP-39 salt with an empty passphrase. The GPU uses a hard-coded padded copy
/// (`gpu::pack::BIP39_SALT_BLOCK`); the startup self-test's canonical-vector
/// check catches any drift.
pub const BIP39_SALT: &[u8; 8] = b"mnemonic";

/// BIP-39 canonical vector: the phrase for 16 zero bytes of entropy and its
/// seed with an empty passphrase. Not test-only: the GPU self-test checks the
/// kernel against it at runtime.
pub(crate) const CANONICAL_PHRASE: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
pub(crate) const CANONICAL_SEED_HEX: &str = "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4";

/// BIP-39 seed derivation using ring's optimized PBKDF2-HMAC-SHA512.
pub fn derive_seed(mnemonic: &Mnemonic) -> [u8; 64] {
    ring_pbkdf2_sha512(mnemonic.phrase().as_bytes(), BIP39_SALT, PBKDF2_ROUNDS)
}

/// BIP-39 seeds for `L` mnemonics at once, PBKDF2 streams interleaved.
pub fn derive_seeds<const L: usize>(mnemonics: &[Mnemonic; L]) -> [[u8; 64]; L] {
    let passwords: [&[u8]; L] = std::array::from_fn(|i| mnemonics[i].phrase().as_bytes());
    pbkdf2_hmac_sha512::<L>(passwords, BIP39_SALT, PBKDF2_ROUNDS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bip39::{Language, Mnemonic};

    /// BIP-39 canonical test vector: "abandon...about" / no passphrase
    #[test]
    fn derive_seed_matches_bip39_vector() {
        let m = Mnemonic::from_phrase(CANONICAL_PHRASE, Language::English).unwrap();
        let seed = derive_seed(&m);
        let expected = hex::decode(CANONICAL_SEED_HEX).unwrap();
        assert_eq!(seed.as_slice(), expected.as_slice());
    }

    #[test]
    fn derive_seeds_matches_derive_seed_per_lane() {
        use crate::pbkdf2_lanes::LANES;
        use bip39::MnemonicType;
        let mut mnemonics: [Mnemonic; LANES] =
            std::array::from_fn(|_| Mnemonic::new(MnemonicType::Words12, Language::English));
        mnemonics[0] = Mnemonic::from_phrase(CANONICAL_PHRASE, Language::English).unwrap();
        let seeds = derive_seeds(&mnemonics);
        assert_eq!(hex::encode(seeds[0]), CANONICAL_SEED_HEX);
        for (m, seed) in mnemonics.iter().zip(seeds.iter()) {
            assert_eq!(seed, &derive_seed(m));
        }
    }
}
