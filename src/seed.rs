use crate::pbkdf2_lanes::pbkdf2_hmac_sha512;
use bip39::Mnemonic;
use std::num::NonZeroU32;

const PBKDF2_ROUNDS: u32 = 2048;

/// BIP-39 seed derivation using ring's optimized PBKDF2-HMAC-SHA512.
pub fn derive_seed(mnemonic: &Mnemonic) -> [u8; 64] {
    let password = mnemonic.phrase().as_bytes();
    let salt = b"mnemonic";
    let mut seed = [0u8; 64];
    ring::pbkdf2::derive(
        ring::pbkdf2::PBKDF2_HMAC_SHA512,
        NonZeroU32::new(PBKDF2_ROUNDS).unwrap(),
        salt,
        password,
        &mut seed,
    );
    seed
}

/// BIP-39 seeds for `L` mnemonics at once, PBKDF2 streams interleaved.
pub fn derive_seeds<const L: usize>(mnemonics: &[Mnemonic; L]) -> [[u8; 64]; L] {
    let passwords: [&[u8]; L] = std::array::from_fn(|i| mnemonics[i].phrase().as_bytes());
    pbkdf2_hmac_sha512::<L>(passwords, b"mnemonic", PBKDF2_ROUNDS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bip39::{Language, Mnemonic};

    /// BIP-39 canonical test vector: "abandon...about" / no passphrase
    #[test]
    fn derive_seed_matches_bip39_vector() {
        let m = Mnemonic::from_phrase(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            Language::English,
        ).unwrap();
        let seed = derive_seed(&m);
        let expected = hex::decode("5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4").unwrap();
        assert_eq!(seed.as_slice(), expected.as_slice());
    }

    #[test]
    fn derive_seeds_matches_derive_seed_per_lane() {
        use crate::pbkdf2_lanes::LANES;
        use bip39::MnemonicType;
        let mut mnemonics: [Mnemonic; LANES] =
            std::array::from_fn(|_| Mnemonic::new(MnemonicType::Words12, Language::English));
        mnemonics[0] = Mnemonic::from_phrase(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            Language::English,
        ).unwrap();
        let seeds = derive_seeds(&mnemonics);
        assert_eq!(
            hex::encode(seeds[0]),
            "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"
        );
        for (m, seed) in mnemonics.iter().zip(seeds.iter()) {
            assert_eq!(seed, &derive_seed(m));
        }
    }
}
