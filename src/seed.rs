use crate::pbkdf2_lanes::pbkdf2_hmac_sha512;
use bip39::Mnemonic;
use std::num::NonZeroU32;

/// BIP-39 PBKDF2 iteration count. `pub` so `crate::gpu` can dispatch the GPU
/// kernel for exactly the number of rounds the CPU reference uses.
pub const PBKDF2_ROUNDS: u32 = 2048;

/// BIP-39 salt with an empty passphrase. `pub` so `crate::gpu::pack` builds the
/// GPU's salt block from the same bytes `derive_seed` hands to `ring`.
pub const BIP39_SALT: &[u8; 8] = b"mnemonic";

/// BIP-39 seed derivation using ring's optimized PBKDF2-HMAC-SHA512.
pub fn derive_seed(mnemonic: &Mnemonic) -> [u8; 64] {
    let password = mnemonic.phrase().as_bytes();
    let mut seed = [0u8; 64];
    ring::pbkdf2::derive(
        ring::pbkdf2::PBKDF2_HMAC_SHA512,
        NonZeroU32::new(PBKDF2_ROUNDS).unwrap(),
        BIP39_SALT,
        password,
        &mut seed,
    );
    seed
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
        let m = Mnemonic::from_phrase(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            Language::English,
        ).unwrap();
        let seed = derive_seed(&m);
        let expected = hex::decode("5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4").unwrap();
        assert_eq!(seed.as_slice(), expected.as_slice());
    }

    /// The GPU dispatches `PBKDF2_ROUNDS` rounds over a salt block packed from
    /// `BIP39_SALT`. Pin that those two exported constants, fed to the *other*
    /// CPU implementation, still reproduce the canonical BIP-39 vector - so a
    /// drift in either is caught here rather than in a wallet nobody can open.
    #[test]
    fn exported_constants_reproduce_the_pinned_bip39_vector() {
        use crate::pbkdf2_lanes::pbkdf2_hmac_sha512;
        assert_eq!(PBKDF2_ROUNDS, 2048);
        assert_eq!(BIP39_SALT, b"mnemonic");
        let m = Mnemonic::from_phrase(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            Language::English,
        ).unwrap();
        let seeds = pbkdf2_hmac_sha512::<1>([m.phrase().as_bytes()], BIP39_SALT, PBKDF2_ROUNDS);
        assert_eq!(
            hex::encode(seeds[0]),
            "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"
        );
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
