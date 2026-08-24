//! TON native 24-word mnemonic derivation (Tonkeeper / MyTonWallet / @ton/crypto compatible).
//!
//! Unlike BIP-39, TON reuses the 2048-word English wordlist but derives the Ed25519
//! seed via HMAC-SHA512 of the phrase, an acceptance filter (basic_seed[0] == 0)
//! and a 100,000-iter PBKDF2-HMAC-SHA512. The filter accepts ~1/256 of phrases,
//! so generation is roughly 100x slower than other chains' BIP-39 pipelines.
//! Both PBKDF2 stages run `pbkdf2_lanes::LANES` phrases interleaved (see
//! `generate_ton_wallets`), which halves the per-wallet cost on Apple Silicon.
//!
//! Reference: https://github.com/toncenter/tonweb-mnemonic/blob/master/src/functions/generate.ts

use crate::pbkdf2_lanes::{pbkdf2_hmac_sha512, LANES};
use bip39::{Language, Mnemonic, MnemonicType};
use ed25519_dalek::SigningKey;
use ring::{hmac, pbkdf2};
use std::num::NonZeroU32;

/// PBKDF2 rounds used for the fast "basic_seed" acceptance check (~100_000 / 256).
const PBKDF2_BASIC_ITER: u32 = 390;
/// PBKDF2 rounds used for the final Ed25519 seed derivation.
const PBKDF2_SEED_ITER: u32 = 100_000;

/// Compute the TON mnemonic entropy per `@ton/crypto`:
/// `HMAC_SHA512(key = phrase, msg = password)`. We always use an empty password,
/// so msg is empty. This direction (phrase-as-key) matches Tonkeeper's own
/// `mnemonicToEntropy(words, password)` and is required for addresses computed
/// by vanaddy to match those computed by Tonkeeper.
fn hmac_sha512_empty_key(phrase: &[u8]) -> [u8; 64] {
    let key = hmac::Key::new(hmac::HMAC_SHA512, phrase);
    let tag = hmac::sign(&key, &[]);
    let mut out = [0u8; 64];
    out.copy_from_slice(tag.as_ref());
    out
}

/// PBKDF2-HMAC-SHA512 using ring (already a repo dependency).
fn pbkdf2_sha512(password: &[u8], salt: &[u8], iter: u32, out_len: usize) -> Vec<u8> {
    let mut out = vec![0u8; out_len];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA512,
        NonZeroU32::new(iter).unwrap(),
        salt,
        password,
        &mut out,
    );
    out
}

/// Generate a TON wallet compatible with Tonkeeper / @ton/crypto.
///
/// Loops until a candidate 24-word phrase passes the TON acceptance filter
/// (basic_seed[0] == 0), then returns (phrase, Ed25519 signing key).
///
/// Uses `Mnemonic::new(Words24, English)` for random wordlist sampling. The
/// BIP-39 checksum word is irrelevant to TON's derivation — we only use the
/// phrase string as HMAC/PBKDF2 input.
pub fn generate_ton_wallet() -> (String, SigningKey) {
    loop {
        let mnemonic = Mnemonic::new(MnemonicType::Words24, Language::English);
        let phrase = mnemonic.phrase().to_string();

        let entropy = hmac_sha512_empty_key(phrase.as_bytes());
        let basic_seed = pbkdf2_sha512(
            &entropy,
            b"TON seed version",
            PBKDF2_BASIC_ITER,
            64,
        );
        if basic_seed[0] != 0 {
            continue;
        }

        let seed_bytes = pbkdf2_sha512(
            &entropy,
            b"TON default seed",
            PBKDF2_SEED_ITER,
            32,
        );
        let mut seed_arr = [0u8; 32];
        seed_arr.copy_from_slice(&seed_bytes);
        let signing_key = SigningKey::from_bytes(&seed_arr);
        return (phrase, signing_key);
    }
}

/// Generate `LANES` Tonkeeper-compatible wallets, running the acceptance
/// filter and the final 100k-iteration PBKDF2 for all lanes interleaved.
pub fn generate_ton_wallets() -> [(String, SigningKey); LANES] {
    // Phase 1: trial phrases LANES at a time until LANES of them pass the filter.
    let mut accepted: Vec<(String, [u8; 64])> = Vec::with_capacity(LANES);
    while accepted.len() < LANES {
        let phrases: [String; LANES] = std::array::from_fn(|_| {
            Mnemonic::new(MnemonicType::Words24, Language::English)
                .phrase()
                .to_string()
        });
        let entropies: [[u8; 64]; LANES] =
            std::array::from_fn(|i| hmac_sha512_empty_key(phrases[i].as_bytes()));
        let passwords: [&[u8]; LANES] = std::array::from_fn(|i| entropies[i].as_slice());
        let basic = pbkdf2_hmac_sha512::<LANES>(passwords, b"TON seed version", PBKDF2_BASIC_ITER);
        for (i, phrase) in phrases.into_iter().enumerate() {
            if basic[i][0] == 0 && accepted.len() < LANES {
                accepted.push((phrase, entropies[i]));
            }
        }
    }

    // Phase 2: the expensive seed derivation for all accepted phrases at once.
    let passwords: [&[u8]; LANES] = std::array::from_fn(|i| accepted[i].1.as_slice());
    let seeds = pbkdf2_hmac_sha512::<LANES>(passwords, b"TON default seed", PBKDF2_SEED_ITER);
    let mut accepted = accepted.into_iter();
    std::array::from_fn(|i| {
        let (phrase, _entropy) = accepted.next().expect("LANES phrases accepted");
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&seeds[i][..32]);
        (phrase, SigningKey::from_bytes(&seed))
    })
}

/// Recover the Ed25519 signing key from an existing TON mnemonic phrase.
/// Used for round-trip determinism tests.
#[cfg(test)]
pub fn mnemonic_to_signing_key(phrase: &str) -> SigningKey {
    let entropy = hmac_sha512_empty_key(phrase.as_bytes());
    let seed_bytes = pbkdf2_sha512(
        &entropy,
        b"TON default seed",
        PBKDF2_SEED_ITER,
        32,
    );
    let mut seed_arr = [0u8; 32];
    seed_arr.copy_from_slice(&seed_bytes);
    SigningKey::from_bytes(&seed_arr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_produces_24_word_phrase() {
        let (phrase, _sk) = generate_ton_wallet();
        let words: Vec<&str> = phrase.split_whitespace().collect();
        assert_eq!(words.len(), 24, "TON phrase must be 24 words, got {}", words.len());
    }

    #[test]
    fn round_trip_deterministic() {
        let (phrase, sk1) = generate_ton_wallet();
        let sk2 = mnemonic_to_signing_key(&phrase);
        assert_eq!(
            sk1.to_bytes(),
            sk2.to_bytes(),
            "re-deriving from the same phrase must yield identical signing key"
        );
    }

    #[test]
    fn batch_wallets_match_single_path_and_pass_filter() {
        let wallets = generate_ton_wallets();
        let mut phrases: Vec<&str> = wallets.iter().map(|(p, _)| p.as_str()).collect();
        for (phrase, sk) in &wallets {
            assert_eq!(phrase.split_whitespace().count(), 24);
            assert_eq!(sk.to_bytes(), mnemonic_to_signing_key(phrase).to_bytes());
            let entropy = hmac_sha512_empty_key(phrase.as_bytes());
            let basic = pbkdf2_sha512(&entropy, b"TON seed version", PBKDF2_BASIC_ITER, 64);
            assert_eq!(basic[0], 0, "every batch phrase must pass the acceptance filter");
        }
        phrases.sort_unstable();
        phrases.dedup();
        assert_eq!(phrases.len(), wallets.len(), "phrases must be distinct");
    }

    #[test]
    fn generated_phrase_passes_basic_seed_filter() {
        // By construction, generate_ton_wallet only returns phrases whose
        // basic_seed[0] == 0. Re-run the filter on a freshly generated phrase
        // to confirm that invariant holds.
        let (phrase, _sk) = generate_ton_wallet();
        let entropy = hmac_sha512_empty_key(phrase.as_bytes());
        let basic_seed = pbkdf2_sha512(
            &entropy,
            b"TON seed version",
            PBKDF2_BASIC_ITER,
            64,
        );
        assert_eq!(basic_seed[0], 0, "accepted phrase must satisfy basic_seed[0] == 0");
    }
}
