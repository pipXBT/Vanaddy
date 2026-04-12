use super::super::bip32::{bip32_derive_secp256k1, EVM_PATH};
use super::Chain;
use super::super::matcher::Matcher;
use super::super::seed::derive_seed;
use bip39::{Language, Mnemonic, MnemonicType};
use sha3::{Digest, Keccak256};

pub struct Evm;

impl Chain for Evm {
    const LABEL: &'static str = "EVM";
    const CHARSET: &'static str = "0123456789abcdefABCDEF";
    const MAX_VANITY: usize = 8;

    type AddressBytes = [u8; 20];
    type SecretRaw = libsecp256k1::SecretKey;

    fn generate() -> (Self::AddressBytes, Self::SecretRaw, String) {
        let mnemonic = Mnemonic::new(MnemonicType::Words12, Language::English);
        let seed_bytes = derive_seed(&mnemonic);
        let secret_key = bip32_derive_secp256k1(&seed_bytes, &EVM_PATH);
        let public_key = libsecp256k1::PublicKey::from_secret_key(&secret_key);
        let pubkey_bytes = public_key.serialize();
        let pubkey_uncompressed = &pubkey_bytes[1..];
        let hash = Keccak256::digest(pubkey_uncompressed);

        let mut addr = [0u8; 20];
        addr.copy_from_slice(&hash[12..]);

        (addr, secret_key, mnemonic.phrase().to_string())
    }

    fn encode_address(bytes: &Self::AddressBytes) -> String {
        format!("0x{}", hex::encode(bytes))
    }

    fn encode_secret(raw: &Self::SecretRaw) -> String {
        hex::encode(raw.serialize())
    }

    fn matches_raw(matcher: &Matcher, bytes: &Self::AddressBytes) -> bool {
        matcher.matches_evm_raw(bytes)
    }
}
