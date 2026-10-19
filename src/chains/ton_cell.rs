//! TVM cell hashing per TON whitepaper §3.1.5, for the one layout we produce:
//! the wallet-v5r1 (W5) state_init.
//!
//! A cell's "representation hash" is
//! `SHA-256(refs_desc || bits_desc || data || for_each_ref(depth_be_u16) || for_each_ref(hash))`.
//! We don't parse BOC: the W5 code cell is hardcoded as its (hash, max_depth).

use ring::digest::{Context, SHA256};

/// Wallet-v5r1 (W5) code cell root hash — constant across all W5 wallets.
///
/// Root cell hash of the W5 code BOC published in `@ton/ton`
/// (`src/wallets/v5r1/WalletContractV5R1.ts`); verified empirically against
/// Tonkeeper's W5 address for a known mnemonic. The code cell is a tree of
/// depth 6, hence the code max_depth in `wallet_v5r1_state_init_hash`.
const WALLET_V5R1_CODE_HASH: [u8; 32] = [
    0x20, 0x83, 0x4b, 0x7b, 0x72, 0xb1, 0x12, 0x14,
    0x7e, 0x1b, 0x2f, 0xb4, 0x57, 0xb8, 0x4e, 0x74,
    0xd1, 0xa3, 0x0f, 0x04, 0xf7, 0x37, 0xd4, 0xf6,
    0x2a, 0x66, 0x8e, 0x95, 0x52, 0xd2, 0xb7, 0x2f,
];

/// Wallet-v5r1 wallet_id for mainnet (global_id = -239), workchain 0,
/// wallet_version 0, subwalletNumber 0.
///
/// Per `@ton/ton`'s `WalletV5R1WalletId`, `wallet_id = global_id ^ context_id`
/// where the client context packs
/// `[has_client_context=1 : 1][workchain : i8][wallet_version=0 : u8][subwallet=0 : u15]`
/// into a signed 32-bit int. For mainnet defaults, that evaluates to
/// `0x7FFFFF11` = 2147483409.
const W5_MAINNET_WALLET_ID: i32 = 0x7FFF_FF11;

/// Representation hash of the W5 data cell (no refs, 322 bits):
/// `is_signature_allowed(1=true) || seqno(u32=0) || wallet_id(i32) ||
///  pubkey(u256) || extensions_dict(1=empty)`.
fn wallet_v5r1_data_hash(pubkey: &[u8; 32]) -> [u8; 32] {
    // The byte-aligned middle: seqno || wallet_id || pubkey (320 bits).
    let mut raw = [0u8; 40];
    raw[4..8].copy_from_slice(&W5_MAINNET_WALLET_ID.to_be_bytes());
    raw[8..].copy_from_slice(pubkey);

    // The data bits are `1 || raw || 0`, so each byte is raw shifted right
    // one bit, with the previous byte's low bit (or the sig flag) on top.
    let mut data = [0u8; 41];
    let mut carry = 0x80; // is_signature_allowed = 1
    for (out, &b) in data.iter_mut().zip(&raw) {
        *out = carry | (b >> 1);
        carry = b << 7;
    }
    // raw's last bit, extensions_dict = 0, then the completion tag bit.
    data[40] = carry | 0x20;

    let mut ctx = Context::new(&SHA256);
    ctx.update(&[
        0,  // refs_desc: ordinary cell, 0 refs
        81, // bits_desc: floor(322/8) + ceil(322/8)
    ]);
    ctx.update(&data);
    ctx.finish().as_ref().try_into().unwrap()
}

/// Representation hash of the W5 state_init cell, i.e. the account_id.
/// StateInit TL-B with no split_depth, no special, code and data refs, no
/// library.
pub fn wallet_v5r1_state_init_hash(pubkey: &[u8; 32]) -> [u8; 32] {
    let mut ctx = Context::new(&SHA256);
    ctx.update(&[
        2,           // refs_desc: ordinary cell, 2 refs (code, data)
        1,           // bits_desc: floor(5/8) + ceil(5/8)
        0b0011_0100, // data bits `00110` + completion tag bit
    ]);
    ctx.update(&6u16.to_be_bytes()); // code cell max_depth
    ctx.update(&0u16.to_be_bytes()); // data cell max_depth (no refs)
    ctx.update(&WALLET_V5R1_CODE_HASH);
    ctx.update(&wallet_v5r1_data_hash(pubkey));
    ctx.finish().as_ref().try_into().unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Self-pinned data-cell hash for W5 with an all-zero pubkey and the
    /// mainnet default wallet_id. Purely a function of this file's W5 data-cell
    /// encoding: catches any accidental regression in the 322-bit layout
    /// (sig-flag position, seqno width, wallet_id endianness, pubkey byte
    /// order, plugin-dict bit). Verified against `tonsdk` independently.
    #[test]
    fn wallet_v5r1_data_cell_zero_pubkey_pins_hash() {
        let hash = wallet_v5r1_data_hash(&[0u8; 32]);
        let expected = hex::decode(
            "0f80a4e3e2630cba3f6f37d12dbcf6afaaa015cd889eeb681a334a4fbe84cf31",
        )
        .unwrap();
        assert_eq!(&hash[..], &expected[..]);
    }

    /// W5 (v5r1) Tonkeeper round-trip pin. For the canonical mnemonic,
    /// Tonkeeper's W5 tab shows the address
    /// `UQAkFCMtkN0Q1TNP6Gk9SqYWsBFc6Aglwckj6ES4AeBEzWja`. Its account_id
    /// (bytes [2..34] of the base64url-decoded address) must equal the hash
    /// of our W5 state_init cell. If this fails, W5 derivation is wrong and
    /// no W5-flavored address we produce should be trusted.
    #[test]
    fn wallet_v5r1_matches_tonkeeper_vector() {
        use super::super::ton_mnemonic::mnemonic_to_signing_key;
        let phrase = "cloth orbit much expose crater arrow success drop verify then letter song field million quantum fame ankle stereo quote rhythm believe farm property tube";
        let sk = mnemonic_to_signing_key(phrase);
        let pubkey: [u8; 32] = sk.verifying_key().to_bytes();

        let hash = wallet_v5r1_state_init_hash(&pubkey);

        let expected = hex::decode(
            "2414232d90dd10d5334fe8693d4aa616b0115ce80825c1c923e844b801e044cd",
        )
        .unwrap();
        assert_eq!(
            &hash[..],
            &expected[..],
            "W5 state_init hash mismatch — derived pubkey = {} — if wallet_id or code hash drifted this will flag it",
            hex::encode(&pubkey),
        );
    }
}
