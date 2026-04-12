pub mod evm;
pub mod solana;

use super::matcher::Matcher;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::Sender;

/// Channel payload emitted when a vanity address is found.
/// (chain_label, address, secret_hex, mnemonic)
pub type MatchPayload = (String, String, String, String);

pub trait Chain: Send + Sync + 'static {
    const LABEL: &'static str;
    const CHARSET: &'static str;
    const MAX_VANITY: usize;

    type AddressBytes: AsRef<[u8]>;
    type SecretRaw;

    fn generate() -> (Self::AddressBytes, Self::SecretRaw, String);
    fn encode_address(bytes: &Self::AddressBytes) -> String;
    fn encode_secret(raw: &Self::SecretRaw) -> String;
    fn matches_raw(matcher: &Matcher, bytes: &Self::AddressBytes) -> bool;
}

/// Runtime chain selection. The `match` is evaluated once per thread spawn,
/// outside the hot loop; `search::<C>` is monomorphized per chain.
#[derive(Clone, Copy, PartialEq)]
pub enum ChainKind {
    Solana,
    Evm,
}

impl ChainKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Solana => solana::Solana::LABEL,
            Self::Evm => evm::Evm::LABEL,
        }
    }
    pub fn charset(self) -> &'static str {
        match self {
            Self::Solana => solana::Solana::CHARSET,
            Self::Evm => evm::Evm::CHARSET,
        }
    }
    pub fn max_vanity(self) -> usize {
        match self {
            Self::Solana => solana::Solana::MAX_VANITY,
            Self::Evm => evm::Evm::MAX_VANITY,
        }
    }
    pub fn search(
        self,
        matcher: &Matcher,
        stop: &AtomicBool,
        counter: &AtomicU64,
        tx: &Sender<MatchPayload>,
    ) {
        match self {
            Self::Solana => search::<solana::Solana>(matcher, stop, counter, tx),
            Self::Evm => search::<evm::Evm>(matcher, stop, counter, tx),
        }
    }
}

#[inline]
pub fn search<C: Chain>(
    matcher: &Matcher,
    stop: &AtomicBool,
    counter: &AtomicU64,
    tx: &Sender<MatchPayload>,
) {
    while !stop.load(Ordering::Relaxed) {
        let (addr_bytes, secret_raw, phrase) = C::generate();
        counter.fetch_add(1, Ordering::Relaxed);

        if C::matches_raw(matcher, &addr_bytes) {
            let addr = C::encode_address(&addr_bytes);
            let secret_hex = C::encode_secret(&secret_raw);
            let _ = tx.send((C::LABEL.to_string(), addr, secret_hex, phrase));
        }
    }
}
