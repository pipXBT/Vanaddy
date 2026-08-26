pub mod bitcoin;
pub mod evm;
pub mod monero;
mod monero_wordlist;
pub mod solana;
pub mod ton;
pub mod ton_cell;
mod ton_mnemonic;

use super::matcher::Matcher;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::Sender;

/// Channel payload emitted when a vanity address is found.
#[derive(Clone)]
pub struct Match {
    pub chain: String,
    pub address: String,
    pub secret_hex: String,
    pub mnemonic: String,
    /// Proof that this row re-derives via the reference (`ring`) path.
    /// A future CSV-writing call site that takes `&Match` will be unable to
    /// receive a row without one, once that gate lands (Task 2.5) — no such
    /// call site exists yet; today's writer (`App::drain_matches`) takes
    /// `Match` by value and does not read this field. See
    /// `verify::Verified`'s module doc for what this token does and does not
    /// guarantee.
    pub verified: crate::verify::Verified,
}

pub trait Chain: Send + Sync + 'static {
    const LABEL: &'static str;
    const CHARSET: &'static str;
    const MAX_VANITY: usize;
    /// Candidates emitted per `generate_batch` call.
    const BATCH: usize = 1;

    type AddressBytes: AsRef<[u8]>;
    type SecretRaw;

    fn generate() -> (Self::AddressBytes, Self::SecretRaw, String);
    /// Emit exactly `BATCH` candidates. Chains dominated by PBKDF2 override
    /// this to derive `pbkdf2_lanes::LANES` seeds interleaved on one core.
    fn generate_batch(mut emit: impl FnMut(Self::AddressBytes, Self::SecretRaw, String)) {
        let (addr, secret, phrase) = Self::generate();
        emit(addr, secret, phrase);
    }
    fn encode_address(bytes: &Self::AddressBytes) -> String;
    fn encode_secret(raw: &Self::SecretRaw) -> String;
    fn matches_raw(matcher: &Matcher, bytes: &Self::AddressBytes) -> bool;
}

/// A chain whose entire candidate is a pure function of a 64-byte BIP-39 seed.
/// Implementing this — and nothing else — opts a chain into the GPU pipeline.
/// Evm implements it. Solana and Bitcoin each already have a private `from_seed`
/// of exactly this shape and are one line away; Ton (own mnemonic, 100k rounds,
/// different salt) and Monero (no BIP-39) structurally cannot — that is the
/// reuse seam.
///
/// A separate trait, rather than `const GPU_SEEDS: bool` plus a defaulted
/// `from_gpu_seed` whose body is `unreachable!()`: with the const, a future
/// maintainer can flip it true without implementing the tail, compile cleanly,
/// and then panic inside a Rayon worker with the terminal in raw mode. Here that
/// state is unrepresentable.
pub trait Bip39GpuChain: Chain {
    fn from_gpu_seed(seed: &[u8; 64]) -> (Self::AddressBytes, Self::SecretRaw);
    /// Re-derive from the phrase alone with the reference (`ring`) path.
    /// MUST NOT use the batched or GPU path. Returns `bool`, never `Option`.
    fn verify(address: &str, secret_hex: &str, phrase: &str) -> bool;
}

/// Runtime chain selection. The `match` is evaluated once per thread spawn,
/// outside the hot loop; `search::<C>` is monomorphized per chain.
#[derive(Clone, Copy, PartialEq)]
pub enum ChainKind {
    Solana,
    Evm,
    Bitcoin,
    Ton,
    Monero,
}

impl ChainKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Solana => solana::Solana::LABEL,
            Self::Evm => evm::Evm::LABEL,
            Self::Bitcoin => bitcoin::Bitcoin::LABEL,
            Self::Ton => ton::Ton::LABEL,
            Self::Monero => monero::Monero::LABEL,
        }
    }
    pub fn charset(self) -> &'static str {
        match self {
            Self::Solana => solana::Solana::CHARSET,
            Self::Evm => evm::Evm::CHARSET,
            Self::Bitcoin => bitcoin::Bitcoin::CHARSET,
            Self::Ton => ton::Ton::CHARSET,
            Self::Monero => monero::Monero::CHARSET,
        }
    }
    pub fn max_vanity(self) -> usize {
        match self {
            Self::Solana => solana::Solana::MAX_VANITY,
            Self::Evm => evm::Evm::MAX_VANITY,
            Self::Bitcoin => bitcoin::Bitcoin::MAX_VANITY,
            Self::Ton => ton::Ton::MAX_VANITY,
            Self::Monero => monero::Monero::MAX_VANITY,
        }
    }
    pub fn search(
        self,
        matcher: &Matcher,
        stop: &AtomicBool,
        counter: &AtomicU64,
        tx: &Sender<Match>,
    ) {
        match self {
            Self::Solana => search::<solana::Solana>(matcher, stop, counter, tx),
            Self::Evm => search::<evm::Evm>(matcher, stop, counter, tx),
            Self::Bitcoin => search::<bitcoin::Bitcoin>(matcher, stop, counter, tx),
            Self::Ton => search::<ton::Ton>(matcher, stop, counter, tx),
            Self::Monero => search::<monero::Monero>(matcher, stop, counter, tx),
        }
    }
}

/// The unchanged CPU batch, factored out so `search` and `search_hybrid` share
/// ONE body and cannot drift. Byte-identical to today's loop interior.
#[inline(always)]
fn search_cpu_step<C: Chain>(matcher: &Matcher, counter: &AtomicU64, tx: &Sender<Match>) {
    C::generate_batch(|addr_bytes, secret_raw, phrase| {
        if C::matches_raw(matcher, &addr_bytes) {
            let _ = tx.send(Match {
                chain: C::LABEL.to_string(),
                address: C::encode_address(&addr_bytes),
                secret_hex: C::encode_secret(&secret_raw),
                mnemonic: phrase,
                verified: crate::verify::Verified::cpu_reference(),
            });
        }
    });
    counter.fetch_add(C::BATCH as u64, Ordering::Relaxed);
}

/// Unchanged signature. Solana/Bitcoin/Ton/Monero still call THIS.
pub fn search<C: Chain>(
    matcher: &Matcher,
    stop: &AtomicBool,
    counter: &AtomicU64,
    tx: &Sender<Match>,
) {
    while !stop.load(Ordering::Relaxed) {
        search_cpu_step::<C>(matcher, counter, tx);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pbkdf2_lanes::LANES;
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn search_counts_whole_batches_and_honours_stop() {
        // Nine 'z's cannot occur at the start of a 44-char base58 key in 20 ms.
        let matcher = Matcher::new("zzzzzzzzz".into(), String::new(), true, ChainKind::Solana);
        let stop = AtomicBool::new(false);
        let counter = AtomicU64::new(0);
        let (tx, _rx) = mpsc::channel();
        thread::scope(|s| {
            s.spawn(|| search::<solana::Solana>(&matcher, &stop, &counter, &tx));
            thread::sleep(Duration::from_millis(20));
            stop.store(true, Ordering::Relaxed);
        });
        let n = counter.load(Ordering::Relaxed);
        assert!(n > 0, "search must make progress");
        assert_eq!(solana::Solana::BATCH, LANES);
        assert_eq!(n % LANES as u64, 0, "counter advances in whole batches, got {n}");
    }

    /// The CPU path is the reference, so its matches mint `Verified::cpu_reference()`
    /// directly — but they must still actually re-derive. This is the property the
    /// whole gate exists to preserve, asserted on the path that does not need a GPU.
    #[test]
    fn cpu_step_emits_matches_that_carry_a_token_and_re_derive() {
        use crate::chains::evm::Evm;

        // Empty prefix and empty suffix: Matcher::new leaves evm_prefix/evm_suffix
        // as None, matches_evm_raw returns true unconditionally, so one batch of
        // LANES candidates produces exactly LANES matches.
        let matcher = Matcher::new(String::new(), String::new(), false, ChainKind::Evm);
        let counter = AtomicU64::new(0);
        let (tx, rx) = mpsc::channel();

        search_cpu_step::<Evm>(&matcher, &counter, &tx);
        drop(tx);

        let got: Vec<Match> = rx.into_iter().collect();
        assert_eq!(
            got.len(),
            LANES,
            "an all-accepting matcher must emit every candidate"
        );
        assert_eq!(counter.load(Ordering::Relaxed), LANES as u64);
        for m in &got {
            assert_eq!(m.chain, "EVM");
            assert!(
                Evm::verify(&m.address, &m.secret_hex, &m.mnemonic),
                "CPU-path match must re-derive via ring: {}",
                m.address
            );
        }
    }
}
