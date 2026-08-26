pub mod bitcoin;
pub mod evm;
pub mod monero;
mod monero_wordlist;
pub mod solana;
pub mod ton;
pub mod ton_cell;
mod ton_mnemonic;

use super::matcher::Matcher;
use crate::gpu::{GpuDisableReason, GpuHealth};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::Sender;

/// Channel payload emitted when a vanity address is found.
pub struct Match {
    pub chain: String,
    pub address: String,
    pub secret_hex: String,
    pub mnemonic: String,
    /// Proof that this row re-derives via the reference (`ring`) path.
    /// `app::append_match_row(path: &Path, m: &Match)` is the crate's single
    /// CSV-row writer, and takes `&Match` — so it cannot receive a row without
    /// one, even though it never reads this field's value directly.
    /// `App::drain_matches` routes every emitted match through it. See
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

/// Stop check granularity inside a GPU block: 16 × C::BATCH = 64 candidates
/// ≈ 3.2 ms at the measured 50.5 µs tail — comparable to the CPU path's
/// ~1.3 ms, versus 25.9 ms for a whole 512-block.
const GPU_CHUNK_BATCHES: usize = 16;

/// The EVM search loop when a GPU producer may be feeding it. `try_recv` is
/// non-blocking and therefore self-balancing: when the GPU is fast the workers
/// drain it, when the GPU stalls (compositor contention drops it 2–4×) they fall
/// straight through to the CPU batch with no static split to get wrong.
pub fn search_hybrid<C: Bip39GpuChain>(
    matcher: &Matcher,
    stop: &AtomicBool,
    counter: &AtomicU64,
    tx: &Sender<Match>,
    gpu: Option<&crate::gpu::GpuRx>,
    health: &crate::gpu::GpuHealth,
) {
    while !stop.load(Ordering::Relaxed) {
        if let Some(rx) = gpu {
            if !health.disable.load(Ordering::Relaxed) {
                if let Ok(block) = rx.try_recv() {
                    drain_gpu_block::<C>(&block, matcher, stop, counter, tx, health);
                    continue; // block is zeroized on drop
                }
            }
        }
        search_cpu_step::<C>(matcher, counter, tx);
    }
}

fn drain_gpu_block<C: Bip39GpuChain>(
    block: &crate::gpu::SeedBlock,
    matcher: &Matcher,
    stop: &AtomicBool,
    counter: &AtomicU64,
    tx: &Sender<Match>,
    health: &crate::gpu::GpuHealth,
) {
    debug_assert_eq!(block.len() % C::BATCH.max(1), 0);
    for chunk in block.chunks(C::BATCH.max(1) * GPU_CHUNK_BATCHES) {
        if stop.load(Ordering::Relaxed) {
            return; // only what was checked has been counted
        }
        for cand in chunk {
            // The GPU seed is UNTRUSTED and is used only to FILTER.
            let (addr, _gpu_secret) = C::from_gpu_seed(&cand.seed);
            if C::matches_raw(matcher, &addr) {
                emit_gpu_match::<C>(tx, &cand.entropy, &addr, health);
            }
        }
        counter.fetch_add(chunk.len() as u64, Ordering::Relaxed);
        health
            .seeds_delivered
            .fetch_add(chunk.len() as u64, Ordering::Relaxed);
    }
}

fn emit_gpu_match<C: Bip39GpuChain>(
    tx: &Sender<Match>,
    entropy: &[u8; 16],
    gpu_addr: &C::AddressBytes,
    health: &GpuHealth,
) {
    match crate::verify::verify_gpu::<C>(entropy, gpu_addr) {
        Some((addr, secret, phrase, proof)) => {
            // Everything written here is the CPU-derived value, never the
            // GPU-derived one.
            let _ = tx.send(Match {
                chain: C::LABEL.to_string(),
                address: C::encode_address(&addr),
                secret_hex: C::encode_secret(&secret),
                mnemonic: phrase,
                verified: proof,
            });
        }
        None => {
            // A GPU seed that MATCHED the pattern but does not re-derive is a
            // GPU fault, never a false positive. Disable the GPU, keep the CPU
            // search alive, and surface it. The candidate is dropped — it is
            // provably not a wallet anyone can open, so there is nothing to save.
            health.verify_rejections.fetch_add(1, Ordering::Relaxed);
            health.raise(GpuDisableReason::VerifyMismatch {
                address: C::encode_address(gpu_addr),
            });
        }
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

    /// Regression guard, not a driver: it passes the moment this file exists.
    /// Its job is to FAIL LATER, if someone re-adds a `Clone`/`Copy` derive to
    /// `Match` — that would let a caller build `let mut fake = real.clone();
    /// fake.address = "...".to_string();`, keeping the original's minted
    /// `Verified` token while attesting to unrelated data. See
    /// `verify::Verified`'s module doc for the forgery this closes.
    ///
    /// A `compile_fail` doc test would be the natural spelling, but this crate
    /// is binary-only (no `lib.rs`, see CLAUDE.md), and `cargo test` never runs
    /// doc tests for a bin target — the doctest would silently never execute.
    /// So the property is pinned at the source level, like
    /// `verify::tests::verify_source_pins_the_private_field_declaration`.
    #[test]
    fn match_source_pins_the_absence_of_a_forging_derive() {
        let src = include_str!("mod.rs");
        // Assembled with concat! so this test's OWN source text does not
        // contain the needle contiguously — otherwise `find` would match this
        // call site instead of the real declaration.
        let decl = concat!("pub struct ", "Match {");
        assert_eq!(
            src.matches(decl).count(),
            1,
            "expected exactly one occurrence of Match's declaration; the source may have \
             changed shape"
        );
        let at = src.find(decl).expect("Match's declaration must exist");
        // Walk upward over the WHOLE contiguous run of attribute lines above
        // the declaration — not just the one line immediately above it — so a
        // derive stacked under an unrelated attribute (e.g. `#[repr(...)]`)
        // can't hide from this check. `contains`, not `starts_with`, so
        // `#[cfg_attr(test, derive(Clone))]` is caught too. The walk stops at
        // the first line that isn't an attribute, so a doc-comment reflow
        // still can't fail this test.
        let forging_attr = src[..at]
            .lines()
            .rev()
            .map(str::trim)
            .take_while(|line| line.starts_with("#["))
            .find(|line| line.contains("derive"));
        assert!(
            forging_attr.is_none(),
            "Match must have no #[derive(...)] (directly or via cfg_attr) anywhere in the \
             attribute run above it (found: {forging_attr:?}). Clone would let a caller clone an \
             existing Match, keeping its minted token while swapping in unrelated data."
        );
    }

    /// Deterministic entropy so a red build replays exactly. Every 16-byte array
    /// is valid BIP-39 entropy — the checksum is computed FROM it.
    #[cfg(test)]
    fn gpu_test_entropy(i: usize) -> [u8; 16] {
        let mut e = [0u8; 16];
        e[14] = (i >> 8) as u8;
        e[15] = i as u8;
        e
    }

    /// A block the GPU could have produced, except `ring` did the PBKDF2.
    /// Returns the block plus the address each candidate must resolve to.
    fn ring_seed_block(n: usize) -> (crate::gpu::SeedBlock, Vec<String>) {
        use crate::chains::evm::Evm;
        use crate::gpu::{GpuCandidate, SeedBlock};
        use bip39::{Language, Mnemonic};

        let mut block = SeedBlock::with_capacity(n);
        let mut addrs = Vec::with_capacity(n);
        for i in 0..n {
            let entropy = gpu_test_entropy(i);
            let m = Mnemonic::from_entropy(&entropy, Language::English).unwrap();
            let seed = crate::seed::derive_seed(&m);
            let (addr, _sk) = Evm::from_gpu_seed(&seed);
            addrs.push(Evm::encode_address(&addr));
            block.push(GpuCandidate { entropy, seed });
        }
        (block, addrs)
    }

    #[test]
    fn gpu_block_is_consumed_counted_and_cpu_verified() {
        use crate::chains::evm::Evm;
        use crate::gpu::GpuHealth;

        // 128 = 2 full chunks of C::BATCH(4) * GPU_CHUNK_BATCHES(16), so the
        // chunk loop must actually advance rather than handling one chunk.
        const N: usize = 128;
        let (block, want) = ring_seed_block(N);

        let matcher = Matcher::new(String::new(), String::new(), false, ChainKind::Evm);
        let stop = AtomicBool::new(false);
        let counter = AtomicU64::new(0);
        let health = GpuHealth::default();
        let (tx, rx) = mpsc::channel();

        drain_gpu_block::<Evm>(&block, &matcher, &stop, &counter, &tx, &health);
        drop(tx);

        let got: Vec<Match> = rx.into_iter().collect();
        assert_eq!(
            got.len(),
            N,
            "an all-accepting matcher must emit every candidate"
        );
        assert_eq!(counter.load(Ordering::Relaxed), N as u64);
        assert_eq!(health.seeds_delivered.load(Ordering::Relaxed), N as u64);
        assert_eq!(health.verify_rejections.load(Ordering::Relaxed), 0);
        assert!(!health.disable.load(Ordering::Relaxed));

        let got_addrs: Vec<String> = got.iter().map(|m| m.address.clone()).collect();
        assert_eq!(got_addrs, want, "pairing and order must survive the drain");
        for m in &got {
            assert_eq!(m.chain, "EVM");
            assert!(
                Evm::verify(&m.address, &m.secret_hex, &m.mnemonic),
                "every emitted match must re-derive via ring: {}",
                m.address
            );
        }
    }

    /// A GPU seed that MATCHED the pattern but does not re-derive is a GPU fault,
    /// never a false positive: the GPU is disabled, the candidate is dropped (it
    /// is provably not a wallet anyone can open), and the CPU search stays alive.
    #[test]
    fn corrupted_gpu_seed_raises_fault_and_emits_nothing() {
        use crate::chains::evm::Evm;
        use crate::gpu::{GpuCandidate, GpuDisableReason, GpuHealth, SeedBlock};
        use bip39::{Language, Mnemonic};

        const N: usize = 4; // == Evm::BATCH, so the debug_assert on block length holds
        let mut block = SeedBlock::with_capacity(N);
        let mut good = Vec::new();
        let mut corrupted_addr = String::new();
        for i in 0..N {
            let entropy = gpu_test_entropy(500 + i);
            let m = Mnemonic::from_entropy(&entropy, Language::English).unwrap();
            let mut seed = crate::seed::derive_seed(&m);
            if i == 3 {
                seed[0] ^= 0x01; // one flipped bit, exactly as a faulty kernel would
                let (bad, _sk) = Evm::from_gpu_seed(&seed);
                corrupted_addr = Evm::encode_address(&bad);
            } else {
                let (addr, _sk) = Evm::from_gpu_seed(&seed);
                good.push(Evm::encode_address(&addr));
            }
            block.push(GpuCandidate { entropy, seed });
        }

        let matcher = Matcher::new(String::new(), String::new(), false, ChainKind::Evm);
        let stop = AtomicBool::new(false);
        let counter = AtomicU64::new(0);
        let health = GpuHealth::default();
        let (tx, rx) = mpsc::channel();

        drain_gpu_block::<Evm>(&block, &matcher, &stop, &counter, &tx, &health);
        drop(tx);

        let got: Vec<Match> = rx.into_iter().collect();
        assert_eq!(got.len(), 3, "the corrupted candidate must not be emitted");
        let got_addrs: Vec<String> = got.iter().map(|m| m.address.clone()).collect();
        assert_eq!(got_addrs, good);
        assert!(!got_addrs.contains(&corrupted_addr));
        for m in &got {
            assert!(Evm::verify(&m.address, &m.secret_hex, &m.mnemonic));
        }

        // The counter is honest about work inspected, not work emitted.
        assert_eq!(counter.load(Ordering::Relaxed), N as u64);
        assert_eq!(health.seeds_delivered.load(Ordering::Relaxed), N as u64);
        assert_eq!(health.verify_rejections.load(Ordering::Relaxed), 1);
        assert!(
            health.disable.load(Ordering::Relaxed),
            "a verify miss must disable the GPU"
        );
        assert_eq!(
            health.take_reason(),
            Some(GpuDisableReason::VerifyMismatch {
                address: corrupted_addr
            })
        );
    }

    /// The stop check is per chunk of C::BATCH * GPU_CHUNK_BATCHES = 64 candidates
    /// (~3.2 ms), and the counter is incremented only AFTER a chunk was actually
    /// inspected — "only what was checked has been counted".
    #[test]
    fn gpu_drain_honours_stop_mid_block() {
        use crate::chains::evm::Evm;
        use crate::gpu::GpuHealth;

        const N: usize = 128;
        let (block, _want) = ring_seed_block(N);

        let matcher = Matcher::new(String::new(), String::new(), false, ChainKind::Evm);
        let stop = AtomicBool::new(true); // already stopped: deterministic, no sleeps
        let counter = AtomicU64::new(0);
        let health = GpuHealth::default();
        let (tx, rx) = mpsc::channel();

        drain_gpu_block::<Evm>(&block, &matcher, &stop, &counter, &tx, &health);
        drop(tx);

        assert_eq!(
            counter.load(Ordering::Relaxed),
            0,
            "a stopped drain must not count candidates it never inspected"
        );
        assert_eq!(health.seeds_delivered.load(Ordering::Relaxed), 0);
        assert!(rx.try_recv().is_err(), "a stopped drain must emit nothing");
    }

    /// With `gpu: None`, `search_hybrid` must behave exactly like `search`:
    /// whole CPU batches, honours stop, touches no GPU health counter.
    #[test]
    fn search_with_no_gpu_source_is_unchanged() {
        use crate::chains::evm::Evm;
        use crate::gpu::GpuHealth;

        // Eight hex 'f's cannot occur at the start of an EVM address in 30 ms.
        let matcher = Matcher::new("ffffffff".into(), String::new(), false, ChainKind::Evm);
        let stop = AtomicBool::new(false);
        let counter = AtomicU64::new(0);
        let health = GpuHealth::default();
        let (tx, _rx) = mpsc::channel();
        thread::scope(|s| {
            s.spawn(|| search_hybrid::<Evm>(&matcher, &stop, &counter, &tx, None, &health));
            thread::sleep(Duration::from_millis(30));
            stop.store(true, Ordering::Relaxed);
        });
        let n = counter.load(Ordering::Relaxed);
        assert!(
            n > 0,
            "hybrid search with no GPU must still make CPU progress"
        );
        assert_eq!(Evm::BATCH, LANES);
        assert_eq!(
            n % LANES as u64,
            0,
            "counter advances in whole CPU batches, got {n}"
        );
        assert_eq!(health.seeds_delivered.load(Ordering::Relaxed), 0);
        assert!(!health.disable.load(Ordering::Relaxed));
    }
}
