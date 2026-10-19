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
use evm::Evm;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::Sender;

/// Channel payload emitted when a vanity address is found.
pub struct Match {
    pub chain: String,
    pub address: String,
    pub secret_hex: String,
    pub mnemonic: String,
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
    /// Only the `Evm` arm routes to `search_hybrid`; the other four call the
    /// unchanged `search::<C>` and ignore both GPU parameters. The `match` is
    /// still evaluated once per thread spawn and each arm is monomorphized
    /// separately — no `dyn`, no v-table, nothing per-candidate.
    pub fn search(
        self,
        matcher: &Matcher,
        stop: &AtomicBool,
        counter: &AtomicU64,
        tx: &Sender<Match>,
        gpu: Option<&crate::gpu::GpuRx>,
        health: &crate::gpu::GpuHealth,
    ) {
        match self {
            Self::Solana => search::<solana::Solana>(matcher, stop, counter, tx),
            Self::Evm => search_hybrid(matcher, stop, counter, tx, gpu, health),
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

/// Stop check granularity inside a GPU block: 16 × Evm::BATCH = 64 candidates
/// ≈ 3.2 ms at the measured 50.5 µs tail — comparable to the CPU path's
/// ~1.3 ms, versus 25.9 ms for a whole 512-block.
const GPU_CHUNK_BATCHES: usize = 16;

/// The EVM search loop when a GPU producer may be feeding it. `try_recv` is
/// non-blocking and therefore self-balancing: when the GPU is fast the workers
/// drain it, when the GPU stalls (compositor contention drops it 2–4×) they fall
/// straight through to the CPU batch with no static split to get wrong.
pub fn search_hybrid(
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
                    drain_gpu_block(&block, matcher, stop, counter, tx, health);
                    continue; // block is zeroized on drop
                }
            }
        }
        search_cpu_step::<Evm>(matcher, counter, tx);
    }
}

fn drain_gpu_block(
    block: &crate::gpu::SeedBlock,
    matcher: &Matcher,
    stop: &AtomicBool,
    counter: &AtomicU64,
    tx: &Sender<Match>,
    health: &crate::gpu::GpuHealth,
) {
    debug_assert_eq!(block.len() % Evm::BATCH, 0);
    for chunk in block.chunks(Evm::BATCH * GPU_CHUNK_BATCHES) {
        if stop.load(Ordering::Relaxed) {
            return; // only what was checked has been counted
        }
        for cand in chunk {
            // The GPU seed is UNTRUSTED and is used only to FILTER.
            let (addr, _gpu_secret) = Evm::from_seed(&cand.seed);
            if Evm::matches_raw(matcher, &addr) {
                emit_gpu_match(tx, &cand.entropy, &addr, health);
            }
        }
        counter.fetch_add(chunk.len() as u64, Ordering::Relaxed);
        health
            .seeds_delivered
            .fetch_add(chunk.len() as u64, Ordering::Relaxed);
    }
}

fn emit_gpu_match(tx: &Sender<Match>, entropy: &[u8; 16], gpu_addr: &[u8; 20], health: &GpuHealth) {
    match crate::verify::verify_gpu(entropy, gpu_addr) {
        Some((addr, secret, phrase)) => {
            // Everything written here is the CPU-derived value, never the
            // GPU-derived one.
            let _ = tx.send(Match {
                chain: Evm::LABEL.to_string(),
                address: Evm::encode_address(&addr),
                secret_hex: Evm::encode_secret(&secret),
                mnemonic: phrase,
            });
        }
        None => {
            // A GPU seed that MATCHED the pattern but does not re-derive is a
            // GPU fault, never a false positive. Disable the GPU, keep the CPU
            // search alive, and surface it. The candidate is dropped — it is
            // provably not a wallet anyone can open, so there is nothing to save.
            health.verify_rejections.fetch_add(1, Ordering::Relaxed);
            health.raise(GpuDisableReason::VerifyMismatch {
                address: Evm::encode_address(gpu_addr),
            });
        }
    }
}

/// Shared body of each chain's `*_starts_and_ends_with_both_required` test: the
/// address's own 3-char prefix (after the chain's `skip` fixed chars) and 3-char
/// suffix must match, and the same prefix with a wrong suffix must not.
#[cfg(test)]
fn assert_prefix_suffix<C: Chain>(
    kind: ChainKind,
    bytes: &C::AddressBytes,
    skip: usize,
    case_sensitive: bool,
) {
    let addr = C::encode_address(bytes);
    let prefix = &addr[skip..skip + 3];
    let suffix = &addr[addr.len() - 3..];
    let wrong_suffix = if suffix == "zzz" { "aaa" } else { "zzz" };
    let m = Matcher::new(prefix.into(), wrong_suffix.into(), case_sensitive, kind);
    assert!(!C::matches_raw(&m, bytes), "must reject wrong suffix");
    let m = Matcher::new(prefix.into(), suffix.into(), case_sensitive, kind);
    assert!(C::matches_raw(&m, bytes), "must accept both correct");
}

/// Shared body of each BIP-39 chain's
/// `generate_batch_emits_lane_count_candidates_matching_single_path`: the
/// batched (4-lane) path must emit `LANES` candidates that each equal the
/// single-path (`ring`) derivation of their own phrase.
#[cfg(test)]
fn assert_batch_matches_single_path<C: Chain, F>(from_seed: F)
where
    F: Fn(&[u8; 64]) -> (C::AddressBytes, C::SecretRaw),
    C::AddressBytes: Copy + PartialEq + std::fmt::Debug,
{
    use crate::pbkdf2_lanes::LANES;
    use bip39::{Language, Mnemonic};
    let mut got = Vec::new();
    C::generate_batch(|addr, secret, phrase| got.push((addr, secret, phrase)));
    assert_eq!(C::BATCH, LANES);
    assert_eq!(got.len(), LANES);
    for (addr, secret, phrase) in &got {
        let m = Mnemonic::from_phrase(phrase, Language::English).unwrap();
        let (addr2, secret2) = from_seed(&crate::seed::derive_seed(&m));
        assert_eq!(
            addr, &addr2,
            "batch address must match single-path derivation"
        );
        assert_eq!(C::encode_secret(secret), C::encode_secret(&secret2));
    }
    let mut addrs: Vec<_> = got.iter().map(|c| c.0).collect();
    addrs.dedup();
    assert_eq!(addrs.len(), LANES, "every lane must use fresh entropy");
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::pbkdf2_lanes::LANES;
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    /// `ChainKind::search` gained two GPU parameters; this pins the `ChainKind`
    /// arms (the Evm arm is `search_hybrid`, the others are `search`). With
    /// `gpu: None` — the state every non-EVM chain is
    /// permanently in, and the state EVM is in until Milestone 6 spawns a
    /// producer — behaviour must be exactly what it was: whole `C::BATCH`
    /// increments, prompt stop, and no GPU bookkeeping.
    #[test]
    fn chain_kind_search_with_no_gpu_source_is_unchanged() {
        let health = crate::gpu::GpuHealth::default();

        // EVM routes through search_hybrid; 8 hex chars is 1 in 2^32, so no
        // candidate can match and no Match is ever emitted.
        let matcher = Matcher::new("ffffffff".into(), String::new(), false, ChainKind::Evm);
        let stop = AtomicBool::new(false);
        let counter = AtomicU64::new(0);
        let (tx, rx) = mpsc::channel();
        thread::scope(|s| {
            s.spawn(|| ChainKind::Evm.search(&matcher, &stop, &counter, &tx, None, &health));
            thread::sleep(Duration::from_millis(50));
            stop.store(true, Ordering::Relaxed);
        });
        let n = counter.load(Ordering::Relaxed);
        assert!(
            n > 0,
            "hybrid search with no GPU source must still make CPU progress"
        );
        assert_eq!(evm::Evm::BATCH, LANES);
        assert_eq!(
            n % LANES as u64,
            0,
            "counter advances in whole CPU batches, got {n}"
        );
        assert_eq!(
            health.seeds_delivered.load(Ordering::Relaxed),
            0,
            "no GPU source means no GPU seeds may be counted"
        );
        assert!(
            !health.disable.load(Ordering::Relaxed),
            "a clean CPU run raises no fault"
        );
        drop(tx);
        assert!(
            rx.try_recv().is_err(),
            "an 8-hex-char prefix cannot be hit in 50 ms"
        );

        // A non-EVM arm must ignore both new parameters entirely.
        let matcher = Matcher::new("zzzzzzzzz".into(), String::new(), true, ChainKind::Solana);
        let stop = AtomicBool::new(false);
        let counter = AtomicU64::new(0);
        let (tx, _rx) = mpsc::channel();
        thread::scope(|s| {
            s.spawn(|| ChainKind::Solana.search(&matcher, &stop, &counter, &tx, None, &health));
            thread::sleep(Duration::from_millis(50));
            stop.store(true, Ordering::Relaxed);
        });
        let n = counter.load(Ordering::Relaxed);
        assert!(n > 0, "Solana must still search");
        assert_eq!(
            n % LANES as u64,
            0,
            "Solana counter advances in whole batches, got {n}"
        );
        assert_eq!(
            health.seeds_delivered.load(Ordering::Relaxed),
            0,
            "non-EVM chains must never touch GPU health"
        );
    }

    /// A 512-candidate GPU block is ~25.9 ms of work. Ctrl+C must not have to
    /// wait for it, so `drain_gpu_block` re-reads `stop` at every
    /// `Evm::BATCH * GPU_CHUNK_BATCHES` = 64-candidate boundary (~3.2 ms), and
    /// counts only chunks it actually finished. Milestone 2's
    /// `gpu_drain_honours_stop_mid_block` covers the already-stopped case;
    /// this covers stopping part-way through a block.
    #[test]
    fn gpu_drain_stop_granularity_is_one_chunk() {
        use crate::gpu::{GpuCandidate, GpuHealth, SeedBlock};

        // 4096 candidates = 64 chunks. Far more than can be drained between
        // the moment the first chunk lands and the moment the poll loop below
        // notices it and sets stop.
        const N: usize = 4096;
        let mut block = SeedBlock::with_capacity(N);
        for i in 0..N {
            let mut seed = [0u8; 64];
            for (j, b) in seed.iter_mut().enumerate() {
                *b = (i as u32)
                    .wrapping_mul(2_654_435_761)
                    .wrapping_add(j as u32) as u8;
            }
            let mut entropy = [0u8; 16];
            entropy[..4].copy_from_slice(&(i as u32).to_le_bytes());
            block.push(GpuCandidate { entropy, seed });
        }

        // 8 hex chars is 1 in 2^32: nothing in this block can match, so the
        // verify gate is never entered and no Match is ever emitted.
        let matcher = Matcher::new("ffffffff".into(), String::new(), false, ChainKind::Evm);
        let stop = AtomicBool::new(false);
        let counter = AtomicU64::new(0);
        let health = GpuHealth::default();
        let (tx, rx) = mpsc::channel();
        let chunk = (Evm::BATCH * GPU_CHUNK_BATCHES) as u64;
        assert_eq!(chunk, 64, "chunk is BATCH(4) * GPU_CHUNK_BATCHES(16)");

        thread::scope(|s| {
            s.spawn(|| drain_gpu_block(&block, &matcher, &stop, &counter, &tx, &health));
            let deadline = std::time::Instant::now() + Duration::from_secs(20);
            while counter.load(Ordering::Relaxed) < chunk && std::time::Instant::now() < deadline {
                thread::sleep(Duration::from_millis(1));
            }
            stop.store(true, Ordering::Relaxed);
        });

        let n = counter.load(Ordering::Relaxed);
        assert!(
            n >= chunk,
            "drain must count at least one whole chunk, got {n}"
        );
        assert!(
            n < N as u64,
            "stop must abandon the rest of the block, got {n} of {N}"
        );
        assert_eq!(
            n % chunk,
            0,
            "counter advances one whole chunk at a time, got {n}"
        );
        assert_eq!(
            health.seeds_delivered.load(Ordering::Relaxed),
            n,
            "seeds_delivered must track the counter exactly"
        );
        assert!(
            !health.disable.load(Ordering::Relaxed),
            "a clean drain raises no fault"
        );
        assert_eq!(health.verify_rejections.load(Ordering::Relaxed), 0);
        drop(tx);
        assert!(rx.try_recv().is_err(), "an 8-hex-char prefix cannot match");
    }

    /// The routing property `chain_kind_search_with_no_gpu_source_is_unchanged`
    /// cannot see: with `gpu: Some(rx)` actually holding a block, `ChainKind::Evm
    /// .search` must route through `search_hybrid` and drain it. If the `Evm` arm
    /// ever regressed to `search::<evm::Evm>(..)`, this would still compile and
    /// the block would sit undrained forever.
    #[test]
    fn chain_kind_search_evm_drains_a_real_gpu_block() {
        use crate::gpu::{GpuHealth, SeedBlock};

        const N: usize = LANES; // == Evm::BATCH: whole block is one GPU_CHUNK_BATCHES chunk
        let (block, _want) = ring_seed_block(N);

        // "ffffffff" cannot match any deterministically ring-derived address, so
        // nothing is emitted and only the drain bookkeeping matters here.
        let matcher = Matcher::new("ffffffff".into(), String::new(), false, ChainKind::Evm);
        let stop = AtomicBool::new(false);
        let counter = AtomicU64::new(0);
        let health = GpuHealth::default();
        let (gpu_tx, gpu_rx) = crossbeam_channel::bounded::<Box<SeedBlock>>(1);
        gpu_tx.send(Box::new(block)).unwrap();
        let (tx, _rx) = mpsc::channel();

        thread::scope(|s| {
            s.spawn(|| {
                ChainKind::Evm.search(&matcher, &stop, &counter, &tx, Some(&gpu_rx), &health)
            });
            thread::sleep(Duration::from_millis(50));
            stop.store(true, Ordering::Relaxed);
        });

        assert_eq!(
            health.seeds_delivered.load(Ordering::Relaxed),
            N as u64,
            "ChainKind::Evm.search with gpu: Some(..) must drain the block through \
             search_hybrid, not silently fall back to search::<Evm> which ignores \
             gpu entirely"
        );
        assert!(
            gpu_rx.try_recv().is_err(),
            "the pre-loaded block must have been consumed"
        );
    }

    /// The CPU path is the reference, so its matches skip `verify_gpu` — but they
    /// must still actually re-derive. This is the property the whole gate exists
    /// to preserve, asserted on the path that does not need a GPU.
    #[test]
    fn cpu_step_emits_matches_that_re_derive() {
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

    /// Deterministic entropy so a red build replays exactly. Every 16-byte array
    /// is valid BIP-39 entropy — the checksum is computed FROM it.
    pub(crate) fn gpu_test_entropy(i: usize) -> [u8; 16] {
        let mut e = [0u8; 16];
        e[14] = (i >> 8) as u8;
        e[15] = i as u8;
        e
    }

    /// A block the GPU could have produced, except `ring` did the PBKDF2.
    /// Returns the block plus the address each candidate must resolve to.
    pub(crate) fn ring_seed_block(n: usize) -> (crate::gpu::SeedBlock, Vec<[u8; 20]>) {
        use crate::chains::evm::Evm;
        use crate::gpu::{GpuCandidate, SeedBlock};
        use bip39::{Language, Mnemonic};

        let mut block = SeedBlock::with_capacity(n);
        let mut addrs = Vec::with_capacity(n);
        for i in 0..n {
            let entropy = gpu_test_entropy(i);
            let m = Mnemonic::from_entropy(&entropy, Language::English).unwrap();
            let seed = crate::seed::derive_seed(&m);
            addrs.push(Evm::from_seed(&seed).0);
            block.push(GpuCandidate { entropy, seed });
        }
        (block, addrs)
    }

    #[test]
    fn gpu_block_is_consumed_counted_and_cpu_verified() {
        use crate::chains::evm::Evm;
        use crate::gpu::GpuHealth;

        // 128 = 2 full chunks of Evm::BATCH(4) * GPU_CHUNK_BATCHES(16), so the
        // chunk loop must actually advance rather than handling one chunk.
        const N: usize = 128;
        let (block, want) = ring_seed_block(N);

        let matcher = Matcher::new(String::new(), String::new(), false, ChainKind::Evm);
        let stop = AtomicBool::new(false);
        let counter = AtomicU64::new(0);
        let health = GpuHealth::default();
        let (tx, rx) = mpsc::channel();

        drain_gpu_block(&block, &matcher, &stop, &counter, &tx, &health);
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
        let want: Vec<String> = want.iter().map(Evm::encode_address).collect();
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
                let (bad, _sk) = Evm::from_seed(&seed);
                corrupted_addr = Evm::encode_address(&bad);
            } else {
                let (addr, _sk) = Evm::from_seed(&seed);
                good.push(Evm::encode_address(&addr));
            }
            block.push(GpuCandidate { entropy, seed });
        }

        let matcher = Matcher::new(String::new(), String::new(), false, ChainKind::Evm);
        let stop = AtomicBool::new(false);
        let counter = AtomicU64::new(0);
        let health = GpuHealth::default();
        let (tx, rx) = mpsc::channel();

        drain_gpu_block(&block, &matcher, &stop, &counter, &tx, &health);
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

    /// The stop check is per chunk of Evm::BATCH * GPU_CHUNK_BATCHES = 64 candidates
    /// (~3.2 ms), and the counter is incremented only AFTER a chunk was actually
    /// inspected — "only what was checked has been counted".
    #[test]
    fn gpu_drain_honours_stop_mid_block() {
        use crate::gpu::GpuHealth;

        const N: usize = 128;
        let (block, _want) = ring_seed_block(N);

        let matcher = Matcher::new(String::new(), String::new(), false, ChainKind::Evm);
        let stop = AtomicBool::new(true); // already stopped: deterministic, no sleeps
        let counter = AtomicU64::new(0);
        let health = GpuHealth::default();
        let (tx, rx) = mpsc::channel();

        drain_gpu_block(&block, &matcher, &stop, &counter, &tx, &health);
        drop(tx);

        assert_eq!(
            counter.load(Ordering::Relaxed),
            0,
            "a stopped drain must not count candidates it never inspected"
        );
        assert_eq!(health.seeds_delivered.load(Ordering::Relaxed), 0);
        assert!(rx.try_recv().is_err(), "a stopped drain must emit nothing");
    }
}
