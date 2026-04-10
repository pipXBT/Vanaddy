use bip39::{Language, Mnemonic, MnemonicType};
use csv::WriterBuilder;
use ed25519_dalek::SigningKey;
use rayon::prelude::*;
use ring::hmac;
use sha3::{Digest, Keccak256};
use std::{
    fs::OpenOptions,
    io::{self, Write},
    num::NonZeroU32,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc, Arc,
    },
    thread,
    time::{Duration, Instant},
};

/// BIP-39 seed derivation using ring's ARM64-optimized PBKDF2-HMAC-SHA512.
/// Replaces tiny-bip39's Seed::new() which uses a slower pure-Rust PBKDF2.
fn derive_seed(mnemonic: &Mnemonic) -> [u8; 64] {
    const PBKDF2_ROUNDS: u32 = 2048;
    let password = mnemonic.phrase().as_bytes();
    let salt = b"mnemonic"; // no passphrase
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

// ---------------------------------------------------------------------------
// Chain abstraction
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
enum Chain {
    Solana,
    Evm,
}

trait ChainInfo: Send + Sync {
    fn valid_charset(&self) -> &'static str;
}

// ---------------------------------------------------------------------------
// Solana: mnemonic -> BIP-39 seed -> first 32 bytes as Ed25519 key
// ---------------------------------------------------------------------------

struct SolanaInfo;

impl ChainInfo for SolanaInfo {
    fn valid_charset(&self) -> &'static str {
        "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    }
}

// ---------------------------------------------------------------------------
// EVM: mnemonic -> BIP-39 seed -> BIP-32 derive m/44'/60'/0'/0/0 -> secp256k1
// ---------------------------------------------------------------------------

struct EvmInfo;

/// BIP-32 child key derivation for secp256k1 (hardened and normal).
fn bip32_derive_evm_key(seed: &[u8]) -> libsecp256k1::SecretKey {
    // Master key: HMAC-SHA512("Bitcoin seed", seed)
    let master_key = hmac::Key::new(hmac::HMAC_SHA512, b"Bitcoin seed");
    let result = hmac::sign(&master_key, seed);
    let result = result.as_ref();
    let mut key = [0u8; 32];
    let mut chain_code = [0u8; 32];
    key.copy_from_slice(&result[..32]);
    chain_code.copy_from_slice(&result[32..]);

    // Derive path: m/44'/60'/0'/0/0
    let path: [u32; 5] = [0x8000002C, 0x8000003C, 0x80000000, 0, 0];

    for &index in &path {
        let hmac_key = hmac::Key::new(hmac::HMAC_SHA512, &chain_code);
        let parent = libsecp256k1::SecretKey::parse_slice(&key).expect("valid key");

        let result = if index >= 0x80000000 {
            // Hardened: 0x00 || key || index
            let mut data = [0u8; 37]; // 1 + 32 + 4
            data[1..33].copy_from_slice(&key);
            data[33..].copy_from_slice(&index.to_be_bytes());
            hmac::sign(&hmac_key, &data)
        } else {
            // Normal: compressed public key || index
            let pk = libsecp256k1::PublicKey::from_secret_key(&parent);
            let mut data = [0u8; 37]; // 33 + 4
            data[..33].copy_from_slice(&pk.serialize_compressed());
            data[33..].copy_from_slice(&index.to_be_bytes());
            hmac::sign(&hmac_key, &data)
        };

        let result = result.as_ref();
        let il_key = libsecp256k1::SecretKey::parse_slice(&result[..32]).expect("valid IL");
        let mut child = parent;
        child.tweak_add_assign(&il_key).expect("valid tweak");
        key.copy_from_slice(&child.serialize());
        chain_code.copy_from_slice(&result[32..]);
    }

    libsecp256k1::SecretKey::parse_slice(&key).expect("valid derived key")
}

impl ChainInfo for EvmInfo {
    fn valid_charset(&self) -> &'static str {
        "0123456789abcdefABCDEF"
    }
}

// ---------------------------------------------------------------------------
// Match engine
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
enum MatchPosition {
    StartsWith,
    EndsWith,
    StartsAndEndsWith,
}

struct Matcher {
    prefix: String,
    suffix: String,
    position: MatchPosition,
    case_sensitive: bool,
    /// Pre-lowercased for case-insensitive string matching (avoids alloc in hot loop)
    prefix_lower: String,
    suffix_lower: String,
    /// For Solana starts-with: pre-decoded base58 bytes for raw comparison
    raw_prefix: Option<Vec<u8>>,
    /// For EVM: pre-decoded hex bytes for raw comparison (skips hex::encode in hot loop)
    evm_prefix: Option<(Vec<u8>, Option<u8>)>, // (full_bytes, extra_high_nibble)
    evm_suffix: Option<(Vec<u8>, Option<u8>)>, // (full_bytes, extra_low_nibble)
}

/// Parse a hex string into full bytes + optional trailing high nibble (for prefix matching).
/// e.g. "dead" -> ([0xde, 0xad], None), "dea" -> ([0xde], Some(0x0a))
fn hex_prefix_to_bytes(hex: &str) -> (Vec<u8>, Option<u8>) {
    let hex_lower = hex.to_lowercase();
    let nibbles: Vec<u8> = hex_lower
        .chars()
        .map(|c| c.to_digit(16).unwrap() as u8)
        .collect();
    let full_count = nibbles.len() / 2;
    let mut bytes = Vec::with_capacity(full_count);
    for i in 0..full_count {
        bytes.push((nibbles[i * 2] << 4) | nibbles[i * 2 + 1]);
    }
    let extra = if nibbles.len() % 2 == 1 {
        Some(nibbles[nibbles.len() - 1])
    } else {
        None
    };
    (bytes, extra)
}

/// Parse a hex string into full bytes + optional leading low nibble (for suffix matching).
/// e.g. "beef" -> ([0xbe, 0xef], None), "def" -> ([0xef], Some(0x0d))
fn hex_suffix_to_bytes(hex: &str) -> (Vec<u8>, Option<u8>) {
    let hex_lower = hex.to_lowercase();
    let nibbles: Vec<u8> = hex_lower
        .chars()
        .map(|c| c.to_digit(16).unwrap() as u8)
        .collect();
    let has_extra = nibbles.len() % 2 == 1;
    let start = if has_extra { 1 } else { 0 };
    let full_count = (nibbles.len() - start) / 2;
    let mut bytes = Vec::with_capacity(full_count);
    for i in 0..full_count {
        let idx = start + i * 2;
        bytes.push((nibbles[idx] << 4) | nibbles[idx + 1]);
    }
    let extra = if has_extra { Some(nibbles[0]) } else { None };
    (bytes, extra)
}

impl Matcher {
    fn new(
        prefix: String,
        suffix: String,
        position: MatchPosition,
        case_sensitive: bool,
        chain: Chain,
    ) -> Self {
        let raw_prefix = match (chain, position) {
            (Chain::Solana, MatchPosition::StartsWith | MatchPosition::StartsAndEndsWith)
                if case_sensitive && !prefix.is_empty() =>
            {
                bs58::decode(&prefix).into_vec().ok()
            }
            _ => None,
        };

        let evm_prefix = match chain {
            Chain::Evm if !prefix.is_empty() => Some(hex_prefix_to_bytes(&prefix)),
            _ => None,
        };

        let evm_suffix = match chain {
            Chain::Evm if !suffix.is_empty() => Some(hex_suffix_to_bytes(&suffix)),
            _ => None,
        };

        let prefix_lower = prefix.to_lowercase();
        let suffix_lower = suffix.to_lowercase();

        Matcher {
            prefix,
            suffix,
            position,
            case_sensitive,
            prefix_lower,
            suffix_lower,
            raw_prefix,
            evm_prefix,
            evm_suffix,
        }
    }

    fn matches_raw(&self, pubkey_bytes: &[u8]) -> bool {
        if let Some(ref prefix) = self.raw_prefix {
            pubkey_bytes.starts_with(prefix)
        } else {
            false
        }
    }

    /// Match EVM address bytes directly — no hex encoding needed.
    fn matches_evm_raw(&self, addr_bytes: &[u8; 20]) -> bool {
        let prefix_ok = if let Some((ref full, ref extra)) = self.evm_prefix {
            if !addr_bytes[..full.len()].starts_with(full) {
                return false;
            }
            if let Some(nibble) = extra {
                if (addr_bytes[full.len()] >> 4) != *nibble {
                    return false;
                }
            }
            true
        } else {
            true
        };

        if !prefix_ok {
            return false;
        }

        if let Some((ref full, ref extra)) = self.evm_suffix {
            let start = 20 - full.len();
            if &addr_bytes[start..] != full.as_slice() {
                return false;
            }
            if let Some(nibble) = extra {
                let idx = start - 1;
                if (addr_bytes[idx] & 0x0f) != *nibble {
                    return false;
                }
            }
        }

        true
    }

    fn matches_str(&self, address: &str) -> bool {
        let addr = if address.starts_with("0x") {
            &address[2..]
        } else {
            address
        };

        if self.case_sensitive {
            match self.position {
                MatchPosition::StartsWith => addr.starts_with(&self.prefix),
                MatchPosition::EndsWith => addr.ends_with(&self.suffix),
                MatchPosition::StartsAndEndsWith => {
                    addr.starts_with(&self.prefix) && addr.ends_with(&self.suffix)
                }
            }
        } else {
            let a = addr.to_lowercase();
            match self.position {
                MatchPosition::StartsWith => a.starts_with(&self.prefix_lower),
                MatchPosition::EndsWith => a.ends_with(&self.suffix_lower),
                MatchPosition::StartsAndEndsWith => {
                    a.starts_with(&self.prefix_lower) && a.ends_with(&self.suffix_lower)
                }
            }
        }
    }

    fn description(&self) -> String {
        match self.position {
            MatchPosition::StartsWith => format!("starts with '{}'", self.prefix),
            MatchPosition::EndsWith => format!("ends with '{}'", self.suffix),
            MatchPosition::StartsAndEndsWith => {
                format!("starts with '{}' and ends with '{}'", self.prefix, self.suffix)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Search functions
// ---------------------------------------------------------------------------

/// Channel payload: (chain_label, address, secret_hex, mnemonic)
type MatchPayload = (String, String, String, String);

// ---------------------------------------------------------------------------
// TUI state
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq)]
enum AppState {
    Configuring,
    Searching,
}

struct App {
    state: AppState,
    should_quit: bool,

    // Form fields
    active_field: usize,
    chain: Chain,
    match_position: MatchPosition,
    vanity_prefix: String,
    vanity_suffix: String,
    case_sensitive: bool,
    thread_count: String,
    error_message: Option<String>,

    // Search state
    matches: Vec<MatchPayload>,
    selected_match: usize,
    counter: Arc<AtomicU64>,
    match_count: Arc<AtomicU64>,
    start_time: Option<Instant>,
    stop: Arc<AtomicBool>,
    rx: Option<mpsc::Receiver<MatchPayload>>,
}

impl App {
    fn new() -> Self {
        let recommended_threads = detect_optimal_threads();
        App {
            state: AppState::Configuring,
            should_quit: false,
            active_field: 0,
            chain: Chain::Solana,
            match_position: MatchPosition::StartsWith,
            vanity_prefix: String::new(),
            vanity_suffix: String::new(),
            case_sensitive: false,
            thread_count: recommended_threads.to_string(),
            error_message: None,
            matches: Vec::new(),
            selected_match: 0,
            counter: Arc::new(AtomicU64::new(0)),
            match_count: Arc::new(AtomicU64::new(0)),
            start_time: None,
            stop: Arc::new(AtomicBool::new(false)),
            rx: None,
        }
    }

    fn field_count(&self) -> usize {
        if matches!(self.match_position, MatchPosition::StartsAndEndsWith) {
            6
        } else {
            5
        }
    }

    fn is_text_field(&self) -> bool {
        match self.active_field {
            2 => true,
            3 if matches!(self.match_position, MatchPosition::StartsAndEndsWith) => true,
            f if f == self.field_count() - 1 => true,
            _ => false,
        }
    }

    fn valid_charset(&self) -> &'static str {
        match self.chain {
            Chain::Solana => "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz",
            Chain::Evm => "0123456789abcdefABCDEF",
        }
    }

    fn max_vanity_len(&self) -> usize {
        match self.chain {
            Chain::Solana => 9,
            Chain::Evm => 8,
        }
    }

    fn validate(&self) -> Result<(), String> {
        let charset = self.valid_charset();
        let max_len = self.max_vanity_len();

        let input_str = match self.match_position {
            MatchPosition::EndsWith => &self.vanity_suffix,
            _ => &self.vanity_prefix,
        };
        if input_str.is_empty() {
            return Err("Vanity string cannot be empty".to_string());
        }
        if input_str.len() > max_len {
            return Err(format!("Must be 1-{} characters", max_len));
        }
        if let Some(c) = input_str.chars().find(|c| !charset.contains(*c)) {
            return Err(format!("'{}' is not valid for this chain", c));
        }

        if matches!(self.match_position, MatchPosition::StartsAndEndsWith) {
            if self.vanity_suffix.is_empty() {
                return Err("Suffix cannot be empty".to_string());
            }
            if self.vanity_suffix.len() > max_len {
                return Err(format!("Suffix must be 1-{} characters", max_len));
            }
            if let Some(c) = self.vanity_suffix.chars().find(|c| !charset.contains(*c)) {
                return Err(format!("'{}' is not valid for this chain", c));
            }
        }

        let max_threads = num_cpus::get().max(1) * 2;
        let count = self.thread_count.parse::<usize>().map_err(|_| "Invalid thread count".to_string())?;
        if count == 0 || count > max_threads {
            return Err(format!("Threads must be 1-{}", max_threads));
        }

        Ok(())
    }

    fn start_search(&mut self) {
        let num_threads: usize = self.thread_count.parse().unwrap();
        self.error_message = None;
        self.matches.clear();
        self.selected_match = 0;
        self.counter = Arc::new(AtomicU64::new(0));
        self.match_count = Arc::new(AtomicU64::new(0));
        self.stop = Arc::new(AtomicBool::new(false));
        self.start_time = Some(Instant::now());
        self.state = AppState::Searching;

        let (prefix, suffix) = match self.match_position {
            MatchPosition::StartsWith => (self.vanity_prefix.clone(), String::new()),
            MatchPosition::EndsWith => (String::new(), self.vanity_prefix.clone()),
            MatchPosition::StartsAndEndsWith => (self.vanity_prefix.clone(), self.vanity_suffix.clone()),
        };

        let matcher = Matcher::new(prefix, suffix, self.match_position, self.case_sensitive, self.chain);
        let chain = self.chain;
        let stop = self.stop.clone();
        let counter = self.counter.clone();

        let (tx, rx) = mpsc::channel();
        self.rx = Some(rx);

        // Ensure CSV has header
        {
            let file = OpenOptions::new()
                .create(true)
                .append(true)
                .open("vanity_wallets.csv")
                .expect("Failed to open vanity_wallets.csv");
            let needs_header = file.metadata().map(|m| m.len() == 0).unwrap_or(true);
            if needs_header {
                let mut wtr = WriterBuilder::new().has_headers(false).from_writer(file);
                wtr.write_record(["Chain", "Address", "Private Key (hex)", "Seed Phrase"]).unwrap();
                wtr.flush().unwrap();
            }
        }

        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(num_threads)
            .build()
            .expect("Failed to build Rayon thread pool");

        pool.spawn(move || {
            (0..num_threads).into_par_iter().for_each(|_| {
                match chain {
                    Chain::Solana => search_solana_raw(&matcher, &stop, &counter, &tx),
                    Chain::Evm => search_evm_raw(&matcher, &stop, &counter, &tx),
                }
            });
            drop(tx);
        });
    }

    fn stop_search(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.rx = None;
        self.state = AppState::Configuring;
    }

    fn drain_matches(&mut self) {
        if let Some(ref rx) = self.rx {
            while let Ok(payload) = rx.try_recv() {
                self.match_count.fetch_add(1, Ordering::Relaxed);

                if let Ok(file) = OpenOptions::new().create(true).append(true).open("vanity_wallets.csv") {
                    let mut wtr = WriterBuilder::new().has_headers(false).from_writer(file);
                    let _ = wtr.write_record(&[&payload.0, &payload.1, &payload.2, &payload.3]);
                    let _ = wtr.flush();
                }

                self.matches.push(payload);
                self.selected_match = self.matches.len().saturating_sub(1);
            }
        }
    }
}

/// Generate a Solana keypair returning raw pubkey bytes — only base58-encode on match.
fn generate_solana_raw() -> ([u8; 32], SigningKey, String) {
    let mnemonic = Mnemonic::new(MnemonicType::Words12, Language::English);
    let seed_bytes = derive_seed(&mnemonic);
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&seed_bytes[..32]);
    let signing_key = SigningKey::from_bytes(&key_bytes);
    let pubkey_bytes = signing_key.verifying_key().to_bytes();
    (pubkey_bytes, signing_key, mnemonic.phrase().to_string())
}

fn search_solana_raw(
    matcher: &Matcher,
    stop: &AtomicBool,
    counter: &AtomicU64,
    tx: &mpsc::Sender<MatchPayload>,
) {
    let has_raw_prefix = matcher.raw_prefix.is_some();

    while !stop.load(Ordering::Relaxed) {
        let (pubkey_bytes, signing_key, phrase) = generate_solana_raw();
        counter.fetch_add(1, Ordering::Relaxed);

        // Fast path: reject on raw prefix bytes before base58-encoding
        if has_raw_prefix && !matcher.matches_raw(&pubkey_bytes) {
            continue;
        }

        // Only base58-encode when prefix matched (or no prefix to check)
        let addr = bs58::encode(&pubkey_bytes).into_string();
        if matcher.matches_str(&addr) {
            // Solana keypair format: 64 bytes = secret_key (32) || public_key (32)
            let mut keypair_bytes = [0u8; 64];
            keypair_bytes[..32].copy_from_slice(signing_key.as_bytes());
            keypair_bytes[32..].copy_from_slice(&pubkey_bytes);
            let secret_hex = hex::encode(keypair_bytes);
            let _ = tx.send(("Solana".to_string(), addr, secret_hex, phrase));
        }
    }
}

/// Generate an EVM address as raw 20 bytes — only format to hex on match.
fn generate_evm_raw() -> ([u8; 20], libsecp256k1::SecretKey, String) {
    let mnemonic = Mnemonic::new(MnemonicType::Words12, Language::English);
    let seed_bytes = derive_seed(&mnemonic);
    let secret_key = bip32_derive_evm_key(&seed_bytes);
    let public_key = libsecp256k1::PublicKey::from_secret_key(&secret_key);
    let pubkey_bytes = public_key.serialize();
    let pubkey_uncompressed = &pubkey_bytes[1..];
    let hash = Keccak256::digest(pubkey_uncompressed);

    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..]);

    (addr, secret_key, mnemonic.phrase().to_string())
}

fn search_evm_raw(
    matcher: &Matcher,
    stop: &AtomicBool,
    counter: &AtomicU64,
    tx: &mpsc::Sender<MatchPayload>,
) {
    while !stop.load(Ordering::Relaxed) {
        let (addr_bytes, secret_key, phrase) = generate_evm_raw();
        counter.fetch_add(1, Ordering::Relaxed);

        if matcher.matches_evm_raw(&addr_bytes) {
            // Only format to hex string on match
            let addr = format!("0x{}", hex::encode(addr_bytes));
            let secret_hex = hex::encode(secret_key.serialize());
            let _ = tx.send(("EVM".to_string(), addr, secret_hex, phrase));
        }
    }
}

// ---------------------------------------------------------------------------
// Interactive prompts
// ---------------------------------------------------------------------------

fn display_banner() {
    println!("\n\n\n");
    println!("==========================================================\n");
    println!("██╗   ██╗ █████╗ ███╗   ██╗ █████╗ ██████╗ ██████╗ ██╗   ██╗");
    println!("██║   ██║██╔══██╗████╗  ██║██╔══██╗██╔══██╗██╔══██╗╚██╗ ██╔╝");
    println!("██║   ██║███████║██╔██╗ ██║███████║██║  ██║██║  ██║ ╚████╔╝ ");
    println!("╚██╗ ██╔╝██╔══██║██║╚██╗██║██╔══██║██║  ██║██║  ██║  ╚██╔╝  ");
    println!(" ╚████╔╝ ██║  ██║██║ ╚████║██║  ██║██████╔╝██████╔╝   ██║   ");
    println!("  ╚═══╝  ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═════╝ ╚═════╝    ╚═╝   ");
    println!("\n                     v0.4 — Solana & EVM");
    println!("==========================================================\n");
}

fn read_line_trimmed() -> io::Result<String> {
    let mut buf = String::new();
    io::stdin().read_line(&mut buf)?;
    Ok(buf.trim().to_owned())
}

fn read_chain() -> io::Result<Chain> {
    println!("Select chain:");
    println!("  [1] Solana");
    println!("  [2] EVM (Ethereum, Base, Arbitrum, etc.)");
    print!("> ");
    io::stdout().flush()?;

    match read_line_trimmed()?.as_str() {
        "1" => Ok(Chain::Solana),
        "2" => Ok(Chain::Evm),
        _ => Err(io::Error::new(io::ErrorKind::InvalidInput, "Choose 1 or 2")),
    }
}

fn read_match_position() -> io::Result<MatchPosition> {
    println!("\nMatch position:");
    println!("  [1] Starts with");
    println!("  [2] Ends with");
    println!("  [3] Starts and ends with");
    print!("> ");
    io::stdout().flush()?;

    match read_line_trimmed()?.as_str() {
        "1" => Ok(MatchPosition::StartsWith),
        "2" => Ok(MatchPosition::EndsWith),
        "3" => Ok(MatchPosition::StartsAndEndsWith),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Choose 1, 2, or 3",
        )),
    }
}

fn read_vanity_string(label: &str, chain: Chain, info: &dyn ChainInfo) -> io::Result<String> {
    let max_len = match chain {
        Chain::Solana => 9,
        Chain::Evm => 8,
    };
    let charset = info.valid_charset();

    println!(
        "\nEnter vanity {} (1-{} chars, {} charset):",
        label,
        max_len,
        match chain {
            Chain::Solana => "base58",
            Chain::Evm => "hex (0-9, a-f)",
        }
    );
    print!("> ");
    io::stdout().flush()?;

    let input = read_line_trimmed()?;

    if input.is_empty() || input.len() > max_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Must be 1-{} characters", max_len),
        ));
    }

    if let Some(c) = input.chars().find(|c| !charset.contains(*c)) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("'{}' is not valid for this chain's address format", c),
        ));
    }

    Ok(input)
}

fn read_case_sensitivity() -> io::Result<bool> {
    println!("\nCase-sensitive? (yes/no):");
    print!("> ");
    io::stdout().flush()?;
    Ok(read_line_trimmed()?.eq_ignore_ascii_case("yes"))
}

fn detect_optimal_threads() -> usize {
    let physical = num_cpus::get_physical();
    let logical = num_cpus::get();

    // On Apple Silicon: physical == logical (no hyperthreading).
    // Use all cores — the OS scheduler handles P/E core assignment.
    // On x86 with hyperthreading: physical < logical.
    // For crypto-heavy work, physical cores are usually optimal.
    if logical > physical {
        // Hyperthreaded (x86): use physical cores for compute-bound work
        physical
    } else {
        // Apple Silicon or non-HT: use all cores
        logical
    }
}

fn read_thread_count() -> io::Result<usize> {
    let recommended = detect_optimal_threads();
    let max_threads = num_cpus::get().max(1) * 2; // allow oversubscription up to 2x

    println!(
        "\nThreads (1-{}) [detected {} cores, recommended: {}]:",
        max_threads, num_cpus::get(), recommended
    );
    println!("  Press Enter for recommended ({}), or type a number:", recommended);
    print!("> ");
    io::stdout().flush()?;

    let input = read_line_trimmed()?;

    let count = if input.is_empty() {
        recommended
    } else {
        input
            .parse::<usize>()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?
    };

    if count == 0 || count > max_threads {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Must be 1-{}", max_threads),
        ));
    }

    Ok(count)
}

// ---------------------------------------------------------------------------
// CSV writer
// ---------------------------------------------------------------------------

fn start_csv_writer(
    rx: mpsc::Receiver<MatchPayload>,
    match_count: Arc<AtomicU64>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open("vanity_wallets.csv")
            .expect("Failed to open vanity_wallets.csv");

        let needs_header = file.metadata().map(|m| m.len() == 0).unwrap_or(true);

        let mut wtr = WriterBuilder::new()
            .has_headers(false)
            .from_writer(file);

        if needs_header {
            wtr.write_record(["Chain", "Address", "Private Key (hex)", "Seed Phrase"])
                .unwrap();
            wtr.flush().unwrap();
        }

        while let Ok((chain, address, secret_hex, phrase)) = rx.recv() {
            wtr.write_record(&[&chain, &address, &secret_hex, &phrase])
                .unwrap();
            wtr.flush().unwrap();
            match_count.fetch_add(1, Ordering::Relaxed);
            println!("\n  >> MATCH FOUND: {} [{}]", address, chain);
        }
    })
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() -> io::Result<()> {
    display_banner();

    let chain = read_chain()?;
    let position = read_match_position()?;

    let chain_info: Box<dyn ChainInfo> = match chain {
        Chain::Solana => Box::new(SolanaInfo),
        Chain::Evm => Box::new(EvmInfo),
    };

    let (prefix, suffix) = match position {
        MatchPosition::StartsWith => {
            let p = read_vanity_string("prefix", chain, chain_info.as_ref())?;
            (p, String::new())
        }
        MatchPosition::EndsWith => {
            let s = read_vanity_string("suffix", chain, chain_info.as_ref())?;
            (String::new(), s)
        }
        MatchPosition::StartsAndEndsWith => {
            let p = read_vanity_string("prefix (start)", chain, chain_info.as_ref())?;
            let s = read_vanity_string("suffix (end)", chain, chain_info.as_ref())?;
            (p, s)
        }
    };

    let case_sensitive = read_case_sensitivity()?;
    let num_threads = read_thread_count()?;

    rayon::ThreadPoolBuilder::new()
        .num_threads(num_threads)
        .build_global()
        .expect("Failed to build Rayon thread pool");

    let matcher = Matcher::new(prefix, suffix, position, case_sensitive, chain);

    let stop = Arc::new(AtomicBool::new(false));
    let counter = Arc::new(AtomicU64::new(0));
    let match_count = Arc::new(AtomicU64::new(0));

    let stop_signal = stop.clone();
    ctrlc::set_handler(move || {
        stop_signal.store(true, Ordering::Relaxed);
    })
    .expect("Failed to set Ctrl+C handler");

    let (tx, rx) = mpsc::channel();
    let writer_handle = start_csv_writer(rx, match_count.clone());

    let start_time = Instant::now();

    println!(
        "\nSearching for addresses that {} ({})... Press Ctrl+C to stop.\n",
        matcher.description(),
        if case_sensitive {
            "case-sensitive"
        } else {
            "case-insensitive"
        }
    );

    // Progress display thread
    let progress_stop = stop.clone();
    let progress_counter = counter.clone();
    let progress_matches = match_count.clone();
    let progress_handle = thread::spawn(move || {
        while !progress_stop.load(Ordering::Relaxed) {
            let count = progress_counter.load(Ordering::Relaxed);
            let matches = progress_matches.load(Ordering::Relaxed);
            let elapsed = start_time.elapsed().as_secs();
            let rate = if elapsed > 0 { count / elapsed } else { 0 };
            print!(
                "\r  Checked: {} | Matches: {} | Rate: {}/s | Elapsed: {}s   ",
                count, matches, rate, elapsed
            );
            io::stdout().flush().unwrap();
            thread::sleep(Duration::from_millis(200));
        }
    });

    // Run workers via Rayon — each chain has its own optimized search path
    (0..num_threads).into_par_iter().for_each(|_| {
        match chain {
            Chain::Solana => search_solana_raw(&matcher, &stop, &counter, &tx),
            Chain::Evm => search_evm_raw(&matcher, &stop, &counter, &tx),
        }
    });

    drop(tx);
    let _ = writer_handle.join();
    let _ = progress_handle.join();

    let total = counter.load(Ordering::Relaxed);
    let matches = match_count.load(Ordering::Relaxed);
    let elapsed = start_time.elapsed();
    println!("\n\n==========================================================");
    println!("  Wallets checked : {}", total);
    println!("  Matches found   : {}", matches);
    println!("  Elapsed time    : {:.2?}", elapsed);
    if matches > 0 {
        println!("  Saved to        : vanity_wallets.csv");
    }
    println!("==========================================================\n");

    Ok(())
}
