use bip39::{Language, Mnemonic, MnemonicType, Seed};
use csv::WriterBuilder;
use hmac::{Hmac, Mac, NewMac};
use rayon::prelude::*;
use sha2::Sha512;
use sha3::{Digest, Keccak256};
use solana_sdk::signature::{keypair_from_seed, Signer};
use std::{
    fs::OpenOptions,
    io::{self, Write},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc, Arc,
    },
    thread,
    time::{Duration, Instant},
};

type HmacSha512 = Hmac<Sha512>;

// ---------------------------------------------------------------------------
// Chain abstraction
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
enum Chain {
    Solana,
    HyperEvm,
}

/// (address, secret_key_hex, mnemonic_phrase)
type KeyResult = (String, String, String);

trait KeyGenerator: Send + Sync {
    fn generate(&self) -> KeyResult;
    fn valid_charset(&self) -> &'static str;
    fn chain_label(&self) -> &'static str;
}

// ---------------------------------------------------------------------------
// Solana: mnemonic -> BIP-39 seed -> first 32 bytes as Ed25519 key
// ---------------------------------------------------------------------------

struct SolanaGenerator;

impl KeyGenerator for SolanaGenerator {
    fn generate(&self) -> KeyResult {
        let mnemonic = Mnemonic::new(MnemonicType::Words12, Language::English);
        let seed = Seed::new(&mnemonic, "");
        let seed_bytes = seed.as_bytes();

        // Solana uses the first 32 bytes of the BIP-39 seed as the Ed25519 private key.
        // This matches `solana-keygen` behavior.
        let kp = keypair_from_seed(&seed_bytes[..32]).expect("valid seed");
        let addr = kp.pubkey().to_string();
        let secret_hex = hex::encode(kp.to_bytes());
        let phrase = mnemonic.phrase().to_string();

        (addr, secret_hex, phrase)
    }

    fn valid_charset(&self) -> &'static str {
        "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    }

    fn chain_label(&self) -> &'static str {
        "Solana"
    }
}

// ---------------------------------------------------------------------------
// EVM: mnemonic -> BIP-39 seed -> BIP-32 derive m/44'/60'/0'/0/0 -> secp256k1
// ---------------------------------------------------------------------------

struct EvmGenerator;

/// BIP-32 child key derivation for secp256k1 (hardened and normal).
fn bip32_derive_evm_key(seed: &[u8]) -> libsecp256k1::SecretKey {
    // Master key: HMAC-SHA512("Bitcoin seed", seed)
    let mut mac =
        HmacSha512::new_varkey(b"Bitcoin seed").expect("HMAC can take key of any size");
    mac.update(seed);
    let result = mac.finalize().into_bytes();
    let mut key = result[..32].to_vec();
    let mut chain_code = result[32..].to_vec();

    // Derive path: m/44'/60'/0'/0/0
    // Hardened indices: 44' = 0x8000002C, 60' = 0x8000003C, 0' = 0x80000000
    // Normal indices: 0, 0
    let path: [u32; 5] = [0x8000002C, 0x8000003C, 0x80000000, 0, 0];

    for &index in &path {
        let mut mac =
            HmacSha512::new_varkey(&chain_code).expect("HMAC can take key of any size");

        if index >= 0x80000000 {
            // Hardened: 0x00 || key || index
            mac.update(&[0u8]);
            mac.update(&key);
        } else {
            // Normal: compressed public key || index
            let sk = libsecp256k1::SecretKey::parse_slice(&key).expect("valid key");
            let pk = libsecp256k1::PublicKey::from_secret_key(&sk);
            mac.update(&pk.serialize_compressed());
        }
        mac.update(&index.to_be_bytes());

        let result = mac.finalize().into_bytes();
        // Child key = parse(IL) + parent_key (mod n)
        let il = &result[..32];
        let ir = &result[32..];

        let mut child_key = [0u8; 32];
        // Add IL to parent key modulo the curve order
        let parent = libsecp256k1::SecretKey::parse_slice(&key).expect("valid key");
        let il_key = libsecp256k1::SecretKey::parse_slice(il).expect("valid IL");
        // tweak_add: child = parent + IL (mod n)
        let mut child = parent;
        child.tweak_add_assign(&il_key).expect("valid tweak");
        child_key.copy_from_slice(&child.serialize());

        key = child_key.to_vec();
        chain_code = ir.to_vec();
    }

    libsecp256k1::SecretKey::parse_slice(&key).expect("valid derived key")
}

impl KeyGenerator for EvmGenerator {
    fn generate(&self) -> KeyResult {
        let mnemonic = Mnemonic::new(MnemonicType::Words12, Language::English);
        let seed = Seed::new(&mnemonic, "");

        let secret_key = bip32_derive_evm_key(seed.as_bytes());
        let public_key = libsecp256k1::PublicKey::from_secret_key(&secret_key);
        // Uncompressed: 65 bytes (0x04 || x || y). Drop the 0x04 prefix.
        let pubkey_bytes = public_key.serialize();
        let pubkey_uncompressed = &pubkey_bytes[1..]; // 64 bytes

        let hash = Keccak256::digest(pubkey_uncompressed);
        let addr_bytes = &hash[12..]; // last 20 bytes
        let addr = format!("0x{}", hex::encode(addr_bytes));

        let secret_hex = hex::encode(secret_key.serialize());
        let phrase = mnemonic.phrase().to_string();

        (addr, secret_hex, phrase)
    }

    fn valid_charset(&self) -> &'static str {
        "0123456789abcdefABCDEF"
    }

    fn chain_label(&self) -> &'static str {
        "HyperEVM"
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
            Chain::HyperEvm if !prefix.is_empty() => Some(hex_prefix_to_bytes(&prefix)),
            _ => None,
        };

        let evm_suffix = match chain {
            Chain::HyperEvm if !suffix.is_empty() => Some(hex_suffix_to_bytes(&suffix)),
            _ => None,
        };

        Matcher {
            prefix,
            suffix,
            position,
            case_sensitive,
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

    fn suffix_matches_str(&self, address: &str) -> bool {
        let addr = if address.starts_with("0x") {
            &address[2..]
        } else {
            address
        };

        if self.case_sensitive {
            addr.ends_with(&self.suffix)
        } else {
            addr.to_lowercase().ends_with(&self.suffix.to_lowercase())
        }
    }

    fn matches_str(&self, address: &str) -> bool {
        let addr = if address.starts_with("0x") {
            &address[2..]
        } else {
            address
        };

        let (a, p, s) = if self.case_sensitive {
            (addr.to_string(), self.prefix.clone(), self.suffix.clone())
        } else {
            (
                addr.to_lowercase(),
                self.prefix.to_lowercase(),
                self.suffix.to_lowercase(),
            )
        };

        match self.position {
            MatchPosition::StartsWith => a.starts_with(&p),
            MatchPosition::EndsWith => a.ends_with(&s),
            MatchPosition::StartsAndEndsWith => a.starts_with(&p) && a.ends_with(&s),
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

fn search_solana_raw(
    matcher: &Matcher,
    stop: &AtomicBool,
    counter: &AtomicU64,
    tx: &mpsc::Sender<MatchPayload>,
    gen: &dyn KeyGenerator,
) {
    let needs_suffix_check = matches!(matcher.position, MatchPosition::StartsAndEndsWith);

    while !stop.load(Ordering::Relaxed) {
        let (addr, secret_hex, phrase) = gen.generate();
        counter.fetch_add(1, Ordering::Relaxed);

        // Decode address back to raw bytes for fast prefix check
        if let Ok(raw_bytes) = bs58::decode(&addr).into_vec() {
            if matcher.matches_raw(&raw_bytes) {
                if needs_suffix_check && !matcher.suffix_matches_str(&addr) {
                    continue;
                }
                let _ = tx.send(("Solana".to_string(), addr, secret_hex, phrase));
            }
        }
    }
}

/// Generate an EVM address as raw 20 bytes — only format to hex on match.
fn generate_evm_raw() -> ([u8; 20], libsecp256k1::SecretKey, String) {
    let mnemonic = Mnemonic::new(MnemonicType::Words12, Language::English);
    let seed = Seed::new(&mnemonic, "");
    let secret_key = bip32_derive_evm_key(seed.as_bytes());
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
            let _ = tx.send(("HyperEVM".to_string(), addr, secret_hex, phrase));
        }
    }
}

fn search_generic(
    gen: &dyn KeyGenerator,
    matcher: &Matcher,
    stop: &AtomicBool,
    counter: &AtomicU64,
    tx: &mpsc::Sender<MatchPayload>,
) {
    while !stop.load(Ordering::Relaxed) {
        let (addr, secret_hex, phrase) = gen.generate();
        counter.fetch_add(1, Ordering::Relaxed);

        if matcher.matches_str(&addr) {
            let _ = tx.send((gen.chain_label().to_string(), addr, secret_hex, phrase));
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
    println!("\n                   v0.3 — Solana & HyperEVM");
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
    println!("  [2] HyperEVM");
    print!("> ");
    io::stdout().flush()?;

    match read_line_trimmed()?.as_str() {
        "1" => Ok(Chain::Solana),
        "2" => Ok(Chain::HyperEvm),
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

fn read_vanity_string(label: &str, chain: Chain, generator: &dyn KeyGenerator) -> io::Result<String> {
    let max_len = match chain {
        Chain::Solana => 9,
        Chain::HyperEvm => 8,
    };
    let charset = generator.valid_charset();

    println!(
        "\nEnter vanity {} (1-{} chars, {} charset):",
        label,
        max_len,
        match chain {
            Chain::Solana => "base58",
            Chain::HyperEvm => "hex (0-9, a-f)",
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

    let generator: Box<dyn KeyGenerator> = match chain {
        Chain::Solana => Box::new(SolanaGenerator),
        Chain::HyperEvm => Box::new(EvmGenerator),
    };

    let (prefix, suffix) = match position {
        MatchPosition::StartsWith => {
            let p = read_vanity_string("prefix", chain, generator.as_ref())?;
            (p, String::new())
        }
        MatchPosition::EndsWith => {
            let s = read_vanity_string("suffix", chain, generator.as_ref())?;
            (String::new(), s)
        }
        MatchPosition::StartsAndEndsWith => {
            let p = read_vanity_string("prefix (start)", chain, generator.as_ref())?;
            let s = read_vanity_string("suffix (end)", chain, generator.as_ref())?;
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
    let use_solana_raw = matcher.raw_prefix.is_some();
    let use_evm_raw = matcher.evm_prefix.is_some() || matcher.evm_suffix.is_some();

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

    // Run workers via Rayon
    (0..num_threads).into_par_iter().for_each(|_| {
        if use_solana_raw {
            search_solana_raw(&matcher, &stop, &counter, &tx, generator.as_ref());
        } else if use_evm_raw {
            search_evm_raw(&matcher, &stop, &counter, &tx);
        } else {
            search_generic(generator.as_ref(), &matcher, &stop, &counter, &tx);
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
