> Generated: 2026-10-19 | Token-lean format for LLM context

# Data & Helpers

## Top-Level Types

| Type | Defined in | Notes |
|------|------------|-------|
| `App` / `AppState` | `src/app.rs:42` / `:37` | TUI + search + GPU fields / `Configuring \| Searching` |
| `Chain` | `src/chains/mod.rs:25` | `LABEL`, `CHARSET`, `MAX_VANITY`, `BATCH` (default 1), `AddressBytes`, `SecretRaw`; `generate`, `generate_batch`, `encode_address`, `encode_secret`, `matches_raw` |
| `ChainKind` | `src/chains/mod.rs:50` | `Solana \| Evm \| Bitcoin \| Ton \| Monero`. `search(.., gpu: Option<&GpuRx>, &GpuHealth)`: Evm → `search_hybrid`, others → `search::<C>` |
| `Match` | `src/chains/mod.rs:18` | `{ chain, address, secret_hex, mnemonic }`, all `String`. No derives |
| `Matcher` / `MatchPosition` | `src/matcher.rs:11` / `:5` | see below / `StartsWith \| EndsWith \| StartsAndEndsWith`, `Copy` |
| `MoneroKeypair` | `src/chains/monero.rs:24` | `{ spend_sec, view_sec }: [u8; 32]`, `Zeroize + ZeroizeOnDrop` |
| `GpuCandidate` | `src/gpu/mod.rs:161` | `{ entropy: [u8; 16], seed: [u8; 64] }`, `Clone + Copy + Zeroize`. `seed` untrusted, filter only |
| `SeedBlock` / `GpuRx` | `src/gpu/mod.rs:172` / `:204` | `Vec<GpuCandidate>`, `Zeroize + ZeroizeOnDrop`; `pub(crate)` `with_capacity`/`push` (panics rather than reallocate), read `len`/`is_empty`/`chunks` / `crossbeam_channel::Receiver<Box<SeedBlock>>` |
| `GpuHealth` | `src/gpu/mod.rs:211` | `Default`. `disable: AtomicBool`, private `reason: OnceLock<GpuDisableReason>`, `seeds_delivered: AtomicU64` |
| `Schedule` | `src/gpu/mod.rs:268` | `Production \| Irregular(&'static [u32])`. Last entry repeats; non-production = 1 dispatch per command buffer |
| `KeyBlock` | `src/gpu/pack.rs:12` | `#[repr(C, align(16))] [u64; 16]` big-endian, 128 B, `Copy + Zeroize` |
| `SelfTestError` | `src/gpu/selftest.rs:43` | `WrongLength \| CanonicalVectorMismatch \| RingMismatch \| AllZero \| Poisoned \| ScheduleDivergence \| DuplicateEntropy \| Backend(String)` |
| `GpuEngine` | `gpu/metal.rs:541`, `gpu/stub.rs:21` | `start(tx, health)`, `status`, `signal_stop`, `is_finished`, `reap`. Holds no ObjC type |

## GPU State Enums (`src/gpu/mod.rs`)

```rust
pub enum GpuStatus {                 // Clone, Debug, PartialEq
    Unavailable(String),             // stub build, no device, --no-default-features
    Ready { device: String },        // probe() ok, no thread yet
    Initializing,                    // thread spawned: compile + self-test
    Running { device: String },
    Disabled(GpuDisableReason),      // sticky for the process
}
pub enum GpuDisableReason {          // Clone, Debug, PartialEq
    NotSupported, UserOff,
    Backend(GpuError), SelfTest(SelfTestError),
    AuditMismatch { index: usize },  // in-wave random ring audit disagreed
    VerifyMismatch { address: String }, // matched GPU candidate failed verify_gpu
    Panicked,
}
pub enum GpuError {                  // Debug, Clone, PartialEq
    NoDevice, ShaderCompile(String), PipelineCreate(String), BufferAlloc,
    BadConfig(String), CommandBuffer { status: i64, message: String },
}
```

`GpuHealth::raise(r)` sets reason (first wins) then `disable` `Release`; `take_reason()` `Acquire`-loads and clones. `classify_command_buffer_status` (`:104`): `Ok` only for status 4 with no error.

## Matcher Internals (`src/matcher.rs`)

```rust
pub struct Matcher {
    pub(crate) prefix: String,
    pub(crate) suffix: String,
    pub(crate) case_sensitive: bool,
    pub(crate) evm_prefix: Option<(Vec<u8>, Option<u8>)>, // full bytes, extra high nibble
    pub(crate) evm_suffix: Option<(Vec<u8>, Option<u8>)>, // full bytes, extra low nibble
    pub(crate) bech32_prefix_5bit: Option<Vec<u8>>,       // Bitcoin only
}
pub fn new(prefix: String, suffix: String, case_sensitive: bool, chain: ChainKind) -> Self
```

| Helper | Purpose |
|--------|---------|
| `hex_prefix_to_bytes` / `hex_suffix_to_bytes` | `"dea"` → `([0xde], Some(0x0a))` / `"def"` → `([0xef], Some(0x0d))` |
| `matches_evm_raw(&[u8; 20])` | byte + nibble compare (EVM only) |
| `prefix_matches(&str)` / `suffix_matches(&str)` | empty → true; else head/tail bytes, `eq_ignore_ascii_case` unless case-sensitive |

`evm_*` set only for `ChainKind::Evm` with a non-empty affix. `bech32_prefix_5bit` maps each char to its index in `Bitcoin::CHARSET` (`qpzry9x8gf2tvdw0s3jn54khce6mua7l`).

## Crypto Helpers

| File | Function | Returns / notes |
|------|----------|-----------------|
| `seed.rs:21` | `derive_seed(&Mnemonic)` | `[u8; 64]` = `ring_pbkdf2_sha512(phrase, BIP39_SALT, PBKDF2_ROUNDS)` |
| `seed.rs:26` | `derive_seeds::<L>(&[Mnemonic; L])` | `[[u8; 64]; L]` via `pbkdf2_hmac_sha512::<L>` |
| `pbkdf2_lanes.rs:16` | `pbkdf2_hmac_sha512::<L>(passwords, salt, iters)` | asserts salt ≤ 107, iters ≥ 1. aarch64 + `sha3` → `hw::pbkdf2_lanes`, else `ring_pbkdf2_sha512` per lane |
| `pbkdf2_lanes.rs:49` | `ring_pbkdf2_sha512(pw, salt, iters)` | `[u8; 64]` via `ring::pbkdf2::derive`. Reference path; panics on 0 iters |
| `pbkdf2_lanes.rs:136`, `:229` | `hw::compress::<L>`, `hw::pbkdf2_lanes::<L>` | `#[target_feature(enable = "sha3")]`, 40 round pairs, lanes interleaved; key > `HMAC_BLOCK_LEN` pre-hashed with ring SHA-512 |
| `bip32.rs:5` | `hmac512(key, data)` | `pub(crate)`, ring HMAC-SHA512 split 32/32. Shared with slip10 |
| `bip32.rs:13` | `bip32_derive_secp256k1(seed, path)` | `SecretKey`. Master key `"Bitcoin seed"`; ≥ `0x80000000` hardened, else compressed pubkey (global ctx) |
| `slip10.rs:6` | `slip10_derive_ed25519(seed, path)` | `[u8; 32]`. Master key `"ed25519 seed"`; panics on a non-hardened index |
| `ton_mnemonic.rs:43`, `:60` | `generate_ton_wallet`, `generate_ton_wallets` | `(String, SigningKey)` via ring, loops until filter passes / `[_; LANES]`, both PBKDF2 stages lane-interleaved |
| `ton_mnemonic.rs:94` | `mnemonic_to_signing_key` | first 32 B of the seed PBKDF2 |
| `ton_cell.rs:65` | `wallet_v5r1_state_init_hash(pubkey)` | `[u8; 32]` W5 account_id. Only cell layout in the tree |
| `verify.rs:16` | `verify_gpu(&[u8; 16], &[u8; 20])` | `Option<([u8; 20], SecretKey, String)>`: `from_entropy` → `derive_seed` → `Evm::from_seed`; any failure → `None` |
| `gpu/pack.rs:18` | `pack_key_block(pw)` | `KeyBlock`; hard-asserts `1..=HMAC_BLOCK_LEN` (GPU has no pre-hash) |

`seed::CANONICAL_PHRASE` (`abandon`×11 `about`) and `CANONICAL_SEED_HEX` (`5eb00bbd…ce9e38e4`) are `pub(crate)` and not test-only: the GPU self-test checks them at runtime.

### Salts & Iteration Counts

| Use | Salt / input | Iterations | Source |
|-----|--------------|------------|--------|
| BIP-39 seed (Solana, EVM, Bitcoin, GPU) | `BIP39_SALT` = `b"mnemonic"` | `PBKDF2_ROUNDS` = 2048 | `seed.rs:11`, `:6` |
| GPU salt block | `BIP39_SALT_BLOCK`: `"mnemonic"` ‖ INT(1) ‖ `0x80` ‖ 0… ‖ `0x460` (1120 bits) | — | `gpu/pack.rs:40` |
| TON entropy | HMAC-SHA512(key = phrase, msg = "") | — | `ton_mnemonic.rs:27` `hmac_sha512_empty_key` |
| TON filter | `b"TON seed version"`, accept if `out[0] == 0` | `PBKDF2_BASIC_ITER` = 390 | `ton_mnemonic.rs:18` |
| TON seed | `b"TON default seed"` | `PBKDF2_SEED_ITER` = 100_000 | `ton_mnemonic.rs:20` |

### Path Constants

| Constant | Value | Used by |
|----------|-------|---------|
| `slip10::PHANTOM_SOLANA_PATH` | m/44'/501'/0'/0' (`[0x8000002C, 0x800001F5, 0x80000000, 0x80000000]`) | Solana |
| `bip32::EVM_PATH` | m/44'/60'/0'/0/0 | EVM, `verify_gpu` |
| `bip32::BTC_BIP84_PATH` | m/84'/0'/0'/0/0 | Bitcoin |

### Other Constants

| Constant | Value | File / note |
|----------|-------|-------------|
| `LANES` | 4 | `pbkdf2_lanes.rs:11`. `BATCH` for Solana/EVM/Bitcoin/TON; Monero keeps 1 |
| `HMAC_BLOCK_LEN` / `MAX_SALT_LEN` | 128 / 107 | `pbkdf2_lanes.rs:41`, `:45`. 107 = 128 − 4 − 1 − 16 |
| `W5_MAINNET_WALLET_ID` / `WALLET_V5R1_CODE_HASH` | `0x7FFF_FF11` / `20834b7b…52d2b72f` (code max_depth 6) | `ton_cell.rs:31`, `:16` |
| `NETWORK_BYTE_MAINNET` / `MONERO_ADDRESS_LEN` | `0x12` / 95 | Monero → leading `4` / 69-byte payload, stack buffer |
| `MATCH_CAP` / `tick_rate` | 500 / 100 ms | `app.rs:29` in-memory list / `main.rs:34` |
| `EVM_GPU_TAIL_SECS` | 50.5e-6 | `app.rs:34`, BIP-32 + kG + Keccak per GPU seed |

## GPU Wave Geometry (`src/gpu/mod.rs:30-73` unless noted)

| Constant | Value | Note |
|----------|-------|------|
| `WAVE` | 8_192 | candidates per wave |
| `BLOCK` | 512 | per channel message, 16 per wave |
| `CHANNEL_CAPACITY` | 32 | two waves of blocks |
| `ITERS_PER_DISPATCH` | 8 | 2047 = 255×8 + 7 → 256 dispatches |
| `DISPATCHES_PER_COMMAND_BUFFER` | 4 | 64 command buffers, ~8.8 ms each |
| `PIPELINE_DEPTH` | 3 | command buffers in flight |
| `MAX_THREADS_PER_THREADGROUP` | 256 | default; `VANADDY_GPU_TG` overrides; rounded to exec width, clamped to pipeline max (`metal.rs:166-177`) |
| `AUDITS_PER_WAVE` | 4 | random indices (`audit_indices`), ring re-derive |
| `EVM_GPU_SEEDS_PER_SEC` | 13_600.0 | pre-search ETA only |
| `GPU_CHUNK_BATCHES` | 16 | `chains/mod.rs:144`. Stop check every 64 candidates |
| `SELF_TEST_COUNT` / `_RAGGED_COUNT` / `IRREGULAR_SCHEDULE` | 512 / 511 / `[1, 1000, 46, 1000]` | `selftest.rs:26-34` |
| seeds poison | `0xA5` | filled every wave (`metal.rs:303`) |

Compile-time asserts (`mod.rs:41-50`): `WAVE % BLOCK == 0`, `CHANNEL_CAPACITY == 2·(WAVE/BLOCK)`, `BLOCK % MAX_THREADS_PER_THREADGROUP == 0`, `AUDITS_PER_WAVE < WAVE`, `ceil(2047/8) % 4 == 0`. `metal.rs:54-55`: `size_of::<KeyBlock>() == 128`, `Params` == 16.

Metal buffers (`WaveBuffers`, `metal.rs:85`): keys `WAVE×128`, states `WAVE×256` (`Pbkdf2State { inner, outer, u, t: ulong[8] }`), seeds `WAVE×64`; 3.5 MiB total, all zeroed on drop. `Params { count, iters, finalize, _pad }: u32`.

## Address Encoding & Match Logic

| Chain | Display (`encode_address`) | Hot `matches_raw` | Vanity slice |
|-------|----------------------------|-------------------|--------------|
| Solana | `bs58::encode` → `String` | stack `[u8; 44]` encode, both helpers on full addr | `addr[..]` |
| EVM | `0x` + `hex::encode` | `matches_evm_raw`; case-sensitive adds both helpers on `[u8; 40]` EIP-55 | hex from index 0 (`0x` display only) |
| Bitcoin | `bech32::encode("bc", ..)` | `expand_5bit` vs `bech32_prefix_5bit` (miss returns pre-encode), then stack `AddrBuf` (64 B) + `encode_to_fmt` | `addr[4..]` (skip `bc1q`) |
| TON | `user_friendly_ascii` → `String` | `[u8; 48]` via `encode_slice` | `encoded[2..]` (skip `UQ`) |
| Monero | `encode_address_into` → `String` | `[u8; 95]` stack Base58 | `addr[1..]` (skip `4`) |

Suffix always checks the full string. TON: 36 B = tag `0x51` ‖ workchain `0x00` ‖ account_id(32) ‖ CRC16-XMODEM. Monero: 65 B payload + 4 B Keccak checksum, Base58 in 8-byte blocks, `BLOCK_SIZES = [0,2,3,5,6,7,9,10,11]`, pad `1`.

## Memory & Secrets

- Solana / TON: ed25519-dalek `SigningKey` zeroizes on drop. EVM / Bitcoin: secp256k1 `SecretKey` is `Copy`, not wiped; hex built only on a match.
- Monero: `MoneroKeypair` wipes on drop; `generate_keys` wipes raw bytes and both `Scalar`s; `monero_seed_phrase` wipes word indices and checksum input.
- CPU search: `search_cpu_step` zeroizes every non-matching candidate's phrase (all chains).
- GPU: `SeedBlock` zeroizes on drop. Producer `entropy` / `keys` are `Zeroizing<Vec<_>>`, overwritten each wave. `pack_key_block` wipes its stack copy. `WaveBuffers` zeroed on drop. The GPU seed is a filter, never a CSV field.
- Entropy: `Mnemonic::new` for BIP-39, TON and the GPU fill; `OsRng` for Monero. Kernel `tid` only in `kernel_src::TID_ALLOWLIST` lines (slot offsets, bounds guard, params).

## CSV Format

| Item | Value |
|------|-------|
| Path | `CSV_PATH = "vanity_wallets.csv"` (`app.rs:712`), cwd. `App::csv_path` overridable (tests) |
| Header | `Chain,Address,Private Key (hex),Seed Phrase`. Written when file length is 0; failure aborts `start_search` |
| Row | `[chain, address, secret_hex, mnemonic]` via `write_match_row` → `write_row` (`has_headers(false)`, flush per record) |
| Secret | Solana 64 B keypair hex (secret ‖ pubkey); EVM / Bitcoin 32 B hex; TON 32 B Ed25519 seed hex; Monero `spend_sec:view_sec` hex |
| Phrase | BIP-39 12 words (Solana / EVM / Bitcoin); TON 24 words; Monero 24 + CRC32 checksum word (1626-word list) |
| Perms | `open_csv_secure` (`app.rs:723`): `mode(0o600)` at create + `file.set_permissions(0o600)` (fchmod on the handle, error propagates) every open |
| Writers | held `File` from `start_search`; `append_match_row` (`app.rs:762`) when none. `stop_search` compares dev/ino, warns if replaced or deleted |

## Test Vectors (pinned)

179 `#[test]` fns, 4 `#[ignore]`. Load-bearing:

| Test | What it pins |
|------|--------------|
| `seed::derive_seed_matches_bip39_vector`, `derive_seeds_matches_derive_seed_per_lane` | canonical 64-byte seed; lanes == ring |
| `pbkdf2_lanes::every_lane_matches_bip39_canonical_vector`, `distinct_lanes_match_ring_reference` | hardware PBKDF2; 4 phrases (one > 128 B) == ring |
| `pbkdf2_lanes::ton_salts_and_iteration_counts_match_ring` | TON 390 and 100_000 |
| `pbkdf2_lanes::hmac_block_len_is_the_prehash_boundary_and_max_salt_len_is_the_padding_budget` | 128 / 107 bounds |
| `slip10::slip10_ed25519_test_vector_1_m_0h`, `slip10_ed25519_test_vector_1_m_0h_1h` | SLIP-0010 |
| `solana::solana_phantom_derivation_from_canonical_phrase` | `HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk` |
| `bitcoin::bip84_canonical_vector` | `bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu` |
| `evm::bip44_canonical_vector`; `eip55_canonical_vector`, `eip55_second_vector` | `0x9858EfFD232B4033E47d90003D41EC34EcaEda94`; EIP-55 |
| `{solana,evm,bitcoin}::generate_batch_emits_lane_count_candidates_matching_single_path`, `ton::generate_batch_emits_lane_count_wallets_with_consistent_addresses` | batch == single |
| `ton::ton_tonkeeper_round_trip_vector` | `UQAkFCMtkN0Q1TNP6Gk9SqYWsBFc6Aglwckj6ES4AeBEzWja` |
| `ton_cell::wallet_v5r1_matches_tonkeeper_vector`, `wallet_v5r1_data_cell_zero_pubkey_pins_hash` | state_init hash `2414232d…01e044cd`; data-cell layout |
| `monero::keccak256_empty_vector` | original Keccak, not SHA3 |
| `monero::monero_seed_phrase_sequential_bytes_pinned`, `monero_generate_keys_are_consistent` | self-captured 25 words (no external vector); view = H(spend), pubs = secret·G |
| `bitcoin::matches_raw_agrees_with_encode_address_for_one_char_prefix_and_suffix`, `ton::matches_raw_agrees_with_encode_address_for_one_char_affix`, `monero::monero_matches_raw_agrees_with_encode_address`, `{solana,evm}::matches_raw_agrees_with_encode_address_on_random_candidates` | stack encode == `encode_address` |
| `chains::chain_kind_search_with_no_gpu_source_is_unchanged`, `corrupted_gpu_seed_raises_fault_and_emits_nothing` | counter steps by `BATCH`; verify miss → `VerifyMismatch`, no row |
| `verify::verify_gpu_accepts_the_bip39_canonical_vector` | entropy 0 → MetaMask account |
| `gpu::pack::pack_key_block_matches_the_cpu_ipad_and_opad_blocks` | GPU key block == CPU HMAC pads |
| `gpu::selftest::detects_every_corruption` | 8 fault shapes each caught |
| `gpu::backend::gpu_seed_matches_bip39_canonical_vector` | GPU vs BIP-39 vector |
| `gpu::backend::gpu_chunk_schedule_invariance` | 5 schedules incl. production R=8, `[1,1000,46,1000]` |
| `gpu::backend::gpu_ring_and_4lane_agree_over_512_deterministic_phrases` | GPU == ring == 4-lane |
| `gpu::kernel_src` `kernel_source_uses_tid_only_in_index_expressions`, `kernel_source_bans_threadgroup_simd_barrier_atomic` | kernel source |
