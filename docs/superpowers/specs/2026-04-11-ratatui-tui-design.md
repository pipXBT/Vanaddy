# Vanaddy Ratatui TUI Design

## Overview

Replace the current println-based interactive prompts and progress display with a full Ratatui terminal UI. The search engine, matching logic, and CSV output are unchanged — only the presentation layer changes.

## Layout

```
┌──────────────────────────────────────────────────────────────────┐
│                         Logo Banner (20%)                        │
│              Vanaddy ASCII art + version, centered               │
├────────────────┬─────────────────────────────────────────────────┤
│ Config (25%)   │ Results (75%)                                   │
│                │                                                 │
│ Form fields    │ ┌─ Matches (scrollable table) ────────────────┐ │
│ (top section)  │ │ #  Chain   Address                          │ │
│                │ │ 1  Solana  ABcF7k...xyz                     │ │
│                │ │ 2  Solana  ABcD9m...qrs                     │ │
│ Live stats     │ ├─ Detail (selected match) ───────────────────┤ │
│ (bottom sect.) │ │ Address: full address                       │ │
│                │ │ Key: full hex private key                   │ │
│ Key hints      │ │ Phrase: word1 word2 ... word12              │ │
├────────────────┴─────────────────────────────────────────────────┤
```

- **Top ~20%**: Bordered block with Vanaddy ASCII logo, centered, version subtitle
- **Bottom ~80%**: Horizontal split — left 25% config/stats, right 75% results
- **Left panel**: Config form (top), live stats (bottom), key hints (footer)
- **Right panel**: Match table (top, scrollable), detail view (bottom, shows selected match)

## App States

### Configuring

- All 5 form fields visible, active field highlighted
- Tab/Shift-Tab navigates between fields
- Field-specific input: 1/2/3 for toggles, typing for text, y/n for boolean
- Right panel shows empty placeholder: "Configure and press Enter to start"
- Enter validates and starts search; invalid input shows inline error
- q quits

### Searching

- Left panel: config summary (read-only), live stats (checked, rate, matches, elapsed)
- Right panel: match table populates as matches arrive, detail view shows selected match
- Up/Down arrow selects match in table, detail view updates
- Ctrl+C stops search, returns to Configuring state (can tweak and re-run)
- q quits

## Form Fields

| # | Field | Input Type | Values |
|---|-------|-----------|--------|
| 0 | Chain | Toggle (1/2) | Solana, EVM |
| 1 | Match position | Toggle (1/2/3) | Starts with, Ends with, Both |
| 2 | Vanity string | Text input | Prefix (and suffix if Both) |
| 3 | Case sensitive | Toggle (y/n) | Yes, No |
| 4 | Threads | Text input | Pre-filled with auto-detected recommendation |

When match position is "Both", field 2 shows two sub-inputs: prefix and suffix.

## Architecture

### Approach

Single-file (main.rs). All TUI code added alongside existing search logic.

### Dependencies

- `ratatui = "0.29"` (includes crossterm backend)
- `crossterm` (terminal raw mode, event polling)

### App Struct

```rust
struct App {
    state: AppState,              // Configuring | Searching
    active_field: usize,          // 0-4
    chain: Chain,
    match_position: MatchPosition,
    vanity_prefix: String,
    vanity_suffix: String,
    case_sensitive: bool,
    thread_count: String,
    error_message: Option<String>,
    matches: Vec<MatchPayload>,
    selected_match: usize,
    counter: Arc<AtomicU64>,
    match_count: Arc<AtomicU64>,
    start_time: Option<Instant>,
    stop: Arc<AtomicBool>,
    should_quit: bool,
}
```

### Event Loop (10fps)

```
loop {
    terminal.draw(|f| ui(f, &app))?;
    if crossterm::event::poll(Duration::from_millis(100))? {
        handle_key_event(&mut app);
    }
    drain_match_channel(&mut app);
    if app.should_quit { break; }
}
```

- 100ms poll timeout = 10fps rendering
- Key events handled immediately when available
- Match channel drained each tick — new matches appended to app.matches

### Unchanged Components

These are NOT modified:

- `derive_seed()` — ring PBKDF2
- `bip32_derive_evm_key()` — BIP-32 derivation
- `generate_solana_raw()` / `generate_evm_raw()` — key generation
- `search_solana_raw()` / `search_evm_raw()` — worker loops
- `Matcher` — all matching logic
- CSV writing — matches written to vanity_wallets.csv as they arrive

### Removed Components

- `display_banner()` — replaced by TUI logo widget
- `read_chain()`, `read_match_position()`, `read_vanity_string()`, `read_case_sensitivity()`, `read_thread_count()` — replaced by TUI form
- `read_line_trimmed()` — no longer needed
- Progress display thread — replaced by TUI render loop
- All `println!`/`print!` output — replaced by Ratatui widgets

## Keybindings

### Configuring State

| Key | Action |
|-----|--------|
| Tab | Next field |
| Shift-Tab | Previous field |
| 1/2/3 | Select option (toggle fields) |
| y/n | Toggle case sensitivity |
| Typing | Text input (vanity string, threads) |
| Backspace | Delete last char in text input |
| Enter | Validate and start search |
| q | Quit (only when not in a text input field) |

### Searching State

| Key | Action |
|-----|--------|
| Up/Down | Select match in table |
| Ctrl+C | Stop search, return to Configuring |
| q | Quit application |

## Validation

On Enter (start search):
- Vanity string must be 1-9 chars (Solana) or 1-8 chars (EVM)
- Characters must be valid for chain charset (base58 or hex)
- Thread count must be 1 to 2x logical cores
- If "Both" selected, both prefix and suffix must be non-empty

Errors shown inline in the left panel (red text below the invalid field).
