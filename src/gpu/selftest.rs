//! GPU self-test. Runs once on the GPU thread before any candidate is accepted,
//! and is the only thing standing between a mis-compiled kernel and a user's
//! wallet.
//!
//! `derive` is injected so the fault-detection logic can be unit-tested on any
//! machine by passing a deliberately faulty closure. No Metal type appears in
//! this file: it compiles, and its tests run, on Linux and under
//! `--no-default-features`.
//!
//! Measured cost of one real run: ~154 ms of GPU plus ~512 × 260 µs = 133 ms of
//! `ring`, i.e. ~300 ms one-time on the GPU thread, off the UI thread.

use crate::gpu::{GpuError, Schedule};
use crate::seed::{CANONICAL_PHRASE, CANONICAL_SEED_HEX};
use bip39::{Language, Mnemonic, MnemonicType};
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use zeroize::Zeroizing;

/// 512 candidates = 2 threadgroups at tg=256. `count = 1` is REJECTED: it
/// structurally cannot exercise `keyblocks + 16*tid`, `states + tid`,
/// `seeds + 64*tid`, or the host-side 128-byte `KeyBlock` stride — every
/// candidate except tid 0 could derive from the wrong key block and a count=1
/// test would still pass cleanly.
pub const SELF_TEST_COUNT: usize = 512;

/// Deliberately not a multiple of 256 (the threadgroup size) or of 32 (the
/// SIMD width), so the non-uniform tail of `dispatchThreads` is exercised.
pub const SELF_TEST_RAGGED_COUNT: usize = 511;

/// 1 + 1000 + 46 + 1000 = 2047: the same total, cut nothing like the production
/// schedule.
pub const IRREGULAR_SCHEDULE: Schedule = Schedule::Irregular(&[1, 1000, 46, 1000]);

/// All 2047 follow-up iterations in one dispatch.
const ONE_SHOT_SCHEDULE: Schedule = Schedule::Irregular(&[crate::seed::PBKDF2_ROUNDS - 1]);

/// The byte `run_wave` fills `seeds` with before every wave.
const POISON: u8 = 0xA5;

#[derive(Debug, Clone, PartialEq)]
pub enum SelfTestError {
    WrongLength {
        got: usize,
        want: usize,
    },
    CanonicalVectorMismatch {
        got: String,
    },
    RingMismatch {
        index: usize,
        phrase: String,
        got: String,
        want: String,
    },
    AllZero {
        index: usize,
    },
    /// 0xA5 survived → the kernel never wrote this slot.
    Poisoned {
        index: usize,
    },
    ScheduleDivergence {
        schedule: &'static str,
        index: usize,
    },
    /// The freshly generated phrases were not all distinct — an RNG fault, not
    /// a GPU fault, but equally disqualifying.
    DuplicateEntropy {
        distinct: usize,
        want: usize,
    },
    Backend(String),
}

impl From<GpuError> for SelfTestError {
    fn from(e: GpuError) -> Self {
        SelfTestError::Backend(format!("{e:?}"))
    }
}

/// Run the whole self-test against an injected `derive`.
///
/// Six checks, in this order:
///   1. entropy distinctness over the 510 fresh phrases;
///   2. a count=512 wave, all distinct phrases;
///   3. the BIP-39 canonical vector at index 0 AND index 511 — checked BEFORE
///      any `ring` cross-check, because `ring` is what `derive_seed` uses and a
///      `ring`-first check would be circular;
///   4. no output all-zero, no output still poisoned;
///   5. every output against `crate::seed::derive_seed` (`ring`);
///   6. a count=511 ragged wave against the ring-checked count=512 outputs,
///      and chunk-schedule invariance over three schedules.
///
/// `stop` is read before the first phase and after each one. One run is ~154 ms
/// of GPU plus ~133 ms of `ring` — long enough that a quit issued during startup
/// would otherwise go unobserved for ~300 ms. A raised flag returns `Ok(())`,
/// not an error: nothing was proven faulty, and reporting a
/// `GpuDisableReason::SelfTest` on the way out would be a lie.
pub fn self_test<F>(stop: &AtomicBool, mut derive: F) -> Result<(), SelfTestError>
where
    F: FnMut(&[&str], u32, Schedule) -> Result<Vec<Zeroizing<[u8; 64]>>, GpuError>,
{
    if stop.load(Ordering::Relaxed) {
        return Ok(());
    }

    let mut mnemonics: Vec<Mnemonic> = Vec::with_capacity(SELF_TEST_COUNT);
    mnemonics.push(
        Mnemonic::from_phrase(CANONICAL_PHRASE, Language::English).expect("canonical phrase"),
    );
    for _ in 1..SELF_TEST_COUNT - 1 {
        mnemonics.push(Mnemonic::new(MnemonicType::Words12, Language::English));
    }
    mnemonics.push(
        Mnemonic::from_phrase(CANONICAL_PHRASE, Language::English).expect("canonical phrase"),
    );

    let fresh: HashSet<[u8; 16]> = mnemonics[1..SELF_TEST_COUNT - 1]
        .iter()
        .map(|m| {
            let mut e = [0u8; 16];
            e.copy_from_slice(m.entropy());
            e
        })
        .collect();
    if fresh.len() != SELF_TEST_COUNT - 2 {
        return Err(SelfTestError::DuplicateEntropy {
            distinct: fresh.len(),
            want: SELF_TEST_COUNT - 2,
        });
    }
    if stop.load(Ordering::Relaxed) {
        return Ok(());
    }

    let phrases: Vec<&str> = mnemonics.iter().map(|m| m.phrase()).collect();

    let full = derive(&phrases, crate::seed::PBKDF2_ROUNDS, Schedule::Production)?;
    if full.len() != SELF_TEST_COUNT {
        return Err(SelfTestError::WrongLength {
            got: full.len(),
            want: SELF_TEST_COUNT,
        });
    }
    for i in [0usize, SELF_TEST_COUNT - 1] {
        let got = hex::encode(*full[i]);
        if got != CANONICAL_SEED_HEX {
            return Err(SelfTestError::CanonicalVectorMismatch { got });
        }
    }
    for (i, seed) in full.iter().enumerate() {
        if seed.iter().all(|&b| b == 0) {
            return Err(SelfTestError::AllZero { index: i });
        }
        if seed.iter().all(|&b| b == POISON) {
            return Err(SelfTestError::Poisoned { index: i });
        }
    }
    if stop.load(Ordering::Relaxed) {
        return Ok(());
    }

    for (i, seed) in full.iter().enumerate() {
        let want = hex::encode(crate::seed::derive_seed(&mnemonics[i]));
        let got = hex::encode(**seed);
        if got != want {
            return Err(SelfTestError::RingMismatch {
                index: i,
                phrase: phrases[i].to_string(),
                got,
                want,
            });
        }
    }

    if stop.load(Ordering::Relaxed) {
        return Ok(());
    }

    let ragged = derive(
        &phrases[..SELF_TEST_RAGGED_COUNT],
        crate::seed::PBKDF2_ROUNDS,
        Schedule::Production,
    )?;
    if ragged.len() != SELF_TEST_RAGGED_COUNT {
        return Err(SelfTestError::WrongLength {
            got: ragged.len(),
            want: SELF_TEST_RAGGED_COUNT,
        });
    }
    // `full` already matched `ring` slot for slot, so it is the reference here.
    for (i, (seed, want)) in ragged.iter().zip(full.iter()).enumerate() {
        if seed.iter().all(|&b| b == POISON) {
            return Err(SelfTestError::Poisoned { index: i });
        }
        if seed != want {
            return Err(SelfTestError::RingMismatch {
                index: i,
                phrase: phrases[i].to_string(),
                got: hex::encode(**seed),
                want: hex::encode(**want),
            });
        }
    }

    if stop.load(Ordering::Relaxed) {
        return Ok(());
    }

    for (label, schedule) in [
        ("one-shot", ONE_SHOT_SCHEDULE),
        ("production", Schedule::Production),
        ("irregular", IRREGULAR_SCHEDULE),
    ] {
        let one = derive(&[CANONICAL_PHRASE], crate::seed::PBKDF2_ROUNDS, schedule)?;
        if one.len() != 1 {
            return Err(SelfTestError::WrongLength {
                got: one.len(),
                want: 1,
            });
        }
        if hex::encode(*one[0]) != CANONICAL_SEED_HEX {
            return Err(SelfTestError::ScheduleDivergence {
                schedule: label,
                index: 0,
            });
        }
    }

    Ok(())
}

/// PBKDF2-HMAC-SHA512 over `crate::seed::BIP39_SALT` via `ring` — the same
/// primitive `src/seed.rs` uses, but with `iters` free. The reference every GPU
/// test compares against.
#[cfg(test)]
pub(crate) fn ring_reference(phrase: &str, iters: u32) -> [u8; 64] {
    let mut out = [0u8; 64];
    ring::pbkdf2::derive(
        ring::pbkdf2::PBKDF2_HMAC_SHA512,
        std::num::NonZeroU32::new(iters).expect("iters >= 1"),
        crate::seed::BIP39_SALT,
        phrase.as_bytes(),
        &mut out,
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    type Seeds = Vec<Zeroizing<[u8; 64]>>;

    /// A correct backend: `ring`, ignoring the schedule (a correct GPU produces
    /// the same bytes under every schedule — that is the property being tested).
    fn reference(phrases: &[&str], iters: u32, _schedule: Schedule) -> Result<Seeds, GpuError> {
        Ok(phrases
            .iter()
            .map(|p| Zeroizing::new(ring_reference(p, iters)))
            .collect())
    }

    /// Run the self-test over `reference`, with `mutate` corrupting each
    /// call's output, and return the error it must report.
    fn fails_with(mut mutate: impl FnMut(&[&str], Schedule, &mut Seeds)) -> SelfTestError {
        self_test(&AtomicBool::new(false), |p, i, s| {
            let mut o = reference(p, i, s)?;
            mutate(p, s, &mut o);
            Ok(o)
        })
        .unwrap_err()
    }

    #[test]
    fn accepts_a_correct_derive_fn() {
        assert_eq!(self_test(&AtomicBool::new(false), reference), Ok(()));
    }

    #[test]
    fn detects_every_corruption() {
        type Mutate = fn(&[&str], Schedule, &mut Seeds);
        type Check = fn(&SelfTestError) -> bool;
        let cases: [(&str, Mutate, Check); 8] = [
            // The same flip on every wave, so the ragged wave agrees with the
            // full one: only the full-wave `ring` loop can see it.
            (
                "single bit flip",
                |_, _, o| {
                    if o.len() > 7 {
                        o[7][0] ^= 0x01;
                    }
                },
                |e| matches!(e, SelfTestError::RingMismatch { index: 7, .. }),
            ),
            // A permutation: every seed is individually valid, but paired with
            // the wrong phrase. This is the mis-pairing class, and it is the one
            // a count=1 self-test can never see.
            (
                "swapped outputs",
                |_, _, o| {
                    if o.len() > 4 {
                        o.swap(3, 4);
                    }
                },
                |e| matches!(e, SelfTestError::RingMismatch { index: 3, .. }),
            ),
            (
                "all-zero output",
                |_, _, o| {
                    if o.len() > 9 {
                        o[9] = Zeroizing::new([0u8; 64]);
                    }
                },
                |e| *e == SelfTestError::AllZero { index: 9 },
            ),
            (
                "surviving poison",
                |_, _, o| {
                    if o.len() > 12 {
                        o[12] = Zeroizing::new([0xA5u8; 64]);
                    }
                },
                |e| *e == SelfTestError::Poisoned { index: 12 },
            ),
            (
                "short output vec",
                |_, _, o| {
                    o.pop();
                },
                |e| {
                    *e == SelfTestError::WrongLength {
                        got: SELF_TEST_COUNT - 1,
                        want: SELF_TEST_COUNT,
                    }
                },
            ),
            (
                "schedule divergence",
                |_, s, o| {
                    if s == ONE_SHOT_SCHEDULE {
                        o[0][63] ^= 0x80;
                    }
                },
                |e| {
                    *e == SelfTestError::ScheduleDivergence {
                        schedule: "one-shot",
                        index: 0,
                    }
                },
            ),
            // Corrupts only the canonical slot (index 0), before any ring
            // cross-check runs. This is the self-test's only non-circular anchor
            // to an external BIP-39 fact — `reference()` and `derive_seed` both
            // call `ring::pbkdf2::derive` identically, so everywhere else a
            // fault that disagrees with `ring` also disagrees with `ring`, which
            // proves nothing about `ring` itself being right. If the
            // `CanonicalVectorMismatch` check were ever deleted, execution would
            // fall through to the ring cross-check, which would (correctly, but
            // for the wrong reason) report `RingMismatch` instead — so this
            // case's exact-variant check catches the regression.
            (
                "canonical vector mismatch",
                |_, _, o| o[0][0] ^= 0x01,
                |e| {
                    let mut bytes = hex::decode(CANONICAL_SEED_HEX).expect("valid hex constant");
                    bytes[0] ^= 0x01;
                    *e == SelfTestError::CanonicalVectorMismatch {
                        got: hex::encode(bytes),
                    }
                },
            ),
            // Corrupts index 250 ONLY on the count=512 wave, leaving the
            // count=511 ragged wave and the single-phrase schedule calls
            // untouched, so the full and ragged waves disagree there.
            (
                "full-wave-only ring mismatch",
                |p, _, o| {
                    if p.len() == SELF_TEST_COUNT {
                        o[250][0] ^= 0x01;
                    }
                },
                |e| matches!(e, SelfTestError::RingMismatch { index: 250, .. }),
            ),
        ];
        for (label, mutate, check) in cases {
            let e = fails_with(mutate);
            assert!(check(&e), "{label}: {e:?}");
        }
    }

    /// The backend serves a previous wave's results, shifted by one — the shape
    /// a stale `seeds` buffer takes when `finalize` silently did not run. The
    /// first (full) wave is served honestly, so it is the ragged-vs-full check
    /// that reports it.
    #[test]
    fn detects_stale_previous_result() {
        let mut previous: Option<Seeds> = None;
        let e = fails_with(|p, _, o| match &previous {
            None => previous = Some(o.clone()),
            Some(old) => *o = old[1..=p.len()].to_vec(),
        });
        assert!(
            matches!(
                &e,
                SelfTestError::RingMismatch { index: 0, want, .. } if want == CANONICAL_SEED_HEX
            ),
            "{e:?}"
        );
    }

    #[test]
    fn detects_backend_error() {
        let e = self_test(&AtomicBool::new(false), |_, _, _| {
            Err(GpuError::BufferAlloc)
        })
        .unwrap_err();
        assert_eq!(e, SelfTestError::Backend("BufferAlloc".to_string()));
    }

    /// The spec requires `stop` to be observed between self-test phases. A flag
    /// that is already raised must short-circuit before the very first phase —
    /// the `derive` closure below panics if it is ever called.
    #[test]
    fn an_already_raised_stop_short_circuits_without_a_fault() {
        let stop = AtomicBool::new(true);
        assert_eq!(
            self_test(&stop, |_, _, _| panic!(
                "derive must not run once stop is set"
            )),
            Ok(())
        );
    }
}
