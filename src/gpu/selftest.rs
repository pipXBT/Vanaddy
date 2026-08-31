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

/// BIP-39 canonical vector — the same phrase and the same hex constant already
/// pinned at src/seed.rs:37 and src/seed.rs:41.
pub const CANONICAL_PHRASE: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
pub const CANONICAL_SEED_HEX: &str = "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4";

/// 1 + 1000 + 46 + 1000 = 2047: the same total, cut nothing like the production
/// schedule.
pub const IRREGULAR_SCHEDULE: Schedule = Schedule::Irregular(&[1, 1000, 46, 1000]);

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
///   6. a count=511 ragged wave, and chunk-schedule invariance over three
///      schedules.
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
    for (i, seed) in ragged.iter().enumerate() {
        if seed.iter().all(|&b| b == POISON) {
            return Err(SelfTestError::Poisoned { index: i });
        }
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

    for (label, schedule) in [
        (
            "one-shot",
            Schedule::Uniform(crate::seed::PBKDF2_ROUNDS - 1),
        ),
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A correct backend: `ring`, ignoring the schedule (a correct GPU produces
    /// the same bytes under every schedule — that is the property being tested).
    fn reference(
        phrases: &[&str],
        iters: u32,
        _schedule: Schedule,
    ) -> Result<Vec<Zeroizing<[u8; 64]>>, GpuError> {
        Ok(phrases
            .iter()
            .map(|p| {
                let mut out = [0u8; 64];
                ring::pbkdf2::derive(
                    ring::pbkdf2::PBKDF2_HMAC_SHA512,
                    std::num::NonZeroU32::new(iters).expect("iters >= 1"),
                    crate::seed::BIP39_SALT,
                    p.as_bytes(),
                    &mut out,
                );
                Zeroizing::new(out)
            })
            .collect())
    }

    #[test]
    fn accepts_a_correct_derive_fn() {
        assert_eq!(self_test(&AtomicBool::new(false), reference), Ok(()));
    }

    #[test]
    fn detects_single_bit_flip() {
        let e = self_test(&AtomicBool::new(false), |p, i, s| {
            let mut o = reference(p, i, s)?;
            if o.len() > 7 {
                o[7][0] ^= 0x01;
            }
            Ok(o)
        })
        .unwrap_err();
        assert!(
            matches!(e, SelfTestError::RingMismatch { index: 7, .. }),
            "{e:?}"
        );
    }

    /// A permutation: every seed is individually valid, but paired with the
    /// wrong phrase. This is the mis-pairing class, and it is the one a
    /// count=1 self-test can never see.
    #[test]
    fn detects_swapped_outputs() {
        let e = self_test(&AtomicBool::new(false), |p, i, s| {
            let mut o = reference(p, i, s)?;
            if o.len() > 4 {
                o.swap(3, 4);
            }
            Ok(o)
        })
        .unwrap_err();
        assert!(
            matches!(e, SelfTestError::RingMismatch { index: 3, .. }),
            "{e:?}"
        );
    }

    #[test]
    fn detects_all_zero_output() {
        let e = self_test(&AtomicBool::new(false), |p, i, s| {
            let mut o = reference(p, i, s)?;
            if o.len() > 9 {
                o[9] = Zeroizing::new([0u8; 64]);
            }
            Ok(o)
        })
        .unwrap_err();
        assert_eq!(e, SelfTestError::AllZero { index: 9 });
    }

    #[test]
    fn detects_surviving_poison() {
        let e = self_test(&AtomicBool::new(false), |p, i, s| {
            let mut o = reference(p, i, s)?;
            if o.len() > 12 {
                o[12] = Zeroizing::new([0xA5u8; 64]);
            }
            Ok(o)
        })
        .unwrap_err();
        assert_eq!(e, SelfTestError::Poisoned { index: 12 });
    }

    /// The backend serves a previous wave's results, shifted by one — the shape
    /// a stale `seeds` buffer takes when `finalize` silently did not run.
    #[test]
    fn detects_stale_previous_result() {
        let mut previous: Option<Vec<Zeroizing<[u8; 64]>>> = None;
        let e = self_test(&AtomicBool::new(false), |p, i, s| {
            let fresh = reference(p, i, s)?;
            match previous.take() {
                None => {
                    previous = Some(fresh.clone());
                    Ok(fresh)
                }
                Some(old) => {
                    previous = Some(old.clone());
                    Ok(old[1..=p.len()].to_vec())
                }
            }
        })
        .unwrap_err();
        assert!(matches!(e, SelfTestError::RingMismatch { .. }), "{e:?}");
    }

    #[test]
    fn detects_short_output_vec() {
        let e = self_test(&AtomicBool::new(false), |p, i, s| {
            let mut o = reference(p, i, s)?;
            o.pop();
            Ok(o)
        })
        .unwrap_err();
        assert_eq!(
            e,
            SelfTestError::WrongLength {
                got: SELF_TEST_COUNT - 1,
                want: SELF_TEST_COUNT
            }
        );
    }

    #[test]
    fn detects_schedule_divergence() {
        let e = self_test(&AtomicBool::new(false), |p, i, s| {
            let mut o = reference(p, i, s)?;
            if s == Schedule::Uniform(crate::seed::PBKDF2_ROUNDS - 1) {
                o[0][63] ^= 0x80;
            }
            Ok(o)
        })
        .unwrap_err();
        assert_eq!(
            e,
            SelfTestError::ScheduleDivergence {
                schedule: "one-shot",
                index: 0
            }
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
