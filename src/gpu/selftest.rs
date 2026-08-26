//! GPU self-test fault taxonomy. Milestone 3 adds the injectable `self_test`
//! checker itself; this milestone defines only the error type, because
//! `GpuDisableReason::SelfTest` carries it.

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
    /// 0xA5 survived -> the kernel never wrote this slot.
    Poisoned {
        index: usize,
    },
    ScheduleDivergence {
        schedule: &'static str,
        index: usize,
    },
    /// The freshly generated phrases were not all distinct -> an RNG fault, not
    /// a GPU fault, but equally disqualifying. Only milestone 3's self-test
    /// raises it; it is declared here so that milestone's rewrite of this file
    /// cannot diverge from the taxonomy milestone 1 published.
    DuplicateEntropy {
        distinct: usize,
        want: usize,
    },
    Backend(String),
}
