//! P5.1 — libFuzzer target for the wire-envelope harness.
//!
//! Rotates through the same envelope harness as the native smoke tests using
//! the first byte of the input as a discriminator so libFuzzer's coverage
//! feedback drives each branch. Any panic / unwrap / overflow that escapes the
//! validator is a finding — `libfuzzer-sys` will abort and record the input.
#![no_main]

#[path = "../../src/fuzz/mod.rs"]
pub mod fuzz;

use fuzz::envelope_fuzz::{fuzz_event_envelope, fuzz_signal_envelope};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let (selector, payload) = data.split_first().expect("non-empty checked above");
    // Discriminate so libFuzzer can credit branch coverage per envelope shape;
    // Ordinary validation rejection returns Ok; Err is a caught panic and
    // must escape so libFuzzer records a finding and its reproducing input.
    let result = if selector % 2 == 0 {
        fuzz_event_envelope(payload)
    } else {
        fuzz_signal_envelope(payload)
    };
    result.expect("envelope validator panicked");
});
