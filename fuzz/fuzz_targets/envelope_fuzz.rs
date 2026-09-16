//! P5.1 — libFuzzer target for the wire-envelope harness.
//!
//! Rotates through the envelope shapes in `cotest::fuzz::envelope_fuzz` using
//! the first byte of the input as a discriminator so libFuzzer's coverage
//! feedback drives each branch. Any panic / unwrap / overflow that escapes the
//! validator is a finding — `libfuzzer-sys` will abort and record the input.
#![no_main]

use cotest::fuzz::envelope_fuzz::{fuzz_event_envelope, fuzz_signal_envelope};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let (selector, payload) = data.split_first().expect("non-empty checked above");
    // Discriminate so libFuzzer can credit branch coverage per envelope shape;
    // the validators all return `Result<(), String>` on panic — surfacing
    // means the inner `catch_unwind` already converted a panic into Err.
    let _ = if selector % 2 == 0 {
        fuzz_event_envelope(payload)
    } else {
        fuzz_signal_envelope(payload)
    };
});
