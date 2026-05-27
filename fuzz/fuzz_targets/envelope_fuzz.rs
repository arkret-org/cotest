//! P5.1 — libFuzzer target for the wire-envelope harness.
//!
//! Rotates through the four envelope shapes in `cotest::fuzz::envelope_fuzz`
//! using the first byte of the input as a discriminator so libFuzzer's coverage
//! feedback drives each branch. Any panic / unwrap / overflow that escapes the
//! validator is a finding — `libfuzzer-sys` will abort and record the input.
#![no_main]

use libfuzzer_sys::fuzz_target;

use cotest::fuzz::envelope_fuzz::{
    fuzz_anchor_envelope, fuzz_event_envelope, fuzz_move_envelope, fuzz_snapshot_chunk,
};

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let (selector, payload) = data.split_first().expect("non-empty checked above");
    // Discriminate so libFuzzer can credit branch coverage per envelope shape;
    // the validators all return `Result<(), String>` on panic — surfacing
    // means the inner `catch_unwind` already converted a panic into Err.
    let _ = match selector % 4 {
        0 => fuzz_event_envelope(payload),
        1 => fuzz_move_envelope(payload),
        2 => fuzz_anchor_envelope(payload),
        _ => fuzz_snapshot_chunk(payload),
    };
});
