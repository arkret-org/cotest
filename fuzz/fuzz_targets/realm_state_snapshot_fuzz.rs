//! P5.1 — libFuzzer target for the authority snapshot and commit parsers.
//!
//! Splits the input across the three `fuzz_*` entry points so libFuzzer
//! exercises the signed typed snapshot, one `RealmCommit` and its shape rule,
//! and a returned stream tail with its contiguity walk. Output is discarded —
//! panics are converted to Err by `catch_unwind` inside the harness;
//! libfuzzer-sys's signal handler catches anything that still aborts.
#![no_main]

use cotest::fuzz::realm_state_snapshot_fuzz::{
    fuzz_realm_commit, fuzz_realm_state_snapshot, fuzz_stream_scan_outcome,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let (selector, payload) = data.split_first().expect("non-empty checked above");
    let _ = match selector % 3 {
        0 => fuzz_realm_state_snapshot(payload),
        1 => fuzz_realm_commit(payload),
        _ => fuzz_stream_scan_outcome(payload),
    };
});
