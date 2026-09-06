//! P5.1 — libFuzzer target for snapshot manifest + chunk-header parsing.
//!
//! Splits the input across the two `fuzz_snapshot_*` entry points so libFuzzer
//! exercises both the manifest schema validator and the chunk-header
//! discriminator. Output is discarded — panics are converted to Err by
//! `catch_unwind` inside the harness; libfuzzer-sys's signal handler catches
//! anything that still aborts the process.
#![no_main]

use cotest::fuzz::realm_state_snapshot_fuzz::{fuzz_realm_state_snapshot_chunk_header, fuzz_realm_state_snapshot_manifest};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let (selector, payload) = data.split_first().expect("non-empty checked above");
    let _ = if selector & 1 == 0 {
        fuzz_realm_state_snapshot_manifest(payload)
    } else {
        fuzz_realm_state_snapshot_chunk_header(payload)
    };
});
