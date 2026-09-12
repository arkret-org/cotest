//! P5.1 — libFuzzer target for the deep-Seal harness.
//!
//! Wraps `cotest::fuzz::seal_fuzz::fuzz_seal_deep` so libFuzzer's
//! coverage-guided mutator can search the Seal schema and typed validator
//! surface.
#![no_main]

use cotest::fuzz::seal_fuzz::fuzz_seal_deep;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = fuzz_seal_deep(data);
});
