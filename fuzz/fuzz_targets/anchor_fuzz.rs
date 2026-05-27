//! P5.1 — libFuzzer target for the deep-anchor harness.
//!
//! Wraps `cotest::fuzz::anchor_fuzz::fuzz_anchor_deep` so libFuzzer's
//! coverage-guided mutator can search the anchor lattice / inclusion-proof
//! validator surface.
#![no_main]

use libfuzzer_sys::fuzz_target;

use cotest::fuzz::anchor_fuzz::fuzz_anchor_deep;

fuzz_target!(|data: &[u8]| {
    let _ = fuzz_anchor_deep(data);
});
