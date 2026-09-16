//! CT-19 — wire-envelope fuzz smoke test.
//!
//! Runs 1000 deterministic-but-randomised inputs through each fuzz entry
//! point in [`cotest::fuzz::envelope_fuzz`] and asserts no panic escapes the
//! validator boundary. A panic here is itself the finding and means the SDK
//! has an unwrap / panic / overflow on attacker-controlled wire bytes.
//!
//! Run with output:
//!
//!   cargo test -p cotest --test fuzz_envelope_smoke -- --nocapture

use std::collections::BTreeMap;

use cotest::fuzz::envelope_fuzz::{fuzz_event_envelope, fuzz_signal_envelope};
use cotest::fuzz::realm_state_snapshot_fuzz::{
    fuzz_realm_commit, fuzz_realm_state_snapshot, fuzz_stream_scan_outcome,
};

/// Deterministic-but-mixing PRNG: a 64-bit xorshift seeded from
/// `iter_index` so re-running the smoke test reproduces the same byte
/// stream. Pure stdlib so the test does not pick up a `rand` dependency.
fn fill_random(seed: u64, buffer: &mut [u8]) {
    let mut state = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    for chunk in buffer.chunks_mut(8) {
        // xorshift64*
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        let value = state.wrapping_mul(0x2545_F491_4F6C_DD1D);
        for (i, byte) in chunk.iter_mut().enumerate() {
            *byte = ((value >> (i * 8)) & 0xff) as u8;
        }
    }
}

const ITERATIONS: usize = 1000;
const INPUT_BYTES: usize = 256;

fn run_fuzz_loop(
    name: &str,
    f: fn(&[u8]) -> Result<(), String>,
    findings: &mut BTreeMap<String, Vec<String>>,
) {
    let mut buffer = vec![0u8; INPUT_BYTES];
    for iter in 0..ITERATIONS {
        fill_random(iter as u64, &mut buffer);
        if let Err(panic_message) = f(&buffer) {
            findings
                .entry(name.to_owned())
                .or_default()
                .push(format!("iter {iter} panicked: {panic_message}"));
        }
    }
}

#[test]
fn fuzz_envelope_smoke() {
    let mut findings: BTreeMap<String, Vec<String>> = BTreeMap::new();
    run_fuzz_loop("event_envelope", fuzz_event_envelope, &mut findings);
    run_fuzz_loop("signal_envelope", fuzz_signal_envelope, &mut findings);
    run_fuzz_loop(
        "realm_state_snapshot",
        fuzz_realm_state_snapshot,
        &mut findings,
    );
    run_fuzz_loop("realm_commit", fuzz_realm_commit, &mut findings);
    run_fuzz_loop(
        "stream_scan_outcome",
        fuzz_stream_scan_outcome,
        &mut findings,
    );

    if !findings.is_empty() {
        // Build a single readable failure report. Each finding is a real
        // SDK bug (an unwrap / panic reachable from validator entry).
        let mut report = String::from("CT-19 fuzz smoke found panics in SDK validator paths:\n");
        for (name, messages) in &findings {
            report.push_str(&format!("  {name}: {} panics\n", messages.len()));
            for message in messages.iter().take(3) {
                report.push_str(&format!("    - {message}\n"));
            }
        }
        panic!("{report}");
    }

    eprintln!(
        "ok: {} validator paths × {} iterations × {} bytes/input, zero panics",
        5, ITERATIONS, INPUT_BYTES
    );
}
