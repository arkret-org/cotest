//! CT-19 — wire-envelope fuzzing.
//!
//! These modules feed random / `arbitrary`-derived bytes through the SDK's
//! envelope deserializers + schema validators and assert no panic / unwrap /
//! arithmetic-overflow escapes the validator boundary. Only typed `Result::Err`
//! is acceptable; a panic is itself a finding and the smoke test under
//! `cotest/tests/fuzz_envelope_smoke.rs` will fail loudly.
//!
//! A full `cargo-fuzz` setup (libFuzzer corpus management, persistent
//! mutator dictionaries, sancov coverage) is preferable for real-world
//! coverage but lives outside this harness — the smoke test is a regression
//! guard, not a search.

pub mod envelope_fuzz;
mod panic_guard;
pub mod realm_state_snapshot_fuzz;
