//! R2.1 / R2.3 (Phase 2, Round R2 — 2026-05-20) — Realm/Space reversal
//! wire round-trip integration test.
//!
//! Drives the unit-style scenario in
//! [`cotest::scenarios::realm_wire_round_trip`]. The scenario uses the
//! SDK canonical encoder and event classifier directly — no binary or
//! network — so this file boots in <1ms and runs in default `cargo
//! test -p cotest --tests`. Cross-project contract gate: if soland,
//! yougen, sodmin or federation peers drift on the renamed event
//! kinds, the failure surfaces here long before it hits an integration
//! scenario.
//!
//! Coverage map:
//!
//! - R2.1 positive — `cx.realm.create` / `cx.space.create` (container)
//!   / `cx.realm.delivery_binding_policy` / `cx.realm.link` build via
//!   SDK typed `Event`, encode via `canonical_json_bytes`, round-trip
//!   back to the same kind + payload, and classify into the post-
//!   reversal `EventClass::Realm` / `EventClass::Space` families.
//! - R2.1 / R2.3 negative — legacy pre-rename
//!   `cx.space.<security>` and `cx.place.*` kinds classify as
//!   `EventClass::Custom`, matching soland's
//!   `realm_kind_renamed_in_v1` / `place_kind_renamed_to_space`
//!   hard_reject in `routing/events/event_log.rs`.
//!
//! HTTP-level negative coverage (POST a legacy kind, observe the
//! 400 + `realm_kind_renamed_in_v1` reason code) lives alongside the
//! protocol_payloads scenarios — this file is the pure-SDK gate.

use anyhow::Result;

use cotest::scenarios::realm_wire_round_trip::{
    run_legacy_reason_code_constants_present, run_negative_legacy_kinds_rejected,
    run_positive_round_trip,
};

#[test]
fn realm_wire_positive_round_trip() -> Result<()> {
    run_positive_round_trip()
}

#[test]
fn legacy_security_event_kind_rejected() -> Result<()> {
    // R2.3 — `cx.space.<security>` (pre-reversal) and `cx.place.*`
    // (pre-reversal container) MUST NOT classify into a known SDK
    // event family. soland mirrors this on the wire by hard_rejecting
    // submissions of these kinds with
    // `realm_kind_renamed_in_v1` / `place_kind_renamed_to_space`.
    run_negative_legacy_kinds_rejected()
}

#[test]
fn soland_rename_reason_codes_present() -> Result<()> {
    run_legacy_reason_code_constants_present()
}
