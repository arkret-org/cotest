//! Realm/Space boundary split wire round-trip integration test.
//!
//! Drives the unit-style scenario in
//! [`cotest::scenarios::realm_wire_round_trip`]. The scenario uses the
//! SDK canonical encoder and event classifier directly — no binary or
//! network — so this file boots in <1ms and runs in default `cargo
//! test -p cotest --tests`. Cross-project contract gate: if soland,
//! yougen, sodmin or federation peers drift on Realm/Space event kinds,
//! the failure surfaces here long before it hits an integration scenario.
//!
//! Coverage map:
//!
//! - R2.1 positive — `ck.realm.create` / `ck.space.create` (container) /
//!   `ck.realm.delivery_binding_policy` / `ck.realm.link` build via SDK typed `Event`, encode via
//!   `canonical_json_bytes`, round-trip back to the same kind + payload, and classify into the
//!   `EventClass::Realm` / `EventClass::Space` families.

use anyhow::Result;
use cotest::scenarios::realm_wire_round_trip::run_positive_round_trip;

#[test]
fn realm_wire_positive_round_trip() -> Result<()> {
    run_positive_round_trip()
}
