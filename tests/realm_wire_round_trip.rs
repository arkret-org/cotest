//! Realm/Space boundary split wire round-trip integration test.
//!
//! Drives the unit-style scenario in
//! [`cotest::scenarios::realm_wire_round_trip`]. The scenario uses the
//! SDK canonical encoder and event classifier directly — no binary or
//! network — so this file boots in <1ms and runs in default `cargo
//! test -p cotest --tests`. Cross-project contract gate: if soland,
//! inkson, sodmin or federation peers drift on Realm/Space event kinds,
//! the failure surfaces here long before it hits an integration scenario.
//!
//! Coverage map:
//!
//! - R2.1 positive — `ak.realm.create` / `ak.space.create` (container) / `ak.realm.link` builds via
//!   SDK typed `Event`, encodes via `canonical_json_bytes`, round-trip back to the same kind +
//!   payload, and classify into the `EventProductClass::Realm` / `EventProductClass::Space`
//!   families.

use anyhow::Result;
use cotest::scenarios::realm_wire_round_trip::run_positive_round_trip;

#[test]
fn realm_wire_positive_round_trip() -> Result<()> {
    run_positive_round_trip()
}
