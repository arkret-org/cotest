//! Rejection checkpoints for the retired minimal-metadata MLS Realm profile.
//!
//! The v1 spec does not register this profile and does not allow a profile
//! identifier in Realm `schema_refs`. A historical pairwise KeyPackage/Welcome
//! success path would falsely claim support for a removed protocol. This
//! entrypoint therefore exercises the fail-closed boundary before any Event is
//! authored or submitted. Ordinary KeyPackage and Welcome delivery coverage
//! belongs to the current typed MLS scenarios.

use anyhow::{Result, ensure};
use serde_json::json;

use crate::harness::realm_create_payload_for_station;

const LEGACY_MINIMAL_METADATA_PROFILE: &str = "ak.profile.mls.minimal_metadata_realm.v1";
const REALM_SCHEMA: &str = "ak.schema.realm.v1";
const STATION_ID: &str = "ak:did_core:web:station.example";

/// Keep the historical scenario entrypoint as a strict compatibility rejection
/// so the conformance runner cannot silently skip the retired profile.
pub async fn run_minimal_metadata_pairwise_keypackage_live() -> Result<()> {
    let legacy_schema_ref = json!({
        "title": "Retired minimal metadata MLS profile",
        "summary": "must fail closed",
        "schema_refs": [REALM_SCHEMA, LEGACY_MINIMAL_METADATA_PROFILE],
        "encryption_profile": "mls_rfc9420"
    });
    ensure!(
        realm_create_payload_for_station(STATION_ID, &legacy_schema_ref).is_err(),
        "Realm authoring accepted a retired MLS profile in schema_refs"
    );

    // A client must also reject the old one-step MLS bootstrap path even if
    // the invalid schema ref is omitted. Current MLS activation requires a
    // separate accepted ak.mls.genesis Event and its RealmCommit.
    let implicit_mls_bootstrap = json!({
        "title": "Implicit MLS bootstrap",
        "summary": "must fail closed",
        "schema_refs": [REALM_SCHEMA],
        "encryption_profile": "mls_rfc9420"
    });
    ensure!(
        realm_create_payload_for_station(STATION_ID, &implicit_mls_bootstrap).is_err(),
        "Realm authoring accepted MLS activation without an accepted Genesis"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn retired_pairwise_realm_profile_fails_closed() {
        run_minimal_metadata_pairwise_keypackage_live()
            .await
            .expect("retired profile and implicit MLS bootstrap must be rejected");
    }
}
