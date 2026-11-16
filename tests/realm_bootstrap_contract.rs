//! The current harness accepts a plaintext bootstrap and rejects unsupported
//! facets or implicit MLS activation before authoring any Event.

use cotest::harness::realm_create_payload_for_station;
use serde_json::json;

const STATION_ID: &str = "ak:did_core:web:station.example";

#[test]
fn realm_bootstrap_rejects_unsupported_facets_and_implicit_mls() {
    let valid = json!({
        "title": "Current bootstrap",
        "schema_refs": ["ak.schema.realm.v1"],
        "encryption_profile": "none"
    });
    realm_create_payload_for_station(STATION_ID, &valid).unwrap();

    let mut unsupported_facet = valid.clone();
    unsupported_facet["schema_refs"] = json!(["ak.schema.realm.v1", "ak.schema.unregistered.v1"]);
    let error = realm_create_payload_for_station(STATION_ID, &unsupported_facet)
        .err()
        .expect("unsupported facet must fail before authoring");
    assert!(error.to_string().contains("schema-ref facet"));

    let mut implicit_mls = valid;
    implicit_mls["encryption_profile"] = json!("mls_rfc9420");
    let error = realm_create_payload_for_station(STATION_ID, &implicit_mls)
        .err()
        .expect("MLS activation needs a separate accepted Genesis");
    assert!(error.to_string().contains("accepted ak.mls.genesis"));
}
