//! Signed single-kind targets use the canonical object kind, without aliases.

use std::path::PathBuf;

use arkret_canonical::{DigestSuite, canonical_json_bytes};
use arkret_schema_conformance::{
    event_payload_validator_catalog_from_spec_artifacts, schema_registry_from_spec_artifacts,
};
use arkret_signatures::Ed25519PayloadSigner;
use arkret_signatures::proof::{PublicKeyMaterial, verify_ed25519_detached_jws_proof};
use arkret_test_kit::signed_event::SignedEventFixtureBuilder;
use arkret_wire::{AccountId, ActorId, Did, DidCoreId, DidUrl, RealmId, SchemaId, ScopeRef};
use chrono::{TimeZone as _, Utc};
use serde_json::{Value, json};

const REALM: &str = "ak:realm:ARQRpvtCGBgQfVQzTK4_Hgbg0D0HSnc3gPCvXOQUICir";
const TOKEN: &str = "Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-";

fn payloads() -> Vec<(&'static str, &'static str, Value)> {
    vec![
        (
            "ak.strand.update",
            "strand_id",
            json!({"strand_id":format!("ak:strand:{TOKEN}"),"patch":{"metadata.title":{"$op":"set","value":"Named target"}}}),
        ),
        (
            "ak.strand.tracks.update",
            "strand_id",
            json!({"strand_id":format!("ak:strand:{TOKEN}"),"patch":{"tracks.discussion.enabled":{"$op":"set","value":true}}}),
        ),
        (
            "ak.morph.update",
            "morph_id",
            json!({"morph_id":format!("ak:morph:{TOKEN}"),"patch":{"metadata.title":{"$op":"set","value":"Named target"}}}),
        ),
        (
            "ak.profile.update",
            "actor_profile_id",
            json!({"actor_profile_id":format!("ak:actor_profile:{TOKEN}"),"patch":{"display_name":{"$op":"set","value":"Named target"}}}),
        ),
        (
            "ak.profile.realm_override",
            "actor_profile_id",
            json!({"actor_profile_id":format!("ak:actor_profile:{TOKEN}"),"target_realm_id":REALM,"patch":{"display_name":{"$op":"set","value":"Named target"}}}),
        ),
    ]
}

#[test]
fn signed_single_kind_targets_match_schema_and_reject_retained_proof_mutations() {
    let artifacts =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../arkret-spec/spec/v1/artifacts");
    let catalog = event_payload_validator_catalog_from_spec_artifacts(&artifacts).unwrap();
    let schemas = schema_registry_from_spec_artifacts(&artifacts).unwrap();
    let signer = Ed25519PayloadSigner::from_did_key_seed(
        [73; 32],
        Did::new("did:web:alice.example").unwrap(),
        DidUrl::new("did:web:alice.example#key-1").unwrap(),
    );
    let actor = ActorId::account(AccountId::new(
        DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
        DidCoreId::new("ak:did_core:web:station.example").unwrap(),
    ));
    let public_key = PublicKeyMaterial::Ed25519Raw {
        bytes: signer.verifying_key().to_bytes().to_vec(),
    };

    for (kind, field, payload) in payloads() {
        catalog.validate_payload(kind, &payload).unwrap();
        let event = SignedEventFixtureBuilder::new(
            kind,
            ScopeRef::Realm {
                realm_id: RealmId::new(REALM).unwrap(),
            },
            actor.clone(),
            payload.clone(),
        )
        .with_created_at(Utc.with_ymd_and_hms(2026, 11, 11, 1, 0, 0).unwrap())
        .sign_verifiable(&signer)
        .unwrap()
        .expect_verifiable();
        schemas
            .validate_value(SchemaId::EVENT_V1, &serde_json::to_value(&event).unwrap())
            .unwrap();
        event
            .verify_event_id_matches_content_with_digest_suite(DigestSuite::Sha256)
            .unwrap();
        let signed_bytes = canonical_json_bytes(&event.digest_payload().unwrap()).unwrap();
        let proof = event.producer_proof.as_ref().unwrap();
        verify_ed25519_detached_jws_proof(proof, &signed_bytes, &actor, &public_key).unwrap();

        for mutation in ["old_name", "both_names", "wrong_kind"] {
            let mut changed = event.clone();
            match mutation {
                "old_name" => {
                    let target = changed.payload.remove(field).unwrap();
                    changed.payload.insert("target_ref".to_owned(), target);
                }
                "both_names" => {
                    changed
                        .payload
                        .insert("target_ref".to_owned(), payload[field].clone());
                }
                _ => {
                    let wrong_kind = if field == "morph_id" {
                        "strand"
                    } else {
                        "morph"
                    };
                    changed
                        .payload
                        .insert(field.to_owned(), json!(format!("ak:{wrong_kind}:{TOKEN}")));
                }
            }
            let changed_payload = serde_json::to_value(&changed.payload).unwrap();
            assert!(
                catalog.validate_payload(kind, &changed_payload).is_err(),
                "{kind} {mutation}"
            );
            assert!(
                schemas
                    .validate_value(SchemaId::EVENT_V1, &serde_json::to_value(&changed).unwrap())
                    .is_err(),
                "{kind} {mutation}"
            );
            assert!(
                changed
                    .verify_event_id_matches_content_with_digest_suite(DigestSuite::Sha256)
                    .is_err(),
                "{kind} {mutation}"
            );
            let changed_bytes = canonical_json_bytes(&changed.digest_payload().unwrap()).unwrap();
            assert_ne!(signed_bytes, changed_bytes, "{kind} {mutation}");
            assert!(
                verify_ed25519_detached_jws_proof(proof, &changed_bytes, &actor, &public_key)
                    .is_err(),
                "{kind} {mutation} retained an obsolete producer proof"
            );
        }
    }
}
