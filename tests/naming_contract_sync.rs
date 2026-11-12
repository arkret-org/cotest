//! Canonical names, scoped identifiers and producer signatures share one contract.

use std::collections::BTreeSet;
use std::path::PathBuf;

use arkret_canonical::{DigestSuite, canonical_json_bytes};
use arkret_models_collaboration::events_payloads::preview::PreviewPolicyPayloadValueToken;
use arkret_models_collaboration::governance::agent_participation::AgentParticipationResponseBody;
use arkret_models_collaboration::governance::grant_constraint::GrantConstraint;
use arkret_models_collaboration::governance::realm_invite_link::{
    RealmInviteLinkCreatePayload, RealmInviteLinkLimits, RealmInviteLinkView,
};
use arkret_models_collaboration::sync_frames::account_subscribe::AgentDraftPendingIntentKey;
use arkret_models_identity::account::{
    AccountRegistrationInvitationPolicy, AccountRegistrationPolicy,
    AccountRegistrationPolicyEvidence, AccountRegistrationVerificationPolicy,
};
use arkret_models_identity::handle_claim::HandleClaimVariant;
use arkret_models_integration::FieldDefinition;
use arkret_schema_conformance::{
    ProtocolSchemaRegistry, event_payload_validator_catalog_from_spec_artifacts,
    schema_registry_from_spec_artifacts,
};
use arkret_signatures::Ed25519PayloadSigner;
use arkret_signatures::proof::{PublicKeyMaterial, verify_ed25519_detached_jws_proof};
use arkret_test_kit::signed_event::SignedEventFixtureBuilder;
use arkret_wire::{AccountId, ActorId, AgentKeyId, Did, DidCoreId, DidUrl, RealmId, ScopeRef};
use chrono::{TimeZone as _, Utc};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

const TOKEN: &str = "Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-";
const REALM: &str = "ak:realm:ARQRpvtCGBgQfVQzTK4_Hgbg0D0HSnc3gPCvXOQUICir";

fn artifacts() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../arkret-spec/spec/v1/artifacts")
}

fn account() -> AccountId {
    AccountId::new(
        DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
        DidCoreId::new("ak:did_core:web:station.example").unwrap(),
    )
}

fn fragment(registry: &mut ProtocolSchemaRegistry, file: &str, pointer: &str) -> String {
    let document =
        serde_json::from_slice(&std::fs::read(artifacts().join("schemas").join(file)).unwrap())
            .unwrap();
    let key = format!("test.naming.{file}{pointer}");
    registry
        .register_fragment(&key, document, format!("#{pointer}"))
        .unwrap();
    key
}

fn renamed<T: DeserializeOwned + Serialize>(
    registry: &mut ProtocolSchemaRegistry,
    file: &str,
    pointer: &str,
    positive: Value,
    names: &[(&str, &str)],
) {
    let key = fragment(registry, file, pointer);
    registry.validate_value(&key, &positive).unwrap();
    let typed: T = serde_json::from_value(positive.clone()).unwrap();
    let serialized = serde_json::to_value(typed).unwrap();
    for &(old, new) in names {
        assert_eq!(serialized[new], positive[new], "{key} omitted {new}");
        assert!(serialized.get(old).is_none(), "{key} emitted {old}");
        for keep_new in [false, true] {
            let mut changed = positive.clone();
            let value = changed[new].clone();
            if !keep_new {
                changed.as_object_mut().unwrap().remove(new);
            }
            changed[old] = value;
            assert!(
                registry.validate_value(&key, &changed).is_err(),
                "{key}: {changed}"
            );
            assert!(
                serde_json::from_value::<T>(changed.clone()).is_err(),
                "{key}: {changed}"
            );
        }
    }
}

#[test]
fn canonical_fields_round_trip_and_legacy_or_dual_names_are_rejected() {
    let mut registry = schema_registry_from_spec_artifacts(artifacts()).unwrap();
    renamed::<AccountRegistrationVerificationPolicy>(
        &mut registry,
        "account-operations.schema.json",
        "/$defs/account_registration_verification_policy",
        json!({"verification_required":true}),
        &[("required", "verification_required")],
    );
    renamed::<AccountRegistrationInvitationPolicy>(
        &mut registry,
        "account-operations.schema.json",
        "/$defs/account_registration_invitation_policy",
        json!({"invitation_required":true}),
        &[("required", "invitation_required")],
    );
    renamed::<AccountRegistrationPolicy>(
        &mut registry,
        "account-operations.schema.json",
        "/$defs/account_registration_policy",
        json!({"allowed_organization_labels":["deployment-label"]}),
        &[("organization_allowlist", "allowed_organization_labels")],
    );
    renamed::<AccountRegistrationPolicyEvidence>(
        &mut registry,
        "account-operations.schema.json",
        "/$defs/account_registration_policy_evidence",
        json!({"organization_label":"deployment-label"}),
        &[("organization", "organization_label")],
    );
    renamed::<GrantConstraint>(
        &mut registry,
        "grant-constraint.schema.json",
        "",
        json!({"constraint_kind":"claim_based","constraint_subkind":"approval",
            "effect":"require_review","approval_required":true,"approval_mode":"before_commit",
            "approval_principal_ids":["ak:did_core:web:bob.example"],
            "approval_threshold":"unanimous","timeout":"PT60S"}),
        &[("approval_actor_ids", "approval_principal_ids")],
    );
    renamed::<FieldDefinition>(
        &mut registry,
        "applet-edge-operations.schema.json",
        "/$defs/field_definition",
        json!({"field_required":true,"value_kind":"string"}),
        &[("required", "field_required")],
    );
    renamed::<PreviewPolicyPayloadValueToken>(
        &mut registry,
        "event-payload.schema.json",
        "/$defs/preview_policy_payload/properties/value/properties/token",
        json!({"token_required":true,"target_digest_binding_required":true}),
        &[
            ("required", "token_required"),
            ("bind_target_digest", "target_digest_binding_required"),
        ],
    );
    renamed::<RealmInviteLinkCreatePayload>(
        &mut registry,
        "realm-invite-link.schema.json",
        "/$defs/create_payload",
        json!({"public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "expires_at":"2026-11-13T00:00:00.000Z","max_use_count":2}),
        &[("max_uses", "max_use_count")],
    );
    renamed::<RealmInviteLinkLimits>(
        &mut registry,
        "realm-invite-link.schema.json",
        "/$defs/limits",
        json!({"max_lifetime_seconds":60,"max_use_count_per_link":2}),
        &[("max_uses_per_link", "max_use_count_per_link")],
    );
    renamed::<RealmInviteLinkView>(
        &mut registry,
        "realm-invite-link.schema.json",
        "/$defs/view",
        json!({"realm_invite_link_id":format!("ak:realm_invite_link:{TOKEN}"),"realm_id":REALM,
            "inviter_account_id":account(),"expires_at":"2026-11-13T00:00:00.000Z",
            "max_use_count":2,"use_count":0,"status":"active",
            "create_event_id":format!("ak:event:{TOKEN}"),"evaluated_at":"2026-11-12T00:00:00.000Z"}),
        &[("max_uses", "max_use_count"), ("as_of", "evaluated_at")],
    );

    let key = fragment(
        &mut registry,
        "realm-invite-link.schema.json",
        "/$defs/create_payload",
    );
    for count in [0_u64, u64::from(u32::MAX) + 1] {
        let value = json!({"public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "expires_at":"2026-11-13T00:00:00.000Z","max_use_count":count});
        assert!(registry.validate_value(&key, &value).is_err());
        if let Ok(typed) = serde_json::from_value::<RealmInviteLinkCreatePayload>(value) {
            assert!(typed.validate().is_err());
        }
    }
    let token = fragment(
        &mut registry,
        "event-payload.schema.json",
        "/$defs/preview_policy_payload/properties/value/properties/token",
    );
    assert!(
        registry
            .validate_value(&token, &json!({"target_digest_binding_required":false}))
            .is_err()
    );
    for value in [json!(false), Value::Null] {
        assert!(
            serde_json::from_value::<PreviewPolicyPayloadValueToken>(
                json!({"target_digest_binding_required":value})
            )
            .is_err()
        );
    }
}

#[test]
fn agent_key_selector_matches_every_event_evidence_and_projection_carrier() {
    let mut registry = schema_registry_from_spec_artifacts(artifacts()).unwrap();
    let carriers = [
        ("event-payload.schema.json", "/$defs/agent_key_id"),
        (
            "event-payload.schema.json",
            "/$defs/agent_key_authorize_payload/properties/key_id",
        ),
        (
            "event-payload.schema.json",
            "/$defs/agent_key_authorize_payload/properties/supersedes/items/properties/key_id",
        ),
        (
            "event-payload.schema.json",
            "/$defs/agent_key_revoke_payload/properties/key_id",
        ),
        (
            "agent-operations.schema.json",
            "/$defs/agent_key_authorization_state/properties/key_id",
        ),
        (
            "agent-authority-evidence.schema.json",
            "/$defs/agent_key_authorization/properties/agent_key_id",
        ),
        (
            "current-state.schema.json",
            "/$defs/current_agent_key/properties/selector/properties/agent_key_id",
        ),
    ];
    let prefix = "did:web:example.org#";
    let samples = [
        ("runtime-key:one".to_owned(), true),
        ("a".repeat(256), true),
        (
            format!("{prefix}{}", "🦀".repeat(256 - prefix.chars().count())),
            true,
        ),
        (String::new(), false),
        ("a".repeat(257), false),
        ("ak:key:example".to_owned(), false),
        (
            format!("{prefix}{}", "🦀".repeat(257 - prefix.chars().count())),
            false,
        ),
        ("local\n".to_owned(), false),
        (format!("{prefix}key\n"), false),
    ];
    for (file, pointer) in carriers {
        let key = fragment(&mut registry, file, pointer);
        for (literal, expected) in &samples {
            assert_eq!(
                registry.validate_value(&key, &json!(literal)).is_ok(),
                *expected,
                "{file}{pointer}: {literal:?}"
            );
            assert_eq!(AgentKeyId::new(literal.clone()).is_ok(), *expected);
            let parsed = serde_json::from_value::<AgentKeyId>(json!(literal));
            assert_eq!(parsed.is_ok(), *expected);
            if let Ok(value) = parsed {
                assert_eq!(value.as_str(), literal);
                assert_eq!(serde_json::to_value(value).unwrap(), json!(literal));
            }
        }
    }
}

#[test]
fn actual_draft_wire_adapter_keeps_the_exact_scoped_handle() {
    let mut registry = schema_registry_from_spec_artifacts(artifacts()).unwrap();
    let key = fragment(
        &mut registry,
        "account-subscribe-frame.schema.json",
        "/$defs/agent_draft_pending_intent_key",
    );
    for literal in [" ".to_owned(), "e\u{301}".repeat(128), "🦀".repeat(256)] {
        let value = json!({"controller_account_id":account(),
            "agent_id":"ak:did_core:web:agent.example","draft_id":literal});
        registry.validate_value(&key, &value).unwrap();
        let typed: AgentDraftPendingIntentKey = serde_json::from_value(value).unwrap();
        assert_eq!(typed.draft_id, literal);
        assert_eq!(serde_json::to_value(typed).unwrap()["draft_id"], literal);
    }
    for literal in [
        json!(""),
        json!("ak:did_core:web:agent.example"),
        json!("🦀".repeat(257)),
        Value::Null,
    ] {
        let value = json!({"controller_account_id":account(),
            "agent_id":"ak:did_core:web:agent.example","draft_id":literal});
        assert!(registry.validate_value(&key, &value).is_err());
        assert!(serde_json::from_value::<AgentDraftPendingIntentKey>(value).is_err());
    }
}

#[test]
fn existing_principal_types_reject_wrong_kind_and_bare_did_carriers() {
    let mut registry = schema_registry_from_spec_artifacts(artifacts()).unwrap();
    let claim = fragment(
        &mut registry,
        "handle-claim.schema.json",
        "/$defs/claim_variant",
    );
    let participation = fragment(
        &mut registry,
        "agent-operations.schema.json",
        "/$defs/agent_participation_response_body",
    );
    for value in [
        "ak:did_core:web:organization.example",
        "did:web:organization.example",
        "not-a-principal",
    ] {
        let expected = value.starts_with("ak:did_core:");
        let claim_value = json!({"kind":"organization_handle","organization_id":value});
        assert_eq!(
            registry.validate_value(&claim, &claim_value).is_ok(),
            expected
        );
        assert_eq!(
            serde_json::from_value::<HandleClaimVariant>(claim_value).is_ok(),
            expected
        );
        let response = json!({"agent_id":value,"participation_entries":[]});
        assert_eq!(
            registry.validate_value(&participation, &response).is_ok(),
            expected
        );
        assert_eq!(
            serde_json::from_value::<AgentParticipationResponseBody>(response).is_ok(),
            expected
        );
    }
}

fn scoped_nodes(node: &Value, pointer: &str, out: &mut Vec<(String, String, usize)>) {
    if let Some(object) = node.as_object() {
        if let Some(reference) = object.get("$ref").and_then(Value::as_str)
            && let Some(profile) = reference
                .strip_prefix("./")
                .unwrap_or(reference)
                .strip_prefix("string-profiles.schema.json#/$defs/")
            && [
                "realm_action_name",
                "membership_admission_handle",
                "agent_confirmation_handle",
                "agent_draft_handle",
                "media_focus_handle",
                "applet_install_handle",
                "agent_rejection_handle",
                "organization_statement_handle",
            ]
            .contains(&profile)
        {
            out.push((
                pointer.to_owned(),
                profile.to_owned(),
                object
                    .get("maxLength")
                    .and_then(Value::as_u64)
                    .unwrap_or(256) as usize,
            ));
        }
        for (name, child) in object {
            scoped_nodes(
                child,
                &format!("{pointer}/{}", name.replace('~', "~0").replace('/', "~1")),
                out,
            );
        }
    } else if let Some(array) = node.as_array() {
        for (index, child) in array.iter().enumerate() {
            scoped_nodes(child, &format!("{pointer}/{index}"), out);
        }
    }
}

#[test]
fn every_scoped_identifier_carrier_preserves_literals_and_code_point_bounds() {
    let mut registry = schema_registry_from_spec_artifacts(artifacts()).unwrap();
    let mut seen = BTreeSet::new();
    let mut carrier_count = 0;
    let mut uuid_carrier_count = 0;
    for entry in std::fs::read_dir(artifacts().join("schemas")).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_none_or(|extension| extension != "json") {
            continue;
        }
        let document: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        let mut nodes = Vec::new();
        scoped_nodes(&document, "", &mut nodes);
        for (pointer, profile, maximum) in nodes {
            seen.insert(profile);
            carrier_count += 1;
            let file = path.file_name().unwrap().to_str().unwrap();
            let key = fragment(&mut registry, file, &pointer);
            if document.pointer(&pointer).unwrap()["format"] == "uuid" {
                uuid_carrier_count += 1;
                let literal = "01904100-0000-7000-8000-000000000001";
                registry.validate_value(&key, &json!(literal)).unwrap();
                arkret_wire::validate_bounded_non_typed_identifier(literal, maximum).unwrap();
                for literal in [
                    String::new(),
                    "ak:did_core:web:example.org".to_owned(),
                    " ".to_owned(),
                    "e\u{301}".repeat(maximum / 2),
                    "🦀".repeat(maximum),
                    "🦀".repeat(maximum + 1),
                ] {
                    assert!(
                        registry.validate_value(&key, &json!(literal)).is_err(),
                        "{file}{pointer}: UUID owner constraint must remain in force"
                    );
                }
                continue;
            }
            for literal in [
                " ".to_owned(),
                "e\u{301}".repeat(maximum / 2),
                "🦀".repeat(maximum),
            ] {
                registry.validate_value(&key, &json!(literal)).unwrap();
                arkret_wire::validate_bounded_non_typed_identifier(&literal, maximum).unwrap();
            }
            for literal in [
                String::new(),
                "ak:did_core:web:example.org".to_owned(),
                "🦀".repeat(maximum + 1),
            ] {
                assert!(
                    registry.validate_value(&key, &json!(literal)).is_err(),
                    "{file}{pointer}"
                );
                assert!(
                    arkret_wire::validate_bounded_non_typed_identifier(&literal, maximum).is_err()
                );
            }
        }
    }
    assert_eq!(
        seen.len(),
        8,
        "scoped-profile test unexpectedly lost its declaration surface"
    );
    assert_eq!(carrier_count, 30, "scoped carrier inventory drifted");
    assert_eq!(uuid_carrier_count, 3, "UUID owner inventory drifted");
}

#[test]
fn renamed_signed_payloads_reject_obsolete_names_and_retained_producer_proofs() {
    let catalog = event_payload_validator_catalog_from_spec_artifacts(artifacts()).unwrap();
    let signer = Ed25519PayloadSigner::from_did_key_seed(
        [73; 32],
        Did::new("did:web:alice.example").unwrap(),
        DidUrl::new("did:web:alice.example#key-1").unwrap(),
    );
    let actor = ActorId::account(account());
    let public_key = PublicKeyMaterial::Ed25519Raw {
        bytes: signer.verifying_key().to_bytes().to_vec(),
    };
    let preview = json!({"value":{"mode":"directory_card","audiences":["anonymous"],
        "fields":["title"],"token":{"token_required":true,"target_digest_binding_required":true}}});
    for (kind, payload, pointer, old, new) in [
        (
            "ak.realm_invite_link.create",
            json!({"public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "expires_at":"2026-11-13T00:00:00.000Z","max_use_count":2}),
            "",
            "max_uses",
            "max_use_count",
        ),
        (
            "ak.realm.preview_policy",
            preview.clone(),
            "/value/token",
            "required",
            "token_required",
        ),
        (
            "ak.realm.preview_policy",
            preview,
            "/value/token",
            "bind_target_digest",
            "target_digest_binding_required",
        ),
    ] {
        catalog.validate_payload(kind, &payload).unwrap();
        let event = SignedEventFixtureBuilder::new(
            kind,
            ScopeRef::Realm {
                realm_id: RealmId::new(REALM).unwrap(),
            },
            actor.clone(),
            payload,
        )
        .with_created_at(Utc.with_ymd_and_hms(2026, 11, 12, 0, 0, 0).unwrap())
        .sign_verifiable(&signer)
        .unwrap()
        .expect_verifiable();
        let original = canonical_json_bytes(&event.digest_payload().unwrap()).unwrap();
        let proof = event.producer_proof.as_ref().unwrap();
        verify_ed25519_detached_jws_proof(proof, &original, &actor, &public_key).unwrap();
        for keep_new in [false, true] {
            let mut changed = event.clone();
            let mut payload = serde_json::to_value(&changed.payload).unwrap();
            let owner = payload
                .pointer_mut(pointer)
                .unwrap()
                .as_object_mut()
                .unwrap();
            owner.insert(old.to_owned(), owner[new].clone());
            if !keep_new {
                owner.remove(new);
            }
            assert!(
                catalog.validate_payload(kind, &payload).is_err(),
                "{kind}: {payload}"
            );
            changed.payload = serde_json::from_value(payload).unwrap();
            assert!(
                changed
                    .verify_event_id_matches_content_with_digest_suite(DigestSuite::Sha256)
                    .is_err()
            );
            let bytes = canonical_json_bytes(&changed.digest_payload().unwrap()).unwrap();
            assert!(verify_ed25519_detached_jws_proof(proof, &bytes, &actor, &public_key).is_err());
        }
    }
}
