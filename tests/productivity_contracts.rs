use std::collections::BTreeSet;
use std::path::PathBuf;

use arkret_models_collaboration::objects::productivity::{
    DraftKind, draft_account_data_key, saved_account_data_key, scheduled_send_account_data_key,
    search_index_manifest_account_data_key, snooze_account_data_key,
    validate_private_account_data_key,
};
use arkret_schema::event_payload_validator_catalog_from_spec_artifacts;
use arkret_wire::{MessageId, RealmId};
use serde_json::{Value, json};

fn artifacts_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("cotest is under workspace root")
        .join("arkret-spec/spec/v1/artifacts")
}

fn load_registry(file: &str) -> Value {
    let path = artifacts_root().join("registry").join(file);
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    serde_json::from_str(&raw).unwrap_or_else(|err| panic!("parse {}: {err}", path.display()))
}

#[test]
fn productivity_registry_entries_are_present_and_exact() {
    let event_registry = load_registry("event-kind-registry.json");
    let event_kinds: BTreeSet<_> = event_registry["event_kinds"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|entry| entry["event_kind"].as_str())
        .collect();
    for expected in [
        arkret_wire::events::EventKind::RSVP_SET,
        arkret_wire::events::EventKind::PIN_ADD,
        arkret_wire::events::EventKind::PIN_REMOVE,
        arkret_wire::events::EventKind::PIN_REORDER,
        arkret_wire::events::EventKind::REALM_DISAPPEARING_POLICY,
        arkret_wire::events::EventKind::REALM_SEARCH_POLICY,
    ] {
        assert!(
            event_kinds.contains(expected),
            "missing event kind {expected}"
        );
    }

    let capability_registry = load_registry("capability-action-registry.json");
    let actions: BTreeSet<_> = capability_registry["actions"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|entry| entry["action"].as_str())
        .collect();
    for expected in [
        "ak.rsvp.set",
        "ak.pin.add",
        "ak.pin.remove",
        "ak.pin.reorder",
        "ak.realm.disappearing_policy",
        "ak.realm.search_policy",
    ] {
        assert!(
            actions.contains(expected),
            "missing capability action {expected}"
        );
    }
    assert!(!actions.contains("ak.pin.*"));

    let account_registry = load_registry("account-data-type-registry.json");
    let key_patterns: BTreeSet<_> = account_registry["account_data_types"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|entry| entry["key_pattern"].as_str())
        .collect();
    for expected in [
        "ak.reminders.v1:<id>",
        "ak.scheduled_send.v1:<planned_message_id>",
        "ak.snooze.v1:<target_key>",
        "ak.saved.v1:<collection_key>:<target_key>",
        "ak.draft.v1:<kind>:<target_key>:<slot_key>",
        "ak.search.index_manifest.v1:<realm_key>",
    ] {
        assert!(
            key_patterns.contains(expected),
            "missing account-data key pattern {expected}"
        );
    }
}

#[test]
fn productivity_payload_validator_accepts_current_fields_and_rejects_drafts() {
    let catalog = event_payload_validator_catalog_from_spec_artifacts(artifacts_root()).unwrap();

    catalog
        .validate_payload(
            arkret_wire::events::EventKind::RSVP_SET,
            &json!({
                "event_ref": "ak:strand:01904100-0000-7000-8000-000000000001",
                "status": "accepted",
                "occurrence": null
            }),
        )
        .unwrap();
    assert!(
        catalog
            .validate_payload(
                arkret_wire::events::EventKind::RSVP_SET,
                &json!({
                    "event_ref": "ak:strand:01904100-0000-7000-8000-000000000001",
                    "status": "yes",
                    "occurrence": null
                }),
            )
            .is_err(),
        "old RSVP status aliases must not validate"
    );

    let pin_scope = json!({
        "kind": "strand",
        "id": "ak:strand:01904100-0000-7000-8000-000000000001"
    });
    catalog
        .validate_payload(
            arkret_wire::events::EventKind::PIN_ADD,
            &json!({
                "pin_scope": pin_scope,
                "target_ref": "ak:message:01904100-0000-7000-8000-000000000002",
                "rank": "a0"
            }),
        )
        .unwrap();

    catalog
        .validate_payload(
            arkret_wire::events::EventKind::REALM_DISAPPEARING_POLICY,
            &json!({
                "enabled": true,
                "max_ttl_ms": 3600000,
                "allowed_triggers": ["on_send", "on_first_read"],
                "default_grace_ms": 0,
                "allow_plaintext_realms": false
            }),
        )
        .unwrap();
    // `grace_ms` is a message-expiry field, not a realm disappearing-policy
    // field. The payload is selected through a closed `oneOf`, so the unknown
    // field prevents either branch from matching and must fail validation.
    assert!(
        catalog
            .validate_payload(
                arkret_wire::events::EventKind::REALM_DISAPPEARING_POLICY,
                &json!({
                    "enabled": true,
                    "max_ttl_ms": 3600000,
                    "allowed_triggers": ["on_send"],
                    "grace_ms": 0
                }),
            )
            .is_err(),
        "grace_ms (a message-expiry field) must not validate as realm policy"
    );

    catalog
        .validate_payload(
            arkret_wire::events::EventKind::REALM_SEARCH_POLICY,
            &json!({
                "enabled_profile_refs": ["ak.profile.search.blind_index.v1"],
                "allowed_service_ids": ["did:web:search.example"],
                "data_classes": ["encrypted_index", "blind_tokens"],
                "index_retention_ms": 86400000,
                "revocation_behavior": "fail_closed"
            }),
        )
        .unwrap();
    assert!(
        catalog
            .validate_payload(
                arkret_wire::events::EventKind::REALM_SEARCH_POLICY,
                &json!({
                    "profile_refs": ["ak.profile.search.blind_index.v1"],
                    "service_ids": ["did:web:search.example"],
                    "data_classes": ["encrypted_index"],
                    "shard_id": "old-field"
                }),
            )
            .is_err(),
        "old search policy field names must not validate"
    );
}

#[test]
fn private_account_data_keys_do_not_leak_raw_refs() {
    let ns = b"cotest productivity namespace";
    let message_id = MessageId::new("ak:message:01904100-0000-7000-8000-000000000001").unwrap();
    let realm_id = RealmId::new("ak:realm:01904100-0000-7000-8000-000000000002").unwrap();
    let target_ref = message_id.as_str();

    let scheduled_send_key = scheduled_send_account_data_key(&message_id);
    validate_private_account_data_key(&scheduled_send_key).unwrap();
    assert_eq!(
        scheduled_send_key,
        format!("ak.scheduled_send.v1:{}", message_id.as_str()),
        "scheduled-send key must use the spec-defined planned_message_id idempotency anchor"
    );

    let keys = [
        snooze_account_data_key(ns, target_ref).unwrap(),
        saved_account_data_key(ns, "Inbox", target_ref).unwrap(),
        draft_account_data_key(ns, DraftKind::Message, target_ref, "main").unwrap(),
        search_index_manifest_account_data_key(ns, &realm_id).unwrap(),
    ];
    for key in keys {
        validate_private_account_data_key(&key).unwrap();
        assert!(
            !key.contains(target_ref),
            "account-data key leaked raw target ref: {key}"
        );
        assert!(!key.contains("Inbox"), "saved key leaked collection title");
    }

    assert!(
        validate_private_account_data_key(
            "ak.draft.v1:message:ak:message:01904100-0000-7000-8000-000000000001:main"
        )
        .is_err(),
        "raw typed refs in private account-data keys must be rejected"
    );
}
