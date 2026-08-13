use std::collections::BTreeSet;
use std::path::PathBuf;

use arkret_models_collaboration::objects::productivity::{
    DraftKind, draft_account_data_key, saved_account_data_key, scheduled_send_account_data_key,
    search_index_manifest_account_data_key, snooze_account_data_key,
    validate_private_account_data_key,
};
use arkret_schema::event_payload_validator_catalog_from_spec_artifacts;
use arkret_wire::{MessageId, RealmId, ScheduledSendId};
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
        arkret_wire::event_kind_str::RSVP_SET,
        arkret_wire::event_kind_str::PIN_ADD,
        arkret_wire::event_kind_str::PIN_REMOVE,
        arkret_wire::event_kind_str::PIN_REORDER,
        arkret_wire::event_kind_str::REALM_SEARCH_POLICY,
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
        "ak.realm.search_policy",
    ] {
        assert!(
            actions.contains(expected),
            "missing capability action {expected}"
        );
    }
    assert!(!actions.contains("ak.pin.*"));

    let account_registry = load_registry("account-data-key-registry.json");
    let key_patterns: BTreeSet<_> = account_registry["account_data_key_patterns"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|entry| entry["key_pattern"].as_str())
        .collect();
    for expected in [
        "ak.reminders.v1:<id>",
        "ak.scheduled_send.v1:<scheduled_send_id>",
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

    const BASIS: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    // The response lives inside the complete entry together with the schedule
    // basis, so both converge as one lattice value.
    catalog
        .validate_payload(
            arkret_wire::event_kind_str::RSVP_SET,
            &json!({
                "event_ref": "ak:strand:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
                "occurrence": null,
                "entry": {
                    "schedule_basis_refs": [BASIS],
                    "response": {"status": "accepted"}
                }
            }),
        )
        .unwrap();
    assert!(
        catalog
            .validate_payload(
                arkret_wire::event_kind_str::RSVP_SET,
                &json!({
                    "event_ref": "ak:strand:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
                    "occurrence": null,
                    "entry": {
                        "schedule_basis_refs": [BASIS],
                        "response": {"status": "yes"}
                    }
                }),
            )
            .is_err(),
        "old RSVP status aliases must not validate"
    );
    assert!(
        catalog
            .validate_payload(
                arkret_wire::event_kind_str::RSVP_SET,
                &json!({
                    "event_ref": "ak:strand:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
                    "occurrence": null,
                    "status": "accepted"
                }),
            )
            .is_err(),
        "the pre-closure flat payload must not validate"
    );
    assert!(
        catalog
            .validate_payload(
                arkret_wire::event_kind_str::RSVP_SET,
                &json!({
                    "event_ref": "ak:strand:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
                    "occurrence": null,
                    "entry": {"schedule_basis_refs": [BASIS]}
                }),
            )
            .is_err(),
        "an entry with neither response branch must not validate"
    );

    let pin_scope = json!({
        "kind": "strand",
        "id": "ak:strand:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19"
    });
    catalog
        .validate_payload(
            arkret_wire::event_kind_str::PIN_ADD,
            &json!({
                "pin_scope": pin_scope,
                "target_ref": "ak:message:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1",
                "rank": "a0"
            }),
        )
        .unwrap();

    catalog
        .validate_payload(
            arkret_wire::event_kind_str::REALM_SEARCH_POLICY,
            &json!({
                "enabled_profile_refs": ["ak.profile.search.blind_index.v1"],
                "allowed_service_ids": ["ak:did_core:web:search.example"],
                "data_classes": ["encrypted_index", "blind_tokens"],
                "index_retention_ms": 86400000,
                "revocation_behavior": "fail_closed"
            }),
        )
        .unwrap();
    assert!(
        catalog
            .validate_payload(
                arkret_wire::event_kind_str::REALM_SEARCH_POLICY,
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
    let message_id =
        MessageId::new("ak:message:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19").unwrap();
    let scheduled_send_id =
        ScheduledSendId::new("ak:scheduled_send:01904100-0000-7000-8000-000000000003").unwrap();
    let realm_id = RealmId::new("ak:realm:AT1FV5Oc-IicigRsbtaKiJcXWc0f4WBgwlQTJk_XFuyQ").unwrap();
    let target_ref = message_id.as_str();

    let scheduled_send_key = scheduled_send_account_data_key(&scheduled_send_id);
    validate_private_account_data_key(&scheduled_send_key).unwrap();
    assert_eq!(
        scheduled_send_key,
        format!("ak.scheduled_send.v1:{}", scheduled_send_id.as_str()),
        "scheduled-send key must use its producer-allocated plan identity"
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
            "ak.draft.v1:message:ak:message:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19:main"
        )
        .is_err(),
        "raw typed refs in private account-data keys must be rejected"
    );
}
