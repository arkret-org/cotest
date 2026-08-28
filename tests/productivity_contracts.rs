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

// ── Scheduled-send plan lifecycle (spec `models/personal-productivity.md` §4) ──

use arkret_crypto::account_data_crypto::{
    AccountDataEncryptedValue, open_account_data_value, seal_account_data_value,
};
use arkret_event_draft::TypedEventDraft;
use arkret_models_collaboration::events_payloads::{ContentBlock, MessageCreatePayload};
use arkret_wire::{
    Did, DidCoreId, DidUrl, Hash, Hlc, ProducerEventProof, ScopeRef, StrandId, event_spec,
    project_did_to_core_id,
};
use chrono::{TimeZone as _, Utc};
use garth::queued_record::{
    AuthoringAuthorityModel, AuthoringGeneration, QueuedSdkEvent, ScheduledSendSubmissionState,
};

const SCHEDULED_SEND_ID: &str = "ak:scheduled_send:01904100-0000-7000-8000-000000000003";

fn scheduled_send_core_id(did: &str) -> DidCoreId {
    project_did_to_core_id(&Did::new(did.to_owned()).unwrap()).unwrap()
}

fn scheduled_send_test_payload(body: &str) -> MessageCreatePayload {
    MessageCreatePayload::with_content(
        StrandId::new("ak:strand:AcsXlJSItqSzy43Swu0nFz2ijj4Yaf0RgjmoTeivRt8M").unwrap(),
        "discussion",
        ContentBlock::text(body),
    )
}

fn scheduled_send_plan(send_at: &str, body: &str, updated_hlc: &str) -> arkret::ScheduledSendValue {
    inkson::account_data::build_scheduled_send_value(
        SCHEDULED_SEND_ID,
        send_at,
        scheduled_send_test_payload(body),
        updated_hlc,
    )
    .expect("valid scheduled-send plan")
}

fn scheduled_send_schema_registry() -> jsonschema::Registry<'static> {
    let schemas_dir = artifacts_root().join("schemas");
    let mut paths: Vec<PathBuf> = std::fs::read_dir(&schemas_dir)
        .unwrap_or_else(|err| panic!("read {}: {err}", schemas_dir.display()))
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("json"))
        .collect();
    paths.sort();
    let mut builder = jsonschema::Registry::new();
    for path in paths {
        let raw = std::fs::read_to_string(&path)
            .unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
        let value: Value = serde_json::from_str(&raw)
            .unwrap_or_else(|err| panic!("parse {}: {err}", path.display()));
        let id = value["$id"]
            .as_str()
            .unwrap_or_else(|| panic!("{} missing $id", path.display()))
            .to_owned();
        builder = builder
            .add(id.as_str(), jsonschema::Resource::from_contents(value))
            .unwrap_or_else(|err| panic!("registry add {id}: {err}"));
    }
    builder.prepare().expect("schema registry prepares")
}

#[test]
fn scheduled_send_plan_plaintext_matches_spec_schema() {
    let registry = scheduled_send_schema_registry();
    let validator = jsonschema::options()
        .with_registry(&registry)
        .build(&json!({
            "$ref": "https://arkret.org/v1/schemas/personal-productivity.schema.json#/$defs/scheduled_send"
        }))
        .expect("scheduled_send def compiles");

    let plan = scheduled_send_plan(
        "2026-08-19T08:30:00.000Z",
        "scheduled hello",
        "01970e589d21-0000-a13f9c2e",
    );
    let wire = inkson::account_data::scheduled_send_account_data_value(&plan).unwrap();
    if let Err(error) = validator.validate(&wire) {
        panic!("stored plan plaintext must validate against the spec schema: {error}");
    }

    // Spec §4: the stored message_payload MUST omit the future Event / Message
    // identity; the schema closes over additionalProperties to enforce it.
    let mut preminted = wire.clone();
    preminted["message_payload"]
        .as_object_mut()
        .unwrap()
        .insert(
            "event_id".to_owned(),
            json!("ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19"),
        );
    assert!(
        validator.validate(&preminted).is_err(),
        "a plan carrying a pre-minted event_id must not validate"
    );
    let mut missing_hlc = wire.clone();
    missing_hlc.as_object_mut().unwrap().remove("updated_hlc");
    assert!(
        validator.validate(&missing_hlc).is_err(),
        "a plan without updated_hlc must not validate"
    );
}

fn scheduled_send_signed_event(body: &str) -> arkret_wire::AuthoredEvent {
    let mut event = TypedEventDraft::<event_spec::MessageCreate>::new(
        ScopeRef::Realm {
            realm_id: RealmId::new("ak:realm:ARQRpvtCGBgQfVQzTK4_Hgbg0D0HSnc3gPCvXOQUICir")
                .unwrap(),
        },
        scheduled_send_core_id("did:web:alice.example"),
        scheduled_send_core_id("did:web:principal.example"),
        scheduled_send_test_payload(body),
    )
    .unwrap()
    .author_with_digest_suite(
        7,
        Hlc::new("01970e589d21-0001-a13f9c2e").unwrap(),
        Utc.with_ymd_and_hms(2026, 8, 13, 1, 2, 3).single().unwrap(),
        arkret_canonical::DigestSuite::Sha256,
    )
    .unwrap();
    let digest = Hash::new(
        event
            .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
            .unwrap(),
    )
    .unwrap();
    let (signer_resolution_evidence_ref, signer_resolution_evidence_digest) =
        cotest::fixture_signer_evidence_pair("scheduled-send-producer");
    event.attach_proof(
        ProducerEventProof {
            kind: arkret_wire::proof_kind::DETACHED_JWS.to_owned(),
            verification_method: DidUrl::new("did:web:alice.example#device-1").unwrap(),
            event_digest: digest,
            signer_resolution_evidence_ref: Some(signer_resolution_evidence_ref),
            signer_resolution_evidence_digest: Some(signer_resolution_evidence_digest),
            created_at: event.created_at,
            domain: None,
            audience: None,
            proof_purpose: None,
            jws: "header..signature".to_owned(),
        }
        .into(),
    );
    event
}

fn scheduled_send_generation() -> AuthoringGeneration {
    AuthoringGeneration {
        authority_model: AuthoringAuthorityModel::AcceptedDevice,
        authority_principal_id: "did:web:alice.example".to_owned(),
        generation_ref: "1-QmCurrent".to_owned(),
    }
}

#[test]
fn scheduled_send_dispatch_freezes_content_bound_identities_and_bytes() {
    let event = scheduled_send_signed_event("frozen scheduled text");
    let scheduled_send_id = ScheduledSendId::new(SCHEDULED_SEND_ID).unwrap();
    let queued = QueuedSdkEvent::scheduled_authored(
        scheduled_send_id.clone(),
        event.clone(),
        scheduled_send_generation(),
    )
    .unwrap();

    // Spec §4: dispatch derives the content-bound EventId only after the
    // envelope is complete, retypes that same token into the MessageId, and
    // persists both with the full canonical signed bytes before any submit.
    let dispatch = queued.scheduled_dispatch.as_ref().unwrap();
    assert_eq!(dispatch.scheduled_send_id, scheduled_send_id);
    assert_eq!(dispatch.event_id, event.event_id);
    assert_eq!(
        dispatch.message_id,
        MessageId::from_event_id(&event.event_id)
    );
    assert_eq!(
        dispatch.submission_state,
        ScheduledSendSubmissionState::Ready
    );
    let frozen_bytes = arkret_canonical::canonical_json_bytes(&event).unwrap();
    assert_eq!(dispatch.canonical_signed_event_bytes, frozen_bytes);
    assert_eq!(queued.local_operation_id, SCHEDULED_SEND_ID);
    assert_eq!(
        queued
            .authored_attempt
            .as_ref()
            .unwrap()
            .transport_idempotency_key,
        event.event_id.to_string()
    );

    // The durable record survives a serde round trip byte-exact, and an
    // uncertain submission is a one-way latch: a crash retry reopens the same
    // frozen bytes instead of re-authoring.
    let persisted = serde_json::to_value(&queued).unwrap();
    let mut reopened: QueuedSdkEvent = serde_json::from_value(persisted).unwrap();
    reopened.validate().unwrap();
    assert!(reopened.mark_scheduled_submission_uncertain());
    assert!(!reopened.mark_scheduled_submission_uncertain());
    let dispatch = reopened.scheduled_dispatch.as_ref().unwrap();
    assert_eq!(
        dispatch.submission_state,
        ScheduledSendSubmissionState::SubmissionUncertain
    );
    assert_eq!(dispatch.canonical_signed_event_bytes, frozen_bytes);

    // Dispatch refuses an envelope that was never signed.
    let mut unsigned = scheduled_send_signed_event("unsigned");
    unsigned.clear_proofs();
    assert!(
        QueuedSdkEvent::scheduled_authored(
            ScheduledSendId::new(SCHEDULED_SEND_ID).unwrap(),
            unsigned,
            scheduled_send_generation(),
        )
        .is_err(),
        "scheduled dispatch must reject an unsigned Event"
    );
}

/// Minimal in-memory `cas_register`: the store accepts a write only when the
/// caller's `expected_revision` matches the current one, and otherwise reports
/// the conflict with the current entry, mirroring the server contract the
/// client retry loop consumes.
#[derive(Default)]
struct MemoryCasRegister {
    revision: u64,
    entry: Option<AccountDataEncryptedValue>,
}

#[derive(Debug)]
struct CasConflict {
    current_revision: u64,
    current_entry: Option<Box<AccountDataEncryptedValue>>,
}

impl MemoryCasRegister {
    fn cas_register(
        &mut self,
        expected_revision: u64,
        entry: AccountDataEncryptedValue,
    ) -> Result<u64, CasConflict> {
        if expected_revision != self.revision {
            return Err(CasConflict {
                current_revision: self.revision,
                current_entry: self.entry.clone().map(Box::new),
            });
        }
        self.revision += 1;
        self.entry = Some(entry);
        Ok(self.revision)
    }
}

#[test]
fn scheduled_send_cas_conflict_retry_decrypts_merges_and_reseals() {
    let secret = [7u8; 32];
    let actor = scheduled_send_core_id("did:web:alice.example");
    let key = scheduled_send_account_data_key(&ScheduledSendId::new(SCHEDULED_SEND_ID).unwrap());

    // Device A writes the plan first (revision 1).
    let plan_a = scheduled_send_plan(
        "2026-08-19T08:30:00.000Z",
        "from device A",
        "01970e589d21-0000-a13f9c2e",
    );
    let wire_a = inkson::account_data::scheduled_send_account_data_value(&plan_a).unwrap();
    let sealed_a = seal_account_data_value(&secret, &actor, &key, &wire_a).unwrap();
    let mut server = MemoryCasRegister::default();
    assert_eq!(server.cas_register(0, sealed_a).unwrap(), 1);

    // Device B writes with a stale expected revision and hits cas_conflict.
    let plan_b = scheduled_send_plan(
        "2026-08-19T09:30:00.000Z",
        "from device B",
        "01970e589d22-0000-a13f9c2e",
    );
    let wire_b = inkson::account_data::scheduled_send_account_data_value(&plan_b).unwrap();
    let sealed_b = seal_account_data_value(&secret, &actor, &key, &wire_b).unwrap();
    let conflict = server.cas_register(0, sealed_b).unwrap_err();
    assert_eq!(conflict.current_revision, 1);

    // The server only ever stores ciphertext; the AAD visibly binds the
    // actor and account-data key, but the plan content stays sealed.
    let current = conflict.current_entry.unwrap();
    let current_wire = serde_json::to_string(&current).unwrap();
    assert!(!current_wire.contains("from device A"));

    // Spec §4 retry: decrypt the server's current entry, merge on the
    // decrypted plaintext, and retry against the fresh revision.
    let remote_plain = open_account_data_value(&secret, &actor, &key, &current).unwrap();
    let remote =
        inkson::account_data::scheduled_send_value_from_account_data(&remote_plain).unwrap();
    let winner =
        inkson::account_data::merge_scheduled_send_values(plan_b.clone(), Some(&remote)).unwrap();
    assert_eq!(
        winner.send_at, plan_b.send_at,
        "the newer updated_hlc must win the conflict merge"
    );
    let winner_wire = inkson::account_data::scheduled_send_account_data_value(&winner).unwrap();
    let resealed = seal_account_data_value(&secret, &actor, &key, &winner_wire).unwrap();
    assert_eq!(
        server
            .cas_register(conflict.current_revision, resealed)
            .unwrap(),
        2
    );

    let stored = server.entry.unwrap();
    let stored_wire = serde_json::to_string(&stored).unwrap();
    assert!(!stored_wire.contains("from device B"));
    let stored_plain = open_account_data_value(&secret, &actor, &key, &stored).unwrap();
    let stored_plan =
        inkson::account_data::scheduled_send_value_from_account_data(&stored_plain).unwrap();
    assert_eq!(
        serde_json::to_value(&stored_plan).unwrap(),
        serde_json::to_value(&plan_b).unwrap(),
        "the retried write persists the merged winner"
    );

    // Arrival order does not change the election.
    let winner = inkson::account_data::merge_scheduled_send_values(remote, Some(&plan_b)).unwrap();
    assert_eq!(winner.send_at, plan_b.send_at);
}
