use std::path::PathBuf;

use arkret_models_collaboration::objects::productivity::scheduled_send_account_data_key;
use arkret_wire::ScheduledSendId;
use serde_json::{Value, json};
fn artifacts_root() -> PathBuf {
    cotest::conformance::spec_artifacts_root()
}
use arkret_crypto::account_data_crypto::{
    AccountDataEncryptedValue, open_account_data_value, seal_account_data_value,
};
use arkret_models_collaboration::events_payloads::{ContentBlock, MessageCreatePayload};
use arkret_wire::{Did, DidCoreId, StrandId, project_did_to_core_id};

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

/// Minimal in-memory optimistic write: the store accepts a write only when the
/// caller's `expected_revision` matches the current one, and otherwise reports
/// the conflict with the current entry, mirroring the server contract the
/// client retry loop consumes.
#[derive(Default)]
struct MemoryRevisionStore {
    revision: u64,
    entry: Option<AccountDataEncryptedValue>,
}

#[derive(Debug)]
struct CasConflict {
    current_revision: u64,
    current_entry: Option<Box<AccountDataEncryptedValue>>,
}

impl MemoryRevisionStore {
    fn compare_and_set(
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
    let actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        scheduled_send_core_id("did:web:alice.example"),
        scheduled_send_core_id("did:web:station.example"),
    ));
    let key = scheduled_send_account_data_key(&ScheduledSendId::new(SCHEDULED_SEND_ID).unwrap());

    // Device A writes the plan first (revision 1).
    let plan_a = scheduled_send_plan(
        "2026-08-19T08:30:00.000Z",
        "from device A",
        "01970e589d21-0000-a13f9c2e",
    );
    let wire_a = inkson::account_data::scheduled_send_account_data_value(&plan_a).unwrap();
    let sealed_a = seal_account_data_value(&secret, &actor, &key, &wire_a).unwrap();
    let mut server = MemoryRevisionStore::default();
    assert_eq!(server.compare_and_set(0, sealed_a).unwrap(), 1);

    // Device B writes with a stale expected revision and hits cas_conflict.
    let plan_b = scheduled_send_plan(
        "2026-08-19T09:30:00.000Z",
        "from device B",
        "01970e589d22-0000-a13f9c2e",
    );
    let wire_b = inkson::account_data::scheduled_send_account_data_value(&plan_b).unwrap();
    let sealed_b = seal_account_data_value(&secret, &actor, &key, &wire_b).unwrap();
    let conflict = server.compare_and_set(0, sealed_b).unwrap_err();
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
            .compare_and_set(conflict.current_revision, resealed)
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
