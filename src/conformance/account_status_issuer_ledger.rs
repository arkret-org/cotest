//! `ak.vector.account_status.issuer_ledger.v1` — Account Authority issuer ledger
//! (`fixtures/account-status-issuer-ledger-fixture.json`).
//!
//! Account lifecycle is **not** a Realm finality domain. An `AccountStatusRecord`
//! is not an Event: it never enters a commit stream, is never covered by a
//! `RealmCommit`, and never waits for a Station checkpoint. Its ordering comes
//! from its own compare-and-swap chain — `status_seq` plus
//! `previous_account_status_record_id` — keyed by `(account_authority_id,
//! account_id)`.
//!
//! Everything here is executed against shipped code rather than restated:
//!
//! * the fixture's `unsigned_core_canonical_bytes_utf8`, `unsigned_core_digest`
//!   and `account_status_record_id` are re-derived from the record itself with
//!   [`UnsignedAccountStatusRecord`], so a fixture whose declared identity stops
//!   matching its own bytes fails here;
//! * the declared proof metadata is re-bound with the SDK's proof-binding bytes,
//!   so a proof that names another digest, time or context is rejected;
//! * every `replica_classification_cases` row is run through soland's shipped
//!   [`classify_account_status_replica_append`] — the receiver implementation
//!   itself — and cross-checked against the normative decision table in
//!   `registry/account-status-replica-decision-table.json`;
//! * the record's member set is closed against every removed carrier, so a
//!   commit, stream, Seal or Cell reference cannot creep back into the ledger.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, anyhow, bail, ensure};
use arkret_models_collaboration::account_status::{
    AccountStatusReceipt, AccountStatusRecord, UnsignedAccountStatusReceipt,
    UnsignedAccountStatusRecord,
};
use arkret_models_collaboration::objects::account_status::AccountStatus;
use arkret_wire::{
    AccountId, AccountStatusRecordId, DidCoreId, DidUrl, ErrorCode, Hash, PayloadProof, ReceiptId,
    SchemaId,
};
use chrono::{DateTime, Utc};
use serde_json::{Map, Value};
use soland_storage::{
    AccountStatusReplicaAppend, AccountStatusReplicaConflictKind,
    classify_account_status_replica_append,
};

use super::{
    canonical_json, fixture_runner_entrypoint, load_artifact_json, load_fixture_value,
    required_bool, required_field, required_str, required_u64, sha256_prefixed, value_array,
};

pub const VECTOR_ID_ACCOUNT_STATUS_ISSUER_LEDGER: &str =
    "ak.vector.account_status.issuer_ledger.v1";

const FIXTURE: &str = "account-status-issuer-ledger-fixture.json";
const SUITE: &str = "account_status_issuer_ledger";
const RUNNER_ENTRYPOINT: &str = "ak.suite.account_status.issuer_ledger.v1";
const REPLICA_DECISION_TABLE_REF: &str = "registry/account-status-replica-decision-table.json";

const PROOF_CONTEXT: &str = "ak.account_status_record_proof.v1";

/// The compare-and-swap key of the issuer ledger.
const CAS_KEY: [&str; 2] = ["account_authority_id", "account_id"];

/// Writes the successor transaction performs atomically.
const ATOMIC_WRITES: [&str; 4] = [
    "account_row",
    "immutable_record",
    "transition_audit",
    "propagation_outbox",
];

/// The idempotency scope of a replica submission.
const IDEMPOTENCY_SCOPE: [&str; 3] = [
    "Source-Service-ID",
    "Destination-Service-ID",
    "Idempotency-Key",
];

/// The only two terminal acks a bounded outbox may mark a destination on.
const TERMINAL_ACKS: [&str; 2] = ["accepted", "duplicate"];

/// Members no `AccountStatusRecord` may ever carry: the ledger is not a Realm
/// timeline, so no commit, stream, position or retired coverage carrier belongs
/// in it.
const FORBIDDEN_RECORD_MEMBERS: &[&str] = &[
    "commit_id",
    "commit_ref",
    "previous_commit_ref",
    "stream_ref",
    "stream_position",
    "event_id",
    "event_ref",
    "committed_event_ref",
    "realm_commit",
    "seal_ref",
    "seal_id",
    "seal_basis",
    "cell_id",
    "cell_ref",
    "frontier",
    "control_proposal",
    "state_root",
    "policy_root",
];

/// Run the issuer-ledger vector.
pub fn run_account_status_issuer_ledger_vector() -> Result<()> {
    let fixture = load_fixture_value(FIXTURE)?;
    verify_fixture_identity(&fixture)?;

    let ledger = required_field(&fixture, "ledger")?;
    verify_ledger_identity(ledger)?;

    let chain = parse_records(ledger, "records")?;
    let conflicting = parse_named_records(ledger, "conflicting_records")?;
    verify_record_identity_and_proof_binding(ledger, &chain, &conflicting)?;
    verify_record_carries_no_commit_or_stream_carrier(&chain, &conflicting)?;
    verify_chain_is_a_cas_successor_chain(&chain)?;
    verify_genesis_rules(&fixture, &chain)?;
    verify_successor_cas_contract(ledger, &fixture)?;

    let index = record_index(&chain, &conflicting);
    verify_replica_classification(&fixture, &index)?;
    verify_idempotency_contract(&fixture)?;
    verify_fanout_outbox(&fixture)?;
    Ok(())
}

// ── Fixture identity ────────────────────────────────────────────────────────

fn verify_fixture_identity(fixture: &Value) -> Result<()> {
    ensure!(
        required_str(fixture, "suite")? == SUITE,
        "issuer-ledger fixture suite drifted"
    );
    ensure!(
        fixture_runner_entrypoint(fixture)? == RUNNER_ENTRYPOINT,
        "issuer-ledger fixture runner entrypoint drifted"
    );
    let covers = value_array(required_field(fixture, "covers_vectors")?, "covers_vectors")?;
    ensure!(
        covers
            .iter()
            .any(|vector| vector.as_str() == Some(VECTOR_ID_ACCOUNT_STATUS_ISSUER_LEDGER)),
        "issuer-ledger fixture is no longer bound to {VECTOR_ID_ACCOUNT_STATUS_ISSUER_LEDGER}"
    );
    for section in [
        "ledger",
        "genesis_rules",
        "successor_cas",
        "idempotency",
        "replica_classification_cases",
        "fanout_outbox",
    ] {
        ensure!(
            fixture.get(section).is_some(),
            "issuer-ledger fixture lost the {section} section"
        );
    }
    Ok(())
}

fn verify_ledger_identity(ledger: &Value) -> Result<()> {
    let authority = DidCoreId::new(required_str(ledger, "account_authority_id")?.to_owned())?;
    let account: AccountId = serde_json::from_value(required_field(ledger, "account_id")?.clone())?;
    account.validate()?;
    ensure!(
        account.station_id() != &authority || account.principal_id() != &authority,
        "the fixture account must not collapse principal, Station and Authority into one id"
    );
    ensure!(
        required_str(ledger, "proof_context")? == PROOF_CONTEXT,
        "issuer-ledger proof context drifted"
    );
    // The declared identity rule is the one the SDK implements: a suite-tagged
    // digest over the JCS bytes of the record without its id and proof.
    let rule = required_str(ledger, "identity_rule")?;
    for fragment in [
        "account_status_record_id",
        "SHA-256",
        "JCS",
        "without account_status_record_id and proof",
    ] {
        ensure!(
            rule.contains(fragment),
            "issuer-ledger identity rule no longer states {fragment}"
        );
    }
    Ok(())
}

// ── Record projection ───────────────────────────────────────────────────────

/// One declared record plus the identity the fixture asserts for it.
#[derive(Clone, Debug)]
struct DeclaredRecord {
    name: String,
    record: AccountStatusRecord,
    declared_canonical_bytes: String,
    declared_core_digest: String,
    declared_record_id: AccountStatusRecordId,
}

fn parse_declared(name: &str, entry: &Value) -> Result<DeclaredRecord> {
    let record: AccountStatusRecord =
        serde_json::from_value(required_field(entry, "record")?.clone())
            .map_err(|error| anyhow!("{name}: record is not an AccountStatusRecord: {error}"))?;
    record
        .validate_shape()
        .map_err(|error| anyhow!("{name}: record failed its own shape validator: {error}"))?;
    Ok(DeclaredRecord {
        name: name.to_owned(),
        record,
        declared_canonical_bytes: required_str(entry, "unsigned_core_canonical_bytes_utf8")?
            .to_owned(),
        declared_core_digest: required_str(entry, "unsigned_core_digest")?.to_owned(),
        declared_record_id: AccountStatusRecordId::new(
            required_str(entry, "account_status_record_id")?.to_owned(),
        )?,
    })
}

fn parse_records(ledger: &Value, key: &str) -> Result<Vec<DeclaredRecord>> {
    let mut out = Vec::new();
    for (index, entry) in value_array(required_field(ledger, key)?, key)?
        .iter()
        .enumerate()
    {
        out.push(parse_declared(&format!("{key}[{index}]"), entry)?);
    }
    ensure!(!out.is_empty(), "issuer-ledger {key} is empty");
    Ok(out)
}

fn parse_named_records(ledger: &Value, key: &str) -> Result<Vec<DeclaredRecord>> {
    let mut out = Vec::new();
    for entry in value_array(required_field(ledger, key)?, key)? {
        out.push(parse_declared(required_str(entry, "name")?, entry)?);
    }
    ensure!(!out.is_empty(), "issuer-ledger {key} is empty");
    Ok(out)
}

fn record_index<'a>(
    chain: &'a [DeclaredRecord],
    conflicting: &'a [DeclaredRecord],
) -> BTreeMap<AccountStatusRecordId, &'a DeclaredRecord> {
    chain
        .iter()
        .chain(conflicting.iter())
        .map(|declared| (declared.record.account_status_record_id.clone(), declared))
        .collect()
}

// ── Identity and proof binding ──────────────────────────────────────────────

/// Re-derive the unsigned core from each declared record and require the
/// fixture's own canonical bytes, digest and record id to fall out of it.
fn verify_record_identity_and_proof_binding(
    ledger: &Value,
    chain: &[DeclaredRecord],
    conflicting: &[DeclaredRecord],
) -> Result<()> {
    let authority = DidCoreId::new(required_str(ledger, "account_authority_id")?.to_owned())?;
    let mut seen_ids = BTreeSet::new();

    for declared in chain.iter().chain(conflicting.iter()) {
        let name = &declared.name;
        let unsigned = declared.record.unsigned();
        unsigned
            .validate()
            .map_err(|error| anyhow!("{name}: unsigned core is invalid: {error}"))?;

        let canonical_bytes = unsigned
            .canonical_bytes()
            .map_err(|error| anyhow!("{name}: unsigned core has no canonical bytes: {error}"))?;
        let canonical_text = String::from_utf8(canonical_bytes.clone())
            .map_err(|error| anyhow!("{name}: canonical bytes are not UTF-8: {error}"))?;
        ensure!(
            canonical_text == declared.declared_canonical_bytes,
            "{name}: declared canonical core bytes do not match the SDK encoder\n  declared: {}\n  derived:  {canonical_text}",
            declared.declared_canonical_bytes
        );
        // The declared bytes really are the record minus exactly two members.
        verify_core_omits_only_id_and_proof(name, &declared.record, &canonical_text)?;

        let derived_digest = sha256_prefixed(&canonical_bytes);
        ensure!(
            derived_digest == declared.declared_core_digest,
            "{name}: declared core digest {} is not the digest of the core bytes ({derived_digest})",
            declared.declared_core_digest
        );

        let derived_id = unsigned
            .record_id()
            .map_err(|error| anyhow!("{name}: record id derivation failed: {error}"))?;
        ensure!(
            derived_id == declared.declared_record_id
                && derived_id == declared.record.account_status_record_id,
            "{name}: the record id is not the content address of its own core"
        );
        ensure!(
            seen_ids.insert(derived_id.clone()),
            "{name}: two declared records share one record id"
        );

        // The proof binds this exact core: same digest, same issuance time, and
        // the Account Authority's own verification method.
        let proof = &declared.record.proof;
        let payload_digest = unsigned
            .payload_digest()
            .map_err(|error| anyhow!("{name}: payload digest failed: {error}"))?;
        ensure!(
            proof.payload_digest == payload_digest,
            "{name}: the proof does not name the digest of its own core"
        );
        unsigned
            .canonical_proof_binding_bytes(&proof.unsigned())
            .map_err(|error| anyhow!("{name}: proof metadata does not bind the core: {error}"))?;
        ensure!(
            proof
                .verification_method
                .as_str()
                .contains(authority.as_str().trim_start_matches("ak:did_core:")),
            "{name}: the record is not signed by its own Account Authority"
        );

        // A record the fixture re-signs with a different digest must be refused
        // by the same binding check, so the check is not vacuous.
        let mut tampered = proof.unsigned();
        tampered.payload_digest = Hash::new(format!("sha256:{}", "ab".repeat(32)))?;
        ensure!(
            unsigned.canonical_proof_binding_bytes(&tampered).is_err(),
            "{name}: a proof naming a foreign digest was accepted"
        );
    }
    Ok(())
}

/// The unsigned core is the record without exactly `account_status_record_id`
/// and `proof` — nothing else is dropped and nothing is added.
fn verify_core_omits_only_id_and_proof(
    name: &str,
    record: &AccountStatusRecord,
    canonical_text: &str,
) -> Result<()> {
    let full = serde_json::to_value(record)?;
    let mut expected: Map<String, Value> = full
        .as_object()
        .ok_or_else(|| anyhow!("{name}: record must serialize as an object"))?
        .clone();
    let dropped_id = expected.remove("account_status_record_id").is_some();
    let dropped_proof = expected.remove("proof").is_some();
    ensure!(
        dropped_id && dropped_proof,
        "{name}: the record no longer carries both an id and a proof"
    );
    let expected_text = canonical_json(&Value::Object(expected))?;
    ensure!(
        expected_text == canonical_text,
        "{name}: the unsigned core drops more or less than the id and the proof"
    );
    Ok(())
}

/// The ledger keeps its own chain. It must not carry a Realm commit, stream,
/// position or any retired coverage carrier.
fn verify_record_carries_no_commit_or_stream_carrier(
    chain: &[DeclaredRecord],
    conflicting: &[DeclaredRecord],
) -> Result<()> {
    for declared in chain.iter().chain(conflicting.iter()) {
        let mut members = BTreeSet::new();
        collect_keys(&serde_json::to_value(&declared.record)?, &mut members);
        for forbidden in FORBIDDEN_RECORD_MEMBERS {
            ensure!(
                !members.contains(*forbidden),
                "{}: the issuer ledger reintroduced the carrier {forbidden}",
                declared.name
            );
        }
        // The chain link it does carry is its own predecessor record id.
        ensure!(
            members.contains("status_seq") && members.contains("binding_version"),
            "{}: the record lost its own ordering fields",
            declared.name
        );
    }
    Ok(())
}

fn collect_keys(value: &Value, out: &mut BTreeSet<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                out.insert(key.clone());
                collect_keys(child, out);
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_keys(item, out);
            }
        }
        _ => {}
    }
}

// ── The declared chain ──────────────────────────────────────────────────────

fn verify_chain_is_a_cas_successor_chain(chain: &[DeclaredRecord]) -> Result<()> {
    ensure!(
        chain.len() >= 3,
        "the issuer ledger needs a genesis and at least two successors"
    );
    let mut previous: Option<&AccountStatusRecord> = None;
    for declared in chain {
        let record = &declared.record;
        ensure!(
            record.schema == SchemaId::ACCOUNT_STATUS_RECORD_V1,
            "{}: record schema drifted",
            declared.name
        );
        match previous {
            None => {
                ensure!(
                    record.status_seq == 1
                        && record.previous_account_status_record_id.is_none()
                        && record.status == AccountStatus::Active,
                    "{}: genesis must be an active record at status_seq 1 with no predecessor",
                    declared.name
                );
            }
            Some(head) => {
                ensure!(
                    record.status_seq == head.status_seq + 1,
                    "{}: the chain must advance by exactly one sequence",
                    declared.name
                );
                ensure!(
                    record.previous_account_status_record_id.as_ref()
                        == Some(&head.account_status_record_id),
                    "{}: the successor must name the exact predecessor record id",
                    declared.name
                );
                ensure!(
                    record.account_authority_id == head.account_authority_id
                        && record.account_id == head.account_id,
                    "{}: the chain must stay inside one compare-and-swap key",
                    declared.name
                );
                ensure!(
                    record.binding_version >= head.binding_version,
                    "{}: the binding version must never roll back along the chain",
                    declared.name
                );
                ensure!(
                    record.issued_at >= head.issued_at,
                    "{}: the chain must not travel backwards in issuance time",
                    declared.name
                );
            }
        }
        previous = Some(record);
    }
    Ok(())
}

// ── Genesis ─────────────────────────────────────────────────────────────────

/// Genesis is created inside the account-binding transaction and waits for
/// nothing in the commit plane: no Station checkpoint, no `RealmCommit`.
fn verify_genesis_rules(fixture: &Value, chain: &[DeclaredRecord]) -> Result<()> {
    let rules = required_field(fixture, "genesis_rules")?;
    ensure!(
        required_bool(rules, "created_in_the_binding_commit_transaction")?,
        "account status genesis must be created in the binding transaction"
    );
    ensure!(
        required_u64(rules, "status_seq")? == 1,
        "account status genesis must be status_seq 1"
    );
    ensure!(
        required_str(rules, "status")? == "active",
        "account status genesis must be active"
    );
    ensure!(
        !required_bool(rules, "carries_previous_account_status_record_id")?,
        "account status genesis must carry no predecessor"
    );
    ensure!(
        !required_bool(rules, "waits_for_station_checkpoint")?,
        "account status genesis must not wait for a Station checkpoint"
    );
    ensure!(
        !required_bool(rules, "waits_for_realm_commit")?,
        "account status genesis must not wait for a RealmCommit"
    );

    // The rules are executable, not documentation: the SDK validator refuses a
    // genesis that carries a predecessor and refuses a non-active genesis.
    let genesis = chain
        .first()
        .ok_or_else(|| anyhow!("the ledger declares no genesis record"))?;
    let mut with_predecessor = genesis.record.unsigned();
    with_predecessor.previous_account_status_record_id =
        Some(chain[1].record.account_status_record_id.clone());
    ensure!(
        with_predecessor.validate().is_err(),
        "a genesis record with a predecessor was accepted"
    );
    let mut inactive = genesis.record.unsigned();
    inactive.status = AccountStatus::Locked;
    ensure!(
        inactive.validate().is_err(),
        "a genesis record that is not active was accepted"
    );
    let mut zero = genesis.record.unsigned();
    zero.status_seq = 0;
    ensure!(
        zero.validate().is_err(),
        "a record at status_seq 0 was accepted"
    );
    Ok(())
}

// ── Successor compare-and-swap ──────────────────────────────────────────────

fn verify_successor_cas_contract(ledger_owner: &Value, fixture: &Value) -> Result<()> {
    let _ = ledger_owner;
    let cas = required_field(fixture, "successor_cas")?;
    let key = string_list(cas, "cas_key")?;
    ensure!(
        key == CAS_KEY,
        "the issuer-ledger compare-and-swap key drifted: {key:?}"
    );
    ensure!(
        required_str(cas, "required_status_seq")? == "head.status_seq + 1",
        "a successor must take exactly the next sequence"
    );
    ensure!(
        required_str(cas, "required_predecessor")? == "head.account_status_record_id",
        "a successor must name the durable head as its predecessor"
    );
    let writes = string_list(cas, "atomic_writes")?;
    ensure!(
        writes == ATOMIC_WRITES,
        "the successor transaction's atomic write set drifted: {writes:?}"
    );
    Ok(())
}

fn string_list(value: &Value, key: &str) -> Result<Vec<String>> {
    value_array(required_field(value, key)?, key)?
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::to_owned)
                .ok_or_else(|| anyhow!("{key} entries must be strings"))
        })
        .collect()
}

// ── Replica classification ──────────────────────────────────────────────────

/// Run every declared classification case through the shipped receiver and
/// cross-check it against the normative decision table.
fn verify_replica_classification(
    fixture: &Value,
    index: &BTreeMap<AccountStatusRecordId, &DeclaredRecord>,
) -> Result<()> {
    let table = load_artifact_json(REPLICA_DECISION_TABLE_REF)?;
    ensure!(
        required_str(&table, "comparison_baseline")? == "durable_replica_head",
        "the replica decision table changed its comparison baseline"
    );
    let rows: BTreeMap<String, Value> = value_array(
        required_field(&table, "classifications")?,
        "classifications",
    )?
    .iter()
    .map(|row| Ok((required_str(row, "name")?.to_owned(), row.clone())))
    .collect::<Result<_>>()?;

    let mut executed = BTreeSet::new();
    for case in value_array(
        required_field(fixture, "replica_classification_cases")?,
        "replica_classification_cases",
    )? {
        let name = required_str(case, "name")?;
        let classification = required_str(case, "classification")?;
        let row = rows.get(classification).ok_or_else(|| {
            anyhow!("{name}: classification {classification} is not in the decision table")
        })?;

        let submitted_id = AccountStatusRecordId::new(required_str(case, "submitted")?.to_owned())?;
        let submitted = index
            .get(&submitted_id)
            .ok_or_else(|| anyhow!("{name}: submitted record {submitted_id} is not declared"))?;

        let head = match case.get("durable_head") {
            None | Some(Value::Null) => None,
            Some(head) => {
                let head_id = AccountStatusRecordId::new(
                    required_str(head, "account_status_record_id")?.to_owned(),
                )?;
                let declared = index
                    .get(&head_id)
                    .ok_or_else(|| anyhow!("{name}: durable head {head_id} is not declared"))?;
                ensure!(
                    declared.record.status_seq == required_u64(head, "status_seq")?
                        && declared.record.binding_version
                            == required_u64(head, "binding_version")?,
                    "{name}: the declared durable head disagrees with the record it names"
                );
                Some((declared.record.clone(), receipt_for(&declared.record)?))
            }
        };

        let observed = classify_account_status_replica_append(&submitted.record, head.as_ref());
        let expected = required_field(case, "expected")?;
        compare_classification(name, classification, row, expected, &observed)?;
        executed.insert(classification.to_owned());
    }

    // Every row of the normative table must be executed by some case, otherwise
    // the table has a branch nothing in this repository ever reaches.
    for row in rows.keys() {
        ensure!(
            executed.contains(row),
            "the decision table row {row} is never executed by the fixture"
        );
    }
    Ok(())
}

fn compare_classification(
    name: &str,
    classification: &str,
    row: &Value,
    expected: &Value,
    observed: &Option<AccountStatusReplicaAppend>,
) -> Result<()> {
    let outcome = required_str(expected, "outcome")?;
    ensure!(
        required_str(row, "outcome")? == outcome,
        "{name}: the fixture outcome disagrees with the decision table row {classification}"
    );
    ensure!(
        required_str(expected, "replica_writes")? == required_str(row, "replica_writes")?,
        "{name}: the fixture write set disagrees with the decision table row {classification}"
    );

    match (outcome, observed) {
        // `None` means the receiver admits the submission and must perform the
        // advancing write itself.
        ("accepted", None) => {
            ensure!(
                required_str(expected, "replica_writes")? == "advance",
                "{name}: an admitted submission must advance the replica"
            );
            ensure!(
                expected.get("reason_code").is_none_or(Value::is_null),
                "{name}: an accepted submission carries no reason code"
            );
        }
        ("duplicate", Some(AccountStatusReplicaAppend::Duplicate(_))) => {
            ensure!(
                required_bool(expected, "terminal_ack")?,
                "{name}: duplicate is a terminal ack"
            );
            ensure!(
                TERMINAL_ACKS.contains(&outcome),
                "{name}: duplicate must stay a terminal ack"
            );
        }
        (
            "dependency_missing",
            Some(AccountStatusReplicaAppend::DependencyMissing {
                required_status_seq,
                ..
            }),
        ) => {
            ensure!(
                *required_status_seq == required_u64(expected, "required_status_seq")?,
                "{name}: the receiver reported required_status_seq {required_status_seq}"
            );
            ensure!(
                required_bool(row, "retryable_for_exact_record")?,
                "{name}: dependency_missing is the only retryable outcome"
            );
        }
        ("rejected", Some(append)) => {
            verify_rejection(name, classification, row, expected, append)?;
        }
        (outcome, observed) => bail!(
            "{name}: the shipped receiver returned {observed:?} for a fixture that expects {outcome}"
        ),
    }
    Ok(())
}

fn verify_rejection(
    name: &str,
    classification: &str,
    row: &Value,
    expected: &Value,
    observed: &AccountStatusReplicaAppend,
) -> Result<()> {
    let error_code = required_str(expected, "error_code")?;
    ensure!(
        ErrorCode::from_wire(error_code).is_some(),
        "{name}: {error_code} is not a registered wire error code"
    );
    ensure!(
        required_str(row, "error_code")? == error_code,
        "{name}: the fixture error code disagrees with the decision table"
    );
    let reason_code = required_str(expected, "reason_code")?;
    ensure!(
        required_str(row, "reason_code")? == reason_code,
        "{name}: the fixture reason code disagrees with the decision table"
    );
    ensure!(
        !required_bool(row, "retryable_for_exact_record")?,
        "{name}: a rejected submission is never retryable for the exact record"
    );

    match (classification, observed) {
        (
            "fork_predecessor_mismatch" | "fork_same_sequence",
            AccountStatusReplicaAppend::Conflict {
                kind: AccountStatusReplicaConflictKind::Fork,
                ..
            },
        ) => {
            ensure!(
                required_bool(expected, "quarantine")?,
                "{name}: a fork is quarantined, never silently dropped"
            );
        }
        (
            "binding_version_rollback",
            AccountStatusReplicaAppend::Conflict {
                kind: AccountStatusReplicaConflictKind::BindingRollback,
                ..
            },
        ) => {}
        ("stale", AccountStatusReplicaAppend::Stale { .. }) => {
            ensure!(
                required_bool(expected, "duplicate_forbidden")?,
                "{name}: a below-head submission must never be reported as duplicate"
            );
        }
        (classification, observed) => bail!(
            "{name}: classification {classification} produced {observed:?} from the shipped receiver"
        ),
    }
    Ok(())
}

/// A receipt for a durable head. Only the head's identity is read by the
/// classifier, so this binds the exact record it acknowledges.
fn receipt_for(record: &AccountStatusRecord) -> Result<AccountStatusReceipt> {
    let unsigned = record.unsigned();
    let record_digest = unsigned.payload_digest()?;
    let verification_method = record.proof.verification_method.clone();
    let receipt = UnsignedAccountStatusReceipt {
        receipt_id: receipt_id_for(record)?,
        account_status_record_id: record.account_status_record_id.clone(),
        record_digest: record_digest.clone(),
        account_authority_id: record.account_authority_id.clone(),
        account_id: record.account_id.clone(),
        status_seq: record.status_seq,
        receiver_id: record.account_id.station_id().clone(),
        accepted_at: record.issued_at,
        verification_method: verification_method.clone(),
    };
    Ok(AccountStatusReceipt {
        receipt_id: receipt.receipt_id.clone(),
        account_status_record_id: receipt.account_status_record_id.clone(),
        record_digest: receipt.record_digest.clone(),
        account_authority_id: receipt.account_authority_id.clone(),
        account_id: receipt.account_id.clone(),
        status_seq: receipt.status_seq,
        receiver_id: receipt.receiver_id.clone(),
        accepted_at: receipt.accepted_at,
        proof: head_receipt_proof(&receipt, verification_method)?,
    })
}

fn head_receipt_proof(
    receipt: &UnsignedAccountStatusReceipt,
    verification_method: DidUrl,
) -> Result<PayloadProof> {
    Ok(PayloadProof {
        kind: arkret_wire::proof_kind::DETACHED_JWS.to_owned(),
        verification_method,
        payload_digest: receipt.payload_digest()?,
        created_at: receipt.accepted_at,
        domain: None,
        audience: None,
        proof_purpose: None,
        jws: "eyJhbGciOiJFZDI1NTE5In0..AA".to_owned(),
    })
}

fn receipt_id_for(record: &AccountStatusRecord) -> Result<ReceiptId> {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(b"cotest.account_status.receipt.");
    hasher.update(record.account_status_record_id.as_str().as_bytes());
    Ok(ReceiptId::from_digest(hasher.finalize().into()))
}

// ── Idempotency ─────────────────────────────────────────────────────────────

/// One idempotency key scoped to a source/destination pair either replays the
/// first response bytes or is a typed conflict. It never half-writes, and it
/// never leaves a pending commit behind, because the ledger has no commit plane.
fn verify_idempotency_contract(fixture: &Value) -> Result<()> {
    let idempotency = required_field(fixture, "idempotency")?;
    let scope = string_list(idempotency, "scope")?;
    ensure!(
        scope == IDEMPOTENCY_SCOPE,
        "the issuer-ledger idempotency scope drifted: {scope:?}"
    );
    ensure!(
        required_str(idempotency, "same_key_same_canonical_body")?
            == "replays the first response bytes",
        "a byte-identical replay must return the first response bytes"
    );
    let different = required_field(idempotency, "same_key_different_canonical_body")?;
    ensure!(
        required_str(different, "outcome")? == "rejected",
        "one key must not cover two canonical bodies"
    );
    let error_code = required_str(different, "error_code")?;
    ensure!(
        ErrorCode::from_wire(error_code) == Some(ErrorCode::DuplicateConflict),
        "an idempotency-key reuse under a different body is duplicate_conflict, not {error_code}"
    );
    ensure!(
        required_str(different, "replica_writes")? == "none",
        "a rejected idempotency reuse performs zero writes"
    );
    let acks = string_list(idempotency, "terminal_acks")?;
    ensure!(
        acks == TERMINAL_ACKS,
        "the terminal ack set drifted: {acks:?}"
    );
    ensure!(
        !required_bool(idempotency, "pending_commit_exists")?,
        "the issuer ledger has no commit plane and therefore no pending commit"
    );
    Ok(())
}

// ── Bounded fanout outbox ───────────────────────────────────────────────────

/// Propagation is a bounded outbox: one outstanding update per destination, a
/// bounded destination set, a dedupe key that names the exact record, and a
/// completion rule that only terminal acks satisfy.
fn verify_fanout_outbox(fixture: &Value) -> Result<()> {
    let outbox = required_field(fixture, "fanout_outbox")?;
    let dedupe = string_list(outbox, "dedupe_key")?;
    ensure!(
        dedupe
            == [
                "account_authority_id",
                "account_id",
                "destination_id",
                "account_status_record_id"
            ],
        "the fanout dedupe key drifted: {dedupe:?}"
    );
    let max_destinations = required_u64(outbox, "max_destinations_per_account")?;
    ensure!(
        max_destinations == 256,
        "the destination bound drifted: {max_destinations}"
    );
    ensure!(
        required_u64(outbox, "max_outstanding_updates_per_destination")? == 1,
        "a destination may carry at most one outstanding update"
    );

    let mut complete = 0_u32;
    let mut incomplete = 0_u32;
    for transition in value_array(required_field(outbox, "transitions")?, "transitions")? {
        let name = required_str(transition, "name")?;
        let acks = string_list(transition, "destination_acks")?;
        ensure!(!acks.is_empty(), "{name}: a transition declares its acks");
        let all_terminal = acks.iter().all(|ack| TERMINAL_ACKS.contains(&ack.as_str()));
        let expected_state = required_str(transition, "expected_state")?;
        let derived = if all_terminal {
            "complete"
        } else {
            "incomplete"
        };
        ensure!(
            derived == expected_state,
            "{name}: a record is complete exactly when every destination gave a terminal ack"
        );
        ensure!(
            !required_bool(transition, "may_skip_predecessor")?,
            "{name}: a destination must never skip a predecessor record"
        );
        if expected_state == "complete" {
            complete += 1;
        } else {
            incomplete += 1;
        }

        // A non-terminal ack that is a wire outcome must still be registered.
        for ack in &acks {
            ensure!(
                TERMINAL_ACKS.contains(&ack.as_str())
                    || matches!(ack.as_str(), "pending" | "dependency_missing"),
                "{name}: unregistered destination ack {ack}"
            );
        }
        if acks.iter().any(|ack| ack == "dependency_missing") {
            ensure!(
                required_str(transition, "required_action")?
                    == "resolve_from_required_status_seq_then_resubmit",
                "{name}: a destination gap resolves before the successor is submitted"
            );
        }
    }
    ensure!(
        complete >= 1 && incomplete >= 2,
        "the outbox table must keep both the completing and the blocking transitions"
    );

    let barriers = string_list(outbox, "barrier_statuses")?;
    ensure!(
        barriers == ["deactivated", "erasure_pending"],
        "the propagation barrier statuses drifted: {barriers:?}"
    );
    for barrier in &barriers {
        ensure!(
            serde_json::from_value::<AccountStatus>(Value::String(barrier.clone())).is_ok(),
            "barrier status {barrier} is not a registered AccountStatus"
        );
    }
    Ok(())
}

/// Unused import guard: the suite reads timestamps through the record types.
#[allow(dead_code)]
fn _timestamp_type_is_used(value: DateTime<Utc>) -> DateTime<Utc> {
    value
}
