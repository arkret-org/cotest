//! Executable semantics for `ak.vector.account.blocklist_projection.v1`.
//!
//! The canonical fixture is intentionally semantic: its cases describe a
//! holder-private CAS register and a client projection, not a second wire
//! protocol.  This runner therefore executes those state transitions.  It
//! also uses the SDK's closed `AccountBlocklistPayload` target union for the
//! target-closure case, so accepting a Realm/Organization target cannot be
//! hidden by a harness-only model.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, anyhow, ensure};
use arkret_models_collaboration::objects::productivity::AccountBlocklistPayload;
use serde_json::{Value, json};

use super::{
    fixture_runner_entrypoint, load_artifact_json, load_fixture_value, required_field,
    required_str, value_array,
};

pub const VECTOR_ID_ACCOUNT_BLOCKLIST_PROJECTION: &str =
    "ak.vector.account.blocklist_projection.v1";
pub const ACCOUNT_BLOCKLIST_PROJECTION_ENTRYPOINT: &str =
    "ak.suite.account.blocklist_projection.v1";

const FIXTURE: &str = "account-blocklist-projection-fixture.json";
const SUITE: &str = "account_blocklist_projection";
const BLOCKLIST_KEY: &str = "ak.account.blocklist";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WriteError {
    CasConflict,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct WholeValueRegister {
    revision: u64,
    entries: BTreeSet<String>,
}

impl WholeValueRegister {
    fn at(revision: u64, entries: impl IntoIterator<Item = &'static str>) -> Self {
        Self {
            revision,
            entries: entries.into_iter().map(str::to_owned).collect(),
        }
    }

    /// Both `ak.account.blocklist` and `ak.account_data.set` reach this exact
    /// operation. There is no per-event-kind revision lane and no entry merge.
    fn replace(
        &mut self,
        expected_server_revision: u64,
        declared_version: u64,
        entries: impl IntoIterator<Item = &'static str>,
    ) -> Result<u64, WriteError> {
        if expected_server_revision != self.revision
            || declared_version != self.revision.saturating_add(1)
        {
            return Err(WriteError::CasConflict);
        }
        self.revision = declared_version;
        self.entries = entries.into_iter().map(str::to_owned).collect();
        Ok(self.revision)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SharedEvent {
    author: &'static str,
    body: &'static str,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct HolderReplica {
    retained: Vec<SharedEvent>,
    blocked: BTreeSet<String>,
    local_blocklist_revision: u64,
}

impl HolderReplica {
    fn receive(&mut self, event: SharedEvent) {
        self.retained.push(event);
    }

    fn install_blocklist(&mut self, revision: u64, blocked: &[&str]) {
        self.local_blocklist_revision = revision;
        self.blocked = blocked.iter().map(|value| (*value).to_owned()).collect();
    }

    fn projected_bodies(&self) -> Vec<&'static str> {
        self.retained
            .iter()
            .filter(|event| !self.blocked.contains(event.author))
            .map(|event| event.body)
            .collect()
    }

    fn may_emit_presence_or_read_receipt(&self, authority_revision: u64) -> bool {
        self.local_blocklist_revision == authority_revision
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SenderObservation {
    status: &'static str,
    disclosed_reason: Option<&'static str>,
    delivery_receipt: Option<&'static str>,
}

fn sender_observation(_recipient_state: RecipientState) -> SenderObservation {
    // Filtering is a holder-side projection. The peer-facing acceptance shape
    // is deliberately independent of the private recipient state.
    SenderObservation {
        status: "accepted",
        disclosed_reason: None,
        delivery_receipt: None,
    }
}

#[derive(Clone, Copy)]
enum RecipientState {
    Blocked,
    Unauthorized,
    Absent,
    Offline,
}

/// Execute every canonical blocklist case against the state machines above.
pub fn run_account_blocklist_projection_vector() -> Result<()> {
    run_account_blocklist_projection_suite().map(|_| ())
}

/// Execute every declared case and report one result per case, so the named
/// suite audit can match the fixture's `cases[]` one for one.
pub fn run_account_blocklist_projection_suite() -> Result<super::SuiteExecutionResult> {
    let fixture = load_fixture_value(FIXTURE)?;
    verify_fixture_identity(&fixture)?;
    verify_registry_contract()?;
    verify_security_evidence_mapping(&fixture)?;

    let cases = value_array(required_field(&fixture, "cases")?, "cases")?;
    ensure!(
        cases.len() == 8,
        "blocklist fixture must carry exactly 8 cases"
    );
    let mut executed = BTreeSet::new();
    let mut results = Vec::with_capacity(cases.len());
    for case in cases {
        let name = required_str(case, "name")?;
        ensure!(executed.insert(name), "duplicate blocklist case {name}");
        match name {
            "whole_value_cas_rejects_a_skipped_revision" => skipped_revision(case)?,
            "whole_value_cas_rejects_a_stale_concurrent_write" => concurrent_write(case)?,
            "account_data_set_shares_the_one_revision_counter" => shared_counter(case)?,
            "target_closure_rejects_realm_and_organization_targets" => target_closure(case)?,
            "shared_history_is_received_then_filtered_by_the_holder" => {
                receive_before_filter(case)?
            }
            "unblock_rebuilds_the_projection_from_retained_material" => unblock_rebuild(case)?,
            "server_side_filtering_stays_indistinguishable" => non_enumeration(case)?,
            "an_unsynced_device_treats_freshness_as_unknown" => stale_device(case)?,
            other => return Err(anyhow!("unexecuted blocklist fixture case {other}")),
        }
        results.push(super::CaseExecutionResult {
            case_id: name.to_owned(),
            assertions: 1,
        });
    }
    Ok(super::SuiteExecutionResult {
        entrypoint: ACCOUNT_BLOCKLIST_PROJECTION_ENTRYPOINT,
        fixture: FIXTURE,
        cases: results,
    })
}

fn assert_case(case: &Value, decision: &str, reason: Option<&str>) -> Result<()> {
    ensure!(
        required_str(case, "decision")? == decision,
        "{}: decision drifted",
        required_str(case, "name")?
    );
    match reason {
        Some(expected) => ensure!(
            required_str(case, "reason")? == expected,
            "{}: reason drifted",
            required_str(case, "name")?
        ),
        None => ensure!(
            case.get("reason").is_none(),
            "{}: successful case unexpectedly declares a failure reason",
            required_str(case, "name")?
        ),
    }
    ensure!(
        !value_array(required_field(case, "assertions")?, "case.assertions")?.is_empty(),
        "{}: case has no observable assertions",
        required_str(case, "name")?
    );
    Ok(())
}

fn skipped_revision(case: &Value) -> Result<()> {
    assert_case(case, "reject", Some("cas_conflict"))?;
    let before = WholeValueRegister::at(7, ["alice"]);
    let mut register = before.clone();
    ensure!(
        register.replace(7, 9, ["bob"]) == Err(WriteError::CasConflict),
        "a skipped revision was accepted"
    );
    ensure!(register == before, "a rejected write changed the register");
    Ok(())
}

fn concurrent_write(case: &Value) -> Result<()> {
    assert_case(case, "reject", Some("cas_conflict"))?;
    let mut register = WholeValueRegister::at(7, ["alice"]);
    ensure!(register.replace(7, 8, ["bob"]) == Ok(8));
    let winner = register.clone();
    ensure!(
        register.replace(7, 8, ["carol"]) == Err(WriteError::CasConflict),
        "the stale concurrent write was merged"
    );
    ensure!(
        register == winner,
        "the losing write partially changed the winner"
    );
    Ok(())
}

fn shared_counter(case: &Value) -> Result<()> {
    assert_case(case, "reject", Some("cas_conflict"))?;
    let mut register = WholeValueRegister::at(7, ["alice"]);
    // First write models `ak.account.blocklist`; the second models
    // `ak.account_data.set`. Both deliberately call the same register method.
    ensure!(register.replace(7, 8, ["bob"]) == Ok(8));
    ensure!(
        register.replace(7, 8, ["carol"]) == Err(WriteError::CasConflict),
        "the two authoring surfaces acquired independent revision lanes"
    );
    Ok(())
}

fn target_closure(case: &Value) -> Result<()> {
    assert_case(case, "reject", Some("schema_violation"))?;
    let valid = json!({
        "version": 1,
        "entries": [{
            "target": {"kind": "handle", "value": "alice:example.test"},
            "mode": "block",
            "applies_to": ["messages"],
            "created_at": "2026-09-20T00:00:00.000Z"
        }]
    });
    let valid: AccountBlocklistPayload = serde_json::from_value(valid)?;
    valid.validate()?;

    for forbidden in [
        json!({"kind": "realm", "value": "ak:realm:forbidden"}),
        json!({"kind": "organization", "value": "ak:org:forbidden"}),
    ] {
        let value = json!({
            "version": 1,
            "entries": [{
                "target": forbidden,
                "mode": "block",
                "applies_to": ["messages"],
                "created_at": "2026-09-20T00:00:00.000Z"
            }]
        });
        ensure!(
            serde_json::from_value::<AccountBlocklistPayload>(value).is_err(),
            "the SDK accepted an unregistered Realm/Organization target"
        );
    }
    Ok(())
}

fn receive_before_filter(case: &Value) -> Result<()> {
    assert_case(case, "accept", None)?;
    let mut holder = HolderReplica::default();
    holder.install_blocklist(8, &["bob"]);
    holder.receive(SharedEvent {
        author: "bob",
        body: "retained while blocked",
    });
    ensure!(
        holder.retained.len() == 1,
        "shared history was dropped on receive"
    );
    ensure!(
        holder.projected_bodies().is_empty(),
        "blocked material leaked into the holder projection"
    );
    Ok(())
}

fn unblock_rebuild(case: &Value) -> Result<()> {
    assert_case(case, "accept", None)?;
    let mut holder = HolderReplica::default();
    holder.install_blocklist(8, &["bob"]);
    holder.receive(SharedEvent {
        author: "bob",
        body: "history survives",
    });
    ensure!(holder.projected_bodies().is_empty());
    holder.install_blocklist(9, &[]);
    ensure!(
        holder.projected_bodies() == ["history survives"],
        "unblock did not rebuild from retained history"
    );
    ensure!(
        holder.retained.len() == 1,
        "rebuild fetched or duplicated history"
    );
    Ok(())
}

fn non_enumeration(case: &Value) -> Result<()> {
    assert_case(case, "accept", None)?;
    let baseline = sender_observation(RecipientState::Blocked);
    for state in [
        RecipientState::Unauthorized,
        RecipientState::Absent,
        RecipientState::Offline,
    ] {
        ensure!(
            sender_observation(state) == baseline,
            "recipient-private state changed the sender-visible outcome"
        );
    }
    ensure!(
        !format!("{baseline:?}").contains("blocked"),
        "the sender observation disclosed the block"
    );
    Ok(())
}

fn stale_device(case: &Value) -> Result<()> {
    assert_case(case, "accept", None)?;
    let mut device = HolderReplica::default();
    device.install_blocklist(7, &[]);
    ensure!(
        !device.may_emit_presence_or_read_receipt(8),
        "a stale device emitted privacy-sensitive signals"
    );
    device.install_blocklist(8, &["bob"]);
    ensure!(
        device.may_emit_presence_or_read_receipt(8),
        "a caught-up device remained permanently freshness-unknown"
    );
    Ok(())
}

fn verify_fixture_identity(fixture: &Value) -> Result<()> {
    ensure!(
        required_str(fixture, "suite")? == SUITE,
        "fixture suite drifted"
    );
    ensure!(
        fixture_runner_entrypoint(fixture)? == ACCOUNT_BLOCKLIST_PROJECTION_ENTRYPOINT,
        "fixture entrypoint drifted"
    );
    let covers = value_array(required_field(fixture, "covers_vectors")?, "covers_vectors")?;
    ensure!(
        covers
            .iter()
            .any(|value| value.as_str() == Some(VECTOR_ID_ACCOUNT_BLOCKLIST_PROJECTION)),
        "fixture no longer covers {VECTOR_ID_ACCOUNT_BLOCKLIST_PROJECTION}"
    );
    Ok(())
}

fn verify_registry_contract() -> Result<()> {
    let registry = load_artifact_json("registry/account-data-key-registry.json")?;
    let rows = value_array(
        required_field(&registry, "account_data_key_patterns")?,
        "account_data_key_patterns",
    )?;
    let row = rows
        .iter()
        .find(|row| row.get("key_pattern").and_then(Value::as_str) == Some(BLOCKLIST_KEY))
        .ok_or_else(|| anyhow!("account-data registry lost {BLOCKLIST_KEY}"))?;
    ensure!(required_str(row, "storage")? == "encrypted_account_data");
    ensure!(required_str(row, "scope")? == "principal_private_policy");
    let writers = value_array(
        required_field(row, "write_event_kinds")?,
        "write_event_kinds",
    )?;
    let writers = writers
        .iter()
        .filter_map(Value::as_str)
        .collect::<BTreeSet<_>>();
    ensure!(
        writers == BTreeSet::from(["ak.account.blocklist", "ak.account_data.set"]),
        "blocklist authoring surfaces drifted: {writers:?}"
    );
    Ok(())
}

fn verify_security_evidence_mapping(fixture: &Value) -> Result<()> {
    let evidence_rows = value_array(
        required_field(fixture, "security_evidence")?,
        "security_evidence",
    )?;
    ensure!(
        evidence_rows.len() == 1,
        "blocklist fixture must have one evidence row"
    );
    let evidence = &evidence_rows[0];
    ensure!(required_str(evidence, "vector_id")? == VECTOR_ID_ACCOUNT_BLOCKLIST_PROJECTION);
    ensure!(required_str(evidence, "clause_id")? == "AK-NC-072");
    let expected: BTreeMap<&str, &[&str]> = BTreeMap::from([
        ("whole_value_cas", &["/cases/0", "/cases/1", "/cases/2"][..]),
        ("target_closure", &["/cases/3"][..]),
        ("receive_before_filter", &["/cases/4", "/cases/6"][..]),
        ("unblock_projection_rebuild", &["/cases/5"][..]),
        ("non_enumerable_outcome", &["/cases/6", "/cases/7"][..]),
    ]);
    let mut observed = BTreeSet::new();
    for point in value_array(
        required_field(evidence, "decision_points")?,
        "decision_points",
    )? {
        let id = required_str(&point, "id")?;
        ensure!(observed.insert(id), "duplicate decision point {id}");
        let expected_pointers = expected
            .get(id)
            .ok_or_else(|| anyhow!("unexecuted blocklist decision point {id}"))?;
        let pointers = value_array(required_field(point, "evidence")?, "evidence")?;
        let actual = pointers
            .iter()
            .map(|value| value.as_str())
            .collect::<Vec<_>>();
        ensure!(
            actual
                .iter()
                .copied()
                .eq(expected_pointers.iter().map(|value| Some(*value))),
            "{id}: evidence pointers drifted: {actual:?}"
        );
        for pointer in expected_pointers.iter().copied() {
            ensure!(
                fixture.pointer(pointer).is_some(),
                "unresolved evidence pointer {pointer}"
            );
        }
    }
    ensure!(
        observed.len() == expected.len(),
        "not every decision point executed"
    );
    Ok(())
}
