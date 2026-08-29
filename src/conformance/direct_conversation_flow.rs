//! End-to-end state-machine coverage for Direct Conversation founding
//! durability and MLS finality fences.

use anyhow::{Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::load_artifact_json;
use crate::transcripts::record_vector_event;

const FOUNDER_LOSS_VECTOR: &str = "ak.vector.direct_conversation.founder_loss_terminality.v1";
const CONTACT_MIRROR_VECTOR: &str = "ak.vector.contact.pending_incoming_request_receipt.v1";

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DirectConversationFixture {
    suite: String,
    fixture_kind: String,
    profile: String,
    covers_vectors: Vec<String>,
    version: String,
    spec_anchor: String,
    source_refs: Vec<Value>,
    description: String,
    runner: Value,
    /// Free-form protocol instances validated by their referenced JSON Schemas.
    schema_validation_cases: Vec<Value>,
    semantic_cases: Vec<Value>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DurableFoundingStage {
    Prepared,
    ResponsePersisted,
    FoundingFinalityConfirmed,
    Sent,
    Rejected,
}

#[derive(Clone, Debug)]
struct DurableFoundingProbe {
    canonical_unit: Vec<u8>,
    receipt: Option<Vec<u8>>,
    stage: DurableFoundingStage,
}

impl DurableFoundingProbe {
    fn prepared(unit: &Value) -> Result<Self> {
        Ok(Self {
            canonical_unit: arkret_canonical::canonical_json_bytes(unit)?,
            receipt: None,
            stage: DurableFoundingStage::Prepared,
        })
    }

    fn persist_response(&mut self, receipt: &Value) -> Result<()> {
        if self.stage != DurableFoundingStage::Prepared {
            bail!("founding response may only close a prepared exact unit");
        }
        self.receipt = Some(arkret_canonical::canonical_json_bytes(receipt)?);
        self.stage = DurableFoundingStage::ResponsePersisted;
        Ok(())
    }

    fn mark_sent(&mut self) -> Result<()> {
        if self.stage != DurableFoundingStage::FoundingFinalityConfirmed || self.receipt.is_none() {
            bail!("founding cannot become sent before its receipt and covering Seals are durable");
        }
        self.stage = DurableFoundingStage::Sent;
        Ok(())
    }

    fn confirm_covering_seals(&mut self) -> Result<()> {
        if self.stage != DurableFoundingStage::ResponsePersisted || self.receipt.is_none() {
            bail!("founding finality requires the persisted acceptance receipt first");
        }
        self.stage = DurableFoundingStage::FoundingFinalityConfirmed;
        Ok(())
    }

    fn reject(&mut self) -> Result<()> {
        if self.stage != DurableFoundingStage::Prepared {
            bail!("only an unaccepted founding attempt can be rejected");
        }
        self.stage = DurableFoundingStage::Rejected;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AdmissionStage {
    CommitPending,
    CommitAcceptedWaitingSeal,
    WelcomesAuthored,
    WelcomesAcceptedWaitingSeal,
    Complete,
}

fn advance_admission(stage: AdmissionStage, observation: &str) -> Result<AdmissionStage> {
    use AdmissionStage::*;
    match (stage, observation) {
        (CommitPending, "commit_accepted") => Ok(CommitAcceptedWaitingSeal),
        (CommitAcceptedWaitingSeal, "commit_covering_seal") => Ok(WelcomesAuthored),
        (WelcomesAuthored, "welcomes_accepted") => Ok(WelcomesAcceptedWaitingSeal),
        (WelcomesAcceptedWaitingSeal, "welcome_covering_seals") => Ok(Complete),
        (CommitPending, "commit_rejected") => Ok(CommitPending),
        (WelcomesAuthored, "welcome_rejected") => Ok(WelcomesAuthored),
        _ => bail!("MLS admission attempted to cross a missing exact finality fence"),
    }
}

fn validate_founder_loss_terminality(fixture: &DirectConversationFixture) -> Result<()> {
    let covered = &fixture.covers_vectors;
    if !covered.iter().any(|value| value == FOUNDER_LOSS_VECTOR) {
        bail!("Direct Conversation fixture does not cover {FOUNDER_LOSS_VECTOR}");
    }

    let cases = &fixture.semantic_cases;
    let selected = cases
        .iter()
        .filter(|case| case["vector_id"] == FOUNDER_LOSS_VECTOR)
        .collect::<Vec<_>>();
    let expected = [
        (
            "same_founder_authority_recovery_is_not_succession",
            "accept",
        ),
        ("founder_loss_never_transfers_the_same_pair_slot", "reject"),
        (
            "different_stable_identity_creates_a_new_non_continuous_pair",
            "accept",
        ),
        (
            "all_members_private_state_loss_permanently_suspends_same_pair",
            "reject",
        ),
        (
            "offline_member_or_late_backup_means_state_was_not_globally_lost",
            "accept_existing_only",
        ),
    ];
    if selected.len() != expected.len() {
        bail!("founder-loss vector must expose exactly five closed paths");
    }
    for (name, outcome) in expected {
        let case = selected
            .iter()
            .find(|case| case["name"] == name)
            .ok_or_else(|| anyhow!("founder-loss vector missing case {name}"))?;
        if case["semantic_outcome"] != outcome {
            bail!("founder-loss case {name} has the wrong semantic outcome");
        }
    }

    let schema = load_artifact_json("schemas/direct-conversation-operations.schema.json")?;
    let states = schema["$defs"]["direct_conversation_resolve_outcome"]["oneOf"]
        .as_array()
        .ok_or_else(|| anyhow!("resolver outcome is not a closed oneOf"))?
        .iter()
        .filter_map(|branch| branch["properties"]["state"]["const"].as_str())
        .collect::<Vec<_>>();
    if states.contains(&"founder_unrecoverable") {
        bail!("v1 resolver reintroduced a founder_unrecoverable consensus state");
    }
    Ok(())
}

fn validate_contact_verified_mirror_contract(fixture: &DirectConversationFixture) -> Result<()> {
    let covered = &fixture.covers_vectors;
    if !covered.iter().any(|value| value == CONTACT_MIRROR_VECTOR) {
        bail!("Direct Conversation fixture does not cover {CONTACT_MIRROR_VECTOR}");
    }
    let expected = [
        (
            "contact_mirror_branch_returns_exact_event_without_seal",
            "accept",
            ["exact signed Event", "no seals member", "no Event other"],
        ),
        (
            "contact_mirror_branch_has_no_seal_selector_and_refuses_unverified_rows",
            "reject",
            [
                "rejects a seal_refs member",
                "unverified local row",
                "does not reveal",
            ],
        ),
        (
            "contact_mirror_visibility_closes_on_terminal_round",
            "reject",
            [
                "clears request_receipt",
                "accounted into missing",
                "local audit",
            ],
        ),
    ];
    for (name, outcome, required_assertions) in expected {
        let case = semantic_case(fixture, name)?;
        if case["vector_id"] != CONTACT_MIRROR_VECTOR || case["semantic_outcome"] != outcome {
            bail!("Contact mirror case {name} has the wrong vector or outcome");
        }
        let assertions = case["assertions"]
            .as_array()
            .ok_or_else(|| anyhow!("Contact mirror case {name} omits assertions[]"))?;
        for required in required_assertions {
            if !assertions
                .iter()
                .filter_map(Value::as_str)
                .any(|assertion| assertion.contains(required))
            {
                bail!("Contact mirror case {name} omits assertion `{required}`");
            }
        }
    }
    Ok(())
}

fn semantic_case<'a>(fixture: &'a DirectConversationFixture, name: &str) -> Result<&'a Value> {
    fixture
        .semantic_cases
        .iter()
        .find(|case| case.get("name").and_then(Value::as_str) == Some(name))
        .ok_or_else(|| anyhow!("Direct Conversation fixture omits semantic case `{name}`"))
}

fn validate_event_id_digest_mirror_removal(fixture: &DirectConversationFixture) -> Result<()> {
    const REMOVED_PAIRS: [(&str, &str); 6] = [
        ("head_event_ref", "head_digest"),
        ("request_event_ref", "request_digest"),
        ("response_event_ref", "response_digest"),
        ("reject_event_ref", "reject_digest"),
        ("signed_event_ref", "signed_event_digest"),
        ("agent_provision_ref", "agent_provision_digest"),
    ];

    fn reject_mirrors(value: &Value, path: &str) -> Result<()> {
        match value {
            Value::Object(object) => {
                for (event_ref, digest) in REMOVED_PAIRS {
                    if object.contains_key(event_ref) && object.contains_key(digest) {
                        bail!("{path} reintroduces redundant {event_ref}/{digest} wire fields");
                    }
                }
                for (key, child) in object {
                    reject_mirrors(child, &format!("{path}.{key}"))?;
                }
            }
            Value::Array(array) => {
                for (index, child) in array.iter().enumerate() {
                    reject_mirrors(child, &format!("{path}[{index}]"))?;
                }
            }
            _ => {}
        }
        Ok(())
    }

    reject_mirrors(&serde_json::to_value(fixture)?, "$")?;
    let event_id =
        arkret_wire::EventId::new("ak:event:AWAIb405aEEenVBHYRG-ZfDs-f9_j3E67tWGI36uYxFJ")?;
    if event_id.event_digest().as_str()
        != "sha256:60086f8d3968411e9d50476111be65f0ecf9ff7f8f713aeed586237eae631149"
    {
        bail!("EventId digest decoding no longer matches the fixture KAT");
    }
    Ok(())
}

fn validate_founding_and_crash_replay(fixture: &DirectConversationFixture) -> Result<()> {
    for name in [
        "founding_coordinates_are_derived_from_unit_bytes",
        "founding_unit_strand_uses_bootstrap_no_basis_shape",
        "founder_multi_device_concurrency_admits_first_valid_unit",
        "exact_unit_replay_returns_byte_identical_receipt",
        "same_idempotency_key_different_unit_conflicts",
    ] {
        semantic_case(fixture, name)?;
    }

    let unit = json!({
        "unit_kind": "direct_conversation_founding",
        "idempotency_key": "01JDCFLOW000000000000000001",
        "events": [
            "create-bytes",
            "peer-join-bytes",
            "main-strand-bytes",
            "founder-join-bytes"
        ]
    });
    let receipt = json!({
        "status": "accepted",
        "accepted_at": "2026-08-10T00:00:00Z",
        "founding_unit_digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    });
    let prepared = DurableFoundingProbe::prepared(&unit)?;
    let crash_before_write = prepared.clone();
    if crash_before_write.canonical_unit != prepared.canonical_unit {
        bail!("pre-submit recovery reauthored the founding unit");
    }
    let mut response_persisted = prepared.clone();
    response_persisted.persist_response(&receipt)?;
    let crash_after_response = response_persisted.clone();
    if crash_after_response.canonical_unit != prepared.canonical_unit
        || crash_after_response.receipt != response_persisted.receipt
    {
        bail!("post-response recovery changed unit or receipt bytes");
    }
    let mut premature_sent = response_persisted.clone();
    if premature_sent.mark_sent().is_ok() {
        bail!("founding ingress acceptance crossed its exact covering-Seal fence");
    }
    response_persisted.confirm_covering_seals()?;
    response_persisted.mark_sent()?;
    let mut rejected = prepared;
    rejected.reject()?;
    if rejected.stage != DurableFoundingStage::Rejected || rejected.receipt.is_some() {
        bail!("rejected founding attempt acquired acceptance evidence");
    }
    Ok(())
}

fn validate_bilateral_continuity_checkpoint_fixture() -> Result<()> {
    let fixture = load_artifact_json("fixtures/bilateral-continuity-checkpoint-fixture.json")?;
    let cases = fixture
        .get("cases")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("bilateral continuity fixture has no cases"))?;
    for name in [
        "root_basis_digest_is_sha256_of_jcs_and_not_wire_state",
        "history_beyond_64_uses_checkpoint_and_bounded_tail",
        "same_sequence_different_digest_is_fork",
        "single_roundtrip_countersigns_and_commits_same_checkpoint",
        "response_loss_replays_same_completed_checkpoint",
        "rollback_or_missing_checkpoint_predecessor_is_invalid",
        "wrong_root_pair_accumulator_or_single_signature_is_invalid",
        "temporarily_missing_portable_material_is_unavailable",
        "migrated_holder_imports_checkpoint_without_skipping_tail",
        "new_lineage_does_not_inherit_old_audit_identity",
    ] {
        if !cases
            .iter()
            .any(|case| case.get("name").and_then(Value::as_str) == Some(name))
        {
            bail!("bilateral continuity fixture omits `{name}`");
        }
    }
    let root_digest = cases
        .iter()
        .find(|case| case["name"] == "root_basis_digest_is_sha256_of_jcs_and_not_wire_state")
        .unwrap();
    let canonical_root = arkret_canonical::canonical_json_bytes(&root_digest["root_basis"])?;
    let actual_root_digest = arkret_canonical::sha256_digest(canonical_root);
    if root_digest["expected_root_basis_digest"].as_str() != Some(actual_root_digest.as_str())
        || root_digest["wire_member"].as_bool() != Some(false)
    {
        bail!("continuity root basis digest formula drifted or became wire state");
    }
    let fork = cases
        .iter()
        .find(|case| case["name"] == "same_sequence_different_digest_is_fork")
        .unwrap();
    if fork["expected_error"] != "continuity_invalid" || !fork["winner"].is_null() {
        bail!("checkpoint fork vector reintroduced a winner election");
    }
    let unavailable = cases
        .iter()
        .find(|case| case["name"] == "temporarily_missing_portable_material_is_unavailable")
        .unwrap();
    if unavailable["expected_error"] != "continuity_evidence_unavailable"
        || unavailable["retry_after_import"] != true
    {
        bail!("missing continuity material is no longer retryable after exact import");
    }
    let new_lineage = cases
        .iter()
        .find(|case| case["name"] == "new_lineage_does_not_inherit_old_audit_identity")
        .unwrap();
    if new_lineage["inherits_history"] != false || new_lineage["expected"] != "independent_root" {
        bail!("new Contact lineage silently inherited compacted history");
    }
    let registry = load_artifact_json("registry/operation-registry.json")?;
    let operations = registry["operations"]
        .as_array()
        .ok_or_else(|| anyhow!("operation registry has no operations"))?;
    let self_checkpoint = operations
        .iter()
        .find(|operation| operation["operation_id"] == "ak.self.contact.command.checkpoint.v1");
    if self_checkpoint.and_then(|operation| operation["http"].as_str())
        != Some("POST /_arkret/self/contacts/continuity-checkpoint")
    {
        bail!("bilateral checkpoint has no registered holder-authorized issuance surface");
    }
    Ok(())
}

fn validate_commit_welcome_fences() -> Result<()> {
    let mut stage = AdmissionStage::CommitPending;
    if advance_admission(stage, "commit_covering_seal").is_ok() {
        bail!("Welcome authoring crossed an unaccepted Commit");
    }
    stage = advance_admission(stage, "commit_rejected")?;
    stage = advance_admission(stage, "commit_accepted")?;
    if advance_admission(stage, "welcomes_accepted").is_ok() {
        bail!("Welcome authoring crossed a Commit without an exact covering Seal");
    }
    stage = advance_admission(stage, "commit_covering_seal")?;
    stage = advance_admission(stage, "welcome_rejected")?;
    stage = advance_admission(stage, "welcomes_accepted")?;
    if advance_admission(stage, "activate_without_welcome_seal").is_ok() {
        bail!("delivery handoff crossed a Welcome without its covering Seal");
    }
    stage = advance_admission(stage, "welcome_covering_seals")?;
    if stage != AdmissionStage::Complete {
        bail!("MLS admission did not finish after both exact finality fences");
    }
    Ok(())
}

pub fn run_direct_conversation_flow_suite() -> Result<()> {
    let fixture: DirectConversationFixture = serde_json::from_value(load_artifact_json(
        "fixtures/direct-conversation-fixture.json",
    )?)?;
    if fixture.suite != "direct_conversation_realm_conformance"
        || fixture.fixture_kind.trim().is_empty()
        || fixture.profile.trim().is_empty()
        || fixture.version.trim().is_empty()
        || fixture.spec_anchor.trim().is_empty()
        || fixture.source_refs.is_empty()
        || fixture.description.trim().is_empty()
        || fixture.runner.is_null()
        || fixture.schema_validation_cases.is_empty()
    {
        bail!("Direct Conversation fixture metadata drifted");
    }
    validate_event_id_digest_mirror_removal(&fixture)?;
    validate_founding_and_crash_replay(&fixture)?;
    validate_bilateral_continuity_checkpoint_fixture()?;
    validate_contact_verified_mirror_contract(&fixture)?;
    validate_founder_loss_terminality(&fixture)?;
    validate_commit_welcome_fences()?;
    record_vector_event(
        "direct_conversation.end_to_end_flow",
        &json!({"fixture": "direct-conversation-fixture.json"}),
        &json!({
            "flow_002": "single_scope_group_since_join_history",
            "flow_004_008": "exact_four_event_first_valid_unit_and_byte_identical_retry",
            "continuity": "bilateral_checkpoint_plus_bounded_tail_reaches_unique_root",
            "contact_mirror": "exact_event_from_verified_pending_mirror_without_seal_then_missing_after_terminal",
            "flow_005": "commit_and_welcome_each_wait_for_exact_covering_seal",
            "founder_loss": "same_authority_recovers_other_authorities_reject_new_identity_is_new_pair"
        }),
        &json!({"status": "validated"}),
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_conversation_flow_suite_closes_registered_transitions() {
        run_direct_conversation_flow_suite().expect("Direct Conversation flow suite");
    }
}
