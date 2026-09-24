//! Direct Conversation continuity and MLS finality fences.
//!
//! The formal `direct-conversation-fixture.json` was retired upstream; its
//! founding, crash-replay, founder-loss and Contact prepare vectors are
//! registry-only now and have no machine fixture to execute. What remains
//! executable here is the bilateral continuity checkpoint fixture and the
//! Commit/Welcome covering-Seal fence ordering.

use anyhow::{Result, anyhow, bail};
use serde_json::{Value, json};

use super::load_artifact_json;
use crate::transcripts::record_vector_event;

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
        "same_exact_pair_cannot_restart_root_when_tail_is_full",
        "different_exact_pair_explicit_first_contact_has_independent_root",
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
    let same_pair = cases
        .iter()
        .find(|case| case["name"] == "same_exact_pair_cannot_restart_root_when_tail_is_full")
        .unwrap();
    if same_pair["same_trust_domain"] != true
        || same_pair["same_actor_pair"] != true
        || same_pair["expected_error"] != "continuity_evidence_unavailable"
        || same_pair["may_restart_root"] != false
    {
        bail!("the same exact Contact pair may not reset a blocked lineage");
    }
    let new_pair = cases
        .iter()
        .find(|case| {
            case["name"] == "different_exact_pair_explicit_first_contact_has_independent_root"
        })
        .unwrap();
    if new_pair["same_actor_pair"] != false
        || new_pair["explicit_user_action"] != true
        || new_pair["inherits_history"] != false
        || new_pair["inherits_direct_conversation"] != false
        || new_pair["inherits_mls_state"] != false
        || new_pair["expected"] != "independent_root"
    {
        bail!(
            "new Contact pair must be explicitly initiated without inherited history, DM or MLS state"
        );
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
    validate_bilateral_continuity_checkpoint_fixture()?;
    validate_commit_welcome_fences()?;
    record_vector_event(
        "direct_conversation.end_to_end_flow",
        &json!({"fixture": "bilateral-continuity-checkpoint-fixture.json"}),
        &json!({
            "continuity": "bilateral_checkpoint_plus_bounded_tail_reaches_unique_root",
            "flow_005": "commit_and_welcome_each_wait_for_exact_covering_seal"
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
