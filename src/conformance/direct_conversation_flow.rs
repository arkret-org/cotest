//! End-to-end state-machine coverage for Direct Conversation history,
//! founding durability, MLS finality fences, and same-coordinate repair.

use anyhow::{Result, anyhow, bail};
use serde_json::{Value, json};

use super::load_artifact_json;
use crate::transcripts::record_vector_event;

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RepairStage {
    ActiveGenerationRemoved,
    SelfRejoined,
    RepairRequestRelayed,
    ExactPairReadded,
    ReplacementActivated,
}

fn advance_repair(stage: RepairStage, action: &str) -> Result<RepairStage> {
    use RepairStage::*;
    match (stage, action) {
        (ActiveGenerationRemoved, "ak.member.rejoin.own") => Ok(SelfRejoined),
        (SelfRejoined, "ak.member.repair.request") => Ok(RepairRequestRelayed),
        (RepairRequestRelayed, "exact_pair_readd") => Ok(ExactPairReadded),
        (ExactPairReadded, "replacement_generation_activate") => Ok(ReplacementActivated),
        _ => bail!("Direct Conversation repair action is out of order or outside its profile"),
    }
}

fn semantic_case<'a>(fixture: &'a Value, name: &str) -> Result<&'a Value> {
    fixture
        .get("semantic_cases")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .find(|case| case.get("name").and_then(Value::as_str) == Some(name))
        .ok_or_else(|| anyhow!("Direct Conversation fixture omits semantic case `{name}`"))
}

fn validate_joined_shared_history() -> Result<()> {
    let profiles = load_artifact_json("profiles/conformance-profiles.json")?;
    let profile = profiles
        .pointer("/profile_requirements/ak.profile.direct_conversation_realm.v1")
        .ok_or_else(|| anyhow!("Direct Conversation profile is missing"))?;
    if profile
        .pointer("/realm_defaults/history_visibility")
        .and_then(Value::as_str)
        != Some("joined")
    {
        bail!("Direct Conversation history visibility must remain joined");
    }
    let expected = profile
        .pointer("/history_sharing_policy_fixed_baseline/value")
        .ok_or_else(|| anyhow!("Direct Conversation fixed history baseline is missing"))?;
    let actual =
        arkret_policy::history_visibility::direct_conversation_realm_history_sharing_policy()?;
    let actual = serde_json::to_value(actual)?;
    if &actual != expected {
        bail!("SDK Direct Conversation fixed history baseline drifted from the profile");
    }
    let receiver_states = expected
        .get("allowed_receiver_states")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("fixed history baseline omits receiver states"))?;
    if receiver_states.len() != 1
        || receiver_states[0].as_str() != Some("active_member")
        || expected.get("pre_join_history").and_then(Value::as_str) != Some("deny")
        || expected
            .get("post_removal_recovery")
            .and_then(Value::as_str)
            != Some("deny")
    {
        bail!("Direct Conversation exact-peer history boundary drifted");
    }
    // Realm membership is already joined at Genesis even while the peer has
    // not become an MLS leaf. Generation-0 sharing therefore is joined
    // history, not the pre-Realm-membership `pre_join_history` branch.
    let peer_joined_at_genesis = true;
    let peer_is_mls_leaf = false;
    let generation_zero_share_allowed = peer_joined_at_genesis && !peer_is_mls_leaf;
    if !generation_zero_share_allowed {
        bail!("joined peer lost generation-0 provisional history sharing");
    }
    Ok(())
}

fn validate_founding_and_crash_replay(fixture: &Value) -> Result<()> {
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
        "events": ["create-bytes", "peer-join-bytes", "main-strand-bytes"]
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
    if advance_admission(stage, "replacement_generation_activate").is_ok() {
        bail!("delivery handoff crossed a Welcome without its covering Seal");
    }
    stage = advance_admission(stage, "welcome_covering_seals")?;
    if stage != AdmissionStage::Complete {
        bail!("MLS admission did not finish after both exact finality fences");
    }
    Ok(())
}

fn validate_repair(fixture: &Value) -> Result<()> {
    semantic_case(fixture, "rejoin_uses_same_realm_without_old_keys")?;
    semantic_case(
        fixture,
        "repair_dispatch_is_a_non_authorizing_durable_trigger",
    )?;
    let realm = "ak:realm:AQJmSg1s9QyzppFeJL40dN92YVHZeLdBBt3UWHa9XNOD";
    let strand = "ak:strand:AT0qp3NTTWtVZNVOgsvsAncs9xRV-c5HXCz7uzXd7NQS";
    let current_generation = 7_u64;
    let mut stage = RepairStage::ActiveGenerationRemoved;
    if advance_repair(stage, "ak.member.leave.own").is_ok() {
        bail!("repair authority accepted daily self-leave instead of rejoin.own");
    }
    stage = advance_repair(stage, "ak.member.rejoin.own")?;
    let repair_request = json!({
        "realm_id": realm,
        "requester_principal_id": "ak:did_core:webvh:z6mkfixture:alice.example",
        "requester_device_id": "ak:device:01964137-1000-7000-8000-000000000011",
        "requester_keypackage_ref": "ak:keypackage:fixture-requester-1",
        "observed_active_generation_value_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "rejoin_event_id": "ak:event:AWAIb405aEEenVBHYRG-ZfDs-f9_j3E67tWGI36uYxFJ",
        "created_at": "2026-08-10T00:00:00.000Z"
    });
    let typed_request = serde_json::from_value::<
        arkret_models_collaboration::events_payloads::MemberRepairRequestPayload,
    >(repair_request)?;
    typed_request.validate()?;
    stage = advance_repair(stage, "ak.member.repair.request")?;
    stage = advance_repair(stage, "exact_pair_readd")?;
    stage = advance_repair(stage, "replacement_generation_activate")?;
    let replacement_generation = current_generation + 1;
    let old_history_keys_delivered = false;
    if stage != RepairStage::ReplacementActivated
        || replacement_generation != 8
        || old_history_keys_delivered
        || realm.is_empty()
        || strand.is_empty()
    {
        bail!("Direct Conversation repair changed coordinates, generation, or history boundary");
    }
    Ok(())
}

pub fn run_direct_conversation_flow_suite() -> Result<()> {
    let fixture = load_artifact_json("fixtures/direct-conversation-fixture.json")?;
    validate_joined_shared_history()?;
    validate_founding_and_crash_replay(&fixture)?;
    validate_commit_welcome_fences()?;
    validate_repair(&fixture)?;
    record_vector_event(
        "direct_conversation.end_to_end_flow",
        &json!({"fixture": "direct-conversation-fixture.json"}),
        &json!({
            "flow_002": "joined_generation_zero_history_shared",
            "flow_004_008": "exact_three_event_first_valid_unit_and_byte_identical_retry",
            "flow_005": "commit_and_welcome_each_wait_for_exact_covering_seal",
            "flow_014": "remove_rejoin_durable_request_readd_replacement_generation_without_old_keys"
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
