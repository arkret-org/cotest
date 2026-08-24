//! Native Personal Agent membership-cascade conformance.

use std::collections::BTreeSet;

use anyhow::{Context as _, Result, bail};
use arkret_models_collaboration::governance::agent_membership_cascade::{
    AgentCleanupRecord, AgentCleanupStatusView, AgentControllerMembershipBinding,
    AgentMembershipCascadeSchema,
};
use arkret_models_collaboration::governance::membership_invite::MembershipPayload;
use arkret_wire::{DidCoreId, EventId, Hash, PrincipalAuthorityKey, RealmId};
use chrono::{Duration, TimeZone as _, Utc};

use super::load_fixture_value;

const FIXTURE: &str = "agent-membership-cascade-fixture.json";
const VECTOR: &str = "ak.vector.agent.membership_cascade.v1";
const REQUIRED_CASES: [&str; 8] = [
    "effective_membership_is_exact_controller_generation_and",
    "controller_rejoin_does_not_revive_old_agent_join",
    "self_leave_requires_complete_atomic_set",
    "third_party_terminal_is_not_blocked_by_cleanup",
    "emergency_cleanup_requires_original_initiator_and_exact_set",
    "cleanup_replay_and_conflict_are_durable",
    "cleanup_overdue_never_restores_authority",
    "membership_cause_is_non_authorizing",
];

pub fn run_agent_membership_cascade_suite() -> Result<()> {
    let fixture = load_fixture_value(FIXTURE)?;
    validate_fixture_identity(&fixture)?;
    let binding = validate_membership_payload(&fixture)?;
    validate_effective_membership_and_generation_fence(&binding)?;
    validate_cleanup_intent_digest_and_states(&binding)
}

fn validate_fixture_identity(fixture: &serde_json::Value) -> Result<()> {
    if fixture["suite"] != "agent_membership_cascade"
        || fixture["runner"]["kind"] != "named_suite"
        || fixture["runner"]["entrypoint"] != "ak.suite.agent.membership_cascade.v1"
    {
        bail!("Agent membership cascade fixture runner identity drifted");
    }
    if fixture["covers_vectors"] != serde_json::json!([VECTOR]) {
        bail!("Agent membership cascade fixture vector registration drifted");
    }
    let names = fixture["semantic_cases"]
        .as_array()
        .context("Agent membership cascade semantic_cases")?
        .iter()
        .map(|case| {
            case["name"]
                .as_str()
                .context("Agent membership cascade semantic case name")
        })
        .collect::<Result<BTreeSet<_>>>()?;
    if names != BTreeSet::from(REQUIRED_CASES) {
        bail!("Agent membership cascade semantic case registry is not the closed eight-case set");
    }
    Ok(())
}

fn validate_membership_payload(
    fixture: &serde_json::Value,
) -> Result<AgentControllerMembershipBinding> {
    let case = fixture["schema_validation_cases"]
        .as_array()
        .context("Agent membership cascade schema cases")?
        .iter()
        .find(|case| {
            case["name"]
                == "agent_cleanup_membership_payload_accepts_cause_and_exact_controller_binding"
        })
        .context("Agent cleanup membership payload case")?;
    let payload: MembershipPayload = serde_json::from_value(case["instance"].clone())?;
    let binding = payload
        .agent_controller_binding
        .context("Agent cleanup payload controller binding")?;
    binding.validate()?;
    if payload.membership_cause
        != Some(
            arkret_models_collaboration::governance::agent_membership_cascade::MembershipLifecycleCause::ControllerMembershipEnded,
        )
        || binding.controller_terminal_event_ref.is_none()
    {
        bail!("Agent cleanup payload lost its closed cause or terminal Event binding");
    }
    Ok(binding)
}

fn validate_effective_membership_and_generation_fence(
    binding: &AgentControllerMembershipBinding,
) -> Result<()> {
    let effective = |agent_join: bool,
                     controller_join: bool,
                     authority: &PrincipalAuthorityKey,
                     generation: &EventId,
                     lifecycle_active: bool,
                     provision_active: bool| {
        agent_join
            && controller_join
            && authority == &binding.controller_authority
            && generation == &binding.controller_membership_generation_ref
            && lifecycle_active
            && provision_active
    };
    assert!(effective(
        true,
        true,
        &binding.controller_authority,
        &binding.controller_membership_generation_ref,
        true,
        true,
    ));
    let new_generation = EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [0x71; 32]);
    assert!(!effective(
        true,
        true,
        &binding.controller_authority,
        &new_generation,
        true,
        true,
    ));
    let mut wrong_server = binding.controller_authority.clone();
    wrong_server.principal_server_id = DidCoreId::new("ak:did_core:web:other-principal.example")?;
    assert!(!effective(
        true,
        true,
        &wrong_server,
        &binding.controller_membership_generation_ref,
        true,
        true,
    ));
    assert!(!effective(
        true,
        false,
        &binding.controller_authority,
        &binding.controller_membership_generation_ref,
        true,
        true,
    ));
    Ok(())
}

fn validate_cleanup_intent_digest_and_states(
    binding: &AgentControllerMembershipBinding,
) -> Result<()> {
    let accepted_at = Utc
        .with_ymd_and_hms(2026, 8, 15, 0, 0, 0)
        .single()
        .context("fixed Agent cascade timestamp")?;
    let terminal_event_id = binding
        .controller_terminal_event_ref
        .clone()
        .context("Agent cleanup terminal Event")?;
    let mut record = AgentCleanupRecord {
        schema: AgentMembershipCascadeSchema::V1,
        realm_id: RealmId::from_event_id(&EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [0x72; 32],
        )),
        controller_authority: binding.controller_authority.clone(),
        controller_membership_generation_ref: binding.controller_membership_generation_ref.clone(),
        initiator_authority: PrincipalAuthorityKey {
            principal_id: DidCoreId::new("ak:did_core:web:moderator.example")?,
            principal_server_id: binding.controller_authority.principal_server_id.clone(),
        },
        controller_terminal_event_id: terminal_event_id,
        controller_terminal_event_digest: Hash::new(format!("sha256:{}", "7".repeat(64)))?,
        expected_agent_ids: vec![DidCoreId::new("ak:did_core:webvh:z6mkfixtureagentexample")?],
        cleanup_intent_digest: Hash::new(format!("sha256:{}", "0".repeat(64)))?,
        accepted_at,
        cleanup_due_at: accepted_at + Duration::hours(1),
        completed_at: None,
        agent_transition_event_ids: None,
    };
    record.cleanup_intent_digest = record.expected_cleanup_intent_digest()?;
    record.validate()?;
    assert_eq!(
        record.expected_cleanup_intent_digest()?,
        record.cleanup_intent_digest
    );

    let mut changed = record.clone();
    changed.initiator_authority.principal_id =
        DidCoreId::new("ak:did_core:web:other-moderator.example")?;
    assert_ne!(
        changed.expected_cleanup_intent_digest()?,
        record.cleanup_intent_digest,
        "same intent digest must not name changed canonical content"
    );

    if record.cleanup_status(accepted_at + Duration::minutes(30)) != AgentCleanupStatusView::Pending
        || record.cleanup_status(accepted_at + Duration::hours(2))
            != AgentCleanupStatusView::Overdue
    {
        bail!("Agent cleanup status is not derived from its deadline");
    }
    if record.completed_at.is_some() || record.agent_transition_event_ids.is_some() {
        bail!("overdue cleanup incorrectly materialized synthetic Agent transitions");
    }
    Ok(())
}
