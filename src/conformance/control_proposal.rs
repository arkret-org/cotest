use anyhow::{Context, Result, anyhow, bail, ensure};
use arkret_wire::notary::NotaryValue;
use arkret_wire::{
    ControlProposalAck, ControlProposalDecision, ControlProposalDecisionPolicy,
    ControlProposalDeferReason, DidUrl, Hash, PayloadSignature,
};
use chrono::{DateTime, Utc};
use serde_json::Value;

use super::load_fixture_value;

pub fn run_control_proposal_bounded_decision_suite() -> Result<()> {
    let fixture = load_fixture_value("seal-submit-fixture.json")?;
    let cases = fixture
        .get("schema_validation_cases")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("seal-submit fixture has no schema_validation_cases[]"))?;
    let case = |name: &str| {
        cases
            .iter()
            .find(|case| case.get("name").and_then(Value::as_str) == Some(name))
            .ok_or_else(|| anyhow!("seal-submit fixture is missing {name}"))
    };

    let ack = case("control_proposal_ack_commits_initial_and_absolute_deadlines")?;
    let ack_instance = &ack["instance"];
    let received_at = timestamp(ack_instance, "received_at")?;
    let decision_due_at = timestamp(ack_instance, "decision_due_at")?;
    let absolute_due_at = timestamp(ack_instance, "absolute_due_at")?;
    if decision_due_at - received_at != chrono::Duration::seconds(30)
        || absolute_due_at - received_at != chrono::Duration::seconds(90)
        || ack_instance["defer_count"].as_u64() != Some(0)
    {
        bail!("Control Proposal Ack does not pin the 30s initial / 90s absolute window");
    }

    let second = &case("second_defer_at_immutable_absolute_deadline")?["instance"];
    if second["kind"].as_str() != Some("signed_defer")
        || second["defer_count"].as_u64() != Some(2)
        || timestamp(second, "decision_due_at")? != absolute_due_at
        || timestamp(second, "absolute_due_at")? != absolute_due_at
    {
        bail!("second defer must end exactly at the immutable absolute deadline");
    }

    let third = case("third_defer_is_schema_rejected")?;
    if third["expect_valid"].as_bool() != Some(false)
        || third["instance"]["defer_count"].as_u64() != Some(3)
    {
        bail!("third defer must be a schema rejection at defer_count=3");
    }

    let late = case("late_valid_seal_remains_accepted_and_fault_is_retained")?;
    let late_instance = &late["instance"];
    if late["semantic_outcome"].as_str() != Some("accept")
        || late["receiver_state"]["seal_acceptance"].as_str() != Some("accepted")
        || late["receiver_state"]["governance_fault_retained"].as_bool() != Some(true)
        || late_instance["kind"].as_str() != Some("signed_defer")
        || timestamp(late_instance, "decided_at")? <= decision_due_at
        || timestamp(late_instance, "absolute_due_at")? != absolute_due_at
    {
        bail!("late decision vector must retain the fault while accepting the later valid Seal");
    }
    Ok(())
}

pub fn run_control_proposal_ack_suite() -> Result<()> {
    let fixture = load_fixture_value("control-proposal-ack-fixture.json")?;
    let cases = fixture["cases"]
        .as_array()
        .context("Control Proposal Ack cases missing")?;
    let policy = ControlProposalDecisionPolicy {
        proposal_intake_sla: chrono::Duration::seconds(60),
        decision_window: chrono::Duration::seconds(30),
        absolute_horizon: chrono::Duration::seconds(90),
        max_defers: 2,
    };
    for case in cases {
        let name = case["name"].as_str().context("Ack case name missing")?;
        if let Some(configuration) = case.get("realm_configuration") {
            let candidate = ControlProposalDecisionPolicy {
                decision_window: chrono::Duration::milliseconds(
                    configuration["proposal_decision_window_ms"]
                        .as_i64()
                        .context("decision window missing")?,
                ),
                absolute_horizon: chrono::Duration::milliseconds(
                    configuration["proposal_absolute_deadline_ms"]
                        .as_i64()
                        .context("absolute window missing")?,
                ),
                max_defers: u8::try_from(
                    configuration["max_proposal_defers"]
                        .as_u64()
                        .context("max defers missing")?,
                )?,
                ..policy
            };
            ensure!(
                candidate.validate().is_ok()
                    == (case["expected"]["decision"].as_str() == Some("accept")),
                "{name}: policy verdict differs"
            );
        } else {
            ensure!(
                serde_json::from_value::<ControlProposalAck>(case["instance"].clone()).is_ok()
                    == case["expect_valid"]
                        .as_bool()
                        .context("Ack verdict missing")?,
                "{name}: closed Ack shape differs"
            );
        }
    }
    let valid = cases
        .iter()
        .find(|case| case["name"] == "sole_authority_ack_valid")
        .context("sole authority Ack vector missing")?;
    let mut ack: ControlProposalAck = serde_json::from_value(valid["instance"].clone())?;
    ack.signature.payload_digest = ack.ack_body_digest()?;
    ack.validate_structural(policy)?;
    let method = &ack.signature.verification_method;
    let did = arkret_wire::Did::new(
        method
            .as_str()
            .split_once('#')
            .context("Ack method missing fragment")?
            .0,
    )?;
    let notary = NotaryValue::new(
        crate::fixture_notary_signer_for_method(
            arkret_wire::project_did_to_core_id(&did)?,
            method.clone(),
        ),
        0,
    )?;
    ack.validate_notary_authority(&notary)?;
    let mut substituted = ack.clone();
    substituted.signature.verification_method =
        DidUrl::new("did:web:other.example#notary").map_err(anyhow::Error::msg)?;
    ensure!(
        substituted.validate_notary_authority(&notary).is_err(),
        "an unrelated Station supplied the sole Ack"
    );
    ensure!(
        ControlProposalDecisionPolicy {
            proposal_intake_sla: chrono::Duration::hours(24),
            ..policy
        }
        .validate()
        .is_ok(),
        "inclusive intake maximum rejected"
    );
    ensure!(
        ControlProposalDecisionPolicy {
            proposal_intake_sla: chrono::Duration::milliseconds(86_400_001),
            ..policy
        }
        .validate()
        .is_err(),
        "intake above maximum accepted"
    );

    let mut decision = ControlProposalDecision::SignedDefer {
        realm_id: ack.realm_id.clone(),
        proposal_digest: ack.proposal_digest.clone(),
        proposal_ack_digest: hash('0'),
        decided_at: ack.received_at + chrono::Duration::seconds(1),
        decision_due_at: ack.decision_due_at + chrono::Duration::seconds(1),
        absolute_due_at: ack.absolute_due_at,
        defer_count: 1,
        reason_code: ControlProposalDeferReason::TemporarilyUnavailable,
        authority_set_ref: ack.authority_set_ref.clone(),
        proof: PayloadSignature {
            verification_method: ack.signature.verification_method.clone(),
            payload_digest: hash('0'),
            created_at: ack.received_at + chrono::Duration::seconds(1),
            jws: "a..b".to_owned(),
        },
    };
    let digest = decision.decision_digest()?;
    let ControlProposalDecision::SignedDefer { proof, .. } = &mut decision;
    proof.payload_digest = digest;
    ensure!(
        decision
            .validate_chain_for_notary(&ack, &[], policy, &notary)
            .is_err(),
        "defer crossed exact Ack binding"
    );
    let ControlProposalDecision::SignedDefer {
        proposal_ack_digest,
        ..
    } = &mut decision;
    *proposal_ack_digest = ack.proposal_ack_digest()?;
    let digest = decision.decision_digest()?;
    let ControlProposalDecision::SignedDefer { proof, .. } = &mut decision;
    proof.payload_digest = digest;
    decision.validate_chain_for_notary(&ack, &[], policy, &notary)?;
    Ok(())
}

fn hash(byte: char) -> Hash {
    Hash::new(format!("sha256:{}", byte.to_string().repeat(64))).unwrap()
}

fn timestamp(value: &Value, field: &str) -> Result<DateTime<Utc>> {
    value[field]
        .as_str()
        .ok_or_else(|| anyhow!("{field} is missing"))?
        .parse()
        .map_err(|error| anyhow!("{field} is not an RFC3339 timestamp: {error}"))
}
