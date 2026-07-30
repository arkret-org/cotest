use std::collections::BTreeMap;

use anyhow::{Context, Result, anyhow, bail, ensure};
use arkret_wire::notary::{ForensicAttribution, NotaryValue};
use arkret_wire::{
    ControlProposalDecision, ControlProposalDecisionPolicy, ControlProposalReceipt,
    ControlProposalRejectReason, Hash, PayloadSignature, ProposalMemberReceipt, RealmId,
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

    let receipt = case("proposal_receipt_commits_initial_and_absolute_deadlines")?;
    let receipt_instance = &receipt["instance"];
    let received_at = timestamp(receipt_instance, "received_at")?;
    let decision_due_at = timestamp(receipt_instance, "decision_due_at")?;
    let absolute_due_at = timestamp(receipt_instance, "absolute_due_at")?;
    if decision_due_at - received_at != chrono::Duration::seconds(30)
        || absolute_due_at - received_at != chrono::Duration::seconds(90)
        || receipt_instance["defer_count"].as_u64() != Some(0)
    {
        bail!("proposal receipt does not pin the 30s initial / 90s absolute window");
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
        bail!(
            "late decision vector must retain the fault while accepting the later valid Seal, without a terminal signed-reject contradiction"
        );
    }
    Ok(())
}

pub fn run_control_proposal_receipt_suite() -> Result<()> {
    let fixture = load_fixture_value("control-proposal-receipt-fixture.json")?;
    ensure!(
        fixture.get("suite").and_then(Value::as_str) == Some("control_proposal_receipt")
            && fixture
                .pointer("/runner/entrypoint")
                .and_then(Value::as_str)
                == Some("ak.suite.cba.control_proposal_receipt.v1"),
        "control proposal receipt fixture metadata changed"
    );
    let cases = fixture
        .get("cases")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("control proposal receipt fixture has no cases[]"))?;
    let mut cases_by_name = BTreeMap::new();
    for value in cases {
        let name = value
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("control proposal receipt case is missing name"))?;
        ensure!(
            cases_by_name.insert(name, value).is_none(),
            "control proposal receipt fixture contains duplicate case {name}"
        );
    }
    let case = |name: &str| {
        cases_by_name
            .get(name)
            .copied()
            .ok_or_else(|| anyhow!("control proposal receipt fixture is missing {name}"))
    };

    let threshold_case = case("threshold_receipt_set_uses_distinct_current_members")?;
    let receipt_members = threshold_case["member_receipts"]
        .as_array()
        .ok_or_else(|| anyhow!("threshold member_receipts must be an array"))?;
    let authority_ref = hash('a');
    let members = receipt_members
        .iter()
        .map(|member| member_from_fixture(member, authority_ref.clone()))
        .collect::<Result<Vec<_>>>()?;
    let authority_members = members
        .iter()
        .map(|member| {
            let controller = member
                .signature
                .verification_method
                .rsplit_once('#')
                .map(|(controller, _)| controller)
                .ok_or_else(|| anyhow!("member verification method is not a DID URL"))?;
            arkret_wire::Did::new(controller).map_err(anyhow::Error::msg)
        })
        .collect::<Result<Vec<_>>>()?;
    let notary = NotaryValue::Threshold {
        threshold: threshold_case["threshold"]
            .as_u64()
            .and_then(|value| u32::try_from(value).ok())
            .ok_or_else(|| anyhow!("threshold is invalid"))?,
        members: authority_members,
        forensic_attribution: ForensicAttribution::QuorumIntersection,
    };
    let policy = ControlProposalDecisionPolicy {
        receipt_sla: chrono::Duration::seconds(60),
        decision_window: chrono::Duration::seconds(30),
        absolute_horizon: chrono::Duration::seconds(90),
        max_defers: 2,
    };
    let receipt =
        ControlProposalReceipt::from_member_receipts_for_notary(members, policy, &notary)?;
    ensure!(
        receipt.received_at == timestamp(&threshold_case["expected"], "received_at")?
            && receipt.decision_due_at
                == timestamp(&threshold_case["expected"], "decision_due_at")?
            && receipt.absolute_due_at
                == timestamp(&threshold_case["expected"], "absolute_due_at")?,
        "threshold receipt aggregate window diverged"
    );
    let actual_order = receipt
        .member_receipts
        .iter()
        .map(|member| member.signature.verification_method.as_str())
        .collect::<Vec<_>>();
    let expected_order = threshold_case["expected"]["member_order"]
        .as_array()
        .ok_or_else(|| anyhow!("expected member order must be an array"))?
        .iter()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>();
    ensure!(
        actual_order == expected_order,
        "member order is not canonical"
    );

    let duplicate = case("duplicate_member_does_not_count_twice")?;
    let duplicate_methods = duplicate["member_verification_methods"]
        .as_array()
        .ok_or_else(|| anyhow!("duplicate methods must be an array"))?;
    let duplicate_members = duplicate_methods
        .iter()
        .map(|method| {
            member(
                method
                    .as_str()
                    .ok_or_else(|| anyhow!("duplicate method must be text"))?,
                "2026-07-29T00:00:00.000Z",
                "2026-07-29T00:00:30.000Z",
                "2026-07-29T00:01:30.000Z",
                authority_ref.clone(),
            )
        })
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        ControlProposalReceipt::from_member_receipts_for_notary(
            duplicate_members,
            policy,
            &notary,
        )
        .is_err(),
        "duplicate member counted twice"
    );

    let mixed = case("mixed_authority_set_and_out_of_window_rejected")?;
    let refs = mixed["member_authority_set_refs"]
        .as_array()
        .ok_or_else(|| anyhow!("mixed authority refs must be an array"))?;
    let mixed_members = vec![
        member(
            "did:webvh:z6mkfixture:authority-a.example#notary",
            "2026-07-29T00:00:00.000Z",
            "2026-07-29T00:00:30.000Z",
            "2026-07-29T00:01:30.000Z",
            Hash::new(refs[0].as_str().unwrap())?,
        )?,
        member(
            "did:webvh:z6mkfixture:authority-b.example#notary",
            "2026-07-29T00:01:00.001Z",
            "2026-07-29T00:01:30.001Z",
            "2026-07-29T00:02:30.001Z",
            Hash::new(refs[1].as_str().unwrap())?,
        )?,
    ];
    ensure!(
        ControlProposalReceipt::from_member_receipts(mixed_members, policy).is_err(),
        "mixed authority receipt set was accepted"
    );

    ensure!(
        ControlProposalDecisionPolicy {
            receipt_sla: chrono::Duration::hours(24),
            ..policy
        }
        .validate()
        .is_ok(),
        "inclusive receipt SLA maximum was rejected"
    );
    ensure!(
        ControlProposalDecisionPolicy {
            receipt_sla: chrono::Duration::milliseconds(86_400_001),
            ..policy
        }
        .validate()
        .is_err(),
        "receipt SLA above the wire maximum was accepted"
    );

    let replay = case("exact_member_retry_is_byte_identical_and_conflict_cannot_extend")?;
    let original = serde_json::to_vec(&receipt.member_receipts[0])?;
    let request = b"canonical-request".to_vec();
    let mut ledger = BTreeMap::from([("receipt-key", (request.clone(), original.clone()))]);
    let exact = ledger
        .get("receipt-key")
        .filter(|(stored_request, _)| stored_request == &request)
        .map(|(_, outcome)| outcome.clone())
        .context("exact retry missed its original member receipt")?;
    let conflict = ledger
        .get_mut("receipt-key")
        .is_some_and(|(stored_request, _)| stored_request != b"different-request");
    ensure!(
        exact == original
            && conflict
            && replay["expected"]["deadline_extended"].as_bool() == Some(false),
        "member receipt replay semantics diverged"
    );

    let decision_case = case("decision_proofs_cannot_cross_receipt_sets")?;
    let wrong_receipt_digest = Hash::new(
        decision_case["decision_proof_receipt_digests"][1]
            .as_str()
            .unwrap(),
    )?;
    let mut decision = ControlProposalDecision::SignedReject {
        realm_id: receipt.realm_id.clone(),
        proposal_digest: receipt.proposal_digest.clone(),
        receipt_digest: wrong_receipt_digest,
        decided_at: receipt.received_at,
        decision_due_at: receipt.decision_due_at,
        absolute_due_at: receipt.absolute_due_at,
        defer_count: 0,
        reason_code: ControlProposalRejectReason::PolicyDenied,
        authority_set_ref: receipt.authority_set_ref.clone(),
        proofs: vec![PayloadSignature {
            alg: "EdDSA".to_owned(),
            verification_method: "did:webvh:z6mkfixture:authority-a.example#notary".to_owned(),
            payload_digest: hash('0'),
            created_at: receipt.received_at,
            jws: "a..b".to_owned(),
        }],
    };
    let digest = decision.decision_digest()?;
    let ControlProposalDecision::SignedReject { proofs, .. } = &mut decision else {
        unreachable!()
    };
    proofs[0].payload_digest = digest;
    ensure!(
        decision.validate_chain(&receipt, &[], policy).is_err(),
        "decision proof crossed receipt sets"
    );

    for name in [
        "proposal_decision_window_after_absolute_deadline_rejected",
        "equal_proposal_windows_without_defers_accepted",
        "equal_proposal_windows_with_defers_rejected",
    ] {
        let vector = case(name)?;
        let configuration = &vector["realm_configuration"];
        let policy = ControlProposalDecisionPolicy {
            receipt_sla: chrono::Duration::hours(24),
            decision_window: chrono::Duration::milliseconds(
                configuration["proposal_decision_window_ms"]
                    .as_i64()
                    .ok_or_else(|| anyhow!("{name} decision window is missing"))?,
            ),
            absolute_horizon: chrono::Duration::milliseconds(
                configuration["proposal_absolute_deadline_ms"]
                    .as_i64()
                    .ok_or_else(|| anyhow!("{name} absolute deadline is missing"))?,
            ),
            max_defers: configuration["max_proposal_defers"]
                .as_u64()
                .and_then(|value| u8::try_from(value).ok())
                .ok_or_else(|| anyhow!("{name} max defers is invalid"))?,
        };
        let accepted = policy.validate().is_ok();
        let expected_accept = vector["expected"]["decision"].as_str() == Some("accept");
        ensure!(
            accepted == expected_accept,
            "{name} SDK policy verdict diverged from fixture"
        );
        if !expected_accept {
            ensure!(
                vector["expected"]["reason"].as_str() == Some("schema_violation")
                    && vector["expected"]["must_not_write_realm_state"].as_bool() == Some(true),
                "{name} no longer requires atomic schema rejection"
            );
        }
    }
    Ok(())
}

fn hash(byte: char) -> Hash {
    Hash::new(format!("sha256:{}", byte.to_string().repeat(64))).unwrap()
}

fn member_from_fixture(value: &Value, authority_set_ref: Hash) -> Result<ProposalMemberReceipt> {
    member(
        value["verification_method"]
            .as_str()
            .ok_or_else(|| anyhow!("verification_method is missing"))?,
        value["received_at"]
            .as_str()
            .ok_or_else(|| anyhow!("received_at is missing"))?,
        value["decision_due_at"]
            .as_str()
            .ok_or_else(|| anyhow!("decision_due_at is missing"))?,
        value["absolute_due_at"]
            .as_str()
            .ok_or_else(|| anyhow!("absolute_due_at is missing"))?,
        authority_set_ref,
    )
}

fn member(
    verification_method: &str,
    received_at: &str,
    decision_due_at: &str,
    absolute_due_at: &str,
    authority_set_ref: Hash,
) -> Result<ProposalMemberReceipt> {
    let received_at = received_at.parse()?;
    let mut member = ProposalMemberReceipt {
        realm_id: RealmId::new("ak:realm:01904100-0000-7000-8000-65c7feb295d7")?,
        proposal_digest: hash('c'),
        received_at,
        decision_due_at: decision_due_at.parse()?,
        absolute_due_at: absolute_due_at.parse()?,
        authority_set_ref,
        signature: PayloadSignature {
            alg: "EdDSA".to_owned(),
            verification_method: verification_method.to_owned(),
            payload_digest: hash('0'),
            created_at: received_at,
            jws: "a..b".to_owned(),
        },
    };
    member.signature.payload_digest = member.member_receipt_digest()?;
    Ok(member)
}

fn timestamp(value: &Value, field: &str) -> Result<DateTime<Utc>> {
    value[field]
        .as_str()
        .ok_or_else(|| anyhow!("{field} is missing"))?
        .parse()
        .map_err(|error| anyhow!("{field} is not an RFC3339 timestamp: {error}"))
}
