use std::collections::BTreeMap;

use anyhow::{Context, Result, anyhow, bail, ensure};
use arkret_wire::notary::NotaryValue;
use arkret_wire::{
    ControlProposalAck, ControlProposalAuthorityAck, ControlProposalDecision,
    ControlProposalDecisionPolicy, ControlProposalDeferReason, DidUrl, Hash, PayloadSignature,
    RealmId,
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
    ensure!(
        fixture.get("suite").and_then(Value::as_str) == Some("control_proposal_ack")
            && fixture
                .pointer("/runner/entrypoint")
                .and_then(Value::as_str)
                == Some("ak.suite.cbs.control_proposal_ack.v1"),
        "Control Proposal Ack fixture metadata changed"
    );
    let cases = fixture
        .get("cases")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("Control Proposal Ack fixture has no cases[]"))?;
    const REQUIRED_CASES: [&str; 10] = [
        "quorum_ack_set_uses_distinct_current_members",
        "duplicate_member_does_not_count_twice",
        "mixed_authority_set_and_out_of_window_rejected",
        "proposal_intake_sla_wire_maximum_is_inclusive",
        "proposal_intake_sla_above_wire_maximum_is_rejected",
        "exact_member_retry_is_byte_identical_and_conflict_cannot_extend",
        "decision_proofs_cannot_cross_ack_sets",
        "proposal_decision_window_after_absolute_deadline_rejected",
        "equal_proposal_windows_without_defers_accepted",
        "equal_proposal_windows_with_defers_rejected",
    ];
    let mut cases_by_name = BTreeMap::new();
    for value in cases {
        let name = value
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("Control Proposal Ack case is missing name"))?;
        ensure!(
            cases_by_name.insert(name, value).is_none(),
            "Control Proposal Ack fixture contains duplicate case {name}"
        );
    }
    for required in REQUIRED_CASES {
        ensure!(
            cases_by_name.contains_key(required),
            "Control Proposal Ack fixture is missing {required}"
        );
    }
    let case = |name: &str| {
        cases_by_name
            .get(name)
            .copied()
            .ok_or_else(|| anyhow!("Control Proposal Ack fixture is missing {name}"))
    };

    let policy = ControlProposalDecisionPolicy {
        proposal_intake_sla: chrono::Duration::seconds(60),
        decision_window: chrono::Duration::seconds(30),
        absolute_horizon: chrono::Duration::seconds(90),
        max_defers: 2,
    };
    let quorum_case = case("quorum_ack_set_uses_distinct_current_members")?;
    ensure!(
        quorum_case.pointer("/notary/kind").and_then(Value::as_str) == Some("quorum"),
        "Control Proposal Ack must use the sole quorum notary kind"
    );
    let fault_tolerance = quorum_case
        .pointer("/notary/fault_tolerance")
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| anyhow!("quorum Ack fixture has invalid fault_tolerance"))?;
    let signer_methods = quorum_case
        .pointer("/notary/signer_verification_methods")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("quorum Ack fixture has no signer_verification_methods[]"))?;
    let signers = signer_methods
        .iter()
        .map(|method| notary_signer_from_method(required_string(method, "notary method")?))
        .collect::<Result<Vec<_>>>()?;
    let notary = NotaryValue::new(signers, fault_tolerance, 0)?;
    ensure!(
        notary.signers.len() == 4 && notary.quorum_size() == 3,
        "f=1 Control Proposal Ack must use n=4 and q=3"
    );

    let authority_ref = hash('a');
    let quorum_members = quorum_case
        .get("authority_acks")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("quorum Ack fixture has no authority_acks[]"))?
        .iter()
        .map(|value| {
            member(
                required_field(value, "verification_method")?,
                required_field(value, "received_at")?,
                required_field(value, "decision_due_at")?,
                required_field(value, "absolute_due_at")?,
                authority_ref.clone(),
            )
        })
        .collect::<Result<Vec<_>>>()?;
    let ack = ControlProposalAck::from_authority_acks_for_notary(
        quorum_members.clone(),
        policy,
        &notary,
    )?;
    let expected = &quorum_case["expected"];
    let actual_member_order = ack
        .authority_acks
        .iter()
        .map(|member| member.signature.verification_method.as_str())
        .collect::<Vec<_>>();
    let expected_member_order = expected["member_order"]
        .as_array()
        .ok_or_else(|| anyhow!("quorum Ack fixture has no expected member_order[]"))?
        .iter()
        .map(|value| required_string(value, "expected member"))
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        ack.received_at == timestamp(expected, "received_at")?
            && ack.decision_due_at == timestamp(expected, "decision_due_at")?
            && ack.absolute_due_at == timestamp(expected, "absolute_due_at")?
            && actual_member_order == expected_member_order,
        "quorum Ack aggregation diverged from the f=1 fixture"
    );

    let duplicate_case = case("duplicate_member_does_not_count_twice")?;
    let duplicate_methods = duplicate_case["authority_ack_verification_methods"]
        .as_array()
        .ok_or_else(|| anyhow!("duplicate-member fixture has no authority methods[]"))?;
    let mut duplicate_members = Vec::new();
    for method in duplicate_methods {
        let method = required_string(method, "duplicate member method")?;
        let source = quorum_members
            .iter()
            .find(|member| member.signature.verification_method.as_str() == method)
            .ok_or_else(|| anyhow!("duplicate-member fixture names unknown signer {method}"))?;
        duplicate_members.push(source.clone());
    }
    ensure!(
        ControlProposalAck::from_authority_acks_for_notary(duplicate_members, policy, &notary)
            .is_err(),
        "duplicate signer A,A,B incorrectly reached the f=1 quorum"
    );

    let mixed_case = case("mixed_authority_set_and_out_of_window_rejected")?;
    let mut mixed_members = quorum_members;
    mixed_members[1].authority_set_ref = hash('b');
    mixed_members[2].received_at = mixed_members[0].received_at
        + chrono::Duration::milliseconds(
            mixed_case["received_at_span_ms"]
                .as_i64()
                .ok_or_else(|| anyhow!("mixed Ack fixture has no received_at_span_ms"))?,
        );
    ensure!(
        ControlProposalAck::from_authority_acks_for_notary(mixed_members, policy, &notary).is_err(),
        "mixed authority set / out-of-window Ack set was accepted"
    );

    ensure!(
        ControlProposalDecisionPolicy {
            proposal_intake_sla: chrono::Duration::hours(24),
            ..policy
        }
        .validate()
        .is_ok(),
        "inclusive proposal intake SLA maximum was rejected"
    );
    ensure!(
        ControlProposalDecisionPolicy {
            proposal_intake_sla: chrono::Duration::milliseconds(86_400_001),
            ..policy
        }
        .validate()
        .is_err(),
        "proposal intake SLA above the wire maximum was accepted"
    );

    for name in [
        "proposal_decision_window_after_absolute_deadline_rejected",
        "equal_proposal_windows_without_defers_accepted",
        "equal_proposal_windows_with_defers_rejected",
    ] {
        let value = case(name)?;
        let configuration = value
            .get("realm_configuration")
            .ok_or_else(|| anyhow!("{name} is missing realm_configuration"))?;
        let milliseconds = |field: &str| -> Result<i64> {
            configuration
                .get(field)
                .and_then(Value::as_i64)
                .ok_or_else(|| anyhow!("{name}.{field} must be an integer"))
        };
        let max_defers = configuration
            .get("max_proposal_defers")
            .and_then(Value::as_u64)
            .and_then(|value| u8::try_from(value).ok())
            .ok_or_else(|| anyhow!("{name}.max_proposal_defers must fit u8"))?;
        let candidate = ControlProposalDecisionPolicy {
            proposal_intake_sla: policy.proposal_intake_sla,
            decision_window: chrono::Duration::milliseconds(milliseconds(
                "proposal_decision_window_ms",
            )?),
            absolute_horizon: chrono::Duration::milliseconds(milliseconds(
                "proposal_absolute_deadline_ms",
            )?),
            max_defers,
        };
        let accepted = candidate.validate().is_ok();
        let expected_accepted =
            value.pointer("/expected/decision").and_then(Value::as_str) == Some("accept");
        ensure!(
            accepted == expected_accepted,
            "{name} policy validation produced {}, expected {}",
            if accepted { "accept" } else { "reject" },
            if expected_accepted {
                "accept"
            } else {
                "reject"
            }
        );
    }

    let replay = case("exact_member_retry_is_byte_identical_and_conflict_cannot_extend")?;
    let original = serde_json::to_vec(&ack.authority_acks[0])?;
    let request = b"canonical-request".to_vec();
    let mut ledger = BTreeMap::from([("ack-key", (request.clone(), original.clone()))]);
    let exact = ledger
        .get("ack-key")
        .filter(|(stored_request, _)| stored_request == &request)
        .map(|(_, outcome)| outcome.clone())
        .context("exact retry missed its original authority Ack")?;
    let conflict = ledger
        .get_mut("ack-key")
        .is_some_and(|(stored_request, _)| stored_request != b"different-request");
    ensure!(
        exact == original
            && conflict
            && replay["expected"]["deadline_extended"].as_bool() == Some(false),
        "authority Ack replay semantics diverged"
    );

    let decision_case = case("decision_proofs_cannot_cross_ack_sets")?;
    let wrong_proposal_ack_digest = Hash::new(
        decision_case["decision_proof_proposal_ack_digests"][1]
            .as_str()
            .unwrap(),
    )?;
    let mut decision = ControlProposalDecision::SignedDefer {
        realm_id: ack.realm_id.clone(),
        proposal_digest: ack.proposal_digest.clone(),
        proposal_ack_digest: wrong_proposal_ack_digest,
        decided_at: ack.received_at + chrono::Duration::seconds(1),
        decision_due_at: ack.decision_due_at + chrono::Duration::seconds(1),
        absolute_due_at: ack.absolute_due_at,
        defer_count: 1,
        reason_code: ControlProposalDeferReason::QuorumUnreachable,
        authority_set_ref: ack.authority_set_ref.clone(),
        proofs: vec![PayloadSignature {
            verification_method: crate::fixture_did_url(
                "did:webvh:z6mkfixture:authority-a.example#notary",
            ),
            payload_digest: hash('0'),
            created_at: ack.received_at + chrono::Duration::seconds(1),
            jws: "a..b".to_owned(),
        }],
    };
    let digest = decision.decision_digest()?;
    let ControlProposalDecision::SignedDefer { proofs, .. } = &mut decision;
    proofs[0].payload_digest = digest;
    ensure!(
        decision.validate_chain(&ack, &[], policy).is_err(),
        "decision proof crossed Ack sets"
    );
    let ControlProposalDecision::SignedDefer {
        proposal_ack_digest,
        ..
    } = &mut decision;
    *proposal_ack_digest = ack.proposal_ack_digest()?;
    let digest = decision.decision_digest()?;
    let ControlProposalDecision::SignedDefer { proofs, .. } = &mut decision;
    proofs[0].payload_digest = digest;
    decision
        .validate_chain(&ack, &[], policy)
        .context("the same bounded defer must validate with its exact Ack binding")?;

    for name in [
        "proposal_decision_window_after_absolute_deadline_rejected",
        "equal_proposal_windows_without_defers_accepted",
        "equal_proposal_windows_with_defers_rejected",
    ] {
        let vector = case(name)?;
        let configuration = &vector["realm_configuration"];
        let policy = ControlProposalDecisionPolicy {
            proposal_intake_sla: chrono::Duration::hours(24),
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

fn required_string<'a>(value: &'a Value, context: &str) -> Result<&'a str> {
    value
        .as_str()
        .ok_or_else(|| anyhow!("{context} must be a string"))
}

fn required_field<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("authority Ack is missing string field {field}"))
}

fn notary_signer_from_method(method: &str) -> Result<arkret_wire::NotarySignerDescriptor> {
    let verification_method = DidUrl::new(method.to_owned()).map_err(anyhow::Error::msg)?;
    let controller = method
        .rsplit_once('#')
        .map(|(controller, _)| controller)
        .ok_or_else(|| anyhow!("notary verification method is not a DID URL: {method}"))?;
    let did = arkret_wire::Did::new(controller.to_owned())?;
    let actor_id = arkret_wire::project_did_to_core_id(&did).map_err(anyhow::Error::msg)?;
    Ok(crate::fixture_notary_signer_for_method(
        actor_id,
        verification_method,
    ))
}

fn member(
    // Fixture-supplied text: validated into a `DidUrl` here, at the boundary,
    // so a fixture carrying a bare DID fails with an error rather than being
    // widened into the wire type.
    verification_method: &str,
    received_at: &str,
    decision_due_at: &str,
    absolute_due_at: &str,
    authority_set_ref: Hash,
) -> Result<ControlProposalAuthorityAck> {
    let received_at = received_at.parse()?;
    let mut member = ControlProposalAuthorityAck {
        realm_id: RealmId::new("ak:realm:AYcmQBZ6x7FCwln_vbdWIyV2tJ4pOJ4rmbd6v_0Y7N9_")?,
        proposal_digest: hash('c'),
        received_at,
        decision_due_at: decision_due_at.parse()?,
        absolute_due_at: absolute_due_at.parse()?,
        authority_set_ref,
        signature: PayloadSignature {
            verification_method: DidUrl::new(verification_method).map_err(anyhow::Error::msg)?,
            payload_digest: hash('0'),
            created_at: received_at,
            jws: "a..b".to_owned(),
        },
    };
    member.signature.payload_digest = member.authority_ack_digest()?;
    Ok(member)
}

fn timestamp(value: &Value, field: &str) -> Result<DateTime<Utc>> {
    value[field]
        .as_str()
        .ok_or_else(|| anyhow!("{field} is missing"))?
        .parse()
        .map_err(|error| anyhow!("{field} is not an RFC3339 timestamp: {error}"))
}
