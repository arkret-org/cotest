//! Differential gate between the production SDK/Soland Kernel and the
//! independent Cotest reference reducer.

use std::collections::BTreeSet;
use std::fs;

use anyhow::{Context, Result, anyhow, bail};
use arkret_event_draft::ProjectedEventOperation as Operation;
use arkret_event_draft::test_support::raw_projected_operation;
use arkret_identifiers::{
    AuthorizationLeaseId, CellRef, DeviceId, DidCoreId, Hash, Hlc, OperationId, RealmId, SealId,
};
use arkret_state::lattice::ordered_log::{IssuedOp, OrderedLog};
use arkret_state::lattice::{CasRegister, CellState, Lattice, OrSet, SealedOp};
use arkret_wire::offline_publication::{
    AuthoritySetAuthorizationRule, AuthoritySetIssuer, AuthoritySetIssuerRole, AuthoritySetPolicy,
    AuthoritySetPolicyKind, AuthoritySetPolicySource, AuthoritySetRef, AuthoritySetSourceKind,
    AuthorizationLease, LeaseBasisRef, RiskTier,
};
use arkret_wire::{
    CapabilityActionId, CbaProofBundle, ControlProposalDecisionPolicy, DidFullId, DidUrl,
    LatticeOp, LatticeOpType, NotarySig, NotaryValue, SchemaId, ScopeRef, Seal, SealSignature,
};
use chrono::{TimeZone, Utc};
use serde_json::{Value, json};
use soland_domain::reducer::{MlsEffect, ProjectionEffect, ProjectionState, mls};

use super::kernel_reference::{
    self, KernelGateCase, KernelGateFixture, KernelGateInput, KernelGateOutcome,
};
use super::{load_local_fixture_value, local_fixture_path};

pub const KERNEL_JOINT_GATE_FIXTURE: &str = "kernel-joint-gate.json";

pub fn run_kernel_joint_gate_suite() -> Result<()> {
    assert_reference_dependency_boundary()?;
    let fixture: KernelGateFixture =
        serde_json::from_value(load_local_fixture_value(KERNEL_JOINT_GATE_FIXTURE)?)?;
    if fixture.suite != "kernel_joint_gate" {
        bail!("kernel joint gate fixture suite drifted");
    }
    let required = [
        "genesis_authority",
        "profile_negotiation",
        "membership_mls_atomicity",
        "offline_data_convergence",
        "merge_safe_control",
        "exclusive_control_bottom",
        "security_barrier_quorum",
        "cba_basis_completion",
        "expired_lease",
        "revoked_device_lease",
        "proposal_decision",
        "seal_equivocation",
    ];
    let covered = fixture
        .cases
        .iter()
        .map(|case| case.requirement.as_str())
        .collect::<BTreeSet<_>>();
    for requirement in required {
        if !covered.contains(requirement) {
            bail!("kernel joint gate fixture does not cover {requirement}");
        }
    }

    for case in &fixture.cases {
        compare_case(case)?;
    }
    assert_order_independence(&fixture.cases)?;
    Ok(())
}

fn compare_case(case: &KernelGateCase) -> Result<()> {
    let reference = kernel_reference::reduce(&case.input);
    let kernel = reduce_with_kernel(&case.input);
    if reference != kernel {
        bail!(
            "kernel differential mismatch for {}: reference={}, kernel={}",
            case.case_id,
            serde_json::to_string(&reference)?,
            serde_json::to_string(&kernel)?
        );
    }
    if kernel != case.expected {
        bail!(
            "kernel gate semantic mismatch for {}: expected={}, observed={}",
            case.case_id,
            serde_json::to_string(&case.expected)?,
            serde_json::to_string(&kernel)?
        );
    }
    Ok(())
}

fn assert_order_independence(cases: &[KernelGateCase]) -> Result<()> {
    for case_id in ["offline_data_two_devices", "open_set_merge_safe_control"] {
        let case = cases
            .iter()
            .find(|case| case.case_id == case_id)
            .ok_or_else(|| anyhow!("kernel joint gate missing order case {case_id}"))?;
        let mut reversed = case.input.clone();
        let pointer = if case_id == "offline_data_two_devices" {
            "/offline_writes"
        } else {
            "/writes"
        };
        reversed
            .payload
            .pointer_mut(pointer)
            .and_then(Value::as_array_mut)
            .ok_or_else(|| anyhow!("kernel order case {case_id} has no {pointer}"))?
            .reverse();
        let reference = kernel_reference::reduce(&reversed);
        let kernel = reduce_with_kernel(&reversed);
        if reference != case.expected || kernel != case.expected {
            bail!("kernel order case {case_id} changed after reversing concurrent input");
        }
    }
    Ok(())
}

fn assert_reference_dependency_boundary() -> Result<()> {
    let source_path = local_fixture_path(KERNEL_JOINT_GATE_FIXTURE)
        .parent()
        .and_then(|tests| tests.parent())
        .and_then(|manifest| manifest.parent())
        .map(|manifest| manifest.join("src/conformance/kernel_reference.rs"))
        .ok_or_else(|| anyhow!("could not resolve Cotest source root"))?;
    let source = fs::read_to_string(&source_path)
        .with_context(|| format!("failed to read {}", source_path.display()))?;
    for forbidden in [
        "arkret_state",
        "soland_domain",
        "ProjectionState",
        "MemorySealStore",
    ] {
        if source.contains(forbidden) {
            bail!(
                "independent reference reducer imports or names forbidden production state symbol {forbidden}"
            );
        }
    }
    Ok(())
}

fn reduce_with_kernel(input: &KernelGateInput) -> KernelGateOutcome {
    match input.kind.as_str() {
        "ak.realm.create" => kernel_genesis(input),
        "ak.realm.notary" => kernel_notary_profile(input),
        "ak.mls.commit" => kernel_membership_mls(input),
        "ak.message.create" if input.payload.get("offline_writes").is_some() => {
            kernel_offline_data(input)
        }
        "ak.capability.grant" => kernel_merge_safe(input),
        "ak.realm.policy" => kernel_exclusive_control(input),
        "ak.device.revoke" => kernel_security_barrier(input),
        "ak.message.create" if input.payload.get("cba_proof_bundle").is_some() => {
            kernel_cba_bundle(input)
        }
        "ak.message.create" => kernel_offline_publication(input),
        "ak.self.authorization_leases.command.issue" => kernel_lease_issue(input),
        "ak.self.control_proposal_acks.command.issue" => kernel_proposal(input),
        "ak.notary.fault.equivocation" => kernel_equivocation(input),
        _ => error("unsupported_feature", "kernel_gate_kind_unsupported"),
    }
}

fn kernel_genesis(input: &KernelGateInput) -> KernelGateOutcome {
    let notary = match parse_notary(input.payload.pointer("/object/notary")) {
        Ok(notary) => notary,
        Err(outcome) => return outcome,
    };
    if notary.validate().is_err() {
        return error("genesis_seal_invalid", "founding_authority_invalid");
    }
    let required = string_set(input.basis.get("required_cells"));
    let covered = string_set(input.basis.get("covered_cells"));
    if required.is_empty() || !required.is_subset(&covered) {
        return error("genesis_seal_invalid", "founding_unit_incomplete");
    }
    let authorities = notary_members(&notary);
    let signers = string_set(input.basis.pointer("/seal/signers"));
    if authorities.is_disjoint(&signers) {
        return error("genesis_seal_invalid", "founding_authority_not_bound");
    }
    projection(json!({
        "authority": authorities.into_iter().collect::<Vec<_>>(),
        "status": "sealed"
    }))
}

fn kernel_notary_profile(input: &KernelGateInput) -> KernelGateOutcome {
    let notary = match parse_notary(input.payload.get("notary")) {
        Ok(notary) => notary,
        Err(outcome) => return outcome,
    };
    if notary.validate().is_err() {
        return error("schema_violation", "notary_profile_invalid");
    }
    let profile = match &notary {
        NotaryValue::OpenSet { .. } => "open_set",
        _ => "single_chain",
    };
    if !string_set(input.basis.get("supported_profiles")).contains(profile) {
        return error("unsupported_feature", "notary_profile_not_supported");
    }
    projection(json!({
        "members": notary_members(&notary),
        "profile": profile
    }))
}

fn kernel_membership_mls(input: &KernelGateInput) -> KernelGateOutcome {
    if input
        .payload
        .pointer("/membership/state")
        .and_then(Value::as_str)
        != Some("join")
    {
        return error("schema_violation", "membership_transition_invalid");
    }
    if input.basis.get("atomic_unit").and_then(Value::as_bool) != Some(true) {
        return error("failed_precondition", "membership_mls_commit_not_atomic");
    }
    let basis_frontier = input
        .basis
        .get("security_frontier_digest")
        .and_then(Value::as_str);
    let binding_frontier = input
        .payload
        .pointer("/commit/governance_binding/security_frontier_digest")
        .and_then(Value::as_str);
    if basis_frontier.is_none() || basis_frontier != binding_frontier {
        return error(
            "state_mismatch",
            "mls_governance_binding_security_frontier_mismatch",
        );
    }

    let Some(genesis_payload) = input.payload.get("genesis").cloned() else {
        return error("schema_violation", "mls_genesis_missing");
    };
    let Some(commit_payload) = input.payload.get("commit").cloned() else {
        return error("schema_violation", "mls_commit_missing");
    };
    let mut state = ProjectionState::new();
    let genesis = operation("ak.mls.genesis", genesis_payload, 1);
    if !matches!(
        mls::apply_group_genesis(&mut state, &genesis),
        ProjectionEffect::Mls(MlsEffect::GroupGenesis { .. })
    ) {
        return error("schema_violation", "mls_genesis_invalid");
    }
    let commit = operation("ak.mls.commit", commit_payload, 2);
    match mls::apply_commit_epoch(&mut state, &commit) {
        ProjectionEffect::Mls(MlsEffect::CommitEpochAdvanced { new_epoch, .. }) => {
            projection(json!({
                "membership": "join",
                "security_frontier_digest": basis_frontier,
                "mls_epoch": new_epoch
            }))
        }
        ProjectionEffect::Rejected { reason } => error("state_mismatch", &reason),
        _ => error("schema_violation", "mls_commit_invalid"),
    }
}

fn kernel_offline_data(input: &KernelGateInput) -> KernelGateOutcome {
    let Some(writes) = input
        .payload
        .get("offline_writes")
        .and_then(Value::as_array)
    else {
        return error("schema_violation", "offline_writes_missing");
    };
    let mut ops = Vec::new();
    for write in writes {
        let Some(actor) = write.get("actor_id").and_then(Value::as_str) else {
            return error("schema_violation", "actor_id_missing");
        };
        let Some(digest) = write.get("event_digest").and_then(Value::as_str) else {
            return error("schema_violation", "event_digest_missing");
        };
        let Some(value) = write.get("value").cloned() else {
            return error("schema_violation", "data_value_missing");
        };
        let (Ok(issuer), Ok(move_id)) = (DidCoreId::new(actor), Hash::new(digest)) else {
            return error("schema_violation", "offline_write_identifier_invalid");
        };
        ops.push(IssuedOp {
            issuer,
            op: SealedOp::new(
                move_id,
                lattice_op(LatticeOpType::Append, None, Some(value), Some(0)),
            ),
        });
    }
    let report = OrderedLog.join_with_issuer_report(&ops);
    if !report.identity_collisions.is_empty() || report.entries.len() != writes.len() {
        return error("state_mismatch", "offline_data_join_failed");
    }
    projection(json!({
        "entries": report.entries,
        "sibling_event_digests": report
            .sibling_groups
            .first()
            .map(|item| item.event_digests.clone())
            .unwrap_or_default()
    }))
}

fn kernel_merge_safe(input: &KernelGateInput) -> KernelGateOutcome {
    let Some(writes) = input.payload.get("writes").and_then(Value::as_array) else {
        return error("schema_violation", "merge_safe_writes_missing");
    };
    let mut ops = Vec::new();
    let mut sequence = 1u8;
    for write in input
        .pre_state
        .get("entries")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .chain(writes)
    {
        let Some(tag) = write.get("tag").and_then(Value::as_str) else {
            return error("schema_violation", "merge_safe_write_invalid");
        };
        let Some(value) = write.get("value").cloned() else {
            return error("schema_violation", "merge_safe_write_invalid");
        };
        ops.push(SealedOp::new(
            repeated_hash(sequence),
            lattice_op(LatticeOpType::Add, Some(tag.to_owned()), Some(value), None),
        ));
        sequence = sequence.saturating_add(1);
    }
    match OrSet.join(
        &sample_cell(arkret_wire::CellFamilyId::CAPABILITY_GRANT_V1),
        &ops,
    ) {
        CellState::Value(entries) => projection(json!({"entries": entries})),
        CellState::Bottom(_) => error("state_mismatch", "merge_safe_control_bottom"),
    }
}

fn kernel_exclusive_control(input: &KernelGateInput) -> KernelGateOutcome {
    let Some(values) = input
        .payload
        .get("concurrent_values")
        .and_then(Value::as_array)
    else {
        return error("schema_violation", "exclusive_write_missing");
    };
    let ops = values
        .iter()
        .enumerate()
        .map(|(index, value)| {
            SealedOp::new(
                repeated_hash(u8::try_from(index + 1).unwrap_or(u8::MAX)),
                lattice_op(LatticeOpType::Set, None, Some(value.clone()), None),
            )
        })
        .collect::<Vec<_>>();
    match CasRegister.join(
        &sample_cell(arkret_wire::CellFamilyId::REALM_POLICY_V1),
        &ops,
    ) {
        CellState::Value(value) => projection(json!({"value": value})),
        CellState::Bottom(bottom) => {
            let mut heads = bottom.heads;
            heads.sort_by_key(Value::to_string);
            projection(json!({
                "heads": heads,
                "kind": "conflict",
                "status": "bottom"
            }))
        }
    }
}

fn kernel_security_barrier(input: &KernelGateInput) -> KernelGateOutcome {
    let Some(authority) = input.payload.get("authority") else {
        return error("schema_violation", "security_barrier_authority_invalid");
    };
    let Some(threshold) = authority.get("threshold").and_then(Value::as_u64) else {
        return error("schema_violation", "security_barrier_authority_invalid");
    };
    let Some(members) = authority.get("members").and_then(Value::as_array) else {
        return error("schema_violation", "security_barrier_authority_invalid");
    };
    let unique_members = members
        .iter()
        .filter_map(Value::as_str)
        .collect::<BTreeSet<_>>();
    if threshold == 0 || unique_members.len() != members.len() || threshold as usize > members.len()
    {
        return error("schema_violation", "security_barrier_authority_invalid");
    }
    if usize::try_from(threshold)
        .ok()
        .is_none_or(|threshold| threshold.saturating_mul(2) <= members.len())
    {
        return error(
            "failed_precondition",
            "security_barrier_quorum_not_intersecting",
        );
    }
    projection(json!({"barrier": "accepted"}))
}

fn kernel_cba_bundle(input: &KernelGateInput) -> KernelGateOutcome {
    let basis_known = input
        .basis
        .get("target_seal_known")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if basis_known {
        return projection(json!({"basis_complete": true}));
    }
    let Some(bundle_input) = input
        .payload
        .get("cba_proof_bundle")
        .and_then(Value::as_object)
    else {
        return error("dependency_missing", "cba_basis_incomplete");
    };
    let Some(target_ref) = bundle_input.get("target_seal_ref").and_then(Value::as_str) else {
        return error("dependency_missing", "cba_basis_incomplete");
    };
    let Some(seal_inputs) = bundle_input.get("seals").and_then(Value::as_array) else {
        return error("dependency_missing", "cba_basis_incomplete");
    };
    if seal_inputs.len() != 1 {
        return error("dependency_missing", "cba_basis_incomplete");
    }
    let seal_input = &seal_inputs[0];
    if seal_input.get("seal_ref").and_then(Value::as_str) != Some(target_ref)
        || seal_input
            .get("predecessor_refs")
            .and_then(Value::as_array)
            .is_none_or(|predecessors| !predecessors.is_empty())
        || seal_input.get("realm_id").and_then(Value::as_str) != Some(sample_realm().as_str())
    {
        return error("dependency_missing", "cba_basis_incomplete");
    }
    let notary_seq = seal_input
        .get("notary_seq")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let Some(delta_byte) = seal_input
        .get("delta_digest")
        .and_then(Value::as_str)
        .and_then(digest_tail_byte)
    else {
        return error("dependency_missing", "cba_basis_incomplete");
    };
    let seal = sample_seal(
        notary_seq,
        delta_byte,
        &crate::fixture_did_url("did:webvh:z6mkfixture:notary.example#key-1"),
    );
    let bundle = CbaProofBundle {
        target_seal_ref: seal.id.clone(),
        seals: vec![seal],
        control_moves: Vec::new(),
        inclusion_proofs: Vec::new(),
        availability_proofs: Vec::new(),
    };
    if bundle.validate_structural().is_err() {
        return error("dependency_missing", "cba_basis_incomplete");
    }
    projection(json!({"basis_complete": true}))
}

fn kernel_offline_publication(input: &KernelGateInput) -> KernelGateOutcome {
    let Some(issued_at_ms) = input
        .payload
        .pointer("/authorization_lease/issued_at_ms")
        .and_then(Value::as_i64)
    else {
        return error("schema_violation", "authorization_lease_invalid");
    };
    let Some(expires_at_ms) = input
        .payload
        .pointer("/authorization_lease/expires_at_ms")
        .and_then(Value::as_i64)
    else {
        return error("schema_violation", "authorization_lease_invalid");
    };
    let Some(evaluate_at_ms) = input
        .payload
        .pointer("/authorization_lease/evaluate_at_ms")
        .and_then(Value::as_i64)
    else {
        return error("schema_violation", "authorization_lease_invalid");
    };
    let Some(issued_at) = Utc.timestamp_millis_opt(issued_at_ms).single() else {
        return error("schema_violation", "authorization_lease_invalid");
    };
    let Some(expires_at) = Utc.timestamp_millis_opt(expires_at_ms).single() else {
        return error("schema_violation", "authorization_lease_invalid");
    };
    let Some(evaluate_at) = Utc.timestamp_millis_opt(evaluate_at_ms).single() else {
        return error("schema_violation", "authorization_lease_invalid");
    };
    let lease = sample_lease(issued_at, expires_at);
    let receipt_covered = input
        .pre_state
        .pointer("/ingress_receipt/received_at_ms")
        .and_then(Value::as_i64)
        .and_then(|value| Utc.timestamp_millis_opt(value).single())
        .is_some_and(|received_at| lease.covers_instant(received_at));
    if !lease.covers_instant(evaluate_at) && !receipt_covered {
        return error("authorization_expired", "authorization_lease_expired");
    }
    projection(json!({"publication": "accepted"}))
}

fn kernel_lease_issue(input: &KernelGateInput) -> KernelGateOutcome {
    let Some(device_id) = input.payload.get("device_id").and_then(Value::as_str) else {
        return error("schema_violation", "device_id_missing");
    };
    let Some(action) = input.payload.get("action").and_then(Value::as_str) else {
        return error("schema_violation", "action_missing");
    };
    let Some(action_id) = CapabilityActionId::from_wire(action) else {
        return error("unsupported_feature", "capability_action_unknown");
    };
    if arkret_schema::capability_action_descriptor(action_id).risk_tier
        != arkret_schema::CapabilityRiskTier::High
    {
        return error("schema_violation", "expected_high_risk_action");
    }
    if string_set(input.pre_state.get("revoked_devices")).contains(device_id) {
        return error("capability_denied", "device_revoked");
    }
    projection(json!({"lease": "issued"}))
}

fn kernel_proposal(input: &KernelGateInput) -> KernelGateOutcome {
    let max_defers = input
        .basis
        .get("max_defers")
        .and_then(Value::as_u64)
        .and_then(|value| u8::try_from(value).ok())
        .unwrap_or(2);
    let policy = ControlProposalDecisionPolicy {
        max_defers,
        ..ControlProposalDecisionPolicy::default()
    };
    if policy.validate().is_err() {
        return error("schema_violation", "proposal_policy_invalid");
    }
    let defer_count = input
        .payload
        .get("defer_count")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    match input.payload.get("decision").and_then(Value::as_str) {
        Some("include") => projection(json!({"proposal_status": "included"})),
        Some("reject") => projection(json!({"proposal_status": "rejected"})),
        Some("defer") if defer_count <= u64::from(policy.max_defers) => projection(json!({
            "defer_count": defer_count,
            "proposal_status": "pending"
        })),
        Some("defer") => error("schema_violation", "proposal_defer_limit_exceeded"),
        _ => error("schema_violation", "proposal_decision_invalid"),
    }
}

fn kernel_equivocation(input: &KernelGateInput) -> KernelGateOutcome {
    let signer_a = input
        .payload
        .pointer("/seal_a/signer_id")
        .and_then(Value::as_str);
    let signer_b = input
        .payload
        .pointer("/seal_b/signer_id")
        .and_then(Value::as_str);
    let verification_method_a = input
        .payload
        .pointer("/seal_a/verification_method")
        .and_then(Value::as_str);
    let verification_method_b = input
        .payload
        .pointer("/seal_b/verification_method")
        .and_then(Value::as_str);
    let seq_a = input
        .payload
        .pointer("/seal_a/notary_seq")
        .and_then(Value::as_u64);
    let seq_b = input
        .payload
        .pointer("/seal_b/notary_seq")
        .and_then(Value::as_u64);
    let (
        Some(signer_a),
        Some(signer_b),
        Some(verification_method_a),
        Some(verification_method_b),
        Some(seq_a),
        Some(seq_b),
    ) = (
        signer_a,
        signer_b,
        verification_method_a,
        verification_method_b,
        seq_a,
        seq_b,
    )
    else {
        return error("schema_violation", "notary_fault_evidence_invalid");
    };
    let Some(delta_a) = input
        .payload
        .pointer("/seal_a/canonical_body_digest")
        .and_then(Value::as_str)
        .and_then(digest_tail_byte)
    else {
        return error("schema_violation", "notary_fault_evidence_invalid");
    };
    let Some(delta_b) = input
        .payload
        .pointer("/seal_b/canonical_body_digest")
        .and_then(Value::as_str)
        .and_then(digest_tail_byte)
    else {
        return error("schema_violation", "notary_fault_evidence_invalid");
    };
    let parse_verification_method = |value: &str, signer: &str| {
        let method = DidUrl::new(value.to_owned()).ok()?;
        let (controller, _) = value.rsplit_once('#')?;
        let controller = DidFullId::new(controller.to_owned()).ok()?;
        let projected = arkret_wire::project_full_id_to_core_id(&controller).ok()?;
        (projected.as_str() == signer).then_some(method)
    };
    let (Some(verification_method_a), Some(verification_method_b)) = (
        parse_verification_method(verification_method_a, signer_a),
        parse_verification_method(verification_method_b, signer_b),
    ) else {
        return error("schema_violation", "notary_fault_evidence_invalid");
    };
    let seal_a = sample_seal(seq_a, delta_a, &verification_method_a);
    let seal_b = sample_seal(seq_b, delta_b, &verification_method_b);
    let equivocation = signer_a == signer_b
        && seq_a == seq_b
        && seal_a.canonical_bytes_for_id().ok() != seal_b.canonical_bytes_for_id().ok();
    if !equivocation {
        return error("failed_precondition", "notary_fault_evidence_invalid");
    }
    projection(json!({
        "reason": "notary_equivocation",
        "recovery_required": true,
        "status": "quarantine"
    }))
}

fn parse_notary(value: Option<&Value>) -> std::result::Result<NotaryValue, KernelGateOutcome> {
    let Some(value) = value else {
        return Err(error("genesis_seal_invalid", "founding_authority_missing"));
    };
    serde_json::from_value(value.clone())
        .map_err(|_| error("schema_violation", "notary_profile_invalid"))
}

fn notary_members(notary: &NotaryValue) -> BTreeSet<String> {
    match notary {
        NotaryValue::SingleSigner {
            signer,
            recovery_members,
            ..
        } => {
            let mut members = BTreeSet::from([signer.actor_id.as_str().to_owned()]);
            members.extend(
                recovery_members
                    .iter()
                    .map(|member| member.actor_id.as_str().to_owned()),
            );
            members
        }
        NotaryValue::Threshold { members, .. } | NotaryValue::OpenSet { members } => members
            .iter()
            .map(|member| member.actor_id.as_str().to_owned())
            .collect(),
        NotaryValue::Mixed {
            signer,
            recovery_members,
            ..
        } => {
            let mut members = BTreeSet::from([signer.actor_id.as_str().to_owned()]);
            members.extend(
                recovery_members
                    .iter()
                    .map(|member| member.actor_id.as_str().to_owned()),
            );
            members
        }
    }
}

fn operation(kind: &str, payload: Value, suffix: u8) -> Operation {
    let mut operation = raw_projected_operation(
        OperationId::new(format!(
            "ak:operation:0196419b-0000-7000-8000-{suffix:012x}"
        ))
        .expect("fixed operation id is valid"),
        sample_realm(),
        kind,
        payload,
    );
    operation.created_at = Utc
        .with_ymd_and_hms(2026, 7, 28, 0, 0, u32::from(suffix))
        .single()
        .expect("fixed timestamp is valid");
    operation
}

fn sample_cell(component: &str) -> CellRef {
    CellRef::new(format!("ak:cell:{component}:null")).expect("fixed cell id is valid")
}

fn sample_realm() -> RealmId {
    RealmId::new("ak:realm:AZAySZA7XRDeJ9cO4MqaDWrJD-rqPk6Cudk7CCzsDQz1")
        .expect("fixed Realm id is valid")
}

fn repeated_hash(byte: u8) -> Hash {
    Hash::new(format!("sha256:{}", format!("{byte:02x}").repeat(32))).expect("fixed hash is valid")
}

fn lattice_op(
    op_type: LatticeOpType,
    tag: Option<String>,
    value: Option<Value>,
    issuer_seq: Option<u64>,
) -> LatticeOp {
    LatticeOp {
        op_type,
        tag,
        value,
        from: None,
        to: None,
        reason: None,
        issuer_seq,
    }
}

fn sample_seal(notary_seq: u64, delta_byte: u8, verification_method: &DidUrl) -> Seal {
    let sealed_at = Utc
        .with_ymd_and_hms(2026, 7, 28, 0, 0, 0)
        .single()
        .expect("fixed timestamp is valid");
    let mut seal = Seal {
        id: SealId::new(format!("ak:seal:{}", repeated_hash(0).as_str()))
            .expect("fixed Seal id is valid"),
        realm_id: sample_realm(),
        predecessor_refs: Vec::new(),
        delta: vec![repeated_hash(delta_byte)],
        control_event_set_root: repeated_hash(0x11),
        state_root: repeated_hash(0x22),
        completeness_root: repeated_hash(0x33),
        notary_seq,
        data_view_root: None,
        data_event_set_root: None,
        availability_receipt_digests: Vec::new(),
        covered_event_digests: Vec::new(),
        previous_state_root: None,
        previous_digest_algorithm: None,
        notary_signature: NotarySig::Single(SealSignature {
            verification_method: verification_method.clone(),
            payload_digest: repeated_hash(0x55),
            jws: "e30..c2ln".to_owned(),
        }),
        sealed_at,
        hlc: Hlc::new("01970e589d21-0000-a13f9c2e").expect("fixed HLC is valid"),
    };
    seal.id = seal
        .derive_id(arkret_canonical::DigestSuite::Sha256)
        .expect("sample Seal id derives");
    seal
}

fn sample_lease(
    issued_at: chrono::DateTime<Utc>,
    expires_at: chrono::DateTime<Utc>,
) -> AuthorizationLease {
    let scope_ref = ScopeRef::Realm {
        realm_id: sample_realm(),
    };
    let policy = AuthoritySetPolicy {
        schema: SchemaId::AUTHORITY_SET_POLICY_V1.to_owned(),
        authority_set_id: "ak.authority_set.realm_admission.v1".to_owned(),
        policy_kind: AuthoritySetPolicyKind::RealmAdmission,
        scope_ref: scope_ref.clone(),
        source: AuthoritySetPolicySource {
            source_kind: AuthoritySetSourceKind::RealmControl,
            source_ref: "ak:event:AR4I3pqI_AE1Vxb4LEKq2azQxWXhHobgzwnTJmhVKJT-".to_owned(),
            source_digest: repeated_hash(0x61),
            generation_ref: "1".to_owned(),
        },
        authorization_rules: vec![AuthoritySetAuthorizationRule {
            rule_id: "realm_admission".to_owned(),
            issuer_role: AuthoritySetIssuerRole::RealmAdmission,
            allowed_actions: vec!["ak.message.create".to_owned()],
            issuers: vec![AuthoritySetIssuer {
                verification_method: DidUrl::new("did:webvh:z6mkfixture:authority.example#key-1")
                    .expect("fixed DID URL is valid"),
            }],
            threshold: 1,
        }],
    };
    let authority_set_ref = AuthoritySetRef {
        authority_set_id: policy.authority_set_id.clone(),
        authority_set_digest: policy.digest().expect("sample authority policy hashes"),
    };
    AuthorizationLease {
        authorization_lease_id: AuthorizationLeaseId::new(
            "ak:authorization_lease:0196419b-0000-7000-8000-000000000001",
        )
        .expect("fixed authorization lease id is valid"),
        basis_ref: LeaseBasisRef::Seal(
            SealId::new(format!("ak:seal:{}", repeated_hash(0x62).as_str()))
                .expect("fixed Seal id is valid"),
        ),
        actor_id: DidCoreId::new("ak:did_core:web:alice.example")
            .expect("fixed actor DID is valid"),
        device_id: DeviceId::new("ak:device:0196419b-0000-7000-8000-000000000001")
            .expect("fixed device id is valid"),
        scope_ref,
        action: "ak.message.create".to_owned(),
        authorization_rule_id: "realm_admission".to_owned(),
        risk_tier: RiskTier::High,
        issued_at,
        expires_at,
        authority_set_ref,
        authority_set_policy: policy,
        proofs: Vec::new(),
    }
}

fn string_set(value: Option<&Value>) -> BTreeSet<String> {
    value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(ToOwned::to_owned)
        .collect()
}

fn digest_tail_byte(digest: &str) -> Option<u8> {
    let (_, hex) = digest.split_once(':')?;
    let tail = hex.get(hex.len().checked_sub(2)?..)?;
    u8::from_str_radix(tail, 16).ok()
}

fn projection(value: Value) -> KernelGateOutcome {
    KernelGateOutcome::Projection { value }
}

fn error(code: &str, reason: &str) -> KernelGateOutcome {
    KernelGateOutcome::TypedError {
        code: code.to_owned(),
        reason: reason.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn independent_reference_and_kernel_match_all_joint_gate_cases() {
        run_kernel_joint_gate_suite().expect("kernel joint gate must pass");
    }
}
