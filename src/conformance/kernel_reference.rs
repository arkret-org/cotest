//! Independent, test-only Arkret Kernel reference reducer.
//!
//! This module intentionally stays on `std + serde`: it must not import the
//! SDK state runtime or Soland. The joint gate compares this implementation
//! with the production SDK/Soland adapter in `kernel_joint_gate`.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelGateFixture {
    pub suite: String,
    pub cases: Vec<KernelGateCase>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelGateCase {
    pub case_id: String,
    pub requirement: String,
    pub input: KernelGateInput,
    pub expected: KernelGateOutcome,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelGateInput {
    pub kind: String,
    pub payload: Value,
    pub basis: Value,
    pub pre_state: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case", deny_unknown_fields)]
pub enum KernelGateOutcome {
    Projection { value: Value },
    TypedError { code: String, reason: String },
}

impl KernelGateOutcome {
    fn projection(value: Value) -> Self {
        Self::Projection { value }
    }

    fn error(code: &str, reason: &str) -> Self {
        Self::TypedError {
            code: code.to_owned(),
            reason: reason.to_owned(),
        }
    }
}

pub fn reduce(input: &KernelGateInput) -> KernelGateOutcome {
    match input.kind.as_str() {
        "ak.realm.create" => reduce_genesis(input),
        "ak.realm.notary" => reduce_notary_profile(input),
        "ak.mls.commit" => reduce_membership_mls(input),
        "ak.message.create" if input.payload.get("offline_writes").is_some() => {
            reduce_offline_data(input)
        }
        "ak.capability.grant" => reduce_merge_safe(input),
        "ak.realm.policy" => reduce_exclusive_control(input),
        "ak.device.revoke" => reduce_security_barrier(input),
        "ak.message.create" if input.payload.get("cba_proof_bundle").is_some() => {
            reduce_cba_bundle(input)
        }
        "ak.message.create" => reduce_offline_publication(input),
        "ak.self.authorization_leases.command.issue" => reduce_lease_issue(input),
        "ak.self.control_proposal_acks.command.issue" => reduce_proposal(input),
        "ak.notary.fault.equivocation" => reduce_equivocation(input),
        _ => KernelGateOutcome::error("unsupported_feature", "kernel_gate_kind_unsupported"),
    }
}

fn reduce_genesis(input: &KernelGateInput) -> KernelGateOutcome {
    let Some(notary) = input.payload.pointer("/object/notary") else {
        return KernelGateOutcome::error("genesis_seal_invalid", "founding_authority_missing");
    };
    let Some(authorities) = notary_authorities(notary) else {
        return KernelGateOutcome::error("genesis_seal_invalid", "founding_authority_invalid");
    };
    let required = string_set(input.basis.get("required_cells"));
    let covered = string_set(input.basis.get("covered_cells"));
    if required.is_empty() || !required.is_subset(&covered) {
        return KernelGateOutcome::error("genesis_seal_invalid", "founding_unit_incomplete");
    }
    let signers = string_set(input.basis.pointer("/seal/signers"));
    if authorities.is_disjoint(&signers) {
        return KernelGateOutcome::error("genesis_seal_invalid", "founding_authority_not_bound");
    }
    KernelGateOutcome::projection(json!({
        "authority": authorities.into_iter().collect::<Vec<_>>(),
        "status": "sealed"
    }))
}

fn reduce_notary_profile(input: &KernelGateInput) -> KernelGateOutcome {
    let Some(notary) = input.payload.get("notary") else {
        return KernelGateOutcome::error("schema_violation", "notary_profile_missing");
    };
    let Some(profile) = profile_name(notary) else {
        return KernelGateOutcome::error("schema_violation", "notary_profile_invalid");
    };
    if !string_set(input.basis.get("supported_profiles")).contains(profile) {
        return KernelGateOutcome::error("unsupported_feature", "notary_profile_not_supported");
    }
    let members = notary_authorities(notary)
        .unwrap_or_default()
        .into_iter()
        .collect::<Vec<_>>();
    KernelGateOutcome::projection(json!({"members": members, "profile": profile}))
}

fn reduce_membership_mls(input: &KernelGateInput) -> KernelGateOutcome {
    let membership = input
        .payload
        .pointer("/membership/state")
        .and_then(Value::as_str);
    if membership != Some("join") {
        return KernelGateOutcome::error("schema_violation", "membership_transition_invalid");
    }
    if input.basis.get("atomic_unit").and_then(Value::as_bool) != Some(true) {
        return KernelGateOutcome::error("failed_precondition", "membership_mls_commit_not_atomic");
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
        return KernelGateOutcome::error(
            "state_mismatch",
            "mls_governance_binding_security_frontier_mismatch",
        );
    }
    let current_epoch = input
        .pre_state
        .get("mls_epoch")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let expected_previous = input
        .payload
        .pointer("/commit/base_epoch")
        .and_then(Value::as_u64);
    if expected_previous != Some(current_epoch) {
        return KernelGateOutcome::error("state_mismatch", "mls_epoch_skew");
    }
    KernelGateOutcome::projection(json!({
        "membership": "join",
        "security_frontier_digest": basis_frontier,
        "mls_epoch": current_epoch + 1
    }))
}

fn reduce_offline_data(input: &KernelGateInput) -> KernelGateOutcome {
    let Some(writes) = input
        .payload
        .get("offline_writes")
        .and_then(Value::as_array)
    else {
        return KernelGateOutcome::error("schema_violation", "offline_writes_missing");
    };
    let mut by_digest = BTreeMap::new();
    for write in writes {
        let Some(digest) = write.get("event_digest").and_then(Value::as_str) else {
            return KernelGateOutcome::error("schema_violation", "event_digest_missing");
        };
        let Some(value) = write.get("value") else {
            return KernelGateOutcome::error("schema_violation", "data_value_missing");
        };
        let Some(actor_id) = write.get("actor_id").and_then(Value::as_str) else {
            return KernelGateOutcome::error("schema_violation", "actor_id_missing");
        };
        by_digest.insert(digest.to_owned(), (actor_id.to_owned(), value.clone()));
    }
    if by_digest.is_empty() {
        return KernelGateOutcome::error("schema_violation", "offline_writes_empty");
    }
    let entries = by_digest
        .iter()
        .map(|(digest, (actor_id, value))| {
            json!({
                "issuer": actor_id,
                "issuer_seq": 0,
                "event_digest": digest,
                "value": value
            })
        })
        .collect::<Vec<_>>();
    let sibling_event_digests = by_digest.keys().cloned().collect::<Vec<_>>();
    KernelGateOutcome::projection(json!({
        "entries": entries,
        "sibling_event_digests": sibling_event_digests
    }))
}

fn reduce_merge_safe(input: &KernelGateInput) -> KernelGateOutcome {
    let mut entries = input
        .pre_state
        .get("entries")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(parse_tagged_entry)
        .collect::<BTreeMap<_, _>>();
    let Some(writes) = input.payload.get("writes").and_then(Value::as_array) else {
        return KernelGateOutcome::error("schema_violation", "merge_safe_writes_missing");
    };
    for write in writes {
        let Some((tag, value)) = parse_tagged_entry(write) else {
            return KernelGateOutcome::error("schema_violation", "merge_safe_write_invalid");
        };
        entries.insert(tag, value);
    }
    let entries = entries
        .into_iter()
        .map(|(tag, value)| json!({"tag": tag, "value": value}))
        .collect::<Vec<_>>();
    KernelGateOutcome::projection(json!({"entries": entries}))
}

fn reduce_exclusive_control(input: &KernelGateInput) -> KernelGateOutcome {
    let mut heads = input
        .payload
        .get("concurrent_values")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    heads.sort_by_key(|value| value.to_string());
    heads.dedup();
    match heads.as_slice() {
        [] => KernelGateOutcome::error("schema_violation", "exclusive_write_missing"),
        [value] => KernelGateOutcome::projection(json!({"value": value})),
        _ => KernelGateOutcome::projection(json!({
            "heads": heads,
            "kind": "conflict",
            "status": "bottom"
        })),
    }
}

fn reduce_security_barrier(input: &KernelGateInput) -> KernelGateOutcome {
    let threshold = input
        .payload
        .pointer("/authority/threshold")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let members = input
        .payload
        .pointer("/authority/members")
        .and_then(Value::as_array)
        .map_or(0, Vec::len) as u64;
    if threshold == 0 || members == 0 || threshold > members {
        return KernelGateOutcome::error("schema_violation", "security_barrier_authority_invalid");
    }
    if threshold.saturating_mul(2) <= members {
        return KernelGateOutcome::error(
            "failed_precondition",
            "security_barrier_quorum_not_intersecting",
        );
    }
    KernelGateOutcome::projection(json!({"barrier": "accepted"}))
}

fn reduce_cba_bundle(input: &KernelGateInput) -> KernelGateOutcome {
    let basis_known = input
        .basis
        .get("target_seal_known")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if basis_known {
        return KernelGateOutcome::projection(json!({"basis_complete": true}));
    }
    let Some(bundle) = input
        .payload
        .get("cba_proof_bundle")
        .and_then(Value::as_object)
    else {
        return KernelGateOutcome::error("dependency_missing", "cba_basis_incomplete");
    };
    let Some(target) = bundle.get("target_seal_ref").and_then(Value::as_str) else {
        return KernelGateOutcome::error("dependency_missing", "cba_basis_incomplete");
    };
    let Some(seals) = bundle.get("seals").and_then(Value::as_array) else {
        return KernelGateOutcome::error("dependency_missing", "cba_basis_incomplete");
    };
    let mut graph = BTreeMap::<String, (String, BTreeSet<String>)>::new();
    for seal in seals {
        let Some(seal_ref) = seal.get("seal_ref").and_then(Value::as_str) else {
            return KernelGateOutcome::error("dependency_missing", "cba_basis_incomplete");
        };
        let Some(realm_id) = seal.get("realm_id").and_then(Value::as_str) else {
            return KernelGateOutcome::error("dependency_missing", "cba_basis_incomplete");
        };
        if graph
            .insert(
                seal_ref.to_owned(),
                (
                    realm_id.to_owned(),
                    string_set(seal.get("predecessor_refs")),
                ),
            )
            .is_some()
        {
            return KernelGateOutcome::error("dependency_missing", "cba_basis_incomplete");
        }
    }
    let Some((target_realm, _)) = graph.get(target) else {
        return KernelGateOutcome::error("dependency_missing", "cba_basis_incomplete");
    };
    if graph.values().any(|(realm_id, _)| realm_id != target_realm) {
        return KernelGateOutcome::error("dependency_missing", "cba_basis_incomplete");
    }
    let mut reachable = BTreeSet::new();
    let mut pending = vec![target.to_owned()];
    while let Some(seal_ref) = pending.pop() {
        if !reachable.insert(seal_ref.clone()) {
            continue;
        }
        if let Some((_, predecessors)) = graph.get(&seal_ref) {
            pending.extend(
                predecessors
                    .iter()
                    .filter(|predecessor| graph.contains_key(*predecessor))
                    .cloned(),
            );
        }
    }
    if reachable.len() != graph.len() {
        return KernelGateOutcome::error("dependency_missing", "cba_basis_incomplete");
    }
    KernelGateOutcome::projection(json!({"basis_complete": true}))
}

fn reduce_offline_publication(input: &KernelGateInput) -> KernelGateOutcome {
    let now = input
        .payload
        .pointer("/authorization_lease/evaluate_at_ms")
        .and_then(Value::as_i64);
    let issued = input
        .payload
        .pointer("/authorization_lease/issued_at_ms")
        .and_then(Value::as_i64);
    let expires = input
        .payload
        .pointer("/authorization_lease/expires_at_ms")
        .and_then(Value::as_i64);
    let receipt_received = input
        .pre_state
        .pointer("/ingress_receipt/received_at_ms")
        .and_then(Value::as_i64);
    let (Some(now), Some(issued), Some(expires)) = (now, issued, expires) else {
        return KernelGateOutcome::error("schema_violation", "authorization_lease_invalid");
    };
    let covered = issued <= now && now <= expires;
    let receipt_covered =
        receipt_received.is_some_and(|received| issued <= received && received <= expires);
    if !covered && !receipt_covered {
        return KernelGateOutcome::error("authorization_expired", "authorization_lease_expired");
    }
    KernelGateOutcome::projection(json!({"publication": "accepted"}))
}

fn reduce_lease_issue(input: &KernelGateInput) -> KernelGateOutcome {
    let device_id = input.payload.get("device_id").and_then(Value::as_str);
    let revoked = string_set(input.pre_state.get("revoked_devices"));
    if device_id.is_some_and(|device| revoked.contains(device)) {
        return KernelGateOutcome::error("capability_denied", "device_revoked");
    }
    KernelGateOutcome::projection(json!({"lease": "issued"}))
}

fn reduce_proposal(input: &KernelGateInput) -> KernelGateOutcome {
    let decision = input.payload.get("decision").and_then(Value::as_str);
    let defer_count = input
        .payload
        .get("defer_count")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let max_defers = input
        .basis
        .get("max_defers")
        .and_then(Value::as_u64)
        .unwrap_or(2);
    match decision {
        Some("include") => KernelGateOutcome::projection(json!({"proposal_status": "included"})),
        Some("reject") => KernelGateOutcome::projection(json!({"proposal_status": "rejected"})),
        Some("defer") if defer_count <= max_defers => KernelGateOutcome::projection(json!({
            "defer_count": defer_count,
            "proposal_status": "pending"
        })),
        Some("defer") => {
            KernelGateOutcome::error("schema_violation", "proposal_defer_limit_exceeded")
        }
        _ => KernelGateOutcome::error("schema_violation", "proposal_decision_invalid"),
    }
}

fn reduce_equivocation(input: &KernelGateInput) -> KernelGateOutcome {
    let signer_a = input.payload.pointer("/seal_a/signer_id");
    let signer_b = input.payload.pointer("/seal_b/signer_id");
    let seq_a = input.payload.pointer("/seal_a/notary_seq");
    let seq_b = input.payload.pointer("/seal_b/notary_seq");
    let digest_a = input.payload.pointer("/seal_a/canonical_body_digest");
    let digest_b = input.payload.pointer("/seal_b/canonical_body_digest");
    if signer_a == signer_b && seq_a == seq_b && digest_a != digest_b {
        return KernelGateOutcome::projection(json!({
            "reason": "notary_equivocation",
            "recovery_required": true,
            "status": "quarantine"
        }));
    }
    KernelGateOutcome::error("failed_precondition", "notary_fault_evidence_invalid")
}

fn notary_authorities(notary: &Value) -> Option<BTreeSet<String>> {
    match notary.get("kind").and_then(Value::as_str)? {
        "single_signer" => Some(
            notary
                .pointer("/signer/actor_id")
                .and_then(Value::as_str)
                .map(|actor_id| BTreeSet::from([actor_id.to_owned()]))
                .unwrap_or_default(),
        ),
        "open_set" | "threshold" => Some(notary_descriptor_actor_set(notary.get("members"))),
        "mixed" => {
            let mut members = notary_descriptor_actor_set(notary.get("recovery_members"));
            if let Some(actor_id) = notary.pointer("/signer/actor_id").and_then(Value::as_str) {
                members.insert(actor_id.to_owned());
            }
            Some(members)
        }
        _ => None,
    }
}

fn profile_name(notary: &Value) -> Option<&'static str> {
    match notary.get("kind").and_then(Value::as_str)? {
        "single_signer" | "threshold" | "mixed" => Some("single_chain"),
        "open_set" => Some("open_set"),
        _ => None,
    }
}

fn notary_descriptor_actor_set(value: Option<&Value>) -> BTreeSet<String> {
    value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|entry| entry.get("actor_id").and_then(Value::as_str))
        .map(ToOwned::to_owned)
        .collect()
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

fn parse_tagged_entry(value: &Value) -> Option<(String, Value)> {
    Some((
        value.get("tag")?.as_str()?.to_owned(),
        value.get("value")?.clone(),
    ))
}
