//! Direct history-governance traversal and history-access ratchet checks.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, anyhow, bail};
use arkret_models_collaboration::governance::realm_lifecycle::HistoryAccessPayload;
use arkret_models_collaboration::history_key::{
    HistoryGovernanceTraversalIntent, HistoryGovernanceTraversalRetention,
    PeerHistoryTraversalAccess, SelfHistoryTraversalAccess, response_capability_commitment,
};
use arkret_wire::HistoryAccess;
use serde_json::{Value, json};

use super::load_artifact_json;
use crate::transcripts::record_vector_event;

pub fn run_history_key_direct_traversal_suite() -> Result<()> {
    let fixture = load_artifact_json("fixtures/history-key-recovery-fixture.json")?;
    let retention: HistoryGovernanceTraversalRetention = serde_json::from_value(
        fixture
            .pointer("/direct_traversal_kat/member_retention")
            .cloned()
            .context("history-key fixture omits member_retention")?,
    )?;
    retention.validate_digest()?;

    let archive_intent: HistoryGovernanceTraversalIntent = serde_json::from_value(
        fixture
            .pointer("/direct_traversal_kat/organization_recovery_intent")
            .cloned()
            .context("history-key fixture omits organization_recovery_intent")?,
    )?;
    archive_intent.validate()?;

    let self_request: SelfHistoryTraversalAccess = serde_json::from_value(json!({
        "kind": "request_receipt",
        "request_receipt_digest": format!("sha256:{}", "11".repeat(32))
    }))?;
    let self_archive: SelfHistoryTraversalAccess = serde_json::from_value(json!({
        "kind": "archive_replica",
        "archive_replica_digest": format!("sha256:{}", "22".repeat(32))
    }))?;
    let peer_archive: PeerHistoryTraversalAccess = serde_json::from_value(json!({
        "kind": "pending_archive_replica",
        "pending_archive_replica_digest": format!("sha256:{}", "33".repeat(32))
    }))?;
    for access in [
        serde_json::to_value(self_request)?,
        serde_json::to_value(self_archive)?,
        serde_json::to_value(peer_archive)?,
    ] {
        if access.get("kind").and_then(Value::as_str).is_none() {
            bail!("history traversal access lost its closed branch discriminator");
        }
    }

    let negative_cases = fixture
        .pointer("/direct_traversal_kat/negative_cases")
        .and_then(Value::as_array)
        .context("history-key fixture omits direct traversal negative cases")?;
    for expected_name in [
        "hidden_predecessor",
        "target_does_not_dominate_current",
        "branch_stops_before_base",
        "base_leaf_not_consumed",
        "surplus_descriptor",
    ] {
        let case = negative_cases
            .iter()
            .find(|case| case["name"].as_str() == Some(expected_name))
            .with_context(|| format!("history traversal fixture omits {expected_name}"))?;
        let expected_error = case["expected_error"].as_str().with_context(|| {
            format!("history traversal case {expected_name} omits expected_error")
        })?;
        if !case["actual_errors"].as_array().is_some_and(|errors| {
            errors
                .iter()
                .any(|error| error.as_str() == Some(expected_error))
        }) {
            bail!("history traversal case {expected_name} did not produce {expected_error}");
        }
    }
    verify_direct_cut_graph_mutations(
        fixture
            .pointer("/direct_traversal_kat/direct_cut")
            .context("history-key fixture omits direct_cut")?,
    )?;

    HistoryAccessPayload::initialize(HistoryAccess::AllHistoryForCurrentMembers).validate()?;
    HistoryAccessPayload::tighten().validate()?;
    HistoryAccessPayload {
        from: Some(HistoryAccess::SinceJoin),
        to: HistoryAccess::AllHistoryForCurrentMembers,
        reason: None,
    }
    .validate()
    .expect_err("history access widening must fail closed");

    let capability_kat = fixture
        .pointer("/history_response_capability_kat")
        .context("history-key fixture omits history response capability KAT")?;
    let capability = capability_kat["response_capability_b64u"]
        .as_str()
        .context("history response capability KAT omits capability")?;
    if capability_kat["decoded_length"].as_u64() != Some(32)
        || response_capability_commitment(capability)?.as_ref()
            != capability_kat["expected_response_capability_commitment"]
                .as_str()
                .context("history response capability KAT omits commitment")?
        || capability_kat
            .pointer("/surface/read")
            .and_then(Value::as_str)
            != Some("POST /_arkret/self/history-key-responses/read")
        || capability_kat
            .pointer("/surface/ack")
            .and_then(Value::as_str)
            != Some("POST /_arkret/self/history-key-responses/ack")
        || capability_kat
            .pointer("/surface/request_locator_in_path_query_or_body")
            .and_then(Value::as_bool)
            != Some(false)
    {
        bail!("history response capability KAT drifted");
    }
    let capability_negative_cases = capability_kat["negative_cases"]
        .as_array()
        .context("history response capability KAT omits negative cases")?;
    for required in [
        "unknown_expired_gc_and_unauthorized_same_not_found_shape",
        "stream_a_capability_cannot_read_or_ack_stream_b",
        "stream_a_capability_cannot_consume_stream_b_ack_token",
        "commitment_collision_resampled_before_any_durable_write",
        "exact_create_retry_returns_byte_identical_sealed_capability",
    ] {
        if !capability_negative_cases
            .iter()
            .any(|case| case.as_str() == Some(required))
        {
            bail!("history response capability KAT omits {required}");
        }
    }

    let scale_cases = fixture
        .pointer("/streaming_direct_traversal_scale_kats")
        .and_then(Value::as_array)
        .context("history-key fixture omits streaming scale KATs")?;
    let expected_scale = [
        (
            26_298_u64,
            26_299_u64,
            7_416_182_u64,
            "sha256:c702bba991ec05314014566a763db2c99aeecba920b02fb58cbd0347277aed45",
        ),
        (
            65_536_u64,
            65_537_u64,
            18_481_298_u64,
            "sha256:1d1377c13c8b58b688f887be4d7df282b12aa0597424360d57b74fd06e78da19",
        ),
    ];
    for (epoch_count, seal_count, descriptor_bytes, aggregate_digest) in expected_scale {
        let case = scale_cases
            .iter()
            .find(|case| case["epoch_count"].as_u64() == Some(epoch_count))
            .with_context(|| format!("history scale fixture omits {epoch_count} epochs"))?;
        if case["verified_epoch_count"].as_u64() != Some(epoch_count)
            || case["resolved_control_event_count"].as_u64() != Some(epoch_count)
            || case["resolved_availability_receipt_count"].as_u64() != Some(epoch_count)
            || case["visited_seal_count"].as_u64() != Some(seal_count)
            || case["max_live_descriptor_bytes"].as_u64() != Some(282)
            || case["descriptor_canonical_bytes"].as_u64() != Some(descriptor_bytes)
            || case["descriptor_stream_aggregate_digest"].as_str() != Some(aggregate_digest)
            || case["outbox_write_count"].as_u64() != Some(0)
        {
            bail!("history scale fixture drifted at {epoch_count} epochs");
        }
    }
    let over_limit = fixture
        .pointer("/streaming_direct_traversal_scale_negative_kats/0")
        .context("history-key fixture omits 65,537-epoch prewrite rejection")?;
    if over_limit["epoch_count"].as_u64() != Some(65_537)
        || over_limit["rejected_before_staging"].as_bool() != Some(true)
        || over_limit["journal_rows"].as_u64() != Some(0)
        || over_limit["resolved_objects"].as_u64() != Some(0)
        || over_limit["outbox_writes"].as_u64() != Some(0)
    {
        bail!("history 65,537-epoch prewrite rejection drifted");
    }

    record_vector_event(
        "history_key.direct_traversal",
        &json!({"fixture": "history-key-recovery-fixture.json"}),
        &json!({
            "member_intent_digest_valid": true,
            "organization_recovery_intent_valid": true,
            "closed_access_branches_valid": true,
            "closed_cut_negative_cases_valid": true,
            "history_access_widening_rejected": true,
            "response_capability_kat_valid": true,
            "streaming_scale_kats_valid": true,
        }),
        &json!({"status": "validated"}),
    );
    Ok(())
}

#[derive(Clone, Debug)]
struct DirectCutSeal {
    seal_ref: String,
    predecessor_refs: Vec<String>,
}

fn verify_direct_cut_graph_mutations(cut: &Value) -> Result<()> {
    let basis = |name: &str| -> Result<Vec<String>> {
        cut.pointer(&format!("/{name}/leaves"))
            .and_then(Value::as_array)
            .with_context(|| format!("direct cut omits {name}.leaves"))?
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| anyhow!("direct cut {name} leaf is not text"))
            })
            .collect()
    };
    let base = basis("trusted_history_base_basis")?;
    let current = basis("trusted_current_basis")?;
    let target = basis("target_basis")?;
    let seals = cut
        .get("seals")
        .and_then(Value::as_array)
        .context("direct cut omits seals[]")?
        .iter()
        .map(|value| {
            Ok(DirectCutSeal {
                seal_ref: value["seal_ref"]
                    .as_str()
                    .context("direct cut seal_ref is not text")?
                    .to_owned(),
                predecessor_refs: value["predecessor_refs"]
                    .as_array()
                    .context("direct cut predecessor_refs is not an array")?
                    .iter()
                    .map(|predecessor| {
                        predecessor
                            .as_str()
                            .map(str::to_owned)
                            .context("direct cut predecessor ref is not text")
                    })
                    .collect::<Result<Vec<_>>>()?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    if !direct_cut_errors(&base, &current, &target, &seals).is_empty() {
        bail!("canonical direct cut does not satisfy its closed interval");
    }

    let mut hidden = seals.clone();
    hidden.retain(|seal| seal.seal_ref != current[0]);
    require_cut_error(&base, &current, &target, &hidden, "dependency_missing")?;

    require_cut_error(
        &base,
        &current,
        &target[..1],
        &seals,
        "trusted_current_not_dominated",
    )?;

    let mut early_stop = seals.clone();
    let branch = early_stop
        .iter_mut()
        .find(|seal| seal.seal_ref == current[0])
        .context("direct cut lacks the first current leaf")?;
    branch.predecessor_refs.clear();
    require_cut_error(
        &base,
        &current,
        &target,
        &early_stop,
        "interval_stops_before_base",
    )?;

    require_cut_error(
        &base,
        &current[..1],
        &target[..1],
        &seals,
        "base_leaf_not_consumed",
    )?;

    let mut surplus = seals.clone();
    surplus.push(DirectCutSeal {
        seal_ref: format!("ak:seal:sha256:{}", "ee".repeat(32)),
        predecessor_refs: Vec::new(),
    });
    require_cut_error(&base, &current, &target, &surplus, "surplus_descriptor")
}

fn require_cut_error(
    base: &[String],
    current: &[String],
    target: &[String],
    seals: &[DirectCutSeal],
    expected: &'static str,
) -> Result<()> {
    let errors = direct_cut_errors(base, current, target, seals);
    if !errors.contains(expected) {
        bail!("direct cut mutation did not produce {expected}: {errors:?}");
    }
    Ok(())
}

fn direct_cut_errors(
    base: &[String],
    current: &[String],
    target: &[String],
    seals: &[DirectCutSeal],
) -> BTreeSet<&'static str> {
    let mut errors = BTreeSet::new();
    let mut by_ref = BTreeMap::new();
    for seal in seals {
        if by_ref.insert(seal.seal_ref.as_str(), seal).is_some() {
            errors.insert("duplicate_descriptor");
        }
    }
    let base = base.iter().map(String::as_str).collect::<BTreeSet<_>>();
    let current = current.iter().map(String::as_str).collect::<BTreeSet<_>>();
    let mut visited = BTreeSet::new();
    let mut consumed_base = BTreeSet::new();
    let mut stack = target.iter().map(String::as_str).collect::<Vec<_>>();
    while let Some(seal_ref) = stack.pop() {
        if !visited.insert(seal_ref) {
            continue;
        }
        let Some(seal) = by_ref.get(seal_ref) else {
            errors.insert("dependency_missing");
            continue;
        };
        if base.contains(seal_ref) {
            consumed_base.insert(seal_ref);
            continue;
        }
        if seal.predecessor_refs.is_empty() {
            errors.insert("interval_stops_before_base");
        }
        stack.extend(seal.predecessor_refs.iter().map(String::as_str));
    }
    if !current.is_subset(&visited) {
        errors.insert("trusted_current_not_dominated");
    }
    if consumed_base != base {
        errors.insert("base_leaf_not_consumed");
    }
    let described = by_ref.keys().copied().collect::<BTreeSet<_>>();
    if described != visited {
        errors.insert("surplus_descriptor");
    }
    errors
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_traversal_suite_uses_the_shared_wire_types() {
        run_history_key_direct_traversal_suite().unwrap();
    }
}
