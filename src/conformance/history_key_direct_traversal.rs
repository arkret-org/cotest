//! Direct history-governance traversal and history-access ratchet checks.

use std::collections::BTreeSet;

use anyhow::{Context, Result, anyhow, bail};
use arkret_models_collaboration::governance::realm_lifecycle::HistoryAccessPayload;
use arkret_models_collaboration::history_key::{
    AuthorizationIncarnation, HistoryGovernanceTraversalIntent,
    HistoryGovernanceTraversalRetention, PeerHistoryTraversalAccess, SelfHistoryTraversalAccess,
    response_capability_commitment,
};
use arkret_state::direct_traversal::{
    BoundedDirectTraversalJournal, DirectCutDescriptorIndex, DirectCutRequest,
    SealPredecessorDescriptor, discover_direct_cut,
};
use arkret_wire::{HistoryAccess, RealmId, SealBasis, SealId};
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
    verify_direct_cut_graph_mutations(
        fixture
            .pointer("/direct_traversal_kat/direct_cut")
            .context("history-key fixture omits direct_cut")?,
        negative_cases,
    )?;
    verify_since_join_lineage(
        fixture
            .pointer("/direct_traversal_kat/since_join_lineage")
            .context("history-key fixture omits since_join_lineage")?,
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
            "since_join_lineage_valid": true,
            "history_access_widening_rejected": true,
            "response_capability_kat_valid": true,
            "streaming_scale_kats_valid": true,
        }),
        &json!({"status": "validated"}),
    );
    Ok(())
}

/// Fixture-declared reverse-traversal descriptor.
#[derive(Clone, Debug)]
struct DirectCutSeal {
    seal_ref: String,
    predecessor_refs: Vec<String>,
}

impl DirectCutSeal {
    fn into_descriptor(self) -> Result<SealPredecessorDescriptor> {
        Ok(SealPredecessorDescriptor {
            seal_ref: SealId::new(self.seal_ref)?,
            predecessor_refs: self
                .predecessor_refs
                .into_iter()
                .map(|value| Ok(SealId::new(value)?))
                .collect::<Result<Vec<_>>>()?,
        })
    }
}

const UNREACHABLE_SEAL_REF: &str =
    "ak:seal:sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";

const TRAVERSAL_REALM_ID: &str = "ak:realm:AYw-PHWIOTuZhm-EenZx-cCbOziC8pNCrh10oRfqiEmN";

fn seal_basis(leaves: &[String]) -> Result<SealBasis> {
    let mut leaves = leaves
        .iter()
        .map(|value| Ok(SealId::new(value.clone())?))
        .collect::<Result<Vec<_>>>()?;
    leaves.sort();
    let basis = SealBasis { leaves };
    basis.validate_protocol_bounds()?;
    Ok(basis)
}

/// Run one cut through the SDK verifier and return its canonical error names.
fn cut_errors(
    base: &[String],
    current: &[String],
    target: &[String],
    seals: &[DirectCutSeal],
) -> Result<BTreeSet<String>> {
    let request = DirectCutRequest {
        realm_id: RealmId::new(TRAVERSAL_REALM_ID)?,
        trusted_history_base_basis: seal_basis(base)?,
        trusted_current_basis: seal_basis(current)?,
        target_basis: seal_basis(target)?,
    };
    let source = DirectCutDescriptorIndex::new(
        seals
            .iter()
            .cloned()
            .map(DirectCutSeal::into_descriptor)
            .collect::<Result<Vec<_>>>()?,
    )?;
    let mut journal = BoundedDirectTraversalJournal::default();
    Ok(discover_direct_cut(&request, &source, &mut journal)?
        .error_names()
        .into_iter()
        .map(str::to_owned)
        .collect())
}

/// Drive the SDK direct-traversal verifier against the fixture's canonical cut
/// and its five declared negative mutations. The assertion is equality with each
/// case's complete `actual_errors` set, not mere containment, so a verifier that
/// over- or under-reports fails here.
fn verify_direct_cut_graph_mutations(cut: &Value, negative_cases: &[Value]) -> Result<()> {
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
    if !cut_errors(&base, &current, &target, &seals)?.is_empty() {
        bail!("canonical direct cut does not satisfy its closed interval");
    }

    let hidden_ref = current
        .first()
        .context("direct cut lacks a first current leaf")?
        .clone();

    // The responder simply omits one interval descriptor while its successor
    // still points at it.
    let mut hidden_predecessor = seals.clone();
    hidden_predecessor.retain(|seal| seal.seal_ref != hidden_ref);

    // The same branch is additionally truncated, so the surviving successor is
    // predecessor-free without being a base leaf.
    let mut branch_stops_before_base = hidden_predecessor.clone();
    for seal in &mut branch_stops_before_base {
        seal.predecessor_refs.retain(|value| *value != hidden_ref);
    }

    let mut extended_base = base.clone();
    extended_base.push(UNREACHABLE_SEAL_REF.to_owned());

    let mut surplus = seals.clone();
    surplus.push(DirectCutSeal {
        seal_ref: UNREACHABLE_SEAL_REF.to_owned(),
        predecessor_refs: Vec::new(),
    });

    let disjoint_current = vec![UNREACHABLE_SEAL_REF.to_owned()];

    let mutations: [(&str, &[String], &[String], &[String], &[DirectCutSeal]); 5] = [
        (
            "hidden_predecessor",
            &base,
            &current,
            &target,
            &hidden_predecessor,
        ),
        (
            "target_does_not_dominate_current",
            &base,
            &disjoint_current,
            &target,
            &seals,
        ),
        (
            "branch_stops_before_base",
            &base,
            &current,
            &target,
            &branch_stops_before_base,
        ),
        (
            "base_leaf_not_consumed",
            &extended_base,
            &current,
            &target,
            &seals,
        ),
        ("surplus_descriptor", &base, &current, &target, &surplus),
    ];
    for (name, base, current, target, seals) in mutations {
        let case = negative_cases
            .iter()
            .find(|case| case["name"].as_str() == Some(name))
            .with_context(|| format!("history traversal fixture omits {name}"))?;
        let expected_error = case["expected_error"]
            .as_str()
            .with_context(|| format!("history traversal case {name} omits expected_error"))?;
        let expected_errors = case["actual_errors"]
            .as_array()
            .with_context(|| format!("history traversal case {name} omits actual_errors"))?
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| anyhow!("history traversal case {name} error is not text"))
            })
            .collect::<Result<BTreeSet<_>>>()?;
        let observed = cut_errors(base, current, target, seals)?;
        if observed != expected_errors {
            bail!(
                "SDK direct traversal for {name} produced {observed:?}, fixture declares {expected_errors:?}"
            );
        }
        if !observed.contains(expected_error) {
            bail!("SDK direct traversal for {name} did not produce {expected_error}");
        }
    }
    Ok(())
}

/// Check the fixture's `since_join` lineage against the only two admissible
/// `join_epoch` sources: the winning Commit that consumes the exact Add, and a
/// proven Genesis initial leaf. Local clocks and current epoch stay forbidden.
fn verify_since_join_lineage(lineage: &Value) -> Result<()> {
    let incarnation: AuthorizationIncarnation =
        serde_json::from_value(lineage["add_target_authorization_incarnation"].clone())?;
    let AuthorizationIncarnation::Realm {
        realm_membership_incarnation_ref,
    } = &incarnation
    else {
        bail!("since_join lineage fixture is not a Realm incarnation");
    };
    if lineage["membership_incarnation_ref"].as_str()
        != Some(realm_membership_incarnation_ref.as_str())
    {
        bail!("since_join lineage incarnation refs disagree");
    }
    let expected = lineage["expected_join_epoch"]
        .as_u64()
        .context("since_join lineage omits expected_join_epoch")?;
    if lineage["winning_commit_next_epoch"].as_u64() != Some(expected) {
        bail!("since_join lineage expected_join_epoch is not the winning Commit next_epoch");
    }
    let winning_commit_ref = lineage["winning_commit_ref"]
        .as_str()
        .context("since_join lineage omits winning_commit_ref")?;
    let add_proposal_ref = lineage["add_proposal_ref"]
        .as_str()
        .context("since_join lineage omits add_proposal_ref")?;
    if winning_commit_ref == add_proposal_ref
        || !lineage["winning_commit_proposal_refs"]
            .as_array()
            .context("since_join lineage omits winning_commit_proposal_refs")?
            .iter()
            .any(|value| value.as_str() == Some(add_proposal_ref))
    {
        bail!("since_join lineage winning Commit does not consume the exact Add proposal");
    }
    for forbidden in lineage["forbidden_derivations"]
        .as_array()
        .context("since_join lineage omits forbidden_derivations")?
    {
        let forbidden = forbidden
            .as_str()
            .context("since_join forbidden derivation is not text")?;
        if !matches!(
            forbidden,
            "joined_at" | "received_at" | "latest_epoch" | "current_session_device"
        ) {
            bail!("since_join lineage declares an unknown forbidden derivation {forbidden}");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_traversal_suite_uses_the_shared_wire_types() {
        run_history_key_direct_traversal_suite().unwrap();
    }
}
