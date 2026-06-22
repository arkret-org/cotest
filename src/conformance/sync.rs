use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, anyhow, bail};
use serde_json::{Value, json};

use super::{
    canonical_json, load_fixture_value, looks_like_sha256_digest, required_field, sha256_prefixed,
    validate_profile, value_array, value_field_str, value_field_u64,
};
use crate::transcripts::record_vector_event;

pub fn run_sync_fixture_suite() -> Result<()> {
    let value = load_fixture_value("sync-fixture.json")?;
    validate_profile(&value, "ck.profile.sync_vectors.v1")?;
    validate_collection_projection(&value)?;
    validate_strand_discussion_timeline(&value)?;
    validate_snapshot_frontier_recovery(&value)?;
    validate_snapshot_inclusion_challenge(&value)?;
    validate_e2ee_pending(&value)?;
    Ok(())
}

fn validate_collection_projection(value: &Value) -> Result<()> {
    let projection = required_field(value, "collection_projection")?;
    if value_field_str(projection, "projection")? != "collection"
        || value_field_str(projection, "renderer")? != "board"
    {
        bail!("sync artifact collection projection discriminator drifted");
    }
    let state_digest = projection
        .pointer("/frontier/state_digest")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("sync artifact collection projection missing state_digest"))?;
    if !looks_like_sha256_digest(state_digest) {
        bail!("sync artifact collection projection state_digest was invalid");
    }
    let groups = value_array(
        required_field(projection, "groups")?,
        "collection_projection.groups",
    )?;
    if groups.is_empty() {
        bail!("sync artifact collection projection has no groups");
    }
    for group in groups {
        let items = value_array(required_field(group, "items")?, "group.items")?;
        for item in items {
            let object = required_field(item, "object")?;
            if !value_field_str(object, "id")?.starts_with("ck:strand:") {
                bail!("sync artifact collection item object id was not a strand");
            }
            let position = required_field(item, "position")?;
            let model = value_field_str(position, "model")?;
            if model != "relation" && model != "relation_container" {
                bail!("sync artifact collection item position model was invalid");
            }
            if !value_field_str(position, "relation_id")?.starts_with("ck:relation:") {
                bail!("sync artifact collection item relation id was invalid");
            }
        }
    }
    Ok(())
}

fn validate_strand_discussion_timeline(value: &Value) -> Result<()> {
    let timeline = required_field(value, "strand_discussion_timeline")?;
    if !value_field_str(timeline, "strand_id")?.starts_with("ck:strand:") {
        bail!("sync artifact strand discussion timeline strand id was invalid");
    }
    if !value_field_str(timeline, "next_cursor")?.starts_with("ck:cursor:") {
        bail!("sync artifact strand discussion timeline cursor was invalid");
    }
    for entry in value_array(
        required_field(timeline, "entries")?,
        "strand_discussion_timeline.entries",
    )? {
        if !value_field_str(entry, "event_id")?.starts_with("ck:event:") {
            bail!("sync artifact strand discussion timeline event id was invalid");
        }
        if !value_field_str(entry, "message_id")?.starts_with("ck:message:") {
            bail!("sync artifact strand discussion timeline message id was invalid");
        }
    }
    Ok(())
}

fn validate_snapshot_frontier_recovery(value: &Value) -> Result<()> {
    let snapshot = required_field(value, "snapshot_frontier_recovery")?;
    let state_digest = value_field_str(snapshot, "state_digest")?;
    if !looks_like_sha256_digest(state_digest) {
        bail!("sync artifact snapshot state_digest was invalid");
    }
    let root = snapshot
        .pointer("/event_set_commitment/root")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("sync artifact snapshot commitment missing digest root"))?;
    if !looks_like_sha256_digest(root) {
        bail!("sync artifact snapshot commitment root was invalid");
    }
    Ok(())
}

fn validate_snapshot_inclusion_challenge(value: &Value) -> Result<()> {
    let vector = required_field(value, "snapshot_inclusion_challenge")?;
    let vector_id = value_field_str(vector, "vector_id")?;
    if vector_id != "ck.vector.snapshot.inclusion_challenge.v1" {
        bail!("sync artifact snapshot inclusion challenge vector id drifted");
    }

    let manifest = required_field(vector, "manifest")?;
    if value_field_str(manifest, "security_class")? != "high_assurance" {
        bail!("snapshot inclusion challenge must pin high_assurance security_class");
    }
    let commitment = required_field(manifest, "event_set_commitment")?;
    if value_field_str(commitment, "algorithm")? != "merkle_event_set_v1" {
        bail!("snapshot inclusion challenge must exercise merkle_event_set_v1");
    }
    let entries = value_array(
        required_field(vector, "event_set_entries")?,
        "snapshot_inclusion_challenge.event_set_entries",
    )?;
    let computed_root = merkle_event_set_root(entries)?;
    let manifest_root = value_field_str(commitment, "root")?;
    if computed_root != manifest_root {
        bail!("snapshot inclusion challenge manifest root does not match event_set_entries");
    }
    if value_field_u64(commitment, "covered_event_count")? as usize != entries.len() {
        bail!("snapshot inclusion challenge covered_event_count drifted");
    }

    let base_challenge = required_field(vector, "base_challenge")?;
    let base_response = required_field(vector, "base_response")?;
    let cases = value_array(
        required_field(vector, "cases")?,
        "snapshot_inclusion_challenge.cases",
    )?;
    let mut seen = BTreeSet::new();
    for case in cases {
        let name = value_field_str(case, "name")?;
        seen.insert(name.to_owned());
        let mutation = value_field_str(case, "mutation")?;
        let mut challenge = base_challenge.clone();
        let mut response = base_response.clone();
        apply_snapshot_inclusion_mutation(mutation, &mut challenge, &mut response)?;
        let observed = evaluate_snapshot_inclusion_case(manifest, entries, &challenge, &response)?;
        assert_expected_subset(name, required_field(case, "expected")?, &observed)?;
        record_vector_event(
            &format!("sync.snapshot_inclusion_challenge.{name}"),
            &json!({"vector_id": vector_id, "case": case}),
            required_field(case, "expected")?,
            &observed,
        );
    }

    for required in [
        "valid_high_assurance_challenge",
        "insufficient_event_id_samples",
        "commitment_root_mismatch",
        "silent_actor_seq_gap",
    ] {
        if !seen.contains(required) {
            bail!("snapshot inclusion challenge fixture missing case {required}");
        }
    }
    Ok(())
}

fn evaluate_snapshot_inclusion_case(
    manifest: &Value,
    entries: &[Value],
    challenge: &Value,
    response: &Value,
) -> Result<Value> {
    let commitment = required_field(manifest, "event_set_commitment")?;
    let covered_event_count = value_field_u64(commitment, "covered_event_count")?;
    let minimum_event_samples = std::cmp::max(20, ceil_log2(covered_event_count));
    let samples = value_array(required_field(challenge, "samples")?, "challenge.samples")?;
    let mut sampled_event_ids = BTreeSet::new();
    let mut sampled_range_keys = BTreeSet::new();
    for sample in samples {
        match value_field_str(sample, "kind")? {
            "event_id" => {
                for event_id in value_array(required_field(sample, "event_ids")?, "event_ids")? {
                    sampled_event_ids.insert(
                        event_id
                            .as_str()
                            .ok_or_else(|| anyhow!("event_ids entry must be string"))?
                            .to_owned(),
                    );
                }
            }
            "actor_seq_range" => {
                sampled_range_keys.insert(range_key(sample)?);
            }
            other => bail!("snapshot inclusion challenge sample kind {other} is unsupported"),
        }
    }
    if sampled_event_ids.len() < minimum_event_samples as usize || sampled_range_keys.len() < 3 {
        return Ok(json!({
            "decision": "reject",
            "reason": "insufficient_challenge_samples",
        }));
    }

    let manifest_root = value_field_str(commitment, "root")?;
    let computed_root = merkle_event_set_root(entries)?;
    if value_field_str(response, "commitment_algorithm")?
        != value_field_str(commitment, "algorithm")?
        || value_field_str(response, "commitment_root")? != manifest_root
        || computed_root != manifest_root
    {
        return Ok(json!({"decision": "reject", "reason": "inclusion_proof_failed"}));
    }
    let signature = required_field(response, "issuer_signature")?;
    if signature.get("signature_valid").and_then(Value::as_bool) != Some(true)
        || signature
            .get("verification_authorized_at_created_at")
            .and_then(Value::as_bool)
            != Some(true)
    {
        return Ok(json!({"decision": "reject", "reason": "inclusion_proof_failed"}));
    }

    let entry_ids = entries
        .iter()
        .map(|entry| value_field_str(entry, "event_id").map(str::to_owned))
        .collect::<Result<BTreeSet<_>>>()?;
    let proofs = value_array(required_field(response, "proofs")?, "response.proofs")?;
    let mut event_proofs = BTreeSet::new();
    let mut range_proofs = BTreeMap::new();
    for proof in proofs {
        match value_field_str(proof, "kind")? {
            "event_id" => {
                event_proofs.insert(value_field_str(proof, "event_id")?.to_owned());
            }
            "actor_seq_range" => {
                range_proofs.insert(range_key(proof)?, proof);
            }
            other => bail!("snapshot inclusion proof kind {other} is unsupported"),
        }
    }
    for event_id in &sampled_event_ids {
        if !entry_ids.contains(event_id) || !event_proofs.contains(event_id) {
            return Ok(json!({"decision": "reject", "reason": "inclusion_proof_failed"}));
        }
    }
    for key in &sampled_range_keys {
        let Some(proof) = range_proofs.get(key) else {
            return Ok(json!({"decision": "reject", "reason": "inclusion_proof_failed"}));
        };
        let gap_attribution = value_array(
            required_field(proof, "gap_attribution")?,
            "proof.gap_attribution",
        )?;
        if gap_attribution.is_empty() {
            return Ok(json!({"decision": "reject", "reason": "inclusion_proof_failed"}));
        }
        for gap in gap_attribution {
            match value_field_str(gap, "category")? {
                "soft_failed" | "quarantined" | "conflict_records" => {}
                other => bail!("snapshot inclusion gap category {other} is unsupported"),
            }
        }
    }

    Ok(json!({"decision": "accept"}))
}

fn apply_snapshot_inclusion_mutation(
    mutation: &str,
    challenge: &mut Value,
    response: &mut Value,
) -> Result<()> {
    match mutation {
        "none" => {}
        "drop_one_event_id_sample" => {
            let samples = challenge
                .get_mut("samples")
                .and_then(Value::as_array_mut)
                .ok_or_else(|| anyhow!("challenge samples must be mutable array"))?;
            let Some(index) = samples
                .iter()
                .position(|sample| sample.get("kind").and_then(Value::as_str) == Some("event_id"))
            else {
                bail!("cannot drop event_id sample from challenge");
            };
            samples.remove(index);
        }
        "commitment_root_mismatch" => {
            response["commitment_root"] = Value::String(format!("sha256:{}", "0".repeat(64)));
        }
        "drop_gap_attribution" => {
            let proofs = response
                .get_mut("proofs")
                .and_then(Value::as_array_mut)
                .ok_or_else(|| anyhow!("response proofs must be mutable array"))?;
            let Some(proof) = proofs.iter_mut().find(|proof| {
                proof.get("kind").and_then(Value::as_str) == Some("actor_seq_range")
            }) else {
                bail!("cannot drop gap attribution from actor_seq_range proof");
            };
            proof["gap_attribution"] = Value::Array(Vec::new());
        }
        other => bail!("unknown snapshot inclusion mutation {other}"),
    }
    Ok(())
}

fn merkle_event_set_root(entries: &[Value]) -> Result<String> {
    if entries.is_empty() {
        return Ok(sha256_prefixed(&[]));
    }
    let mut sorted = Vec::with_capacity(entries.len());
    for entry in entries {
        sorted.push((
            value_field_str(entry, "actor_id")?.to_owned(),
            value_field_u64(entry, "actor_seq")?,
            value_field_str(entry, "event_id")?.to_owned(),
            entry,
        ));
    }
    sorted.sort_by(|left, right| (&left.0, left.1, &left.2).cmp(&(&right.0, right.1, &right.2)));

    let mut level = sorted
        .into_iter()
        .map(|(_, _, _, entry)| {
            let canonical = canonical_json(entry)?;
            Ok(sha256_prefixed(canonical.as_bytes()))
        })
        .collect::<Result<Vec<_>>>()?;
    while level.len() > 1 {
        let mut next = Vec::with_capacity((level.len() + 1) / 2);
        let mut chunks = level.chunks_exact(2);
        for pair in &mut chunks {
            let mut bytes = digest_bytes(&pair[0])?;
            bytes.extend_from_slice(&digest_bytes(&pair[1])?);
            next.push(sha256_prefixed(&bytes));
        }
        if let Some(tail) = chunks.remainder().first() {
            next.push(tail.clone());
        }
        level = next;
    }
    Ok(level.remove(0))
}

fn digest_bytes(value: &str) -> Result<Vec<u8>> {
    let hex = value
        .strip_prefix("sha256:")
        .ok_or_else(|| anyhow!("digest must use sha256 prefix"))?;
    if hex.len() != 64 {
        bail!("sha256 digest must have 64 hex chars");
    }
    (0..hex.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&hex[index..index + 2], 16)
                .map_err(|error| anyhow!("invalid sha256 digest hex: {error}"))
        })
        .collect()
}

fn range_key(value: &Value) -> Result<String> {
    Ok(format!(
        "{}:{}:{}",
        value_field_str(value, "actor_id")?,
        value_field_u64(value, "from_seq")?,
        value_field_u64(value, "to_seq")?
    ))
}

fn ceil_log2(value: u64) -> u64 {
    if value <= 1 {
        0
    } else {
        u64::BITS as u64 - (value - 1).leading_zeros() as u64
    }
}

fn assert_expected_subset(name: &str, expected: &Value, observed: &Value) -> Result<()> {
    let expected = expected
        .as_object()
        .ok_or_else(|| anyhow!("{name} expected value must be an object"))?;
    let observed = observed
        .as_object()
        .ok_or_else(|| anyhow!("{name} observed value must be an object"))?;
    for (key, expected_value) in expected {
        match observed.get(key) {
            Some(observed_value) if observed_value == expected_value => {}
            Some(observed_value) => {
                bail!("{name} expected {key}={expected_value}, got {observed_value}");
            }
            None => bail!("{name} observed result missing expected key {key}"),
        }
    }
    Ok(())
}

fn validate_e2ee_pending(value: &Value) -> Result<()> {
    let pending = required_field(value, "e2ee_decryption_pending")?;
    if pending
        .get("must_not_drop_timeline_entry")
        .and_then(Value::as_bool)
        != Some(true)
    {
        bail!("sync artifact no longer requires keeping pending E2EE entries");
    }
    Ok(())
}
