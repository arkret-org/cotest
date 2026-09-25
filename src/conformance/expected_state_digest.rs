//! `ak.vector.current_results.expected_state_digest.v1` — the one
//! `expected_state_digest` algorithm of `zh/sync/current-results.md` §2
//! (decisions 0113 and 0115).
//!
//! Every case recomputes its digest input `v` from the fixture inputs before
//! comparing anything: a single-value family digests its complete frozen value,
//! `actor_profile_realm_override` folds every assertion patch onto `{}` in
//! accepted commit order, and `member_identity_updates` folds the `replaces[]`
//! edges into the effective set and digests its exact signed payloads through
//! the SDK `member_identity_effective_set_digest`. Only then are the JCS bytes
//! and the `sha256:` digest compared with the published known answers.

use std::collections::BTreeSet;

use anyhow::{Context as _, Result, anyhow, bail, ensure};
use arkret_models_identity::member_identity_effective_set_digest;
use arkret_wire::EventId;
use serde_json::{Map, Value};

use super::{canonical_json, load_fixture_value, required_str, sha256_prefixed};

pub const VECTOR_ID_EXPECTED_STATE_DIGEST: &str =
    "ak.vector.current_results.expected_state_digest.v1";

const FIXTURE: &str = "expected-state-digest-kat-fixture.json";

const REGISTERED_CASES: [&str; 5] = [
    "single_value_family_complete_value",
    "realm_override_without_assertions",
    "realm_override_folded_patches",
    "member_identity_empty_effective_set",
    "member_identity_effective_set_after_replacement",
];

/// Execute every known answer of the fixture and return the number of cases.
pub fn run_expected_state_digest_known_answers() -> Result<usize> {
    let fixture = load_fixture_value(FIXTURE)?;
    ensure!(
        fixture["covers_vectors"]
            .as_array()
            .is_some_and(|ids| ids.iter().any(|id| id == VECTOR_ID_EXPECTED_STATE_DIGEST)),
        "{FIXTURE} does not cover {VECTOR_ID_EXPECTED_STATE_DIGEST}"
    );
    ensure!(
        fixture["algorithm"]["domain_prefix"].is_null(),
        "{FIXTURE}: the expected_state_digest algorithm has no domain prefix"
    );
    let cases = fixture["cases"]
        .as_array()
        .context("expected_state_digest fixture cases")?;
    let names = cases
        .iter()
        .map(|case| required_str(case, "name"))
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        names == REGISTERED_CASES,
        "{FIXTURE}: case set drifted: {names:?}"
    );
    for case in cases {
        run_case(case).with_context(|| format!("{FIXTURE}: {}", case["name"]))?;
    }
    Ok(cases.len())
}

fn run_case(case: &Value) -> Result<()> {
    let family = required_str(case, "result_family")?;
    let inputs = &case["inputs"];
    let (value, sdk_digest) = match family {
        "realm_authority_root" => (inputs["frozen_value"].clone(), None),
        "actor_profile_realm_override" => (fold_override(inputs)?, None),
        "member_identity_updates" => {
            let (value, digest) = fold_member_identity(inputs)?;
            (value, Some(digest))
        }
        other => bail!("unregistered result family {other}"),
    };
    ensure!(
        value == case["digest_input_value"],
        "the recomputed digest input differs from the published value"
    );
    let canonical = canonical_json(&value)?;
    ensure!(
        canonical == required_str(case, "canonical_utf8")?,
        "SDK JCS bytes differ from the fixture"
    );
    let digest = sha256_prefixed(canonical.as_bytes());
    ensure!(
        digest == required_str(case, "expected_digest")?,
        "digest {digest} differs from the published known answer"
    );
    if let Some(sdk_digest) = sdk_digest {
        ensure!(
            sdk_digest == digest,
            "SDK member_identity_effective_set_digest {sdk_digest} differs from {digest}"
        );
    }
    Ok(())
}

/// Apply every assertion patch onto `{}` in accepted commit order.
fn fold_override(inputs: &Value) -> Result<Value> {
    let mut folded = Map::new();
    for assertion in inputs["assertions_in_commit_order"]
        .as_array()
        .context("assertions_in_commit_order")?
    {
        let patch = assertion["patch"].as_object().context("assertion patch")?;
        for (path, op) in patch {
            apply_path(&mut folded, path, op)?;
        }
    }
    Ok(Value::Object(folded))
}

fn apply_path(target: &mut Map<String, Value>, path: &str, op: &Value) -> Result<()> {
    let (unset, value) = match op.as_object().and_then(|object| object.get("$op")) {
        Some(kind) if kind == "unset" => (true, None),
        Some(kind) if kind == "set" => (false, op.get("value").cloned()),
        Some(kind) => bail!("patch op {kind} is not a display-path fold operation"),
        None => (false, Some(op.clone())),
    };
    let segments = path.split('.').collect::<Vec<_>>();
    let (last, parents) = segments.split_last().context("empty patch path")?;
    let mut current = target;
    for segment in parents {
        let entry = current
            .entry((*segment).to_owned())
            .or_insert_with(|| Value::Object(Map::new()));
        current = entry
            .as_object_mut()
            .ok_or_else(|| anyhow!("patch path {path} crosses a non-object value"))?;
    }
    if unset {
        current.remove(*last);
    } else {
        current.insert((*last).to_owned(), value.context("set without a value")?);
    }
    Ok(())
}

/// Fold the `replaces[]` edges into the effective set and return the ordered
/// array of exact payloads plus the SDK digest over the same set.
fn fold_member_identity(inputs: &Value) -> Result<(Value, String)> {
    let updates = inputs["updates"].as_array().context("updates")?;
    let mut carriers = Vec::with_capacity(updates.len());
    for update in updates {
        let event_id = required_str(update, "event_id")?;
        let carrier =
            sha256_prefixed(canonical_json(&update["payload"]["identity_payload"])?.as_bytes());
        carriers.push((event_id, carrier));
    }
    let mut replaced = BTreeSet::new();
    for update in updates {
        for edge in update["payload"]["replaces"]
            .as_array()
            .into_iter()
            .flatten()
        {
            let target = required_str(edge, "event_id")?;
            let digest = required_str(edge, "payload_digest")?;
            if carriers
                .iter()
                .any(|(event_id, carrier)| *event_id == target && carrier == digest)
            {
                replaced.insert(target.to_owned());
            }
        }
    }
    let mut effective = Vec::new();
    for update in updates {
        let event_id = required_str(update, "event_id")?;
        if replaced.contains(event_id) {
            continue;
        }
        effective.push((
            EventId::new(event_id.to_owned()).map_err(|error| anyhow!("{event_id}: {error}"))?,
            update["payload"].clone(),
        ));
    }
    let refs = effective
        .iter()
        .map(|(event_id, payload)| (event_id, payload))
        .collect::<Vec<_>>();
    let sdk_digest = member_identity_effective_set_digest(&refs)
        .map_err(|error| anyhow!("member_identity_effective_set_digest: {error}"))?;
    effective.sort_by(|a, b| a.0.as_str().cmp(b.0.as_str()));
    let value = Value::Array(effective.into_iter().map(|(_, payload)| payload).collect());
    Ok((value, sdk_digest))
}
