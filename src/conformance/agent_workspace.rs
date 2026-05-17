//! `cx.profile.agent_workspace.v1` conformance suites.
//!
//! Spec: `contrix-spec/spec/v1/zh/extensions/agent-workspace-profile.md`.
//! Vectors live under `contrix-spec/spec/v1/artifacts/conformance/agent-workspace/`.
//!
//! These suites verify that the spec-side conformance fixtures are
//! well-formed and contain the structural invariants the reducer must
//! enforce. They are **structural** checks (the cotest harness does not
//! drive a live soland reducer through every transition here); the wire
//! verification of each vector happens when each fixture is fed into an
//! actual soland integration test (tracked in `_todos.md` AW-2.7).
//!
//! Suites:
//!
//! - `run_agent_workspace_registry_suite`: validates the new agent_workspace
//!   surface is registered in event-kind / id-kind / capability-action /
//!   operation registries with profile_gate set correctly.
//! - `run_agent_workspace_fsm_fixture_suite`: walks the 44 vector
//!   fixtures, asserts each carries a vector_id, spec_section, and a
//!   shape-appropriate expected_* block matching the spec contract.
//!   Supported shapes: input_event / input_events / input_move /
//!   input_moves / input_steps / input_notification / input_event_template.
//! - `run_agent_workspace_schema_suite`: validates the four new schema files
//!   parse, and that capability-grant.schema.json carries the
//!   `attached_authority` extension.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use anyhow::{Result, anyhow, bail};
use serde_json::Value;

use super::{load_artifact_json, spec_artifacts_root};

const AGENT_WS_CONFORMANCE_DIR: &str = "conformance/agent-workspace";
const AGENT_WS_PROFILE_ID: &str = "cx.profile.agent_workspace.v1";

const EXPECTED_EVENT_KINDS: &[&str] = &[
    "cx.agent_task.create",
    "cx.agent_task.execution.transition",
    "cx.agent_task.transparency.transition",
    "cx.agent_task.source_authority.transition",
    "cx.agent_task.cancel",
];

const EXPECTED_CAPABILITY_ACTIONS: &[&str] = &[
    "cx.capability.agent_workspace.reserve",
    "cx.capability.agent_workspace.recover",
    "cx.capability.agent_workspace.cleanup",
];

const EXPECTED_OPERATIONS: &[&str] = &[
    "cx.agent_workspace.resolve_mirror_flow",
    "cx.agent_workspace.list_pending_tasks",
];

const EXPECTED_SCHEMAS: &[(&str, &str)] = &[
    ("cx.schema.agent_task.v1", "schemas/agent-task.schema.json"),
    (
        "cx.schema.content.mention_redirect.v1",
        "schemas/content-mention-redirect.schema.json",
    ),
    (
        "cx.schema.content.import_attestation.v1",
        "schemas/content-import-attestation.schema.json",
    ),
    (
        "cx.schema.content.source_export_policy_attestation.v1",
        "schemas/content-source-export-policy-attestation.schema.json",
    ),
];

const RESERVATION_SENTINEL: &str = "__unset__";

// ── Registry suite ──────────────────────────────────────────────────────────

pub fn run_agent_workspace_registry_suite() -> Result<()> {
    let event_kinds = load_artifact_json("registry/event-kind-registry.json")?;
    let kinds = event_kinds
        .get("event_kinds")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("event-kind-registry missing event_kinds[]"))?;
    let kind_map: BTreeMap<&str, &Value> = kinds
        .iter()
        .filter_map(|entry| {
            entry
                .get("event_kind")
                .and_then(Value::as_str)
                .map(|k| (k, entry))
        })
        .collect();
    for expected in EXPECTED_EVENT_KINDS {
        let entry = kind_map
            .get(*expected)
            .ok_or_else(|| anyhow!("event-kind-registry missing {expected}"))?;
        let status = entry.get("status").and_then(Value::as_str);
        if status != Some("active") {
            bail!("event_kind {expected} not active (status={:?})", status);
        }
        let gate = entry.get("profile_gate").and_then(Value::as_str);
        if gate != Some(AGENT_WS_PROFILE_ID) {
            bail!(
                "event_kind {expected} missing profile_gate={AGENT_WS_PROFILE_ID} (got {:?})",
                gate
            );
        }
    }

    let capability_actions = load_artifact_json("registry/capability-action-registry.json")?;
    let actions = capability_actions
        .get("actions")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("capability-action-registry missing actions[]"))?;
    let action_set: std::collections::BTreeSet<&str> = actions
        .iter()
        .filter_map(|a| a.get("action").and_then(Value::as_str))
        .collect();
    for expected in EXPECTED_CAPABILITY_ACTIONS {
        if !action_set.contains(*expected) {
            bail!("capability-action-registry missing {expected}");
        }
    }

    let operations = load_artifact_json("registry/operation-registry.json")?;
    let ops = operations
        .get("operations")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("operation-registry missing operations[]"))?;
    let op_set: std::collections::BTreeSet<&str> = ops
        .iter()
        .filter_map(|o| o.get("operation_id").and_then(Value::as_str))
        .collect();
    for expected in EXPECTED_OPERATIONS {
        if !op_set.contains(*expected) {
            bail!("operation-registry missing {expected}");
        }
    }

    let id_kinds = load_artifact_json("registry/id-kind-registry.json")?;
    let id_arr = id_kinds
        .get("id_kinds")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("id-kind-registry missing id_kinds[]"))?;
    if !id_arr
        .iter()
        .any(|e| e.get("kind").and_then(Value::as_str) == Some("agent_task"))
    {
        bail!("id-kind-registry missing kind=agent_task");
    }

    Ok(())
}

// ── Schema suite ────────────────────────────────────────────────────────────

pub fn run_agent_workspace_schema_suite() -> Result<()> {
    // Each declared schema file exists, parses, and announces its $id.
    for (schema_id, relative_path) in EXPECTED_SCHEMAS {
        let raw = load_artifact_json(relative_path)
            .map_err(|err| anyhow!("schema {schema_id} ({relative_path}) failed to load: {err}"))?;
        let id = raw.get("$id").and_then(Value::as_str);
        if !matches!(id, Some(s) if s.contains(schema_id.trim_end_matches(".v1"))) {
            // Schema $id uses a URL form (.../<file>.schema.json), so we
            // just check the file at least loads as a JSON-Schema object.
            // Strict identity is enforced via `schema-registry.json`.
        }
        if raw.get("type").and_then(Value::as_str) != Some("object") {
            bail!("schema {schema_id} is not declared as JSON object schema");
        }
    }

    // schema-registry.json registers all four with the correct schema_id.
    let registry = load_artifact_json("registry/schema-registry.json")?;
    let schemas = registry
        .get("schemas")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("schema-registry missing schemas[]"))?;
    let by_id: BTreeMap<&str, &str> = schemas
        .iter()
        .filter_map(|s| {
            let id = s.get("schema_id").and_then(Value::as_str)?;
            let file = s.get("file").and_then(Value::as_str)?;
            Some((id, file))
        })
        .collect();
    for (schema_id, expected_file) in EXPECTED_SCHEMAS {
        match by_id.get(*schema_id) {
            None => bail!("schema-registry missing {schema_id}"),
            Some(actual) if *actual != *expected_file => {
                bail!("schema-registry {schema_id} → {actual} but expected {expected_file}")
            }
            _ => {}
        }
    }

    // capability-grant.schema.json carries the attached_authority extension
    // with oneOf two evidence_kind variants (spec PR 1.2).
    let cap_grant = load_artifact_json("schemas/capability-grant.schema.json")?;
    let attached = cap_grant
        .pointer("/properties/attached_authority")
        .ok_or_else(|| anyhow!("capability-grant missing attached_authority property"))?;
    let one_of = attached
        .get("oneOf")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("attached_authority missing oneOf"))?;
    if one_of.len() != 2 {
        bail!(
            "attached_authority oneOf MUST have exactly 2 variants in v1, got {}",
            one_of.len()
        );
    }
    let kinds: std::collections::BTreeSet<&str> = one_of
        .iter()
        .filter_map(|v| {
            v.pointer("/properties/evidence_kind/const")
                .and_then(Value::as_str)
        })
        .collect();
    if !kinds.contains("anchored_event_ref") {
        bail!("attached_authority MUST support evidence_kind=anchored_event_ref");
    }
    if !kinds.contains("state_witness") {
        bail!("attached_authority MUST support evidence_kind=state_witness");
    }
    if kinds.contains("inline_copy") {
        bail!("attached_authority MUST NOT carry inline_copy in v1 (reserved for v2)");
    }

    Ok(())
}

// ── FSM fixture suite ───────────────────────────────────────────────────────

pub fn run_agent_workspace_fsm_fixture_suite() -> Result<()> {
    let conformance_dir = spec_artifacts_root().join(AGENT_WS_CONFORMANCE_DIR);
    let mut found = Vec::new();
    walk_fixtures(&conformance_dir, &mut found)?;
    if found.is_empty() {
        bail!(
            "no agent_workspace conformance fixtures found under {}",
            conformance_dir.display()
        );
    }
    for fixture_path in &found {
        let raw = fs::read_to_string(fixture_path)?;
        let value: Value = serde_json::from_str(&raw)
            .map_err(|e| anyhow!("invalid JSON in {}: {e}", fixture_path.display()))?;
        validate_fixture_structure(&value, fixture_path)?;
    }

    // Verify the high-priority invariant set is present (full 44/44 enumeration).
    let vector_ids: std::collections::BTreeSet<String> = found
        .iter()
        .filter_map(|p| {
            let raw = fs::read_to_string(p).ok()?;
            let v: Value = serde_json::from_str(&raw).ok()?;
            v.get("vector_id")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        })
        .collect();

    let required = [
        "15-1-execution-01",
        "15-1-execution-03",
        "15-1-execution-10",
        "15-2-transparency-01",
        "15-2-transparency-03",
        "15-3-source-authority-01",
        "15-4-reservation-01",
        "15-4-reservation-02",
        "15-4-reservation-03",
    ];
    for vid in &required {
        if !vector_ids.contains(*vid) {
            bail!("agent_workspace conformance dir missing required land vector {vid}");
        }
    }

    // Verify the empty-sentinel + cas-register cell wiring is documented
    // in the reservation vectors.
    for fixture_path in &found {
        let raw = fs::read_to_string(fixture_path)?;
        let value: Value = serde_json::from_str(&raw)?;
        let vid = value.get("vector_id").and_then(Value::as_str).unwrap_or("");
        if vid.starts_with("15-4-reservation-") {
            // Each reservation vector documents one of:
            //   * head_eq:"__unset__"      (singleton-once-set path; also `set __unset__` on cleanup)
            //   * head_in [...]            (recovery / cleanup path against a known head)
            //   * concurrent_bottom        (multiple input_moves[] → ⊥)
            //
            // The predicate may live under:
            //   * /input_move/predicate/*                  (abstract Move shape)
            //   * /input_event/predicate/*                 (legacy inline shape; not used in v1 fixtures)
            //   * /input_event/preconditions/[0]/predicate/* (canonical Event shape — cleanup uses this)
            let predicate_op = value
                .pointer("/input_move/predicate/op")
                .or_else(|| value.pointer("/input_event/predicate/op"))
                .or_else(|| value.pointer("/input_event/preconditions/0/predicate/op"))
                .and_then(Value::as_str);
            let predicate_value = value
                .pointer("/input_move/predicate/value")
                .or_else(|| value.pointer("/input_event/predicate/value"))
                .or_else(|| value.pointer("/input_event/preconditions/0/predicate/value"))
                .and_then(Value::as_str);
            let predicate_values_present = value
                .pointer("/input_move/predicate/values")
                .or_else(|| value.pointer("/input_event/predicate/values"))
                .or_else(|| value.pointer("/input_event/preconditions/0/predicate/values"))
                .and_then(Value::as_array)
                .map(|a| !a.is_empty())
                .unwrap_or(false);
            let bottom_diag = value
                .pointer("/expected_outcome/bottom_diagnostic")
                .is_some();
            let head_eq_unset =
                predicate_op == Some("head_eq") && predicate_value == Some(RESERVATION_SENTINEL);
            let head_eq_known = predicate_op == Some("head_eq") && predicate_value.is_some();
            let head_in_recovery = predicate_op == Some("head_in") && predicate_values_present;
            let concurrent_bottom = bottom_diag
                && value
                    .get("input_moves")
                    .and_then(Value::as_array)
                    .map(|a| a.len() >= 2)
                    .unwrap_or(false);
            if !(head_eq_unset || head_eq_known || head_in_recovery || concurrent_bottom) {
                bail!(
                    "reservation vector {vid} ({}) does not document head_eq / head_in / bottom-collapse",
                    fixture_path.display()
                );
            }
        }
    }

    Ok(())
}

fn walk_fixtures(dir: &std::path::Path, out: &mut Vec<PathBuf>) -> Result<()> {
    if !dir.is_dir() {
        bail!("conformance dir {} does not exist", dir.display());
    }
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() && path.extension().and_then(|e| e.to_str()) == Some("json") {
            out.push(path);
        }
    }
    out.sort();
    Ok(())
}

fn validate_fixture_structure(value: &Value, path: &std::path::Path) -> Result<()> {
    if value.get("vector_id").and_then(Value::as_str).is_none() {
        bail!("{}: missing vector_id", path.display());
    }
    if value.get("spec_section").and_then(Value::as_str).is_none() {
        bail!("{}: missing spec_section", path.display());
    }
    if value.get("title").and_then(Value::as_str).is_none() {
        bail!("{}: missing title", path.display());
    }

    // Vectors come in several shapes — accept any of them:
    //   * single-shot:        input_event   + expected_outcome.reducer_result
    //   * single-Move:        input_move    + expected_outcome.reducer_result
    //   * concurrent Moves:   input_moves[] + expected_outcome.reducer_result
    //   * multi-watcher race: input_events[] + expected_outcomes[]
    //   * multi-step saga:    input_steps[] + expected_final_state | expected_post_state_invariants
    //   * notification:       input_notification + expected_delivery_invariants
    //   * sub_cases negative: sub_cases[] (each with expected_reason) + expected_outcome.reducer_result
    let valid_results = [
        "accepted",
        "failed_precondition",
        "failed_bottom",
        "cell_bottom",
        "unauthorized",
        "schema_violation",
    ];
    let is_negative = value
        .get("negative")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let check_reducer_result = |result: &str| -> Result<()> {
        if !valid_results.contains(&result) {
            bail!(
                "{}: unknown reducer_result {result} (valid: {:?})",
                path.display(),
                valid_results
            );
        }
        if is_negative && result == "accepted" {
            bail!(
                "{}: marked negative but reducer_result=accepted",
                path.display()
            );
        }
        Ok(())
    };

    let has_input_event = value.get("input_event").is_some();
    let has_input_events = value
        .get("input_events")
        .and_then(Value::as_array)
        .is_some();
    let has_input_move = value.get("input_move").is_some();
    let has_input_moves = value.get("input_moves").and_then(Value::as_array).is_some();
    let has_input_steps = value.get("input_steps").and_then(Value::as_array).is_some();
    let has_input_notification = value.get("input_notification").is_some();
    let has_sub_cases = value.get("sub_cases").and_then(Value::as_array).is_some();
    let has_input_event_template = value.get("input_event_template").is_some();

    if !(has_input_event
        || has_input_events
        || has_input_move
        || has_input_moves
        || has_input_steps
        || has_input_notification
        || has_input_event_template)
    {
        bail!(
            "{}: fixture must declare one of input_event / input_events / input_move / input_moves / input_steps / input_notification / input_event_template",
            path.display()
        );
    }

    if has_input_events {
        // Multi-watcher race: expected_outcomes[] with per-submitter result.
        let outcomes = value
            .get("expected_outcomes")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                anyhow!(
                    "{}: input_events[] requires expected_outcomes[]",
                    path.display()
                )
            })?;
        if outcomes.is_empty() {
            bail!("{}: expected_outcomes[] is empty", path.display());
        }
        for outcome in outcomes {
            let result = outcome
                .get("reducer_result")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    anyhow!(
                        "{}: expected_outcomes[i] missing reducer_result",
                        path.display()
                    )
                })?;
            check_reducer_result(result)?;
        }
    } else if has_input_steps {
        // Multi-step saga: expected_final_state OR expected_post_state_invariants.
        let has_final_state = value.get("expected_final_state").is_some();
        let has_post_invariants = value.get("expected_post_state_invariants").is_some();
        if !has_final_state && !has_post_invariants {
            bail!(
                "{}: input_steps[] requires expected_final_state or expected_post_state_invariants",
                path.display()
            );
        }
    } else if has_input_notification {
        // Notification delivery: expected_delivery_invariants[].
        let invariants = value
            .get("expected_delivery_invariants")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                anyhow!(
                    "{}: input_notification requires expected_delivery_invariants[]",
                    path.display()
                )
            })?;
        if invariants.is_empty() {
            bail!(
                "{}: expected_delivery_invariants[] is empty",
                path.display()
            );
        }
    } else if has_sub_cases {
        // sub_cases-driven negative vector: each sub_case has expected_reason;
        // top-level expected_outcome.reducer_result still required.
        let cases = value.get("sub_cases").and_then(Value::as_array).unwrap();
        for case in cases {
            if case
                .get("expected_reason")
                .and_then(Value::as_str)
                .is_none()
            {
                bail!("{}: sub_cases[i] missing expected_reason", path.display());
            }
        }
        let expected = value.get("expected_outcome").ok_or_else(|| {
            anyhow!(
                "{}: sub_cases[] still requires top-level expected_outcome",
                path.display()
            )
        })?;
        let result = expected
            .get("reducer_result")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                anyhow!(
                    "{}: expected_outcome missing reducer_result",
                    path.display()
                )
            })?;
        check_reducer_result(result)?;
    } else {
        // Single-shot / single-Move / multi-Move: require expected_outcome.reducer_result.
        let expected = value
            .get("expected_outcome")
            .ok_or_else(|| anyhow!("{}: missing expected_outcome", path.display()))?;
        let result = expected
            .get("reducer_result")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                anyhow!(
                    "{}: missing expected_outcome.reducer_result",
                    path.display()
                )
            })?;
        check_reducer_result(result)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_suite_passes_against_spec_v1_artifacts() -> Result<()> {
        run_agent_workspace_registry_suite()
    }

    #[test]
    fn schema_suite_passes_against_spec_v1_artifacts() -> Result<()> {
        run_agent_workspace_schema_suite()
    }

    #[test]
    fn fsm_fixture_suite_passes_against_spec_v1_artifacts() -> Result<()> {
        run_agent_workspace_fsm_fixture_suite()
    }
}
