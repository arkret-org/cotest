//! Operation- and error-code registry-coverage wire-model conformance vectors.

use anyhow::{Result, anyhow, bail};
use serde_json::{Value, json};

use super::{emit_vector, load_local_fixture};
use crate::conformance::{required_str, validate_profile};

/// A3 Round 23 — operation registry coverage.
pub fn run_operation_registry_coverage_fixture_suite() -> Result<()> {
    use std::collections::{BTreeMap, BTreeSet};

    let fixture = load_local_fixture("operation_registry_coverage_fixture.json")?;
    validate_profile(
        &fixture,
        "ck.profile.operation_registry_coverage_vectors.v1",
    )?;

    let op_registry = crate::conformance::load_artifact_json("registry/operation-registry.json")?;
    let event_kind_registry =
        crate::conformance::load_artifact_json("registry/event-kind-registry.json")?;
    let cap_action_registry =
        crate::conformance::load_artifact_json("registry/capability-action-registry.json")?;

    let valid_tiers: BTreeSet<&str> = ["core", "extension", "interop_bridge", "deployment_local"]
        .into_iter()
        .collect();

    let operations = op_registry
        .get("operations")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("operation-registry missing operations[]"))?;
    let mut op_ids: BTreeSet<String> = BTreeSet::new();
    for entry in operations {
        let id = required_str(entry, "operation_id")?;
        op_ids.insert(id.to_owned());
    }

    let surface_groups = op_registry
        .get("surface_groups")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("operation-registry missing surface_groups[]"))?;
    let mut op_tier: BTreeMap<String, String> = BTreeMap::new();
    for group in surface_groups {
        let tier = required_str(group, "tier")?;
        if !valid_tiers.contains(tier) {
            bail!("surface_group declares invalid tier {tier}");
        }
        let ops = group
            .get("operations")
            .and_then(Value::as_array)
            .ok_or_else(|| anyhow!("surface_group missing operations[]"))?;
        for op in ops {
            let id = op
                .as_str()
                .ok_or_else(|| anyhow!("surface_group operation must be string"))?;
            if !op_ids.contains(id) {
                bail!("surface_group references operation_id {id} not in operations[]");
            }
            if let Some(prev) = op_tier.insert(id.to_owned(), tier.to_owned()) {
                if prev != tier {
                    bail!(
                        "operation_id {id} declared in two surface_groups with different tiers {prev} / {tier}"
                    );
                }
            }
        }
    }
    for id in &op_ids {
        if !op_tier.contains_key(id) {
            bail!("operation_id {id} is orphaned (not in any surface_group)");
        }
    }

    let actions = cap_action_registry
        .get("actions")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("capability-action-registry missing actions[]"))?;
    let event_kinds = event_kind_registry
        .get("event_kinds")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("event-kind-registry missing event_kinds[]"))?;
    let mut live_event_kinds: BTreeSet<String> = BTreeSet::new();
    for entry in event_kinds {
        let k = required_str(entry, "event_kind")?;
        live_event_kinds.insert(k.to_owned());
    }
    for entry in actions {
        let action_id = required_str(entry, "action")?;
        let _risk = required_str(entry, "risk_tier")?;
        if let Some(targets) = entry.get("target_event_kinds").and_then(Value::as_array) {
            for t in targets {
                let kind = t.as_str().ok_or_else(|| {
                    anyhow!("action {action_id} target_event_kind must be string")
                })?;
                if !live_event_kinds.contains(kind) {
                    bail!(
                        "capability action {action_id} target_event_kind {kind} not in event-kind-registry"
                    );
                }
            }
        }
    }

    let vectors = fixture
        .get("vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("operation_registry_coverage fixture missing vectors[]"))?;
    let mut covered: BTreeSet<&str> = BTreeSet::new();
    for v in vectors {
        let name = required_str(v, "name")?;
        let outcome = v
            .pointer("/expected/outcome")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("vector {name} missing expected.outcome"))?;
        if outcome == "tier_match" {
            let op = required_str(v, "operation_id")?;
            let expected_tier = v
                .pointer("/expected/tier")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("vector {name} missing expected.tier"))?;
            let live = op_tier
                .get(op)
                .ok_or_else(|| anyhow!("vector {name} op {op} not in any surface_group"))?;
            if live != expected_tier {
                bail!("vector {name} tier drift: op {op} live={live}, expected={expected_tier}");
            }
        }
        covered.insert(name);
        emit_vector(
            "operation_registry_coverage.vector",
            v,
            json!({"name": name, "outcome": outcome}),
        );
    }
    for required in [
        "every_operation_belongs_to_a_surface_group",
        "every_surface_group_op_exists_in_operations_array",
        "valid_tier_vocabulary",
        "events_submit_is_core",
        "moderation_report_is_extension",
        "applet_ping_is_interop_bridge",
        "applet_install_preview_is_extension",
        "applet_install_is_extension",
        "applet_revoke_is_extension",
        "admin_get_server_status_is_deployment_local",
        "every_capability_action_target_event_kind_resolves_in_event_kind_registry",
    ] {
        if !covered.contains(required) {
            bail!("operation_registry_coverage fixture missing vector {required}");
        }
    }

    let negatives = fixture
        .get("negative_vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("operation_registry_coverage fixture missing negative_vectors[]"))?;
    let mut neg_orphan = false;
    let mut neg_tier = false;
    let mut neg_target = false;
    for v in negatives {
        let name = required_str(v, "name")?;
        let drift = v
            .pointer("/drift/kind")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("negative {name} missing drift.kind"))?;
        match drift {
            "operation_not_in_any_surface_group" => {
                let synth = required_str(v, "synthetic_operation_id")?;
                if op_ids.contains(synth) {
                    bail!("negative {name} synthetic op {synth} is real — not a drift");
                }
                neg_orphan = true;
            }
            "tier_mismatch" => {
                let op = required_str(v, "operation_id")?;
                let claimed_tier = required_str(v, "claimed_tier")?;
                let live = op_tier
                    .get(op)
                    .ok_or_else(|| anyhow!("negative {name} op {op} not in surface_group"))?;
                if live == claimed_tier {
                    bail!("negative {name} claimed_tier equals live — not a drift");
                }
                neg_tier = true;
            }
            "target_event_kind_dangling" => {
                let synth = required_str(v, "synthetic_target_event_kind")?;
                if live_event_kinds.contains(synth) {
                    bail!("negative {name} synthetic target {synth} is real — not a drift");
                }
                neg_target = true;
            }
            other => bail!("negative {name} unknown drift.kind {other}"),
        }
    }
    if !(neg_orphan && neg_tier && neg_target) {
        bail!(
            "operation_registry_coverage fixture must cover orphaned op, tier mismatch, target dangling negatives"
        );
    }

    Ok(())
}
/// A4 Round 23 — error code registry coverage. Spec uses {both, endpoint};
/// validator accepts the published superset {client, server, both, endpoint}.
pub fn run_error_code_registry_coverage_fixture_suite() -> Result<()> {
    use std::collections::{BTreeMap, BTreeSet};

    let fixture = load_local_fixture("error_code_registry_coverage_fixture.json")?;
    validate_profile(
        &fixture,
        "ck.profile.error_code_registry_coverage_vectors.v1",
    )?;

    let registry = crate::conformance::load_artifact_json("registry/error-code-registry.json")?;
    let codes_arr = registry
        .get("codes")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("error-code-registry missing codes[]"))?;
    // Round 2+3 cleanup (2026-05-20): the spec error-code-registry adds
    // `service_call` scope (federation S2S errors) alongside the existing
    // four. Keep `endpoint` (introduced in earlier rounds for read-side
    // codes) and accept `service_call` so the registry coverage gate
    // doesn't reject the new error codes.
    let valid_scopes: BTreeSet<&str> = ["client", "server", "both", "endpoint", "service_call"]
        .into_iter()
        .collect();

    let mut live_codes: BTreeMap<String, (i64, String)> = BTreeMap::new();
    for c in codes_arr {
        let code = required_str(c, "code")?;
        // Sub-reason codes (spec 653ffb2): a `schema_violation` /
        // state-resolution sub-reason carries `applies_to` instead of a
        // top-level HTTP `http_status` / `scope` (it is never an
        // independently returnable HTTP status, only a refinement of a
        // parent code). The http/scope coverage checks do not apply; we
        // still require a documented description.
        if c.get("http_status").is_none() && c.get("applies_to").is_some() {
            let description = required_str(c, "description")?;
            if description.is_empty() {
                bail!("sub-reason code {code} has empty description");
            }
            continue;
        }
        let http = c
            .get("http_status")
            .and_then(Value::as_i64)
            .ok_or_else(|| anyhow!("code {code} missing http_status (integer)"))?;
        // Round-4 (spec 7446832) introduced diagnostic codes that surface
        // on a 200 response (the canonical example is `historical_only` —
        // federation idempotency cache hit with a stale source key
        // produces a 200 + `reason_code=historical_only` so the caller
        // can treat the body as cached-only and skip side effects).
        // Recognise that family by checking the `scope` of `diagnostic`
        // or the `success_diagnostic` boolean — when present, the http
        // status MUST be 200; otherwise the canonical 400-599 range
        // applies.
        let is_diagnostic = c
            .get("success_diagnostic")
            .and_then(Value::as_bool)
            .unwrap_or(false)
            || c.get("scope").and_then(Value::as_str) == Some("diagnostic")
            || http == 200;
        if is_diagnostic {
            if http != 200 {
                bail!(
                    "code {code} declared as success_diagnostic but http_status {http} is not 200"
                );
            }
        } else if !(400..=599).contains(&http) {
            bail!("code {code} has http_status {http} outside 400-599 range");
        }
        let scope = required_str(c, "scope")?;
        if !valid_scopes.contains(scope) {
            bail!(
                "code {code} has scope {scope} not in {{client, server, both, endpoint, service_call}}"
            );
        }
        let description = required_str(c, "description")?;
        if description.is_empty() {
            bail!("code {code} has empty description");
        }
        live_codes.insert(code.to_owned(), (http, scope.to_owned()));
    }

    let expected_refs = fixture
        .get("expected_referenced_codes")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            anyhow!("error_code_registry_coverage fixture missing expected_referenced_codes[]")
        })?;
    for r in expected_refs {
        let code = required_str(r, "code")?;
        let exp_http = r
            .get("expected_http_status")
            .and_then(Value::as_i64)
            .ok_or_else(|| anyhow!("ref {code} missing expected_http_status"))?;
        let exp_scope = required_str(r, "expected_scope")?;
        let live = live_codes
            .get(code)
            .ok_or_else(|| anyhow!("expected referenced code {code} missing from registry"))?;
        if live.0 != exp_http {
            bail!(
                "code {code} http_status drift: live={}, expected={exp_http}",
                live.0
            );
        }
        if live.1 != exp_scope {
            bail!(
                "code {code} scope drift: live={}, expected={exp_scope}",
                live.1
            );
        }
    }

    let vectors = fixture
        .get("vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("error_code_registry_coverage fixture missing vectors[]"))?;
    for v in vectors {
        let name = required_str(v, "name")?;
        let outcome = v
            .pointer("/expected/outcome")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("vector {name} missing expected.outcome"))?;
        if outcome == "code_match" {
            let code = required_str(v, "code")?;
            let live = live_codes
                .get(code)
                .ok_or_else(|| anyhow!("vector {name} code {code} not in registry"))?;
            let exp_http = v
                .pointer("/expected/http_status")
                .and_then(Value::as_i64)
                .ok_or_else(|| anyhow!("vector {name} missing expected.http_status"))?;
            let exp_scope = v
                .pointer("/expected/scope")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("vector {name} missing expected.scope"))?;
            if live.0 != exp_http {
                bail!(
                    "vector {name} code {code} http_status drift: live={}, exp={exp_http}",
                    live.0
                );
            }
            if live.1 != exp_scope {
                bail!(
                    "vector {name} code {code} scope drift: live={}, exp={exp_scope}",
                    live.1
                );
            }
        }
        emit_vector(
            "error_code_registry_coverage.vector",
            v,
            json!({"name": name, "outcome": outcome}),
        );
    }

    let negatives = fixture
        .get("negative_vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            anyhow!("error_code_registry_coverage fixture missing negative_vectors[]")
        })?;
    let mut neg_unknown = false;
    let mut neg_scope = false;
    let mut neg_status = false;
    for v in negatives {
        let name = required_str(v, "name")?;
        let drift = v
            .pointer("/drift/kind")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("negative {name} missing drift.kind"))?;
        match drift {
            "code_not_in_registry" => {
                let synth = required_str(v, "synthetic_code")?;
                if live_codes.contains_key(synth) {
                    bail!("negative {name} synthetic code {synth} is real");
                }
                neg_unknown = true;
            }
            "scope_invalid" => {
                let synth = required_str(v, "synthetic_scope")?;
                if valid_scopes.contains(synth) {
                    bail!("negative {name} synthetic scope {synth} is valid");
                }
                neg_scope = true;
            }
            "http_status_out_of_range" => {
                let synth = v
                    .get("synthetic_http_status")
                    .and_then(Value::as_i64)
                    .ok_or_else(|| anyhow!("negative {name} missing synthetic_http_status"))?;
                if (400..=599).contains(&synth) {
                    bail!("negative {name} synthetic http_status {synth} is in valid range");
                }
                neg_status = true;
            }
            other => bail!("negative {name} unknown drift.kind {other}"),
        }
    }
    if !(neg_unknown && neg_scope && neg_status) {
        bail!(
            "error_code_registry_coverage fixture must cover unknown code, invalid scope, out-of-range http_status negatives"
        );
    }

    Ok(())
}

/// S-13 (cokret-spec 653ffb2, 2026-06-04) — Applet install/package surface
/// and its audit intersection, pinned against the live spec artifacts.
///
/// Fixture-decoupled: asserts directly against the canonical registries +
/// schemas so the new protocol surface can't silently drift:
/// - `ck.applet.install.preview` / `ck.applet.install` / `ck.applet.revoke` operations exist;
/// - `ck.schema.applet_package.v1` is registered and its schema requires `registration_epoch` /
///   `package_digest` / `proof` and the base `ck.profile.applet_service.v1` profile;
/// - `applet_registration_payload` now requires `registration_epoch`;
/// - `applet_bridge_error_payload` requires exactly the §7 field set;
/// - the audit∩applet event kinds (`ck.audit.applet_binding`, `ck.audit.release`) are present
///   alongside the applet wire events.
pub fn run_applet_audit_surface_check() -> Result<()> {
    use std::collections::BTreeSet;

    // (1) Install / revoke operations exist in the operation registry.
    let op_registry = crate::conformance::load_artifact_json("registry/operation-registry.json")?;
    let op_ids: BTreeSet<&str> = op_registry
        .get("operations")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("operation-registry missing operations[]"))?
        .iter()
        .filter_map(|o| o.get("operation_id").and_then(Value::as_str))
        .collect();
    for op in [
        "ck.applet.install.preview",
        "ck.applet.install",
        "ck.applet.revoke",
    ] {
        if !op_ids.contains(op) {
            bail!("operation-registry missing applet install operation {op}");
        }
    }

    // (2) ck.schema.applet_package.v1 is registered and well-formed.
    let schema_registry = crate::conformance::load_artifact_json("registry/schema-registry.json")?;
    let pkg_entry = schema_registry
        .get("schemas")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("schema-registry missing schemas[]"))?
        .iter()
        .find(|s| s.get("schema_id").and_then(Value::as_str) == Some("ck.schema.applet_package.v1"))
        .ok_or_else(|| anyhow!("schema-registry missing ck.schema.applet_package.v1"))?;
    let pkg_file = required_str(pkg_entry, "file")?;
    let pkg_schema = crate::conformance::load_artifact_json(pkg_file)?;
    if pkg_schema
        .pointer("/properties/schema/const")
        .and_then(Value::as_str)
        != Some("ck.schema.applet_package.v1")
    {
        bail!("applet-package schema `schema` const drifted");
    }
    let pkg_required: BTreeSet<&str> = pkg_schema
        .get("required")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("applet-package schema missing required[]"))?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    for field in [
        "schema",
        "applet_id",
        "controller_did",
        "claimed_profiles",
        "registration_epoch",
        "package_digest",
        "proof",
    ] {
        if !pkg_required.contains(field) {
            bail!("applet-package schema required[] missing {field}");
        }
    }
    if pkg_schema
        .pointer("/properties/claimed_profiles/contains/const")
        .and_then(Value::as_str)
        != Some("ck.profile.applet_service.v1")
    {
        bail!("applet-package claimed_profiles must contain ck.profile.applet_service.v1");
    }

    // (3) + (4) ck.applet.registration / ck.applet.bridge_error payloads.
    let event_payload =
        crate::conformance::load_artifact_json("schemas/event-payload.schema.json")?;
    let reg_required: BTreeSet<&str> = event_payload
        .pointer("/$defs/applet_registration_payload/required")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("event-payload missing applet_registration_payload.required[]"))?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    if !reg_required.contains("registration_epoch") {
        bail!("applet_registration_payload.required missing registration_epoch (S-13 drift)");
    }

    let bridge_required: BTreeSet<&str> = event_payload
        .pointer("/$defs/applet_bridge_error_payload/required")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("event-payload missing applet_bridge_error_payload.required[]"))?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    let expected_bridge: BTreeSet<&str> = [
        "applet_id",
        "realm_id",
        "failed_transaction_ref",
        "error_class",
        "error_code",
        "retriable",
        "visibility_scope",
    ]
    .into_iter()
    .collect();
    if bridge_required != expected_bridge {
        bail!(
            "applet_bridge_error_payload.required drifted: live={bridge_required:?}, expected={expected_bridge:?}"
        );
    }

    // (5) Audit ∩ applet event kinds present.
    let event_kind_registry =
        crate::conformance::load_artifact_json("registry/event-kind-registry.json")?;
    let kinds: BTreeSet<&str> = event_kind_registry
        .get("event_kinds")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("event-kind-registry missing event_kinds[]"))?
        .iter()
        .filter_map(|e| e.get("event_kind").and_then(Value::as_str))
        .collect();
    for kind in [
        "ck.applet.registration",
        "ck.applet.bridge_error",
        "ck.audit.applet_binding",
        "ck.audit.release",
    ] {
        if !kinds.contains(kind) {
            bail!("event-kind-registry missing {kind}");
        }
    }

    // (6) Applet / audit error codes landed alongside the install model.
    let error_registry =
        crate::conformance::load_artifact_json("registry/error-code-registry.json")?;
    let error_codes: BTreeSet<&str> = error_registry
        .get("codes")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("error-code-registry missing codes[]"))?
        .iter()
        .filter_map(|c| c.get("code").and_then(Value::as_str))
        .collect();
    for code in [
        "applet_registration_unauthorized",
        "applet_install_plan_mismatch",
        "applet_revoked",
        "applet_e2ee_join_unauthorized",
        "audit_receipt_invalidated",
    ] {
        if !error_codes.contains(code) {
            bail!("error-code-registry missing applet/audit code {code}");
        }
    }

    emit_vector(
        "applet_audit_surface.summary",
        &json!({ "name": "applet_audit_surface" }),
        json!({
            "install_ops": ["ck.applet.install.preview", "ck.applet.install", "ck.applet.revoke"],
            "package_schema": "ck.schema.applet_package.v1",
            "registration_epoch_required": true,
            "bridge_error_required": expected_bridge.iter().collect::<Vec<_>>(),
            "audit_event_kinds": ["ck.audit.applet_binding", "ck.audit.release"],
        }),
    );
    Ok(())
}
