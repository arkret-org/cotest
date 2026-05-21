//! Cotest profile gate registry.
//!
//! Loads `contrix-spec/spec/v1/artifacts/profiles/conformance-profiles.json`
//! at runtime and produces a per-profile gate report. Two profile classes are
//! handled:
//!
//! - **Vector profiles** — every `required_cotest_suites[].suite` is looked
//!   up in the local cotest suite registry. Known suites resolve to a wired
//!   runner function. Unknown suites are reported as
//!   `skipped(suite_not_implemented)` rather than being silently treated as
//!   passing.
//!
//! - **Implementation profiles** — the harness cannot drive every required
//!   event_kind / operation through a live server in offline mode, so each
//!   entry is reported with the spec's default unsupported behavior
//!   (`unsupported(profile_id=...)`). The list is explicit so a profile is
//!   never silently skipped from the rollup.
//!
//! - **Deprecated hard-reject profiles** — removed profile ids are validated
//!   against the drift registry and must not reappear in implementation
//!   profile catalogs. They are negative-test context only, not rollup
//!   implementation entries.
//!
//! The resulting [`ProfileGateReport`] is consumed by
//! `cotest/tests/conformance_fixtures.rs::profile_registry_gate_suite_...` and
//! by the certification-report scenario so each new profile id appears in the
//! JSON / Markdown summary with its status (`certified` / `unsupported` /
//! `skipped` / `not_implemented`).

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, anyhow, bail};
use serde::Serialize;
use serde_json::{Value, json};

use super::{load_artifact_json, local_fixture_path, required_str, string_array_field};
use crate::transcripts::record_vector_event;

/// Status reported by the profile gate for one profile id.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileGateStatus {
    /// Every required suite is wired and exists in the harness registry.
    Certified,
    /// The profile is acknowledged but the harness cannot drive it in
    /// offline-only mode (default_unsupported_behavior). The runner did not
    /// silently skip it — the gate explicitly emits an entry.
    Unsupported,
    /// A required suite is named in the spec but has no runner wired yet.
    /// Treated as skipped (NOT passing) so the rollup surfaces the gap.
    Skipped,
    /// A required suite is wired but its registry entry is marked TODO /
    /// not-yet-implemented (suite returns this status itself).
    NotImplemented,
}

impl ProfileGateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            ProfileGateStatus::Certified => "certified",
            ProfileGateStatus::Unsupported => "unsupported",
            ProfileGateStatus::Skipped => "skipped",
            ProfileGateStatus::NotImplemented => "not_implemented",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProfileGateEntry {
    pub profile_id: String,
    pub status: String,
    pub category: String,
    pub required_suites: Vec<String>,
    pub missing_suites: Vec<String>,
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProfileGateReport {
    pub schema: String,
    pub entries: Vec<ProfileGateEntry>,
}

/// New vector profiles that cotest MUST gate. Membership is hardcoded so a
/// future spec drift (the id silently disappearing from `vector_profiles[]`)
/// is caught — but the suite list itself is loaded from the artifact at
/// runtime, never hardcoded.
const NEW_VECTOR_PROFILES: &[&str] = &[
    "cx.profile.discovery_vectors.v1",
    "cx.profile.event_kind_lattice_dispatch_vectors.v1",
    "cx.profile.event_kind_payload_coverage_vectors.v1",
    "cx.profile.operation_registry_coverage_vectors.v1",
    "cx.profile.error_code_registry_coverage_vectors.v1",
];

/// New implementation profiles that cotest emits explicit manifest entries
/// for. Aggressive mode: the harness does not yet drive every required
/// event_kind through a live server, so they default to `unsupported` per
/// spec's `default_unsupported_behavior` — never silently skipped.
const NEW_IMPLEMENTATION_PROFILES: &[&str] = &[
    "cx.profile.e2ee_relaxed.v1",
    "cx.profile.directory_service.v1",
    // Round C45 (2026-05-18 main; spec 5ed365c) — federation high-assurance
    // peer profile, sender_commitment opt-in franking profile, and
    // morph.schema_migrate transformation profile. All default to
    // `unsupported` here pending fixture vectors.
    "cx.profile.federation.high_assurance.v1",
    "cx.profile.franking.sender_commitment.v1",
    "cx.profile.morph.schema_migration_transformations.v1",
];

/// Removed profile ids that must remain in the registry-drift negative-test
/// context and must not be treated as current implementation profiles.
const DEPRECATED_HARD_REJECT_PROFILES: &[&str] = &[
    "cx.profile.agent_workspace.v1",
    "cx.profile.agent_workspace.lite.v1",
    "cx.profile.agent_workspace.governed.v1",
    "cx.profile.agent_workspace.strict.v1",
];

/// Removed operation ids kept only as hard-reject drift sentinels.
const REMOVED_AGENT_WORKSPACE_OPERATIONS: &[&str] = &[
    "cx.agent_workspace.resolve_mirror_flow",
    "cx.agent_workspace.list_pending_tasks",
];

/// Removed event kinds kept only as hard-reject drift sentinels.
const REMOVED_AGENT_TASK_EVENT_KINDS: &[&str] = &[
    "cx.agent_task.create",
    "cx.agent_task.execution.transition",
    "cx.agent_task.transparency.transition",
    "cx.agent_task.source_authority.transition",
    "cx.agent_task.cancel",
];

/// Wired cotest suites. Each entry is `(suite_id, fixture_file)`. The fixture
/// existence under `tests/fixtures/` is used as the run-time check; the suite
/// runner itself is dispatched by `cargo test --test conformance_fixtures` and
/// referenced by id in `required_cotest_suites[]`.
fn suite_registry() -> BTreeMap<&'static str, &'static str> {
    let mut map = BTreeMap::new();
    map.insert(
        "discovery_profile_fixture",
        "discovery_profile_fixture.json",
    );
    map.insert(
        "event_kind_lattice_dispatch_fixture",
        "event_kind_lattice_dispatch_fixture.json",
    );
    map.insert(
        "event_kind_payload_coverage_fixture",
        "event_kind_payload_coverage_fixture.json",
    );
    map.insert(
        "operation_registry_coverage_fixture",
        "operation_registry_coverage_fixture.json",
    );
    map.insert(
        "error_code_registry_coverage_fixture",
        "error_code_registry_coverage_fixture.json",
    );
    map.insert("event_envelope_fixture", "");
    map.insert(
        "security_negative_profile",
        "security-negative-profile-fixture.json",
    );
    map
}

/// Build the profile gate report by reading `conformance-profiles.json` from
/// the spec at runtime (no hardcoded suite list per-profile).
pub fn build_profile_gate_report() -> Result<ProfileGateReport> {
    let profiles = load_artifact_json("profiles/conformance-profiles.json")?;
    let declared_vector_profiles: BTreeSet<String> =
        string_array_field(&profiles, "vector_profiles")?
            .into_iter()
            .map(ToOwned::to_owned)
            .collect();
    let requirements = profiles
        .get("profile_requirements")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow!("conformance-profiles missing profile_requirements"))?;

    let registry = suite_registry();
    let mut entries = Vec::new();

    // Vector profiles — gate each required suite against the registry.
    for profile_id in NEW_VECTOR_PROFILES {
        if !declared_vector_profiles.contains(*profile_id) {
            bail!(
                "vector profile {profile_id} not declared in vector_profiles[] (spec drift); \
                 cotest gate cannot validate a profile that is no longer published"
            );
        }
        let requirement = requirements
            .get(*profile_id)
            .ok_or_else(|| anyhow!("vector profile {profile_id} missing profile_requirements"))?;
        let suite_items = requirement
            .get("required_cotest_suites")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                anyhow!("vector profile {profile_id} missing required_cotest_suites[]")
            })?;
        let mut required = Vec::new();
        let mut missing = Vec::new();
        for item in suite_items {
            let suite = required_str(item, "suite")?;
            required.push(suite.to_owned());
            match registry.get(suite) {
                Some(fixture) if !fixture.is_empty() => {
                    let path = local_fixture_path(fixture);
                    if !path.is_file() {
                        missing.push(format!("{suite}:fixture_missing"));
                    }
                }
                Some(_) => { /* suite with no local fixture is OK */ }
                None => missing.push(suite.to_owned()),
            }
        }
        let status = if missing.is_empty() {
            ProfileGateStatus::Certified
        } else {
            ProfileGateStatus::Skipped
        };
        let reason = if missing.is_empty() {
            None
        } else {
            Some(format!("suite_not_implemented: {}", missing.join(",")))
        };
        entries.push(ProfileGateEntry {
            profile_id: (*profile_id).to_owned(),
            status: status.as_str().to_owned(),
            category: "vector_profile".to_owned(),
            required_suites: required,
            missing_suites: missing,
            reason,
        });
    }

    // Implementation profiles — emit explicit `unsupported` entries per the
    // spec's default_unsupported_behavior (offline harness cannot drive a
    // full event_kind / operation surface against a live server).
    let declared_impl_profiles: BTreeSet<String> =
        collect_declared_implementation_profiles(&profiles)?;
    for profile_id in NEW_IMPLEMENTATION_PROFILES {
        if !declared_impl_profiles.contains(*profile_id) {
            bail!(
                "implementation profile {profile_id} not declared in any implementation_profiles / \
                 deployment_profiles catalog (spec drift)"
            );
        }
        // The profile MUST have a profile_requirements entry; if it doesn't,
        // that's a spec drift error rather than a silent skip.
        if !requirements.contains_key(*profile_id) {
            bail!(
                "implementation profile {profile_id} missing profile_requirements; \
                 cotest cannot emit a manifest entry for an undeclared profile"
            );
        }
        entries.push(ProfileGateEntry {
            profile_id: (*profile_id).to_owned(),
            status: ProfileGateStatus::Unsupported.as_str().to_owned(),
            category: "implementation_profile".to_owned(),
            required_suites: Vec::new(),
            missing_suites: Vec::new(),
            reason: Some(format!(
                "profile_id={profile_id}: default_unsupported_behavior — cotest offline harness \
                 cannot drive a full live-server surface for this profile"
            )),
        });
    }
    validate_deprecated_profile_drift(&declared_impl_profiles)?;
    validate_hard_reject_registry_entries(
        "registry/removed-operation-ids.json",
        "removed operation",
        REMOVED_AGENT_WORKSPACE_OPERATIONS,
    )?;
    validate_hard_reject_registry_entries(
        "registry/removed-event-kinds.json",
        "removed event kind",
        REMOVED_AGENT_TASK_EVENT_KINDS,
    )?;

    let report = ProfileGateReport {
        schema: "cx.cotest.profile_gate_report.v1".to_owned(),
        entries,
    };
    Ok(report)
}

/// Public entrypoint mirrored against the existing `run_profile_matrix_suite`
/// pattern. The conformance_fixtures.rs test calls this to produce a
/// transcript event and to hard-fail if a vector profile lost its
/// `required_cotest_suites` block.
pub fn run_profile_registry_gate_suite() -> Result<()> {
    let report = build_profile_gate_report()?;

    record_vector_event(
        "profile_registry_gate.summary",
        &json!({
            "entries": report.entries.len(),
            "vector_profiles": NEW_VECTOR_PROFILES.len(),
            "implementation_profiles": NEW_IMPLEMENTATION_PROFILES.len(),
            "deprecated_hard_reject_profiles": DEPRECATED_HARD_REJECT_PROFILES.len(),
            "removed_agent_workspace_operations": REMOVED_AGENT_WORKSPACE_OPERATIONS.len(),
            "removed_agent_task_event_kinds": REMOVED_AGENT_TASK_EVENT_KINDS.len(),
        }),
        &json!({
            "schema": report.schema.clone(),
            "expected_categories": ["vector_profile", "implementation_profile"],
        }),
        &serde_json::to_value(&report)?,
    );

    // Hard-fail rule: vector profiles MUST resolve to certified or skipped
    // with a reason. Implementation profiles MUST resolve to unsupported
    // with a reason. Anything else means a registry / wiring bug.
    for entry in &report.entries {
        match entry.category.as_str() {
            "vector_profile" => {
                if entry.status == "skipped" && entry.reason.is_none() {
                    bail!("vector profile {} skipped without reason", entry.profile_id);
                }
                if entry.status != "certified" && entry.status != "skipped" {
                    bail!(
                        "vector profile {} resolved to unexpected status {}",
                        entry.profile_id,
                        entry.status
                    );
                }
            }
            "implementation_profile" => {
                if entry.status != "unsupported" {
                    bail!(
                        "implementation profile {} must report unsupported per \
                         default_unsupported_behavior, got {}",
                        entry.profile_id,
                        entry.status
                    );
                }
                if entry.reason.is_none() {
                    bail!(
                        "implementation profile {} missing unsupported reason",
                        entry.profile_id
                    );
                }
            }
            other => bail!("unknown profile gate category {other}"),
        }
    }
    Ok(())
}

/// Markdown rendering of the gate report for inclusion in the certification
/// rollup. One row per profile id with status.
pub fn render_profile_gate_report_markdown(report: &ProfileGateReport) -> String {
    let mut out =
        String::from("| profile_id | category | status | reason |\n| --- | --- | --- | --- |\n");
    for entry in &report.entries {
        out.push_str(&format!(
            "| {} | {} | {} | {} |\n",
            entry.profile_id,
            entry.category,
            entry.status,
            entry.reason.as_deref().unwrap_or("")
        ));
    }
    out
}

/// JSON rendering of the gate report.
pub fn render_profile_gate_report_json(report: &ProfileGateReport) -> Result<String> {
    serde_json::to_string_pretty(report).map_err(Into::into)
}

fn collect_declared_implementation_profiles(profiles: &Value) -> Result<BTreeSet<String>> {
    let mut declared = BTreeSet::new();
    for field in [
        "implementation_profiles",
        "deployment_profiles",
        "hardening_profiles",
        "identity_extension_profiles",
        "constraint_extension_profiles",
        "lattice_extension_profiles",
        "interop_compat_profiles",
        "encoding_extension_profiles",
        "hash_extension_profiles",
        "anchor_profiles",
    ] {
        for profile in string_array_field(profiles, field)? {
            declared.insert(profile.to_owned());
        }
    }
    for field in [
        "e2ee_hardening",
        "federation_hardening",
        "privacy_hardening",
        "mimi_interop",
    ] {
        if let Some(array) = profiles.get(field).and_then(Value::as_array) {
            for entry in array {
                if let Some(profile) = entry.as_str() {
                    if profile.starts_with("cx.profile.") {
                        declared.insert(profile.to_owned());
                    }
                }
            }
        }
    }
    Ok(declared)
}

fn validate_deprecated_profile_drift(declared_impl_profiles: &BTreeSet<String>) -> Result<()> {
    validate_hard_reject_registry_entries(
        "registry/deprecated-profile-ids.json",
        "deprecated profile",
        DEPRECATED_HARD_REJECT_PROFILES,
    )?;

    for profile_id in DEPRECATED_HARD_REJECT_PROFILES {
        if declared_impl_profiles.contains(*profile_id) {
            bail!(
                "deprecated hard-reject profile {profile_id} still declared as an \
                 implementation profile; keep it only in registry-drift negative context"
            );
        }
    }

    Ok(())
}

fn validate_hard_reject_registry_entries(
    relative_path: &str,
    entry_label: &str,
    expected_ids: &[&str],
) -> Result<()> {
    let registry = load_artifact_json(relative_path)?;
    let entries = registry
        .get("entries")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("{relative_path} missing entries[]"))?;

    let mut hard_reject_ids = BTreeSet::new();
    for entry in entries {
        let id = required_str(entry, "id")?;
        if !expected_ids.contains(&id) {
            continue;
        }

        let rejection_level = required_str(entry, "rejection_level")?;
        if rejection_level != "hard_reject" {
            bail!("{entry_label} {id} must be hard_reject, got {rejection_level}");
        }

        let allowed_contexts = string_array_field(entry, "allowed_contexts")?;
        if !allowed_contexts
            .iter()
            .any(|context| *context == "negative_test")
        {
            bail!("{entry_label} {id} must allow cotest negative_test context");
        }

        hard_reject_ids.insert(id.to_owned());
    }

    for id in expected_ids {
        if !hard_reject_ids.contains(*id) {
            bail!(
                "{entry_label} {id} missing as hard_reject negative-test entry from {relative_path}"
            );
        }
    }

    Ok(())
}
