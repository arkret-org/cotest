use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, anyhow, bail};
use serde_json::Value;

use super::{load_artifact_json, required_str, string_array_field};

const PROFILE_LIST_FIELDS: &[&str] = &[
    "implementation_profiles",
    "identity_extension_profiles",
    "deployment_profiles",
    "constraint_extension_profiles",
    "lattice_extension_profiles",
    "interop_compat_profiles",
    "encoding_extension_profiles",
    "hash_extension_profiles",
    "hardening_profiles",
    "vector_profiles",
    "anchor_profiles",
    // Round 2+3 (2026-05-20): the spec's conformance-profiles.json now
    // declares a `candidate_profiles` group for unregistered workflow
    // concept/action profiles gated fail-closed (see
    // `candidate_profiles_tier_rule` in the spec). Candidate profiles
    // MUST be recognised by the matrix loader so their
    // `profile_requirements` entries don't trigger
    // `not_declared_in_any_profile_catalog`.
    "candidate_profiles",
];

const MIXED_PROFILE_FIELDS: &[&str] = &[
    "e2ee_hardening",
    "federation_hardening",
    "privacy_hardening",
    "mimi_interop",
];

const LOCAL_PROFILE_SUITES: &[(&str, &str)] = &[(
    "ck.profile.privacy_security_vectors.v1",
    "security_negative_profile",
)];

#[derive(Debug)]
struct ProfileRequirement {
    inherited_profiles: BTreeSet<String>,
    required_operations: BTreeSet<String>,
    required_event_kinds: BTreeSet<String>,
    required_schemas: BTreeSet<String>,
    cotest_suites: BTreeSet<String>,
}

#[derive(Debug)]
struct ProfileMatrix {
    declared_profiles: BTreeSet<String>,
    requirements: BTreeMap<String, ProfileRequirement>,
}

pub fn validate_server_profile_claims(describe: &Value) -> Result<()> {
    let matrix = load_profile_matrix()?;
    validate_server_claims_against_matrix(describe, &matrix)
}

fn load_profile_matrix() -> Result<ProfileMatrix> {
    let profiles = load_artifact_json("profiles/conformance-profiles.json")?;
    let operation_ids = registry_id_set(
        &load_artifact_json("registry/operation-registry.json")?,
        "operations",
        "operation_id",
    )?;
    let event_kinds = registry_id_set(
        &load_artifact_json("registry/event-kind-registry.json")?,
        "event_kinds",
        "event_kind",
    )?;
    let schema_ids = registry_id_set(
        &load_artifact_json("registry/schema-registry.json")?,
        "schemas",
        "schema_id",
    )?;
    let declared_profiles = collect_declared_profiles(&profiles)?;
    let requirements = collect_profile_requirements(
        &profiles,
        &declared_profiles,
        &operation_ids,
        &event_kinds,
        &schema_ids,
    )?;

    Ok(ProfileMatrix {
        declared_profiles,
        requirements,
    })
}

fn collect_declared_profiles(profiles: &Value) -> Result<BTreeSet<String>> {
    let mut declared = BTreeSet::new();
    for field in PROFILE_LIST_FIELDS {
        for profile in string_array_field(profiles, field)? {
            validate_profile_id(profile)?;
            declared.insert(profile.to_owned());
        }
    }
    for field in MIXED_PROFILE_FIELDS {
        for profile in string_array_field(profiles, field)? {
            if profile.starts_with("ck.profile.") {
                validate_profile_id(profile)?;
                declared.insert(profile.to_owned());
            }
        }
    }
    Ok(declared)
}

fn collect_profile_requirements(
    profiles: &Value,
    declared_profiles: &BTreeSet<String>,
    operation_ids: &BTreeSet<String>,
    event_kinds: &BTreeSet<String>,
    schema_ids: &BTreeSet<String>,
) -> Result<BTreeMap<String, ProfileRequirement>> {
    let requirements = profiles
        .get("profile_requirements")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow!("conformance-profiles missing profile_requirements object"))?;
    let vector_profiles = string_array_field(profiles, "vector_profiles")?
        .into_iter()
        .map(ToOwned::to_owned)
        .collect::<BTreeSet<_>>();

    for vector_profile in &vector_profiles {
        if !requirements.contains_key(vector_profile) {
            bail!("vector profile {vector_profile} missing profile_requirements block");
        }
    }

    let mut matrix = BTreeMap::new();
    for (profile, requirement) in requirements {
        if !declared_profiles.contains(profile) {
            bail!("profile_requirements key {profile} is not declared in any profile catalog");
        }

        let inherited_profiles = collect_profile_refs(requirement, "inherits", declared_profiles)?;
        let required_operations = collect_known_refs(
            requirement,
            "required_endpoints",
            operation_ids,
            "operation",
        )?;
        let required_event_kinds =
            collect_event_kind_refs(requirement, "required_event_kinds", event_kinds, "required")?;
        let _rejected_event_kinds =
            collect_event_kind_refs(requirement, "rejected_event_kinds", event_kinds, "rejected")?;
        let required_schemas =
            collect_known_refs(requirement, "required_schemas", schema_ids, "schema")?;
        let cotest_suites = collect_cotest_suites(requirement, profile)?;

        for extension in string_array_field(requirement, "optional_extensions")? {
            if extension.starts_with("ck.profile.") && !declared_profiles.contains(extension) {
                bail!("{profile} references unknown optional profile {extension}");
            }
        }
        if requirement
            .pointer("/feature_discovery/required")
            .and_then(Value::as_array)
            .is_none()
        {
            bail!("{profile} missing feature_discovery.required[]");
        }

        matrix.insert(
            profile.to_owned(),
            ProfileRequirement {
                inherited_profiles,
                required_operations,
                required_event_kinds,
                required_schemas,
                cotest_suites,
            },
        );
    }
    Ok(matrix)
}

fn collect_profile_refs(
    requirement: &Value,
    field: &str,
    declared_profiles: &BTreeSet<String>,
) -> Result<BTreeSet<String>> {
    let mut refs = BTreeSet::new();
    for profile in string_array_field(requirement, field)? {
        if !declared_profiles.contains(profile) {
            bail!("requirement {field} references unknown profile {profile}");
        }
        refs.insert(profile.to_owned());
    }
    Ok(refs)
}

fn collect_known_refs(
    requirement: &Value,
    field: &str,
    known: &BTreeSet<String>,
    label: &str,
) -> Result<BTreeSet<String>> {
    let mut refs = BTreeSet::new();
    for value in string_array_field(requirement, field)? {
        if !known.contains(value) {
            bail!("requirement {field} references unknown {label} {value}");
        }
        refs.insert(value.to_owned());
    }
    Ok(refs)
}

fn collect_event_kind_refs(
    requirement: &Value,
    field: &str,
    known: &BTreeSet<String>,
    label: &str,
) -> Result<BTreeSet<String>> {
    let mut refs = BTreeSet::new();
    for value in string_array_field(requirement, field)? {
        if let Some(scope) = value.strip_prefix("wire_scope:") {
            if !matches!(
                scope,
                "durable_event" | "actor_private_event" | "ephemeral_event"
            ) {
                bail!("requirement {field} references unknown wire scope {value}");
            }
        } else if !known.contains(value) {
            bail!("requirement {field} references unknown {label} event kind {value}");
        }
        refs.insert(value.to_owned());
    }
    Ok(refs)
}

fn collect_cotest_suites(requirement: &Value, profile: &str) -> Result<BTreeSet<String>> {
    let mut suites = BTreeSet::new();
    if let Some(items) = requirement
        .get("required_cotest_suites")
        .and_then(Value::as_array)
    {
        for item in items {
            let suite = required_str(item, "suite")?;
            suites.insert(suite.to_owned());
        }
    }
    for &(local_profile, suite) in LOCAL_PROFILE_SUITES {
        if local_profile == profile {
            suites.insert(suite.to_owned());
        }
    }

    Ok(suites)
}

fn registry_id_set(
    registry: &Value,
    array_field: &str,
    id_field: &str,
) -> Result<BTreeSet<String>> {
    let entries = registry
        .get(array_field)
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("registry missing {array_field}[]"))?;
    let mut ids = BTreeSet::new();
    for entry in entries {
        let id = required_str(entry, id_field)?;
        if !ids.insert(id.to_owned()) {
            bail!("duplicate registry id {id}");
        }
    }
    Ok(ids)
}

fn validate_server_claims_against_matrix(describe: &Value, matrix: &ProfileMatrix) -> Result<()> {
    let claimed_profiles = string_set_field(describe, "supported_profiles")?;
    let supported_operations = string_set_field(describe, "supported_operations")?;
    let supported_event_kinds = optional_string_set_field(describe, "supported_event_kinds")?;
    let supported_schemas = optional_string_set_field(describe, "supported_event_schemas")?;
    ensure_limited_profiles_are_not_supported(&claimed_profiles)?;
    validate_explicit_unsupported_limited_profiles(describe)?;

    let mut expanded_claims = BTreeSet::new();
    for profile in &claimed_profiles {
        expand_profile_claim(profile, matrix, &mut expanded_claims)?;
    }

    validate_conformance_results(describe, &expanded_claims, matrix)?;

    for profile in expanded_claims {
        let Some(requirement) = matrix.requirements.get(&profile) else {
            continue;
        };
        ensure_subset(
            &requirement.required_operations,
            &supported_operations,
            &format!("{profile} supported_operations"),
        )?;
        if let Some(supported_event_kinds) = &supported_event_kinds {
            let required_events = requirement
                .required_event_kinds
                .iter()
                .filter(|kind| !kind.starts_with("wire_scope:"))
                .cloned()
                .collect::<BTreeSet<_>>();
            ensure_subset(
                &required_events,
                supported_event_kinds,
                &format!("{profile} supported_event_kinds"),
            )?;
        }
        if let Some(supported_schemas) = &supported_schemas {
            ensure_subset(
                &requirement.required_schemas,
                supported_schemas,
                &format!("{profile} supported_event_schemas"),
            )?;
        }
    }

    Ok(())
}

fn ensure_limited_profiles_are_not_supported(claimed_profiles: &BTreeSet<String>) -> Result<()> {
    for profile in claimed_profiles {
        if is_limited_profile(profile) {
            bail!(
                "limited profile {profile} must be listed only under unsupported_profiles, not supported_profiles"
            );
        }
    }
    Ok(())
}

fn validate_explicit_unsupported_limited_profiles(describe: &Value) -> Result<()> {
    let Some(items) = describe
        .get("unsupported_profiles")
        .and_then(Value::as_array)
    else {
        return Ok(());
    };
    for item in items {
        if let Some(profile) = item.as_str() {
            if is_limited_profile(profile) {
                bail!(
                    "limited profile {profile} in unsupported_profiles must use an explicit object with status=unsupported"
                );
            }
            continue;
        }
        let Some(profile) = item.get("profile").and_then(Value::as_str) else {
            bail!("unsupported_profiles entries must be strings or objects with profile");
        };
        if !is_limited_profile(profile) {
            continue;
        }
        if item.get("status").and_then(Value::as_str) != Some("unsupported") {
            bail!("limited profile {profile} must declare status=unsupported");
        }
        if item
            .get("reason")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        {
            bail!("limited profile {profile} must include an unsupported reason");
        }
    }
    Ok(())
}

fn validate_conformance_results(
    describe: &Value,
    expanded_claims: &BTreeSet<String>,
    matrix: &ProfileMatrix,
) -> Result<()> {
    let Some(results) = describe
        .get("conformance_results")
        .and_then(Value::as_object)
    else {
        return Ok(());
    };

    for profile in expanded_claims {
        let Some(result) = results.get(profile) else {
            continue;
        };
        if let Some(status) = result_status(result)
            && is_failed_conformance_status(status)
        {
            bail!("server claims profile {profile} but conformance status is {status}");
        }
        let Some(requirement) = matrix.requirements.get(profile) else {
            continue;
        };
        let Some(suites) = result.get("suites").and_then(Value::as_object) else {
            continue;
        };
        for suite in &requirement.cotest_suites {
            if let Some(status) = suites.get(suite).and_then(result_status)
                && is_failed_conformance_status(status)
            {
                bail!(
                    "server claims profile {profile} but required cotest suite {suite} is {status}"
                );
            }
        }
    }
    Ok(())
}

fn result_status(value: &Value) -> Option<&str> {
    value
        .as_str()
        .or_else(|| value.get("status").and_then(Value::as_str))
}

fn is_failed_conformance_status(status: &str) -> bool {
    matches!(
        status,
        "fail" | "failed" | "error" | "regression" | "skipped" | "not_run" | "unsupported"
    )
}

fn is_limited_profile(profile: &str) -> bool {
    profile.starts_with("ck.profile.")
        && profile.ends_with(".v1")
        && (profile.contains(".limited_")
            || profile.contains("_limited_")
            || profile.contains("_limited."))
}

fn expand_profile_claim(
    profile: &str,
    matrix: &ProfileMatrix,
    expanded: &mut BTreeSet<String>,
) -> Result<()> {
    if !matrix.declared_profiles.contains(profile) {
        bail!("server claims unknown profile {profile}");
    }
    if !expanded.insert(profile.to_owned()) {
        return Ok(());
    }
    if let Some(requirement) = matrix.requirements.get(profile) {
        for inherited in &requirement.inherited_profiles {
            expand_profile_claim(inherited, matrix, expanded)?;
        }
    }
    Ok(())
}

fn ensure_subset(
    required: &BTreeSet<String>,
    actual: &BTreeSet<String>,
    context: &str,
) -> Result<()> {
    for required in required {
        if !actual.contains(required) {
            bail!("{context} missing required value {required}");
        }
    }
    Ok(())
}

fn string_set_field(value: &Value, field: &str) -> Result<BTreeSet<String>> {
    Ok(string_array_field(value, field)?
        .into_iter()
        .map(ToOwned::to_owned)
        .collect())
}

fn optional_string_set_field(value: &Value, field: &str) -> Result<Option<BTreeSet<String>>> {
    if value.get(field).is_none() {
        return Ok(None);
    }
    string_set_field(value, field).map(Some)
}

fn validate_profile_id(profile: &str) -> Result<()> {
    if !profile.starts_with("ck.profile.") || !profile.ends_with(".v1") {
        bail!("invalid profile id {profile}");
    }
    Ok(())
}
