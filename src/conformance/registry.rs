use std::{
    collections::{BTreeSet, HashMap},
    fs,
};

use anyhow::{Result, anyhow, bail};
use serde_json::Value;

use super::{
    ARTIFACT_FIXTURES_DIR, RegistryManifestEntry, load_artifact_json, load_artifact_yaml,
    required_str, spec_artifacts_root, string_array_field,
};

pub fn run_artifact_registry_suite() -> Result<()> {
    let root = spec_artifacts_root();
    let registry_manifest = load_artifact_json("registry/registry-manifest.json")?;
    let schema_registry = load_artifact_json("registry/schema-registry.json")?;
    let event_kind_registry = load_artifact_json("registry/event-kind-registry.json")?;
    let operation_registry = load_artifact_json("registry/operation-registry.json")?;
    let id_kind_registry = load_artifact_json("registry/id-kind-registry.json")?;
    let conformance_profiles = load_artifact_json("profiles/conformance-profiles.json")?;
    let openapi = load_artifact_yaml("openapi/contrix-service-api.openapi.yaml")?;
    let non_http_bindings = load_artifact_yaml("bindings/non-http-bindings.yaml")?;
    let registry_entries = validate_registry_manifest(&root, &registry_manifest)?;

    let schema_ids = validate_schema_registry(
        &root,
        &schema_registry,
        registry_manifest_entry(&registry_entries, "registry/schema-registry.json")?,
    )?;
    let (event_kinds, component_types) = validate_event_kind_registry(
        &root,
        &event_kind_registry,
        registry_manifest_entry(&registry_entries, "registry/event-kind-registry.json")?,
    )?;
    let operation_ids = validate_operation_registry(
        &operation_registry,
        registry_manifest_entry(&registry_entries, "registry/operation-registry.json")?,
    )?;
    let id_kinds = validate_id_kind_registry(
        &id_kind_registry,
        registry_manifest_entry(&registry_entries, "registry/id-kind-registry.json")?,
    )?;
    let (profiles, core_profiles) = validate_profile_registry(&conformance_profiles)?;
    validate_profile_requirements(
        &root,
        &conformance_profiles,
        &core_profiles,
        &event_kinds,
        &operation_ids,
        &schema_ids,
        &component_types,
    )?;
    validate_openapi_operation_refs(&openapi, &operation_ids)?;
    validate_non_http_binding_refs(&non_http_bindings, &operation_ids)?;

    validate_fixture_artifact_refs(
        &root,
        &profiles,
        &event_kinds,
        &operation_ids,
        &id_kinds,
        &schema_ids,
    )?;

    Ok(())
}

fn validate_registry_manifest(
    root: &std::path::Path,
    manifest: &Value,
) -> Result<HashMap<String, RegistryManifestEntry>> {
    if manifest.get("source_of_truth").and_then(Value::as_bool) != Some(true) {
        bail!("registry-manifest must declare source_of_truth=true");
    }
    let registries = manifest
        .get("registries")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("registry-manifest missing registries"))?;
    let mut entries = HashMap::new();
    for entry in registries {
        let file = required_str(entry, "file")?;
        if !root.join(file).is_file() {
            bail!("registry-manifest references missing file {file}");
        }
        let kind = required_str(entry, "kind")?;
        let source_role = required_str(entry, "source_role")?;
        let source_of_truth = entry
            .get("source_of_truth")
            .and_then(Value::as_bool)
            .ok_or_else(|| anyhow!("registry-manifest entry {file} missing source_of_truth"))?;
        let generated_from = entry
            .get("generated_from")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        match source_role {
            "canonical" => {
                if !source_of_truth {
                    bail!(
                        "registry-manifest canonical entry {file} must declare source_of_truth=true"
                    );
                }
                if generated_from.is_some() {
                    bail!(
                        "registry-manifest canonical entry {file} must not declare generated_from"
                    );
                }
            }
            "generated" => {
                if source_of_truth {
                    bail!(
                        "registry-manifest generated entry {file} must declare source_of_truth=false"
                    );
                }
                let generated_from = generated_from.as_deref().ok_or_else(|| {
                    anyhow!("registry-manifest generated entry {file} missing generated_from")
                })?;
                if !root.join(generated_from).is_file() {
                    bail!(
                        "registry-manifest generated entry {file} references missing source {generated_from}"
                    );
                }
            }
            other => bail!("registry-manifest entry {file} has invalid source_role {other}"),
        }
        if entries
            .insert(
                file.to_owned(),
                RegistryManifestEntry {
                    kind: kind.to_owned(),
                    source_role: source_role.to_owned(),
                    source_of_truth,
                    generated_from,
                },
            )
            .is_some()
        {
            bail!("registry-manifest duplicate file entry {file}");
        }
    }
    Ok(entries)
}

fn registry_manifest_entry<'a>(
    entries: &'a HashMap<String, RegistryManifestEntry>,
    file: &str,
) -> Result<&'a RegistryManifestEntry> {
    entries
        .get(file)
        .ok_or_else(|| anyhow!("registry-manifest missing {file}"))
}

fn validate_registry_metadata(
    registry_name: &str,
    registry: &Value,
    expected_kind: &str,
    manifest_entry: &RegistryManifestEntry,
) -> Result<()> {
    if manifest_entry.kind != expected_kind {
        bail!(
            "{registry_name} kind drifted: expected {expected_kind}, got {}",
            manifest_entry.kind
        );
    }
    let source_of_truth = registry
        .get("source_of_truth")
        .and_then(Value::as_bool)
        .ok_or_else(|| anyhow!("{registry_name} missing source_of_truth"))?;
    if source_of_truth != manifest_entry.source_of_truth {
        bail!(
            "{registry_name} source_of_truth drifted: expected {}, got {}",
            manifest_entry.source_of_truth,
            source_of_truth
        );
    }
    match manifest_entry.source_role.as_str() {
        "canonical" => {
            if registry.get("generated_from").is_some() {
                bail!("{registry_name} canonical registry must not declare generated_from");
            }
        }
        "generated" => {
            let generated_from = required_str(registry, "generated_from")?;
            if Some(generated_from) != manifest_entry.generated_from.as_deref() {
                bail!(
                    "{registry_name} generated_from drifted: expected {:?}, got {generated_from}",
                    manifest_entry.generated_from
                );
            }
        }
        other => bail!("{registry_name} manifest source_role drifted to {other}"),
    }
    Ok(())
}

fn validate_schema_registry(
    root: &std::path::Path,
    registry: &Value,
    manifest_entry: &RegistryManifestEntry,
) -> Result<BTreeSet<String>> {
    validate_registry_metadata(
        "schema registry",
        registry,
        "schema_registry",
        manifest_entry,
    )?;
    let schemas = registry
        .get("schemas")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("schema registry missing schemas"))?;
    let mut ids = BTreeSet::new();
    for schema in schemas {
        let schema_id = required_str(schema, "schema_id")?;
        if !schema_id.starts_with("cx.schema.") {
            bail!("schema registry contains non-standard id {schema_id}");
        }
        if !ids.insert(schema_id.to_owned()) {
            bail!("duplicate schema id {schema_id}");
        }
        let file = required_str(schema, "file")?;
        let path = root.join(file);
        if !path.is_file() {
            bail!(
                "schema registry file missing for {schema_id}: {}",
                path.display()
            );
        }
        let raw = fs::read_to_string(&path)?;
        serde_json::from_str::<Value>(&raw)
            .map_err(|error| anyhow!("schema file {} is not JSON: {error}", path.display()))?;
    }
    for required in ["cx.schema.event.v1", "cx.schema.event_payload.v1"] {
        if !ids.contains(required) {
            bail!("schema registry missing required {required}");
        }
    }
    Ok(ids)
}

fn validate_event_kind_registry(
    root: &std::path::Path,
    registry: &Value,
    manifest_entry: &RegistryManifestEntry,
) -> Result<(BTreeSet<String>, BTreeSet<String>)> {
    validate_registry_metadata(
        "event-kind registry",
        registry,
        "event_kind_registry",
        manifest_entry,
    )?;
    let envelope_schema = registry
        .pointer("/payload_schema_contract/event_envelope_schema")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("event-kind registry missing event envelope schema ref"))?;
    if !root.join(envelope_schema).is_file() {
        bail!("event envelope schema ref missing: {envelope_schema}");
    }

    let event_kinds = registry
        .get("event_kinds")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("event-kind registry missing event_kinds"))?;
    let mut ids = BTreeSet::new();
    let mut deprecated = BTreeSet::new();
    let mut active_count = 0usize;
    let mut component_types = BTreeSet::new();
    for entry in event_kinds {
        let event_kind = required_str(entry, "event_kind")?;
        if !event_kind.starts_with("cx.") {
            bail!("event kind must use cx.* namespace: {event_kind}");
        }
        if !ids.insert(event_kind.to_owned()) {
            bail!("duplicate event kind {event_kind}");
        }
        let status = required_str(entry, "status")?;
        let wire_scope = required_str(entry, "wire_scope")?;
        if status == "active" && wire_scope == "deprecated_alias" {
            bail!("active event kind {event_kind} cannot be deprecated_alias");
        }
        if status == "active" {
            active_count += 1;
        }
        if status == "deprecated" || wire_scope == "deprecated_alias" {
            deprecated.insert(event_kind.to_owned());
            if entry.get("replaced_by").and_then(Value::as_str).is_none() {
                bail!("deprecated event kind {event_kind} missing replaced_by");
            }
        }
        if let Some(component_type) = entry.get("component_type").and_then(Value::as_str) {
            component_types.insert(component_type.to_owned());
        }
        // W12 partial: every active state-bearing kind must declare the
        // (state_cardinality, component_type, criticality) triple. per_subject
        // kinds additionally need a state_subject_field. Anything missing
        // would silently reduce reducer behaviour to "kind not state-bearing"
        // and let stale-spec implementations slip through.
        if status == "active" {
            if let Some(cardinality) = entry.get("state_cardinality").and_then(Value::as_str) {
                if cardinality != "not_state" {
                    let _ = entry
                        .get("component_type")
                        .and_then(Value::as_str)
                        .ok_or_else(|| {
                            anyhow!(
                                "active state kind {event_kind} missing component_type"
                            )
                        })?;
                    let _ = entry
                        .get("criticality")
                        .and_then(Value::as_str)
                        .ok_or_else(|| {
                            anyhow!(
                                "active state kind {event_kind} missing criticality"
                            )
                        })?;
                    if cardinality == "per_subject"
                        && entry
                            .get("state_subject_field")
                            .and_then(Value::as_str)
                            .is_none()
                    {
                        bail!(
                            "active per_subject state kind {event_kind} missing state_subject_field"
                        );
                    }
                }
            }
        }
    }
    for alias in deprecated {
        if !ids.contains(&alias) {
            bail!("deprecated alias set drift for {alias}");
        }
    }
    // Wire model rework gate: post-Phase 1-5 spec must expose >=129 active kinds
    // (110 baseline + 17 per-facet/lifecycle splits + 2 host kinds + 2 consent kinds
    // - 2 retired aggregates).
    const MIN_ACTIVE_EVENT_KINDS: usize = 129;
    if active_count < MIN_ACTIVE_EVENT_KINDS {
        bail!(
            "event-kind registry has {active_count} active kinds, expected >= {MIN_ACTIVE_EVENT_KINDS} (wire model rework gate)"
        );
    }
    // Phase 4 host writer model + Phase 5 consent state machine must be wired
    // with the cardinality / criticality the spec mandates.
    let required_kinds: &[(&str, &str, &str)] = &[
        ("cx.space.host", "singleton", "required"),
        ("cx.space.host.transfer", "per_subject", "required"),
        ("cx.consent.grant", "per_subject", "required"),
        ("cx.consent.revoke", "per_subject", "required"),
    ];
    for (kind, expected_cardinality, expected_criticality) in required_kinds {
        let entry = event_kinds
            .iter()
            .find(|e| e.get("event_kind").and_then(Value::as_str) == Some(kind))
            .ok_or_else(|| {
                anyhow!("event-kind registry missing required wire-model kind {kind}")
            })?;
        let cardinality = required_str(entry, "state_cardinality")?;
        if cardinality != *expected_cardinality {
            bail!(
                "wire-model kind {kind} must have state_cardinality={expected_cardinality}, got {cardinality}"
            );
        }
        let criticality = required_str(entry, "criticality")?;
        if criticality != *expected_criticality {
            bail!(
                "wire-model kind {kind} must have criticality={expected_criticality}, got {criticality}"
            );
        }
    }
    Ok((ids, component_types))
}

fn validate_operation_registry(
    registry: &Value,
    manifest_entry: &RegistryManifestEntry,
) -> Result<BTreeSet<String>> {
    validate_registry_metadata(
        "operation registry",
        registry,
        "operation_registry",
        manifest_entry,
    )?;
    let operations = registry
        .get("operations")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("operation registry missing operations"))?;
    let mut ids = BTreeSet::new();
    for entry in operations {
        let operation_id = required_str(entry, "operation_id")?;
        if !operation_id.starts_with("cx.") {
            bail!("operation id must use cx.* namespace: {operation_id}");
        }
        if !ids.insert(operation_id.to_owned()) {
            bail!("duplicate operation id {operation_id}");
        }
        for field in ["http", "grpc", "mq"] {
            required_str(entry, field)?;
        }
    }
    for required in [
        "cx.events.describe",
        "cx.events.submit",
        "cx.sync.client_sync",
    ] {
        if !ids.contains(required) {
            bail!("operation registry missing required {required}");
        }
    }
    Ok(ids)
}

fn validate_id_kind_registry(
    registry: &Value,
    manifest_entry: &RegistryManifestEntry,
) -> Result<BTreeSet<String>> {
    validate_registry_metadata(
        "id-kind registry",
        registry,
        "id_kind_registry",
        manifest_entry,
    )?;
    let mut special_kinds = BTreeSet::new();
    for form in registry
        .get("special_forms")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let kind = required_str(form, "kind")?;
        if !special_kinds.insert(kind.to_owned()) {
            bail!("duplicate special id kind {kind}");
        }
    }
    let mut regular_kinds = BTreeSet::new();
    for kind in registry
        .get("id_kinds")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("id-kind registry missing id_kinds"))?
    {
        let id_kind = required_str(kind, "kind")?;
        if !regular_kinds.insert(id_kind.to_owned()) {
            bail!("duplicate id kind {id_kind}");
        }
        let wire_form = required_str(kind, "wire_form")?;
        if !wire_form.starts_with(&format!("cx:{id_kind}:")) {
            bail!("id kind {id_kind} wire_form drifted: {wire_form}");
        }
    }
    let mut kinds = regular_kinds;
    kinds.extend(special_kinds);
    if !kinds.contains("event") {
        bail!("id-kind registry missing event");
    }
    Ok(kinds)
}

fn validate_profile_registry(registry: &Value) -> Result<(BTreeSet<String>, BTreeSet<String>)> {
    let mut core_profiles = BTreeSet::new();
    let mut extension_profiles = BTreeSet::new();
    // Core profiles that require profile_requirements entries
    for field in [
        "implementation_profiles",
        "deployment_profiles",
        "hardening_profiles",
        "vector_profiles",
        // Phase 4: Space-level writer model profiles (hub_writer / peer_mesh).
        // Each Space create-locks one of these; profile_requirements lists them.
        "writer_model_profiles",
    ] {
        if let Some(array) = registry.get(field).and_then(Value::as_array) {
            for profile in array {
                let profile = profile.as_str().ok_or_else(|| {
                    anyhow!("conformance profile entry in {field} is not a string")
                })?;
                if !profile.starts_with("cx.profile.") {
                    bail!("invalid profile id {profile}");
                }
                core_profiles.insert(profile.to_owned());
            }
        }
    }
    // Extension profiles (may not have profile_requirements)
    for field in [
        "identity_extension_profiles",
        "constraint_extension_profiles",
        "encoding_extension_profiles",
    ] {
        if let Some(array) = registry.get(field).and_then(Value::as_array) {
            for profile in array {
                let profile = profile.as_str().ok_or_else(|| {
                    anyhow!("conformance profile entry in {field} is not a string")
                })?;
                if !profile.starts_with("cx.profile.") {
                    bail!("invalid profile id {profile}");
                }
                extension_profiles.insert(profile.to_owned());
            }
        }
    }
    // Hardening lists may mix profile ids with feature-flag tokens (e.g.
    // "service_did_authentication"). Pick out any cx.profile.* entries so the
    // total profile count matches the spec's published catalogue.
    for field in [
        "e2ee_hardening",
        "federation_hardening",
        "privacy_hardening",
        "mimi_interop",
    ] {
        if let Some(array) = registry.get(field).and_then(Value::as_array) {
            for profile in array {
                if let Some(profile) = profile.as_str() {
                    if profile.starts_with("cx.profile.") {
                        extension_profiles.insert(profile.to_owned());
                    }
                }
            }
        }
    }
    let mut all_profiles = core_profiles.clone();
    all_profiles.extend(extension_profiles.clone());
    for required in [
        "cx.profile.core_event_store.v1",
        "cx.profile.chat_mvp.v1",
        "cx.profile.kanban_mvp.v1",
        "cx.profile.push_gateway.v1",
        // Phase 4 Hybrid Writer Model: each Space create-locks one of these.
        "cx.profile.space.hub_writer.v1",
        "cx.profile.space.peer_mesh.v1",
        // Phase 3 E2EE state binding: promoted from optional extension to
        // mandatory inherits of e2ee_client.
        "cx.profile.mls_state_binding.full.v1",
    ] {
        if !all_profiles.contains(required) {
            bail!("conformance profiles missing required {required}");
        }
    }
    // Wire model rework gate: post-Phase 1-5 the spec catalogues >= 50 profile ids.
    const MIN_PROFILE_COUNT: usize = 50;
    if all_profiles.len() < MIN_PROFILE_COUNT {
        bail!(
            "conformance profiles registry has {} ids, expected >= {MIN_PROFILE_COUNT} (wire model rework gate)",
            all_profiles.len()
        );
    }
    Ok((all_profiles, core_profiles))
}

fn validate_profile_requirements(
    root: &std::path::Path,
    registry: &Value,
    core_profiles: &BTreeSet<String>,
    event_kinds: &BTreeSet<String>,
    operation_ids: &BTreeSet<String>,
    schema_ids: &BTreeSet<String>,
    component_types: &BTreeSet<String>,
) -> Result<()> {
    let requirements = registry
        .get("profile_requirements")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow!("conformance profiles missing profile_requirements"))?;

    // Only core profiles must have profile_requirements entries
    for profile in core_profiles {
        if !requirements.contains_key(profile) {
            bail!("conformance profile {profile} missing profile_requirements entry");
        }
    }

    // Phase 3 binding: e2ee_client MUST inherit mls_state_binding.full.v1 directly,
    // not as an optional extension.
    let e2ee_client = requirements
        .get("cx.profile.e2ee_client.v1")
        .ok_or_else(|| anyhow!("e2ee_client.v1 missing profile_requirements entry"))?;
    let inherits = string_array_field(e2ee_client, "inherits")?;
    if !inherits
        .iter()
        .any(|p| *p == "cx.profile.mls_state_binding.full.v1")
    {
        bail!(
            "e2ee_client.v1 must inherit cx.profile.mls_state_binding.full.v1 (Phase 3 binding)"
        );
    }

    // Phase 3 binding requires three component-type lists naming registered
    // component_type values. Each list is non-empty (an empty list would
    // silently disable the corresponding frontier check).
    let mls_binding = requirements
        .get("cx.profile.mls_state_binding.full.v1")
        .ok_or_else(|| {
            anyhow!("mls_state_binding.full.v1 missing profile_requirements entry")
        })?;
    for field in [
        "policy_root_required_components",
        "membership_frontier_required_components",
        "capability_root_required_components",
    ] {
        let entries = string_array_field(mls_binding, field)?;
        if entries.is_empty() {
            bail!("mls_state_binding.full.v1 has empty {field} (cannot be enforceable)");
        }
        for component in &entries {
            if !component_types.contains(*component) {
                bail!(
                    "mls_state_binding.full.v1 {field} references unknown component_type {component}"
                );
            }
        }
    }

    for (profile, requirement) in requirements {
        // profile_requirements can reference both core and extension profiles
        // but only core_profiles are required to have entries
        if !requirements.contains_key(profile) {
            continue; // Skip extension profiles without requirements
        }

        for inherited in string_array_field(requirement, "inherits")? {
            if !core_profiles.contains(inherited) {
                bail!("{profile} inherits unknown profile {inherited}");
            }
        }
        for endpoint in string_array_field(requirement, "required_endpoints")? {
            if !operation_ids.contains(endpoint) {
                bail!("{profile} requires unknown endpoint operation {endpoint}");
            }
        }
        for event_kind in string_array_field(requirement, "required_event_kinds")? {
            if !event_kinds.contains(event_kind) {
                bail!("{profile} requires unknown event kind {event_kind}");
            }
        }
        for rejected in string_array_field(requirement, "rejected_event_kinds")? {
            if rejected.starts_with("wire_scope:") {
                continue;
            }
            if !event_kinds.contains(rejected) {
                bail!("{profile} rejects unknown event kind {rejected}");
            }
        }
        for schema_id in string_array_field(requirement, "required_schemas")? {
            if !schema_ids.contains(schema_id) {
                bail!("{profile} requires unknown schema {schema_id}");
            }
        }
        for fixture in string_array_field(requirement, "required_fixtures")? {
            if !root.join(ARTIFACT_FIXTURES_DIR).join(fixture).is_file() {
                bail!("{profile} requires missing fixture {fixture}");
            }
        }
        for extension in string_array_field(requirement, "optional_extensions")? {
            if extension.starts_with("cx.profile.") && !core_profiles.contains(extension) {
                bail!("{profile} references unknown optional profile {extension}");
            }
        }
        if requirement
            .pointer("/feature_discovery/required")
            .and_then(Value::as_array)
            .is_none()
        {
            bail!("{profile} missing feature_discovery.required");
        }
    }

    Ok(())
}

fn validate_openapi_operation_refs(
    openapi: &serde_yaml::Value,
    operation_ids: &BTreeSet<String>,
) -> Result<()> {
    let mut discovered = BTreeSet::new();
    collect_yaml_values_for_key(openapi, "operationId", &mut discovered);
    if discovered.is_empty() {
        bail!("OpenAPI artifact did not expose any operationId values");
    }
    for operation_id in &discovered {
        if !operation_ids.contains(operation_id) {
            bail!("OpenAPI references unknown operation id {operation_id}");
        }
    }
    for operation_id in operation_ids {
        if !discovered.contains(operation_id) {
            bail!("operation registry {operation_id} missing from OpenAPI artifact");
        }
    }
    Ok(())
}

fn validate_non_http_binding_refs(
    bindings: &serde_yaml::Value,
    operation_ids: &BTreeSet<String>,
) -> Result<()> {
    let mut discovered = BTreeSet::new();
    collect_yaml_operation_like_values(bindings, &mut discovered);
    if discovered.is_empty() {
        bail!("non-HTTP binding artifact did not expose operation refs");
    }
    for operation_id in discovered {
        if !operation_ids.contains(&operation_id) {
            bail!("non-HTTP binding references unknown operation id {operation_id}");
        }
    }
    Ok(())
}

fn collect_yaml_values_for_key(
    value: &serde_yaml::Value,
    wanted_key: &str,
    values: &mut BTreeSet<String>,
) {
    match value {
        serde_yaml::Value::Mapping(map) => {
            for (key, child) in map {
                if key.as_str() == Some(wanted_key) {
                    if let Some(value) = child.as_str() {
                        values.insert(value.to_owned());
                    }
                }
                collect_yaml_values_for_key(child, wanted_key, values);
            }
        }
        serde_yaml::Value::Sequence(items) => {
            for item in items {
                collect_yaml_values_for_key(item, wanted_key, values);
            }
        }
        _ => {}
    }
}

fn collect_yaml_operation_like_values(value: &serde_yaml::Value, values: &mut BTreeSet<String>) {
    match value {
        serde_yaml::Value::Mapping(map) => {
            for child in map.values() {
                collect_yaml_operation_like_values(child, values);
            }
        }
        serde_yaml::Value::Sequence(items) => {
            for item in items {
                collect_yaml_operation_like_values(item, values);
            }
        }
        serde_yaml::Value::String(text) if text.starts_with("cx.") => {
            values.insert(text.to_owned());
        }
        _ => {}
    }
}

fn validate_fixture_artifact_refs(
    root: &std::path::Path,
    profiles: &BTreeSet<String>,
    event_kinds: &BTreeSet<String>,
    operation_ids: &BTreeSet<String>,
    id_kinds: &BTreeSet<String>,
    schema_ids: &BTreeSet<String>,
) -> Result<()> {
    let fixture_root = root.join(ARTIFACT_FIXTURES_DIR);
    for entry in fs::read_dir(&fixture_root)? {
        let path = entry?.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        let raw = fs::read_to_string(&path)?;
        let value: Value = serde_json::from_str(&raw)
            .map_err(|error| anyhow!("fixture {} is not JSON: {error}", path.display()))?;
        if let Some(profile) = value.get("profile").and_then(Value::as_str) {
            if !profiles.contains(profile) {
                bail!(
                    "fixture {} references unknown profile {profile}",
                    path.display()
                );
            }
        }
        validate_value_refs(
            &value,
            path.file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("fixture"),
            event_kinds,
            operation_ids,
            id_kinds,
            schema_ids,
        )?;
    }
    Ok(())
}

fn validate_value_refs(
    value: &Value,
    context: &str,
    event_kinds: &BTreeSet<String>,
    operation_ids: &BTreeSet<String>,
    id_kinds: &BTreeSet<String>,
    schema_ids: &BTreeSet<String>,
) -> Result<()> {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                match (key.as_str(), child.as_str()) {
                    ("operation_id", Some(operation_id)) => {
                        if !operation_ids.contains(operation_id) {
                            bail!("{context} references unknown operation id {operation_id}");
                        }
                    }
                    ("event_kind", Some(event_kind)) => {
                        if !event_kinds.contains(event_kind) {
                            bail!("{context} references unknown event kind {event_kind}");
                        }
                    }
                    ("kind", Some(kind)) if kind.starts_with("cx.") => {
                        if !event_kinds.contains(kind) {
                            bail!("{context} references unknown event kind {kind}");
                        }
                    }
                    ("schema_id", Some(schema_id)) => {
                        if !schema_ids.contains(schema_id) {
                            bail!("{context} references unknown schema id {schema_id}");
                        }
                    }
                    _ => {}
                }
                validate_value_refs(
                    child,
                    context,
                    event_kinds,
                    operation_ids,
                    id_kinds,
                    schema_ids,
                )?;
            }
        }
        Value::Array(items) => {
            for child in items {
                validate_value_refs(
                    child,
                    context,
                    event_kinds,
                    operation_ids,
                    id_kinds,
                    schema_ids,
                )?;
            }
        }
        Value::String(text) => validate_typed_id_ref(text, context, id_kinds)?,
        _ => {}
    }
    Ok(())
}

fn validate_typed_id_ref(value: &str, context: &str, id_kinds: &BTreeSet<String>) -> Result<()> {
    let Some(rest) = value.strip_prefix("cx:") else {
        return Ok(());
    };
    let Some((kind, _tail)) = rest.split_once(':') else {
        return Ok(());
    };
    if !id_kinds.contains(kind) {
        bail!("{context} references unknown typed id kind {kind}: {value}");
    }
    Ok(())
}
