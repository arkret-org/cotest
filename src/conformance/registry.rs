use std::collections::{BTreeSet, HashMap};
use std::fs;

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
    let openapi = load_artifact_yaml("openapi/cokret-service-api.openapi.yaml")?;
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
        &profiles,
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
    for required in ["ck.schema.event.v1", "ck.schema.event_payload.v1"] {
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
        // Move/Anchor/Lattice gate (spec 2026-05-08, tightened M11
        // 2026-05-09): every active reducer-input durable kind that declares
        // `cell_family` MUST also declare a `cell_subject` (object) — null /
        // missing cell_subject silently routes the kind into the cell-family
        // singleton bucket which is almost never what we want for v1 wire
        // semantics. The (cell_family, lattice, bottom, cell_subject) tuple
        // MUST be coherent.
        if status == "active"
            && entry.get("reducer_input").and_then(Value::as_bool) == Some(true)
            && wire_scope == "durable_event"
            && entry.get("cell_family").is_some()
        {
            let cell_family = required_str(entry, "cell_family")?;
            if !cell_family.starts_with("cx.component.") {
                bail!(
                    "reducer-input kind {event_kind} cell_family {cell_family} must start with cx.component."
                );
            }
            let lattice = required_str(entry, "lattice")?;
            const ALLOWED_LATTICES: &[&str] = &[
                "or_set",
                "mv_register",
                "cas_register",
                "fsm",
                "counter",
                "ordered_log",
            ];
            if !ALLOWED_LATTICES.contains(&lattice) {
                bail!("reducer-input kind {event_kind} lattice {lattice} not in core set");
            }
            let bottom = required_str(entry, "bottom")?;
            if bottom != "reject" && bottom != "expose" {
                bail!(
                    "reducer-input kind {event_kind} bottom must be reject or expose, got {bottom}"
                );
            }
            // M11 (spec 2026-05-09): cell_subject MUST be PRESENT (the field
            // itself, even when null). The explicit `cell_subject: null` form
            // declares "space-singleton cell" — one cell per space, keyed by
            // the implicit space_id from the envelope. Kinds where this is
            // the right semantics (ck.realm.policy / ck.realm.history_visibility /
            // ck.space.archive / ...) MUST still set the field to null rather
            // than omit it, so the schema-level intent is unambiguous. A
            // MISSING field is rejected.
            let subject = entry.get("cell_subject").ok_or_else(|| {
                anyhow!(
                    "reducer-input kind {event_kind} declares cell_family but missing cell_subject field (M11: space-singleton cells must set `cell_subject: null` explicitly)"
                )
            })?;
            if !subject.is_null() {
                // Subject shape: single-field (`{type: <scalar>, field: payload.X}`)
                // OR composite/tuple (`{type: composite|tuple, components: [...]}`).
                let obj = subject.as_object().ok_or_else(|| {
                    anyhow!(
                        "reducer-input kind {event_kind} cell_subject must be null or an object"
                    )
                })?;
                let has_field = obj.get("field").and_then(Value::as_str).is_some();
                let multi_field_type = obj.get("type").and_then(Value::as_str);
                let is_multi_field = matches!(multi_field_type, Some("composite") | Some("tuple"))
                    && obj.get("components").and_then(Value::as_array).is_some();
                if !has_field && !is_multi_field {
                    bail!(
                        "reducer-input kind {event_kind} cell_subject must declare `field` or be a `composite` / `tuple` with `components[]`"
                    );
                }
            }
        }
    }
    for alias in deprecated {
        if !ids.contains(&alias) {
            bail!("deprecated alias set drift for {alias}");
        }
    }
    // M11 (spec 2026-05-09): post-Move/Anchor/Lattice spec exposes 132
    // active kinds (110 baseline + 17 per-facet/lifecycle splits + 2
    // consent kinds + 3 anchor/move/anchorer kinds; cx.realm.host* removed in
    // favour of anchorer cell governance). The 134 floor in the round-20
    // mission was aspirational; the spec snapshot at f724863 carries 132,
    // and we hold the line at the spec count to avoid silently shrinking.
    const MIN_ACTIVE_EVENT_KINDS: usize = 132;
    if active_count < MIN_ACTIVE_EVENT_KINDS {
        bail!(
            "event-kind registry has {active_count} active kinds, expected >= {MIN_ACTIVE_EVENT_KINDS} (wire model rework gate)"
        );
    }
    // Holder-private consent (cell or-set) MUST be wired per Move/Anchor/Lattice
    // spec (2026-05-08): both grant and revoke share cell_family
    // ck.component.consent.grant.v1, lattice or-set, cell_subject keyed by
    // payload.consent_id. cx.realm.host{,.transfer} are intentionally
    // removed (anchorer cell governs Anchor signing).
    let required_kinds: &[(&str, &str, &str)] = &[
        (
            "ck.consent.grant",
            "or_set",
            "ck.component.consent.grant.v1",
        ),
        (
            "ck.consent.revoke",
            "or_set",
            "ck.component.consent.grant.v1",
        ),
    ];
    for (kind, expected_lattice, expected_cell_family) in required_kinds {
        let entry = event_kinds
            .iter()
            .find(|e| e.get("event_kind").and_then(Value::as_str) == Some(kind))
            .ok_or_else(|| {
                anyhow!("event-kind registry missing required wire-model kind {kind}")
            })?;
        let lattice = required_str(entry, "lattice")?;
        if lattice != *expected_lattice {
            bail!("wire-model kind {kind} must have lattice={expected_lattice}, got {lattice}");
        }
        let cell_family = required_str(entry, "cell_family")?;
        if cell_family != *expected_cell_family {
            bail!(
                "wire-model kind {kind} must have cell_family={expected_cell_family}, got {cell_family}"
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
        "ck.events.describe",
        "ck.events.submit",
        "ck.account.subscribe",
    ] {
        if !ids.contains(required) {
            bail!("operation registry missing required {required}");
        }
    }

    // C16 (spec 2026-05-08): operation_registry.capability_tiers expanded
    // from 3 values (core / extension / deployment_local) to 4 with
    // `interop_bridge` (adapter surfaces for external protocols like MIMI /
    // Applet). Validate that the spec-declared tier vocabulary contains all
    // four values so future cotest tier filtering doesn't silently drop
    // adapter ops as `unknown_tier`.
    if let Some(tiers) = registry.get("capability_tiers").and_then(|t| t.as_array()) {
        let tier_set: std::collections::BTreeSet<&str> = tiers
            .iter()
            .filter_map(|t| t.get("name").and_then(Value::as_str))
            .collect();
        for required_tier in ["core", "extension", "deployment_local", "interop_bridge"] {
            if !tier_set.contains(required_tier) {
                bail!(
                    "operation_registry.capability_tiers missing required tier '{required_tier}' \
                     (spec C16, 2026-05-08)"
                );
            }
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
        if !wire_form.starts_with(&format!("ck:{id_kind}:")) {
            bail!("id kind {id_kind} wire_form drifted: {wire_form}");
        }
        // C19.A wire-break (spec f724863, 2026-05-09): per-id_kind wire_form
        // MUST end in `<uuid>` placeholder — the canonical typed-id payload is
        // a UUIDv7 (RFC 9562) string. Legacy ULID payloads (`<ulid>` token)
        // are forbidden in the unreleased v1 wire; this is a hard reject.
        if wire_form.contains("<ulid>") {
            bail!(
                "id kind {id_kind} wire_form retains legacy <ulid> token; spec post-2026-05-09 mandates <uuid> (UUIDv7)"
            );
        }
        if !wire_form.ends_with("<uuid>") {
            bail!("id kind {id_kind} wire_form must terminate in <uuid>: {wire_form}");
        }
    }
    let mut kinds = regular_kinds;
    kinds.extend(special_kinds);
    if !kinds.contains("event") {
        bail!("id-kind registry missing event");
    }

    // C19.A wire-break (spec f724863, 2026-05-09): top-level `uuid_pattern` /
    // `typed_uuid_pattern` MUST be the canonical UUIDv7 regex pair (replaces
    // the older `ulid_pattern` / `typed_ulid_pattern` which are now forbidden
    // wire-tokens). Validator rejects fixtures that retain the old field
    // names so a stale spec snapshot fails loudly.
    if registry.get("ulid_pattern").is_some() || registry.get("typed_ulid_pattern").is_some() {
        bail!(
            "id-kind registry retains legacy ulid_pattern / typed_ulid_pattern fields; spec post-2026-05-09 mandates uuid_pattern / typed_uuid_pattern"
        );
    }
    let uuid_pattern = required_str(registry, "uuid_pattern")?;
    let typed_uuid_pattern = required_str(registry, "typed_uuid_pattern")?;
    // Coarse shape sanity: the canonical pattern is a 36-char UUIDv7 form.
    // Avoid pulling a regex engine — string fragment match is enough to flag
    // an outdated v1/v4-only or ULID-shape pattern.
    if !uuid_pattern.contains("[0-9a-f]{8}") || !uuid_pattern.contains("7[0-9a-f]{3}") {
        bail!(
            "id-kind registry uuid_pattern does not look like a UUIDv7 regex (must contain 8-hex prefix and 7xxx version block): {uuid_pattern}"
        );
    }
    if !typed_uuid_pattern.starts_with("^ck:") || !typed_uuid_pattern.contains("[89ab]") {
        bail!(
            "id-kind registry typed_uuid_pattern must be `^ck:<kind>:<UUIDv7>` shape (RFC 9562 variant must include [89ab]): {typed_uuid_pattern}"
        );
    }

    Ok(kinds)
}

fn validate_profile_registry(registry: &Value) -> Result<(BTreeSet<String>, BTreeSet<String>)> {
    // M12 (spec 2026-05-09): the legacy `writer_model_profiles` group key was
    // removed when Move/Anchor/Lattice replaced the writer-model. Any
    // conformance-profiles.json that retains this group key reflects a stale
    // spec snapshot and MUST fail loudly — we explicitly reject the key
    // (rather than silently merge into extension_profiles) so an accidental
    // re-introduction is caught.
    if registry.get("writer_model_profiles").is_some() {
        bail!(
            "conformance-profiles.json retains legacy `writer_model_profiles` group key; spec post-2026-05-08 (Move/Anchor/Lattice) removed this group — drop the key entirely"
        );
    }

    // M12 (spec 2026-05-09): the spec exposes both `anchor_profiles` (a
    // flat list of anchorer-cell profile ids) and may introduce a tiered
    // `anchor_profile_tiers` map (analogous to `profile_tiers`) keying tier
    // names to anchor-profile id arrays. When the tier map is present we
    // validate its shape (object of string→array<cx.profile.anchor.*>) so a
    // typo in a future spec snapshot doesn't slip through.
    if let Some(tiers) = registry.get("anchor_profile_tiers") {
        let map = tiers.as_object().ok_or_else(|| {
            anyhow!(
                "anchor_profile_tiers must be an object mapping tier name → array of profile ids"
            )
        })?;
        for (tier_name, tier_ids) in map {
            // tier_rules is a sibling-style descriptor in profile_tiers; if
            // future spec replicates this for anchor_profile_tiers, allow it.
            if tier_name == "tier_rules" {
                continue;
            }
            let arr = tier_ids.as_array().ok_or_else(|| {
                anyhow!(
                    "anchor_profile_tiers.{tier_name} must be an array of cx.profile.anchor.* ids"
                )
            })?;
            for entry in arr {
                let s = entry.as_str().ok_or_else(|| {
                    anyhow!("anchor_profile_tiers.{tier_name} entry must be a string profile id")
                })?;
                if !s.starts_with("cx.profile.anchor.") {
                    bail!(
                        "anchor_profile_tiers.{tier_name} entry {s} must use the cx.profile.anchor.* namespace"
                    );
                }
            }
        }
    }

    // `anchor_profiles` (flat list) — when present, validate every entry is
    // a cx.profile.anchor.* id. Spec snapshot lists 4 canonical shapes:
    // single_did / threshold / open_set / mixed_recovery.
    if let Some(arr) = registry.get("anchor_profiles").and_then(Value::as_array) {
        for entry in arr {
            let s = entry
                .as_str()
                .ok_or_else(|| anyhow!("anchor_profiles entry must be a string profile id"))?;
            if !s.starts_with("cx.profile.anchor.") {
                bail!("anchor_profiles entry {s} must use cx.profile.anchor.* namespace");
            }
        }
    }

    let mut core_profiles = BTreeSet::new();
    let mut extension_profiles = BTreeSet::new();
    // Core profiles that require profile_requirements entries
    for field in [
        "implementation_profiles",
        "deployment_profiles",
        "hardening_profiles",
        "vector_profiles",
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
    // Extension profiles (may not have profile_requirements). M12: include
    // the spec-current lattice / interop / hash extension groups (and
    // anchor_profiles) so the total count tracks the published catalogue.
    for field in [
        "identity_extension_profiles",
        "constraint_extension_profiles",
        "encoding_extension_profiles",
        "lattice_extension_profiles",
        "interop_compat_profiles",
        "hash_extension_profiles",
        "anchor_profiles",
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
        "ck.profile.core_event_store.v1",
        "ck.profile.chat_mvp.v1",
        "ck.profile.kanban_mvp.v1",
        "ck.profile.push_gateway.v1",
        // E2EE state binding: mandatory inherits of e2ee_client.
        "ck.profile.mls_governance_binding.full.v1",
    ] {
        if !all_profiles.contains(required) {
            bail!("conformance profiles missing required {required}");
        }
    }
    // Wire-model gate: post-Move/Anchor/Lattice spec catalogues >= 47
    // profile ids (writer_model_profiles group was removed in 2026-05-08).
    const MIN_PROFILE_COUNT: usize = 47;
    if all_profiles.len() < MIN_PROFILE_COUNT {
        bail!(
            "conformance profiles registry has {} ids, expected >= {MIN_PROFILE_COUNT} (wire model rework gate)",
            all_profiles.len()
        );
    }
    Ok((all_profiles, core_profiles))
}

#[allow(clippy::too_many_arguments)]
fn validate_profile_requirements(
    root: &std::path::Path,
    registry: &Value,
    profiles: &BTreeSet<String>,
    core_profiles: &BTreeSet<String>,
    event_kinds: &BTreeSet<String>,
    operation_ids: &BTreeSet<String>,
    schema_ids: &BTreeSet<String>,
    _component_types: &BTreeSet<String>,
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

    // Phase 3 binding: e2ee_client MUST inherit mls_governance_binding.full.v1 directly,
    // not as an optional extension.
    let e2ee_client = requirements
        .get("ck.profile.e2ee_client.v1")
        .ok_or_else(|| anyhow!("e2ee_client.v1 missing profile_requirements entry"))?;
    let inherits = string_array_field(e2ee_client, "inherits")?;
    if !inherits.contains(&"ck.profile.mls_governance_binding.full.v1") {
        bail!(
            "e2ee_client.v1 must inherit ck.profile.mls_governance_binding.full.v1 (Phase 3 binding)"
        );
    }

    // Move/Anchor/Lattice binding (spec 2026-05-08): mls_governance_binding.full.v1
    // no longer carries Phase 3 component-type lists; instead it declares
    // required_event_kinds (ck.mls.commit + key share/withheld) and
    // feature_discovery.required (move_based_mls_commit, covered_frontier_cell,
    // mls_epoch_cell). Validate the new shape so a stale profile slips through.
    let mls_binding = requirements
        .get("ck.profile.mls_governance_binding.full.v1")
        .ok_or_else(|| {
            anyhow!("mls_governance_binding.full.v1 missing profile_requirements entry")
        })?;
    let required_event_kinds = string_array_field(mls_binding, "required_event_kinds")?;
    if !required_event_kinds.contains(&"ck.mls.commit") {
        bail!("mls_governance_binding.full.v1 required_event_kinds must include ck.mls.commit");
    }
    let feature_discovery = mls_binding
        .get("feature_discovery")
        .ok_or_else(|| anyhow!("mls_governance_binding.full.v1 missing feature_discovery"))?;
    let required_features = feature_discovery
        .get("required")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            anyhow!("mls_governance_binding.full.v1 feature_discovery.required missing")
        })?;
    let feature_set: BTreeSet<String> = required_features
        .iter()
        .filter_map(|v| v.as_str().map(str::to_owned))
        .collect();
    for required in [
        "move_based_mls_commit",
        "covered_frontier_cell",
        "mls_epoch_cell",
    ] {
        if !feature_set.contains(required) {
            bail!(
                "mls_governance_binding.full.v1 feature_discovery.required must include {required}"
            );
        }
    }

    for (profile, requirement) in requirements {
        // profile_requirements can reference both core and extension profiles
        // but only core_profiles are required to have entries
        if !requirements.contains_key(profile) {
            continue; // Skip extension profiles without requirements
        }

        for inherited in string_array_field(requirement, "inherits")? {
            if !profiles.contains(inherited) {
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
            if extension.starts_with("cx.profile.") && !profiles.contains(extension) {
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
            // C20 wire-break (spec 2026-05-09): `actor_type` was renamed to
            // `actor_kind` in actor-profile.schema.json and friends. v1 is
            // unreleased — no dual-pattern compat. Any fixture that retains
            // `actor_type` as a key MUST fail loudly.
            if map.contains_key("actor_type") {
                bail!(
                    "{context} retains legacy `actor_type` key; spec post-2026-05-09 mandates `actor_kind`"
                );
            }
            // C21 wire-break (spec 2026-05-09): `content_block.type` was
            // renamed `content_block.kind` (and the $defs entry
            // `content_type` → `content_kind`). A `content_block`-shaped
            // object (has a `body` field and a `type` field) is the legacy
            // form — reject. Pure `type` fields outside content_block (e.g.
            // cell_subject `{"type": "composite", ...}`) remain legal.
            if map.contains_key("body") && map.contains_key("type") && !map.contains_key("kind") {
                if let Some(t) = map.get("type").and_then(Value::as_str) {
                    if t.starts_with("cx.content.") || t == "text" || t == "image" || t == "file" {
                        bail!(
                            "{context} content_block uses legacy `type` field; spec post-2026-05-09 mandates `kind` ({t})"
                        );
                    }
                }
            }
            for (key, child) in map {
                match (key.as_str(), child.as_str()) {
                    ("operation_id", Some(operation_id))
                        if !operation_ids.contains(operation_id) =>
                    {
                        bail!("{context} references unknown operation id {operation_id}");
                    }
                    ("event_kind", Some(event_kind)) if !event_kinds.contains(event_kind) => {
                        bail!("{context} references unknown event kind {event_kind}");
                    }
                    ("kind", Some(kind)) if kind.starts_with("cx.") => {
                        // The recursive walk hits `kind:` fields nested in
                        // payload content blocks (e.g. `payload.content.kind`
                        // = `ck.content.text`), profile refs, feature ids,
                        // etc. — none of which live in the event-kind
                        // registry. Skip namespace prefixes that are
                        // intentionally NOT event kinds; only validate
                        // top-level event-style names.
                        let is_non_event_namespace = kind.starts_with("cx.content.")
                            || kind.starts_with("cx.profile.")
                            || kind.starts_with("cx.feature.")
                            || kind.starts_with("cx.schema.")
                            || kind.starts_with("cx.component.")
                            || kind.starts_with("cx.vector.")
                            || kind.starts_with("cx.reducer.");
                        if !is_non_event_namespace && !event_kinds.contains(kind) {
                            bail!("{context} references unknown event kind {kind}");
                        }
                    }
                    ("schema_id", Some(schema_id)) if !schema_ids.contains(schema_id) => {
                        bail!("{context} references unknown schema id {schema_id}");
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
    let Some(rest) = value.strip_prefix("ck:") else {
        return Ok(());
    };
    let Some((kind, tail)) = rest.split_once(':') else {
        return Ok(());
    };
    if !id_kinds.contains(kind) {
        bail!("{context} references unknown typed id kind {kind}: {value}");
    }
    // Round-21 validator hardening (matches SDK round-20 typed-id validator
    // tightening): kinds whose canonical wire_form is `ck:<kind>:<uuid>` MUST
    // carry a 36-character lowercase UUIDv7 payload (RFC 9562: version=7,
    // variant ∈ {8,9,a,b}). The id-kind registry's six `special_forms` —
    // cursor (base64url), blob (sha256:<digest>), mls (<profile>:<id>),
    // pseudonym (<scope>:<random>), anchor (sha256:<digest>), cell
    // (<component>:<subject>) — are exempt: their tails are never UUIDv7.
    //
    // This catches the stale ULID-shape literals (e.g. ck:event:01js0gv01...
    // — Crockford base32, not UUID) that round-20 of the SDK started
    // rejecting at envelope-validation time. cotest fixtures and src
    // literals must mirror the same constraint.
    // Round-4 (spec f9bd7eb) adds `trust_domain` as the seventh special-form
    // id kind. Its payload is `<scope>` (lowercase opaque label), not
    // UUIDv7 — exempt from the UUID-shape check.
    const SPECIAL_FORM_KINDS: &[&str] = &[
        "cursor",
        "blob",
        "mls",
        "pseudonym",
        "anchor",
        "cell",
        "trust_domain",
    ];
    if SPECIAL_FORM_KINDS.contains(&kind) {
        return Ok(());
    }
    if !is_uuidv7_shaped(tail) {
        bail!(
            "{context} typed id {value} (kind={kind}) payload is not a UUIDv7 (RFC 9562 v7 lowercase 36-char form `xxxxxxxx-xxxx-7xxx-Nxxx-xxxxxxxxxxxx`, N∈{{8,9,a,b}}); spec post-2026-05-09 forbids legacy non-UUID payloads"
        );
    }
    Ok(())
}

/// True when `s` matches the canonical UUIDv7 wire form
/// `xxxxxxxx-xxxx-7xxx-Nxxx-xxxxxxxxxxxx` (lowercase hex, version=7,
/// variant ∈ {8,9,a,b}). String-level shape check; no regex engine needed.
pub(crate) fn is_uuidv7_shaped(s: &str) -> bool {
    if s.len() != 36 {
        return false;
    }
    let bytes = s.as_bytes();
    // Hyphen positions: 8, 13, 18, 23.
    for &i in &[8usize, 13, 18, 23] {
        if bytes[i] != b'-' {
            return false;
        }
    }
    for (i, &b) in bytes.iter().enumerate() {
        if matches!(i, 8 | 13 | 18 | 23) {
            continue;
        }
        // Lowercase hex.
        let is_digit = b.is_ascii_digit();
        let is_lower_hex = matches!(b, b'a'..=b'f');
        if !(is_digit || is_lower_hex) {
            return false;
        }
    }
    // Version nibble at index 14 must be '7'.
    if bytes[14] != b'7' {
        return false;
    }
    // Variant nibble at index 19 must be one of 8, 9, a, b.
    if !matches!(bytes[19], b'8' | b'9' | b'a' | b'b') {
        return false;
    }
    true
}
