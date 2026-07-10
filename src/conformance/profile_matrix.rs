use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, anyhow, bail};
use serde_json::Value;

use super::{fixture_path, load_artifact_json, required_str, string_array_field};

const PROFILE_LIST_FIELDS: &[&str] = &[
    "implementation_profiles",
    "identity_extension_profiles",
    "deployment_profiles",
    "constraint_extension_profiles",
    "lattice_extension_profiles",
    "interop_compat_profiles",
    "encoding_extension_profiles",
    "hash_extension_profiles",
    "signature_extension_profiles",
    // 2026-06: the spec's conformance-profiles.json added a
    // `kem_extension_profiles` catalog group (e.g. `ak.profile.hpke.p256.v1`,
    // `ak.profile.kem.hybrid_xwing.v1`). Without it the dependency-graph node
    // for those KEM profiles trips `not_declared_in_any_profile_catalog`.
    "kem_extension_profiles",
    "hardening_profiles",
    "vector_profiles",
    "notary_profiles",
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
    "ak.vector_group.privacy_security.v1",
    "security_negative_profile",
)];

#[derive(Debug)]
struct ProfileRequirement {
    inherited_profiles: BTreeSet<String>,
    depends_on_profiles: BTreeSet<String>,
    mutually_exclusive_profiles: BTreeSet<String>,
    required_operations: BTreeSet<String>,
    required_event_kinds: BTreeSet<String>,
    required_schemas: BTreeSet<String>,
    required_capability_actions: BTreeSet<String>,
    required_features: BTreeSet<String>,
    required_cell_namespaces: BTreeSet<String>,
    required_cells: BTreeSet<String>,
    required_fixtures: BTreeSet<String>,
    must_requirement_blocks: BTreeSet<String>,
    cotest_suites: BTreeSet<String>,
}

#[derive(Debug)]
struct ProfileMatrix {
    declared_profiles: BTreeSet<String>,
    requirements: BTreeMap<String, ProfileRequirement>,
}

#[derive(Debug, Default)]
struct ProfileDependencyGraph {
    nodes: BTreeSet<String>,
    inherits: BTreeMap<String, BTreeSet<String>>,
    depends_on: BTreeMap<String, BTreeSet<String>>,
    mutually_exclusive_with: BTreeMap<String, BTreeSet<String>>,
}

pub fn validate_server_profile_claims(describe: &Value) -> Result<()> {
    let matrix = load_profile_matrix()?;
    validate_server_claims_against_matrix(describe, &matrix)
}

pub fn run_profile_requirement_gate_suite() -> Result<()> {
    let matrix = load_profile_matrix()?;

    let mut full_client_closure = BTreeSet::new();
    expand_profile_claim(
        "ak.profile.full_client.v1",
        &matrix,
        &mut full_client_closure,
    )?;
    for inherited in [
        "ak.profile.chat_mvp.v1",
        "ak.profile.kanban_mvp.v1",
        "ak.profile.core_event_store.v1",
    ] {
        if !full_client_closure.contains(inherited) {
            bail!("profile graph inheritance did not expand full_client to {inherited}");
        }
    }

    let push_gateway = matrix
        .requirements
        .get("ak.profile.push_gateway.v1")
        .ok_or_else(|| anyhow!("missing push_gateway requirement block"))?;
    if !push_gateway
        .depends_on_profiles
        .contains("ak.profile.push_gateway.blind_wakeup.v1")
    {
        bail!("profile graph missing push_gateway -> blind_wakeup dependency");
    }

    let relaxed = matrix
        .requirements
        .get("ak.profile.e2ee_relaxed.v1")
        .ok_or_else(|| anyhow!("missing e2ee_relaxed requirement block"))?;
    if !relaxed
        .required_features
        .contains("ak.feature.e2ee_relaxed.v1")
    {
        bail!("e2ee_relaxed requirement block missing required feature");
    }
    if !relaxed
        .mutually_exclusive_profiles
        .contains("ak.profile.mls_governance_binding.full.v1")
    {
        bail!("profile graph missing e2ee_relaxed mutual exclusion");
    }

    let mls_binding = matrix
        .requirements
        .get("ak.profile.mls_governance_binding.full.v1")
        .ok_or_else(|| anyhow!("missing mls governance binding requirement block"))?;
    if !mls_binding
        .required_cells
        .contains("ak:cell:ak.component.covered_seals.v1:<realm_id>")
    {
        bail!("mls governance binding requirement block missing covered_seals cell");
    }

    let circle = matrix
        .requirements
        .get("ak.profile.circle_conformance.v1")
        .ok_or_else(|| anyhow!("missing circle conformance requirement block"))?;
    if !circle
        .required_fixtures
        .contains("circle-scope-fixture.json")
    {
        bail!("circle conformance requirement block missing required fixture");
    }
    if !circle
        .required_capability_actions
        .contains("ak.circle.create")
    {
        bail!("circle conformance requirement block missing capability action");
    }
    if !circle
        .must_requirement_blocks
        .contains("submit_payload_must")
    {
        bail!("circle conformance requirement block missing submit_payload_must");
    }

    Ok(())
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
    let graph = load_profile_dependency_graph(&declared_profiles)?;
    let requirements = collect_profile_requirements(
        &profiles,
        &graph,
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
            if profile.starts_with("ak.profile.") {
                validate_profile_id(profile)?;
                declared.insert(profile.to_owned());
            }
        }
    }
    Ok(declared)
}

fn load_profile_dependency_graph(
    declared_profiles: &BTreeSet<String>,
) -> Result<ProfileDependencyGraph> {
    let graph = load_artifact_json("registry/profiles-dependency-graph.json")?;
    if graph.get("kind").and_then(Value::as_str) != Some("profiles_dependency_graph") {
        bail!("profiles-dependency-graph.json kind must be profiles_dependency_graph");
    }
    if graph.get("source_of_truth").and_then(Value::as_bool) != Some(true) {
        bail!("profiles-dependency-graph.json must declare source_of_truth=true");
    }

    let mut parsed = ProfileDependencyGraph::default();
    for node in string_array_field(&graph, "nodes")? {
        validate_profile_id(node)?;
        if !declared_profiles.contains(node) {
            bail!("profile graph node {node} is not declared in any profile catalog");
        }
        parsed.nodes.insert(node.to_owned());
    }

    let edges = graph
        .get("edges")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("profiles-dependency-graph.json missing edges[]"))?;
    for edge in edges {
        let from = required_str(edge, "from")?;
        let to = required_str(edge, "to")?;
        let kind = required_str(edge, "kind")?;
        validate_profile_id(from)?;
        validate_profile_id(to)?;
        if !declared_profiles.contains(from) {
            bail!("profile graph edge from undeclared profile {from}");
        }
        if !declared_profiles.contains(to) {
            bail!("profile graph edge to undeclared profile {to}");
        }
        if !parsed.nodes.contains(from) {
            bail!("profile graph edge references from={from} outside nodes[]");
        }
        if !parsed.nodes.contains(to) {
            bail!("profile graph edge references to={to} outside nodes[]");
        }

        let map = match kind {
            "inherits" => &mut parsed.inherits,
            "depends_on" => &mut parsed.depends_on,
            "mutually_exclusive_with" => &mut parsed.mutually_exclusive_with,
            other => bail!("profile graph edge has unknown kind {other}"),
        };
        map.entry(from.to_owned())
            .or_default()
            .insert(to.to_owned());
    }

    ensure_inheritance_graph_is_acyclic(&parsed)?;
    Ok(parsed)
}

fn ensure_inheritance_graph_is_acyclic(graph: &ProfileDependencyGraph) -> Result<()> {
    let mut visiting = BTreeSet::new();
    let mut visited = BTreeSet::new();
    for node in &graph.nodes {
        visit_inheritance_node(node, graph, &mut visiting, &mut visited)?;
    }
    Ok(())
}

fn visit_inheritance_node(
    node: &str,
    graph: &ProfileDependencyGraph,
    visiting: &mut BTreeSet<String>,
    visited: &mut BTreeSet<String>,
) -> Result<()> {
    if visited.contains(node) {
        return Ok(());
    }
    if !visiting.insert(node.to_owned()) {
        bail!("profile inheritance graph contains a cycle at {node}");
    }
    if let Some(targets) = graph.inherits.get(node) {
        for target in targets {
            visit_inheritance_node(target, graph, visiting, visited)?;
        }
    }
    visiting.remove(node);
    visited.insert(node.to_owned());
    Ok(())
}

fn collect_profile_requirements(
    profiles: &Value,
    graph: &ProfileDependencyGraph,
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
    validate_graph_edges_are_requirement_backed(graph, requirements)?;

    let mut matrix = BTreeMap::new();
    for (profile, requirement) in requirements {
        if !declared_profiles.contains(profile) {
            bail!("profile_requirements key {profile} is not declared in any profile catalog");
        }

        validate_requirement_relationship_refs(requirement, profile, declared_profiles, graph)?;
        let inherited_profiles = graph.inherits.get(profile).cloned().unwrap_or_default();
        let depends_on_profiles = graph.depends_on.get(profile).cloned().unwrap_or_default();
        let mutually_exclusive_profiles = graph
            .mutually_exclusive_with
            .get(profile)
            .cloned()
            .unwrap_or_default();
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
        let required_capability_actions =
            collect_plain_refs(requirement, "required_capability_actions")?;
        let required_features = collect_plain_refs(requirement, "required_features")?;
        let required_cell_namespaces =
            collect_cell_refs(requirement, "required_cell_namespaces", false)?;
        let required_cells = collect_cell_refs(requirement, "required_cells", true)?;
        let required_fixtures = collect_required_fixtures(requirement, profile)?;
        let must_requirement_blocks = collect_must_requirement_blocks(requirement, profile)?;
        let cotest_suites = collect_cotest_suites(requirement, profile)?;

        for extension in string_array_field(requirement, "optional_extensions")? {
            if extension.starts_with("ak.profile.") && !declared_profiles.contains(extension) {
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
                depends_on_profiles,
                mutually_exclusive_profiles,
                required_operations,
                required_event_kinds,
                required_schemas,
                required_capability_actions,
                required_features,
                required_cell_namespaces,
                required_cells,
                required_fixtures,
                must_requirement_blocks,
                cotest_suites,
            },
        );
    }
    Ok(matrix)
}

fn validate_requirement_relationship_refs(
    requirement: &Value,
    profile: &str,
    declared_profiles: &BTreeSet<String>,
    graph: &ProfileDependencyGraph,
) -> Result<()> {
    for field in ["inherits", "depends_on", "mutually_exclusive_with"] {
        let mut requirement_refs = BTreeSet::new();
        for referenced_profile in string_array_field(requirement, field)? {
            if !declared_profiles.contains(referenced_profile) {
                bail!(
                    "{profile} requirement {field} references unknown profile {referenced_profile}"
                );
            }
            requirement_refs.insert(referenced_profile.to_owned());
        }
        let graph_refs = graph_relationship_refs(graph, field, profile);
        if requirement_refs != graph_refs {
            bail!(
                "profiles-dependency-graph mirror drift for {profile}.{field}: profile_requirements={requirement_refs:?}, graph={graph_refs:?}"
            );
        }
    }
    Ok(())
}

fn validate_graph_edges_are_requirement_backed(
    graph: &ProfileDependencyGraph,
    requirements: &serde_json::Map<String, Value>,
) -> Result<()> {
    for (field, edges) in [
        ("inherits", &graph.inherits),
        ("depends_on", &graph.depends_on),
        ("mutually_exclusive_with", &graph.mutually_exclusive_with),
    ] {
        for (profile, targets) in edges {
            let Some(requirement) = requirements.get(profile) else {
                bail!(
                    "profile graph {field} edge from {profile} has no profile_requirements block"
                );
            };
            let requirement_refs = string_array_field(requirement, field)?
                .into_iter()
                .map(ToOwned::to_owned)
                .collect::<BTreeSet<_>>();
            if &requirement_refs != targets {
                bail!(
                    "profile graph {field} edges for {profile} are not mirrored by profile_requirements: graph={targets:?}, profile_requirements={requirement_refs:?}"
                );
            }
        }
    }
    Ok(())
}

fn graph_relationship_refs(
    graph: &ProfileDependencyGraph,
    field: &str,
    profile: &str,
) -> BTreeSet<String> {
    let edges = match field {
        "inherits" => &graph.inherits,
        "depends_on" => &graph.depends_on,
        "mutually_exclusive_with" => &graph.mutually_exclusive_with,
        _ => return BTreeSet::new(),
    };
    edges.get(profile).cloned().unwrap_or_default()
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

fn collect_plain_refs(requirement: &Value, field: &str) -> Result<BTreeSet<String>> {
    let mut refs = BTreeSet::new();
    for value in string_array_field(requirement, field)? {
        if value.trim().is_empty() {
            bail!("requirement {field} contains an empty value");
        }
        refs.insert(value.to_owned());
    }
    Ok(refs)
}

fn collect_cell_refs(
    requirement: &Value,
    field: &str,
    require_cell_prefix: bool,
) -> Result<BTreeSet<String>> {
    let mut refs = BTreeSet::new();
    for value in string_array_field(requirement, field)? {
        if value.trim().is_empty() {
            bail!("requirement {field} contains an empty value");
        }
        if require_cell_prefix
            && arkret_core::CellRef::new(value.to_owned()).is_err()
            && !is_template_cell_ref(value)
        {
            bail!(
                "requirement {field} references non-canonical cell value {value}; expected ak:cell:ak.component.*.v<n>:<subject>"
            );
        }
        refs.insert(value.to_owned());
    }
    Ok(refs)
}

/// Profile requirement blocks may describe a cell family with a symbolic
/// subject (for example `...:<realm_id>` or `...:<mls_group_id>`).  These are
/// templates, not wire values, so the typed CellRef parser quite correctly
/// rejects the angle-bracket subject.  Validate the family and placeholder
/// shape here while preserving the template for profile matching.
fn is_template_cell_ref(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("ak:cell:") else {
        return false;
    };
    let Some((family, subject)) = rest.rsplit_once(':') else {
        return false;
    };
    if !family.starts_with("ak.component.") {
        return false;
    }
    let Some(version) = family.rsplit_once(".v").map(|(_, v)| v) else {
        return false;
    };
    if version.is_empty() || !version.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }
    let inner = subject.strip_prefix('<').and_then(|s| s.strip_suffix('>'));
    inner.is_some_and(|s| {
        !s.is_empty()
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    })
}

fn collect_required_fixtures(requirement: &Value, profile: &str) -> Result<BTreeSet<String>> {
    let mut fixtures = BTreeSet::new();
    for fixture in string_array_field(requirement, "required_fixtures")? {
        if fixture.trim().is_empty() {
            bail!("{profile} required_fixtures contains an empty value");
        }
        if fixture.contains('/') || fixture.contains('\\') {
            bail!("{profile} required fixture {fixture} must be a fixture file name");
        }
        let path = fixture_path(fixture);
        if !path.is_file() {
            bail!(
                "{profile} required fixture {fixture} missing from spec artifact fixtures at {}",
                path.display()
            );
        }
        fixtures.insert(fixture.to_owned());
    }
    Ok(fixtures)
}

fn collect_must_requirement_blocks(requirement: &Value, profile: &str) -> Result<BTreeSet<String>> {
    let Some(blocks) = requirement
        .get("additional_requirements")
        .and_then(Value::as_object)
    else {
        return Ok(BTreeSet::new());
    };

    let mut ids = BTreeSet::new();
    for (id, value) in blocks {
        if !id.contains("_must") {
            bail!("{profile} additional requirement block {id} must include _must");
        }
        if !id
            .chars()
            .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_')
        {
            bail!("{profile} additional requirement block {id} must be snake_case ASCII");
        }
        let text = value.as_str().ok_or_else(|| {
            anyhow!("{profile} additional requirement block {id} must be a string")
        })?;
        if text.trim().is_empty() {
            bail!("{profile} additional requirement block {id} must not be empty");
        }
        if !text.contains("MUST") {
            bail!("{profile} additional requirement block {id} must carry MUST text");
        }
        ids.insert(id.to_owned());
    }
    Ok(ids)
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
    let supported_features = optional_string_set_field(describe, "supported_features")?;
    let supported_capability_actions =
        optional_string_set_field(describe, "supported_capability_actions")?;
    let supported_cell_namespaces =
        optional_string_set_field(describe, "supported_cell_namespaces")?;
    let supported_cells = optional_string_set_field(describe, "supported_cells")?;
    let verified_fixtures =
        optional_string_set_field_any(describe, &["verified_fixtures", "supported_fixtures"])?;
    ensure_limited_profiles_are_not_supported(&claimed_profiles)?;
    validate_explicit_unsupported_limited_profiles(describe)?;
    validate_profile_dependency_claims(&claimed_profiles, matrix)?;
    validate_mutually_exclusive_claims(&claimed_profiles, matrix)?;

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
        if let Some(supported_features) = &supported_features {
            ensure_subset(
                &requirement.required_features,
                supported_features,
                &format!("{profile} supported_features"),
            )?;
        }
        if let Some(supported_capability_actions) = &supported_capability_actions {
            ensure_subset(
                &requirement.required_capability_actions,
                supported_capability_actions,
                &format!("{profile} supported_capability_actions"),
            )?;
        }
        if let Some(supported_cell_namespaces) = &supported_cell_namespaces {
            ensure_subset(
                &requirement.required_cell_namespaces,
                supported_cell_namespaces,
                &format!("{profile} supported_cell_namespaces"),
            )?;
        }
        if let Some(supported_cells) = &supported_cells {
            ensure_subset(
                &requirement.required_cells,
                supported_cells,
                &format!("{profile} supported_cells"),
            )?;
        }
        if let Some(verified_fixtures) = &verified_fixtures {
            ensure_subset(
                &requirement.required_fixtures,
                verified_fixtures,
                &format!("{profile} verified_fixtures"),
            )?;
        }
    }

    Ok(())
}

fn validate_profile_dependency_claims(
    claimed_profiles: &BTreeSet<String>,
    matrix: &ProfileMatrix,
) -> Result<()> {
    for profile in claimed_profiles {
        if !matrix.declared_profiles.contains(profile) {
            continue;
        }
        let Some(requirement) = matrix.requirements.get(profile) else {
            continue;
        };
        for dependency in &requirement.depends_on_profiles {
            if !claimed_profiles.contains(dependency) {
                bail!("server claims profile {profile} without required dependency {dependency}");
            }
        }
    }
    Ok(())
}

fn validate_mutually_exclusive_claims(
    claimed_profiles: &BTreeSet<String>,
    matrix: &ProfileMatrix,
) -> Result<()> {
    for profile in claimed_profiles {
        let Some(requirement) = matrix.requirements.get(profile) else {
            continue;
        };
        for incompatible in &requirement.mutually_exclusive_profiles {
            if claimed_profiles.contains(incompatible) {
                bail!("server claims mutually exclusive profiles {profile} and {incompatible}");
            }
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
    profile.starts_with("ak.profile.")
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

fn optional_string_set_field_any(
    value: &Value,
    fields: &[&str],
) -> Result<Option<BTreeSet<String>>> {
    let mut merged = BTreeSet::new();
    let mut found = false;
    for field in fields {
        if value.get(field).is_some() {
            found = true;
            merged.extend(
                string_array_field(value, field)
                    .with_context(|| format!("reading {field}[]"))?
                    .into_iter()
                    .map(ToOwned::to_owned),
            );
        }
    }
    Ok(found.then_some(merged))
}

fn validate_profile_id(profile: &str) -> Result<()> {
    if !profile.starts_with("ak.profile.") || !profile.ends_with(".v1") {
        bail!("invalid profile id {profile}");
    }
    Ok(())
}
