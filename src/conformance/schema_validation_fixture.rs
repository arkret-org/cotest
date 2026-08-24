//! Round 4 / A2 — schema-validation-fixture runner.
//!
//! Loads every schema-validation-shaped fixture registered below from
//! `arkret-spec/spec/v1/artifacts/fixtures/` and runs each positive/negative
//! case against the schema referenced by
//! `schema_ref`. `schema_ref` syntax (mirrors the Python lint
//! `check_fixture_schema_validation_cases`):
//!
//! ```text
//! schemas/<name>.schema.json                         -- whole schema
//! schemas/<name>.schema.json#/$defs/<subschema>      -- sub-schema fragment
//! openapi/arkret-service-api.openapi.yaml#/components/schemas/<Name>
//!                                                   -- OpenAPI component
//! ```
//!
//! Positive cases (`expect_valid: true`) MUST pass schema validation;
//! negative cases (`expect_valid: false`) MUST fail. Any drift is a hard
//! cotest failure.

use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs;

use anyhow::{Context, Result, anyhow, bail};
use jsonschema::{Registry, Resource};
use serde::Deserialize;
use serde_json::{Value, json};

use super::{fixture_path, spec_artifacts_root, validate_profile};

/// Canonical fixture filename.
pub const SCHEMA_VALIDATION_FIXTURE: &str = "schema-validation-fixture.json";

/// Key-backup schema-validation fixture (25 cases against the key-backup /
/// recovery schema family).
pub const KEY_BACKUP_FIXTURE: &str = "key-backup-fixture.json";

/// Realm-organization schema-validation fixture (14 cases against
/// `event-payload.schema.json#/$defs/realm_organization_payload`).
pub const REALM_ORGANIZATION_FIXTURE: &str = "realm-organization-fixture.json";

pub const SDK_CONFORMANCE_CLAIM_FIXTURE: &str = "sdk-conformance-claim-fixture.json";

pub const KEY_TRANSPARENCY_FIXTURE: &str = "key-transparency-fixture.json";

pub const CALENDAR_RSVP_FIXTURE: &str = "calendar-rsvp-fixture.json";

pub const CALENDAR_NOTIFICATION_FIXTURE: &str = "calendar-notification-fixture.json";

pub const EVENT_PAYLOAD_VALUE_CLOSURE_FIXTURE: &str = "event-payload-value-closure-fixture.json";

pub const PUSH_NOTIFY_OUTCOME_FIXTURE: &str = "push-notify-outcome-fixture.json";

pub const SCHEMA_DEFINITION_VALIDATOR_KAT: &str = "schema-definition-validator-kat.json";

#[derive(Clone, Copy)]
enum FixtureIdentity<'a> {
    Profile(&'a str),
    RunnerKind(&'a str),
}

/// Every spec fixture whose `schema_validation_cases` this runner executes.
/// Extend this manifest when the spec ships a new schema-validation-shaped
/// fixture instead of adding a parallel schema runner.
const SCHEMA_VALIDATION_FIXTURE_FILES: &[(&str, FixtureIdentity<'static>, &str)] = &[
    (
        SCHEMA_VALIDATION_FIXTURE,
        FixtureIdentity::Profile(
            crate::conformance::security_closure::SECURITY_CLOSURE_VECTORS_PROFILE,
        ),
        "schema_validation",
    ),
    (
        KEY_BACKUP_FIXTURE,
        FixtureIdentity::Profile("ak.profile.key_backup.memory_hard.v1"),
        "key_backup_schema_validation",
    ),
    (
        REALM_ORGANIZATION_FIXTURE,
        FixtureIdentity::Profile(
            crate::conformance::security_closure::SECURITY_CLOSURE_VECTORS_PROFILE,
        ),
        "realm_organization_conformance",
    ),
    (
        SDK_CONFORMANCE_CLAIM_FIXTURE,
        FixtureIdentity::Profile("ak.vector_group.schema_validation.v1"),
        "sdk_conformance_claim",
    ),
    (
        KEY_TRANSPARENCY_FIXTURE,
        FixtureIdentity::Profile("ak.profile.key_transparency.v1"),
        "key_transparency",
    ),
    (
        CALENDAR_RSVP_FIXTURE,
        FixtureIdentity::Profile("ak.profile.calendar_event.v1"),
        "calendar_rsvp_conformance",
    ),
    (
        CALENDAR_NOTIFICATION_FIXTURE,
        FixtureIdentity::Profile("ak.profile.calendar_notification_dispatch.v1"),
        "calendar_notification_dispatch_conformance",
    ),
    (
        EVENT_PAYLOAD_VALUE_CLOSURE_FIXTURE,
        FixtureIdentity::RunnerKind("json_schema_and_semantic_cases"),
        "event_payload_value_closure",
    ),
    (
        PUSH_NOTIFY_OUTCOME_FIXTURE,
        FixtureIdentity::Profile("ak.vector_group.discovery.v1"),
        "push_notify_outcome_conformance",
    ),
];

const SCHEMA_DIR: &str = "schemas";
const SCHEMA_ID_PREFIX: &str = "https://arkret.org/v1/";
const OPENAPI_FILE: &str = "openapi/arkret-service-api.openapi.yaml";

#[derive(Clone, Debug, Deserialize)]
pub struct SchemaValidationFixture {
    pub suite: String,
    pub version: String,
    #[serde(default)]
    pub description: String,
    pub schema_validation_cases: Vec<SchemaValidationCase>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct SchemaValidationCase {
    pub name: String,
    pub schema_ref: String,
    #[serde(default = "default_true")]
    pub expect_valid: bool,
    #[serde(default)]
    pub semantic_outcome: Option<String>,
    #[serde(default)]
    pub expected_reason_code: Option<String>,
    pub instance: Value,
}

#[derive(Clone, Debug, Deserialize)]
pub struct SchemaSemanticCase {
    pub name: String,
    pub semantic_rule: String,
    pub semantic_outcome: String,
    #[serde(default)]
    pub expected_reason_code: Option<String>,
    pub instance: Value,
}

#[derive(Clone, Debug, Deserialize)]
struct SchemaSemanticCasesFixture {
    #[serde(default)]
    semantic_cases: Vec<SchemaSemanticCase>,
}

#[derive(Clone, Debug, Deserialize)]
struct SchemaDefinitionValidatorKat {
    runner: SchemaDefinitionValidatorKatRunner,
    validator_profile_id: String,
    cases: Vec<SchemaDefinitionValidatorCase>,
}

#[derive(Clone, Debug, Deserialize)]
struct SchemaDefinitionValidatorKatRunner {
    kind: String,
}

#[derive(Clone, Debug, Deserialize)]
struct SchemaDefinitionValidatorCase {
    name: String,
    payload: Value,
    expected_valid: bool,
    #[serde(default)]
    expected_failure_code: Option<String>,
}

fn default_true() -> bool {
    true
}

/// Public entry point: load every fixture in
/// [`SCHEMA_VALIDATION_FIXTURE_FILES`] and run all of their cases.
pub fn run_schema_validation_fixture_suite() -> Result<()> {
    for (file_name, identity, expected_suite) in SCHEMA_VALIDATION_FIXTURE_FILES {
        run_schema_validation_fixture_file_with_identity(file_name, *identity, expected_suite)
            .with_context(|| format!("schema-validation fixture {file_name}"))?;
    }
    run_schema_definition_validator_kat()
}

pub fn run_schema_definition_validator_kat() -> Result<()> {
    let path = fixture_path(SCHEMA_DEFINITION_VALIDATOR_KAT);
    let raw = fs::read_to_string(&path)
        .with_context(|| format!("read schema-definition validator KAT {}", path.display()))?;
    let kat: SchemaDefinitionValidatorKat = serde_json::from_str(&raw)
        .with_context(|| format!("parse schema-definition validator KAT {}", path.display()))?;
    if kat.runner.kind != "json_schema_and_semantic_cases" {
        bail!(
            "schema-definition KAT runner drifted: expected json_schema_and_semantic_cases, got {}",
            kat.runner.kind
        );
    }
    if kat.validator_profile_id != arkret_schema::JSON_SCHEMA_2020_12_DEFINITION_VALIDATOR_PROFILE {
        bail!(
            "schema-definition KAT profile drifted: expected {}, got {}",
            arkret_schema::JSON_SCHEMA_2020_12_DEFINITION_VALIDATOR_PROFILE,
            kat.validator_profile_id
        );
    }
    let event_kind = arkret_wire::EventKind::SchemaDefine;
    let catalog = arkret_schema::event_payload_validator_catalog()?;
    for case in kat.cases {
        let result = catalog
            .validate_payload(event_kind.as_str(), &case.payload)
            .and_then(|()| arkret_schema::validate_schema_definition_payload(&case.payload));
        if case.expected_valid != result.is_ok() {
            bail!(
                "schema-definition KAT {} drifted: expected_valid={}, observed={}",
                case.name,
                case.expected_valid,
                if result.is_ok() { "valid" } else { "invalid" }
            );
        }
        if !case.expected_valid && case.expected_failure_code.as_deref() != Some("schema_violation")
        {
            bail!(
                "schema-definition KAT {} must bind rejection to schema_violation",
                case.name
            );
        }
    }
    Ok(())
}

/// Load one schema-validation-shaped fixture, pin its profile/suite, and run
/// every `schema_validation_cases` entry.
pub fn run_schema_validation_fixture_file(
    file_name: &str,
    expected_profile: &str,
    expected_suite: &str,
) -> Result<()> {
    run_schema_validation_fixture_file_with_identity(
        file_name,
        FixtureIdentity::Profile(expected_profile),
        expected_suite,
    )
}

pub fn run_event_payload_value_closure_fixture() -> Result<()> {
    run_schema_validation_fixture_file_with_identity(
        EVENT_PAYLOAD_VALUE_CLOSURE_FIXTURE,
        FixtureIdentity::RunnerKind("json_schema_and_semantic_cases"),
        "event_payload_value_closure",
    )
}

fn run_schema_validation_fixture_file_with_identity(
    file_name: &str,
    identity: FixtureIdentity<'_>,
    expected_suite: &str,
) -> Result<()> {
    let path = fixture_path(file_name);
    let raw = fs::read_to_string(&path)
        .with_context(|| format!("read schema-validation fixture {}", path.display()))?;
    let value: Value = serde_json::from_str(&raw)
        .with_context(|| format!("parse schema-validation fixture {}", path.display()))?;
    match identity {
        FixtureIdentity::Profile(expected_profile) => validate_profile(&value, expected_profile)?,
        FixtureIdentity::RunnerKind(expected_kind) => {
            let observed_kind = value
                .pointer("/runner/kind")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("fixture artifact missing runner.kind"))?;
            if observed_kind != expected_kind {
                bail!("fixture runner kind drifted: expected {expected_kind}, got {observed_kind}");
            }
        }
    }
    let fixture: SchemaValidationFixture = serde_json::from_value(value.clone())
        .with_context(|| format!("decode schema-validation fixture {}", path.display()))?;
    if fixture.suite != expected_suite {
        bail!(
            "fixture {file_name} suite drifted: expected `{expected_suite}`, got `{}`",
            fixture.suite
        );
    }
    if file_name == EVENT_PAYLOAD_VALUE_CLOSURE_FIXTURE {
        validate_event_payload_value_closure_coverage(&fixture.schema_validation_cases)?;
    }
    run_cases(&fixture.schema_validation_cases)?;
    run_semantic_cases(file_name, &fixture.schema_validation_cases)?;
    if file_name == EVENT_PAYLOAD_VALUE_CLOSURE_FIXTURE {
        let semantic_fixture: SchemaSemanticCasesFixture = serde_json::from_value(value)
            .with_context(|| format!("decode semantic-rule cases from {file_name}"))?;
        run_schema_semantic_cases(&semantic_fixture.semantic_cases)?;
    }
    Ok(())
}

fn validate_event_payload_value_closure_coverage(cases: &[SchemaValidationCase]) -> Result<()> {
    const CLOSED_FAMILIES: &[&str] = &[
        "organization_moderation_policy_state_payload",
        "identity_disclosure_policy_state_payload",
        "identity_disclosure_receipt_state_payload",
        "policy_set_state_payload",
        "policy_action_state_payload",
    ];
    for family in CLOSED_FAMILIES {
        let family_cases = cases
            .iter()
            .filter(|case| case.schema_ref.ends_with(&format!("/$defs/{family}")))
            .collect::<Vec<_>>();
        if family_cases.iter().any(|case| {
            !case.expect_valid && case.expected_reason_code.as_deref() != Some("schema_violation")
        }) {
            bail!("{family} negative cases must bind failure to schema_violation");
        }
        if !family_cases.iter().any(|case| case.expect_valid)
            || !family_cases
                .iter()
                .any(|case| !case.expect_valid && case.name.contains("missing_value"))
            || !family_cases.iter().any(|case| {
                !case.expect_valid
                    && (case.name.contains("unknown") || case.name.contains("former"))
            })
            || !family_cases
                .iter()
                .any(|case| !case.expect_valid && case.name.contains("body_mismatch"))
        {
            bail!(
                "event payload value closure fixture lacks positive/missing/unknown/body-mismatch coverage for {family}"
            );
        }
    }
    Ok(())
}

fn run_schema_semantic_cases(cases: &[SchemaSemanticCase]) -> Result<()> {
    for case in cases {
        let accepted = match case.semantic_rule.as_str() {
            "policy_set_subject_matches_value_identity" => serde_json::from_value::<
                arkret_models_collaboration::events_payloads::PolicySetStatePayload,
            >(case.instance.clone())
            .is_ok(),
            rule => bail!("{} has unknown semantic_rule {rule}", case.name),
        };
        let expected_accept = match case.semantic_outcome.as_str() {
            "accept" => true,
            "reject" => {
                if case.expected_reason_code.as_deref() != Some("schema_violation") {
                    bail!(
                        "{} reject case must require schema_violation, got {:?}",
                        case.name,
                        case.expected_reason_code
                    );
                }
                false
            }
            outcome => bail!("{} has unknown semantic_outcome {outcome}", case.name),
        };
        if accepted != expected_accept {
            bail!(
                "{} semantic outcome drifted: expected {}, observed {}",
                case.name,
                case.semantic_outcome,
                if accepted { "accept" } else { "reject" }
            );
        }
    }
    Ok(())
}

fn run_semantic_cases(file_name: &str, cases: &[SchemaValidationCase]) -> Result<()> {
    if file_name != SDK_CONFORMANCE_CLAIM_FIXTURE {
        return Ok(());
    }
    for case in cases {
        let claims = case
            .instance
            .get("clause_claims")
            .and_then(Value::as_array)
            .ok_or_else(|| anyhow!("{} missing clause_claims[]", case.name))?;
        let mut clause_ids = std::collections::BTreeSet::new();
        let duplicate = claims.iter().any(|claim| {
            claim
                .get("clause_id")
                .and_then(Value::as_str)
                .is_some_and(|clause_id| !clause_ids.insert(clause_id))
        });
        // Accept-class outcomes. `accept_after_digest_revision_and_signature_verification`
        // is the signed, artifact-bound accept: its non-zero digest / spec_revision
        // and proof-signature preconditions are enforced at the schema layer (the
        // `expect_valid` pass in `run_cases`), so at the semantic layer it shares the
        // plain `accept` invariant — no duplicate clause claim.
        match case.semantic_outcome.as_deref() {
            Some(
                outcome @ ("accept" | "accept_after_digest_revision_and_signature_verification"),
            ) if duplicate => {
                bail!(
                    "{} ({outcome}) unexpectedly contains a duplicate clause claim",
                    case.name
                )
            }
            Some("reject") => {
                if case.expected_reason_code.as_deref() == Some("duplicate_clause_claim")
                    && !duplicate
                {
                    bail!(
                        "{} expected duplicate_clause_claim but had no duplicate",
                        case.name
                    );
                }
            }
            Some("accept" | "accept_after_digest_revision_and_signature_verification") | None => {}
            Some(outcome) => bail!("{} has unknown semantic_outcome {outcome}", case.name),
        }
    }
    Ok(())
}

/// Run the supplied cases. Public for tests.
pub fn run_cases(cases: &[SchemaValidationCase]) -> Result<()> {
    if cases.is_empty() {
        bail!("schema-validation-fixture has zero cases");
    }
    let env = SchemaEnv::load()?;
    let mut positives = 0usize;
    let mut negatives = 0usize;
    for case in cases {
        let validator = env.compile(&case.schema_ref)?;
        let is_valid = validator.is_valid(&case.instance);
        if case.expect_valid && !is_valid {
            // Pull the first error for diagnostics.
            let detail = validator
                .iter_errors(&case.instance)
                .next()
                .map(|e| format!("{e}"))
                .unwrap_or_else(|| "<no error reported>".to_string());
            bail!(
                "schema_validation_cases[{}]: positive case rejected by `{}`: {detail}",
                case.name,
                case.schema_ref,
            );
        }
        if !case.expect_valid && is_valid {
            bail!(
                "schema_validation_cases[{}]: negative case accepted by `{}` (expected failure)",
                case.name,
                case.schema_ref,
            );
        }
        if case.expect_valid {
            positives += 1;
        } else {
            negatives += 1;
        }
    }
    eprintln!(
        "[cotest schema_validation_fixture] cases={} positive={positives} negative={negatives}",
        cases.len()
    );
    Ok(())
}

/// Lazy schema/registry environment that caches:
/// * the parsed JSON-Schema source documents
/// * the openapi YAML doc (parsed once)
///
/// `jsonschema::Registry` borrows the supplied resources and is
/// builder-only — we cannot stash a prepared Registry into a field and
/// then hand out validators that outlive a builder borrow. Compiling a
/// validator is the cheap path here (≤34 schemas, no network IO), so we
/// rebuild the registry inline per `compile()` call. The resulting
/// `Validator` is owned and outlives the borrowed registry.
pub(crate) struct SchemaEnv {
    resources: Vec<(String, Value)>,
    schemas_by_file: HashMap<String, Value>,
    openapi: Option<Value>,
}

impl SchemaEnv {
    pub(crate) fn load() -> Result<Self> {
        let artifacts_root = spec_artifacts_root();
        let schemas_dir = artifacts_root.join(SCHEMA_DIR);
        let mut resources: Vec<(String, Value)> = Vec::new();
        let mut schemas_by_file: HashMap<String, Value> = HashMap::new();
        for entry in fs::read_dir(&schemas_dir)
            .with_context(|| format!("read schemas dir {}", schemas_dir.display()))?
        {
            let path = entry?.path();
            if path.extension() != Some(OsStr::new("json")) {
                continue;
            }
            let raw = fs::read_to_string(&path)?;
            let value: Value = serde_json::from_str(&raw)
                .map_err(|err| anyhow!("schema file {} invalid JSON: {err}", path.display()))?;
            let id = value
                .get("$id")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("schema file {} missing $id", path.display()))?
                .to_owned();
            let rel = format!(
                "{SCHEMA_DIR}/{}",
                path.file_name()
                    .and_then(OsStr::to_str)
                    .ok_or_else(|| anyhow!("schema filename invalid"))?
            );
            schemas_by_file.insert(rel, value.clone());
            resources.push((id, value));
        }

        let openapi_path = artifacts_root.join(OPENAPI_FILE);
        let openapi = if openapi_path.is_file() {
            let raw = fs::read_to_string(&openapi_path)
                .with_context(|| format!("read openapi {}", openapi_path.display()))?;
            let yaml: serde_yaml_ng::Value = serde_yaml_ng::from_str(&raw)?;
            Some(yaml_to_json(&yaml)?)
        } else {
            None
        };

        Ok(Self {
            resources,
            schemas_by_file,
            openapi,
        })
    }

    pub(crate) fn compile(&self, schema_ref: &str) -> Result<jsonschema::Validator> {
        let (schema_value, base_uri) = self.resolve_schema_ref(schema_ref)?;
        let mut builder = Registry::new();
        for (id, value) in &self.resources {
            builder = builder
                .add(id.as_str(), Resource::from_contents(value.clone()))
                .map_err(|err| anyhow!("registry add {id} failed: {err}"))?;
        }
        let registry = builder
            .prepare()
            .map_err(|err| anyhow!("registry prepare failed: {err}"))?;
        let mut opts = jsonschema::options()
            .with_registry(&registry)
            .should_validate_formats(true);
        if let Some(base) = base_uri {
            opts = opts.with_base_uri(base);
        }
        opts.build(&schema_value)
            .map_err(|err| anyhow!("compile schema_ref `{schema_ref}` failed: {err}"))
    }

    /// Resolve a `schema_ref` to a JSON Schema value + optional base URI.
    ///
    /// Returns the schema value (already seeded with `$schema` and `$defs`
    /// when appropriate) and a base URI for ref resolution.
    fn resolve_schema_ref(&self, schema_ref: &str) -> Result<(Value, Option<String>)> {
        // Three shapes the fixture uses:
        //  (a) `schemas/<file>.schema.json`
        //  (b) `schemas/<file>.schema.json#/$defs/<name>`
        //  (c) `openapi/arkret-service-api.openapi.yaml#/components/schemas/<Name>`
        if let Some(rest) = schema_ref.strip_prefix("schemas/") {
            let (file_path, fragment) = split_fragment(rest);
            let key = format!("{SCHEMA_DIR}/{file_path}");
            let parent = self
                .schemas_by_file
                .get(&key)
                .ok_or_else(|| anyhow!("schema_ref points at unknown file `{schema_ref}`"))?;
            let base_uri = parent.get("$id").and_then(Value::as_str).map(str::to_owned);
            let mut schema = if let Some(fragment) = fragment {
                let pointer = format!("/{}", fragment.trim_start_matches('/'));
                let value = parent.pointer(&pointer).ok_or_else(|| {
                    anyhow!("schema_ref fragment not found in {schema_ref}: {pointer}")
                })?;
                value.clone()
            } else {
                parent.clone()
            };

            // Seed `$schema` and inherit `$defs` so a fragment compiles
            // standalone but can still resolve sibling defs.
            if let Value::Object(map) = &mut schema {
                map.entry("$schema")
                    .or_insert(json!("https://json-schema.org/draft/2020-12/schema"));
                if let Some(defs) = parent.get("$defs") {
                    map.entry("$defs").or_insert_with(|| defs.clone());
                }
            }
            return Ok((schema, base_uri));
        }
        if let Some(rest) = schema_ref.strip_prefix("openapi/") {
            // We only support OpenAPI refs that target
            // `#/components/schemas/<Name>` — the only form this fixture
            // uses today. If a new form lands, surface a clear error.
            let openapi = self.openapi.as_ref().ok_or_else(|| {
                anyhow!("openapi document not loaded; cannot resolve `{schema_ref}`")
            })?;
            let (file_path, fragment) = split_fragment(rest);
            if file_path != "arkret-service-api.openapi.yaml" {
                bail!("schema_ref points at unknown openapi file: {file_path}");
            }
            let fragment =
                fragment.ok_or_else(|| anyhow!("openapi schema_ref missing component fragment"))?;
            let pointer = format!("/{}", fragment.trim_start_matches('/'));
            let component = openapi
                .pointer(&pointer)
                .ok_or_else(|| anyhow!("openapi component not found: {pointer}"))?;
            // Inline shared component schemas referenced by this component
            // so we don't need a separate openapi-aware registry.
            let inlined = inline_openapi_refs(component, openapi)?;
            let base_uri = Some(format!(
                "{SCHEMA_ID_PREFIX}openapi/arkret-service-api.openapi.yaml"
            ));
            let mut schema = inlined;
            if let Value::Object(map) = &mut schema {
                map.entry("$schema")
                    .or_insert(json!("https://json-schema.org/draft/2020-12/schema"));
            }
            return Ok((schema, base_uri));
        }
        bail!("unsupported schema_ref shape: {schema_ref}")
    }
}

fn split_fragment(input: &str) -> (&str, Option<&str>) {
    match input.find('#') {
        Some(idx) => (&input[..idx], Some(&input[idx + 1..])),
        None => (input, None),
    }
}

fn yaml_to_json(value: &serde_yaml_ng::Value) -> Result<Value> {
    // Round-trip via serde_json to swap representations.
    let s = serde_json::to_string(&value)
        .map_err(|err| anyhow!("yaml to json round-trip failed: {err}"))?;
    serde_json::from_str(&s).map_err(|err| anyhow!("re-decode yaml-as-json failed: {err}"))
}

/// Inline every `{ "$ref": "#/components/schemas/Name" }` reference found
/// inside `value` against `openapi`. The substitution is shallow-deep —
/// we recursively walk arrays/objects but stop expanding after a single
/// substitution cycle to avoid infinite recursion on self-referential
/// components.
fn inline_openapi_refs(value: &Value, openapi: &Value) -> Result<Value> {
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    inline_openapi_refs_inner(value, openapi, &mut seen, 0)
}

fn inline_openapi_refs_inner(
    value: &Value,
    openapi: &Value,
    seen: &mut std::collections::HashSet<String>,
    depth: usize,
) -> Result<Value> {
    if depth > 16 {
        // Hard ceiling — should never happen for our fixture but protects
        // against pathological future openapi authoring.
        return Ok(value.clone());
    }
    match value {
        Value::Object(map) => {
            if let Some(reference) = map.get("$ref").and_then(Value::as_str)
                && let Some(component_name) = reference.strip_prefix("#/components/schemas/")
            {
                if seen.contains(component_name) {
                    // Cycle: leave the reference as-is and let
                    // jsonschema handle it (or fail). For our fixture
                    // there are no cycles, so this path is unused.
                    return Ok(value.clone());
                }
                let pointer = format!("/components/schemas/{component_name}");
                let resolved = openapi
                    .pointer(&pointer)
                    .ok_or_else(|| anyhow!("openapi $ref target missing: {reference}"))?;
                seen.insert(component_name.to_string());
                let expanded = inline_openapi_refs_inner(resolved, openapi, seen, depth + 1)?;
                seen.remove(component_name);
                return Ok(expanded);
            }
            let mut out = serde_json::Map::new();
            for (k, v) in map {
                out.insert(
                    k.clone(),
                    inline_openapi_refs_inner(v, openapi, seen, depth + 1)?,
                );
            }
            Ok(Value::Object(out))
        }
        Value::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                out.push(inline_openapi_refs_inner(item, openapi, seen, depth + 1)?);
            }
            Ok(Value::Array(out))
        }
        other => Ok(other.clone()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spec_fixture_runs() {
        run_schema_validation_fixture_suite()
            .expect("schema-validation-fixture cases should all match expectations");
    }
}
