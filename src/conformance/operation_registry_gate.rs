//! Literal HTTP-operation registry scanner.
//!
//! This gate intentionally scans source text for literal route/path evidence
//! across sibling repositories. It can prove that observed literals are present
//! in the operation registry, but it can miss routes built through macros,
//! string formatting, or generated code. High-risk services should pair this
//! with implementation-native route inventories or generated OpenAPI outputs.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Result, anyhow, bail};
use serde::Deserialize;
use serde_json::Value;

use super::spec_artifacts_root;

const OPERATION_REGISTRY_REF: &str = "registry/operation-registry.json";
const OPENAPI_REF: &str = "openapi/arkret-service-api.openapi.yaml";
const OPERATION_COMPLETENESS_REF: &str = "reports/operation-completeness-report.json";
const OPERATION_SCHEMA_INDEX_REF: &str = "reports/operation-schema-index.json";
const EVENT_KIND_REGISTRY_REF: &str = "registry/event-kind-registry.json";
const PRODUCT_PRIVATE_REF: &str = "operation-product-private-paths.json";

// QUERY (RFC 9110 registered, safe and cacheable with a request body) is what
// the operation registry binds the Events read surface to; a gate that does not
// know the verb reports every one of those operations as an unsupported method.
const HTTP_METHODS: &[&str] = &[
    "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "QUERY",
];
/// Methods this gate will infer from source text.
///
/// QUERY is excluded on purpose. Source-text inference reads both a lowercase
/// `.verb(` call and a bare uppercase token, and QUERY collides with ordinary
/// code on both: `.query(&[..])` is `reqwest`'s query-string builder on a GET,
/// and `AGENT_SIGNER_EVIDENCE_QUERY_PATH` is a path constant, not a verb. A
/// call site whose verb cannot be inferred is still matched against the
/// registered path, so leaving QUERY out costs nothing and stops a GET from
/// being relabelled into an operation that does not exist.
const INFERABLE_METHODS: &[&str] = &["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"];
const OPENAPI_METHODS: &[(&str, &str)] = &[
    ("get", "GET"),
    ("head", "HEAD"),
    ("post", "POST"),
    ("put", "PUT"),
    ("patch", "PATCH"),
    ("delete", "DELETE"),
    ("options", "OPTIONS"),
    ("query", "QUERY"),
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OperationRegistryGateStatus {
    Registered,
    ProductPrivate,
    Failed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationRegistryGateEntry {
    pub source: String,
    pub method: Option<String>,
    pub path: String,
    pub evidence: String,
    pub gate_status: OperationRegistryGateStatus,
    pub operation_id: Option<String>,
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationRegistryGateReport {
    pub registry_operation_count: usize,
    pub openapi_operation_count: usize,
    pub completeness_operation_count: usize,
    pub schema_index_operation_count: usize,
    pub artifact_failures: Vec<String>,
    pub entries: Vec<OperationRegistryGateEntry>,
}

impl OperationRegistryGateReport {
    pub fn failed_entries(&self) -> impl Iterator<Item = &OperationRegistryGateEntry> {
        self.entries
            .iter()
            .filter(|entry| entry.gate_status == OperationRegistryGateStatus::Failed)
    }

    pub fn registered_entries(&self) -> impl Iterator<Item = &OperationRegistryGateEntry> {
        self.entries
            .iter()
            .filter(|entry| entry.gate_status == OperationRegistryGateStatus::Registered)
    }

    pub fn product_private_entries(&self) -> impl Iterator<Item = &OperationRegistryGateEntry> {
        self.entries
            .iter()
            .filter(|entry| entry.gate_status == OperationRegistryGateStatus::ProductPrivate)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct OperationKey {
    method: String,
    path: String,
}

impl OperationKey {
    fn new(method: impl Into<String>, path: impl Into<String>) -> Self {
        Self {
            method: method.into().to_ascii_uppercase(),
            path: normalize_path_template(&path.into()),
        }
    }

    fn as_http(&self) -> String {
        format!("{} {}", self.method, self.path)
    }
}

#[derive(Clone, Debug)]
struct RegisteredOperation {
    operation_id: String,
    key: OperationKey,
    success_shape_kind: Option<String>,
    request_schema_ref: Option<String>,
    response_schema_ref: Option<String>,
    durable_effect: Option<Value>,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct ObservedOperation {
    source: String,
    method: Option<String>,
    path: String,
    evidence: String,
}

#[derive(Debug, Deserialize)]
struct OperationRegistry {
    operations: Vec<RegistryOperation>,
}

#[derive(Debug, Deserialize)]
struct RegistryOperation {
    operation_id: String,
    http: String,
    success_shape_kind: Option<String>,
    request_schema_ref: Option<String>,
    response_schema_ref: Option<String>,
    durable_effect: Option<Value>,
}

#[derive(Debug, Deserialize)]
struct OperationCompletenessReport {
    operations: Vec<CompletenessOperation>,
}

#[derive(Debug, Deserialize)]
struct CompletenessOperation {
    operation_id: String,
    http: String,
}

#[derive(Debug, Deserialize)]
struct OperationSchemaIndex {
    operations: Vec<SchemaIndexOperation>,
}

#[derive(Debug, Deserialize)]
struct SchemaIndexOperation {
    operation_id: String,
    success_shape_kind: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ProductPrivateRegistry {
    allowed: Vec<ProductPrivatePath>,
}

#[derive(Clone, Debug, Deserialize)]
struct ProductPrivatePath {
    source: String,
    method: String,
    path: String,
    classification: String,
    reason: String,
}

#[derive(Clone, Debug, Default)]
struct ProductPrivateIndex {
    entries: Vec<ProductPrivatePath>,
}

#[derive(Clone, Debug)]
pub struct OperationRegistryGatePaths {
    pub artifacts_root: PathBuf,
    pub product_private_path: PathBuf,
    pub source_roots: Vec<OperationSourceRoot>,
}

#[derive(Clone, Debug)]
pub struct OperationSourceRoot {
    pub source: String,
    pub root: PathBuf,
    pub include_files: Vec<PathBuf>,
    pub include_dirs: Vec<PathBuf>,
}

impl OperationSourceRoot {
    pub fn new(source: impl Into<String>, root: impl Into<PathBuf>) -> Self {
        Self {
            source: source.into(),
            root: root.into(),
            include_files: Vec::new(),
            include_dirs: Vec::new(),
        }
    }

    pub fn with_file(mut self, path: impl Into<PathBuf>) -> Self {
        self.include_files.push(path.into());
        self
    }

    pub fn with_dir(mut self, path: impl Into<PathBuf>) -> Self {
        self.include_dirs.push(path.into());
        self
    }
}

pub fn build_operation_registry_gate_report() -> Result<OperationRegistryGateReport> {
    build_operation_registry_gate_report_from_paths(default_gate_paths())
}

pub fn validate_operation_registry_gate() -> Result<OperationRegistryGateReport> {
    let report = build_operation_registry_gate_report()?;
    validate_operation_registry_gate_report(&report)?;
    Ok(report)
}

pub fn validate_operation_registry_gate_report(report: &OperationRegistryGateReport) -> Result<()> {
    let mut failures = report.artifact_failures.clone();
    for entry in report.failed_entries() {
        let method = entry.method.as_deref().unwrap_or("*");
        let reason = entry.reason.as_deref().unwrap_or("unregistered path");
        failures.push(format!(
            "{} {} {} ({}): {reason}",
            entry.source, method, entry.path, entry.evidence
        ));
    }

    if failures.is_empty() {
        return Ok(());
    }

    bail!(
        "operation registry gate found {} failing entries:\n{}",
        failures.len(),
        failures.join("\n")
    )
}

pub fn build_operation_registry_gate_report_from_paths(
    paths: OperationRegistryGatePaths,
) -> Result<OperationRegistryGateReport> {
    let registry_path = paths.artifacts_root.join(OPERATION_REGISTRY_REF);
    let openapi_path = paths.artifacts_root.join(OPENAPI_REF);
    let completeness_path = paths.artifacts_root.join(OPERATION_COMPLETENESS_REF);
    let schema_index_path = paths.artifacts_root.join(OPERATION_SCHEMA_INDEX_REF);
    let event_kind_registry_path = paths.artifacts_root.join(EVENT_KIND_REGISTRY_REF);

    let registry = load_operation_registry(&registry_path)?;
    let registry_by_key = registry
        .iter()
        .map(|operation| (operation.key.clone(), operation.clone()))
        .collect::<BTreeMap<_, _>>();
    let registry_by_id = registry
        .iter()
        .map(|operation| (operation.operation_id.clone(), operation.clone()))
        .collect::<BTreeMap<_, _>>();
    let openapi = load_openapi_operations(&openapi_path)?;
    let completeness = load_completeness_report(&completeness_path)?;
    let schema_index = load_schema_index(&schema_index_path)?;
    let product_private = load_product_private_index(&paths.product_private_path)?;

    let mut artifact_failures = Vec::new();
    artifact_failures.extend(validate_openapi_against_registry(
        &registry_by_id,
        &registry_by_key,
        &openapi,
    ));
    artifact_failures.extend(validate_completeness_against_registry(
        &registry_by_id,
        &completeness,
    ));
    artifact_failures.extend(validate_schema_index_against_registry(
        &registry_by_id,
        &schema_index,
    ));
    artifact_failures.extend(validate_durable_effects(
        &registry_by_id,
        &event_kind_registry_path,
    )?);
    artifact_failures.extend(validate_product_private_index(&product_private));

    let observed = discover_observed_operations(&paths.source_roots)?;
    let mut entries = Vec::with_capacity(observed.len());
    for observed in observed {
        entries.push(classify_observed_operation(
            observed,
            &registry_by_key,
            &product_private,
        ));
    }

    Ok(OperationRegistryGateReport {
        registry_operation_count: registry.len(),
        openapi_operation_count: openapi.len(),
        completeness_operation_count: completeness.len(),
        schema_index_operation_count: schema_index.len(),
        artifact_failures,
        entries,
    })
}

fn default_gate_paths() -> OperationRegistryGatePaths {
    let cotest_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = cotest_root
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| cotest_root.clone());
    OperationRegistryGatePaths {
        artifacts_root: spec_artifacts_root(),
        product_private_path: cotest_root.join(PRODUCT_PRIVATE_REF),
        source_roots: vec![
            OperationSourceRoot::new("soland", workspace_root.join("soland"))
                .with_dir("crates/http/src/routing")
                .with_file("crates/http/src/wire.rs")
                .with_file("crates/http/src/did_resolver_chain.rs"),
            OperationSourceRoot::new("sdk", workspace_root.join("arkret-rust-sdk"))
                .with_dir("crates/http-client/src")
                .with_dir("crates/sdk/src")
                .with_dir("crates/server/src"),
            OperationSourceRoot::new("coauth", workspace_root.join("coauth"))
                .with_dir("crates/backend/src")
                .with_dir("crates/frontend/src/api"),
            OperationSourceRoot::new("starid", workspace_root.join("starid"))
                .with_dir("crates/server/src")
                .with_dir("crates/admin/src/api"),
            OperationSourceRoot::new("teabay", workspace_root.join("teabay"))
                .with_dir("crates/server/src")
                .with_dir("crates/admin/src"),
            OperationSourceRoot::new("inkson", workspace_root.join("inkson"))
                .with_dir("src")
                .with_file("tests/e2e/mockArkretApi.ts")
                .with_file("tests/e2e/mockArkretContract.ts"),
            OperationSourceRoot::new("cotest", cotest_root.clone())
                .with_dir("e2e/helpers")
                .with_dir("e2e/tests")
                .with_dir("src/scenarios"),
        ],
    }
}

fn load_operation_registry(path: &Path) -> Result<Vec<RegisteredOperation>> {
    let raw = fs::read_to_string(path).map_err(|error| {
        anyhow!(
            "failed to read operation registry {}: {error}",
            path.display()
        )
    })?;
    let registry: OperationRegistry = serde_json::from_str(&raw).map_err(|error| {
        anyhow!(
            "failed to parse operation registry {}: {error}",
            path.display()
        )
    })?;

    let mut operations = Vec::with_capacity(registry.operations.len());
    for row in registry.operations {
        let key = parse_http_binding(&row.http)
            .map_err(|error| anyhow!("{}: {error}", row.operation_id))?;
        operations.push(RegisteredOperation {
            operation_id: row.operation_id,
            key,
            success_shape_kind: row.success_shape_kind,
            request_schema_ref: row.request_schema_ref,
            response_schema_ref: row.response_schema_ref,
            durable_effect: row.durable_effect,
        });
    }
    Ok(operations)
}

fn validate_durable_effects(
    registry_by_id: &BTreeMap<String, RegisteredOperation>,
    event_kind_registry_path: &Path,
) -> Result<Vec<String>> {
    let raw = fs::read_to_string(event_kind_registry_path).map_err(|error| {
        anyhow!(
            "failed to read event-kind registry {}: {error}",
            event_kind_registry_path.display()
        )
    })?;
    let registry: Value = serde_json::from_str(&raw).map_err(|error| {
        anyhow!(
            "failed to parse event-kind registry {}: {error}",
            event_kind_registry_path.display()
        )
    })?;
    let active = registry
        .get("event_kinds")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("event-kind registry missing event_kinds[]"))?
        .iter()
        .filter(|row| row.get("status").and_then(Value::as_str) == Some("active"))
        .filter_map(|row| row.get("event_kind").and_then(Value::as_str))
        .collect::<BTreeSet<_>>();
    let private_writes = registry
        .pointer("/actor_private_contracts/event_writes")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            anyhow!("event-kind registry missing actor_private_contracts.event_writes")
        })?;

    let mut failures = Vec::new();
    for operation in registry_by_id.values() {
        let write_operation = matches!(operation.key.method.as_str(), "PUT" | "PATCH" | "DELETE")
            || (operation.key.method == "POST" && !operation.operation_id.contains(".read."));
        let Some(effect) = operation.durable_effect.as_ref() else {
            if write_operation {
                failures.push(format!(
                    "write operation {} is missing durable_effect",
                    operation.operation_id
                ));
            }
            continue;
        };
        let Some(effect) = effect.as_object() else {
            failures.push(format!(
                "{} durable_effect must be an object",
                operation.operation_id
            ));
            continue;
        };
        let kind = effect.get("kind").and_then(Value::as_str).unwrap_or("");
        let allowed_keys: &[&str] = match kind {
            "none" => &["kind", "rationale"],
            "event_log" => &[
                "kind",
                "event_kinds",
                "event_kind_source",
                "event_kind_sources",
                "cross_service_effects",
                "irreversibility_note",
            ],
            "actor_private_event" => &["kind", "event_kind"],
            _ => {
                failures.push(format!(
                    "{} durable_effect.kind is not in the closed union: {kind:?}",
                    operation.operation_id
                ));
                continue;
            }
        };
        for key in effect.keys() {
            if !allowed_keys.contains(&key.as_str()) {
                failures.push(format!(
                    "{} durable_effect contains unknown field {key}",
                    operation.operation_id
                ));
            }
        }
        match kind {
            "none" => {
                if effect
                    .get("rationale")
                    .and_then(Value::as_str)
                    .is_none_or(|value| value.trim().is_empty())
                {
                    failures.push(format!(
                        "{} durable_effect=none requires a non-empty rationale",
                        operation.operation_id
                    ));
                }
            }
            "event_log" => {
                let static_kinds = effect.get("event_kinds").and_then(Value::as_array);
                let dynamic_source = effect.get("event_kind_source").and_then(Value::as_str);
                let dynamic_sources = effect.get("event_kind_sources").and_then(Value::as_array);
                if [
                    static_kinds.is_some(),
                    dynamic_source.is_some(),
                    dynamic_sources.is_some(),
                ]
                .into_iter()
                .filter(|present| *present)
                .count()
                    != 1
                {
                    failures.push(format!(
                        "{} event_log durable_effect must declare exactly one of event_kinds, event_kind_source, or event_kind_sources",
                        operation.operation_id
                    ));
                }
                if let Some(kinds) = static_kinds {
                    if kinds.is_empty() {
                        failures.push(format!(
                            "{} event_log durable_effect has empty event_kinds",
                            operation.operation_id
                        ));
                    }
                    for event_kind in kinds {
                        match event_kind.as_str() {
                            Some(event_kind) if active.contains(event_kind) => {}
                            Some(event_kind) => failures.push(format!(
                                "{} references inactive or unknown event kind {event_kind}",
                                operation.operation_id
                            )),
                            None => failures.push(format!(
                                "{} event_kinds contains a non-string value",
                                operation.operation_id
                            )),
                        }
                    }
                }
                if let Some(source) = dynamic_source
                    && (!source.starts_with("$request.")
                        || !source.ends_with(".event.kind")
                        || source.contains(char::is_whitespace))
                {
                    failures.push(format!(
                        "{} has an unresolvable event_kind_source {source}",
                        operation.operation_id
                    ));
                }
                if let Some(sources) = dynamic_sources {
                    if sources.is_empty() {
                        failures.push(format!(
                            "{} event_log durable_effect has empty event_kind_sources",
                            operation.operation_id
                        ));
                    }
                    for source in sources {
                        match source.as_str() {
                            Some(source)
                                if source.starts_with("$request.")
                                    && source.ends_with(".event.kind")
                                    && !source.contains(char::is_whitespace) => {}
                            Some(source) => failures.push(format!(
                                "{} has an unresolvable event_kind_sources entry {source}",
                                operation.operation_id
                            )),
                            None => failures.push(format!(
                                "{} event_kind_sources contains a non-string value",
                                operation.operation_id
                            )),
                        }
                    }
                }
                if let Some(effects) = effect.get("cross_service_effects") {
                    match effects.as_array() {
                        Some(effects)
                            if !effects.is_empty()
                                && effects.iter().all(|value| {
                                    value
                                        .as_str()
                                        .is_some_and(|value| !value.trim().is_empty())
                                }) => {}
                        _ => failures.push(format!(
                            "{} cross_service_effects must be a non-empty array of non-empty strings",
                            operation.operation_id
                        )),
                    }
                }
                if effect
                    .get("irreversibility_note")
                    .is_some_and(|value| value.as_str().is_none_or(|value| value.trim().is_empty()))
                {
                    failures.push(format!(
                        "{} irreversibility_note must be a non-empty string",
                        operation.operation_id
                    ));
                }
            }
            "actor_private_event" => {
                let Some(event_kind) = effect.get("event_kind").and_then(Value::as_str) else {
                    failures.push(format!(
                        "{} actor_private_event is missing event_kind",
                        operation.operation_id
                    ));
                    continue;
                };
                if !active.contains(event_kind) {
                    failures.push(format!(
                        "{} references inactive or unknown actor-private event {event_kind}",
                        operation.operation_id
                    ));
                }
                let Some(contract) = private_writes.get(event_kind) else {
                    failures.push(format!(
                        "{} event {event_kind} is not registered as actor-private",
                        operation.operation_id
                    ));
                    continue;
                };
                if contract
                    .get("cell_family")
                    .and_then(Value::as_str)
                    .is_none_or(|family| !family.starts_with("ak.private."))
                {
                    failures.push(format!(
                        "{} actor-private event {event_kind} does not target an ak.private.* family",
                        operation.operation_id
                    ));
                }
            }
            _ => unreachable!(),
        }
    }
    Ok(failures)
}

fn load_openapi_operations(path: &Path) -> Result<BTreeMap<OperationKey, String>> {
    let raw = fs::read_to_string(path)
        .map_err(|error| anyhow!("failed to read OpenAPI {}: {error}", path.display()))?;
    let value: Value = serde_yaml_ng::from_str(&raw)
        .map_err(|error| anyhow!("failed to parse OpenAPI {}: {error}", path.display()))?;
    let paths = value
        .get("paths")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow!("OpenAPI {} missing paths object", path.display()))?;

    let mut operations = BTreeMap::new();
    for (path, item) in paths {
        if !path.starts_with("/_arkret") {
            continue;
        }
        let Some(item) = item.as_object() else {
            continue;
        };
        for (openapi_method, method) in OPENAPI_METHODS {
            let Some(operation) = item.get(*openapi_method).and_then(Value::as_object) else {
                continue;
            };
            let operation_id = operation
                .get("operationId")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("OpenAPI {method} {path} missing operationId"))?;
            let key = OperationKey::new(*method, path);
            if let Some(previous) = operations.insert(key.clone(), operation_id.to_owned()) {
                bail!(
                    "OpenAPI duplicate operation binding {}: {previous} and {operation_id}",
                    key.as_http()
                );
            }
        }
    }
    Ok(operations)
}

fn load_completeness_report(path: &Path) -> Result<BTreeMap<String, OperationKey>> {
    let raw = fs::read_to_string(path).map_err(|error| {
        anyhow!(
            "failed to read operation completeness report {}: {error}",
            path.display()
        )
    })?;
    let report: OperationCompletenessReport = serde_json::from_str(&raw).map_err(|error| {
        anyhow!(
            "failed to parse operation completeness report {}: {error}",
            path.display()
        )
    })?;
    let mut operations = BTreeMap::new();
    for row in report.operations {
        let key = parse_http_binding(&row.http)
            .map_err(|error| anyhow!("{}: {error}", row.operation_id))?;
        operations.insert(row.operation_id, key);
    }
    Ok(operations)
}

fn load_schema_index(path: &Path) -> Result<BTreeMap<String, Option<String>>> {
    let raw = fs::read_to_string(path).map_err(|error| {
        anyhow!(
            "failed to read operation schema index {}: {error}",
            path.display()
        )
    })?;
    let index: OperationSchemaIndex = serde_json::from_str(&raw).map_err(|error| {
        anyhow!(
            "failed to parse operation schema index {}: {error}",
            path.display()
        )
    })?;
    Ok(index
        .operations
        .into_iter()
        .map(|row| (row.operation_id, row.success_shape_kind))
        .collect())
}

fn load_product_private_index(path: &Path) -> Result<ProductPrivateIndex> {
    let raw = fs::read_to_string(path).map_err(|error| {
        anyhow!(
            "failed to read operation product-private registry {}: {error}",
            path.display()
        )
    })?;
    let registry: ProductPrivateRegistry = serde_json::from_str(&raw).map_err(|error| {
        anyhow!(
            "failed to parse operation product-private registry {}: {error}",
            path.display()
        )
    })?;
    Ok(ProductPrivateIndex {
        entries: registry.allowed,
    })
}

fn validate_openapi_against_registry(
    registry_by_id: &BTreeMap<String, RegisteredOperation>,
    registry_by_key: &BTreeMap<OperationKey, RegisteredOperation>,
    openapi: &BTreeMap<OperationKey, String>,
) -> Vec<String> {
    let mut failures = Vec::new();
    for operation in registry_by_id.values() {
        match openapi.get(&operation.key) {
            Some(operation_id) if operation_id == &operation.operation_id => {}
            Some(operation_id) => failures.push(format!(
                "OpenAPI {} operationId drift: registry has {}, OpenAPI has {}",
                operation.key.as_http(),
                operation.operation_id,
                operation_id
            )),
            None => failures.push(format!(
                "OpenAPI missing registered operation {} ({})",
                operation.operation_id,
                operation.key.as_http()
            )),
        }
    }

    for (key, operation_id) in openapi {
        match registry_by_key.get(key) {
            Some(operation) if operation.operation_id == *operation_id => {}
            Some(operation) => failures.push(format!(
                "OpenAPI {} maps to {}, registry maps same binding to {}",
                key.as_http(),
                operation_id,
                operation.operation_id
            )),
            None => failures.push(format!(
                "OpenAPI exposes unregistered operation {} ({})",
                operation_id,
                key.as_http()
            )),
        }
    }
    failures
}

fn validate_completeness_against_registry(
    registry_by_id: &BTreeMap<String, RegisteredOperation>,
    completeness: &BTreeMap<String, OperationKey>,
) -> Vec<String> {
    let mut failures = Vec::new();
    for (operation_id, operation) in registry_by_id {
        match completeness.get(operation_id) {
            Some(key) if key == &operation.key => {}
            Some(key) => failures.push(format!(
                "operation completeness report http drift for {operation_id}: registry {}, report {}",
                operation.key.as_http(),
                key.as_http()
            )),
            None => failures.push(format!(
                "operation completeness report missing {operation_id}"
            )),
        }
    }
    for operation_id in completeness.keys() {
        if !registry_by_id.contains_key(operation_id) {
            failures.push(format!(
                "operation completeness report contains unregistered {operation_id}"
            ));
        }
    }
    failures
}

fn validate_schema_index_against_registry(
    registry_by_id: &BTreeMap<String, RegisteredOperation>,
    schema_index: &BTreeMap<String, Option<String>>,
) -> Vec<String> {
    let mut failures = Vec::new();
    for (operation_id, success_shape_kind) in schema_index {
        let Some(operation) = registry_by_id.get(operation_id) else {
            failures.push(format!(
                "operation schema index contains unregistered {operation_id}"
            ));
            continue;
        };
        if let (Some(registry_kind), Some(index_kind)) =
            (&operation.success_shape_kind, success_shape_kind)
            && registry_kind != index_kind
        {
            failures.push(format!(
                "operation schema index success_shape_kind drift for {operation_id}: registry {registry_kind}, index {index_kind}"
            ));
        }
    }

    for operation in registry_by_id.values() {
        if (operation.request_schema_ref.is_some() || operation.response_schema_ref.is_some())
            && !schema_index.contains_key(&operation.operation_id)
        {
            failures.push(format!(
                "operation schema index missing typed schema operation {}",
                operation.operation_id
            ));
        }
    }
    failures
}

fn validate_product_private_index(index: &ProductPrivateIndex) -> Vec<String> {
    let mut failures = Vec::new();
    let mut seen = BTreeSet::new();
    for entry in &index.entries {
        if entry.source.trim().is_empty() {
            failures.push(format!(
                "product-private entry {} has empty source",
                entry.path
            ));
        }
        if entry.classification != "product-private" {
            failures.push(format!(
                "{} {} must use classification=product-private, got {}",
                entry.method, entry.path, entry.classification
            ));
        }
        if entry.reason.trim().is_empty() {
            failures.push(format!(
                "{} {} product-private entry must carry a reason",
                entry.method, entry.path
            ));
        }
        if entry.method != "*" && !HTTP_METHODS.contains(&entry.method.as_str()) {
            failures.push(format!(
                "{} {} product-private method is not a known HTTP method or *",
                entry.method, entry.path
            ));
        }
        if !entry.path.starts_with("/_arkret/") {
            failures.push(format!(
                "{} {} product-private path must stay under /_arkret/*",
                entry.method, entry.path
            ));
        }
        let key = (
            entry.source.as_str(),
            entry.method.as_str(),
            normalize_path_template(&entry.path),
        );
        if !seen.insert(key.clone()) {
            failures.push(format!(
                "{} {} product-private entry is duplicated for {}",
                entry.method, entry.path, entry.source
            ));
        }
    }
    failures
}

fn classify_observed_operation(
    observed: ObservedOperation,
    registry_by_key: &BTreeMap<OperationKey, RegisteredOperation>,
    product_private: &ProductPrivateIndex,
) -> OperationRegistryGateEntry {
    if let Some((operation_id, key)) =
        find_registered_operation(&observed, registry_by_key).map(|operation| {
            (
                operation.operation_id.clone(),
                Some(operation.key.method.clone()),
            )
        })
    {
        return OperationRegistryGateEntry {
            source: observed.source,
            method: observed.method.or(key),
            path: observed.path,
            evidence: observed.evidence,
            gate_status: OperationRegistryGateStatus::Registered,
            operation_id: Some(operation_id),
            reason: None,
        };
    }

    if let Some(entry) = product_private.entries.iter().find(|entry| {
        entry.source == observed.source
            && method_matches(&entry.method, observed.method.as_deref())
            && pattern_matches_path(&entry.path, &observed.path)
    }) {
        return OperationRegistryGateEntry {
            source: observed.source,
            method: observed.method,
            path: observed.path,
            evidence: observed.evidence,
            gate_status: OperationRegistryGateStatus::ProductPrivate,
            operation_id: None,
            reason: Some(entry.reason.clone()),
        };
    }

    OperationRegistryGateEntry {
        source: observed.source,
        method: observed.method,
        path: observed.path,
        evidence: observed.evidence,
        gate_status: OperationRegistryGateStatus::Failed,
        operation_id: None,
        reason: Some(
            "unregistered /_arkret/* path is not explicitly classified as product-private"
                .to_owned(),
        ),
    }
}

fn find_registered_operation<'a>(
    observed: &ObservedOperation,
    registry_by_key: &'a BTreeMap<OperationKey, RegisteredOperation>,
) -> Option<&'a RegisteredOperation> {
    registry_by_key.values().find(|operation| {
        observed
            .method
            .as_deref()
            .is_none_or(|method| method == operation.key.method)
            && pattern_matches_path(&operation.key.path, &observed.path)
    })
}

fn method_matches(allowed: &str, observed: Option<&str>) -> bool {
    allowed == "*" || observed.is_none_or(|method| method == allowed)
}

fn discover_observed_operations(
    source_roots: &[OperationSourceRoot],
) -> Result<Vec<ObservedOperation>> {
    let mut out = BTreeSet::new();
    for root in source_roots {
        if !root.root.is_dir() {
            bail!(
                "operation source root {} for {} is missing",
                root.root.display(),
                root.source
            );
        }

        for include_file in &root.include_files {
            let path = root.root.join(include_file);
            if !path.is_file() {
                bail!(
                    "operation source file {} for {} is missing",
                    path.display(),
                    root.source
                );
            }
            scan_source_file(&root.source, &root.root, &path, &mut out)?;
        }

        for include_dir in &root.include_dirs {
            let dir = root.root.join(include_dir);
            if !dir.is_dir() {
                bail!(
                    "operation source dir {} for {} is missing",
                    dir.display(),
                    root.source
                );
            }
            scan_source_dir(&root.source, &root.root, &dir, &mut out)?;
        }
    }
    Ok(out.into_iter().collect())
}

fn scan_source_dir(
    source: &str,
    root: &Path,
    dir: &Path,
    out: &mut BTreeSet<ObservedOperation>,
) -> Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if path.is_dir() {
            if matches!(name.as_ref(), "target" | "node_modules" | ".git" | "tests") {
                continue;
            }
            scan_source_dir(source, root, &path, out)?;
            continue;
        }
        if source_file_extension_allowed(&path) && source_file_should_be_scanned(source, &path) {
            scan_source_file(source, root, &path, out)?;
        }
    }
    Ok(())
}

fn source_file_extension_allowed(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|ext| ext.to_str()),
        Some("rs" | "ts" | "tsx" | "js" | "json")
    )
}

fn is_generated_or_test_file(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    name.ends_with("_tests.rs")
        || name.ends_with(".spec.ts")
        || name.ends_with("_test.rs")
        || name == "tests.rs"
}

/// Pure data files that embed a verbatim copy of the spec artifacts, NOT
/// implementation source. The SDK ships `embedded_artifacts.json` — a mirror of
/// the spec's `/_arkret/*` registries — which the path scanner would otherwise
/// read as if every mirrored path string were an operation the implementation
/// actually exposes (with a guessed HTTP method), producing spurious
/// unregistered-operation entries.
fn is_artifact_mirror_file(path: &Path) -> bool {
    matches!(
        path.file_name().and_then(|name| name.to_str()),
        Some("embedded_artifacts.json")
    )
}

fn source_file_should_be_scanned(source: &str, path: &Path) -> bool {
    if is_artifact_mirror_file(path) {
        return false;
    }
    source == "cotest" || !is_generated_or_test_file(path)
}

fn scan_source_file(
    source: &str,
    root: &Path,
    path: &Path,
    out: &mut BTreeSet<ObservedOperation>,
) -> Result<()> {
    let raw = fs::read_to_string(path).map_err(|error| {
        anyhow!(
            "failed to read operation source {}: {error}",
            path.display()
        )
    })?;
    let lines = raw.lines().collect::<Vec<_>>();
    let relative = path.strip_prefix(root).unwrap_or(path);

    scan_soland_extension_table(source, relative, &lines, out);

    for (index, line) in lines.iter().enumerate() {
        if is_comment_only_line(line) {
            continue;
        }
        let method = infer_method_near(&lines, index);
        for literal in extract_string_literals(line) {
            if !literal.contains("_arkret") {
                continue;
            }
            if !source_context_allows_literal(line, &lines, index, method.as_deref()) {
                continue;
            }
            for candidate in extract_path_candidates(&literal) {
                push_observed(source, relative, index + 1, method.clone(), candidate, out);
            }
        }
        for candidate in extract_regex_path_candidates(line) {
            if !source_context_allows_literal(line, &lines, index, method.as_deref()) {
                continue;
            }
            push_observed(source, relative, index + 1, method.clone(), candidate, out);
        }
    }

    Ok(())
}

fn is_comment_only_line(line: &str) -> bool {
    let line = line.trim_start();
    line.starts_with("//") || line.starts_with('*')
}

fn scan_soland_extension_table(
    source: &str,
    relative: &Path,
    lines: &[&str],
    out: &mut BTreeSet<ObservedOperation>,
) {
    if relative.file_name().and_then(|name| name.to_str()) != Some("openapi.rs") {
        return;
    }

    for (index, line) in lines.iter().enumerate() {
        if is_comment_only_line(line) {
            continue;
        }
        let literals = extract_string_literals(line);
        let Some(path) = literals
            .iter()
            .find_map(|literal| extract_path_candidates(literal).into_iter().next())
        else {
            continue;
        };
        let method = lines
            .iter()
            .skip(index + 1)
            .take(4)
            .find_map(|candidate| infer_path_item_type_method(candidate));
        if let Some(method) = method {
            push_observed(source, relative, index + 1, Some(method), path, out);
        }
    }
}

fn source_context_allows_literal(
    line: &str,
    lines: &[&str],
    index: usize,
    method: Option<&str>,
) -> bool {
    if method.is_some() {
        return true;
    }
    let context = nearby_context(lines, index, 3).to_ascii_lowercase();
    let line = line.to_ascii_lowercase();
    context.contains("endpoint(")
        || context.contains("post_json")
        || context.contains("get_json")
        || context.contains("put_json")
        || context.contains("delete_json")
        // Local TS wrapper helpers (`getJson(...)`, `postJson(...)`, ...) that
        // suites define around request.get/post. Without these the wrapper
        // context hides template-string paths from the scan entirely (the
        // CTS-CORR-01 false-negative channel).
        || context.contains("getjson(")
        || context.contains("postjson(")
        || context.contains("putjson(")
        || context.contains("deletejson(")
        || context.contains("path ===")
        || context.contains("pathname ===")
        || context.contains("pathname.match")
        || context.contains("page.route")
        || context.contains("waitforrequest")
        || context.contains("router::with_path")
        || line.contains("operationid")
}

fn nearby_context(lines: &[&str], index: usize, radius: usize) -> String {
    let start = index.saturating_sub(radius);
    let end = (index + radius + 1).min(lines.len());
    lines[start..end].join("\n")
}

fn infer_method_near(lines: &[&str], index: usize) -> Option<String> {
    if let Some(method) = infer_method_from_line(lines[index]) {
        return Some(method);
    }
    // Router-table style spread across lines:
    //   Router::with_path("/_arkret/...")
    //       .post(handler),
    // The verb binding sits on the line(s) immediately *after* the path. Prefer
    // the nearest following `.<verb>(` over the symmetric context window, which
    // would otherwise pick up a neighbouring route's verb earlier in the
    // `.push(...).push(...)` chain (INFERABLE_METHODS iteration order makes GET
    // win over POST when both appear in the window).
    for following in lines.iter().skip(index + 1).take(2) {
        if following.contains("with_path(") || following.contains("Router::") {
            break;
        }
        for method in INFERABLE_METHODS {
            if following
                .trim_start()
                .starts_with(&format!(".{}(", method.to_ascii_lowercase()))
            {
                return Some((*method).to_owned());
            }
        }
    }
    // A bare path-list element (a string literal that is the whole statement,
    // e.g. inside `for path in [ "/_arkret/...", ... ]`) carries no verb of its
    // own. Treating the verb as unknown lets the registry lookup match the path
    // template against whichever method the spec registers it under, instead of
    // borrowing an unrelated verb (a nearby `get_json(...openapi.json)` call)
    // from the surrounding context window.
    if is_bare_path_list_element(lines[index]) {
        return None;
    }
    let context = nearby_context(lines, index, 3);
    infer_method_from_context(&context)
}

/// True when the line is just a quoted string literal (optionally followed by a
/// comma), i.e. an element of a path/identifier list rather than part of an
/// HTTP call expression.
fn is_bare_path_list_element(line: &str) -> bool {
    let trimmed = line.trim();
    let trimmed = trimmed.strip_suffix(',').unwrap_or(trimmed).trim_end();
    let mut chars = trimmed.chars();
    let Some(open) = chars.next() else {
        return false;
    };
    if !matches!(open, '"' | '\'' | '`') {
        return false;
    }
    // The closing quote must be the final character and there must be no
    // intervening call syntax (parentheses) that would indicate a request.
    trimmed.ends_with(open) && trimmed.len() >= 2 && !trimmed.contains('(')
}

fn infer_method_from_line(line: &str) -> Option<String> {
    let arkret_index = line.find("_arkret")?;
    // Fetch-style calls carry the verb as an explicit property after the URL.
    // Read it from the same source line so a QUERY call cannot borrow GET/POST
    // from a neighboring array element, and neighboring calls cannot borrow
    // this QUERY declaration.
    for method in HTTP_METHODS {
        if line.contains(&format!("method: \"{method}\""))
            || line.contains(&format!("method: '{method}'"))
        {
            return Some((*method).to_owned());
        }
    }
    let prefix = &line[..arkret_index];
    for token in prefix.split(|ch: char| !ch.is_ascii_alphabetic()) {
        for method in INFERABLE_METHODS {
            if token == *method {
                return Some((*method).to_owned());
            }
        }
    }
    // Router-table style: the HTTP verb follows the path on the same line, e.g.
    // `Router::with_path("/_arkret/...").post(handler)`. The path literal sits
    // between the `with_path(` call and the `.<verb>(` binding, so the verb is
    // in the suffix rather than the prefix. Inferring it from the same line is
    // far more precise than the multi-line context fallback, which can latch
    // onto a neighbouring route's verb in a `.push(...).push(...)` chain.
    let suffix = &line[arkret_index..];
    for method in INFERABLE_METHODS {
        if suffix.contains(&format!(").{}(", method.to_ascii_lowercase())) {
            return Some((*method).to_owned());
        }
    }
    None
}

fn infer_method_from_context(context: &str) -> Option<String> {
    let context_lower = context.to_ascii_lowercase();
    for method in INFERABLE_METHODS {
        let lower = method.to_ascii_lowercase();
        if context.contains(&format!("Method::{method}"))
            || context.contains(&format!(
                "PathItemType::{method_title}",
                method_title = title_method(method)
            ))
            || context.contains(&format!(".{lower}("))
            || context.contains(&format!("{lower}_json"))
            // camelCase TS wrappers: getJson(/postJson(/... — matched
            // case-insensitively with the call paren so unrelated identifiers
            // do not bind a verb.
            || context_lower.contains(&format!("{lower}json("))
            || context.contains(&format!("method() === \"{method}\""))
            || context.contains(&format!("method === \"{method}\""))
            || context.contains(&format!("request.method() === \"{method}\""))
        {
            return Some((*method).to_owned());
        }
    }
    for method in INFERABLE_METHODS {
        if context.contains(&format!("{method} /_arkret"))
            || context.contains(&format!("{method} `_arkret"))
            || context.contains(&format!("{method} `/_arkret"))
        {
            return Some((*method).to_owned());
        }
    }
    None
}

fn infer_path_item_type_method(line: &str) -> Option<String> {
    for method in INFERABLE_METHODS {
        if line.contains(&format!("PathItemType::{}", title_method(method))) {
            return Some((*method).to_owned());
        }
    }
    None
}

fn title_method(method: &str) -> String {
    let mut chars = method.chars();
    let Some(first) = chars.next() else {
        return String::new();
    };
    let mut out = String::new();
    out.push(first);
    out.push_str(&chars.as_str().to_ascii_lowercase());
    out
}

fn extract_string_literals(line: &str) -> Vec<String> {
    let bytes = line.as_bytes();
    let mut literals = Vec::new();
    let mut i = 0usize;
    while i < bytes.len() {
        let quote = bytes[i];
        if !matches!(quote, b'"' | b'\'' | b'`') {
            i += 1;
            continue;
        }
        let start = i + 1;
        i = start;
        let mut literal = String::new();
        while i < bytes.len() {
            let byte = bytes[i];
            if byte == b'\\' && i + 1 < bytes.len() {
                let next = bytes[i + 1] as char;
                match next {
                    '/' | '"' | '\'' | '`' | '\\' => literal.push(next),
                    'n' => literal.push('\n'),
                    'r' => literal.push('\r'),
                    't' => literal.push('\t'),
                    _ => {
                        literal.push('\\');
                        literal.push(next);
                    }
                }
                i += 2;
                continue;
            }
            if byte == quote {
                break;
            }
            literal.push(byte as char);
            i += 1;
        }
        if i < bytes.len() && bytes[i] == quote {
            literals.push(literal);
            i += 1;
        }
    }
    literals
}

fn extract_regex_path_candidates(line: &str) -> Vec<String> {
    let Some(start) = line.find(r"\/_arkret\/") else {
        return Vec::new();
    };
    let tail = &line[start..];
    let mut raw = String::new();
    for ch in tail.chars() {
        if matches!(ch, '$' | '"' | '\'' | '`') {
            break;
        }
        raw.push(ch);
    }
    let normalized = raw
        .replace(r"\/", "/")
        .replace("([^/]+)", "{wildcard}")
        .replace(r"[^/]+", "{wildcard}")
        .replace("\\", "");
    expand_regex_alternatives(&normalized)
        .into_iter()
        .flat_map(|candidate| extract_path_candidates(&candidate))
        .collect()
}

fn expand_regex_alternatives(value: &str) -> Vec<String> {
    let Some((start, end, alternatives)) = find_simple_regex_alternation(value) else {
        return vec![value.to_owned()];
    };

    let mut out = Vec::new();
    for alternative in alternatives {
        let mut expanded = String::with_capacity(value.len());
        expanded.push_str(&value[..start]);
        expanded.push_str(alternative);
        expanded.push_str(&value[end + 1..]);
        out.extend(expand_regex_alternatives(&expanded));
    }
    out
}

fn find_simple_regex_alternation(value: &str) -> Option<(usize, usize, Vec<&str>)> {
    let bytes = value.as_bytes();
    let mut start = 0usize;
    while start < bytes.len() {
        if bytes[start] != b'(' {
            start += 1;
            continue;
        }
        let mut end = start + 1;
        while end < bytes.len() && bytes[end] != b')' {
            if bytes[end] == b'(' {
                break;
            }
            end += 1;
        }
        if end >= bytes.len() || bytes[end] != b')' {
            start += 1;
            continue;
        }
        let inner = &value[start + 1..end];
        if inner.contains('|')
            && inner
                .split('|')
                .all(|part| !part.is_empty() && part.chars().all(is_simple_regex_literal_char))
        {
            return Some((start, end, inner.split('|').collect()));
        }
        start = end + 1;
    }
    None
}

fn is_simple_regex_literal_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.')
}

fn extract_path_candidates(value: &str) -> Vec<String> {
    let collapsed = collapse_template_interpolations(value);
    let normalized = collapsed
        .replace("\\/", "/")
        .replace("\\?", "?")
        .replace("\\#", "#")
        .replace("**/", "")
        .replace("*", "{wildcard}");
    let mut out = Vec::new();
    let mut search_from = 0usize;
    while let Some(offset) = normalized[search_from..].find("_arkret") {
        let match_start = search_from + offset;
        let mut start = match_start;
        if start > 0 && normalized.as_bytes()[start - 1] == b'/' {
            start -= 1;
        } else {
            let prefix = &normalized[..start];
            if prefix.ends_with("http://")
                || prefix.ends_with("https://")
                || prefix.ends_with("://")
                || prefix.ends_with('/')
            {
                start = normalized[..start].rfind('/').unwrap_or(start);
            }
        }
        let candidate = trim_path_candidate(&normalized[start..]);
        if let Some(candidate) = normalize_observed_path(&candidate) {
            out.push(candidate);
        }
        search_from = match_start + "_arkret".len();
    }
    out
}

/// Collapse JavaScript/TypeScript template-literal interpolations (`${...}`)
/// into a single `{wildcard}` segment-token before path extraction.
///
/// Without this, an interpolation like
/// `/_arkret/self/keys/backups/${encodeURIComponent(id)}/unlock` would be cut
/// short at the `(` that `trim_path_candidate` treats as a terminator, dropping
/// the `/unlock` tail and producing a spurious `/_arkret/self/keys/backups/{wildcard}`
/// observation that never matches the registered `.../unlock` operation. By
/// folding the full `${...}` expression (balanced across one nested paren level)
/// into `{wildcard}` first, the trailing path segments survive and the real
/// operation template is recovered.
fn collapse_template_interpolations(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = String::with_capacity(value.len());
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'$' && i + 1 < bytes.len() && bytes[i + 1] == b'{' {
            let mut depth = 0usize;
            let mut j = i + 1;
            while j < bytes.len() {
                match bytes[j] {
                    b'{' => depth += 1,
                    b'}' => {
                        depth -= 1;
                        if depth == 0 {
                            break;
                        }
                    }
                    _ => {}
                }
                j += 1;
            }
            if j < bytes.len() && depth == 0 {
                out.push_str("{wildcard}");
                i = j + 1;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

fn trim_path_candidate(candidate: &str) -> String {
    let mut end = candidate.len();
    for (idx, ch) in candidate.char_indices() {
        if ch.is_whitespace() || matches!(ch, '"' | '\'' | '`' | ',' | ')' | ']' | ';') {
            end = idx;
            break;
        }
    }
    candidate[..end]
        .trim_matches(|ch: char| matches!(ch, '.' | ':' | ','))
        .to_owned()
}

fn normalize_observed_path(candidate: &str) -> Option<String> {
    let mut candidate = candidate.trim();
    if let Some(rest) = candidate.strip_prefix("http://") {
        candidate = rest.find('/').map(|idx| &rest[idx..]).unwrap_or("");
    } else if let Some(rest) = candidate.strip_prefix("https://") {
        candidate = rest.find('/').map(|idx| &rest[idx..]).unwrap_or("");
    }
    let mut path = if candidate.starts_with("/_arkret") {
        candidate.to_owned()
    } else if candidate.starts_with("_arkret") {
        format!("/{candidate}")
    } else {
        return None;
    };

    if let Some((before, _)) = path.split_once('?') {
        path = before.to_owned();
    }
    if let Some((before, _)) = path.split_once('#') {
        path = before.to_owned();
    }
    path = path.trim_end_matches('/').to_owned();
    if path == "/_arkret" || path == "/_arkret/" {
        return None;
    }
    if !path.starts_with("/_arkret/") {
        return None;
    }
    Some(normalize_path_template(&path))
}

fn push_observed(
    source: &str,
    relative: &Path,
    line: usize,
    method: Option<String>,
    path: String,
    out: &mut BTreeSet<ObservedOperation>,
) {
    out.insert(ObservedOperation {
        source: source.to_owned(),
        method,
        path,
        evidence: format!("{}:{line}", relative.display()),
    });
}

fn parse_http_binding(http: &str) -> Result<OperationKey> {
    let mut parts = http.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| anyhow!("http binding missing method"))?;
    let path = parts
        .next()
        .ok_or_else(|| anyhow!("http binding missing path"))?;
    if parts.next().is_some() {
        bail!("http binding has extra fields: {http}");
    }
    let method = method.to_ascii_uppercase();
    if !HTTP_METHODS.contains(&method.as_str()) {
        bail!("http binding has unsupported method {method}");
    }
    if !path.starts_with("/_arkret/") && path != "/_arkret/describe" {
        bail!("http binding path must stay under /_arkret/*: {path}");
    }
    Ok(OperationKey::new(method, path))
}

fn normalize_path_template(path: &str) -> String {
    let mut normalized = path.replace('\\', "/");
    while normalized.contains("//") {
        normalized = normalized.replace("//", "/");
    }
    let mut segments = Vec::new();
    for segment in normalized.trim_end_matches('/').split('/') {
        if segment.is_empty() {
            continue;
        }
        let segment = if segment == "{}"
            || segment == "{wildcard}"
            || segment.starts_with('{')
            || segment.starts_with(':')
            || segment.starts_with("<")
            || segment.contains("[^/]+")
            || segment.contains("${")
        {
            normalize_dynamic_segment(segment)
        } else {
            segment.to_owned()
        };
        segments.push(segment);
    }
    format!("/{}", segments.join("/"))
}

fn normalize_dynamic_segment(segment: &str) -> String {
    if segment == "{**rest}" {
        return "{**rest}".to_owned();
    }
    if segment.starts_with('{') && segment.ends_with('}') {
        return segment.to_owned();
    }
    "{wildcard}".to_owned()
}

fn pattern_matches_path(pattern: &str, path: &str) -> bool {
    let pattern_parts = pattern.trim_matches('/').split('/').collect::<Vec<_>>();
    let path_parts = path.trim_matches('/').split('/').collect::<Vec<_>>();
    let mut pattern_index = 0usize;
    let mut path_index = 0usize;
    while pattern_index < pattern_parts.len() && path_index < path_parts.len() {
        let pattern_part = pattern_parts[pattern_index];
        let path_part = path_parts[path_index];
        if pattern_part == "{**rest}" {
            return true;
        }
        if is_dynamic_segment(pattern_part) || is_dynamic_segment(path_part) {
            if path_part.is_empty() {
                return false;
            }
        } else if pattern_part != path_part {
            return false;
        }
        pattern_index += 1;
        path_index += 1;
    }
    pattern_index == pattern_parts.len() && path_index == path_parts.len()
}

fn is_dynamic_segment(segment: &str) -> bool {
    (segment.starts_with('{') && segment.ends_with('}'))
        || segment.starts_with(':')
        || segment.starts_with('<')
        || segment.contains("[^/]+")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_rust_format_paths() {
        let line = r#"self.get_json(&format!("_arkret/self/agents/{agent_id}"))"#;
        let literals = extract_string_literals(line);
        let paths = extract_path_candidates(&literals[0]);
        assert_eq!(paths, vec!["/_arkret/self/agents/{agent_id}"]);
    }

    #[test]
    fn regex_path_normalizes_to_placeholder() {
        let line = r#"url.pathname.match(/^\/_arkret\/open\/mimi\/strands\/[^/]+\/update$/)"#;
        let paths = extract_regex_path_candidates(line);
        assert_eq!(paths, vec!["/_arkret/open/mimi/strands/{wildcard}/update"]);
    }

    #[test]
    fn regex_capture_group_path_preserves_tail_segments() {
        let line = r#"url.pathname.match(/^\/_arkret\/self\/agents\/([^/]+)\/grants$/)"#;
        let paths = extract_regex_path_candidates(line);
        assert_eq!(paths, vec!["/_arkret/self/agents/{wildcard}/grants"]);
    }

    #[test]
    fn regex_alternative_group_expands_to_literal_paths() {
        let line =
            r#"url.pathname.match(/^\/_arkret\/self\/circles\/([^/]+)\/(archive|restore)$/)"#;
        let paths = extract_regex_path_candidates(line);
        assert_eq!(
            paths,
            vec![
                "/_arkret/self/circles/{wildcard}/archive",
                "/_arkret/self/circles/{wildcard}/restore",
            ]
        );
    }

    #[test]
    fn extracts_absolute_paths_without_looping() {
        let paths = extract_path_candidates("/_arkret/describe");
        assert_eq!(paths, vec!["/_arkret/describe"]);
    }

    #[test]
    fn infers_method_from_aligned_surface_line() {
        let method = infer_method_from_line("surface GET    /_arkret/self/account/subscribe")
            .expect("aligned method should parse");
        assert_eq!(method, "GET");
    }

    #[test]
    fn explicit_fetch_query_method_wins_over_neighboring_get_calls() {
        let line = r#"response: await request.fetch(`${base}/_arkret/self/events`, { method: "QUERY", data: { limit: 20 } })"#;
        assert_eq!(infer_method_from_line(line).as_deref(), Some("QUERY"));
    }

    #[test]
    fn placeholders_match_registry_patterns() {
        assert!(pattern_matches_path(
            "/_arkret/self/keys/backups/{backup_id}",
            "/_arkret/self/keys/backups/{wildcard}"
        ));
        assert!(pattern_matches_path(
            "/_arkret/open/mimi/strands/{strand_id}/messages",
            "/_arkret/open/mimi/strands/{room_id}/messages"
        ));
    }
}
