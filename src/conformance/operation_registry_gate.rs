use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Result, anyhow, bail};
use serde::Deserialize;
use serde_json::Value;

use super::spec_artifacts_root;

const OPERATION_REGISTRY_REF: &str = "registry/operation-registry.json";
const OPENAPI_REF: &str = "openapi/cokret-service-api.openapi.yaml";
const OPERATION_COMPLETENESS_REF: &str = "reports/operation-completeness-report.json";
const OPERATION_SCHEMA_INDEX_REF: &str = "reports/operation-schema-index.json";
const PRODUCT_PRIVATE_REF: &str = "operation-product-private-paths.json";

const HTTP_METHODS: &[&str] = &["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"];
const OPENAPI_METHODS: &[(&str, &str)] = &[
    ("get", "GET"),
    ("head", "HEAD"),
    ("post", "POST"),
    ("put", "PUT"),
    ("patch", "PATCH"),
    ("delete", "DELETE"),
    ("options", "OPTIONS"),
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
                .with_dir("crates/server/src/routing")
                .with_file("crates/server/src/wire.rs")
                .with_file("crates/server/src/did_resolver_chain.rs"),
            OperationSourceRoot::new("sdk", workspace_root.join("cokret-rust-sdk"))
                .with_file("crates/server/src/registry.rs")
                .with_file("crates/core/src/http/paths.rs")
                .with_file("crates/core/src/principal.rs")
                .with_file("crates/core/src/push.rs")
                .with_file("crates/core/src/service.rs")
                .with_file("crates/http-client/src/endpoints_account.rs")
                .with_file("crates/http-client/src/endpoints_data.rs")
                .with_file("crates/http-client/src/endpoints_events.rs")
                .with_file("crates/http-client/src/endpoints_identity.rs")
                .with_file("crates/http-client/src/endpoints_misc.rs"),
            OperationSourceRoot::new("yougen", workspace_root.join("yougen"))
                .with_dir("src/api")
                .with_file("tests/e2e/mockCokretApi.ts")
                .with_file("tests/e2e/mockCokretContract.ts"),
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
        });
    }
    Ok(operations)
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
        if !path.starts_with("/_cokret") {
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
        if !entry.path.starts_with("/_cokret/") {
            failures.push(format!(
                "{} {} product-private path must stay under /_cokret/*",
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
            "unregistered /_cokret/* path is not explicitly classified as product-private"
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
        if source_file_extension_allowed(&path) && !is_generated_or_test_file(&path) {
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
            if !literal.contains("_cokret") {
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
    let context = nearby_context(lines, index, 3);
    infer_method_from_context(&context)
}

fn infer_method_from_line(line: &str) -> Option<String> {
    let cokret_index = line.find("_cokret")?;
    let prefix = &line[..cokret_index];
    for token in prefix.split(|ch: char| !ch.is_ascii_alphabetic()) {
        for method in HTTP_METHODS {
            if token == *method {
                return Some((*method).to_owned());
            }
        }
    }
    None
}

fn infer_method_from_context(context: &str) -> Option<String> {
    for method in HTTP_METHODS {
        let lower = method.to_ascii_lowercase();
        if context.contains(&format!("Method::{method}"))
            || context.contains(&format!(
                "PathItemType::{method_title}",
                method_title = title_method(method)
            ))
            || context.contains(&format!(".{lower}("))
            || context.contains(&format!("{lower}_json"))
            || context.contains(&format!("method() === \"{method}\""))
            || context.contains(&format!("method === \"{method}\""))
            || context.contains(&format!("request.method() === \"{method}\""))
        {
            return Some((*method).to_owned());
        }
    }
    for method in HTTP_METHODS {
        if context.contains(&format!("{method} /_cokret"))
            || context.contains(&format!("{method} `_cokret"))
            || context.contains(&format!("{method} `/_cokret"))
        {
            return Some((*method).to_owned());
        }
    }
    None
}

fn infer_path_item_type_method(line: &str) -> Option<String> {
    for method in HTTP_METHODS {
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
    let Some(start) = line.find(r"\/_cokret\/") else {
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
        .replace(r"[^/]+", "{wildcard}")
        .replace("\\", "");
    extract_path_candidates(&normalized)
}

fn extract_path_candidates(value: &str) -> Vec<String> {
    let normalized = value
        .replace("\\/", "/")
        .replace("\\?", "?")
        .replace("\\#", "#")
        .replace("**/", "")
        .replace("*", "{wildcard}");
    let mut out = Vec::new();
    let mut search_from = 0usize;
    while let Some(offset) = normalized[search_from..].find("_cokret") {
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
        search_from = match_start + "_cokret".len();
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
    let mut path = if candidate.starts_with("/_cokret") {
        candidate.to_owned()
    } else if candidate.starts_with("_cokret") {
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
    if path == "/_cokret" || path == "/_cokret/" {
        return None;
    }
    if !path.starts_with("/_cokret/") {
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
    if !path.starts_with("/_cokret/") && path != "/_cokret/describe" {
        bail!("http binding path must stay under /_cokret/*: {path}");
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
        let line = r#"self.get_json(&format!("_cokret/self/agents/{agent_principal_id}"))"#;
        let literals = extract_string_literals(line);
        let paths = extract_path_candidates(&literals[0]);
        assert_eq!(paths, vec!["/_cokret/self/agents/{agent_principal_id}"]);
    }

    #[test]
    fn regex_path_normalizes_to_placeholder() {
        let line = r#"url.pathname.match(/^\/_cokret\/open\/mimi\/strands\/[^/]+\/update$/)"#;
        let paths = extract_regex_path_candidates(line);
        assert_eq!(paths, vec!["/_cokret/open/mimi/strands/{wildcard}/update"]);
    }

    #[test]
    fn extracts_absolute_paths_without_looping() {
        let paths = extract_path_candidates("/_cokret/describe");
        assert_eq!(paths, vec!["/_cokret/describe"]);
    }

    #[test]
    fn infers_method_from_aligned_surface_line() {
        let method = infer_method_from_line("surface GET    /_cokret/self/account/subscribe")
            .expect("aligned method should parse");
        assert_eq!(method, "GET");
    }

    #[test]
    fn placeholders_match_registry_patterns() {
        assert!(pattern_matches_path(
            "/_cokret/self/keys/backups/{backup_id}",
            "/_cokret/self/keys/backups/{wildcard}"
        ));
        assert!(pattern_matches_path(
            "/_cokret/open/mimi/strands/{strand_id}/messages",
            "/_cokret/open/mimi/strands/{room_id}/messages"
        ));
        assert!(!pattern_matches_path(
            "/_cokret/self/events",
            "/_cokret/self/events/query"
        ));
    }
}
