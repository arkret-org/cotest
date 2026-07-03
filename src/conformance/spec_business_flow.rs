use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Result, anyhow, bail};
use serde::Deserialize;

use super::{load_artifact_json, load_local_fixture_value};

const FIXTURE: &str = "spec-business-flow-coverage.json";
const SCHEMA: &str = "cotest.spec_business_flow_coverage.v1";
const OPERATION_REGISTRY_REF: &str = "registry/operation-registry.json";

const COVERAGE_KINDS: &[&str] = &["ordinary", "joint_e2e", "conformance_fixture", "gap_guard"];
const FLOW_STATUSES: &[&str] = &["implemented", "partially_implemented", "guarded_optional"];

#[derive(Debug, Deserialize)]
struct BusinessFlowFixture {
    schema: String,
    operation_registry_ref: String,
    flows: Vec<BusinessFlow>,
}

#[derive(Debug, Deserialize)]
struct BusinessFlow {
    id: String,
    title: String,
    surfaces: Vec<String>,
    operation_spine: Vec<FlowOperation>,
    coverage: Vec<CoverageEvidence>,
    status: String,
}

#[derive(Debug, Deserialize)]
struct FlowOperation {
    operation_id: String,
    surfaces: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct CoverageEvidence {
    kind: String,
    path: String,
    #[serde(default)]
    markers: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct OperationRegistry {
    surface_groups: Vec<SurfaceGroup>,
    operations: Vec<RegistryOperation>,
}

#[derive(Debug, Deserialize)]
struct SurfaceGroup {
    surface: String,
    operations: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RegistryOperation {
    operation_id: String,
}

pub fn run_spec_business_flow_coverage_suite() -> Result<()> {
    let fixture: BusinessFlowFixture =
        serde_json::from_value(load_local_fixture_value(FIXTURE)?)
            .map_err(|error| anyhow!("failed to parse {FIXTURE}: {error}"))?;
    validate_fixture_header(&fixture)?;

    let registry: OperationRegistry =
        serde_json::from_value(load_artifact_json(OPERATION_REGISTRY_REF)?)
            .map_err(|error| anyhow!("failed to parse {OPERATION_REGISTRY_REF}: {error}"))?;
    let registry_index = RegistryIndex::new(registry)?;
    validate_flows(&fixture.flows, &registry_index, &cotest_root())
}

fn validate_fixture_header(fixture: &BusinessFlowFixture) -> Result<()> {
    if fixture.schema != SCHEMA {
        bail!(
            "{FIXTURE} schema drifted: expected {SCHEMA}, got {}",
            fixture.schema
        );
    }
    if fixture.operation_registry_ref != OPERATION_REGISTRY_REF {
        bail!(
            "{FIXTURE} operation_registry_ref must be {OPERATION_REGISTRY_REF}, got {}",
            fixture.operation_registry_ref
        );
    }
    if fixture.flows.is_empty() {
        bail!("{FIXTURE} must declare at least one business flow");
    }
    Ok(())
}

#[derive(Debug)]
struct RegistryIndex {
    surfaces: BTreeSet<String>,
    operations: BTreeSet<String>,
    operation_surfaces: BTreeMap<String, BTreeSet<String>>,
}

impl RegistryIndex {
    fn new(registry: OperationRegistry) -> Result<Self> {
        let operations = registry
            .operations
            .into_iter()
            .map(|operation| operation.operation_id)
            .collect::<BTreeSet<_>>();
        let mut surfaces = BTreeSet::new();
        let mut operation_surfaces: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for group in registry.surface_groups {
            if !surfaces.insert(group.surface.clone()) {
                bail!(
                    "{OPERATION_REGISTRY_REF} contains duplicate surface {}",
                    group.surface
                );
            }
            if group.operations.is_empty() {
                bail!(
                    "{OPERATION_REGISTRY_REF} surface {} has no operations",
                    group.surface
                );
            }
            for operation_id in group.operations {
                if !operations.contains(&operation_id) {
                    bail!(
                        "{OPERATION_REGISTRY_REF} surface {} references unknown operation {}",
                        group.surface,
                        operation_id
                    );
                }
                operation_surfaces
                    .entry(operation_id)
                    .or_default()
                    .insert(group.surface.clone());
            }
        }
        Ok(Self {
            surfaces,
            operations,
            operation_surfaces,
        })
    }
}

fn validate_flows(
    flows: &[BusinessFlow],
    registry: &RegistryIndex,
    cotest_root: &Path,
) -> Result<()> {
    let mut failures = Vec::new();
    let mut flow_ids = BTreeSet::new();
    let mut assigned_surfaces = BTreeSet::new();

    for flow in flows {
        if !flow_ids.insert(flow.id.as_str()) {
            failures.push(format!("duplicate flow id {}", flow.id));
            continue;
        }
        validate_flow_shape(flow, &mut failures);
        validate_flow_surfaces(flow, registry, &mut assigned_surfaces, &mut failures);
        validate_flow_operations(flow, registry, &mut failures);
        validate_flow_coverage(flow, cotest_root, &mut failures);
    }

    for surface in registry.surfaces.difference(&assigned_surfaces) {
        failures.push(format!(
            "registry surface {surface} is not assigned to any business flow"
        ));
    }

    if failures.is_empty() {
        Ok(())
    } else {
        bail!(
            "spec business flow coverage found {} failing entries:\n{}",
            failures.len(),
            failures.join("\n")
        )
    }
}

fn validate_flow_shape(flow: &BusinessFlow, failures: &mut Vec<String>) {
    if flow.id.trim().is_empty() {
        failures.push("flow id must not be empty".to_owned());
    }
    if flow.title.trim().is_empty() {
        failures.push(format!("{} must declare a title", flow.id));
    }
    if flow.surfaces.is_empty() {
        failures.push(format!("{} must declare surfaces[]", flow.id));
    }
    if flow.operation_spine.is_empty() {
        failures.push(format!(
            "{} must declare representative operation_spine[]",
            flow.id
        ));
    }
    if flow.coverage.is_empty() {
        failures.push(format!("{} must declare coverage[]", flow.id));
    }
    if !FLOW_STATUSES.contains(&flow.status.as_str()) {
        failures.push(format!(
            "{} has unsupported status {}; allowed={FLOW_STATUSES:?}",
            flow.id, flow.status
        ));
    }
}

fn validate_flow_surfaces(
    flow: &BusinessFlow,
    registry: &RegistryIndex,
    assigned_surfaces: &mut BTreeSet<String>,
    failures: &mut Vec<String>,
) {
    let mut local = BTreeSet::new();
    for surface in &flow.surfaces {
        if !local.insert(surface.as_str()) {
            failures.push(format!("{} repeats surface {}", flow.id, surface));
        }
        if !registry.surfaces.contains(surface) {
            failures.push(format!(
                "{} references unknown registry surface {}",
                flow.id, surface
            ));
        } else {
            assigned_surfaces.insert(surface.clone());
        }
    }
}

fn validate_flow_operations(
    flow: &BusinessFlow,
    registry: &RegistryIndex,
    failures: &mut Vec<String>,
) {
    let surfaces = flow
        .surfaces
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let mut operations = BTreeSet::new();
    for step in &flow.operation_spine {
        if step.surfaces.is_empty() {
            failures.push(format!(
                "{} operation {} must declare surfaces[]",
                flow.id, step.operation_id
            ));
        }
        if !operations.insert(step.operation_id.as_str()) {
            failures.push(format!(
                "{} repeats operation {}",
                flow.id, step.operation_id
            ));
        }
        if !registry.operations.contains(&step.operation_id) {
            failures.push(format!(
                "{} references unknown operation {}",
                flow.id, step.operation_id
            ));
            continue;
        }
        let Some(registry_surfaces) = registry.operation_surfaces.get(&step.operation_id) else {
            failures.push(format!(
                "{} operation {} is not assigned to a registry surface",
                flow.id, step.operation_id
            ));
            continue;
        };
        for surface in &step.surfaces {
            if !surfaces.contains(surface.as_str()) {
                failures.push(format!(
                    "{} operation {} declares surface {}, which is not listed in this flow",
                    flow.id, step.operation_id, surface
                ));
            }
            if !registry_surfaces.contains(surface) {
                failures.push(format!(
                    "{} operation {} declares surface {}, but registry assigns it to {:?}",
                    flow.id, step.operation_id, surface, registry_surfaces
                ));
            }
        }
    }
}

fn validate_flow_coverage(flow: &BusinessFlow, cotest_root: &Path, failures: &mut Vec<String>) {
    let mut kinds = BTreeSet::new();
    for evidence in &flow.coverage {
        if !COVERAGE_KINDS.contains(&evidence.kind.as_str()) {
            failures.push(format!(
                "{} coverage path {} has unsupported kind {}",
                flow.id, evidence.path, evidence.kind
            ));
        }
        kinds.insert(evidence.kind.as_str());
        validate_evidence_file(flow, evidence, cotest_root, failures);
    }

    if flow.status == "implemented" {
        for required_kind in ["ordinary", "joint_e2e"] {
            if !kinds.contains(required_kind) {
                failures.push(format!(
                    "{} is implemented but lacks {required_kind} coverage evidence",
                    flow.id
                ));
            }
        }
    }
    if flow.status == "guarded_optional" && !kinds.contains("gap_guard") {
        failures.push(format!(
            "{} is guarded_optional but lacks gap_guard evidence",
            flow.id
        ));
    }
}

fn validate_evidence_file(
    flow: &BusinessFlow,
    evidence: &CoverageEvidence,
    cotest_root: &Path,
    failures: &mut Vec<String>,
) {
    let path = normalize_evidence_path(cotest_root, &evidence.path);
    let source = match fs::read_to_string(&path) {
        Ok(source) => source,
        Err(error) => {
            failures.push(format!(
                "{} coverage file {} cannot be read: {error}",
                flow.id,
                path.display()
            ));
            return;
        }
    };
    for needle in &evidence.markers {
        if !source.contains(needle) {
            failures.push(format!(
                "{} coverage file {} does not contain required marker {:?}",
                flow.id,
                path.display(),
                needle
            ));
        }
    }
}

fn normalize_evidence_path(cotest_root: &Path, path: &str) -> PathBuf {
    let path = PathBuf::from(path);
    if path.is_absolute() {
        path
    } else {
        cotest_root.join(path)
    }
}

fn cotest_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}
