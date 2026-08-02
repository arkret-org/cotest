use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use serde::Deserialize;

const FIXTURE: &str = "protocol-journey-coverage.json";
const SCHEMA: &str = "cotest.protocol_journey_coverage.v1";
const STATUSES: &[&str] = &["existing", "partial", "missing"];
const TEST_LAYERS: &[&str] = &[
    "rust_black_box",
    "playwright_joint_e2e",
    "conformance_fixture",
];
const AGENT_JOURNEY_ROLES: &[&str] = &["supplemental_ux", "not_applicable"];

#[derive(Debug, Deserialize)]
struct Matrix {
    schema: String,
    id_namespace: String,
    journeys: Vec<Journey>,
}

#[derive(Debug, Deserialize)]
struct Journey {
    protocol_journey_id: String,
    request_id: String,
    title: String,
    status: String,
    primary_layer: String,
    agent_journey_role: String,
    stages: Vec<String>,
    evidence: Vec<Evidence>,
    gaps: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct Evidence {
    layer: String,
    path: String,
    markers: Vec<String>,
}

#[test]
fn pj01_through_pj18_have_fail_closed_coverage_accounting() -> Result<()> {
    let matrix = load_matrix()?;
    if matrix.schema != SCHEMA {
        bail!("{FIXTURE} schema drifted: {}", matrix.schema);
    }
    if !matrix
        .id_namespace
        .contains("agent-journeys checkpoint ids")
    {
        bail!("{FIXTURE} must disambiguate protocol ids from Agent Journey checkpoints");
    }
    if matrix.journeys.len() != 18 {
        bail!("{FIXTURE} must contain exactly PJ01-PJ18");
    }

    let mut protocol_ids = BTreeSet::new();
    let mut request_ids = BTreeSet::new();
    for journey in &matrix.journeys {
        validate_journey(journey)?;
        if !protocol_ids.insert(journey.protocol_journey_id.clone()) {
            bail!(
                "duplicate protocol journey id {}",
                journey.protocol_journey_id
            );
        }
        if !request_ids.insert(journey.request_id.clone()) {
            bail!("duplicate request journey id {}", journey.request_id);
        }
    }

    let expected_protocol = (1..=18)
        .map(|n| format!("PJ{n:02}"))
        .collect::<BTreeSet<_>>();
    let expected_request = (1..=18)
        .map(|n| format!("J{n:02}"))
        .collect::<BTreeSet<_>>();
    if protocol_ids != expected_protocol {
        bail!("protocol journey ids must be exactly PJ01-PJ18: {protocol_ids:?}");
    }
    if request_ids != expected_request {
        bail!("request journey ids must be exactly J01-J18: {request_ids:?}");
    }
    Ok(())
}

#[test]
fn known_latest_protocol_drifts_cannot_be_reported_green() -> Result<()> {
    let matrix = load_matrix()?;
    let by_id = matrix
        .journeys
        .iter()
        .map(|journey| (journey.protocol_journey_id.as_str(), journey))
        .collect::<BTreeMap<_, _>>();

    assert_blocked_while_marker_exists(
        &by_id,
        "PJ09",
        "tests/fixtures/kernel-joint-gate.json",
        "membership_and_mls_commit_are_atomic",
        "原子化",
    )?;
    assert_blocked_while_marker_exists(
        &by_id,
        "PJ15",
        "e2e/helpers/soland-api.ts",
        "const leaseResponse = await issueAuthorizationLeasesApi",
        "online",
    )?;
    assert_blocked_while_marker_exists(
        &by_id,
        "PJ16",
        "tests/agent_provision_e2e.rs",
        "build_agent_provision_event_drafts",
        "closed Event pair",
    )?;
    Ok(())
}

fn load_matrix() -> Result<Matrix> {
    let path = cotest_root().join("tests").join("fixtures").join(FIXTURE);
    serde_json::from_str(
        &fs::read_to_string(&path).with_context(|| format!("failed to read {}", path.display()))?,
    )
    .with_context(|| format!("failed to decode {}", path.display()))
}

fn validate_journey(journey: &Journey) -> Result<()> {
    let id = &journey.protocol_journey_id;
    if journey.title.trim().is_empty() || journey.stages.is_empty() {
        bail!("{id} must declare a title and at least one stage");
    }
    if !STATUSES.contains(&journey.status.as_str()) {
        bail!("{id} has unsupported status {}", journey.status);
    }
    if !TEST_LAYERS.contains(&journey.primary_layer.as_str()) {
        bail!(
            "{id} has unsupported deterministic primary layer {}",
            journey.primary_layer
        );
    }
    if !AGENT_JOURNEY_ROLES.contains(&journey.agent_journey_role.as_str()) {
        bail!(
            "{id} has unsupported agent_journey_role {}",
            journey.agent_journey_role
        );
    }
    if journey.evidence.is_empty() {
        bail!("{id} must retain component evidence even when its vertical journey is missing");
    }
    if journey.status == "existing" && !journey.gaps.is_empty() {
        bail!("{id} is existing but still declares gaps");
    }
    if journey.status != "existing" && journey.gaps.is_empty() {
        bail!(
            "{id} is {} but does not declare blocking gaps",
            journey.status
        );
    }

    let mut stages = BTreeSet::new();
    for stage in &journey.stages {
        if stage.trim().is_empty() || !stages.insert(stage) {
            bail!("{id} has an empty or duplicate stage {stage:?}");
        }
    }
    for evidence in &journey.evidence {
        validate_evidence(id, evidence)?;
    }
    Ok(())
}

fn validate_evidence(journey_id: &str, evidence: &Evidence) -> Result<()> {
    if !TEST_LAYERS.contains(&evidence.layer.as_str()) {
        bail!(
            "{journey_id} evidence {} has unsupported layer {}",
            evidence.path,
            evidence.layer
        );
    }
    if evidence.markers.is_empty() {
        bail!(
            "{journey_id} evidence {} must declare markers",
            evidence.path
        );
    }
    let path = cotest_root().join(&evidence.path);
    let source = fs::read_to_string(&path)
        .with_context(|| format!("{journey_id} cannot read evidence {}", path.display()))?;
    for marker in &evidence.markers {
        if !source.contains(marker) {
            bail!(
                "{journey_id} evidence {} lacks marker {marker:?}",
                path.display()
            );
        }
    }
    Ok(())
}

fn assert_blocked_while_marker_exists(
    by_id: &BTreeMap<&str, &Journey>,
    journey_id: &str,
    relative_path: &str,
    stale_marker: &str,
    required_gap_marker: &str,
) -> Result<()> {
    let path = cotest_root().join(relative_path);
    let source = fs::read_to_string(&path)
        .with_context(|| format!("cannot inspect drift guard {}", path.display()))?;
    if !source.contains(stale_marker) {
        return Ok(());
    }
    let journey = by_id
        .get(journey_id)
        .with_context(|| format!("missing drift-guarded journey {journey_id}"))?;
    if journey.status == "existing" {
        bail!(
            "{journey_id} cannot be existing while {relative_path} still contains {stale_marker:?}"
        );
    }
    if !journey
        .gaps
        .iter()
        .any(|gap| gap.contains(required_gap_marker))
    {
        bail!("{journey_id} must name the live drift in {relative_path}");
    }
    Ok(())
}

fn cotest_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}
