use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Result, anyhow, bail};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::{looks_like_sha256_digest, spec_artifacts_root};

const VECTOR_REGISTRY_REF: &str = "registry/vector-registry.json";
const FIXTURE_DIGESTS_REF: &str = "reports/fixture-digests.json";
const ARTIFACT_FIXTURE_PREFIX: &str = "spec/v1/artifacts/fixtures/";
const ARTIFACT_REF_PREFIX: &str = "spec/v1/artifacts/";
const STRICT_GATE_ENV: &str = "COTEST_VECTOR_REGISTRY_GATE_STRICT";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VectorRegistryGateMode {
    Lenient,
    Strict,
}

impl VectorRegistryGateMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Lenient => "lenient",
            Self::Strict => "strict",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VectorRegistryGateStatus {
    FixtureBacked,
    ActiveDocOnly,
    Reserved,
    Unsupported,
    Failed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VectorRegistryGateEntry {
    pub vector_id: String,
    pub registry_status: String,
    pub gate_status: VectorRegistryGateStatus,
    pub fixture_refs: Vec<String>,
    pub evidence_refs: Vec<String>,
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VectorRegistryGateReport {
    pub entries: Vec<VectorRegistryGateEntry>,
}

impl VectorRegistryGateReport {
    pub fn failed_entries(&self) -> impl Iterator<Item = &VectorRegistryGateEntry> {
        self.entries
            .iter()
            .filter(|entry| entry.gate_status == VectorRegistryGateStatus::Failed)
    }

    pub fn validation_failed_entries(
        &self,
        mode: VectorRegistryGateMode,
    ) -> impl Iterator<Item = &VectorRegistryGateEntry> {
        self.entries.iter().filter(move |entry| {
            entry.gate_status == VectorRegistryGateStatus::Failed
                || (mode == VectorRegistryGateMode::Strict
                    && entry.gate_status == VectorRegistryGateStatus::ActiveDocOnly)
        })
    }

    pub fn fixture_backed_entries(&self) -> impl Iterator<Item = &VectorRegistryGateEntry> {
        self.entries
            .iter()
            .filter(|entry| entry.gate_status == VectorRegistryGateStatus::FixtureBacked)
    }

    pub fn active_doc_only_entries(&self) -> impl Iterator<Item = &VectorRegistryGateEntry> {
        self.entries
            .iter()
            .filter(|entry| entry.gate_status == VectorRegistryGateStatus::ActiveDocOnly)
    }

    pub fn gated_entries(&self) -> impl Iterator<Item = &VectorRegistryGateEntry> {
        self.fixture_backed_entries()
    }

    pub fn non_gating_entries(&self) -> impl Iterator<Item = &VectorRegistryGateEntry> {
        self.entries.iter().filter(|entry| {
            matches!(
                entry.gate_status,
                VectorRegistryGateStatus::ActiveDocOnly
                    | VectorRegistryGateStatus::Reserved
                    | VectorRegistryGateStatus::Unsupported
            )
        })
    }
}

#[derive(Debug, Deserialize)]
struct VectorRegistry {
    vectors: Vec<VectorRegistryRow>,
}

#[derive(Debug, Deserialize)]
struct VectorRegistryRow {
    vector_id: String,
    status: String,
    #[serde(default)]
    source_refs: Vec<String>,
    description: Option<String>,
}

#[derive(Debug, Deserialize)]
struct FixtureDigestReport {
    files: Vec<FixtureDigestEntry>,
}

#[derive(Debug, Deserialize)]
struct FixtureDigestEntry {
    path: String,
    sha256: String,
}

#[derive(Clone, Debug, Default)]
struct FixtureDigestIndex {
    missing_report: bool,
    hashes: BTreeMap<String, String>,
}

pub fn build_vector_registry_gate_report() -> Result<VectorRegistryGateReport> {
    let artifacts_root = spec_artifacts_root();
    build_vector_registry_gate_report_from_paths(
        &artifacts_root.join(VECTOR_REGISTRY_REF),
        &artifacts_root,
    )
}

pub fn validate_vector_registry_gate() -> Result<VectorRegistryGateReport> {
    let report = build_vector_registry_gate_report()?;
    validate_vector_registry_gate_report(&report)?;
    Ok(report)
}

pub fn validate_vector_registry_gate_report(report: &VectorRegistryGateReport) -> Result<()> {
    let mode = vector_registry_gate_mode_from_env()?;
    validate_vector_registry_gate_report_with_mode(report, mode)
}

pub fn validate_vector_registry_gate_report_with_mode(
    report: &VectorRegistryGateReport,
    mode: VectorRegistryGateMode,
) -> Result<()> {
    let failures = report.validation_failed_entries(mode).collect::<Vec<_>>();
    if failures.is_empty() {
        return Ok(());
    }

    let mut lines = Vec::with_capacity(failures.len());
    for entry in failures {
        let reason = entry.reason.as_deref().unwrap_or("missing evidence");
        lines.push(format!("{}: {reason}", entry.vector_id));
    }
    bail!(
        "vector registry gate ({}) found {} failing entries:\n{}",
        mode.as_str(),
        lines.len(),
        lines.join("\n")
    )
}

fn vector_registry_gate_mode_from_env() -> Result<VectorRegistryGateMode> {
    let value = match std::env::var(STRICT_GATE_ENV) {
        Ok(value) => value,
        Err(std::env::VarError::NotPresent) => return Ok(VectorRegistryGateMode::Lenient),
        Err(std::env::VarError::NotUnicode(_)) => {
            bail!("{STRICT_GATE_ENV} must be valid UTF-8")
        }
    };

    match value.trim().to_ascii_lowercase().as_str() {
        "" | "0" | "false" | "no" | "off" | "lenient" => Ok(VectorRegistryGateMode::Lenient),
        "1" | "true" | "yes" | "on" | "strict" => Ok(VectorRegistryGateMode::Strict),
        other => bail!(
            "{STRICT_GATE_ENV} must be one of 1/true/yes/on/strict or 0/false/no/off/lenient, got `{other}`"
        ),
    }
}

pub fn build_vector_registry_gate_report_from_paths(
    registry_path: &Path,
    artifacts_root: &Path,
) -> Result<VectorRegistryGateReport> {
    let registry = load_registry(registry_path)?;
    let fixture_digests = load_fixture_digest_index(artifacts_root)?;
    let mut entries = Vec::with_capacity(registry.vectors.len());

    for row in registry.vectors {
        entries.push(build_gate_entry(&row, artifacts_root, &fixture_digests)?);
    }

    Ok(VectorRegistryGateReport { entries })
}

fn load_registry(path: &Path) -> Result<VectorRegistry> {
    let raw = fs::read_to_string(path)
        .map_err(|error| anyhow!("failed to read vector registry {}: {error}", path.display()))?;
    serde_json::from_str(&raw).map_err(|error| {
        anyhow!(
            "failed to parse vector registry {}: {error}",
            path.display()
        )
    })
}

fn build_gate_entry(
    row: &VectorRegistryRow,
    artifacts_root: &Path,
    fixture_digests: &FixtureDigestIndex,
) -> Result<VectorRegistryGateEntry> {
    let fixture_refs = row
        .source_refs
        .iter()
        .filter(|source_ref| source_ref.starts_with(ARTIFACT_FIXTURE_PREFIX))
        .cloned()
        .collect::<Vec<_>>();

    match row.status.as_str() {
        "active" => build_active_gate_entry(row, artifacts_root, fixture_digests, fixture_refs),
        "reserved" => build_non_gating_entry(
            row,
            fixture_refs,
            VectorRegistryGateStatus::Reserved,
            "reserved vector rows require a description reason",
        ),
        "unsupported" => build_non_gating_entry(
            row,
            fixture_refs,
            VectorRegistryGateStatus::Unsupported,
            "unsupported vector rows require a description reason",
        ),
        other => Ok(VectorRegistryGateEntry {
            vector_id: row.vector_id.clone(),
            registry_status: other.to_owned(),
            gate_status: VectorRegistryGateStatus::Failed,
            fixture_refs,
            evidence_refs: Vec::new(),
            reason: Some(format!("unsupported registry status `{other}`")),
        }),
    }
}

fn build_active_gate_entry(
    row: &VectorRegistryRow,
    artifacts_root: &Path,
    fixture_digests: &FixtureDigestIndex,
    fixture_refs: Vec<String>,
) -> Result<VectorRegistryGateEntry> {
    if fixture_refs.is_empty() {
        return Ok(VectorRegistryGateEntry {
            vector_id: row.vector_id.clone(),
            registry_status: row.status.clone(),
            gate_status: VectorRegistryGateStatus::ActiveDocOnly,
            fixture_refs,
            evidence_refs: Vec::new(),
            reason: Some(
                "active doc-only registry entry has no artifact fixture source_ref; strict artifact-driven certification requires machine fixture evidence"
                    .to_owned(),
            ),
        });
    }

    let mut evidence_refs = Vec::new();
    let mut missing_refs = Vec::new();
    for fixture_ref in &fixture_refs {
        let path = resolve_artifact_ref(artifacts_root, fixture_ref)?;
        if !path.is_file() {
            missing_refs.push(format!("{fixture_ref} (file not found)"));
            continue;
        }

        let raw = fs::read_to_string(&path).map_err(|error| {
            anyhow!(
                "failed to read fixture source_ref {} at {}: {error}",
                fixture_ref,
                path.display()
            )
        })?;
        if let Err(reason) = validate_fixture_digest(fixture_digests, fixture_ref, &path)? {
            missing_refs.push(reason);
            continue;
        }
        let value = serde_json::from_str::<Value>(&raw).map_err(|error| {
            anyhow!(
                "failed to parse fixture source_ref {} at {}: {error}",
                fixture_ref,
                path.display()
            )
        })?;
        collect_vector_evidence(&value, &row.vector_id, fixture_ref, "", &mut evidence_refs);
        if !evidence_refs
            .iter()
            .any(|evidence| evidence.starts_with(fixture_ref))
        {
            missing_refs.push(format!("{fixture_ref} (vector_id not found)"));
        }
    }

    if evidence_refs.is_empty() || !missing_refs.is_empty() {
        let mut reason = String::from(
            "active registry entry lacks traceable artifact fixture evidence via vector_id, name, or covers_vectors",
        );
        if !missing_refs.is_empty() {
            reason.push_str(": ");
            reason.push_str(&missing_refs.join(", "));
        }
        return Ok(VectorRegistryGateEntry {
            vector_id: row.vector_id.clone(),
            registry_status: row.status.clone(),
            gate_status: VectorRegistryGateStatus::Failed,
            fixture_refs,
            evidence_refs,
            reason: Some(reason),
        });
    }

    Ok(VectorRegistryGateEntry {
        vector_id: row.vector_id.clone(),
        registry_status: row.status.clone(),
        gate_status: VectorRegistryGateStatus::FixtureBacked,
        fixture_refs,
        evidence_refs,
        reason: None,
    })
}

fn build_non_gating_entry(
    row: &VectorRegistryRow,
    fixture_refs: Vec<String>,
    gate_status: VectorRegistryGateStatus,
    missing_reason: &str,
) -> Result<VectorRegistryGateEntry> {
    let reason = row
        .description
        .as_deref()
        .map(str::trim)
        .filter(|description| !description.is_empty())
        .map(str::to_owned);

    let (gate_status, reason) = match reason {
        Some(reason) => (gate_status, Some(reason)),
        None => (
            VectorRegistryGateStatus::Failed,
            Some(missing_reason.to_owned()),
        ),
    };

    Ok(VectorRegistryGateEntry {
        vector_id: row.vector_id.clone(),
        registry_status: row.status.clone(),
        gate_status,
        fixture_refs,
        evidence_refs: Vec::new(),
        reason,
    })
}

fn resolve_artifact_ref(artifacts_root: &Path, source_ref: &str) -> Result<PathBuf> {
    let relative = source_ref
        .strip_prefix(ARTIFACT_REF_PREFIX)
        .ok_or_else(|| {
            anyhow!("artifact source_ref must start with {ARTIFACT_REF_PREFIX}: {source_ref}")
        })?;
    Ok(relative
        .split('/')
        .fold(artifacts_root.to_owned(), |path, segment| {
            path.join(segment)
        }))
}

fn load_fixture_digest_index(artifacts_root: &Path) -> Result<FixtureDigestIndex> {
    let path = artifacts_root.join(FIXTURE_DIGESTS_REF);
    if !path.is_file() {
        return Ok(FixtureDigestIndex {
            missing_report: true,
            hashes: BTreeMap::new(),
        });
    }

    let raw = fs::read_to_string(&path).map_err(|error| {
        anyhow!(
            "failed to read fixture digest report {}: {error}",
            path.display()
        )
    })?;
    let report: FixtureDigestReport = serde_json::from_str(&raw).map_err(|error| {
        anyhow!(
            "failed to parse fixture digest report {}: {error}",
            path.display()
        )
    })?;
    let hashes = report
        .files
        .into_iter()
        .map(|entry| (entry.path, entry.sha256))
        .collect::<BTreeMap<_, _>>();
    Ok(FixtureDigestIndex {
        missing_report: false,
        hashes,
    })
}

fn validate_fixture_digest(
    fixture_digests: &FixtureDigestIndex,
    fixture_ref: &str,
    path: &Path,
) -> Result<std::result::Result<(), String>> {
    if fixture_digests.missing_report {
        return Ok(Err(format!(
            "{fixture_ref} (fixture digest report {FIXTURE_DIGESTS_REF} not found)"
        )));
    }

    let Some(expected) = fixture_digests.hashes.get(fixture_ref) else {
        return Ok(Err(format!(
            "{fixture_ref} (not listed in {FIXTURE_DIGESTS_REF})"
        )));
    };
    if expected.len() != 64
        || !expected
            .chars()
            .all(|ch| ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase())
    {
        return Ok(Err(format!(
            "{fixture_ref} ({FIXTURE_DIGESTS_REF} sha256 is malformed)"
        )));
    }

    let bytes = fs::read(path).map_err(|error| {
        anyhow!(
            "failed to read fixture source_ref {} at {} for digest validation: {error}",
            fixture_ref,
            path.display()
        )
    })?;
    let actual = sha256_hex(&bytes);
    if actual != *expected {
        return Ok(Err(format!(
            "{fixture_ref} (fixture digest drift: expected {expected}, actual {actual})"
        )));
    }

    Ok(Ok(()))
}

fn sha256_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn collect_vector_evidence(
    value: &Value,
    vector_id: &str,
    fixture_ref: &str,
    pointer: &str,
    evidence_refs: &mut Vec<String>,
) {
    match value {
        Value::Object(object) => {
            if object.get("vector_id").and_then(Value::as_str) == Some(vector_id) {
                push_evidence_ref(evidence_refs, fixture_ref, pointer, "vector_id", object);
            }

            if object.get("name").and_then(Value::as_str) == Some(vector_id) {
                push_evidence_ref(evidence_refs, fixture_ref, pointer, "name", object);
            }

            if object
                .get("covers_vectors")
                .and_then(Value::as_array)
                .is_some_and(|vectors| {
                    vectors
                        .iter()
                        .any(|entry| entry.as_str() == Some(vector_id))
                })
            {
                push_evidence_ref(
                    evidence_refs,
                    fixture_ref,
                    pointer,
                    "covers_vectors",
                    object,
                );
            }

            for (key, child) in object {
                let child_pointer = join_json_pointer(pointer, key);
                collect_vector_evidence(
                    child,
                    vector_id,
                    fixture_ref,
                    &child_pointer,
                    evidence_refs,
                );
            }
        }
        Value::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                let child_pointer = join_json_pointer(pointer, &index.to_string());
                collect_vector_evidence(
                    child,
                    vector_id,
                    fixture_ref,
                    &child_pointer,
                    evidence_refs,
                );
            }
        }
        _ => {}
    }
}

fn push_evidence_ref(
    evidence_refs: &mut Vec<String>,
    fixture_ref: &str,
    pointer: &str,
    field: &str,
    object: &serde_json::Map<String, Value>,
) {
    let digest_suffix = find_expected_digest(object)
        .map(|digest| format!(" expected_digest={digest}"))
        .unwrap_or_default();
    evidence_refs.push(format!(
        "{fixture_ref}{}{} via {field}{digest_suffix}",
        if pointer.is_empty() { "" } else { "#" },
        pointer
    ));
}

fn find_expected_digest(object: &serde_json::Map<String, Value>) -> Option<&str> {
    object.iter().find_map(|(key, value)| {
        if key == "expected_digest" || key.ends_with("_digest") {
            value
                .as_str()
                .filter(|value| looks_like_sha256_digest(value))
        } else {
            None
        }
    })
}

fn join_json_pointer(parent: &str, segment: &str) -> String {
    let escaped = segment.replace('~', "~0").replace('/', "~1");
    if parent.is_empty() {
        format!("/{escaped}")
    } else {
        format!("{parent}/{escaped}")
    }
}
