mod blind_payload;
mod capability;
mod coauth_lifecycle;
mod encoding;
mod envelope;
mod federation;
mod lattice_mixed_kinds;
mod lattice_round_trip;
mod principal_server_certification;
mod privacy;
mod profile_matrix;
mod profile_registry;
mod redaction;
mod registry;
mod round4_allowlist;
mod round4_lint_parity;
mod scaffold_gate;
mod schema_validation;
mod schema_validation_fixture;
mod security_closure;
mod security_negative;
mod snapshot_v2_tampered_merkle;
mod state_resolution;
mod sync;
mod wire_model;
mod yougen_client;

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

const ARTIFACT_REGISTRY_DIR: &str = "registry";
const ARTIFACT_FIXTURES_DIR: &str = "fixtures";

// ── Public suite re-exports ─────────────────────────────────────────────────

pub use blind_payload::{
    run_blind_payload_sanitizer_suite, run_blind_payload_sanitizer_suite_counts,
};
pub use capability::run_capability_facet_fixture_suite;
pub use capability::run_capability_fixture_suite;
pub use coauth_lifecycle::run_coauth_account_lifecycle_fixture_suite;
pub use encoding::run_encoding_fixture_suite;
pub use encoding::run_projection_position_discriminator_fixture_suite;
pub use envelope::{run_deprecated_event_alias_suite, run_event_envelope_fixture_suite};
pub use federation::run_federation_fixture_suite;
pub use lattice_mixed_kinds::run_lattice_mixed_kinds_suite;
pub use lattice_round_trip::run_lattice_round_trip_suite;
pub use principal_server_certification::{
    PrincipalCertificationStatus, run_principal_server_certification_gate_suite,
    validate_principal_server_certification,
};
pub use privacy::run_privacy_security_fixture_suite;
pub use profile_matrix::{run_profile_matrix_suite, validate_server_profile_claims};
pub use profile_registry::{
    ProfileGateEntry, ProfileGateReport, ProfileGateStatus, build_profile_gate_report,
    render_profile_gate_report_json, render_profile_gate_report_markdown,
    run_profile_registry_gate_suite,
};
pub use redaction::run_redaction_fixture_suite;
pub use registry::run_artifact_registry_suite;
pub use round4_allowlist::{
    ROUND4_NEW_CAPABILITY_ACTIONS, ROUND4_NEW_ERROR_CODES, ROUND4_NEW_OBJECT_REF_ID_KINDS,
    ROUND4_NEW_OPENAPI_COMPONENTS, ROUND4_NEW_SCHEMA_DEFS, run_round4_drift_allowlist_suite,
};
pub use round4_lint_parity::{
    run_policy_check_alignment_check, run_service_describe_alignment_check,
    run_vector_reference_closure_check,
};
pub use scaffold_gate::{
    run_live_describe_profile_gate_suite, run_scaffold_profile_gate_suite,
    validate_scaffold_profile_gate,
};
pub use schema_validation::run_schema_validation_suite;
pub use schema_validation_fixture::{
    SCHEMA_VALIDATION_FIXTURE, SCHEMA_VALIDATION_PROFILE, SchemaValidationCase,
    SchemaValidationFixture, run_schema_validation_fixture_suite,
};
pub use security_closure::{
    ObservedRunner, REQUIRED_SECURITY_CLOSURE_VECTOR_IDS, SECURITY_CLOSURE_VECTORS_FIXTURE,
    SECURITY_CLOSURE_VECTORS_PROFILE, SecurityClosureExpected, SecurityClosureFixture,
    SecurityClosureRunner, SecurityClosureStep, SecurityClosureVector,
    run_security_closure_vectors_suite, validate_security_closure_fixture,
};
pub use security_negative::run_security_negative_profile_suite;
pub use snapshot_v2_tampered_merkle::run_snapshot_v2_tampered_merkle_suite;
pub use state_resolution::{
    run_move_anchor_lattice_fixture_suite, run_state_resolution_fixture_suite,
};
pub use sync::run_sync_fixture_suite;
pub use wire_model::run_anchor_view_compaction_fixture_suite;
pub use wire_model::run_anchorer_cell_fixture_suite;
pub use wire_model::run_composite_state_key_encoding_fixture_suite;
pub use wire_model::run_composite_state_subject_fixture_suite;
pub use wire_model::run_conflict_repair_fixture_suite;
pub use wire_model::run_consent_fixture_suite;
pub use wire_model::run_constraint_evaluation_class_fixture_suite;
pub use wire_model::run_constraint_family_fixture_suite;
pub use wire_model::run_cross_signing_reset_fixture_suite;
pub use wire_model::run_device_cross_signing_trust_fixture_suite;
pub use wire_model::run_device_message_negative_fixture_suite;
pub use wire_model::run_device_verification_fixture_suite;
pub use wire_model::run_discovery_profile_fixture_suite;
pub use wire_model::run_error_code_registry_coverage_fixture_suite;
pub use wire_model::run_event_kind_lattice_dispatch_fixture_suite;
pub use wire_model::run_event_kind_payload_coverage_fixture_suite;
pub use wire_model::run_facet_renderer_query_fixture_suite;
pub use wire_model::run_frontier_conflict_resolution_fixture_suite;
pub use wire_model::run_history_visibility_fixture_suite;
pub use wire_model::run_history_visibility_projection_matrix_check;
pub use wire_model::run_key_backup_aead_round_trip_check;
pub use wire_model::run_key_backup_encryption_fixture_suite;
pub use wire_model::run_late_arriving_anchor_fixture_suite;
pub use wire_model::run_late_arriving_anchor_idempotency_check;
pub use wire_model::run_megolm_ratchet_kdf_chain_check;
pub use wire_model::run_megolm_ratcheting_fixture_suite;
pub use wire_model::run_membership_fsm_fixture_suite;
pub use wire_model::run_mimi_components_fixture_suite;
pub use wire_model::run_mls_e2ee_basic_fixture_suite;
pub use wire_model::run_mls_move_covered_frontier_fixture_suite;
pub use wire_model::run_multi_admin_distinct_approver_gate_check;
pub use wire_model::run_multi_space_federation_fixture_suite;
pub use wire_model::run_operation_registry_coverage_fixture_suite;
pub use wire_model::run_production_signing_fixture_suite;
pub use wire_model::run_read_receipt_policy_fixture_suite;
pub use wire_model::run_recovery_bridge_full_chain_fixture_suite;
pub use wire_model::run_recovery_ticket_state_machine_check;
pub use wire_model::run_redacted_cross_server_fixture_suite;
pub use wire_model::run_redaction_history_visibility_fixture_suite;
pub use wire_model::run_restore_full_workflows_fixture_suite;
pub use wire_model::run_state_resolution_quarantine_fixture_suite;
pub use wire_model::run_threshold_multisig_fixture_suite;
pub use yougen_client::run_yougen_client_profile_manifest_suite;

// ── Shared fixture types ────────────────────────────────────────────────────

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct RegistryManifestEntry {
    pub(crate) kind: String,
    pub(crate) source_role: String,
    pub(crate) source_of_truth: bool,
    pub(crate) generated_from: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct EncodingFixture {
    pub(crate) suite: String,
    pub(crate) cases: EncodingCases,
}

#[derive(Debug, Deserialize)]
pub(crate) struct EncodingCases {
    pub(crate) canonical_json: Vec<CanonicalJsonCase>,
    pub(crate) hash_digest: Vec<HashDigestCase>,
    pub(crate) proof_payload: Vec<ProofPayloadCase>,
    pub(crate) hlc: Vec<HlcCase>,
    pub(crate) cursor: Vec<CursorCase>,
    pub(crate) fractional_rank: Vec<FractionalRankCase>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct CanonicalJsonCase {
    pub(crate) name: String,
    pub(crate) input: Value,
    pub(crate) canonical: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct HashDigestCase {
    pub(crate) name: String,
    pub(crate) input_ref: String,
    pub(crate) expected_pattern: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct ProofPayloadCase {
    pub(crate) name: String,
    pub(crate) covered_fields: Vec<String>,
    pub(crate) excluded_fields: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct HlcCase {
    pub(crate) name: String,
    pub(crate) values: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct CursorShape {
    pub(crate) v: String,
    pub(crate) x: u64,
}

#[derive(Debug, Deserialize)]
pub(crate) struct CursorCase {
    pub(crate) name: String,
    pub(crate) shape: CursorShape,
}

#[derive(Debug, Deserialize)]
pub(crate) struct FractionalRankCase {
    pub(crate) name: String,
    pub(crate) left: Option<String>,
    pub(crate) right: Option<String>,
    pub(crate) expected: Option<String>,
    pub(crate) input: Option<String>,
    pub(crate) max_length: Option<usize>,
    pub(crate) active_edge_count: Option<usize>,
    pub(crate) assignment_count: Option<usize>,
    pub(crate) ordered_edges: Option<Vec<RankEdge>>,
    pub(crate) expected_assignments: Option<Vec<RankAssignment>>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct RedactionFixture {
    pub(crate) suite: String,
    pub(crate) cases: Vec<RedactionCase>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct RedactionCase {
    pub(crate) name: String,
    pub(crate) preserve: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct FederationFixture {
    pub(crate) suite: String,
    pub(crate) cases: Vec<NamedCase>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct PrivacySecurityFixture {
    pub(crate) suite: String,
    pub(crate) cases: Vec<NamedCase>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct NamedCase {
    pub(crate) name: String,
    pub(crate) operation_id: Option<String>,
    pub(crate) input: Option<Value>,
    pub(crate) expected: Option<Value>,
}

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct RankEdge {
    pub(crate) relation_id: String,
    pub(crate) object_ref: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub(crate) struct RankAssignment {
    pub(crate) relation_id: String,
    pub(crate) object_ref: String,
    pub(crate) rank: String,
}

// ── Shared utility functions ────────────────────────────────────────────────

pub(crate) fn spec_artifacts_root() -> PathBuf {
    if let Some(root) = std::env::var_os("COTEST_SPEC_ARTIFACTS_ROOT") {
        return PathBuf::from(root);
    }

    if let Some(root) = std::env::var_os("COTEST_SPEC_ROOT") {
        let root = PathBuf::from(root);
        for candidate in spec_artifact_candidates(&root) {
            if candidate.join(ARTIFACT_REGISTRY_DIR).is_dir() {
                return candidate;
            }
        }
    }

    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("contrix-spec")
        .join("spec")
        .join("v1")
        .join("artifacts")
}

pub(crate) fn fixture_path(file_name: &str) -> PathBuf {
    if let Some(root) = std::env::var_os("COTEST_SPEC_ROOT") {
        let root = PathBuf::from(root);
        for artifact_root in spec_artifact_candidates(&root) {
            let candidate = artifact_root.join(ARTIFACT_FIXTURES_DIR).join(file_name);
            if candidate.is_file() {
                return candidate;
            }
        }
    }

    spec_artifacts_root()
        .join(ARTIFACT_FIXTURES_DIR)
        .join(file_name)
}

pub(crate) fn local_fixture_path(file_name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(file_name)
}

pub(crate) fn load_local_fixture_value(file_name: &str) -> Result<Value> {
    let path = local_fixture_path(file_name);
    let raw = fs::read_to_string(&path)?;
    serde_json::from_str(&raw)
        .map_err(|error| anyhow!("failed to parse local fixture {}: {error}", path.display()))
}

fn spec_artifact_candidates(root: &Path) -> Vec<PathBuf> {
    vec![
        root.to_owned(),
        root.join("spec").join("v1").join("artifacts"),
    ]
}

pub(crate) fn load_fixture<T>(file_name: &str) -> Result<T>
where
    T: for<'de> Deserialize<'de>,
{
    parse_fixture_value(file_name, load_fixture_value(file_name)?)
}

pub(crate) fn load_fixture_value(file_name: &str) -> Result<Value> {
    let path = fixture_path(file_name);
    let raw = fs::read_to_string(&path)?;
    serde_json::from_str(&raw)
        .map_err(|error| anyhow!("failed to parse fixture {}: {error}", path.display()))
}

pub(crate) fn parse_fixture_value<T>(file_name: &str, value: Value) -> Result<T>
where
    T: for<'de> Deserialize<'de>,
{
    serde_json::from_value(value)
        .map_err(|error| anyhow!("failed to parse fixture {file_name}: {error}"))
}

pub(crate) fn load_artifact_json(relative_path: &str) -> Result<Value> {
    let path = spec_artifacts_root().join(relative_path);
    let raw = fs::read_to_string(&path)?;
    serde_json::from_str(&raw)
        .map_err(|error| anyhow!("failed to parse artifact {}: {error}", path.display()))
}

pub(crate) fn load_artifact_yaml(relative_path: &str) -> Result<serde_yaml::Value> {
    let path = spec_artifacts_root().join(relative_path);
    let raw = fs::read_to_string(&path)?;
    serde_yaml::from_str(&raw)
        .map_err(|error| anyhow!("failed to parse artifact {}: {error}", path.display()))
}

pub(crate) fn validate_profile(value: &Value, expected: &str) -> Result<()> {
    let profile = value
        .get("profile")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("fixture artifact missing profile"))?;
    if profile != expected {
        bail!("fixture profile drifted: expected {expected}, got {profile}");
    }
    Ok(())
}

pub(crate) fn string_array_field<'a>(value: &'a Value, field: &str) -> Result<Vec<&'a str>> {
    Ok(value
        .get(field)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|item| {
            item.as_str()
                .ok_or_else(|| anyhow!("{field} entry must be a string"))
        })
        .collect::<Result<Vec<_>>>()?)
}

pub(crate) fn required_str<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing string field {field}"))
}

pub(crate) fn required_field<'a>(value: &'a Value, field: &str) -> Result<&'a Value> {
    value
        .as_object()
        .and_then(|object| object.get(field))
        .ok_or_else(|| anyhow!("missing object field {field}"))
}

pub(crate) fn value_array<'a>(value: &'a Value, context: &str) -> Result<&'a Vec<Value>> {
    value
        .as_array()
        .ok_or_else(|| anyhow!("{context} must be an array"))
}

pub(crate) fn value_field_str<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
    required_field(value, field)?
        .as_str()
        .ok_or_else(|| anyhow!("object field {field} must be a string"))
}

pub(crate) fn value_field_u64(value: &Value, field: &str) -> Result<u64> {
    required_field(value, field)?
        .as_u64()
        .ok_or_else(|| anyhow!("object field {field} must be an unsigned integer"))
}

pub(crate) fn canonical_json(value: &Value) -> Result<String> {
    match value {
        Value::Object(map) => {
            let mut ordered = BTreeMap::new();
            for (key, value) in map {
                ordered.insert(key, canonical_json(value)?);
            }
            let mut out = String::from("{");
            for (index, (key, value)) in ordered.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(key)?);
                out.push(':');
                out.push_str(value);
            }
            out.push('}');
            Ok(out)
        }
        Value::Array(items) => {
            let canonical_items = items
                .iter()
                .map(canonical_json)
                .collect::<Result<Vec<_>>>()?;
            Ok(format!("[{}]", canonical_items.join(",")))
        }
        _ => Ok(serde_json::to_string(value)?),
    }
}

pub(crate) fn sha256_prefixed(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity("sha256:".len() + digest.len() * 2);
    out.push_str("sha256:");
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

pub(crate) fn looks_like_sha256_digest(value: &str) -> bool {
    value.starts_with("sha256:")
        && value.len() == "sha256:".len() + 64
        && value["sha256:".len()..]
            .chars()
            .all(|ch| ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase())
}

pub(crate) fn canonical_proof_payload(event: &Value) -> Result<Map<String, Value>> {
    let object = event
        .as_object()
        .ok_or_else(|| anyhow!("proof payload source must be an object"))?;
    let mut payload = Map::new();
    for (key, value) in object {
        if key != "unsigned" {
            payload.insert(key.clone(), value.clone());
        }
    }
    Ok(payload)
}

pub(crate) fn encode_cursor_shape(shape: &CursorShape) -> Result<String> {
    let canonical = canonical_json(&serde_json::to_value(shape)?)?;
    Ok(format!(
        "cx:cursor:{}",
        base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            canonical.as_bytes()
        )
    ))
}

pub(crate) fn decode_cursor_shape(encoded: &str) -> Result<CursorShape> {
    use base64::Engine as _;
    let payload = encoded
        .strip_prefix("cx:cursor:")
        .ok_or_else(|| anyhow!("cursor must start with cx:cursor:"))?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload)?;
    serde_json::from_slice(&bytes).map_err(Into::into)
}

pub(crate) const RANK_ALPHABET: &str =
    "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
pub(crate) const RANK_MAX_LENGTH: usize = 128;

pub(crate) fn rank_between(left: Option<&str>, right: Option<&str>) -> Result<String> {
    if let Some(rank) = left {
        validate_rank(rank, RANK_MAX_LENGTH)?;
    }
    if let Some(rank) = right {
        validate_rank(rank, RANK_MAX_LENGTH)?;
    }

    match (left, right) {
        (Some(left), Some(right)) if left >= right => {
            bail!("left rank must be lower than right rank");
        }
        (Some(left), Some(right)) if right.starts_with(left) => {
            let candidate = format!("{left}0");
            if candidate.as_str() < right {
                return Ok(candidate);
            }
            bail!("no dense rank between {left} and {right}");
        }
        (Some(left), Some(right)) if left.len() == right.len() && left.len() >= 2 => {
            let left_prefix = &left[..left.len() - 1];
            let right_prefix = &right[..right.len() - 1];
            if left_prefix != right_prefix {
                bail!("rank prefixes differ for {left} / {right}");
            }
            let left_digit = rank_char_index(left.chars().last().unwrap())?;
            let right_digit = rank_char_index(right.chars().last().unwrap())?;
            if right_digit <= left_digit + 1 {
                bail!("no space between {left} and {right}");
            }
            let middle = (left_digit + right_digit) / 2;
            Ok(format!("{left_prefix}{}", rank_char_at(middle)?))
        }
        (left, right) => {
            let lower = match left {
                Some(rank) if rank.len() == 1 => rank_char_index(rank.chars().next().unwrap())?,
                Some(rank) => bail!("unsupported lower boundary rank {rank}"),
                None => -1,
            };
            let upper = match right {
                Some(rank) if rank.len() == 1 => rank_char_index(rank.chars().next().unwrap())?,
                Some(rank) => bail!("unsupported upper boundary rank {rank}"),
                None => RANK_ALPHABET.len() as i32,
            };
            if upper <= lower + 1 {
                bail!("no rank available between boundaries");
            }
            let middle = (lower + upper) / 2;
            Ok(rank_char_at(middle)?.to_string())
        }
    }
}

pub(crate) fn validate_rank(rank: &str, max_length: usize) -> Result<()> {
    if rank.is_empty() || rank.len() > max_length {
        bail!("invalid_rank");
    }
    if !rank.chars().all(|ch| RANK_ALPHABET.contains(ch)) {
        bail!("invalid_rank");
    }
    Ok(())
}

pub(crate) fn rank_char_index(ch: char) -> Result<i32> {
    RANK_ALPHABET
        .chars()
        .position(|candidate| candidate == ch)
        .map(|index| index as i32)
        .ok_or_else(|| anyhow!("invalid_rank"))
}

pub(crate) fn rank_char_at(index: i32) -> Result<char> {
    if index < 0 {
        bail!("invalid_rank");
    }
    RANK_ALPHABET
        .chars()
        .nth(index as usize)
        .ok_or_else(|| anyhow!("invalid_rank"))
}

pub(crate) fn rebalance_assignments(edges: &[RankEdge]) -> Result<Vec<RankAssignment>> {
    let count = edges.len();
    validate_rebalance_assignment_count(count, count)?;
    let alphabet_span = (RANK_ALPHABET.len() + 1) as f64;
    let denominator = (count + 1) as f64;
    edges
        .iter()
        .enumerate()
        .map(|(index, edge)| {
            let rank_index =
                (-1.0 + (((index + 1) as f64 * alphabet_span) / denominator)).round() as i32;
            Ok(RankAssignment {
                relation_id: edge.relation_id.clone(),
                object_ref: edge.object_ref.clone(),
                rank: rank_char_at(rank_index)?.to_string(),
            })
        })
        .collect()
}

pub(crate) fn validate_rebalance_assignment_count(
    active_edge_count: usize,
    assignment_count: usize,
) -> Result<()> {
    if active_edge_count != assignment_count {
        bail!("invalid_rebalance_assignment");
    }
    Ok(())
}
