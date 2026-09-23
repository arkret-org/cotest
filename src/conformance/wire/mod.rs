//! Wire-model conformance vectors, organized by protocol domain.
//!
//! These vectors live in cotest (under `tests/fixtures/`) rather than in the
//! shared spec artifact tree, because they describe Space-level behavior that
//! cotest verifies structurally. Each vector couples a fully-shaped input with the outcome the
//! spec mandates; the validation is a static consistency check.
//!
//! Each protocol domain lives in its own submodule; the shared, module-level
//! helpers below back every domain.

mod composite_state;
mod discovery;
mod e2ee;
mod history;
mod interop;
mod key_backup;
mod mimi;
mod multisig;
mod payload_coverage;

use std::path::PathBuf;

use anyhow::{Result, anyhow};
pub use composite_state::{
    run_composite_state_key_encoding_fixture_suite, run_composite_state_subject_fixture_suite,
};
pub use discovery::{run_discovery_profile_fixture_suite, run_facet_renderer_query_fixture_suite};
pub use e2ee::{
    run_device_message_negative_fixture_suite, run_megolm_ratchet_kdf_chain_check,
    run_megolm_ratcheting_fixture_suite,
};
pub use history::run_redacted_cross_server_fixture_suite;
pub use interop::run_interop_downgrade_fixture_suite;
pub use key_backup::{
    run_key_backup_aead_round_trip_check, run_key_backup_encryption_fixture_suite,
    run_recovery_bridge_full_chain_fixture_suite, run_recovery_ticket_state_machine_check,
    run_restore_full_workflows_fixture_suite,
};
pub use mimi::{
    run_mimi_components_fixture_suite, run_mimi_interop_fixture_suite,
    run_read_receipt_policy_fixture_suite,
};
pub use multisig::{
    run_multi_admin_distinct_approver_gate_check, run_production_signing_fixture_suite,
};
pub use payload_coverage::run_event_kind_payload_coverage_fixture_suite;
use serde_json::{Value, json};

use crate::transcripts::{is_active, record_vector_event};

/// Emit a structured transcript event for a wire-model vector at the end of
/// a per-vector loop iteration. `kind_suffix` becomes the trailing portion of
/// the JSONL `kind` field (e.g. `"composite_state_subject.encoded"` →
/// `wire_model.composite_state_subject.encoded`). The full vector value is
/// used for `payload`; `expected` extracts `vector.expected` when present
/// (defaulting to the vector's `name`); `actual` is the caller-supplied
/// summary of what the validator computed.
///
/// No-op when the calling thread has no active transcript writer (i.e. when
/// running under plain `cargo test` without the auto-init fixture wrapper),
/// so it stays free in the hot path.
pub(super) fn emit_vector(kind_suffix: &str, vector: &Value, actual: Value) {
    if !is_active() {
        return;
    }
    let expected = vector
        .get("expected")
        .cloned()
        .unwrap_or_else(|| json!({"name": vector.get("name").cloned().unwrap_or(Value::Null)}));
    record_vector_event(
        &format!("wire_model.{kind_suffix}"),
        vector,
        &expected,
        &actual,
    );
}
pub(super) fn local_fixture_path(file_name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(file_name)
}
pub(super) fn load_local_fixture(file_name: &str) -> Result<Value> {
    let path = local_fixture_path(file_name);
    let raw = std::fs::read_to_string(&path)
        .map_err(|err| anyhow!("read local fixture {}: {err}", path.display()))?;
    serde_json::from_str(&raw)
        .map_err(|err| anyhow!("parse local fixture {}: {err}", path.display()))
}
pub(super) fn expected_outcome<'a>(vector: &'a Value, name: &str) -> Result<&'a str> {
    vector
        .pointer("/expected/outcome")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("vector {name} missing expected.outcome"))
}
pub(super) fn expected_reason(vector: &Value) -> Option<&str> {
    vector
        .pointer("/expected/reason_code")
        .and_then(Value::as_str)
}
