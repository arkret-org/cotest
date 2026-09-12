use anyhow::{Result, ensure};
use serde_json::Value;

use super::{load_fixture_value, validate_profile};

const REQUIRED_SECTIONS: &[&str] = &[
    "client_convergence_kat",
    "sender_crypto_kats",
    "rhrk_registration_rotation_kat",
    "candidate_store_kat",
    "scope_and_endpoint_kats",
    "direct_traversal_kat",
    "authenticated_signer_resolution_evidence_kat",
    "governance_dependency_resolve_kat",
    "streaming_direct_traversal_scale_kats",
    "streaming_direct_traversal_scale_negative_kats",
    "direct_traversal_scale_generator_contract",
    "response_stream_cases",
    "history_response_capability_kat",
    "direct_traversal_replay_kat",
    "backup_recovery_unlock_manifest_kat",
    "organization_recovery_archive_durable_before_gc_kat",
];

pub async fn run_history_key_direct_traversal_suite() -> Result<()> {
    let fixture = load_fixture_value("history-key-recovery-fixture.json")?;
    validate_profile(&fixture, "ak.feature.history_key_recovery.v1")?;
    ensure!(
        fixture
            .pointer("/runner/entrypoint")
            .and_then(Value::as_str)
            == Some("ak.suite.crypto.history_key_recovery.v1"),
        "history-key recovery runner entrypoint drifted"
    );

    for section in REQUIRED_SECTIONS {
        let value = fixture
            .get(section)
            .ok_or_else(|| anyhow::anyhow!("history-key recovery fixture omits {section}"))?;
        ensure!(
            !matches!(value, Value::Null),
            "history-key recovery section {section} is null"
        );
    }

    Ok(())
}
