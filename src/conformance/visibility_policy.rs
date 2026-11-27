//! Current MLS activation and history-visibility vectors.

use std::collections::BTreeSet;

use anyhow::{Context, Result, bail};
use arkret_models_collaboration::governance::mls_activation::{
    MlsActivationError, validate_mls_activation_is_irreversible,
    validate_scope_mls_activation,
};
use serde_json::{Value, json};

const FIXTURE: &str = "visibility-policy-fixture.json";
const VECTOR_IDS: &[&str] = &[
    "ak.vector.e2ee.mls_activation_irreversible.v1",
    "ak.vector.e2ee.plaintext_write_after_activation_rejected.v1",
    "ak.vector.e2ee.ciphertext_write_before_activation_rejected.v1",
    "ak.vector.history_access.since_join_prejoin_denied.v1",
    "ak.vector.preview.token_scoped_stripped_state.v1",
];

fn fixture() -> Result<Value> {
    let value = super::load_fixture_value(FIXTURE)?;
    if value["profile"] != "ak.profile.core_event_store.v1"
        || value["runner"]["entrypoint"] != "ak.suite.visibility.policy.v1"
    {
        bail!("visibility policy fixture identity drifted");
    }
    let covered = value["covers_vectors"]
        .as_array()
        .context("visibility fixture missing covers_vectors")?
        .iter()
        .map(|id| id.as_str().context("vector id must be a string"))
        .collect::<Result<BTreeSet<_>>>()?;
    if covered != VECTOR_IDS.iter().copied().collect() {
        bail!("visibility policy fixture vector set drifted");
    }
    Ok(value)
}

fn case<'a>(fixture: &'a Value, vector_id: &str) -> Result<&'a Value> {
    fixture["cases"]
        .as_array()
        .context("visibility fixture missing cases")?
        .iter()
        .find(|case| case["vector_id"] == vector_id)
        .with_context(|| format!("visibility fixture missing {vector_id}"))
}

fn assert_activation() -> Result<()> {
    let active = Some("ak:mls_group:active");
    if validate_mls_activation_is_irreversible(None, active).is_err()
        || validate_mls_activation_is_irreversible(active, active).is_err()
        || !matches!(
            validate_mls_activation_is_irreversible(active, None),
            Err(MlsActivationError::MlsActivationIrreversible)
        )
        || !matches!(
            validate_mls_activation_is_irreversible(active, Some("ak:mls_group:other")),
            Err(MlsActivationError::MlsActivationIrreversible)
        )
    {
        bail!("MLS activation irreversibility drifted");
    }
    if validate_scope_mls_activation(None, false).is_err()
        || validate_scope_mls_activation(active, true).is_err()
        || !matches!(
            validate_scope_mls_activation(active, false),
            Err(MlsActivationError::MlsActivationRequired)
        )
    {
        bail!("activated scope plaintext-write gate drifted");
    }
    // A definitely inactive scope refuses ciphertext as a generic
    // failed_precondition that names no reason code.
    match validate_scope_mls_activation(None, true) {
        Err(error @ MlsActivationError::MlsScopeInactive)
            if !error.to_string().contains("reason=") => {}
        _ => bail!("inactive scope ciphertext-write gate drifted"),
    }
    // An independent Realm has its own accepted MLS state.
    if validate_scope_mls_activation(None, false).is_err()
        || validate_scope_mls_activation(active, false).is_ok()
    {
        bail!("independent Realm reused another Realm’s MLS state");
    }
    Ok(())
}

pub fn run_visibility_policy_fixture_suite() -> Result<()> {
    let fixture = fixture()?;
    for vector_id in VECTOR_IDS {
        let _ = case(&fixture, vector_id)?;
    }
    assert_activation()?;
    let inactive = case(
        &fixture,
        "ak.vector.e2ee.ciphertext_write_before_activation_rejected.v1",
    )?;
    if inactive["expected"]["outcome"] != "failed_precondition"
        || inactive["expected"].get("reason").is_some()
        || inactive["expected"]["durable_writes"] != 0
    {
        bail!("inactive scope ciphertext refusal contract drifted");
    }
    let history = case(
        &fixture,
        "ak.vector.history_access.since_join_prejoin_denied.v1",
    )?;
    let join_epoch = history["viewer"]["join_epoch"]
        .as_u64()
        .context("history vector missing join epoch")?;
    for event in history["events"]
        .as_array()
        .context("history events missing")?
    {
        if event["expected_visible"].as_bool() != event["epoch"].as_u64().map(|e| e >= join_epoch) {
            bail!("since_join history projection drifted");
        }
    }
    let preview = case(&fixture, "ak.vector.preview.token_scoped_stripped_state.v1")?;
    if preview["expected"]["history_events"] != json!([])
        || preview["expected"]["exporter_secrets"] != json!([])
    {
        bail!("preview projection leaked history or exporter secrets");
    }
    Ok(())
}
