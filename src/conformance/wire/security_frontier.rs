//! MLS Security Frontier conformance vectors backed by the SDK projector.

use std::collections::BTreeMap;

use anyhow::{Context, Result, anyhow, bail};
use arkret_state::CellState;
use arkret_state::mls_governance_proof::{MlsSecurityFrontierLeaf, derive_mls_security_frontier};
use arkret_wire::{CellFamilyId, CellRef, Hash, ScopeRef, composite_subject};
use serde_json::{Value, json};

use crate::conformance::{load_artifact_json, load_fixture_value, required_str, validate_profile};

const FIXTURE: &str = "mls-governance-proof-fixture.json";
const PROFILE: &str = "ak.profile.mls_governance_binding.full.v1";

/// Replays the normative KAT through the public SDK projector and pins the
/// closed frontier semantics that replaced the covered-seals accumulator.
pub fn run_mls_security_frontier_fixture_suite() -> Result<()> {
    let fixture = load_fixture_value(FIXTURE)?;
    validate_profile(&fixture, PROFILE)?;

    let scope: ScopeRef = serde_json::from_value(
        fixture
            .pointer("/source_state/proof_identity/effective_scope")
            .cloned()
            .ok_or_else(|| anyhow!("MLS governance proof fixture missing effective_scope"))?,
    )?;
    let leaves: Vec<MlsSecurityFrontierLeaf> = serde_json::from_value(
        fixture
            .pointer("/commit_context/current_or_pending_mls_leaf_entries")
            .cloned()
            .ok_or_else(|| anyhow!("MLS governance proof fixture missing leaf entries"))?,
    )?;
    let state = fixture_control_state(&fixture)?;
    let expected = Hash::new(
        required_str(
            fixture
                .get("known_answer")
                .ok_or_else(|| anyhow!("MLS governance proof fixture missing known_answer"))?,
            "security_frontier_digest",
        )?
        .to_owned(),
    )?;

    let observed = derive_mls_security_frontier(&state, &scope, &leaves)?;
    if observed != expected {
        bail!("SDK security frontier KAT drifted: expected={expected}, observed={observed}");
    }

    assert_unrelated_state_is_orthogonal(&state, &scope, &leaves, &observed)?;
    assert_active_leaf_revoke_changes_digest(&state, &scope, &leaves, &observed)?;
    assert_realm_circle_isolation(&state, &scope, &leaves, &observed)?;
    assert_closed_registry_rejects_unknown_input()?;
    Ok(())
}

fn fixture_control_state(fixture: &Value) -> Result<BTreeMap<CellRef, CellState>> {
    fixture
        .pointer("/source_state/joined_control_state")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("MLS governance proof fixture missing joined_control_state[]"))?
        .iter()
        .map(|entry| {
            let cell = CellRef::new(required_str(entry, "cell")?.to_owned())?;
            let value = entry
                .pointer("/state/value")
                .cloned()
                .ok_or_else(|| anyhow!("fixture control cell {cell} missing state.value"))?;
            Ok((cell, CellState::Value(value)))
        })
        .collect()
}

fn cell_ref(family: &str, subject_parts: &[&str]) -> Result<CellRef> {
    let subject = match subject_parts {
        [subject] => (*subject).to_owned(),
        parts => composite_subject(parts).context("encoding composite cell subject")?,
    };
    CellRef::new(format!("ak:cell:{family}:{subject}"))
        .with_context(|| format!("constructing {family} cell"))
}

fn assert_unrelated_state_is_orthogonal(
    baseline: &BTreeMap<CellRef, CellState>,
    scope: &ScopeRef,
    leaves: &[MlsSecurityFrontierLeaf],
    expected: &Hash,
) -> Result<()> {
    let mut changed = baseline.clone();
    changed.insert(
        cell_ref(
            CellFamilyId::CAPABILITY_GRANT_V1,
            &["ak:capability:019809f4-a800-7000-8000-000000000501"],
        )?,
        CellState::Value(json!({"action": "ak.message.send", "status": "active"})),
    );
    changed.insert(
        cell_ref(
            CellFamilyId::REALM_METADATA_V1,
            &["ak:realm:AWy1ImsZXpFjP50bGHC-ecStBt4qurkjgu4EoRYSpmnE"],
        )?,
        CellState::Value(json!({"display_name": "orthogonal metadata"})),
    );
    let observed = derive_mls_security_frontier(&changed, scope, leaves)?;
    if &observed != expected {
        bail!("unrelated capability/metadata state changed security_frontier_digest");
    }
    Ok(())
}

fn assert_active_leaf_revoke_changes_digest(
    state: &BTreeMap<CellRef, CellState>,
    scope: &ScopeRef,
    leaves: &[MlsSecurityFrontierLeaf],
    baseline: &Hash,
) -> Result<()> {
    let remaining = leaves
        .get(1..)
        .ok_or_else(|| anyhow!("KAT must contain at least two MLS leaves"))?;
    let observed = derive_mls_security_frontier(state, scope, remaining)?;
    if &observed == baseline {
        bail!("removing an active MLS leaf did not change security_frontier_digest");
    }
    Ok(())
}

fn assert_realm_circle_isolation(
    state: &BTreeMap<CellRef, CellState>,
    realm_scope: &ScopeRef,
    leaves: &[MlsSecurityFrontierLeaf],
    baseline: &Hash,
) -> Result<()> {
    let mut with_other_circle = state.clone();
    with_other_circle.insert(
        cell_ref(
            CellFamilyId::CIRCLE_MEMBER_V1,
            &[
                "ak:circle:019809f4-a800-8000-8000-000000000601",
                "did:webvh:zfixture:bob.example",
            ],
        )?,
        CellState::Value(json!({"membership": "ban"})),
    );
    let realm_observed = derive_mls_security_frontier(&with_other_circle, realm_scope, leaves)?;
    if &realm_observed != baseline {
        bail!("a Circle membership cell contaminated the Realm security frontier");
    }

    let circle_scope: ScopeRef = serde_json::from_value(json!({
        "kind": "circle",
        "realm_id": "ak:realm:AWy1ImsZXpFjP50bGHC-ecStBt4qurkjgu4EoRYSpmnE",
        "circle_id": "ak:circle:019809f4-a800-8000-8000-000000000601"
    }))?;
    let circle_observed = derive_mls_security_frontier(&with_other_circle, &circle_scope, leaves)?;
    if circle_observed == *baseline {
        bail!("Realm and Circle scopes produced the same security frontier digest");
    }
    Ok(())
}

fn assert_closed_registry_rejects_unknown_input() -> Result<()> {
    let registry = load_artifact_json("registry/mls-security-frontier-registry.json")?;
    if registry.get("source_of_truth").and_then(Value::as_bool) != Some(true)
        || registry
            .get("unknown_input_behavior")
            .and_then(Value::as_str)
            != Some("fail_closed")
    {
        bail!("MLS security frontier registry must reject unknown inputs fail closed");
    }
    Ok(())
}
