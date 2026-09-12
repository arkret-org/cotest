use std::collections::BTreeSet;

use anyhow::{Context, Result, bail, ensure};
use arkret_wire::NotaryValue;
use serde_json::Value;

use super::{load_fixture_value, validate_profile};

const STATE_MODELS: &[&str] = &[
    "causal_register",
    "sequenced_state",
    "or_set",
    "counter",
    "ordered_log",
];

const MODEL_BOUND_VECTORS: &[(&str, &str)] = &[
    (
        "ak.vector.cbs_lattice.data_plane_conflict_returns_bottom_without_winner.v1",
        "causal_register",
    ),
    (
        "ak.vector.state_model.sequenced_revision_guard.v1",
        "sequenced_state",
    ),
    (
        "ak.vector.seal.ordered_command_results.v1",
        "sequenced_state",
    ),
    (
        "ak.vector.state_model.causal_transition_heads.v1",
        "causal_register",
    ),
];

pub fn run_state_resolution_fixture_suite() -> Result<()> {
    run_cbs_lattice_fixture_suite()
}

pub fn run_cbs_lattice_fixture_suite() -> Result<()> {
    let fixture = load_fixture_value("cbs-lattice-fixture.json")?;
    validate_profile(&fixture, "ak.vector_group.cbs_lattice.v1")?;
    ensure!(
        fixture
            .pointer("/runner/entrypoint")
            .and_then(Value::as_str)
            == Some("ak.suite.authz.cbs_lattice.v1")
    );
    let notes = fixture
        .get("notes")
        .and_then(Value::as_array)
        .context("CBS state model fixture omits notes[]")?;
    ensure!(notes.iter().any(|note| {
        note.as_str()
            == Some(
                "No ordinary Event requires a fresh Seal, origin countersignature or periodic lease.",
            )
    }));
    let vectors = fixture
        .get("vectors")
        .and_then(Value::as_array)
        .context("CBS state model fixture omits vectors[]")?;
    ensure!(!vectors.is_empty());
    let mut ids = BTreeSet::new();
    for vector in vectors {
        let id = vector
            .get("vector_id")
            .and_then(Value::as_str)
            .context("CBS vector omits vector_id")?;
        ensure!(ids.insert(id), "duplicate CBS vector {id}");
        if let Some(model) = vector.get("state_model").and_then(Value::as_str) {
            ensure!(STATE_MODELS.contains(&model), "unknown state model {model}");
        }
    }
    for (vector_id, expected_model) in MODEL_BOUND_VECTORS {
        let vector = vectors
            .iter()
            .find(|vector| vector.get("vector_id").and_then(Value::as_str) == Some(*vector_id))
            .with_context(|| format!("CBS fixture omits state-model vector {vector_id}"))?;
        ensure!(
            vector.get("state_model").and_then(Value::as_str) == Some(*expected_model),
            "CBS vector {vector_id} is not bound to {expected_model}"
        );
    }

    validate_single_authority_configuration(vectors)?;
    validate_resolution_confirmation_refailure(vectors)?;
    validate_inclusion_obligation(vectors)?;

    let ordinary = vectors
        .iter()
        .find(|vector| {
            vector.get("name").and_then(Value::as_str)
                == Some("ordinary_event_accepts_without_seal_finality")
        })
        .context("CBS fixture omits ordinary offline acceptance vector")?;
    let offline = ordinary
        .get("cases")
        .and_then(Value::as_array)
        .and_then(|cases| {
            cases.iter().find(|case| {
                case.get("name").and_then(Value::as_str) == Some("origin_offline_cached_authority")
            })
        })
        .context("CBS fixture omits offline cached authority case")?;
    ensure!(offline.get("origin_online") == Some(&Value::Bool(false)));
    ensure!(offline.pointer("/expected/accept_live") == Some(&Value::Bool(true)));
    ensure!(offline.pointer("/expected/new_seal_required") == Some(&Value::Bool(false)));
    ensure!(
        ordinary
            .get("description")
            .and_then(Value::as_str)
            .is_some_and(|description| description.contains("portable cached authority"))
    );

    let canonical = arkret_canonical::canonical_json_bytes(&fixture)?;
    for removed in [
        "station_admission",
        "single_signer",
        "open_set",
        "mv_register",
        "cas_register",
    ] {
        if canonical
            .windows(removed.len())
            .any(|window| window == removed.as_bytes())
        {
            bail!("CBS fixture retains removed state/admission term {removed}");
        }
    }
    Ok(())
}

fn validate_resolution_confirmation_refailure(vectors: &[Value]) -> Result<()> {
    let vector = vectors
        .iter()
        .find(|vector| {
            vector.get("vector_id").and_then(Value::as_str)
                == Some("ak.vector.cbs_lattice.sealed_control_move_full_digest_collision.v1")
        })
        .context("CBS fixture omits fork-resolution collision vector")?;
    let case = vector
        .get("cases")
        .and_then(Value::as_array)
        .and_then(|cases| {
            cases.iter().find(|case| {
                case.get("name").and_then(Value::as_str)
                    == Some("resolution_confirmation_failure_refails_closed_after_clear")
            })
        })
        .context("fork-resolution vector omits confirmation-refailure case")?;
    ensure!(
        case.get("resolution_confirmation_after_clear")
            .and_then(Value::as_str)
            == Some("invalid")
            && case
                .get("new_unadjudicated_subject")
                .and_then(Value::as_bool)
                == Some(true)
            && case.get("expected").and_then(Value::as_str) == Some("requarantine_peer")
            && case.get("resolution_cell_status_after_clear").is_none(),
        "fork-resolution refailure must be confirmation-based and must not use security Bottom"
    );
    Ok(())
}

fn validate_inclusion_obligation(vectors: &[Value]) -> Result<()> {
    let vector = vectors
        .iter()
        .find(|vector| {
            vector.get("vector_id").and_then(Value::as_str)
                == Some("ak.vector.cbs_lattice.inclusion_list_obligation.v1")
        })
        .context("CBS fixture omits inclusion-list obligation vector")?;
    let cases = vector["cases"]
        .as_array()
        .context("inclusion-list vector omits cases")?;
    // These are fixture verdicts; only a confirmed command result can discharge
    // the obligation, including when that command result is a rejection.
    for (name, action, result, reason) in [
        ("next_seal_includes_digest", "include", "accept", None),
        (
            "next_seal_records_rejected_command_result",
            "rejected_command_result",
            "accept",
            None,
        ),
        (
            "standalone_verification_failure_is_not_terminal",
            "pre_state_failure_proof",
            "reject",
            Some("inclusion_list_violation"),
        ),
        (
            "next_seal_omits_obligation",
            "omit",
            "reject",
            Some("inclusion_list_violation"),
        ),
    ] {
        let matching = cases
            .iter()
            .filter(|case| case["name"] == name)
            .collect::<Vec<_>>();
        ensure!(
            matching.len() == 1,
            "inclusion-list fixture must contain exactly one {name}"
        );
        let case = matching[0];
        ensure!(
            case["seal_action"] == action
                && case["expected"]["seal_result"] == result
                && case["expected"]["reason"].as_str() == reason,
            "inclusion-list case {name} must require a unique Seal command outcome"
        );
    }
    Ok(())
}

fn validate_single_authority_configuration(vectors: &[Value]) -> Result<()> {
    let vector = vectors
        .iter()
        .find(|vector| {
            vector["vector_id"] == "ak.vector.cbs_lattice.single_authority_configuration.v1"
        })
        .context("CBS fixture omits single authority configuration")?;
    for case in vector["cases"].as_array().context("notary cases missing")? {
        let parsed = serde_json::from_value::<NotaryValue>(case["instance"].clone());
        let accepted = parsed
            .and_then(|value| value.validate().map_err(serde::de::Error::custom))
            .is_ok();
        ensure!(
            accepted
                == case["expect_valid"]
                    .as_bool()
                    .context("notary verdict missing")?,
            "notary configuration {} differs from SDK",
            case["name"]
        );
    }
    Ok(())
}
