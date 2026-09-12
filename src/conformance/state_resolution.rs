use std::collections::BTreeSet;

use anyhow::{Context, Result, bail, ensure};
use arkret_wire::{DidCoreId, NotaryValue};
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

    validate_quorum_geometry(vectors)?;
    validate_resolution_confirmation_refailure(vectors)?;

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

fn validate_quorum_geometry(vectors: &[Value]) -> Result<()> {
    let vector = vectors
        .iter()
        .find(|vector| {
            vector.get("vector_id").and_then(Value::as_str)
                == Some("ak.vector.cbs_lattice.quorum_geometry.v1")
        })
        .context("CBS fixture omits quorum geometry vector")?;
    let cases = vector
        .get("cases")
        .and_then(Value::as_array)
        .context("quorum geometry vector omits cases[]")?;
    for case in cases {
        let name = case
            .get("name")
            .and_then(Value::as_str)
            .context("quorum geometry case omits name")?;
        ensure!(
            case.pointer("/notary/kind").and_then(Value::as_str) == Some("quorum"),
            "{name} uses a removed notary kind"
        );
        let signer_count = case
            .pointer("/notary/signer_count")
            .and_then(Value::as_u64)
            .and_then(|count| usize::try_from(count).ok())
            .context("quorum geometry signer_count is invalid")?;
        let fault_tolerance = case
            .pointer("/notary/fault_tolerance")
            .and_then(Value::as_u64)
            .and_then(|value| u32::try_from(value).ok())
            .context("quorum geometry fault_tolerance is invalid")?;
        let signers = (0..signer_count)
            .map(|index| {
                DidCoreId::new(format!("ak:did_core:web:notary-{index}.cotest.invalid"))
                    .map_err(anyhow::Error::msg)
                    .map(crate::fixture_notary_signer)
            })
            .collect::<Result<Vec<_>>>()?;
        let configuration = NotaryValue::new(signers, fault_tolerance, 0);
        let expected_accept =
            case.pointer("/expected/result").and_then(Value::as_str) == Some("accept");
        match (configuration, expected_accept) {
            (Ok(configuration), true) => {
                let expected_quorum = case
                    .pointer("/expected/quorum")
                    .and_then(Value::as_u64)
                    .and_then(|value| usize::try_from(value).ok())
                    .context("accepted quorum case omits expected quorum")?;
                let present = case
                    .get("present_commit_signatures")
                    .and_then(Value::as_u64)
                    .and_then(|value| usize::try_from(value).ok())
                    .context("accepted quorum case omits signature count")?;
                ensure!(
                    configuration.quorum_size() == expected_quorum && present >= expected_quorum,
                    "{name} diverges from SDK quorum geometry"
                );
            }
            (Err(_), false) => ensure!(
                case.pointer("/expected/reason").and_then(Value::as_str)
                    == Some("schema_violation"),
                "{name} rejected for an unexpected reason"
            ),
            (Ok(configuration), false) => {
                let present = case
                    .get("present_commit_signatures")
                    .and_then(Value::as_u64)
                    .and_then(|value| usize::try_from(value).ok())
                    .context("rejected quorum case omits signature count")?;
                ensure!(
                    present < configuration.quorum_size()
                        && case.pointer("/expected/reason").and_then(Value::as_str)
                            == Some("seal_signer_unauthorized"),
                    "{name} does not exercise an insufficient commit quorum"
                );
            }
            (Err(error), true) => bail!("{name} unexpectedly has invalid quorum geometry: {error}"),
        }
    }
    ensure!(
        cases.len() == 4,
        "quorum geometry fixture must retain four cases"
    );
    Ok(())
}
