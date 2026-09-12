use std::collections::BTreeSet;

use anyhow::{Context, Result, ensure};
use arkret_state::state_model::StateModelKind;
use serde_json::Value;

use super::{load_fixture_value, validate_profile};

const ROUND_TRIP_VECTOR_IDS: &[&str] = &[
    "ak.vector.lattice.causal_register_join.v1",
    "ak.vector.lattice.counter_join.v1",
    "ak.vector.lattice.ordered_log_join.v1",
    "ak.vector.lattice.ordered_log_gap.v1",
    "ak.vector.state_model.causal_transition_validation.v1",
    "ak.vector.lattice.causal_register_supersession.v1",
    "ak.vector.realm_link.transition_matrix.v1",
];

const ROUND_TRIP_MODELS: &[&str] = &[
    "causal_register",
    "counter",
    "ordered_log",
    "ordered_log",
    "causal_register",
    "causal_register",
    "causal_register",
];

pub fn run_state_model_round_trip_suite() -> Result<()> {
    let fixture = load_fixture_value("cbs-lattice-fixture.json")?;
    validate_profile(&fixture, "ak.vector_group.cbs_lattice.v1")?;
    let metadata = fixture
        .get("lattice_round_trip")
        .context("CBS fixture omits state model runner metadata")?;
    ensure!(
        metadata.get("runner").and_then(Value::as_str)
            == Some("ak.suite.authz.cbs_lattice.round_trip.v1")
    );
    let covered = strings(metadata.get("covers_vectors"))?;
    ensure!(covered == ROUND_TRIP_VECTOR_IDS);
    let cases = metadata
        .get("cases")
        .and_then(Value::as_array)
        .context("CBS fixture omits round-trip cases")?;
    ensure!(cases.len() == ROUND_TRIP_VECTOR_IDS.len());
    for ((case, vector_id), expected_model) in cases
        .iter()
        .zip(ROUND_TRIP_VECTOR_IDS)
        .zip(ROUND_TRIP_MODELS)
    {
        ensure!(
            case.get("vector_id").and_then(Value::as_str) == Some(*vector_id),
            "round-trip case order or vector id drifted"
        );
        let model = case
            .get("state_model")
            .and_then(Value::as_str)
            .context("round-trip case omits state_model")?;
        ensure!(known_model(model));
        ensure!(
            model == *expected_model,
            "round-trip vector {vector_id} uses {model}, expected {expected_model}"
        );
        ensure!(
            case.get("assertions")
                .and_then(Value::as_array)
                .is_some_and(|assertions| !assertions.is_empty())
        );
    }

    let registered = [
        StateModelKind::CausalRegister,
        StateModelKind::SequencedState,
        StateModelKind::OrSet,
        StateModelKind::Counter,
        StateModelKind::OrderedLog,
    ];
    ensure!(
        registered
            .iter()
            .map(|kind| kind.as_wire_str())
            .collect::<BTreeSet<_>>()
            .len()
            == 5
    );
    for kind in registered {
        ensure!(
            !kind.event_kinds().is_empty(),
            "unused state model {kind:?}"
        );
    }
    Ok(())
}

fn strings(value: Option<&Value>) -> Result<Vec<&str>> {
    value
        .and_then(Value::as_array)
        .context("expected string array")?
        .iter()
        .map(|value| value.as_str().context("expected string"))
        .collect()
}

fn known_model(value: &str) -> bool {
    matches!(
        value,
        "causal_register" | "sequenced_state" | "or_set" | "counter" | "ordered_log"
    )
}
