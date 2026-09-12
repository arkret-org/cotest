use std::collections::BTreeSet;

use anyhow::{Context, Result, ensure};
use arkret::state_model::ordered_log::IssuedOp;
use arkret::state_model::{
    Counter, OrSet, OrderedLog, ResolvedCellState, StateModel, StateModelKind, StateWrite,
};
use arkret::{
    ActorId, CanonicalCellState, CellRef, DidCoreId, EventCellStateModel, EventId, Hash, LatticeOp,
    LatticeOpType,
};
use serde_json::{Value, json};

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
        let events = kind.event_kinds();
        if kind == StateModelKind::Counter {
            ensure!(
                events.is_empty(),
                "v1 must not invent a built-in counter Cell family"
            );
        } else {
            ensure!(!events.is_empty(), "unused state model {kind:?}");
        }
    }
    assert_canonical_collection_model_states()?;
    Ok(())
}

fn assert_canonical_collection_model_states() -> Result<()> {
    let issuer = ActorId::service(DidCoreId::new(
        "ak:did_core:webvh:z6mkfixturealice".to_owned(),
    )?);
    let event_digest = Hash::new(format!("sha256:{}", "11".repeat(32)))?;
    let event_id = EventId::from_event_digest(&event_digest)?;
    let dot = format!("{event_id}:0");

    let or_set_ops = [
        StateWrite::new(
            event_id.clone(),
            lattice_op(
                LatticeOpType::Add,
                Some(dot.clone()),
                Some(json!("entry")),
                None,
            ),
        ),
        StateWrite::new(
            Hash::new(format!("sha256:{}", "22".repeat(32)))?,
            lattice_op(LatticeOpType::Remove, Some(dot), None, None),
        ),
    ];
    let ResolvedCellState::Value(or_set_value) =
        OrSet.resolve(&fixture_cell("or_set"), &or_set_ops)?
    else {
        anyhow::bail!("OR-set did not return its canonical value")
    };
    let or_set = CanonicalCellState::from_state_object(
        EventCellStateModel::OrSet,
        json!({"value": or_set_value}),
    )?;
    let CanonicalCellState::OrSet(or_set) = or_set else {
        anyhow::bail!("OR-set canonical state decoded as another model")
    };
    ensure!(or_set.value.adds.len() == 1);
    ensure!(or_set.value.removed_tag_ids.len() == 1);
    ensure!(
        CanonicalCellState::from_state_object(
            EventCellStateModel::OrSet,
            json!({"value":[{"tag":"legacy","value":"entry"}]})
        )
        .is_err(),
        "legacy visible-only OR-set arrays must fail closed"
    );

    let counter_ops = [
        IssuedOp {
            issuer_id: issuer.clone(),
            op: StateWrite::new(
                event_id.clone(),
                lattice_op(LatticeOpType::Inc, None, Some(json!(5)), None),
            ),
        },
        IssuedOp {
            issuer_id: issuer.clone(),
            op: StateWrite::new(
                Hash::new(format!("sha256:{}", "33".repeat(32)))?,
                lattice_op(LatticeOpType::Dec, None, Some(json!(2)), None),
            ),
        },
    ];
    let ResolvedCellState::Value(counter_value) =
        Counter.join_with_issuers(&fixture_cell("counter"), &counter_ops)?
    else {
        anyhow::bail!("counter did not return its canonical value")
    };
    let counter = CanonicalCellState::from_state_object(
        EventCellStateModel::Counter,
        json!({"value": counter_value}),
    )?;
    let CanonicalCellState::Counter(counter) = counter else {
        anyhow::bail!("counter canonical state decoded as another model")
    };
    ensure!(counter.value.len() == 1);
    ensure!(counter.value[0].issuer_id == issuer);
    ensure!(counter.value[0].positive == 5 && counter.value[0].negative == 2);
    ensure!(
        CanonicalCellState::from_state_object(EventCellStateModel::Counter, json!({"value": 3}))
            .is_err(),
        "legacy scalar counter state must fail closed"
    );

    let log_ops = [IssuedOp {
        issuer_id: issuer.clone(),
        op: StateWrite::new(
            event_id.clone(),
            lattice_op(LatticeOpType::Append, None, Some(json!("entry")), Some(7)),
        ),
    }];
    let ResolvedCellState::Value(log_value) =
        OrderedLog.join_with_issuers(&fixture_cell("ordered_log"), &log_ops)?
    else {
        anyhow::bail!("ordered log did not return its canonical value")
    };
    let log = CanonicalCellState::from_state_object(
        EventCellStateModel::OrderedLog,
        json!({"value": log_value}),
    )?;
    let CanonicalCellState::OrderedLog(log) = log else {
        anyhow::bail!("ordered-log canonical state decoded as another model")
    };
    ensure!(log.value.len() == 1);
    ensure!(log.value[0].event_digest == event_digest);
    ensure!(log.value[0].issuer_id == issuer);
    ensure!(
        serde_json::to_value(&log.value[0])?["event_digest"] != json!(event_id.clone()),
        "ordered-log Event identity must serialize as a digest, not EventId"
    );
    ensure!(
        CanonicalCellState::from_state_object(
            EventCellStateModel::OrderedLog,
            json!({"value":[{
                "event_digest": event_id,
                "issuer_id": "ak:did_core:webvh:z6mkfixturealice",
                "issuer_seq": 7,
                "value": "entry"
            }]})
        )
        .is_err(),
        "legacy EventId/string-issuer ordered-log entries must fail closed"
    );
    Ok(())
}

fn fixture_cell(suffix: &str) -> CellRef {
    CellRef::new(format!("ak:cell:ak.component.cotest.{suffix}.v1:test"))
        .expect("fixture CellRef is valid")
}

fn lattice_op(
    op_type: LatticeOpType,
    tag: Option<String>,
    value: Option<Value>,
    issuer_seq: Option<u64>,
) -> LatticeOp {
    LatticeOp {
        op_type,
        tag,
        value,
        from: None,
        to: None,
        reason: None,
        issuer_seq,
    }
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
