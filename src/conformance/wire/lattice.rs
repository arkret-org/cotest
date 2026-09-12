use std::collections::BTreeSet;

use anyhow::{Context, Result, ensure};
use arkret_wire::EventCellStateModel;
use serde_json::Value;

use super::load_local_fixture;

const STATE_MODELS: &[&str] = &[
    "causal_register",
    "sequenced_state",
    "or_set",
    "counter",
    "ordered_log",
];

pub fn run_event_kind_lattice_dispatch_fixture_suite() -> Result<()> {
    let fixture = crate::conformance::load_artifact_json(
        "fixtures/event-kind-lattice-dispatch-fixture.json",
    )?;
    ensure!(
        fixture.get("suite").and_then(Value::as_str) == Some("event_kind_lattice_dispatch_fixture")
    );
    let assertions = fixture
        .get("assertions")
        .and_then(Value::as_array)
        .context("dispatch fixture omits assertions[]")?;
    ensure!(!assertions.is_empty());

    let mut used = BTreeSet::new();
    for descriptor in arkret_wire::EVENT_KIND_DESCRIPTORS {
        for write in descriptor.cell_writes {
            if let Some(model) = write.state_model {
                ensure!(STATE_MODELS.contains(&model.as_str()));
                if model != EventCellStateModel::CausalRegister {
                    ensure!(
                        write.bottom.is_none(),
                        "non-causal state model {} declares a Bottom policy",
                        model.as_str()
                    );
                }
                used.insert(model.as_str());
            }
        }
    }
    ensure!(used == STATE_MODELS.iter().copied().collect());
    Ok(())
}

pub fn run_event_kind_payload_coverage_fixture_suite() -> Result<()> {
    let fixture = crate::conformance::load_artifact_json(
        "fixtures/event-kind-payload-coverage-fixture.json",
    )?;
    ensure!(
        fixture
            .get("runner")
            .and_then(|runner| runner.get("kind"))
            .and_then(Value::as_str)
            .is_some()
    );
    let bytes = arkret_canonical::canonical_json_bytes(&fixture)?;
    for removed in ["mv_register", "cas_register", "ak.fsm"] {
        ensure!(
            !bytes
                .windows(removed.len())
                .any(|window| window == removed.as_bytes()),
            "payload coverage fixture retains {removed}"
        );
    }
    Ok(())
}

pub fn run_constraint_family_fixture_suite() -> Result<()> {
    validate_local_cases("constraint_family_fixture.json")
}

pub fn run_constraint_evaluation_class_fixture_suite() -> Result<()> {
    validate_local_cases("constraint_evaluation_class_fixture.json")
}

fn validate_local_cases(file: &str) -> Result<()> {
    let fixture = load_local_fixture(file)?;
    let cases = fixture
        .get("cases")
        .or_else(|| fixture.get("vectors"))
        .and_then(Value::as_array)
        .context("constraint fixture omits cases/vectors")?;
    ensure!(!cases.is_empty());
    for case in cases {
        ensure!(case.get("name").and_then(Value::as_str).is_some());
    }
    Ok(())
}
