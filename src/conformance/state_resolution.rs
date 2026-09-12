use std::collections::BTreeSet;

use anyhow::{Context, Result, bail, ensure};
use serde_json::Value;

use super::{load_fixture_value, validate_profile};

const STATE_MODELS: &[&str] = &[
    "causal_register",
    "sequenced_state",
    "or_set",
    "counter",
    "ordered_log",
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

    let ordinary = vectors
        .iter()
        .find(|vector| {
            vector.get("name").and_then(Value::as_str)
                == Some("data_event_accepts_without_seal_finality")
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
