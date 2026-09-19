//! Explicit audit of `runner.kind = named_suite` fixtures.
//!
//! Loading a fixture is not execution. Only entrypoints in `RUNNERS` count as
//! wired here, and case-oriented runners must return one assertion-bearing
//! result per fixture case. The report intentionally retains every unwired
//! entrypoint so migration work cannot be hidden by a green fixture parser.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;

use anyhow::{Result, anyhow, ensure};
use serde_json::Value;

use super::{
    KEYPACKAGE_WRITE_TRANSCRIPTS_ENTRYPOINT, PROTOCOL_TIME_TOLERANCE_ENTRYPOINT,
    SuiteExecutionResult, run_account_status_issuer_ledger_vector,
    run_keypackage_write_transcripts_suite, run_protocol_time_tolerance_suite, spec_artifacts_root,
};

const ACCOUNT_STATUS_ENTRYPOINT: &str = "ak.suite.account_status.issuer_ledger.v1";

enum Runner {
    Cases(fn() -> Result<SuiteExecutionResult>),
    EvidenceMapped(fn() -> Result<()>),
}

const RUNNERS: [(&str, Runner); 3] = [
    (
        ACCOUNT_STATUS_ENTRYPOINT,
        Runner::EvidenceMapped(run_account_status_issuer_ledger_vector),
    ),
    (
        KEYPACKAGE_WRITE_TRANSCRIPTS_ENTRYPOINT,
        Runner::Cases(run_keypackage_write_transcripts_suite),
    ),
    (
        PROTOCOL_TIME_TOLERANCE_ENTRYPOINT,
        Runner::Cases(run_protocol_time_tolerance_suite),
    ),
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NamedSuiteAuditReport {
    pub fixture_count: usize,
    pub executed_entrypoints: Vec<String>,
    pub unwired_entrypoints: Vec<String>,
}

pub fn run_named_suite_audit() -> Result<NamedSuiteAuditReport> {
    let fixture_dir = spec_artifacts_root().join("fixtures");
    let mut fixtures = BTreeMap::new();
    for entry in fs::read_dir(&fixture_dir)? {
        let path = entry?.path();
        if path.extension().and_then(|value| value.to_str()) != Some("json") {
            continue;
        }
        let value: Value = serde_json::from_slice(&fs::read(&path)?)?;
        if value.pointer("/runner/kind").and_then(Value::as_str) != Some("named_suite") {
            continue;
        }
        let entrypoint = value
            .pointer("/runner/entrypoint")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("{} has no runner entrypoint", path.display()))?;
        ensure!(
            fixtures.insert(entrypoint.to_owned(), value).is_none(),
            "duplicate named-suite entrypoint {entrypoint}"
        );
    }

    let registered = RUNNERS
        .iter()
        .map(|(entrypoint, _)| *entrypoint)
        .collect::<BTreeSet<_>>();
    ensure!(
        registered.len() == RUNNERS.len(),
        "explicit named-suite registry contains a duplicate"
    );

    let mut executed = Vec::new();
    for (entrypoint, runner) in RUNNERS {
        let fixture = fixtures
            .get(entrypoint)
            .ok_or_else(|| anyhow!("registered runner {entrypoint} has no canonical fixture"))?;
        match runner {
            Runner::Cases(run) => {
                let result = run()?;
                ensure!(
                    result.entrypoint == entrypoint,
                    "runner returned the wrong entrypoint"
                );
                result.assert_complete_against(fixture)?;
            }
            Runner::EvidenceMapped(run) => run()?,
        }
        executed.push(entrypoint.to_owned());
    }
    executed.sort();

    let unwired = fixtures
        .keys()
        .filter(|entrypoint| !registered.contains(entrypoint.as_str()))
        .cloned()
        .collect();
    Ok(NamedSuiteAuditReport {
        fixture_count: fixtures.len(),
        executed_entrypoints: executed,
        unwired_entrypoints: unwired,
    })
}
