//! Event payload coverage against the source and generated registries.

use std::collections::BTreeSet;

use anyhow::{Context, Result, bail};

use crate::conformance::{load_artifact_json, schema_validation_fixture};

pub fn run_event_kind_payload_coverage_fixture_suite() -> Result<()> {
    let fixture = load_artifact_json("fixtures/event-kind-payload-coverage-fixture.json")?;
    if fixture["suite"] != "event_kind_payload_coverage_fixture"
        || fixture["runner"]["kind"] != "registry_coverage"
    {
        bail!("event-kind payload coverage fixture identity drifted");
    }
    let cases: schema_validation_fixture::SchemaValidationFixture =
        serde_json::from_value(fixture.clone())?;
    schema_validation_fixture::run_cases(&cases.schema_validation_cases)?;

    let source = load_artifact_json("registry/contract-registry.json")?;
    let generated = load_artifact_json("registry/event-kind-registry.json")?;
    let source_rows = source["event_kind_registry"]["event_kinds"]
        .as_array()
        .context("source event kind registry missing event_kinds")?;
    let generated_rows = generated["event_kinds"]
        .as_array()
        .context("generated event kind registry missing event_kinds")?;
    let source_kinds = source_rows
        .iter()
        .map(|row| {
            row["event_kind"]
                .as_str()
                .context("source row missing event_kind")
        })
        .collect::<Result<BTreeSet<_>>>()?;
    let generated_kinds = generated_rows
        .iter()
        .map(|row| {
            row["event_kind"]
                .as_str()
                .context("generated row missing event_kind")
        })
        .collect::<Result<BTreeSet<_>>>()?;
    if source_kinds.len() != source_rows.len()
        || generated_kinds.len() != generated_rows.len()
        || source_kinds != generated_kinds
    {
        bail!("source and generated event-kind registries are not bijective");
    }
    for row in generated_rows {
        if row["status"] == "active" && row["payload_schema_ref"].as_str().is_none_or(str::is_empty)
        {
            bail!("active event kind has no explicit payload schema reference");
        }
    }
    Ok(())
}
