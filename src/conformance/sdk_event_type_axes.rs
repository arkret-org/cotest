//! SDK023 executes compiler fragments against a supplied exact SDK artifact.
//! Loading a prior adapter report never counts as running this suite.

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, ensure};
use serde_json::Value;

use super::{CaseExecutionResult, SuiteExecutionResult, spec_artifacts_root};

pub const SDK_EVENT_TYPE_AXES_ENTRYPOINT: &str = "ak.suite.sdk.event_type_axes.v1";

pub fn run_sdk_event_type_axes_suite() -> Result<SuiteExecutionResult> {
    let manifest = std::env::var_os("COTEST_SDK_ARTIFACT_MANIFEST")
        .map(PathBuf::from)
        .context("SDK023 requires COTEST_SDK_ARTIFACT_MANIFEST naming the exact SDK artifact; no SDK rebuild or cached-report substitution is permitted")?;
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let directory = std::env::var_os("COTEST_SDK_TYPE_AXES_OUTPUT_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join("artifacts/security-evidence/sdk-event-type-axes"));
    fs::create_dir_all(&directory)?;
    let output = directory.join(format!(
        "{}-{}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
    ));
    let run = Command::new("python")
        .args(["-X", "utf8"])
        .arg(root.join("scripts/sdk_event_type_axes.py"))
        .arg("--artifacts")
        .arg(spec_artifacts_root())
        .arg("--artifact-manifest")
        .arg(manifest)
        .arg("--output")
        .arg(&output)
        .output()
        .context("execute the Rust SDK023 artifact adapter")?;
    fs::write(output.join("adapter.stdout"), &run.stdout)?;
    fs::write(output.join("adapter.stderr"), &run.stderr)?;
    ensure!(
        run.status.success(),
        "SDK023 artifact adapter failed; evidence: {}: {}",
        output.display(),
        String::from_utf8_lossy(&run.stderr)
    );
    let report: Value = serde_json::from_slice(&fs::read(output.join("result.json"))?)?;
    ensure!(
        report["entrypoint"] == SDK_EVENT_TYPE_AXES_ENTRYPOINT
            && report["fixture"] == "sdk-event-type-axes-fixture.json"
            && report["complete"] == true,
        "SDK023 artifact adapter did not complete its canonical cases"
    );
    let cases = report["cases"]
        .as_array()
        .context("SDK023 adapter omitted case execution results")?
        .iter()
        .map(|case| {
            ensure!(case["passed"] == true, "SDK023 case failed: {case}");
            Ok(CaseExecutionResult {
                case_id: case["case_id"]
                    .as_str()
                    .context("SDK023 case id")?
                    .to_owned(),
                assertions: usize::try_from(
                    case["assertions"]
                        .as_u64()
                        .context("SDK023 assertion count")?,
                )?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let execution = SuiteExecutionResult {
        entrypoint: SDK_EVENT_TYPE_AXES_ENTRYPOINT,
        fixture: "sdk-event-type-axes-fixture.json",
        cases,
    };
    let fixture: Value = serde_json::from_slice(&fs::read(
        spec_artifacts_root().join("fixtures/sdk-event-type-axes-fixture.json"),
    )?)?;
    execution.assert_complete_against(&fixture)?;
    println!(
        "[sdk-event-type-axes] cases={} artifact={} evidence={}",
        execution.cases.len(),
        report["artifact"]["sdk"]["sha256"],
        output.display()
    );
    Ok(execution)
}

#[cfg(test)]
mod tests {
    #[test]
    fn exact_sdk_artifact_executes_every_canonical_type_axis_case() -> anyhow::Result<()> {
        super::run_sdk_event_type_axes_suite()?;
        Ok(())
    }
}
