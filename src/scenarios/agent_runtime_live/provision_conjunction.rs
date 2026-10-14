//! Full provision evidence joins real native admission with a fresh browser run.

use std::fs;
use std::path::Path;
use std::process::Command;

use super::*;
use crate::conformance::{CaseExecutionResult, SuiteExecutionResult};

fn capture_inputs(root: &Path, output: &Path) -> Result<serde_json::Value> {
    let status = Command::new("python")
        .args(["-X", "utf8"])
        .arg(root.join("cotest/scripts/record-security-source-inputs.py"))
        .arg(root)
        .arg(output)
        .status()?;
    ensure!(status.success(), "security source capture failed");
    Ok(serde_json::from_slice(&fs::read(output)?)?)
}

pub async fn run_agent_provision_production() -> Result<SuiteExecutionResult> {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR"));
    let root = repo.parent().context("joint workspace root")?;
    let output = std::env::var("COTEST_AGENT_PROVISION_JOINT_DIR")
        .context("full provision requires a fresh, owned browser evidence directory")?;
    let output = Path::new(&output);
    ensure!(
        !output.exists(),
        "provision evidence directory already exists"
    );
    fs::create_dir_all(output)?;
    let before = capture_inputs(root, &output.join("input-before.json"))?;
    let fixture: serde_json::Value = serde_json::from_slice(&fs::read(
        root.join("arkret-spec/spec/v1/artifacts/fixtures/agent-vectors-fixture.json"),
    )?)?;
    let provision = fixture["cases"]
        .as_array()
        .context("canonical Agent cases")?
        .iter()
        .find(|case| case["name"] == "agent_provision")
        .context("canonical Agent provision case")?;
    ensure!(
        provision["assertions"]
            .as_array()
            .context("provision obligations")?
            .len()
            == 20,
        "provision contract changed and requires a new semantic review"
    );

    let registry: serde_json::Value = serde_json::from_slice(&fs::read(
        root.join("arkret-spec/spec/v1/artifacts/registry/operation-registry.json"),
    )?)?;
    let operations = registry["operations"]
        .as_array()
        .context("operation registry")?;
    ensure!(
        operations.iter().any(|operation| {
            operation["operation_id"] == ServiceOperationId::SELF_AGENT_COMMAND_PROVISION_V1
                && operation["http"] == "POST /_arkret/self/agents"
        }),
        "provision operation differs from its formal registry"
    );
    let actions: serde_json::Value = serde_json::from_slice(&fs::read(
        root.join("arkret-spec/spec/v1/artifacts/registry/capability-action-registry.json"),
    )?)?;
    ensure!(
        actions["actions"]
            .as_array()
            .context("capability action registry")?
            .iter()
            .any(|action| action["action"] == ServiceOperationId::SELF_AGENT_COMMAND_PROVISION_V1),
        "provision has no matching registered capability action"
    );

    run_agent_provision_prerequisites_boundary().await?;
    run_agent_provision_key_scope_boundary().await?;
    run_agent_provision_grant_ceiling_boundary().await?;
    run_agent_requested_scope_privacy_production().await?;

    let station_db =
        database("agent-provision-browser-station")?.context("real Station database")?;
    let issuer_db = database("agent-provision-browser-issuer")?.context("real issuer database")?;
    let coland = std::env::var("COLAND_BIN").context("current Coland binary")?;
    let coauth = std::env::var("COAUTH_BIN").context("current Coauth binary")?;
    let joint = output.join("browser");
    let log = fs::File::create(output.join("browser-runner.log"))?;
    let status = Command::new("pwsh")
        .args(["-NoProfile", "-File"])
        .arg(repo.join("scripts/run-joint-e2e.ps1"))
        .arg("-JointDir")
        .arg(&joint)
        .args(["-KeepRuns", "0", "-SkipBuild", "-InksonRoot"])
        .arg(root.join("inkson"))
        .arg("-SutManifest")
        .arg(root.join("coland/Cargo.toml"))
        .arg("-ColandBin")
        .arg(coland)
        .arg("-ColandDatabaseUrl")
        .arg(&station_db.connect_url)
        .args(["-StartCoauth", "-CoauthBin"])
        .arg(coauth)
        .arg("-CoauthPostgresUrl")
        .arg(&issuer_db.connect_url)
        .args([
            "-StartMockEmail",
            "-DnsSuffix",
            "local.host",
            "-RunProfile",
            "joint-full",
            "-PlaywrightProject",
            "joint-inkson",
            "-Grep",
            "@agent-provision-(recovery-prerequisite|durable-recovery)",
            "-RequireScenario",
            "joint/agent-provision-recovery-prerequisite",
            "-ForbidSkippedTests",
        ])
        .env_remove("CARGO_TARGET_DIR")
        .stdout(log.try_clone()?)
        .stderr(log)
        .status()?;
    ensure!(status.success(), "fresh provision browser runner failed");
    let summary: serde_json::Value =
        serde_json::from_slice(&fs::read(joint.join("summary.json"))?)?;
    ensure!(
        summary["exit_code"] == 0
            && summary["test_execution"] == "executed"
            && summary["test_totals"] == json!({"passed":5,"failed":0,"skipped":0,"fixme":0}),
        "browser provision selection was not fully executed"
    );
    let scan: serde_json::Value =
        serde_json::from_slice(&fs::read(joint.join("secret-scan.json"))?)?;
    ensure!(
        scan["status"] == "passed",
        "browser evidence secret scan failed"
    );
    let junit = fs::read_to_string(joint.join("junit.xml"))?;
    for cut in ["inception", "provision", "did-binding"] {
        ensure!(
            junit.contains(&format!(
                "Agent resumes its original durable ceremony after a lost {cut} response @agent-provision-durable-recovery"
            )),
            "browser evidence omitted the {cut} recovery cut"
        );
    }
    ensure!(
        junit.contains("served Inkson bundle was built from the checked-out source")
            && !junit.contains("<failure")
            && !junit.contains("<skipped"),
        "browser source identity or recovery execution failed"
    );
    let after = capture_inputs(root, &output.join("input-after.json"))?;
    ensure!(
        before == after,
        "provision production inputs changed during acceptance"
    );
    println!(
        "[agent-provision] canonical_obligations=20 fresh_browser_cases=5 full_input_fence=11 fixture_only_bootstrap_preserved=1"
    );
    Ok(SuiteExecutionResult {
        entrypoint: "ak.suite.agent.vectors.v1",
        fixture: "agent-vectors-fixture.json",
        cases: vec![CaseExecutionResult {
            case_id: "agent_provision".into(),
            assertions: 20,
        }],
    })
}
