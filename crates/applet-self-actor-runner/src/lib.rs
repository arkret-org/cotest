//! Contract models plus production SDK signature and MLS isolation seams.
//! No live Station, database, delegated-device admission or runtime claim.

use std::path::PathBuf;
use std::process::Command;

use anyhow::{Context, Result, ensure};
use arkret_canonical::base64url::base64url_decode;
use arkret_signatures::PublicKeyMaterial;
use arkret_signatures::detached_object::verify_detached_object_signature;
use arkret_wire::{DetachedObjectSignature, DetachedSignatureContext};
use serde_json::Value;

mod mls_isolation;

pub const APPLET_SELF_ACTOR_ENTRYPOINT: &str = "ak.suite.applet.self_actor_contract.v1";
pub const FIXTURE: &str = "applet-self-actor-fixture.json";

pub struct CaseExecutionResult {
    pub case_id: String,
    pub assertions: usize,
}

pub struct AppletSelfActorExecution {
    pub entrypoint: &'static str,
    pub fixture: &'static str,
    pub cases: Vec<CaseExecutionResult>,
}

fn spec_root() -> PathBuf {
    if let Some(root) = std::env::var_os("COTEST_SPEC_ROOT") {
        return PathBuf::from(root);
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../arkret-spec")
}

fn sdk_signature_kats(fixture: &Value) -> Result<()> {
    for (name, context) in [
        ("invocation", DetachedSignatureContext::AppletDisclosure),
        ("result", DetachedSignatureContext::AppletResult),
    ] {
        let case = &fixture["signature_kats"][name];
        let mut projection = case["host_object"].clone();
        let signature: DetachedObjectSignature = serde_json::from_value(
            projection
                .as_object_mut()
                .context("host object")?
                .remove("signature")
                .context("signature")?,
        )?;
        let key = PublicKeyMaterial::Ed25519Raw {
            bytes: base64url_decode(case["public_key_b64u"].as_str().context("public key")?)?,
        };
        verify_detached_object_signature(&signature, &projection, context, &key)?;
        for field in [
            "body",
            "registration_epoch",
            "registration_ref",
            "applet_actor_id",
        ] {
            let mut altered = projection.clone();
            altered[field] = Value::String("tampered".into());
            ensure!(
                verify_detached_object_signature(&signature, &altered, context, &key).is_err(),
                "SDK accepted altered {field}"
            );
        }
        ensure!(
            verify_detached_object_signature(
                &signature,
                &projection,
                DetachedSignatureContext::RealmCommit,
                &key
            )
            .is_err(),
            "SDK accepted another signature domain"
        );
    }
    Ok(())
}

pub fn run_applet_self_actor_suite() -> Result<AppletSelfActorExecution> {
    let root = spec_root();
    let fixture: Value = serde_json::from_slice(&std::fs::read(
        root.join("spec/v1/artifacts/fixtures").join(FIXTURE),
    )?)?;
    ensure!(fixture["runner"]["entrypoint"] == APPLET_SELF_ACTOR_ENTRYPOINT);
    let output = Command::new(std::env::var_os("COTEST_PYTHON").unwrap_or_else(|| "python".into()))
        .args([
            "-m",
            "tools.check_applet_self_actor_contract",
            "--report-json",
        ])
        .current_dir(&root)
        .output()
        .context("execute authoritative contract tests")?;
    ensure!(
        output.status.success(),
        "contract gate failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout)?;
    let mut cases = report["passed"]
        .as_array()
        .context("executed case report")?
        .iter()
        .map(|name| {
            Ok(CaseExecutionResult {
                case_id: name.as_str().context("test name")?.to_owned(),
                assertions: 1,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    sdk_signature_kats(&fixture)?;
    cases.push(CaseExecutionResult {
        case_id: "sdk_detached_plaintext_signatures".into(),
        assertions: 12,
    });
    mls_isolation::verify()?;
    cases.push(CaseExecutionResult {
        case_id: "sdk_mls_invocation_circle_isolation".into(),
        assertions: 5,
    });
    let expected = fixture["cases"].as_array().context("case inventory")?;
    let mut expected_names: Vec<_> = expected
        .iter()
        .map(|c| c["name"].as_str().unwrap_or_default())
        .collect();
    let mut actual_names: Vec<_> = cases.iter().map(|c| c.case_id.as_str()).collect();
    expected_names.sort_unstable();
    actual_names.sort_unstable();
    ensure!(
        expected_names == actual_names,
        "published case set differs from executed cases"
    );
    Ok(AppletSelfActorExecution {
        entrypoint: APPLET_SELF_ACTOR_ENTRYPOINT,
        fixture: FIXTURE,
        cases,
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn executes_contract_models_and_sdk_crypto_without_claiming_live_support() {
        let execution = super::run_applet_self_actor_suite().unwrap();
        assert!(execution.cases.iter().all(|case| case.assertions > 0));
    }
}
