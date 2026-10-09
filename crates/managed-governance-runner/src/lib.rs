//! Canonical protocol reference tests plus native SDK Device signatures and MLS.
//! These component checks do not claim live Station authorization or delivery.
use std::path::PathBuf;
use std::process::Command;

use anyhow::{Context, Result, ensure};
use arkret_canonical::base64url::base64url_decode;
use arkret_models_integration::applet_models::AppletManagedDeviceMetadata;
use arkret_signatures::http_signature::{
    HttpSignatureScenario, SignatureVerificationPolicy, encode_signature_b64,
    public_key_from_bytes, verify_signed_http_message,
};
use serde_json::Value;

mod mls_isolation;

pub const MANAGED_GOVERNANCE_ENTRYPOINT: &str = "ak.suite.managed_governance.v1";
pub const FIXTURE: &str = "managed-governance-fixture.json";

fn spec_root() -> PathBuf {
    std::env::var_os("COTEST_SPEC_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../arkret-spec"))
}

fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value[key]
        .as_str()
        .with_context(|| format!("fixture string {key}"))
}

fn sdk_device_signature_kat(fixture: &Value) -> Result<()> {
    let case = &fixture["device_request"];
    let metadata: AppletManagedDeviceMetadata = serde_json::from_value(case["metadata"].clone())?;
    let encoded = metadata.to_header_value()?;
    ensure!(encoded == text(&case["components"], "arkret-managed-device")?);
    ensure!(AppletManagedDeviceMetadata::from_header_value(&encoded)? == metadata);
    let key = public_key_from_bytes(&base64url_decode(text(case, "public_key_b64u")?)?)?;
    let mut headers: Vec<(String, String)> = case["components"]
        .as_object()
        .context("covered components")?
        .iter()
        .filter(|(name, _)| !name.starts_with('@'))
        .map(|(name, value)| {
            Ok((
                name.clone(),
                value.as_str().context("header string")?.to_owned(),
            ))
        })
        .collect::<Result<_>>()?;
    headers.push((
        "signature-input".into(),
        format!("sig1={}", text(case, "signature_params")?),
    ));
    headers.push((
        "signature".into(),
        format!(
            "sig1=:{}:",
            encode_signature_b64(&base64url_decode(text(case, "signature_b64u")?)?)
        ),
    ));
    let policy = SignatureVerificationPolicy::for_scenario(
        HttpSignatureScenario::AppletManagedDeviceV1,
        &[],
    )?;
    let verify = |headers: &[(String, String)]| {
        verify_signed_http_message(
            "GET",
            text(&case["components"], "@target-uri").unwrap(),
            "station.example",
            "/_arkret/self/device_messages",
            headers.iter().map(|(n, v)| (n, v)),
            &[],
            &key,
            &policy,
            1791504000,
        )
    };
    verify(&headers)?;
    for field in [
        "account_id",
        "device_id",
        "authorization_event_id",
        "applet_id",
        "effective_scope",
        "nonce",
    ] {
        let mut altered = case["metadata"].clone();
        altered[field] = Value::String("tampered".into());
        let mut changed = headers.clone();
        let bytes = arkret_canonical::canonical_json_bytes(&altered)?;
        changed
            .iter_mut()
            .find(|(n, _)| n == "arkret-managed-device")
            .unwrap()
            .1 = arkret_canonical::base64url_encode(bytes);
        ensure!(verify(&changed).is_err(), "SDK accepted altered {field}");
    }
    let without_metadata: Vec<_> = headers
        .into_iter()
        .filter(|(n, _)| n != "arkret-managed-device")
        .collect();
    ensure!(
        verify(&without_metadata).is_err(),
        "SDK accepted missing covered metadata"
    );
    Ok(())
}

pub fn run_managed_governance_suite() -> Result<()> {
    let root = spec_root();
    let fixture: Value = serde_json::from_slice(&std::fs::read(
        root.join("spec/v1/artifacts/fixtures").join(FIXTURE),
    )?)?;
    ensure!(fixture["runner"]["entrypoint"] == MANAGED_GOVERNANCE_ENTRYPOINT);
    // Run the authoritative reference model as reference evidence, never as SUT execution.
    let output = Command::new(std::env::var_os("COTEST_PYTHON").unwrap_or_else(|| "python".into()))
        .args(["-m", "tools.test_managed_governance_contract"])
        .current_dir(&root)
        .output()
        .context("execute canonical management reference decisions")?;
    ensure!(
        output.status.success(),
        "protocol reference gate failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    sdk_device_signature_kat(&fixture)?;
    mls_isolation::verify()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn reference_and_sdk_components_do_not_claim_live_management_support() {
        super::run_managed_governance_suite().unwrap();
    }
}
