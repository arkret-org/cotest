//! G2 encrypted Realm Agent-member MLS primitive conformance.
//!
//! Existing cotest/browser MLS coverage proves the human-member path: encrypted
//! Realm creation, member invite, KeyPackage-backed Welcome delivery, and
//! cross-member decrypt. Agent provisioning coverage proves agent DPoP submit
//! and stream access after ordinary Realm membership. This file pins the
//! local crypto/store bridge between those two surfaces, including canonical
//! KeyPackage writes, Welcome handling, and restart recovery. It intentionally
//! does not claim live Principal Server, Account Authority, device-message, or
//! HTTP conformance; those require a separately managed Agent runtime harness.

use anyhow::{Context, Result, bail};
use arkret::{
    DeviceId, DidCoreId, Hash, KeyPackageUploadEntry, KeyPackagesConsumeUnsignedRequest,
    KeyPackagesRevokeUnsignedRequest, KeyPackagesUploadUnsignedRequest,
    keypackage_upload_entry_signing_input, keypackages_consume_signing_input,
    keypackages_revoke_signing_input, keypackages_upload_signing_input, late_device_join_steps,
    sign_keypackage_upload_entry, sign_keypackages_consume_request,
    sign_keypackages_revoke_request, sign_keypackages_upload_request,
    verify_keypackage_signing_input,
};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::SigningKey;
use serde_json::Value;

const MLS_FIXTURE: &str = include_str!("fixtures/mls_e2ee_basic_fixture.json");
const KEYPACKAGE_TRANSCRIPT_FIXTURE: &str = "fixtures/keypackage-write-transcript-fixture.json";

#[test]
fn mls_fixture_still_covers_member_join_and_aad_pinning() -> Result<()> {
    let fixture = mls_fixture()?;
    require_vector(&fixture, "member_join_via_commit")?;
    require_vector(&fixture, "encryption_aad_digest_pinning")?;
    require_negative_vector(&fixture, "aad_digest_mismatch_rejected")?;
    Ok(())
}

#[test]
fn keypackage_write_transcripts_match_the_embedded_spec_fixture() -> Result<()> {
    let fixture = arkret_schema::embedded_json_artifact(KEYPACKAGE_TRANSCRIPT_FIXTURE)?;
    let test_key = fixture
        .get("test_key")
        .context("KeyPackage transcript fixture missing test_key")?;
    let kid = test_key
        .get("kid")
        .and_then(Value::as_str)
        .context("KeyPackage transcript fixture missing test_key.kid")?;
    let seed = decode_32(test_key, "private_key_seed")?;
    let public_key = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
    assert_eq!(
        URL_SAFE_NO_PAD.encode(public_key),
        test_key
            .get("public_key")
            .and_then(Value::as_str)
            .context("KeyPackage transcript fixture missing test_key.public_key")?
    );

    for case in fixture
        .get("cases")
        .and_then(Value::as_array)
        .context("KeyPackage transcript fixture missing cases[]")?
    {
        let name = case
            .get("name")
            .and_then(Value::as_str)
            .context("KeyPackage transcript case missing name")?;
        let expected_input = URL_SAFE_NO_PAD.decode(
            case.get("signing_input_base64url")
                .and_then(Value::as_str)
                .context("KeyPackage transcript case missing signing input")?,
        )?;
        let (actual_input, signature) = match name {
            "upload_batch_required_fields" => {
                let unsigned: KeyPackagesUploadUnsignedRequest = serde_json::from_value(
                    case.get("unsigned_request")
                        .cloned()
                        .context("upload case missing unsigned_request")?,
                )?;
                (
                    keypackages_upload_signing_input(&unsigned)?,
                    sign_keypackages_upload_request(&unsigned, kid, &seed)?,
                )
            }
            "upload_entry_signature" => {
                let request = case
                    .get("unsigned_request")
                    .context("entry case missing unsigned_request")?;
                let principal_id: DidCoreId = serde_json::from_value(
                    request
                        .get("principal_id")
                        .cloned()
                        .context("entry case missing principal_id")?,
                )?;
                let device_id: DeviceId = serde_json::from_value(
                    request
                        .get("device_id")
                        .cloned()
                        .context("entry case missing device_id")?,
                )?;
                let entry: KeyPackageUploadEntry = serde_json::from_value(
                    request
                        .get("keypackage")
                        .cloned()
                        .context("entry case missing keypackage")?,
                )?;
                (
                    keypackage_upload_entry_signing_input(&principal_id, &device_id, &entry)?,
                    sign_keypackage_upload_entry(&principal_id, &device_id, &entry, kid, &seed)?,
                )
            }
            "consume_all_optional_fields" => {
                let unsigned: KeyPackagesConsumeUnsignedRequest = serde_json::from_value(
                    case.get("unsigned_request")
                        .cloned()
                        .context("consume case missing unsigned_request")?,
                )?;
                (
                    keypackages_consume_signing_input(&unsigned)?,
                    sign_keypackages_consume_request(&unsigned, kid, &seed)?,
                )
            }
            "revoke_with_reason" => {
                let unsigned: KeyPackagesRevokeUnsignedRequest = serde_json::from_value(
                    case.get("unsigned_request")
                        .cloned()
                        .context("revoke case missing unsigned_request")?,
                )?;
                (
                    keypackages_revoke_signing_input(&unsigned)?,
                    sign_keypackages_revoke_request(&unsigned, kid, &seed)?,
                )
            }
            other => bail!("unexpected KeyPackage transcript case {other}"),
        };

        if actual_input != expected_input {
            bail!(
                "case {name} signing input drifted: actual_base64url={}, actual_signature={}",
                URL_SAFE_NO_PAD.encode(&actual_input),
                signature.sig
            );
        }
        assert_eq!(
            signature.sig.as_str(),
            case.get("signature")
                .and_then(Value::as_str)
                .context("KeyPackage transcript case missing signature")?,
            "case {name}"
        );
        verify_keypackage_signing_input(&public_key, kid, &actual_input, &signature)?;
    }

    let upload_case = &fixture["cases"][0];
    let upload: KeyPackagesUploadUnsignedRequest =
        serde_json::from_value(upload_case["unsigned_request"].clone())?;
    let signature = sign_keypackages_upload_request(&upload, kid, &seed)?;
    let unregistered_domain_input = [
        b"ak.keypackage-upload-v1\n".as_slice(),
        upload_case["canonical_jcs"]
            .as_str()
            .context("upload case missing canonical_jcs")?
            .as_bytes(),
    ]
    .concat();
    assert!(
        verify_keypackage_signing_input(&public_key, kid, &unregistered_domain_input, &signature)
            .is_err()
    );
    Ok(())
}

#[test]
fn native_agent_welcome_is_not_consumed_by_human_device_recovery() -> Result<()> {
    let agent_id = arkret::DidCoreId::new("ak:did_core:web:summary-agent.example")?;
    let endpoint = arkret::MlsEndpointIdentity::native_agent_runtime(
        agent_id,
        arkret::DidUrl::new("did:web:summary-agent.example#runtime-1")
            .map_err(anyhow::Error::msg)?,
        arkret::EventId::new("ak:event:AZ405CdsF4uWwxBhArLvqgzVvWHWYcB3QJ6845E-2ET3")?,
    )?;
    let welcome = arkret::MlsWelcomeEnvelope {
        group_id: "cotest-native-agent".to_owned(),
        epoch: 1,
        recipient: endpoint,
        welcome: "AA".to_owned(),
        welcome_hash: Hash::new(format!("sha256:{}", "a".repeat(64)))?,
        ratchet_tree: None,
    };
    assert!(
        late_device_join_steps(&welcome).is_err(),
        "human-device recovery must fail closed for a Native Agent endpoint"
    );
    Ok(())
}

fn decode_32(value: &Value, field: &str) -> Result<[u8; 32]> {
    URL_SAFE_NO_PAD
        .decode(
            value
                .get(field)
                .and_then(Value::as_str)
                .with_context(|| format!("fixture missing {field}"))?,
        )?
        .try_into()
        .map_err(|bytes: Vec<u8>| anyhow::anyhow!("{field} must be 32 bytes, got {}", bytes.len()))
}

fn mls_fixture() -> Result<Value> {
    Ok(serde_json::from_str(MLS_FIXTURE)?)
}

fn require_vector(fixture: &Value, name: &str) -> Result<()> {
    require_named_entry(fixture, "vectors", name)
}

fn require_negative_vector(fixture: &Value, name: &str) -> Result<()> {
    require_named_entry(fixture, "negative_vectors", name)
}

fn require_named_entry(fixture: &Value, section: &str, name: &str) -> Result<()> {
    let entries = fixture
        .get(section)
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow::anyhow!("MLS fixture missing {section}[]"))?;
    if entries
        .iter()
        .any(|entry| entry.get("name").and_then(Value::as_str) == Some(name))
    {
        Ok(())
    } else {
        bail!("MLS fixture {section}[] missing {name}")
    }
}
