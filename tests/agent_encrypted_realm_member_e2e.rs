//! G2 encrypted Realm Agent-member E2EE lifecycle conformance.
//!
//! Existing cotest/browser MLS coverage proves the human-member path: encrypted
//! Realm creation, member invite, KeyPackage-backed Welcome delivery, and
//! cross-member decrypt. Agent provisioning coverage proves agent DPoP submit
//! and stream access after ordinary Realm membership. This file pins the
//! bridge between those two surfaces, including canonical KeyPackage writes,
//! durable Welcome handling, and restart recovery.

use anyhow::{Context, Result, bail};
use arkret::{
    ArkretMlsGroup, ArkretMlsIdentity, DeviceId, Did, KeyPackageUploadEntry,
    KeyPackagesConsumeUnsignedRequest, KeyPackagesRevokeUnsignedRequest,
    KeyPackagesUploadUnsignedRequest, MlsDeviceWorkflowAction, MlsGroupStateSink,
    keypackage_upload_entry_signing_input, keypackages_consume_signing_input,
    keypackages_revoke_signing_input, keypackages_upload_signing_input, late_device_join_steps,
    sign_keypackage_upload_entry, sign_keypackages_consume_request,
    sign_keypackages_revoke_request, sign_keypackages_upload_request,
    verify_keypackage_signing_input,
};
use arkret_core::MlsKeyPackageState;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::SigningKey;
use garth::{CryptoStore, MemoryCryptoStore, MlsRecoveryAction};
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
                let principal_id: Did = serde_json::from_value(
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
                        .get("key_package")
                        .cloned()
                        .context("entry case missing key_package")?,
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

        assert_eq!(actual_input, expected_input, "case {name}");
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
    let legacy_input = [
        b"ak.keypackage-upload-v1\n".as_slice(),
        upload_case["canonical_jcs"]
            .as_str()
            .context("upload case missing canonical_jcs")?
            .as_bytes(),
    ]
    .concat();
    assert!(verify_keypackage_signing_input(&public_key, kid, &legacy_input, &signature).is_err());
    Ok(())
}

#[test]
fn agent_member_welcome_fixture_joins_persists_and_recovers_locally() -> Result<()> {
    let owner_did = did("alice")?;
    let owner_device = device("000000000101")?;
    let agent_did = did("summary-agent")?;
    let agent_device = device("000000000202")?;

    let owner = ArkretMlsIdentity::new_basic(owner_did.clone(), owner_device)?;
    let mut owner_group = owner.create_group(b"cotest-g2-agent-member-local-fixture")?;

    let agent = ArkretMlsIdentity::new_basic(agent_did.clone(), agent_device.clone())?;
    let agent_key_package = agent.key_package_record()?;
    let agent_private_state = agent.export_private_state()?;
    assert_eq!(agent_key_package.principal_id, agent_did);
    assert_eq!(agent_key_package.device_id, agent_device);
    assert_eq!(agent_key_package.state, MlsKeyPackageState::Published);
    assert!(!agent_key_package.last_resort);
    assert!(agent_key_package.is_usable());

    let mut runtime_store = MemoryCryptoStore::new();
    runtime_store.put_key_package(agent_key_package.clone())?;
    assert_eq!(
        runtime_store
            .key_package(&agent_did, &agent_device)
            .map(|record| record.keypackage_ref.as_str()),
        Some(agent_key_package.keypackage_ref.as_str())
    );

    let add = owner_group.add_member(&agent_key_package)?;
    assert_eq!(add.welcome.recipient_principal_id, agent_did);
    assert_eq!(add.welcome.recipient_device_id, agent_device);
    runtime_store.put_welcome(add.welcome.clone())?;
    runtime_store.put_commit(add.commit.clone())?;

    let pending_welcomes = runtime_store.welcomes_for_device(&agent_did, &agent_device);
    assert_eq!(pending_welcomes.len(), 1);
    let late_join_steps = late_device_join_steps(&add.welcome);
    assert_eq!(late_join_steps.len(), 1);
    assert_eq!(
        late_join_steps[0].action,
        MlsDeviceWorkflowAction::ConsumeWelcome
    );
    assert_eq!(
        late_join_steps[0].group_id.as_deref(),
        Some(add.welcome.group_id.as_str())
    );
    assert!(matches!(
        runtime_store
            .plan_mls_recovery(
                &add.welcome.group_id,
                None,
                add.welcome.epoch,
                &agent_did,
                &agent_device,
            )
            .action,
        MlsRecoveryAction::ConsumeWelcome
    ));

    let restarted_identity = ArkretMlsIdentity::restore_from_private_state(
        agent_did.clone(),
        agent_device.clone(),
        &agent_private_state,
    )?;
    let agent_group = ArkretMlsGroup::join_from_welcome(restarted_identity, &add.welcome)?;
    assert_eq!(agent_group.group_id(), add.welcome.group_id);
    assert_eq!(agent_group.epoch(), add.welcome.epoch);
    assert!(
        agent_group
            .member_principal_ids()
            .iter()
            .any(|principal| principal == &agent_did)
    );
    let persisted = agent_group.persist_state(&mut runtime_store)?;
    assert_eq!(persisted.group_id, add.welcome.group_id);
    assert_eq!(persisted.epoch, add.welcome.epoch);

    let mut restarted_store = MemoryCryptoStore::new();
    restarted_store.put_mls_group_state(persisted.clone())?;
    let restored_state = restarted_store
        .mls_group_state(&add.welcome.group_id)
        .expect("agent MLS group state must survive runtime restart")
        .clone();
    let mut restarted_agent_group = ArkretMlsGroup::restore_from_state_record(&restored_state)?;

    let agent_payload = restarted_agent_group
        .encrypt_payload("ak.message.create", b"agent encrypted hello after restart")?;
    assert_eq!(
        owner_group.decrypt_payload(&agent_payload)?,
        b"agent encrypted hello after restart"
    );

    let owner_next_commit = owner_group.self_update_commit()?;
    restarted_store.put_commit(owner_next_commit.clone())?;
    match restarted_store
        .plan_mls_recovery(
            &owner_next_commit.group_id,
            Some(restarted_agent_group.epoch()),
            owner_next_commit.epoch,
            &agent_did,
            &agent_device,
        )
        .action
    {
        MlsRecoveryAction::ApplyCommits {
            from_epoch,
            to_epoch,
        } => {
            assert_eq!(from_epoch, add.welcome.epoch + 1);
            assert_eq!(to_epoch, owner_next_commit.epoch);
        }
        other => bail!("expected ApplyCommits recovery after owner epoch advance, got {other:?}"),
    }

    assert_eq!(
        restarted_agent_group.apply_commit(&owner_next_commit)?,
        owner_group.epoch()
    );
    restarted_agent_group.persist_state(&mut restarted_store)?;

    let owner_payload = owner_group
        .encrypt_payload("ak.message.create", b"owner next epoch after agent restart")?;
    assert_eq!(
        restarted_agent_group.decrypt_payload(&owner_payload)?,
        b"owner next epoch after agent restart"
    );

    Ok(())
}

/// Runtime-neutral lifecycle: authorized key, publish, Welcome persistence,
/// idempotent consume, restart recovery, next epoch, and supersede revoke.
#[test]
fn agent_member_encrypted_realm_e2e_requires_agent_welcome_lifecycle() -> Result<()> {
    let owner_did = did("agent-lifecycle-owner")?;
    let owner_device = device("000000000301")?;
    let agent_did = did("agent-lifecycle-runtime")?;
    let agent_device = device("000000000302")?;
    let verification_method = format!("{}#runtime-1", agent_did.as_str());

    let owner = ArkretMlsIdentity::new_basic(owner_did, owner_device)?;
    let mut owner_group = owner.create_group(b"cotest-g2-native-agent-lifecycle")?;
    let agent = ArkretMlsIdentity::from_ed25519_signing_seed(
        agent_did.clone(),
        agent_device.clone(),
        [17_u8; 32],
    )?;
    let public_key: [u8; 32] = agent
        .signature_public_key()
        .try_into()
        .context("Agent MLS Ed25519 public key must be 32 bytes")?;

    let record = agent.key_package_record()?;
    let identity_state = agent.export_private_state()?;
    let mut runtime_store = MemoryCryptoStore::new();
    runtime_store.put_key_package(record.clone())?;
    let upload = agent
        .signed_key_packages_upload_request(std::slice::from_ref(&record), &verification_method)?;
    verify_keypackage_signing_input(
        &public_key,
        &verification_method,
        &keypackages_upload_signing_input(&upload.unsigned())?,
        &upload.device_signature,
    )?;

    let add = owner_group.add_member(&record)?;
    runtime_store.put_welcome(add.welcome.clone())?;
    runtime_store.put_commit(add.commit)?;

    let restarted_identity = ArkretMlsIdentity::restore_from_private_state(
        agent_did.clone(),
        agent_device.clone(),
        &identity_state,
    )?;
    let agent_group = ArkretMlsGroup::join_from_welcome(restarted_identity, &add.welcome)?;
    let persisted = agent_group.persist_state(&mut runtime_store)?;
    let consume_unsigned = KeyPackagesConsumeUnsignedRequest {
        key_package_refs: vec![record.keypackage_ref.as_str().to_owned()],
        consumer_device_id: agent_device.clone(),
        claim_ids: vec!["claim-agent-lifecycle-001".to_owned()],
        welcome_ref: Some(add.welcome.welcome_hash.as_str().to_owned()),
        realm_id: None,
        strand_id: None,
        mls_group_id: Some(add.welcome.group_id.clone()),
        epoch: Some(add.welcome.epoch),
    };
    let consume = agent
        .signed_key_packages_consume_request(consume_unsigned.clone(), &verification_method)?;
    verify_keypackage_signing_input(
        &public_key,
        &verification_method,
        &keypackages_consume_signing_input(&consume.unsigned())?,
        &consume.signature,
    )?;
    let retry =
        agent.signed_key_packages_consume_request(consume_unsigned, &verification_method)?;
    assert_eq!(
        serde_json::to_value(&consume)?,
        serde_json::to_value(&retry)?,
        "consume retry must preserve the byte-identical idempotent request"
    );

    let revoke = agent.signed_key_packages_revoke_request(
        KeyPackagesRevokeUnsignedRequest {
            key_package_refs: vec![record.keypackage_ref.as_str().to_owned()],
            device_id: agent_device.clone(),
            reason: Some("authorization_superseded".to_owned()),
        },
        &verification_method,
    )?;
    verify_keypackage_signing_input(
        &public_key,
        &verification_method,
        &keypackages_revoke_signing_input(&revoke.unsigned())?,
        &revoke.signature,
    )?;

    let mut restarted_store = MemoryCryptoStore::new();
    restarted_store.put_mls_group_state(persisted.clone())?;
    let restored_state = restarted_store
        .mls_group_state(&persisted.group_id)
        .context("persisted Agent group state must survive restart")?
        .clone();
    let mut restarted_agent_group = ArkretMlsGroup::restore_from_state_record(&restored_state)?;
    let agent_payload = restarted_agent_group
        .encrypt_payload("ak.message.create", b"native agent after restart")?;
    assert_eq!(
        owner_group.decrypt_payload(&agent_payload)?,
        b"native agent after restart"
    );

    let next_commit = owner_group.self_update_commit()?;
    restarted_agent_group.apply_commit(&next_commit)?;
    restarted_agent_group.persist_state(&mut restarted_store)?;
    let owner_payload = owner_group.encrypt_payload(
        "ak.message.create",
        b"owner to native agent in the next epoch",
    )?;
    assert_eq!(
        restarted_agent_group.decrypt_payload(&owner_payload)?,
        b"owner to native agent in the next epoch"
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

fn did(name: &str) -> Result<Did> {
    Ok(Did::new(format!("did:webvh:z6mkfixture:{name}.example"))?)
}

fn device(suffix: &str) -> Result<DeviceId> {
    Ok(DeviceId::new(format!(
        "ak:device:01904100-0000-7000-8000-{suffix}"
    ))?)
}
