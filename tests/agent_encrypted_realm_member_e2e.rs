//! G2 encrypted Realm agent-member E2E gap pin.
//!
//! Existing cotest/browser MLS coverage proves the human-member path: encrypted
//! Realm creation, member invite, KeyPackage-backed Welcome delivery, and
//! cross-member decrypt. Agent provisioning coverage proves agent DPoP submit
//! and stream access after ordinary Realm membership. This file pins the
//! missing bridge between those two surfaces.

use anyhow::{Result, bail};
use arkret::{
    ArkretMlsGroup, ArkretMlsIdentity, DeviceId, Did, MlsDeviceWorkflowAction, MlsGroupStateSink,
    late_device_join_steps,
};
use arkret_core::MlsKeyPackageState;
use garth::{CryptoStore, MemoryCryptoStore, MlsRecoveryAction};
use serde_json::Value;

const MLS_FIXTURE: &str = include_str!("fixtures/mls_e2ee_basic_fixture.json");

#[test]
fn mls_fixture_still_covers_member_join_and_aad_pinning() -> Result<()> {
    let fixture = mls_fixture()?;
    require_vector(&fixture, "member_join_via_commit")?;
    require_vector(&fixture, "encryption_aad_digest_pinning")?;
    require_negative_vector(&fixture, "aad_digest_mismatch_rejected")?;
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

/// Gating: G2 blocked — agent KeyPackage upload/claim and encrypted Welcome
/// consume path is not exposed end-to-end.
/// Tier: mls-data-plane
#[test]
#[ignore = "G2 blocked: agent KeyPackage upload/claim and encrypted Welcome consume path is not exposed end-to-end"]
fn agent_member_encrypted_realm_e2e_requires_agent_welcome_lifecycle() -> Result<()> {
    let fixture = mls_fixture()?;
    require_vector(&fixture, "member_join_via_commit")?;
    require_vector(&fixture, "encryption_aad_digest_pinning")?;

    let required_path = [
        "controller provisions and pairs agent runtime key",
        "controller creates mls_rfc9420 Realm",
        "agent runtime publishes a device-bound MLS KeyPackage",
        "Realm owner claims the agent KeyPackage",
        "Realm owner adds agent member and produces encrypted Welcome pointer/blob",
        "agent runtime receives or re-fetches Welcome and joins the MLS group",
        "agent submits encrypted Realm content with agent_context",
        "human member decrypts the agent-authored content",
        "agent restart restores group state or key backup and can decrypt next epoch",
    ];

    bail!(
        "G2 encrypted Realm agent-member E2E is blocked before a passing live test can be written. \
         Existing cotest MLS fixtures cover member join/AAD semantics, and browser specs cover \
         human KeyPackage/Welcome flows, but there is no standard cotest/SDK surface for the agent \
         runtime to publish a device-bound KeyPackage, have it claimed for an agent principal, \
         receive or re-fetch an encrypted Welcome pointer/blob, acknowledge/consume it, or restore \
         group state after restart. Required path: {}",
        required_path.join(" -> ")
    )
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
