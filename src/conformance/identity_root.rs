//! Executable conformance for cold-custodied principal identity roots.

use std::collections::BTreeSet;

use anyhow::{Context, Result, anyhow, bail};
use arkret::identity::{
    DID_INCEPTION_REF_ROLE, SelfPrincipalPcrCreateInput, build_self_principal_pcr_create,
    self_principal_bootstrap_submit_request,
};
use arkret::identity_root::{
    bip39_identity_recovery_secret, derive_identity_recovery_key_material,
    derive_identity_recovery_key_material_from_bip39,
};
use arkret_core::{
    Audience, Base64UrlString, DeviceAuthorizePayload, DeviceEnrollmentAuthorityBinding,
    DeviceEnrollmentAuthorityBindingKind, DeviceGenerationState, DeviceGenerationStatus, DeviceId,
    DeviceOrPrincipalRef, DeviceReanchorPayload, DeviceStatus, Did, DidUrl, Event, EventId,
    EventRef, Hash, Hlc, MoveId, NonEmptyString, Proof, QueryDeviceCrossSigningBinding,
    QueryDeviceRecord, RealmId, TypedTrustDomainId, validate_device_reanchor_recovery_first_seal,
};
use serde_json::{Value, json};

use super::load_fixture_value;

const KDF_FIXTURE: &str = "identity-recovery-kdf-fixture.json";
const ROOT_ANCHOR_FIXTURE: &str = "identity-root-anchor-fixture.json";

pub fn run_identity_recovery_kdf_fixture_suite() -> Result<()> {
    let fixture = load_fixture_value(KDF_FIXTURE)?;
    require_vector(&fixture, "ak.vector.identity.recovery_kdf.v1")?;
    let cases = fixture
        .get("cases")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("{KDF_FIXTURE} missing cases[]"))?;
    if cases.len() != 2 {
        bail!("{KDF_FIXTURE} must contain the BIP-39 and raw KAT cases");
    }

    for case in cases {
        let name = required_str(case, "name")?;
        let input = case
            .get("input")
            .ok_or_else(|| anyhow!("{name} missing input"))?;
        let expected = case
            .get("expected")
            .ok_or_else(|| anyhow!("{name} missing expected"))?;
        let material = match required_str(input, "kind")? {
            "bip39" => {
                let mnemonic = required_str(input, "mnemonic_utf8")?;
                let passphrase = required_str(input, "passphrase_utf8")?;
                let secret = bip39_identity_recovery_secret(mnemonic, passphrase)?;
                compare_hex(
                    name,
                    "recovery_secret_bytes_hex",
                    &secret,
                    required_str(input, "recovery_secret_bytes_hex")?,
                )?;
                derive_identity_recovery_key_material_from_bip39(mnemonic, passphrase, 0)?
            }
            "raw" => {
                let secret = hex::decode(required_str(input, "recovery_secret_bytes_hex")?)
                    .with_context(|| format!("{name} invalid recovery_secret_bytes_hex"))?;
                derive_identity_recovery_key_material(&secret, 0)?
            }
            kind => bail!("{name} has unknown recovery secret kind {kind}"),
        };

        compare_hex(
            name,
            "prk_hex",
            &material.prk,
            required_str(expected, "prk_hex")?,
        )?;
        compare_hex(
            name,
            "root_seed_0_hex",
            &material.root_seed,
            required_str(expected, "root_seed_0_hex")?,
        )?;
        compare_hex(
            name,
            "root_seed_1_hex",
            &material.next_root_seed,
            required_str(expected, "root_seed_1_hex")?,
        )?;
        compare_hex(
            name,
            "recovery_proof_seed_hex",
            &material.recovery_proof_seed,
            required_str(expected, "recovery_proof_seed_hex")?,
        )?;
        compare_hex(
            name,
            "backup_hpke_ikm_hex",
            &material.backup_hpke_ikm,
            required_str(expected, "backup_hpke_ikm_hex")?,
        )?;
        compare_hex(
            name,
            "root_public_key_0_hex",
            &material.root_public_key,
            required_str(expected, "root_public_key_0_hex")?,
        )?;
        compare_text(
            name,
            "root_public_key_0_multikey",
            &material.root_public_key_multikey,
            required_str(expected, "root_public_key_0_multikey")?,
        )?;
        compare_hex(
            name,
            "root_public_key_1_hex",
            &material.next_root_public_key,
            required_str(expected, "root_public_key_1_hex")?,
        )?;
        compare_text(
            name,
            "root_public_key_1_multikey",
            &material.next_root_public_key_multikey,
            required_str(expected, "root_public_key_1_multikey")?,
        )?;
        compare_hex(
            name,
            "recovery_proof_public_key_hex",
            &material.recovery_proof_public_key,
            required_str(expected, "recovery_proof_public_key_hex")?,
        )?;
        compare_text(
            name,
            "recovery_proof_public_key_multikey",
            &material.recovery_proof_public_key_multikey,
            required_str(expected, "recovery_proof_public_key_multikey")?,
        )?;
        compare_hex(
            name,
            "backup_hpke_derived_sk_hex",
            &material.backup_hpke_derived_private_key,
            required_str(expected, "backup_hpke_derived_sk_hex")?,
        )?;
        compare_hex(
            name,
            "backup_hpke_serialized_private_key_hex",
            &material.backup_hpke_serialized_private_key,
            required_str(expected, "backup_hpke_serialized_private_key_hex")?,
        )?;
        compare_hex(
            name,
            "backup_hpke_public_key_hex",
            &material.backup_hpke_public_key,
            required_str(expected, "backup_hpke_public_key_hex")?,
        )?;
        compare_text(
            name,
            "backup_hpke_public_key_multikey",
            &material.backup_hpke_public_key_multikey,
            required_str(expected, "backup_hpke_public_key_multikey")?,
        )?;
        compare_text(
            name,
            "root_1_next_key_hash",
            &material.next_root_key_hash,
            required_str(expected, "root_1_next_key_hash")?,
        )?;
    }

    let short_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    if derive_identity_recovery_key_material_from_bip39(short_mnemonic, "", 0).is_ok() {
        bail!("identity recovery accepted a non-24-word BIP-39 mnemonic");
    }
    Ok(())
}

/// Executes the canonical SDK checks currently wired for the formal anchor
/// fixture and verifies the remaining reducer cases stay explicitly declared.
///
/// This is deliberately named a checkpoint suite: presence checks for the
/// 62-case formal matrix are not reported as executed reducer coverage.
pub fn run_identity_root_anchor_checkpoint_suite() -> Result<()> {
    let fixture = load_fixture_value(ROOT_ANCHOR_FIXTURE)?;
    for vector in [
        "ak.vector.identity.root_anchor_exclusivity.v1",
        "ak.vector.identity.device_reanchor.v1",
        "ak.vector.identity.recovery_secret_handoff.v1",
        "ak.vector.identity.recovery_key_role_separation.v1",
    ] {
        require_vector(&fixture, vector)?;
    }
    require_declared_case_checkpoints(&fixture)?;
    validate_bootstrap_helpers()?;
    validate_reanchor_helpers()?;
    validate_recovery_handoff_checkpoints(&fixture)
}

pub fn run_identity_model_generation_fence_suite() -> Result<()> {
    let mut model_a = QueryDeviceRecord {
        device_status: Some(DeviceStatus::Active),
        cross_signing_binding: Some(QueryDeviceCrossSigningBinding {
            verification_method: did_url("did:webvh:z6mkfixture:alice.example#ak_self_signing_v1")?,
            alg: Some(non_empty("EdDSA")?),
            ssk_generation: 1,
            signature: base64_url("c2ln")?,
        }),
        ..QueryDeviceRecord::default()
    };
    if !model_a.is_usable_in_generation(None) {
        bail!("model A device was not usable under its cross-signing authority");
    }

    let authority = enrollment_binding()?;
    let active_generation = DeviceGenerationState {
        current_device_generation_ref: non_empty("2-QmCurrent")?,
        device_generation_status: DeviceGenerationStatus::Active,
    };
    let conflicted_generation = DeviceGenerationState {
        current_device_generation_ref: active_generation.current_device_generation_ref.clone(),
        device_generation_status: DeviceGenerationStatus::Conflicted,
    };
    let mut model_b = QueryDeviceRecord {
        device_status: Some(DeviceStatus::Active),
        enrollment_authority_binding: Some(authority.clone()),
        device_authorize_event_id: Some(EventId::new(
            "ak:event:01904100-0000-7000-8000-000000000004",
        )?),
        authorized_generation_ref: Some(non_empty("2-QmCurrent")?),
        ..QueryDeviceRecord::default()
    };
    if !model_b.is_usable_in_generation(Some(&active_generation))
        || model_b.is_usable_in_generation(None)
        || model_b.is_usable_in_generation(Some(&conflicted_generation))
    {
        bail!("model B generation admission did not fail closed");
    }
    model_b.authorized_generation_ref = Some(non_empty("1-QmPrevious")?);
    if model_b.is_usable_in_generation(Some(&active_generation)) {
        bail!("old-generation model B device remained usable after the fence");
    }

    model_a.enrollment_authority_binding = Some(authority);
    if model_a.is_usable_in_generation(None) {
        bail!("mixed model A/B authority was accepted");
    }
    model_b.authorized_generation_ref = Some(non_empty("2-QmCurrent")?);
    model_b.cross_signing_binding = model_a.cross_signing_binding;
    if model_b.is_usable_in_generation(Some(&active_generation)) {
        bail!("mixed model B/A authority was accepted");
    }
    Ok(())
}

fn validate_bootstrap_helpers() -> Result<()> {
    let principal = Did::new("did:webvh:z6mkfixture:alice.example")?;
    let created_at = "2026-07-15T00:00:00.000Z".parse()?;
    let realm_id = RealmId::new(arkret_core::principal_control_realm_id(&principal))?;
    let create = build_self_principal_pcr_create(SelfPrincipalPcrCreateInput {
        principal_id: principal.clone(),
        realm_id: realm_id.clone(),
        trust_domain: TypedTrustDomainId::new("ak:trust_domain:example.net")?,
        did_inception_ref: EventRef::new(
            "did:webvh:z6mkfixture:alice.example#entry-0",
            DID_INCEPTION_REF_ROLE,
        ),
        event_id: EventId::new("ak:event:01904100-0000-7000-8000-000000000001")?,
        created_at,
        hlc: Hlc::new("01970e589d21-0001-a13f9c2e")?,
    })?;
    let mut create = with_proof(
        create,
        "did:key:z6MkvMW3tjuvW6PqYiX8dLRNwZWyGhxe3biRDjA4ZPiBaFaJ#z6MkvMW3tjuvW6PqYiX8dLRNwZWyGhxe3biRDjA4ZPiBaFaJ",
    )?;
    let authority = enrollment_binding()?;
    let payload = DeviceAuthorizePayload {
        principal_id: principal.clone(),
        device_id: DeviceId::new("ak:device:01904100-0000-7000-8000-000000000001")?,
        device_public_key: non_empty("z6MkiDeviceKey")?,
        hpke_key: non_empty("z6LSDeviceHpkeKey")?,
        algorithms: vec![
            non_empty("ak.hpke_x25519_aead_chacha20poly1305.v1")?,
            non_empty("ak.mls.v1")?,
        ],
        device_key_algorithm: Some(non_empty("EdDSA")?),
        authorized_by: DeviceOrPrincipalRef::Did(authority.authority_did.clone()),
        scopes: None,
        not_before: created_at,
        expires_at: None,
        device_signature: None,
        proof: None,
        cross_signing_binding: None,
        enrollment_authority_binding: Some(authority.clone()),
        recovery_session_id: None,
    };
    let mut authorize = Event::new(
        arkret_wire::events::EventKind::DEVICE_AUTHORIZE,
        realm_id,
        principal,
        1,
        Hlc::new("01970e589d21-0002-a13f9c2e")?,
        serde_json::to_value(payload)?,
    )?;
    authorize.event_id = EventId::new("ak:event:01904100-0000-7000-8000-000000000002")?;
    authorize.created_at = created_at;
    authorize.prev_refs = vec![create.event_id.clone()];
    authorize.executed_by = Some(authority.authority_did.clone());
    authorize.authorization_ref = Some(authority.authorization_ref.to_string());
    authorize = with_proof(
        authorize,
        &format!("{}#enrollment", authority.authority_did),
    )?;

    let request = self_principal_bootstrap_submit_request(create.clone(), authorize)?;
    if request.event.is_some() || request.events.len() != 2 {
        bail!("self principal bootstrap was not emitted as one closed two-event unit");
    }
    create.refs.clear();
    if self_principal_bootstrap_submit_request(create, request.events[1].clone()).is_ok() {
        bail!("self principal bootstrap accepted a missing did_inception anchor");
    }
    Ok(())
}

fn validate_reanchor_helpers() -> Result<()> {
    let value = json!({
        "principal_id": "did:webvh:z6mkfixture:alice.example",
        "did_version_id": "2-QmCurrent",
        "previous_device_generation": "1-QmPrevious",
        "new_device_generation": "2-QmCurrent",
        "pre_fence_basis": null,
        "replacement_authorize_event_id": "ak:event:01904100-0000-7000-8000-000000000003",
        "replacement_authorize_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    });
    let payload: DeviceReanchorPayload = serde_json::from_value(value.clone())?;
    let reanchor_digest = Hash::new(format!("sha256:{}", "1".repeat(64)))?;
    let delta = vec![
        MoveId::new(reanchor_digest.as_str().to_owned())?,
        MoveId::new(payload.replacement_authorize_digest.as_str().to_owned())?,
    ];
    validate_device_reanchor_recovery_first_seal(&payload, &[], &delta, &reanchor_digest)?;
    if validate_device_reanchor_recovery_first_seal(&payload, &[], &delta[..1], &reanchor_digest)
        .is_ok()
    {
        bail!("recovery-first Seal accepted a partial re-anchor unit");
    }

    let mut mismatched = value;
    mismatched["new_device_generation"] = json!("3-QmOther");
    if serde_json::from_value::<DeviceReanchorPayload>(mismatched).is_ok() {
        bail!("device re-anchor accepted a DID/generation mismatch");
    }
    Ok(())
}

fn validate_recovery_handoff_checkpoints(fixture: &Value) -> Result<()> {
    let cases = fixture
        .get("cases")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("{ROOT_ANCHOR_FIXTURE} missing cases[]"))?;
    let actual = cases
        .iter()
        .filter_map(|case| {
            let input = case.get("input")?;
            Some((
                input.get("crash_after_stage")?.as_str()?,
                case.get("expected")?.get("next_stage")?.as_str()?,
            ))
        })
        .collect::<Vec<_>>();
    let expected = [
        (
            "new_secret_custody_confirmed",
            "activate_old_precommitted_root",
        ),
        (
            "old_precommitted_root_activated_and_new_root_committed",
            "activate_new_secret_root",
        ),
        (
            "new_secret_root_activated_and_next_committed",
            "device_reanchor",
        ),
        ("device_reanchor_accepted", "publish_recovery_policy"),
        ("new_recovery_policy_accepted", "rewrap_all_active_series"),
        (
            "all_active_series_rewrapped",
            "advance_active_series_pointers",
        ),
        ("active_series_pointers_advanced", "revoke_old_policy_key"),
    ];
    if actual != expected {
        bail!("recovery handoff crash-resume checkpoint sequence drifted: {actual:?}");
    }
    Ok(())
}

fn require_declared_case_checkpoints(fixture: &Value) -> Result<()> {
    let cases = fixture
        .get("cases")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("{ROOT_ANCHOR_FIXTURE} missing cases[]"))?;
    if cases.len() != 62 {
        bail!(
            "{ROOT_ANCHOR_FIXTURE} formal reducer matrix must declare 62 cases, found {}",
            cases.len()
        );
    }
    let names = cases
        .iter()
        .filter_map(|case| case.get("name").and_then(Value::as_str))
        .collect::<BTreeSet<_>>();
    if names.len() != cases.len() {
        bail!("{ROOT_ANCHOR_FIXTURE} case names must be present and unique");
    }
    for case in cases {
        let name = required_str(case, "name")?;
        required_str(
            case.get("expected")
                .ok_or_else(|| anyhow!("{name} missing expected"))?,
            "decision",
        )?;
    }
    for required in [
        "accept_atomic_principal_control_bootstrap",
        "accept_delegated_agent_pcr_genesis_without_did_inception",
        "reject_self_principal_pcr_genesis_without_did_inception",
        "accept_reanchor_without_prior_seal",
        "accept_reanchor_with_complete_current_frontier",
        "reject_split_or_partially_committed_reanchor_unit",
        "reject_old_generation_event_after_fence",
        "reject_old_generation_seal_after_fence",
        "quarantine_all_same_version_number_conflicts_independent_of_arrival_order",
        "quarantine_same_entry_two_different_units",
        "accept_conflict_resolution_by_next_precommitted_authority",
        "reject_in_place_secret_rotation_without_independent_authority",
        "accept_staged_two_entry_secret_handoff",
        "accept_recovery_policy_distinct_signing_and_hpke_pair",
        "reject_recovery_policy_same_material_for_signing_and_hpke",
        "reject_did_document_only_recovery_signing_or_hpke_key",
    ] {
        if !names.contains(required) {
            bail!("{ROOT_ANCHOR_FIXTURE} missing required case {required}");
        }
    }
    Ok(())
}

fn enrollment_binding() -> Result<DeviceEnrollmentAuthorityBinding> {
    Ok(DeviceEnrollmentAuthorityBinding {
        kind: DeviceEnrollmentAuthorityBindingKind::ServiceAttested,
        authority_did: Did::new("did:webvh:z6mkauthority:auth.example")?,
        authorization_ref: non_empty("did:webvh:z6mkfixture:alice.example#enrollment-authority")?,
    })
}

fn with_proof(mut event: Event, verification_method: &str) -> Result<Event> {
    let digest = Hash::new(event.event_digest()?)?;
    event.proofs = vec![Proof {
        kind: arkret_core::proof_kind::DETACHED_JWS.to_owned(),
        alg: "EdDSA".to_owned(),
        verification_method: verification_method.to_owned(),
        event_digest: digest,
        created_at: event.created_at,
        domain: None,
        audience: Some(Audience::Single(event.realm_id.to_string())),
        jws: "c2ln".to_owned(),
    }];
    Ok(event)
}

fn require_vector(fixture: &Value, vector: &str) -> Result<()> {
    let covers = fixture
        .get("covers_vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("fixture missing covers_vectors[]"))?;
    if !covers.iter().any(|value| value.as_str() == Some(vector)) {
        bail!("fixture does not cover {vector}");
    }
    Ok(())
}

fn required_str<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing string field {field}"))
}

fn compare_hex(name: &str, field: &str, actual: &[u8], expected: &str) -> Result<()> {
    compare_text(name, field, &hex::encode(actual), expected)
}

fn compare_text(name: &str, field: &str, actual: &str, expected: &str) -> Result<()> {
    if actual != expected {
        bail!("{name}.{field} mismatch: expected {expected}, got {actual}");
    }
    Ok(())
}

fn non_empty(value: impl Into<String>) -> Result<NonEmptyString> {
    NonEmptyString::new(value).map_err(anyhow::Error::msg)
}

fn did_url(value: impl Into<String>) -> Result<DidUrl> {
    DidUrl::new(value).map_err(anyhow::Error::msg)
}

fn base64_url(value: impl Into<String>) -> Result<Base64UrlString> {
    Base64UrlString::new(value).map_err(anyhow::Error::msg)
}
