//! Executable conformance for cold-custodied principal identity roots.

use std::collections::BTreeSet;

use anyhow::{Context, Result, anyhow, bail};
use arkret::identity_root::{
    bip39_identity_recovery_secret, derive_identity_recovery_key_material,
    derive_identity_recovery_key_material_from_bip39,
};
use arkret_bootstrap::{
    DID_INCEPTION_REF_ROLE, SelfPrincipalPcrCreateInput, build_self_principal_pcr_create,
    build_self_principal_pcr_genesis_unit, validate_self_principal_pcr_genesis_unit,
};
use arkret_event_draft::EventPayloadExt;
use arkret_identifiers::{
    DeviceId, Did, DidCoreId, Hash, Hlc, TrustDomainId, project_did_to_core_id,
};
use arkret_models_collaboration::events_payloads::device_identity::{
    DeviceAuthorizationBindingKind, DeviceAuthorizePayload, DeviceOrPrincipalRef,
    DeviceReanchorPayload, validate_device_reanchor_recovery_first_seal,
};
use arkret_models_collaboration::events_payloads::{
    FoundingDeviceDescriptor, FoundingDeviceHpkeKeyAlgorithm, FoundingDeviceKeyAlgorithm,
    FoundingDeviceKeyPurpose, SignatureMaterial, device_authorize_payload_digest,
};
use arkret_wire::{
    AccountId, Audience, DidUrl, Event, EventRef, NonEmptyString, ProducerEventProof,
};
use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey};
use serde::Deserialize;
use serde_json::{Value, json};

use super::load_fixture_value;

const KDF_FIXTURE: &str = "identity-recovery-kdf-fixture.json";
const ROOT_ANCHOR_FIXTURE: &str = "identity-root-anchor-fixture.json";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct IdentityRecoveryKdfFixture {
    suite: String,
    version: String,
    runner: Value,
    covers_vectors: Vec<String>,
    contract: Value,
    cases: Vec<Value>,
    negative_mutations: Vec<Value>,
    expected_negative_decision: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct IdentityRootAnchorFixture {
    suite: String,
    version: String,
    runner: Value,
    covers_vectors: Vec<String>,
    cases: Vec<Value>,
}

pub fn run_identity_recovery_kdf_fixture_suite() -> Result<()> {
    let fixture: IdentityRecoveryKdfFixture =
        serde_json::from_value(load_fixture_value(KDF_FIXTURE)?)?;
    require_vector(
        &fixture.covers_vectors,
        "ak.vector.identity.recovery_kdf.v1",
    )?;
    if fixture.suite.trim().is_empty()
        || fixture.version.trim().is_empty()
        || fixture.runner.is_null()
        || fixture.contract.is_null()
        || fixture.negative_mutations.is_empty()
        || fixture.expected_negative_decision.trim().is_empty()
    {
        bail!("{KDF_FIXTURE} metadata drifted");
    }
    let cases = &fixture.cases;
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
    let fixture: IdentityRootAnchorFixture =
        serde_json::from_value(load_fixture_value(ROOT_ANCHOR_FIXTURE)?)?;
    if fixture.suite.trim().is_empty()
        || fixture.version.trim().is_empty()
        || fixture.runner.is_null()
    {
        bail!("{ROOT_ANCHOR_FIXTURE} metadata drifted");
    }
    for vector in [
        "ak.vector.identity.root_anchor_exclusivity.v1",
        "ak.vector.identity.device_reanchor.v1",
        "ak.vector.identity.recovery_secret_handoff.v1",
        "ak.vector.identity.recovery_key_role_separation.v1",
    ] {
        require_vector(&fixture.covers_vectors, vector)?;
    }
    require_declared_case_checkpoints(&fixture)?;
    validate_pcr_genesis_helpers()?;
    validate_reanchor_helpers()?;
    validate_recovery_handoff_checkpoints(&fixture)
}

pub fn run_identity_model_generation_fence_suite() -> Result<()> {
    // Generation fencing is now a single PCR directory rule. Its reducer and
    // remote-evidence matrices live in the SDK; this Cotest entrypoint keeps
    // the release gate wired to the canonical genesis/possession KAT.
    validate_pcr_genesis_helpers()
}

fn validate_pcr_genesis_helpers() -> Result<()> {
    let principal_did = Did::new("did:webvh:z6mkfixture:alice.example")?;
    let principal = project_did_to_core_id(&principal_did)?;
    let created_at = "2026-07-15T00:00:00.000Z".parse()?;
    let device_id = DeviceId::new("ak:device:01904100-0000-7000-8000-000000000001")?;
    let device_verification_method =
        DidUrl::new(format!("{principal_did}#{device_id}")).map_err(anyhow::Error::msg)?;
    let device_key = SigningKey::from_bytes(&[0x42; 32]);
    let device_multibase = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
        &device_key.verifying_key().to_bytes(),
    );
    let device_public_key = non_empty(format!("did:key:{device_multibase}"))?;
    let hpke_key = non_empty("z6LSCotestPcrGenesisHpkeKey")?;
    let algorithms = vec![non_empty("ak.hpke_x25519_aead_chacha20poly1305.v1")?];
    let mut authorize_payload = DeviceAuthorizePayload {
        device_id: device_id.clone(),
        device_public_key_did: device_public_key.clone(),
        hpke_key: hpke_key.clone(),
        algorithms: algorithms.clone(),
        device_key_algorithm: Some(non_empty("Ed25519")?),
        authorized_by: DeviceOrPrincipalRef::Principal(principal.clone()),
        scopes: None,
        not_before: created_at,
        expires_at: None,
        authorization_binding_kind: DeviceAuthorizationBindingKind::RegistrationAnchor,
        device_signature: SignatureMaterial::NonEmptyString(non_empty("pending")?),
        recovery_session_id: None,
    };
    let subject_account_id = AccountId::new(
        principal.clone(),
        DidCoreId::new("ak:did_core:web:principal.example")?,
    );
    let signature =
        device_key.sign(&authorize_payload.device_possession_signature_input(&subject_account_id)?);
    authorize_payload.device_signature = SignatureMaterial::NonEmptyString(non_empty(
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature.to_bytes()),
    )?);
    arkret_signatures::verify_device_authorize_possession(&authorize_payload, &subject_account_id)
        .map_err(|error| anyhow!(error.to_string()))?;
    let authorize_value = serde_json::to_value(&authorize_payload)?;
    let descriptor = FoundingDeviceDescriptor {
        descriptor_version: 1,
        device_id: device_id.clone(),
        device_key_digest: Hash::new(arkret_canonical::canonical::sha256_digest(
            device_public_key.as_bytes(),
        ))?,
        device_public_key_did: device_public_key,
        device_key_algorithm: FoundingDeviceKeyAlgorithm::Ed25519,
        device_key_purpose: FoundingDeviceKeyPurpose::EventSigningAndMlsIdentity,
        hpke_key_digest: Hash::new(arkret_canonical::canonical::sha256_digest(
            hpke_key.as_bytes(),
        ))?,
        hpke_key,
        hpke_key_algorithm: FoundingDeviceHpkeKeyAlgorithm::X25519,
        algorithms,
        founding_authorize_payload_digest: device_authorize_payload_digest(
            &authorize_value,
            arkret_canonical::DigestSuite::Sha256,
        )?,
    };
    let create = build_self_principal_pcr_create(
        SelfPrincipalPcrCreateInput {
            principal_id: principal.clone(),
            station_id: DidCoreId::new("ak:did_core:web:principal.example")?,
            principal_did: principal_did.clone(),
            notary: crate::fixture_single_signer_notary(principal.clone()),
            initial_resolution: arkret_models_identity::ResolutionCommitment {
                did: principal_did,
                method_history_head: format!("sha256:{}", "1".repeat(64)),
                version_id: "1-Qmfixture".to_owned(),
            },
            genesis_salt: arkret_wire::GenesisSalt::generate()?,
            trust_domain: TrustDomainId::new("ak:trust_domain:example.net")?,
            did_inception_ref: EventRef::new(
                "did:webvh:z6mkfixture:alice.example#entry-0",
                DID_INCEPTION_REF_ROLE,
            ),
            founding_device_descriptor: descriptor,
            created_at,
            hlc: Hlc::new("01970e589d21-0001-a13f9c2e")?,
        },
        &crate::publication::project_cells,
    )?;
    let create = with_proof(
        create.into_event(),
        &crate::fixture_did_url(
            "did:key:z6MkvMW3tjuvW6PqYiX8dLRNwZWyGhxe3biRDjA4ZPiBaFaJ#z6MkvMW3tjuvW6PqYiX8dLRNwZWyGhxe3biRDjA4ZPiBaFaJ",
        ),
    )?;
    let realm_id = create.realm_id.clone();
    let mut authorize = arkret_wire::test_support::raw_event(
        arkret_wire::EventKind::DeviceAuthorize.as_str(),
        arkret_wire::ScopeRef::Realm { realm_id },
        principal.clone(),
        DidCoreId::new("ak:did_core:web:principal.example")?,
        1,
        Hlc::new("01970e589d21-0002-a13f9c2e")?,
        authorize_value,
    )?;
    authorize.created_at = created_at;
    authorize.prev_refs = vec![create.event_id.clone()];
    authorize = with_proof(authorize, &device_verification_method)?;
    let unit = build_self_principal_pcr_genesis_unit(
        create.clone(),
        authorize.clone(),
        &crate::publication::project_cells,
    )?;
    unit.validate_ordered_envelopes()?;
    validate_self_principal_pcr_genesis_unit(
        &create,
        &authorize,
        &crate::publication::project_cells,
    )?;

    let mut split = authorize.clone();
    split.prev_refs.clear();
    if validate_self_principal_pcr_genesis_unit(&create, &split, &crate::publication::project_cells)
        .is_ok()
    {
        bail!("PCR genesis accepted a split create/authorize unit");
    }

    let mut tampered: DeviceAuthorizePayload =
        authorize.typed_payload::<arkret_wire::event_spec::DeviceAuthorize>()?;
    tampered.device_signature = SignatureMaterial::NonEmptyString(non_empty("AA")?);
    if arkret_signatures::verify_device_authorize_possession(&tampered, &subject_account_id).is_ok()
    {
        bail!("PCR genesis accepted a mutated founding-device possession proof");
    }
    Ok(())
}

fn validate_reanchor_helpers() -> Result<()> {
    let principal = DidCoreId::new("ak:did_core:webvh:z6mkfixture")?;
    let station_id = DidCoreId::new("ak:did_core:web:principal.example")?;
    let value = json!({
        "account_id": {"principal_id": principal, "station_id": station_id},
        "recovery_authority_kind": "pcr_policy",
        "recovery_policy_id": "ak:policy:01904100-0000-7000-8000-000000000001",
        "recovery_policy_version": 1,
        "recovery_session_id": "ak:recovery_session:01904100-0000-7000-8000-000000000002",
        "previous_device_generation": 1,
        "new_device_generation": 2,
        "pre_fence_seal_frontier": null,
        "replacement_authorize_payload_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    });
    let payload: DeviceReanchorPayload = serde_json::from_value(value.clone())?;
    let reanchor_digest = Hash::new(format!("sha256:{}", "1".repeat(64)))?;
    let authorize_digest = Hash::new(format!("sha256:{}", "2".repeat(64)))?;
    // A Seal `delta` entry is a bare digest: `move` is no longer an id kind.
    let delta = vec![reanchor_digest.clone(), authorize_digest.clone()];
    validate_device_reanchor_recovery_first_seal(
        &payload,
        &[],
        &delta,
        &reanchor_digest,
        &authorize_digest,
    )?;
    if validate_device_reanchor_recovery_first_seal(
        &payload,
        &[],
        &delta[..1],
        &reanchor_digest,
        &authorize_digest,
    )
    .is_ok()
    {
        bail!("recovery-first Seal accepted a partial re-anchor unit");
    }

    // The re-anchor payload MUST NOT carry the authorize Event id or envelope
    // digest: the authorize envelope names the re-anchor in prev_refs, so an id
    // binding would make the two Events preimages of each other.
    let mut carries_event_id = value.clone();
    carries_event_id["replacement_authorize_event_id"] =
        json!("ak:event:AXlG8yvLUgeROF13vorAuw0LMlE4uhRoHybH_PZB3WFx");
    if serde_json::from_value::<DeviceReanchorPayload>(carries_event_id).is_ok() {
        bail!("device re-anchor accepted a replacement Event id binding");
    }

    let mut mismatched = value;
    mismatched["new_device_generation"] = json!(3);
    if serde_json::from_value::<DeviceReanchorPayload>(mismatched).is_ok() {
        bail!("device re-anchor accepted a DID/generation mismatch");
    }
    Ok(())
}

fn validate_recovery_handoff_checkpoints(fixture: &IdentityRootAnchorFixture) -> Result<()> {
    let cases = &fixture.cases;
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

fn require_declared_case_checkpoints(fixture: &IdentityRootAnchorFixture) -> Result<()> {
    let cases = &fixture.cases;
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
        "reject_bootstrap_missing_unique_critical_inception_ref",
        "accept_delegated_agent_pcr_genesis_without_did_inception",
        "reject_self_principal_pcr_genesis_without_did_inception",
        "accept_byte_identical_reanchor_retry",
        "reject_incomplete_or_older_frontier",
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

fn with_proof(mut event: Event, verification_method: &arkret_wire::DidUrl) -> Result<Event> {
    event
        .refresh_content_bound_identity_with_digest_suite(arkret_canonical::DigestSuite::Sha256)?;
    let digest =
        Hash::new(event.event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)?)?;
    let (signer_evidence_ref, signer_evidence_digest) =
        crate::fixture_signer_evidence_pair(verification_method.as_str());
    event.proofs = vec![
        ProducerEventProof {
            kind: arkret_wire::proof_kind::DETACHED_JWS.to_owned(),
            verification_method: verification_method.clone(),
            event_digest: digest,
            signer_resolution_evidence_ref: Some(signer_evidence_ref),
            signer_resolution_evidence_digest: Some(signer_evidence_digest),
            created_at: event.created_at,
            domain: None,
            audience: Some(Audience::Single(event.realm_id.to_string())),
            proof_purpose: None,
            jws: "c2ln".to_owned(),
        }
        .into(),
    ];
    Ok(event)
}

fn require_vector(covers: &[String], vector: &str) -> Result<()> {
    if !covers.iter().any(|value| value == vector) {
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
