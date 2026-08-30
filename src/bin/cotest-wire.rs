use std::io::{self, Read};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use arkret_canonical as canonical;
use arkret_event_draft::EventPayloadExt as _;
use arkret_identifiers::{ConsentId, DeviceId, Did, DidCoreId, Hash, project_did_to_core_id};
use arkret_models_collaboration::http_bodies::{MimiConsentDecision, MimiUpdateConsentRequestBody};
use arkret_wire::{
    Audience, AuditReasonText, DidUrl, Event, EventInitialSubmission, NonEmptyString, PayloadProof,
    ProducerEventProof, SealBasis, SecurityClass, proof_kind,
};
use base64::Engine as _;
use chrono::{Timelike as _, Utc};
use ed25519_dalek::{Signer as _, SigningKey};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

#[derive(Debug, Deserialize)]
struct CanonicalInput {
    value: Value,
}

#[derive(Debug, Deserialize)]
struct EventProofInput {
    actor_did: String,
    verification_method: arkret_wire::DidUrl,
    created_at: String,
    event: Value,
    signing_seed_b64url: Option<String>,
}

#[derive(Debug, Deserialize)]
struct MimiConsentProofInput {
    request: Value,
    verification_method: arkret_wire::DidUrl,
    created_at: String,
    domain: String,
    audience: String,
    signing_seed_b64url: Option<String>,
}

#[derive(Debug, Deserialize)]
struct MlsKeyPackageUploadEntryInput {
    principal_id: DidCoreId,
    device_id: DeviceId,
    signing_seed_b64url: String,
}

#[derive(Debug, Deserialize)]
struct PrincipalControlRealmInput {
    principal_id: DidCoreId,
}

#[derive(Debug, Deserialize)]
struct WebvhPlaceholderDidInput {
    base_url: String,
    local_id: String,
}

#[derive(Debug, Deserialize)]
struct WebvhGenesisInput {
    base_url: String,
    local_id: String,
    root_seed_b64url: String,
    next_root_public_key_multibase: String,
    version_time: Option<String>,
    /// The preliminary DID document, authored against the DID that
    /// `webvh-placeholder-did` returns.
    document: Value,
}

#[derive(Debug, Deserialize)]
struct PrincipalRegistrationFixtureInput {
    station_url: String,
    gate_account_base_url: String,
    handoff_request_id: String,
    identity_creation_lease: Value,
    device_id: String,
    trust_domain: String,
    initial_session: InitialSessionFixtureInput,
}

#[derive(Debug, Deserialize)]
struct InitialSessionFixtureInput {
    session_public_key: arkret::CanonicalSessionPublicJwk,
    audience_id: DidCoreId,
}

#[derive(Debug, Deserialize)]
struct AccountHandoffRequestFixtureInput {
    request_id: String,
    audience_id: DidCoreId,
    oidc_issuer_uri: String,
    client_id: String,
    redirect_uri: String,
    state: String,
    nonce: String,
    authorization_code: String,
    code_verifier: String,
    dpop_seed_b64url: String,
}

#[derive(Debug, Deserialize)]
struct IdentityCreationRegisterFixtureInput {
    challenge: Value,
    did_operation: Value,
    pcr_genesis_unit: Value,
    initial_session: arkret::InitialSessionGrantIntent,
    recovery_key: String,
    display_name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PrincipalBootstrapSealInput {
    pcr_genesis_unit: Value,
    device_signing_seed_b64url: String,
}

#[derive(Debug, Deserialize)]
struct PrincipalSuccessorSealInput {
    events: Vec<Value>,
    predecessor_seal: Value,
    availability_receipt_issue_outcome: Value,
    device_signing_seed_b64url: String,
}

#[derive(Debug, Deserialize)]
struct WebvhVerifyLogInput {
    did: String,
    log_path: String,
    /// `service` selects the generic chain profile that admits service
    /// authority keys; anything else keeps the human-principal profile.
    profile: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct InstallManagedActorAuthorInput {
    authoring_request: Value,
    applet_package: arkret::AppletPackage,
    bot_actor_id: DidCoreId,
    bot_initial_resolution: arkret::ResolutionCommitment,
    bot_method_history_evidence: arkret::ResolutionMethodHistoryEvidence,
    service_signing_seed_b64url: String,
    service_verification_method: DidUrl,
    station_id: DidCoreId,
    station_verification_method: DidUrl,
    station_public_jwk: Value,
    trust_domain: arkret::TrustDomainId,
}

fn main() -> Result<()> {
    let command = std::env::args().nth(1).context("missing command")?;
    let input = read_stdin_json()?;

    let output = match command.as_str() {
        "canonical-json" => canonical_json(input)?,
        "sha256-canonical-json" => sha256_canonical_json(input)?,
        "event-envelope-proof" => event_proof(input, EventDigestMode::RawCanonicalJson)?,
        "event-derived-id" => event_derived_id(input)?,
        "event-envelope-parse" => event_envelope_parse(input)?,
        "mimi-consent-proof" => mimi_consent_proof(input)?,
        "mls-keypackage-upload-entry" => mls_keypackage_upload_entry(input)?,
        "principal-control-realm-id" => principal_control_realm(input)?,
        "webvh-placeholder-did" => webvh_placeholder_did_command(input)?,
        "webvh-genesis" => webvh_genesis(input)?,
        "webvh-verify-log" => webvh_verify_log(input)?,
        "account-handoff-outcome" => account_handoff_outcome(input)?,
        "account-handoff-request" => account_handoff_request(input)?,
        "principal-registration-fixture" => principal_registration_fixture(input)?,
        "identity-creation-register-request" => identity_creation_register_request(input)?,
        "principal-bootstrap-seal" => principal_bootstrap_seal(input)?,
        "principal-successor-seal" => principal_successor_seal(input)?,
        "install-managed-actor-author" => install_managed_actor_author(input)?,
        _ => bail!("unknown cotest-wire command {command:?}"),
    };

    println!("{}", serde_json::to_string(&output)?);
    Ok(())
}

fn install_managed_actor_author(input: Value) -> Result<Value> {
    let input: InstallManagedActorAuthorInput =
        serde_json::from_value(input).context("parse install managed-actor author input")?;
    let raw = &input.authoring_request;
    let basis = raw.get("basis").and_then(Value::as_object);
    let purpose = raw.get("purpose").and_then(Value::as_str);
    let target = basis
        .and_then(|value| value.get("target_station_id"))
        .and_then(Value::as_str);
    let applet_id = basis
        .and_then(|value| value.get("applet_id"))
        .and_then(Value::as_str);
    let service_id = basis
        .and_then(|value| value.get("service_id"))
        .and_then(Value::as_str);
    let package_digest = basis
        .and_then(|value| value.get("package_digest"))
        .and_then(Value::as_str);
    if purpose != Some("install_bot")
        || target != Some(input.station_id.as_str())
        || applet_id != Some(input.applet_package.applet_id.as_str())
        || service_id != Some(input.applet_package.service_id.as_str())
        || package_digest
            != input
                .applet_package
                .package_digest
                .as_ref()
                .map(arkret::Hash::as_str)
    {
        return Ok(author_rejection(
            "authoring_request_coordinate_mismatch",
            400,
            "signed request does not match the package-build authority coordinates",
        ));
    }

    let now = Utc::now();
    let issued_at = raw
        .get("issued_at")
        .and_then(Value::as_str)
        .and_then(|value| value.parse::<chrono::DateTime<Utc>>().ok());
    let expires_at = raw
        .get("expires_at")
        .and_then(Value::as_str)
        .and_then(|value| value.parse::<chrono::DateTime<Utc>>().ok());
    if !matches!((issued_at, expires_at), (Some(issued), Some(expires)) if issued < expires
        && expires - issued <= chrono::Duration::minutes(5)
        && expires > now
        && expires - now <= chrono::Duration::minutes(5))
    {
        return Ok(author_rejection(
            "authoring_request_expired",
            410,
            "authoring request freshness window is invalid",
        ));
    }

    let request: arkret::AppletManagedActorAuthoringRequest =
        match serde_json::from_value(input.authoring_request.clone()) {
            Ok(request) => request,
            Err(error) => {
                return Ok(author_rejection(
                    "authoring_request_coordinate_mismatch",
                    400,
                    &format!("authoring request is not a closed SDK carrier: {error}"),
                ));
            }
        };
    if let Err(error) = request.validate_bindings() {
        return Ok(author_rejection(
            "authoring_request_proof_invalid",
            400,
            &format!("authoring request bindings are invalid: {error}"),
        ));
    }
    if request.proof.created_at > now + chrono::Duration::seconds(30) {
        return Ok(author_rejection(
            "authoring_request_proof_invalid",
            400,
            "authoring request proof creation time is in the future",
        ));
    }
    if request.proof.verification_method != input.station_verification_method
        || request.proof.verification_method != request.hosting_notary.verification_method
    {
        return Ok(author_rejection(
            "authoring_request_proof_invalid",
            400,
            "authoring request was not signed by the current Station key",
        ));
    }
    let principal_key = arkret_signatures::PublicKeyMaterial::Jwk {
        value: input.station_public_jwk,
    };
    if arkret_signatures::Ed25519DetachedJwsVerifier::new()
        .verify_detached_jws(
            &request.proof.jws,
            &request.proof_binding_bytes()?,
            &principal_key,
        )
        .is_err()
    {
        return Ok(author_rejection(
            "authoring_request_proof_invalid",
            400,
            "authoring request detached proof is invalid",
        ));
    }

    let install = request
        .basis
        .install()
        .context("validated install request has no install basis")?;
    if input.bot_actor_id != input.applet_package.bot_actor_id
        || input.service_verification_method != input.applet_package.webhook_auth.key_ref
    {
        return Ok(author_rejection(
            "authoring_request_coordinate_mismatch",
            400,
            "package managed-actor material does not match the signed package",
        ));
    }
    let registration_evidence: arkret::AppletRegistrationEpochEvidence = install
        .registration_event
        .payload
        .get("manifest")
        .and_then(Value::as_object)
        .and_then(|manifest| manifest.get("registration_epoch_evidence"))
        .cloned()
        .context("registration Event omits registration epoch evidence")
        .and_then(|value| {
            serde_json::from_value(value).context("parse registration epoch evidence")
        })?;
    let expected_registration = input
        .applet_package
        .to_registration(&registration_evidence)
        .context("derive package registration payload")?;
    let actual_registration = serde_json::to_value(&install.registration_event.payload)
        .context("serialize registration Event payload")?;
    if actual_registration != serde_json::to_value(expected_registration)?
        || !registration_evidence.contains_signing_key(input.service_verification_method.as_str())
    {
        return Ok(author_rejection(
            "authoring_request_event_binding_invalid",
            400,
            "registration Event or epoch evidence does not bind the package service key",
        ));
    }
    let seal_basis: SealBasis = install
        .registration_event
        .seal_basis
        .clone()
        .context("registration Event omits the accepted Realm Seal basis")?;
    let seed = signing_key_from_seed(&input.service_signing_seed_b64url)?.to_bytes();
    let service_did = Did::new(
        input
            .service_verification_method
            .as_str()
            .split_once('#')
            .map(|(did, _)| did)
            .context("service verification method has no DID fragment")?,
    )?;
    let signer = arkret::Ed25519PayloadSigner::from_did_key_seed(
        seed,
        service_did,
        input.service_verification_method,
    );
    let request_digest = request.canonical_digest()?;
    let digest_bytes = hex::decode(
        request_digest
            .as_str()
            .strip_prefix("sha256:")
            .context("install authoring request digest is not SHA-256")?,
    )
    .context("decode install authoring request digest")?;
    let bundle = arkret::author_applet_managed_actor_bundle(
        &request,
        arkret::AppletManagedActorBundleAuthoringInput {
            actor_id: input.bot_actor_id,
            initial_resolution: input.bot_initial_resolution,
            method_history_evidence: input.bot_method_history_evidence,
            service_actor_seq: 0,
            service_prev_refs: Vec::new(),
            seal_basis,
            digest_suite: arkret::DigestSuite::Sha256,
            trust_domain: input.trust_domain,
            security_class: SecurityClass::Standard,
            genesis_salt: arkret::GenesisSalt::new(
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest_bytes),
            )?,
            bot_display_name: "Applet Bot".to_owned(),
        },
        &signer,
    )?;
    Ok(json!({ "managed_actor_bundle": bundle }))
}

fn author_rejection(code: &str, status: u16, detail: &str) -> Value {
    json!({ "error": code, "status": status, "detail": detail })
}

fn mls_keypackage_upload_entry(input: Value) -> Result<Value> {
    let input: MlsKeyPackageUploadEntryInput =
        serde_json::from_value(input).context("parse MLS KeyPackage upload-entry input")?;
    let seed = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(input.signing_seed_b64url)
        .context("decode MLS signing seed")?;
    let seed: [u8; 32] = seed
        .try_into()
        .map_err(|_| anyhow::anyhow!("MLS signing seed must be 32 bytes"))?;
    let identity = arkret::ArkretMlsIdentity::new_human_device(
        input.principal_id,
        input.device_id,
        arkret::ArkretMlsSigner::from_ed25519_signing_key(ed25519_dalek::SigningKey::from_bytes(
            &seed,
        )),
    )?;
    let record = identity.key_package_record()?;
    let entry = arkret_models_crypto::mls_key_package_record_upload_entry(&record)
        .map_err(anyhow::Error::msg)?;
    serde_json::to_value(entry).context("serialize MLS KeyPackage upload entry")
}

fn event_envelope_parse(input: Value) -> Result<Value> {
    let _: Event = serde_json::from_value(input).context("parse closed Event envelope")?;
    Ok(json!({ "valid": true }))
}

fn non_empty(value: impl Into<String>) -> Result<NonEmptyString> {
    NonEmptyString::new(value.into()).map_err(anyhow::Error::msg)
}

fn principal_registration_fixture(input: Value) -> Result<Value> {
    let input: PrincipalRegistrationFixtureInput =
        serde_json::from_value(input).context("parse principal-registration fixture input")?;
    let initial_session = arkret::InitialSessionGrantIntent {
        device_id: input
            .device_id
            .parse()
            .context("parse founding device id")?,
        session_public_key: input.initial_session.session_public_key,
        audience_id: input.initial_session.audience_id,
    };
    initial_session.validate()?;
    let endpoint = url::Url::parse(&input.station_url).context("parse Station URL")?;
    let created_at = Utc::now().with_nanosecond(0).unwrap_or_else(Utc::now);

    // Cotest fixture entropy is unique to this registration and never leaves
    // the local test process except as the user-facing mnemonic. Production
    // recovery-key generation remains OS-CSPRNG backed in Inkson.
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before Unix epoch")?
        .as_nanos();
    let mut entropy_hasher = Sha256::new();
    entropy_hasher.update(b"cotest-principal-registration-v1");
    entropy_hasher.update(input.handoff_request_id.as_bytes());
    entropy_hasher.update(input.device_id.as_bytes());
    entropy_hasher.update(nonce.to_le_bytes());
    let entropy: [u8; 32] = entropy_hasher.finalize().into();
    let mnemonic = bip39::Mnemonic::from_entropy(&entropy)
        .context("build 24-word principal recovery mnemonic")?;
    let recovery_key = mnemonic.words().collect::<Vec<_>>().join(" ");
    let key_material = arkret::identity_root::derive_identity_recovery_key_material_from_bip39(
        &recovery_key,
        "",
        0,
    )
    .context("derive principal recovery key material")?;
    let draft =
        arkret::webvh::prepare_principal_inception(&arkret::webvh::PrincipalInceptionInput {
            provider_endpoint: &endpoint,
            principal_endpoint: &endpoint,
            local_id: &input
                .handoff_request_id
                .trim_start_matches("ak:request:")
                .to_ascii_lowercase(),
            also_known_as: &[],
            version_time: created_at,
            root_seed: &key_material.root_seed,
            next_root_public_key_multibase: &key_material.next_root_public_key_multikey,
            witness_policy: None,
        })
        .context("prepare principal inception")?;
    let principal = Did::new(draft.did.clone()).context("parse prepared principal DID")?;
    let genesis_salt = arkret::GenesisSalt::generate()?;
    // The create Event has no Realm id yet. This value is only a local HLC
    // allocator namespace and is never emitted as the PCR coordinate.
    let genesis_stamp_scope = "ak:realm:ASyOHakrqmsRPkLKvhTD20V-YWCl-X7zYrlca5tdQLaR";
    let mut hlc = arkret::hlc::HlcGenerator::new(
        genesis_stamp_scope,
        &input.device_id,
        input.handoff_request_id.as_bytes(),
    );
    let recovery_key_fingerprint = format!(
        "sha256:{}",
        hex::encode(Sha256::digest(recovery_key.as_bytes()))
    );
    let did_operation = serde_json::to_value(&draft.submit_body)
        .context("serialize prepared principal DID operation")?;
    let did_document = draft
        .log_entry
        .get("state")
        .cloned()
        .context("prepared principal inception omitted DID document state")?;
    let document_digest = canonical::canonical_sha256(&did_document)
        .context("digest prepared principal DID document")?;
    let lease: arkret::IdentityCreationLease =
        serde_json::from_value(input.identity_creation_lease)
            .context("parse identity-creation lease")?;
    // One HLC value, used by BOTH the checkpoint field and the Event below.
    // Inkson rebuilds this Event from the checkpoint and compares canonical
    // bytes, so a second `generate()` here would fail that comparison.
    let bootstrap_hlc = hlc.generate().to_string();
    let (genesis_create_event, founding_authorize_event, device_signing_seed) =
        build_pcr_genesis_unit(
            &principal,
            initial_session.audience_id.clone(),
            genesis_salt.clone(),
            &input.trust_domain,
            &draft.version_id,
            &arkret_canonical::canonical_sha256(&draft.log_entry)?,
            &draft.root_public_key_multibase,
            &draft.root_verification_method,
            &key_material.root_seed,
            &input.device_id,
            input.handoff_request_id.as_bytes(),
            created_at,
            &bootstrap_hlc,
        )
        .context("build PCR genesis unit")?;
    let challenge_request = garth::identity_binding_challenge_request(
        arkret::RequestId::new(arkret_identifiers::new_prefixed_uuid7("ak:request:"))
            .context("build identity-binding challenge request id")?,
        &lease,
        draft.submit_body,
        &arkret_wire::PcrGenesisUnit::new(
            genesis_create_event.clone(),
            founding_authorize_event.clone(),
        )?,
        &initial_session,
    )
    .context("build identity-binding challenge request")?;
    let checkpoint = json!({
        "station_url": input.station_url,
        "gate_account_base_url": input.gate_account_base_url,
        "handoff_request_id": input.handoff_request_id,
        "lease_id": lease.identity_creation_lease_id,
        "lease_fence": lease.fence,
        "device_id": input.device_id,
        "trust_domain": input.trust_domain,
        "did": draft.did,
        "version_id": draft.version_id,
        "root_public_key_multibase": draft.root_public_key_multibase,
        "root_verification_method": draft.root_verification_method,
        "next_root_public_key_multibase": draft.next_root_public_key_multibase,
        "next_root_key_hash": draft.next_root_key_hash,
        "recovery_proof_public_key_multibase": key_material.recovery_proof_public_key_multikey,
        "backup_hpke_public_key_multibase": key_material.backup_hpke_public_key_multikey,
        "recovery_key_fingerprint": recovery_key_fingerprint,
        "did_operation": did_operation,
        "did_entry0_canonical_base64url": arkret::base64url_encode(
            canonical::canonical_json_bytes(&draft.log_entry)?
        ),
        "did_document": did_document,
        "document_digest": document_digest,
        "history_head": draft.version_id,
        // The signed genesis Event itself, not a reserved id for it. `ak:event:`
        // is an event-derived kind, so its id is a function of this finished
        // envelope; the id-only field this fixture used to emit was both
        // unreadable by Inkson and a forbidden random mint.
        "pcr_genesis_unit": {
            "events": [genesis_create_event, founding_authorize_event],
        },
        "initial_session": initial_session,
        "device_signing_seed_b64url": device_signing_seed,
        "genesis_created_at": arkret_canonical::format_timestamp_canonical(created_at),
        "genesis_hlc": bootstrap_hlc,
        "genesis_salt": genesis_salt,
        "binding_receipt": null,
        "stage": "custody_confirmed",
    });
    Ok(json!({
        "did_operation": checkpoint["did_operation"],
        "recovery_key": recovery_key,
        "checkpoint": checkpoint,
        "challenge_request": challenge_request,
    }))
}

/// The founding Principal Control Realm genesis Event, signed by the identity
/// root the 24 words derive.
///
/// This mirrors Inkson's `build_bootstrap_create_event` exactly, and it has to:
/// Inkson rebuilds the Event from the checkpoint's own fields and refuses the
/// checkpoint unless the canonical bytes match byte-for-byte. Every input below
/// is therefore taken from a field the checkpoint also stores, and the cell
/// projector is the same `DigestSuite::Sha256` projection Inkson routes through.
#[allow(clippy::too_many_arguments)]
fn build_pcr_genesis_unit(
    principal: &Did,
    station_id: DidCoreId,
    genesis_salt: arkret::GenesisSalt,
    trust_domain: &str,
    version_id: &str,
    method_history_head: &str,
    root_public_key_multibase: &str,
    root_verification_method: &str,
    root_seed: &[u8; 32],
    device_id: &str,
    device_seed_basis: &[u8],
    created_at: chrono::DateTime<Utc>,
    hlc: &str,
) -> Result<(Event, Event, String)> {
    let principal_id = project_did_to_core_id(principal)?;
    let principal_device_id = DeviceId::new(device_id.to_owned()).context("parse device id")?;
    let device_seed: [u8; 32] = Sha256::digest(
        [
            b"cotest-pcr-genesis-device-v1".as_slice(),
            device_seed_basis,
        ]
        .concat(),
    )
    .into();
    let device_key = SigningKey::from_bytes(&device_seed);
    let device_public_key_bytes = device_key.verifying_key().to_bytes();
    let device_multibase =
        arkret_canonical::ed25519_pubkey_to_did_key_multibase(&device_public_key_bytes);
    let device_public_key = non_empty(format!("did:key:{device_multibase}"))?;
    let hpke_key = non_empty("z6LSCotestPcrGenesisHpkeKey")?;
    let algorithms = vec![non_empty("ak.hpke_x25519_aead_chacha20poly1305.v1")?];
    let mut authorize_payload =
        arkret_models_collaboration::events_payloads::DeviceAuthorizePayload {
            principal_id: principal_id.clone(),
            device_id: principal_device_id.clone(),
            device_public_key_did: device_public_key.clone(),
            hpke_key: hpke_key.clone(),
            algorithms: algorithms.clone(),
            device_key_algorithm: Some(non_empty("Ed25519")?),
            authorized_by:
                arkret_models_collaboration::events_payloads::DeviceOrPrincipalRef::Principal(
                    principal_id.clone(),
                ),
            scopes: None,
            not_before: created_at,
            expires_at: None,
            authorization_binding_kind: arkret_models_collaboration::events_payloads::DeviceAuthorizationBindingKind::RegistrationAnchor,
            device_signature: arkret_models_collaboration::events_payloads::SignatureMaterial::NonEmptyString(
                non_empty("pending")?,
            ),
            recovery_session_id: None,
        };
    authorize_payload.device_signature =
        arkret_models_collaboration::events_payloads::SignatureMaterial::NonEmptyString(non_empty(
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
                device_key
                    .sign(&authorize_payload.device_possession_signature_input()?)
                    .to_bytes(),
            ),
        )?);
    let authorize_payload_value = serde_json::to_value(&authorize_payload)?;
    let founding_notary = arkret::NotaryValue::single_signer(arkret::NotarySignerDescriptor {
        actor_id: principal_id.clone(),
        verification_method: arkret::DidUrl::new(format!("{principal}#{device_id}"))
            .map_err(anyhow::Error::msg)?,
        key_kind: arkret::NotaryKeyKind::Ed25519Raw32,
        jose_algorithm: arkret::NotaryJoseAlgorithm::Ed25519,
        frozen_public_key_b64u: arkret::base64url_encode(device_public_key_bytes),
        frozen_public_key_digest: arkret::Hash::new(arkret_canonical::canonical::sha256_digest(
            device_public_key_bytes,
        ))?,
    });
    founding_notary.validate()?;
    let descriptor = arkret_models_collaboration::events_payloads::FoundingDeviceDescriptor {
        descriptor_version: 1,
        device_id: principal_device_id,
        device_key_digest: arkret::Hash::new(arkret_canonical::canonical::sha256_digest(
            device_public_key.as_bytes(),
        ))?,
        device_public_key_did: device_public_key,
        device_key_algorithm:
            arkret_models_collaboration::events_payloads::FoundingDeviceKeyAlgorithm::Ed25519,
        device_key_purpose:
            arkret_models_collaboration::events_payloads::FoundingDeviceKeyPurpose::EventSigningAndMlsIdentity,
        hpke_key_digest: arkret::Hash::new(arkret_canonical::canonical::sha256_digest(
            hpke_key.as_bytes(),
        ))?,
        hpke_key,
        hpke_key_algorithm:
            arkret_models_collaboration::events_payloads::FoundingDeviceHpkeKeyAlgorithm::X25519,
        algorithms,
        founding_authorize_payload_digest:
            arkret_models_collaboration::events_payloads::device_authorize_payload_digest(
                &authorize_payload_value,
                arkret_canonical::DigestSuite::Sha256,
            )?,
    };
    let mut create = arkret_bootstrap::build_self_principal_pcr_create(
        arkret_bootstrap::SelfPrincipalPcrCreateInput {
            principal_id: principal_id.clone(),
            station_id,
            principal_did: principal.clone(),
            notary: founding_notary,
            initial_resolution: arkret_models_identity::ResolutionCommitment {
                did: principal.clone(),
                method_history_head: method_history_head.to_owned(),
                version_id: version_id.to_owned(),
            },
            genesis_salt,
            trust_domain: arkret::TrustDomainId::new(trust_domain.to_owned())
                .context("parse trust domain")?,
            did_inception_ref: arkret::EventRef::new(
                version_id.to_owned(),
                arkret_bootstrap::DID_INCEPTION_REF_ROLE,
            ),
            founding_device_descriptor: descriptor,
            created_at,
            hlc: arkret::Hlc::new(hlc.to_owned()).context("parse bootstrap HLC")?,
        },
        &|event| {
            arkret_schema::project_registered_cell_writes(
                event,
                arkret_canonical::DigestSuite::Sha256,
            )
            .map_err(|error| error.to_string())
        },
    )
    .context("build self principal PCR create")?;

    let root_did = Did::new(format!("did:key:{root_public_key_multibase}"))
        .context("parse identity root did:key")?;
    let root_verification_method = arkret_wire::DidUrl::new(root_verification_method.to_owned())
        .map_err(anyhow::Error::msg)
        .context("parse identity root verification method")?;
    let root_signer = arkret::Ed25519PayloadSigner::from_did_key_seed(
        *root_seed,
        root_did,
        root_verification_method.clone(),
    );
    arkret::signatures::sign_event(
        &mut create,
        &root_signer,
        &root_verification_method,
        arkret::signatures::SignEventOptions::new().with_created_at(created_at),
    )
    .context("sign the PCR genesis Event with the identity root")?;
    let mut authorize = arkret_event_draft::TypedEventDraft::<
        arkret_wire::event_spec::DeviceAuthorize,
    >::new(
        arkret::ScopeRef::Realm {
            realm_id: create.realm_id.clone(),
        },
        create.actor_id.clone(),
        authorize_payload,
    )?
    .with_prev_refs(vec![create.event_id.clone()])
    .author_with_digest_suite(
        1,
        arkret::hlc::HlcGenerator::new(create.realm_id.as_str(), device_id, root_seed).generate(),
        created_at,
        arkret_canonical::DigestSuite::Sha256,
    )?;
    let device_method =
        arkret_wire::DidUrl::new(format!("{principal}#{device_id}")).map_err(anyhow::Error::msg)?;
    let device_did = Did::new(format!("did:key:{device_multibase}"))?;
    let device_signer = arkret::Ed25519PayloadSigner::from_did_key_seed(
        device_seed,
        device_did,
        device_method.clone(),
    );
    arkret::signatures::sign_event(
        &mut authorize,
        &device_signer,
        &device_method,
        arkret::signatures::SignEventOptions::new().with_created_at(created_at),
    )?;
    arkret_bootstrap::validate_self_principal_pcr_genesis_unit(&create, &authorize, &|event| {
        arkret_schema::project_registered_cell_writes(event, arkret_canonical::DigestSuite::Sha256)
            .map_err(|error| error.to_string())
    })?;
    Ok((
        create.into_event(),
        authorize.into_event(),
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(device_seed),
    ))
}

/// The webvh method authority (`host` or `host%3Aport`) of a hosting endpoint.
fn webvh_method_authority(base_url: &str) -> Result<String> {
    let endpoint = url::Url::parse(base_url).context("parse webvh hosting endpoint")?;
    let host = endpoint
        .host_str()
        .context("webvh hosting endpoint has no host")?;
    if !host.contains('.') {
        bail!("webvh hosting host must contain a dot: {host}");
    }
    Ok(arkret::webvh::skeleton::webvh_authority_pair(host, endpoint.port()).0)
}

/// The preliminary `did:webvh:{SCID}:…` a genesis DID document is authored
/// against. Callers build their document from this DID and hand it back to
/// `webvh-genesis`, which substitutes the derived SCID over the whole entry.
fn webvh_placeholder_did_command(input: Value) -> Result<Value> {
    let input: WebvhPlaceholderDidInput =
        serde_json::from_value(input).context("parse webvh placeholder DID input")?;
    let method_authority = webvh_method_authority(&input.base_url)?;
    Ok(json!({
        "method_authority": method_authority,
        "did": arkret::webvh::skeleton::webvh_placeholder_did(&method_authority, &input.local_id),
    }))
}

/// Verify one fetched `did:webvh` history (`did.jsonl`) against its DID.
///
/// The joint runner's TLS-topology preflight uses this as an independent
/// third-party check: the bytes come from an HTTPS fetch through the managed
/// reverse proxy, and the chain proof runs here rather than inside the service
/// that published the log. `profile = "service"` selects the generic chain
/// verifier (`verify_did_webvh_v1_chain_bytes`), which admits service
/// authority keys; the default keeps the human-principal profile
/// (`verify_did_webvh_v1_log_bytes`).
fn webvh_verify_log(input: Value) -> Result<Value> {
    let input: WebvhVerifyLogInput =
        serde_json::from_value(input).context("parse webvh verify-log input")?;
    let did = Did::new(input.did).context("parse webvh DID")?;
    let bytes = std::fs::read(&input.log_path)
        .with_context(|| format!("read webvh log {}", input.log_path))?;
    let verified = match input.profile.as_deref() {
        Some("service") => arkret_identity::verify_did_webvh_v1_chain_bytes(&did, &bytes)
            .context("verify did:webvh service chain")?,
        _ => arkret_identity::verify_did_webvh_v1_log_bytes(&did, &bytes)
            .context("verify did:webvh log")?,
    };
    Ok(json!({
        "verified": true,
        "head_version_id": verified.head_version_id,
        "entry_count": verified.entries.len(),
    }))
}

/// Build one signed `did:webvh` entry-0 through the SDK builders.
///
/// The conformance harness owns no webvh construction of its own: SCID
/// derivation, the whole-entry `{SCID}` substitution (identity-did.md §3.4.4),
/// the entry hash and the `eddsa-jcs-2022` proof all come from the SDK, so a
/// harness-minted genesis is byte-identical to a client-minted one.
fn webvh_genesis(input: Value) -> Result<Value> {
    use arkret::webvh::skeleton::{
        WebvhInceptionSkeletonInput, build_webvh_inception_skeleton, derive_webvh_scid,
        finalize_webvh_scid_substitution, format_webvh_did, webvh_entry_hash_multibase,
        webvh_next_key_hash_value,
    };

    let input: WebvhGenesisInput =
        serde_json::from_value(input).context("parse webvh genesis input")?;
    let method_authority = webvh_method_authority(&input.base_url)?;
    let root_signing = signing_key_from_seed(&input.root_seed_b64url)?;
    let root_public_key_multibase = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
        &root_signing.verifying_key().to_bytes(),
    );
    if root_public_key_multibase == input.next_root_public_key_multibase {
        bail!("active and next WebVH root keys must be distinct");
    }
    let version_time = match input.version_time {
        Some(version_time) => version_time,
        None => arkret_canonical::format_timestamp_canonical(Utc::now()),
    };
    let next_root_key_hash = webvh_next_key_hash_value(&input.next_root_public_key_multibase);
    let skeleton = build_webvh_inception_skeleton(&WebvhInceptionSkeletonInput {
        version_time: &version_time,
        update_keys: std::slice::from_ref(&root_public_key_multibase),
        next_key_hashes: std::slice::from_ref(&next_root_key_hash),
        portable: None,
        witness: None,
        state: &input.document,
    });
    let scid = derive_webvh_scid(&skeleton).context("derive webvh SCID")?;
    let mut entry = finalize_webvh_scid_substitution(&skeleton, &scid)
        .context("substitute the derived webvh SCID")?;
    let version_id = format!(
        "1-{}",
        webvh_entry_hash_multibase(&entry, &scid).context("hash the webvh genesis entry")?
    );
    let did = format_webvh_did(&method_authority, &scid, &input.local_id);
    let did_document = entry
        .get("state")
        .cloned()
        .context("webvh genesis entry has no DID document state")?;
    if let Value::Object(map) = &mut entry {
        map.insert("versionId".to_owned(), Value::String(version_id.clone()));
    }
    let proof = arkret_signatures::build_eddsa_jcs_2022_proof(
        &entry,
        &root_signing,
        &format!("did:key:{root_public_key_multibase}#{root_public_key_multibase}"),
        arkret_signatures::DataIntegrityProofPurpose::AssertionMethod,
    )
    .map_err(|error| anyhow::anyhow!("sign webvh genesis entry: {error}"))?;
    if let Value::Object(map) = &mut entry {
        map.insert("proof".to_owned(), Value::Array(vec![proof]));
    }
    Ok(json!({
        "did": did,
        "scid": scid,
        "versionId": version_id,
        "entry": entry,
        "didDocument": did_document,
    }))
}

fn account_handoff_request(input: Value) -> Result<Value> {
    let input: AccountHandoffRequestFixtureInput =
        serde_json::from_value(input).context("parse account-handoff request input")?;
    let signing_key = signing_key_from_seed(&input.dpop_seed_b64url)?;
    let request = garth::oidc_account_handoff_request(
        garth::OidcAccountHandoffInput {
            request_id: arkret::RequestId::new(input.request_id)
                .context("parse account-handoff request id")?,
            audience_id: input.audience_id,
            issuer_uri: input.oidc_issuer_uri,
            client_id: input.client_id,
            redirect_uri: input.redirect_uri,
            state: input.state,
            nonce: input.nonce,
            authorization_code: input.authorization_code,
            code_verifier: input.code_verifier,
        },
        |bytes| {
            Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(signing_key.sign(bytes).to_bytes()))
        },
    )
    .context("build account-handoff request")?;
    serde_json::to_value(request).context("serialize account-handoff request")
}

fn account_handoff_outcome(input: Value) -> Result<Value> {
    let outcome: arkret_models_identity::AccountHandoffOutcome =
        serde_json::from_value(input).context("parse typed account-handoff outcome")?;
    outcome
        .validate()
        .context("validate account-handoff outcome")?;
    serde_json::to_value(outcome).context("serialize validated account-handoff outcome")
}

fn identity_creation_register_request(input: Value) -> Result<Value> {
    let input: IdentityCreationRegisterFixtureInput =
        serde_json::from_value(input).context("parse identity-creation register input")?;
    let challenge: arkret::IdentityBindingChallengeOutcome =
        serde_json::from_value(input.challenge).context("parse identity-binding challenge")?;
    let did_operation: arkret::DidOperationSubmitRequestBody =
        serde_json::from_value(input.did_operation).context("parse DID operation")?;
    let key_material = arkret::identity_root::derive_identity_recovery_key_material_from_bip39(
        &input.recovery_key,
        "",
        0,
    )
    .context("derive identity root for control proof")?;
    let expected_account_subject = challenge.account_subject.clone();
    let request = garth::identity_creation_register_request(
        &challenge,
        &expected_account_subject,
        did_operation,
        serde_json::from_value(input.pcr_genesis_unit).context("parse PCR genesis unit")?,
        input.initial_session,
        &key_material.root_seed,
        input.display_name,
    )
    .context("build identity-creation register request")?;
    serde_json::to_value(request).context("serialize identity-creation register request")
}

fn trusted_actor_signer_material(event: &Event) -> Result<(Did, DidUrl)> {
    let verification_method = event
        .proofs
        .iter()
        .find_map(arkret_wire::EventProof::as_producer)
        .context("founding DeviceAuthorize lacks its signed proof")?
        .verification_method
        .clone();
    let controller = verification_method
        .as_str()
        .split_once('#')
        .map(|(controller, _)| controller)
        .context("founding DeviceAuthorize proof method lacks a controller fragment")?;
    let controller = Did::new(controller.to_owned())
        .context("parse founding DeviceAuthorize proof controller DID")?;
    let controller_actor = project_did_to_core_id(&controller)
        .context("project founding DeviceAuthorize proof controller")?;
    if &controller_actor != event.actor_id.signing_principal_id() {
        bail!("founding DeviceAuthorize proof controller does not match its actor core id");
    }
    Ok((controller, verification_method))
}

fn principal_bootstrap_seal(input: Value) -> Result<Value> {
    let input: PrincipalBootstrapSealInput =
        serde_json::from_value(input).context("parse principal bootstrap Seal input")?;
    let unit: arkret_wire::PcrGenesisUnit = serde_json::from_value(input.pcr_genesis_unit)
        .context("parse PCR genesis unit for bootstrap Seal")?;
    let create = unit.create();
    let authorize = unit.founding_authorize();
    let create_payload = create
        .typed_payload::<arkret::event_spec::RealmCreate>()
        .context("parse PCR create payload")?;
    let descriptor = create_payload
        .object
        .founding_device_descriptor
        .context("PCR create omits founding device descriptor")?;
    let seed = signing_key_from_seed(&input.device_signing_seed_b64url)?.to_bytes();
    let (signer_did, verification_method) = trusted_actor_signer_material(authorize)?;
    let signer =
        arkret::Ed25519PayloadSigner::from_did_key_seed(seed, signer_did, verification_method);
    let mut hlc = arkret_hlc::HlcGenerator::new(
        create.realm_id.as_str(),
        descriptor.device_id.as_str(),
        &seed,
    );
    let seal = arkret_bootstrap::build_self_principal_bootstrap_seal(
        create,
        authorize,
        hlc.generate(),
        &signer,
        &|event| {
            arkret_schema::project_registered_cell_writes(
                event,
                arkret_canonical::DigestSuite::Sha256,
            )
            .map_err(|error| error.to_string())
        },
    )
    .context("build self-principal bootstrap Seal")?;
    serde_json::to_value(seal).context("serialize self-principal bootstrap Seal")
}

fn principal_successor_seal(input: Value) -> Result<Value> {
    let input: PrincipalSuccessorSealInput =
        serde_json::from_value(input).context("parse principal successor Seal input")?;
    let events = input
        .events
        .into_iter()
        .map(|event| serde_json::from_value(event).context("parse principal control Event"))
        .collect::<Result<Vec<Event>>>()?;
    let create = events
        .first()
        .context("principal successor Seal history is empty")?;
    let create_payload = create
        .typed_payload::<arkret::event_spec::RealmCreate>()
        .context("parse PCR create payload")?;
    let descriptor = create_payload
        .object
        .founding_device_descriptor
        .context("PCR create omits founding device descriptor")?;
    let founding_authorize = events
        .get(1)
        .context("principal successor Seal history omits founding DeviceAuthorize")?;
    if founding_authorize.actor_id != create.actor_id {
        bail!("founding DeviceAuthorize actor does not match PCR create actor");
    }
    let predecessor: arkret_wire::Seal = serde_json::from_value(input.predecessor_seal)
        .context("parse resolved principal predecessor Seal")?;
    let availability = serde_json::from_value(input.availability_receipt_issue_outcome)
        .context("parse principal successor availability receipt issue outcome")?;
    let seed = signing_key_from_seed(&input.device_signing_seed_b64url)?.to_bytes();
    let (signer_did, verification_method) = trusted_actor_signer_material(founding_authorize)?;
    let signer =
        arkret::Ed25519PayloadSigner::from_did_key_seed(seed, signer_did, verification_method);
    let mut hlc = arkret_hlc::HlcGenerator::new(
        create.realm_id.as_str(),
        descriptor.device_id.as_str(),
        &seed,
    );
    let seal = arkret_bootstrap::build_self_principal_linear_successor_seal(
        &events,
        &predecessor,
        &availability,
        hlc.generate(),
        &signer,
        &|event| {
            arkret_schema::project_registered_cell_writes(
                event,
                arkret_canonical::DigestSuite::Sha256,
            )
            .map_err(|error| error.to_string())
        },
    )
    .context("build self-principal successor Seal")?;
    serde_json::to_value(seal).context("serialize self-principal successor Seal")
}

fn signing_key_from_seed(seed_b64url: &str) -> Result<SigningKey> {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(seed_b64url)
        .context("decode Ed25519 seed")?;
    let seed: [u8; 32] = bytes.try_into().map_err(|bytes: Vec<u8>| {
        anyhow::anyhow!("Ed25519 seed must be 32 bytes, got {}", bytes.len())
    })?;
    Ok(SigningKey::from_bytes(&seed))
}

fn read_stdin_json() -> Result<Value> {
    let mut stdin = String::new();
    io::stdin()
        .read_to_string(&mut stdin)
        .context("read stdin")?;
    serde_json::from_str(&stdin).context("parse stdin JSON")
}

fn canonical_json(input: Value) -> Result<Value> {
    let input: CanonicalInput = serde_json::from_value(input).context("parse canonical input")?;
    let bytes = canonical::canonical_json_bytes(&input.value).context("canonical JSON encode")?;
    let canonical = String::from_utf8(bytes).context("canonical JSON was not UTF-8")?;
    Ok(json!({ "canonical": canonical }))
}

fn sha256_canonical_json(input: Value) -> Result<Value> {
    let input: CanonicalInput = serde_json::from_value(input).context("parse digest input")?;
    let digest = canonical::canonical_sha256(&input.value).context("canonical JSON digest")?;
    Ok(json!({
        "digest": digest,
        "digest_hex": digest.strip_prefix("sha256:").unwrap_or(digest.as_str()),
    }))
}

fn principal_control_realm(input: Value) -> Result<Value> {
    let input: PrincipalControlRealmInput =
        serde_json::from_value(input).context("parse principal-control realm input")?;
    let _principal_id = input.principal_id;
    bail!(
        "principal-control Realm is event-derived; this command requires an accepted create Event and cannot derive it from a DID"
    )
}

#[derive(Clone, Copy)]
enum EventDigestMode {
    RawCanonicalJson,
}

fn event_proof(input: Value, digest_mode: EventDigestMode) -> Result<Value> {
    let input: EventProofInput =
        serde_json::from_value(input).context("parse event proof input")?;
    let actor_did = Did::new(input.actor_did.clone()).context("parse actor DID")?;
    let actor_core =
        project_did_to_core_id(&actor_did).context("project actor DID to its core id")?;
    let actor: arkret_wire::ActorId = serde_json::from_value(
        input
            .event
            .get("actor_id")
            .cloned()
            .context("Event proof input requires actor_id")?,
    )
    .context("parse Event actor_id")?;
    if actor.signing_principal_id() != &actor_core {
        bail!("Event actor_id does not match actor_did");
    }
    let created_at = canonical::parse_timestamp_canonical(&input.created_at)
        .with_context(|| format!("parse proof created_at {:?}", input.created_at))?;
    let event_digest =
        Hash::new(event_digest(&input.event, digest_mode)?).context("parse event digest")?;
    let signing_key = match input.signing_seed_b64url.as_deref() {
        Some(seed) => signing_key_from_seed(seed).context("parse event signing seed")?,
        None => development_event_signing_key(&input.verification_method),
    };

    let mut proof = ProducerEventProof {
        kind: proof_kind::DETACHED_JWS.to_owned(),
        verification_method: input.verification_method,
        event_digest,
        signer_resolution_evidence_ref: None,
        signer_resolution_evidence_digest: None,
        created_at,
        domain: None,
        audience: None,
        proof_purpose: None,
        jws: String::new(),
    };
    let binding_bytes = proof
        .canonical_binding_bytes(&actor)
        .context("encode event proof binding")?;
    proof.jws = arkret_signatures::proof::sign_ed25519_detached_jws(&signing_key, &binding_bytes)
        .map_err(|err| anyhow::anyhow!("sign event proof: {err}"))?;

    serde_json::to_value(proof).context("serialize event proof")
}

fn mimi_consent_proof(input: Value) -> Result<Value> {
    let input: MimiConsentProofInput =
        serde_json::from_value(input).context("parse MIMI consent proof input")?;
    let created_at = canonical::parse_timestamp_canonical(&input.created_at)
        .with_context(|| format!("parse proof created_at {:?}", input.created_at))?;
    let consent_id = input
        .request
        .get("consent_id")
        .and_then(Value::as_str)
        .context("MIMI consent request requires consent_id")?;
    let decision = input
        .request
        .get("decision")
        .cloned()
        .context("MIMI consent request requires decision")?;
    let actor_id: arkret_wire::ActorId = serde_json::from_value(
        input
            .request
            .get("actor_id")
            .cloned()
            .context("MIMI consent request requires actor_id")?,
    )
    .context("parse MIMI consent actor_id")?;
    let consent_event = input
        .request
        .get("consent_event")
        .cloned()
        .context("MIMI consent request requires consent_event")?;
    let reason = input
        .request
        .get("reason")
        .and_then(Value::as_str)
        .map(AuditReasonText::new)
        .transpose()
        .map_err(|error| anyhow::anyhow!("parse MIMI consent reason: {error}"))?;
    let expires_at = input
        .request
        .get("expires_at")
        .map(|value| serde_json::from_value(value.clone()))
        .transpose()
        .context("parse MIMI consent expires_at")?;
    let mut request = MimiUpdateConsentRequestBody {
        consent_id: ConsentId::new(consent_id.to_owned()).context("parse consent id")?,
        decision: serde_json::from_value::<MimiConsentDecision>(decision)
            .context("parse consent decision")?,
        actor_id,
        consent_event: serde_json::from_value::<EventInitialSubmission>(consent_event)
            .context("parse MIMI consent Event")?,
        signature: PayloadProof {
            kind: proof_kind::DETACHED_JWS.to_owned(),
            verification_method: input.verification_method.clone(),
            payload_digest: Hash::new(format!("sha256:{}", "0".repeat(64)))
                .context("build placeholder payload digest")?,
            created_at,
            domain: Some(input.domain),
            audience: Some(Audience::Single(input.audience)),
            proof_purpose: None,
            jws: "pending".to_owned(),
        },
        reason,
        expires_at,
    };
    request.signature.payload_digest =
        request.payload_digest().context("digest consent request")?;
    let binding = request
        .signature_binding_bytes()
        .context("encode MIMI consent proof binding")?;
    let signing_key = match input.signing_seed_b64url.as_deref() {
        Some(seed) => signing_key_from_seed(seed).context("parse MIMI consent signing seed")?,
        None => development_event_signing_key(&input.verification_method),
    };
    request.signature.jws =
        arkret_signatures::proof::sign_ed25519_detached_jws(&signing_key, &binding)
            .map_err(|error| anyhow::anyhow!("sign MIMI consent proof: {error}"))?;
    serde_json::to_value(request.signature).context("serialize MIMI consent proof")
}

/// The content-bound `event_id` of an envelope, derived the SDK way.
///
/// `encoding.md` section 4.0 makes an Event id a function of the Event's own
/// digest, and section 6 keeps `event_id` out of that digest's preimage. A
/// producer therefore builds the complete digest preimage, derives the id and
/// only then signs. TypeScript callers send that digest-payload shape here and
/// get the real identity back.
fn event_derived_id(event: Value) -> Result<Value> {
    let mut event = event;
    if let Value::Object(object) = &mut event {
        for excluded in ["event_id", "proofs", "unsigned", "actor_kind"] {
            object.remove(excluded);
        }
    }
    let digest_payload_bytes = arkret_canonical::canonical_json_bytes(&event)
        .context("canonicalize SDK Event digest payload")?;
    // This helper serves the existing fixed SHA-256 conformance fixtures.
    // Dynamic-suite protocol paths use the SDK authoring APIs with an explicit
    // replay-derived suite instead of this test-only command.
    let mut event = Event::from_digest_payload_bytes(
        &digest_payload_bytes,
        arkret_canonical::DigestSuite::Sha256,
    )
    .context("derive SDK Event identity from digest payload")?;
    // A Realm genesis names no Realm, so its `realm_id` is a function of the
    // Event that creates it and can only be computed once the Event has its
    // own id. Callers get both back because neither is theirs to choose.
    if event.scope_ref.realm_id_opt().is_none() {
        event.realm_id = arkret_wire::derive_genesis_realm_id(&event.event_id);
    }
    let object_id = arkret_schema::derived_object_id_for_kind(event.kind.as_str(), &event.event_id);
    let event_digest = event
        .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
        .context("derive SDK Event digest")?;
    Ok(serde_json::json!({
        "event_id": event.event_id.to_string(),
        "event_digest": event_digest,
        "realm_id": event.realm_id.to_string(),
        "object_id": object_id,
    }))
}

fn event_digest(event: &Value, _mode: EventDigestMode) -> Result<String> {
    // Use the SDK projection that every verifier uses. Deserializing before
    // hashing is significant: wire defaults such as EventRef.critical=true
    // are part of Event::digest_payload even when the producer omitted them.
    let mut event = event.clone();
    if let Value::Object(object) = &mut event {
        object
            .entry("proofs")
            .or_insert_with(|| Value::Array(Vec::new()));
    }
    let event: Event = serde_json::from_value(event).context("parse SDK Event digest payload")?;
    let payload = event
        .digest_payload()
        .context("build SDK Event digest payload")?;
    canonical::canonical_sha256(&payload).context("hash event digest payload")
}

fn development_event_signing_key(verification_method: &str) -> SigningKey {
    arkret_signatures::development_signing_key(verification_method)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn actor_ids(value: &str) -> (Did, DidCoreId) {
        let did = Did::new(value.to_owned()).unwrap();
        let core_id = project_did_to_core_id(&did).unwrap();
        (did, core_id)
    }

    #[test]
    fn event_digest_uses_producer_envelope_canonical_bytes() {
        let (_, actor_id) = actor_ids(
            "did:webvh:zQmV5MGgUvFGbi15ajBaMzdXR5KQzL3TVDxM7VFQCv5nCwH5C:01kwxhre7cexz894j3nmsvmqh5",
        );
        let event = json!({
            "event_id": "ak:event:AU_Y0iurnoT0IOtu1_ZyZP3V36hCxZmUCbEVS2jcWjxe",
            "kind": "ak.member.state",
            "realm_id": "ak:realm:AV0aa7N4-6SpEMTq2vRgjNbMjn0vCIqfM5PxnJ-qQpPP",
            "scope_ref": {"kind": "realm", "realm_id": "ak:realm:AV0aa7N4-6SpEMTq2vRgjNbMjn0vCIqfM5PxnJ-qQpPP"},
            "actor_id": actor_id,
            "station_id": "ak:did_core:web:principal.example",
            "actor_seq": 1,
            "created_at": "2026-07-07T05:45:49.000Z",
            "hlc": "019f3b1c76c8-0000-ac7eadec",
            "prev_refs": [],
            "refs": [],
            "requirements": {
                "schema": ["ak.schema.event_payload.v1"],
                "features": [],
                "critical_extensions": []
            },
            "payload": {
                "realm_id": "ak:realm:AV0aa7N4-6SpEMTq2vRgjNbMjn0vCIqfM5PxnJ-qQpPP",
                "actor_id": actor_id,
                "membership": "join",
                "reason": "invite_accept"
            },
            "unsigned": {"trace": "local"},
            "scope_ref": {
                "kind": "realm",
                "realm_id": "ak:realm:AV0aa7N4-6SpEMTq2vRgjNbMjn0vCIqfM5PxnJ-qQpPP"
            },
            "actor_kind": "native",
            "proofs": []
        });

        let digest = event_digest(&event, EventDigestMode::RawCanonicalJson).unwrap();
        let producer_event: Event = serde_json::from_value(event).unwrap();
        let producer_event = producer_event.digest_payload().unwrap();

        assert_eq!(
            digest,
            canonical::canonical_sha256(&producer_event).unwrap()
        );
    }

    #[test]
    fn event_digest_materializes_sdk_ref_defaults() {
        let (_, actor_id) = actor_ids(
            "did:webvh:zQmV5MGgUvFGbi15ajBaMzdXR5KQzL3TVDxM7VFQCv5nCwH5C:01kwxhre7cexz894j3nmsvmqh5",
        );
        let event = json!({
            "event_id": "ak:event:AU_Y0iurnoT0IOtu1_ZyZP3V36hCxZmUCbEVS2jcWjxe",
            "kind": "ak.morph.update",
            "realm_id": "ak:realm:AV0aa7N4-6SpEMTq2vRgjNbMjn0vCIqfM5PxnJ-qQpPP",
            "scope_ref": {"kind": "realm", "realm_id": "ak:realm:AV0aa7N4-6SpEMTq2vRgjNbMjn0vCIqfM5PxnJ-qQpPP"},
            "actor_id": actor_id,
            "station_id": "ak:did_core:web:principal.example",
            "actor_seq": 1,
            "created_at": "2026-07-07T05:45:49.000Z",
            "hlc": "019f3b1c76c8-0000-ac7eadec",
            "prev_refs": [],
            "refs": [{
                "role": "authorized_by",
                "id": "ak:grant:AVmnCiapkC3K0OFT032clTI00FaccV3R4XoEuGk4xygg"
            }],
            "requirements": {"schema": ["ak.schema.event_payload.v1"]},
            "payload": {
                "target_ref": "ak:morph:Aa8s5OtJTr4DL7dYQbiLrzNhuis8EyjprcGjTo_qPZDF",
                "patch": [{"op": "replace", "path": "fields.status", "value": "review"}]
            }
        });
        let raw_digest = canonical::canonical_sha256(&event).unwrap();
        let sdk_digest = event_digest(&event, EventDigestMode::RawCanonicalJson).unwrap();
        let mut event_with_proofs = event;
        event_with_proofs["proofs"] = json!([]);
        let sdk_event: Event = serde_json::from_value(event_with_proofs).unwrap();
        let sdk_payload = sdk_event.digest_payload().unwrap();

        assert_eq!(sdk_payload["refs"][0]["critical"], json!(true));
        assert_ne!(sdk_digest, raw_digest);
        assert_eq!(
            sdk_digest,
            canonical::canonical_sha256(&sdk_payload).unwrap()
        );
    }

    #[test]
    fn fallback_event_signer_uses_sdk_method_bound_development_key() {
        let method = "did:webvh:z6mkfixture:alice.example#device";

        assert_eq!(
            development_event_signing_key(method).verifying_key(),
            arkret_signatures::development_verifying_key(method)
        );
        assert_ne!(
            development_event_signing_key(method).verifying_key(),
            arkret_signatures::development_verifying_key(
                "did:webvh:z6mkfixture:alice.example#other-device"
            )
        );
    }

    #[test]
    fn event_proof_with_registered_seed_verifies_through_sdk() {
        let (actor_did, actor_id) = actor_ids("did:webvh:z6mkfixture:alice.example");
        let actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            actor_id.clone(),
            DidCoreId::new("ak:did_core:web:principal.example").unwrap(),
        ));
        let verification_method = format!("{actor_did}#principal-signing-key");
        let seed = [42u8; 32];
        let signing_key = SigningKey::from_bytes(&seed);
        let event = json!({
            "event_id": "ak:event:AU_Y0iurnoT0IOtu1_ZyZP3V36hCxZmUCbEVS2jcWjxe",
            "kind": "ak.member.state",
            "realm_id": "ak:realm:AV0aa7N4-6SpEMTq2vRgjNbMjn0vCIqfM5PxnJ-qQpPP",
            "scope_ref": {"kind": "realm", "realm_id": "ak:realm:AV0aa7N4-6SpEMTq2vRgjNbMjn0vCIqfM5PxnJ-qQpPP"},
            "actor_id": actor,
            "actor_seq": 1,
            "created_at": "2026-07-07T05:45:49.000Z",
            "hlc": "019f3b1c76c8-0000-ac7eadec",
            "prev_refs": [],
            "refs": [],
            "requirements": {
                "schema": ["ak.schema.event_payload.v1"],
                "features": [],
                "critical_extensions": []
            },
            "payload": {
                "realm_id": "ak:realm:AV0aa7N4-6SpEMTq2vRgjNbMjn0vCIqfM5PxnJ-qQpPP",
                "scope_ref": {"kind": "realm", "realm_id": "ak:realm:AV0aa7N4-6SpEMTq2vRgjNbMjn0vCIqfM5PxnJ-qQpPP"},
                "actor_id": actor,
                "membership": "join"
            }
        });
        let proof_value = event_proof(
            json!({
                "actor_did": actor_did,
                "verification_method": verification_method,
                "created_at": "2026-07-07T05:45:49.000Z",
                "event": event,
                "signing_seed_b64url": base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .encode(seed)
            }),
            EventDigestMode::RawCanonicalJson,
        )
        .unwrap();
        let proof: ProducerEventProof = serde_json::from_value(proof_value).unwrap();

        let mut event_with_proofs = event;
        event_with_proofs["proofs"] = json!([]);
        let sdk_event: Event = serde_json::from_value(event_with_proofs).unwrap();
        let canonical_bytes =
            canonical::canonical_json_bytes(&sdk_event.digest_payload().unwrap()).unwrap();
        let public_key = arkret_signatures::proof::PublicKeyMaterial::Ed25519Raw {
            bytes: signing_key.verifying_key().to_bytes().to_vec(),
        };

        assert_eq!(proof.verification_method, verification_method);
        arkret_signatures::proof::verify_ed25519_detached_jws_proof(
            &proof,
            &canonical_bytes,
            &actor,
            &public_key,
        )
        .unwrap();
    }
}
