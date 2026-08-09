use std::io::{self, Read};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use arkret_canonical as canonical;
use arkret_identifiers::{ConsentId, DeviceId, Did, Hash};
use arkret_models_collaboration::direct_conversation_ops::{
    AcceptedAtServiceBinding, DidBindingEvidenceKind, DidBindingEvidenceReceipt,
    DidBindingMethodProof, DidBindingMethodProofKind, MultikeyMethodType,
    PrincipalServiceBindingProofPurpose, PrincipalServiceKind, ServiceVerificationMethod,
};
use arkret_models_collaboration::http_bodies::{MimiConsentDecision, MimiUpdateConsentRequestBody};
use arkret_models_identity::did_document::principal_control_realm_id;
use arkret_wire::{
    Audience, Base64UrlString, DidUrl, Event, EventInitialSubmission, NonEmptyString, PayloadProof,
    Proof, ProtocolSignature, proof_kind,
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
struct PrincipalControlRealmInput {
    principal_id: String,
}

#[derive(Debug, Deserialize)]
struct PrincipalRegistrationFixtureInput {
    principal_server_url: String,
    gate_account_base: String,
    handoff_request_id: String,
    identity_creation_lease: Value,
    device_id: String,
    trust_domain: String,
    initial_session: Value,
}

#[derive(Debug, Deserialize)]
struct PrincipalServiceBindingFixtureInput {
    principal_id: String,
    device_id: String,
    principal_signing_seed_b64url: String,
    service_id: String,
    service_signing_seed_b64url: String,
    trust_domain: String,
    endpoint_origin: String,
    did_document: Value,
    history_head: String,
    version_id: String,
    not_before: String,
    accepted_at: String,
}

#[derive(Debug, Deserialize)]
struct AccountHandoffRequestFixtureInput {
    request_id: String,
    audience: String,
    issuer: String,
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
    initial_session: Value,
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
    predecessor_frontier: Value,
    device_signing_seed_b64url: String,
}

fn main() -> Result<()> {
    let command = std::env::args().nth(1).context("missing command")?;
    let input = read_stdin_json()?;

    let output = match command.as_str() {
        "canonical-json" => canonical_json(input)?,
        "sha256-canonical-json" => sha256_canonical_json(input)?,
        "capability-action-registry-digest" => capability_action_registry_digest()?,
        "event-proof" => event_proof(input, EventDigestMode::RawCanonicalJson)?,
        "event-envelope-proof" => event_proof(input, EventDigestMode::RawCanonicalJson)?,
        "event-derived-id" => event_derived_id(input)?,
        "mimi-consent-proof" => mimi_consent_proof(input)?,
        "principal-control-realm-id" => principal_control_realm(input)?,
        "account-handoff-request" => account_handoff_request(input)?,
        "principal-registration-fixture" => principal_registration_fixture(input)?,
        "principal-service-binding" => principal_service_binding(input)?,
        "identity-creation-register-request" => identity_creation_register_request(input)?,
        "principal-bootstrap-seal" => principal_bootstrap_seal(input)?,
        "principal-successor-seal" => principal_successor_seal(input)?,
        _ => bail!("unknown cotest-wire command {command:?}"),
    };

    println!("{}", serde_json::to_string(&output)?);
    Ok(())
}

fn capability_action_registry_digest() -> Result<Value> {
    let digest = arkret::current_capability_action_registry_digest()
        .context("load SDK capability-action registry digest")?;
    Ok(json!({ "digest": digest.as_str() }))
}

fn non_empty(value: impl Into<String>) -> Result<NonEmptyString> {
    NonEmptyString::new(value.into()).map_err(anyhow::Error::msg)
}

fn principal_registration_fixture(input: Value) -> Result<Value> {
    let input: PrincipalRegistrationFixtureInput =
        serde_json::from_value(input).context("parse principal-registration fixture input")?;
    let endpoint =
        url::Url::parse(&input.principal_server_url).context("parse principal server URL")?;
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
            principal_endpoint: &endpoint,
            local_id: &input
                .handoff_request_id
                .trim_start_matches("ak:request:")
                .to_ascii_lowercase(),
            also_known_as: &[],
            version_time: created_at,
            root_seed: &key_material.root_seed,
            next_root_public_key_multibase: &key_material.next_root_public_key_multikey,
        })
        .context("prepare principal inception")?;
    let principal = Did::new(draft.did.clone()).context("parse prepared principal DID")?;
    let control_realm = principal_control_realm_id(&principal);
    let mut hlc = arkret::hlc::HlcGenerator::new(
        &control_realm,
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
            &control_realm,
            &input.trust_domain,
            &draft.version_id,
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
        &serde_json::from_value(input.initial_session.clone())?,
    )
    .context("build identity-binding challenge request")?;
    let checkpoint = json!({
        "principal_server_url": input.principal_server_url,
        "gate_account_base": input.gate_account_base,
        "handoff_request_id": input.handoff_request_id,
        "lease_id": lease.lease_id,
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
        "initial_session": input.initial_session,
        "device_signing_seed_b64url": device_signing_seed,
        "genesis_created_at": arkret_canonical::format_timestamp_canonical(created_at),
        "genesis_hlc": bootstrap_hlc,
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

fn principal_service_binding(input: Value) -> Result<Value> {
    let input: PrincipalServiceBindingFixtureInput =
        serde_json::from_value(input).context("parse principal-service binding fixture input")?;
    let principal_id = Did::new(input.principal_id).context("parse binding principal DID")?;
    let service_id = Did::new(input.service_id).context("parse binding service DID")?;
    let device_id = DeviceId::new(input.device_id).context("parse binding device id")?;
    let document: arkret_models_identity::did_document::DidDocument =
        serde_json::from_value(input.did_document).context("parse binding DID document")?;
    if document.id != principal_id {
        bail!("binding DID document does not belong to principal");
    }
    document
        .validate()
        .context("validate binding DID document")?;
    if document.method() != "webvh" || input.history_head.is_empty() || input.version_id.is_empty()
    {
        bail!("principal-service binding requires pinned did:webvh history evidence");
    }
    let document_digest =
        Hash::new(canonical::canonical_sha256(&document).context("digest binding DID document")?)
            .context("parse binding DID document digest")?;
    let endpoint =
        url::Url::parse(&input.endpoint_origin).context("parse service endpoint origin")?;
    if endpoint.scheme() != "https"
        || endpoint.host_str().is_none()
        || endpoint.path() != "/"
        || endpoint.query().is_some()
        || endpoint.fragment().is_some()
        || !endpoint.username().is_empty()
        || endpoint.password().is_some()
    {
        bail!("service endpoint origin must be a canonical HTTPS origin");
    }
    let not_before = canonical::parse_timestamp_canonical(&input.not_before)
        .context("parse binding not_before")?;
    let accepted_at = canonical::parse_timestamp_canonical(&input.accepted_at)
        .context("parse binding accepted_at")?;
    let service_verification_method = DidUrl::new(format!("{service_id}#notary-key"))
        .map_err(|error| anyhow::anyhow!("build service notary method: {error}"))?;
    let principal_verification_method = DidUrl::new(format!("{principal_id}#{device_id}"))
        .map_err(|error| anyhow::anyhow!("build principal device method: {error}"))?;
    let service_key = signing_key_from_seed(&input.service_signing_seed_b64url)
        .context("parse service signing seed")?;
    let principal_key = signing_key_from_seed(&input.principal_signing_seed_b64url)
        .context("parse principal device signing seed")?;
    let witness_proofs_digest = Hash::new(
        canonical::canonical_sha256(&Vec::<Value>::new())
            .context("digest empty webvh witness proof set")?,
    )
    .context("parse webvh witness proof digest")?;
    let placeholder = Base64UrlString::new("AA".to_owned())
        .map_err(|error| anyhow::anyhow!("build proof placeholder: {error}"))?;
    let mut binding = AcceptedAtServiceBinding {
        principal_id,
        service_id: service_id.clone(),
        trust_domain: input.trust_domain,
        service_kind: PrincipalServiceKind::PrincipalServer,
        service_verification_method: ServiceVerificationMethod {
            id: service_verification_method.clone(),
            controller: service_id,
            method_type: MultikeyMethodType::Multikey,
            public_key_multibase: arkret_canonical::ed25519_pubkey_to_did_key_multibase(
                service_key.verifying_key().as_bytes(),
            ),
        },
        endpoint_origins: vec![input.endpoint_origin],
        document_digest: document_digest.clone(),
        authority_evidence: DidBindingEvidenceReceipt {
            kind: DidBindingEvidenceKind::AkDidBindingEvidenceV1,
            method: document.method().to_owned(),
            document_digest,
            method_proofs: vec![DidBindingMethodProof {
                kind: DidBindingMethodProofKind::WebvhLog,
                history_head: input.history_head.clone(),
                witnesses: Vec::new(),
                witness_proofs_digest,
            }],
        },
        history_head: Some(input.history_head),
        version_id: Some(input.version_id),
        not_before,
        expires_at: None,
        accepted_at,
        binding_digest: Hash::new(format!("sha256:{}", "0".repeat(64)))
            .context("build binding digest placeholder")?,
        service_acceptance_proof: ProtocolSignature {
            verification_method: service_verification_method.clone(),
            created_at: accepted_at,
            jws: placeholder.clone(),
        },
        principal_authorization_proof: ProtocolSignature {
            verification_method: principal_verification_method.clone(),
            created_at: accepted_at,
            jws: placeholder,
        },
    };
    binding.binding_digest = binding
        .computed_binding_digest()
        .context("compute principal-service binding digest")?;
    let service_input = binding
        .proof_signing_input_bytes(
            PrincipalServiceBindingProofPurpose::ServiceAcceptance,
            &service_verification_method,
        )
        .context("build service acceptance proof input")?;
    binding.service_acceptance_proof.jws = Base64UrlString::new(
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(service_key.sign(&service_input).to_bytes()),
    )
    .map_err(|error| anyhow::anyhow!("encode service acceptance proof: {error}"))?;
    let principal_input = binding
        .proof_signing_input_bytes(
            PrincipalServiceBindingProofPurpose::PrincipalAuthorization,
            &principal_verification_method,
        )
        .context("build principal authorization proof input")?;
    binding.principal_authorization_proof.jws = Base64UrlString::new(
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(principal_key.sign(&principal_input).to_bytes()),
    )
    .map_err(|error| anyhow::anyhow!("encode principal authorization proof: {error}"))?;
    binding
        .validate_shape()
        .context("validate principal-service binding")?;
    serde_json::to_value(binding).context("serialize principal-service binding")
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
    control_realm: &str,
    trust_domain: &str,
    version_id: &str,
    root_public_key_multibase: &str,
    root_verification_method: &str,
    root_seed: &[u8; 32],
    device_id: &str,
    device_seed_basis: &[u8],
    created_at: chrono::DateTime<Utc>,
    hlc: &str,
) -> Result<(Event, Event, String)> {
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
    let device_multibase = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
        &device_key.verifying_key().to_bytes(),
    );
    let device_public_key = non_empty(format!("did:key:{device_multibase}"))?;
    let hpke_key = non_empty("z6LSCotestPcrGenesisHpkeKey")?;
    let algorithms = vec![non_empty("ak.hpke_x25519_aead_chacha20poly1305.v1")?];
    let mut authorize_payload =
        arkret_models_collaboration::events_payloads::DeviceAuthorizePayload {
            principal_id: principal.clone(),
            device_id: principal_device_id.clone(),
            device_public_key: device_public_key.clone(),
            hpke_key: hpke_key.clone(),
            algorithms: algorithms.clone(),
            device_key_algorithm: Some(non_empty("Ed25519")?),
            authorized_by:
                arkret_models_collaboration::events_payloads::DeviceOrPrincipalRef::Did(
                    principal.clone(),
                ),
            scopes: None,
            not_before: created_at,
            expires_at: None,
            authorization_binding_kind: arkret_models_collaboration::events_payloads::DeviceAuthorizationBindingKind::RootAnchored,
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
    let descriptor = arkret_models_collaboration::events_payloads::FoundingDeviceDescriptor {
        descriptor_version: 1,
        device_id: principal_device_id,
        device_key_digest: arkret::Hash::new(arkret_canonical::canonical::sha256_digest(
            device_public_key.as_bytes(),
        ))?,
        device_public_key,
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
            principal_id: principal.clone(),
            realm_id: arkret::RealmId::new(control_realm.to_owned())
                .context("parse Principal Control Realm id")?,
            trust_domain: arkret::TypedTrustDomainId::new(trust_domain.to_owned())
                .context("parse trust domain")?,
            did_inception_ref: arkret::EventRef::new(
                version_id.to_owned(),
                arkret_bootstrap::DID_INCEPTION_REF_ROLE,
            ),
            founding_device_descriptor: descriptor,
            capability_action_registry_digest: arkret::current_capability_action_registry_digest()
                .context("load SDK capability-action registry digest")?,
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
    let digest_suite = serde_json::from_value::<arkret::RealmCreatePayload>(
        serde_json::to_value(&create.payload).context("serialize PCR genesis payload")?,
    )
    .context("decode Principal Control Realm genesis digest suite")?
    .object
    .digest_algorithm;
    arkret::signatures::sign_event_with_digest_suite(
        &mut create,
        &root_signer,
        &root_verification_method,
        digest_suite,
        arkret::signatures::SignEventOptions::new().with_created_at(created_at),
    )
    .context("sign the PCR genesis Event with the identity root")?;
    let mut authorize = Event::new_at(
        arkret_wire::EventKind::DEVICE_AUTHORIZE,
        arkret::ScopeRef::Realm {
            realm_id: arkret::RealmId::new(control_realm.to_owned())?,
        },
        principal.clone(),
        1,
        arkret::Hlc::new(hlc.to_owned())?,
        authorize_payload_value,
        created_at,
    )?;
    authorize.prev_refs = vec![create.event_id.clone()];
    authorize.refresh_content_bound_identity()?;
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
        create,
        authorize,
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(device_seed),
    ))
}

fn account_handoff_request(input: Value) -> Result<Value> {
    let input: AccountHandoffRequestFixtureInput =
        serde_json::from_value(input).context("parse account-handoff request input")?;
    let signing_key = signing_key_from_seed(&input.dpop_seed_b64url)?;
    let request = garth::oidc_account_handoff_request(
        garth::OidcAccountHandoffInput {
            request_id: arkret::RequestId::new(input.request_id)
                .context("parse account-handoff request id")?,
            audience: Did::new(input.audience).context("parse handoff audience")?,
            issuer: input.issuer,
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
    let request = garth::identity_creation_register_request(
        &challenge,
        did_operation,
        serde_json::from_value(input.pcr_genesis_unit).context("parse PCR genesis unit")?,
        serde_json::from_value(input.initial_session).context("parse initial session request")?,
        &key_material.root_seed,
        input.display_name,
    )
    .context("build identity-creation register request")?;
    serde_json::to_value(request).context("serialize identity-creation register request")
}

fn principal_bootstrap_seal(input: Value) -> Result<Value> {
    let input: PrincipalBootstrapSealInput =
        serde_json::from_value(input).context("parse principal bootstrap Seal input")?;
    let unit: arkret_wire::PcrGenesisUnit = serde_json::from_value(input.pcr_genesis_unit)
        .context("parse PCR genesis unit for bootstrap Seal")?;
    let create = unit.create();
    let authorize = unit.founding_authorize();
    let create_payload: arkret_models_collaboration::events_payloads::RealmCreatePayload =
        create.payload_as().context("parse PCR create payload")?;
    let descriptor = create_payload
        .object
        .founding_device_descriptor
        .context("PCR create omits founding device descriptor")?;
    let seed = signing_key_from_seed(&input.device_signing_seed_b64url)?.to_bytes();
    let verification_method =
        arkret_wire::DidUrl::new(format!("{}#{}", create.actor_id, descriptor.device_id)).map_err(
            |error| anyhow::anyhow!("build founding device verification method: {error}"),
        )?;
    let signer = arkret::Ed25519PayloadSigner::from_did_key_seed(
        seed,
        create.actor_id.clone(),
        verification_method,
    );
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
    let create_payload: arkret_models_collaboration::events_payloads::RealmCreatePayload =
        create.payload_as().context("parse PCR create payload")?;
    let descriptor = create_payload
        .object
        .founding_device_descriptor
        .context("PCR create omits founding device descriptor")?;
    let predecessor: arkret_models_collaboration::event_sync::RealmSealFrontierView =
        serde_json::from_value(input.predecessor_frontier)
            .context("parse principal predecessor Seal frontier")?;
    let seed = signing_key_from_seed(&input.device_signing_seed_b64url)?.to_bytes();
    let verification_method =
        arkret_wire::DidUrl::new(format!("{}#{}", create.actor_id, descriptor.device_id)).map_err(
            |error| anyhow::anyhow!("build founding device verification method: {error}"),
        )?;
    let signer = arkret::Ed25519PayloadSigner::from_did_key_seed(
        seed,
        create.actor_id.clone(),
        verification_method,
    );
    let mut hlc = arkret_hlc::HlcGenerator::new(
        create.realm_id.as_str(),
        descriptor.device_id.as_str(),
        &seed,
    );
    let seal = arkret_bootstrap::build_self_principal_linear_successor_seal(
        &events,
        &predecessor,
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
    let principal = Did::new(input.principal_id).context("parse principal DID")?;
    Ok(json!({
        "realm_id": principal_control_realm_id(&principal),
    }))
}

#[derive(Clone, Copy)]
enum EventDigestMode {
    RawCanonicalJson,
}

fn event_proof(input: Value, digest_mode: EventDigestMode) -> Result<Value> {
    let input: EventProofInput =
        serde_json::from_value(input).context("parse event proof input")?;
    let actor = Did::new(input.actor_did.clone()).context("parse actor DID")?;
    let created_at = canonical::parse_timestamp_canonical(&input.created_at)
        .with_context(|| format!("parse proof created_at {:?}", input.created_at))?;
    let event_digest =
        Hash::new(event_digest(&input.event, digest_mode)?).context("parse event digest")?;
    let signing_key = match input.signing_seed_b64url.as_deref() {
        Some(seed) => signing_key_from_seed(seed).context("parse event signing seed")?,
        None => development_event_signing_key(&input.verification_method),
    };

    let mut proof = Proof {
        kind: proof_kind::DETACHED_JWS.to_owned(),
        verification_method: input.verification_method,
        event_digest,
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
    let actor_id = input
        .request
        .get("actor_id")
        .and_then(Value::as_str)
        .context("MIMI consent request requires actor_id")?;
    let consent_event = input
        .request
        .get("consent_event")
        .cloned()
        .context("MIMI consent request requires consent_event")?;
    let reason = input
        .request
        .get("reason")
        .and_then(Value::as_str)
        .map(NonEmptyString::new)
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
        actor_id: Did::new(actor_id.to_owned()).context("parse consent actor DID")?,
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
    let mut event = Event::from_digest_payload_bytes(&digest_payload_bytes)
        .context("derive SDK Event identity from digest payload")?;
    // A Realm genesis names no Realm, so its `realm_id` is a function of the
    // Event that creates it and can only be computed once the Event has its
    // own id. Callers get both back because neither is theirs to choose.
    if event.scope_ref.realm_id_opt().is_none() {
        event.realm_id = arkret_wire::derive_genesis_realm_id(
            &event.event_id,
            &event.actor_id,
            event.payload.get("object"),
        );
    }
    let object_id = arkret_schema::derived_object_id_for_kind(event.kind.as_str(), &event.event_id);
    Ok(serde_json::json!({
        "event_id": event.event_id.to_string(),
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

    #[test]
    fn event_digest_uses_producer_envelope_canonical_bytes() {
        let event = json!({
            "event_id": "ak:event:AU_Y0iurnoT0IOtu1_ZyZP3V36hCxZmUCbEVS2jcWjxe",
            "kind": "ak.member.state",
            "realm_id": "ak:realm:AV0aa7N4-6SpEMTq2vRgjNbMjn0vCIqfM5PxnJ-qQpPP",
            "scope_ref": {"kind": "realm", "realm_id": "ak:realm:AV0aa7N4-6SpEMTq2vRgjNbMjn0vCIqfM5PxnJ-qQpPP"},
            "actor_id": "did:webvh:zQmV5MGgUvFGbi15ajBaMzdXR5KQzL3TVDxM7VFQCv5nCwH5C:01kwxhre7cexz894j3nmsvmqh5",
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
                "actor_id": "did:webvh:zQmV5MGgUvFGbi15ajBaMzdXR5KQzL3TVDxM7VFQCv5nCwH5C:01kwxhre7cexz894j3nmsvmqh5",
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
        let event = json!({
            "event_id": "ak:event:AU_Y0iurnoT0IOtu1_ZyZP3V36hCxZmUCbEVS2jcWjxe",
            "kind": "ak.morph.schema_migrate",
            "realm_id": "ak:realm:AV0aa7N4-6SpEMTq2vRgjNbMjn0vCIqfM5PxnJ-qQpPP",
            "scope_ref": {"kind": "realm", "realm_id": "ak:realm:AV0aa7N4-6SpEMTq2vRgjNbMjn0vCIqfM5PxnJ-qQpPP"},
            "actor_id": "did:webvh:zQmV5MGgUvFGbi15ajBaMzdXR5KQzL3TVDxM7VFQCv5nCwH5C:01kwxhre7cexz894j3nmsvmqh5",
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
                "morph_id": "ak:morph:Aa8s5OtJTr4DL7dYQbiLrzNhuis8EyjprcGjTo_qPZDF",
                "from_schema_refs": ["ak.schema.morph.customer_risk.v1"],
                "to_schema_refs": ["ak.schema.morph.customer_risk.ext.v1"],
                "compatibility_class": "transformation"
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
    fn capability_registry_digest_is_sdk_authoritative() {
        let output = capability_action_registry_digest().unwrap();
        let expected = arkret::current_capability_action_registry_digest().unwrap();

        assert_eq!(output["digest"], expected.as_str());
    }

    #[test]
    fn event_proof_with_registered_seed_verifies_through_sdk() {
        let actor = Did::new("did:webvh:z6mkfixture:alice.example".to_owned()).unwrap();
        let verification_method = format!("{actor}#principal-signing-key");
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
                "actor_did": actor,
                "verification_method": verification_method,
                "created_at": "2026-07-07T05:45:49.000Z",
                "event": event,
                "signing_seed_b64url": base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .encode(seed)
            }),
            EventDigestMode::RawCanonicalJson,
        )
        .unwrap();
        let proof: Proof = serde_json::from_value(proof_value).unwrap();

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
