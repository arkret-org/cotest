use std::collections::{BTreeMap, HashMap};
use std::sync::{LazyLock, Mutex};

use anyhow::{Context, Result};
use arkret_bootstrap::{
    DID_INCEPTION_REF_ROLE, SelfPrincipalPcrCreateInput, build_self_principal_bootstrap_seal,
    build_self_principal_linear_successor_seal, build_self_principal_pcr_create,
    build_self_principal_pcr_genesis_unit,
};
use arkret_canonical::multibase::ed25519_pubkey_to_did_key_multibase;
use arkret_canonical::{canonical_json_bytes, canonical_sha256};
use arkret_event_draft::EventPayloadExt as _;
use arkret_identifiers::{
    DeviceId, DidCoreId, DidFullId, Hlc, RealmId, project_full_id_to_core_id,
};
use arkret_models_collaboration::events_payloads::{
    DeviceAuthorizationBindingKind, DeviceAuthorizePayload, DeviceOrPrincipalRef,
    FoundingDeviceDescriptor, FoundingDeviceHpkeKeyAlgorithm, FoundingDeviceKeyAlgorithm,
    FoundingDeviceKeyPurpose, SignatureMaterial, device_authorize_payload_digest,
};
use arkret_models_collaboration::governance::agent_artifacts::PublicKey;
use arkret_models_collaboration::http_bodies::{
    AccountDevicePairOutcome, AccountDevicePairRequestBody, DevicePairingNonce,
    DevicePairingStageOutcome, DevicePairingStageRequestBody,
    UnsignedDevicePairingTargetAttestation,
};
use arkret_models_crypto::{
    AlgorithmKeyRecords, KeyOperationSignature, KeysUploadRequestBody, KeysUploadUnsignedRequest,
    keys_upload_signing_input,
};
use arkret_models_identity::{
    IdentityBindingPurpose, PCR_GENESIS_UNIT_KINDS, UnsignedIdentityCreationControlProof,
    UnsignedIdentityCreationControlProofBody,
};
use arkret_signatures::device_pairing::{
    ServerDevicePairingChallenge, sign_device_pairing_target_attestation,
    sign_server_device_pairing_challenge,
};
use arkret_signatures::http_signature::{
    Component, SignedRequestParts, canonical_message, format_signature_input_component_list,
    parse_signature_input, sign_message,
};
use arkret_signatures::webvh::{
    PreparedPrincipalInception, PrincipalInceptionInput, prepare_principal_inception,
    sign_identity_creation_control_proof, sign_registration_did_evidence_draft,
    validate_principal_inception_operation,
};
use arkret_wire::{Base64UrlString, EventRef, Hash, IdempotencyKey, NonEmptyString};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use reqwest::StatusCode;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use url::Url;

use crate::harness::{
    ArkretServer, ProvisionedTestPrincipal, TestActorClient, canonical_device_id, dev_login,
    expect_json, register_account, register_account_with_localpart,
    register_event_signing_identity,
};

pub(crate) const HARNESS_ACCOUNT_AUTHORITY_KEY_SEED: [u8; 32] = [0xac; 32];
pub(crate) const HARNESS_ACCOUNT_AUTHORITY_ORIGIN: &str = "https://account-authority.cotest.local";

pub(crate) fn harness_account_authority_full_id() -> DidFullId {
    let key = SigningKey::from_bytes(&HARNESS_ACCOUNT_AUTHORITY_KEY_SEED);
    DidFullId::new(format!(
        "did:key:{}",
        ed25519_pubkey_to_did_key_multibase(&key.verifying_key().to_bytes())
    ))
    .expect("deterministic account authority DID")
}

pub(crate) fn harness_account_authority_id() -> DidCoreId {
    project_full_id_to_core_id(&harness_account_authority_full_id())
        .expect("deterministic account authority core id")
}

pub async fn spawn_with_harness_account_authority(
    name: &str,
    extra_env: &[(&str, &str)],
) -> Result<ArkretServer> {
    let account_authority_id = harness_account_authority_id().to_string();
    let mut env = Vec::with_capacity(extra_env.len() + 2);
    env.push((
        "SOLAND_ACCOUNT_AUTHORITY_URL",
        HARNESS_ACCOUNT_AUTHORITY_ORIGIN,
    ));
    env.push((
        "SOLAND_ACCOUNT_AUTHORITY_SERVICE_ID",
        account_authority_id.as_str(),
    ));
    env.extend_from_slice(extra_env);
    ArkretServer::spawn_with_env(name, &env).await
}

fn registry_digest() -> arkret_identifiers::Hash {
    arkret::current_capability_action_registry_digest()
        .expect("embedded capability-action registry")
}

fn test_device_record_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[0x52; 32])
}

async fn install_test_principal_control_document(
    server: &ArkretServer,
    actor: &str,
) -> Result<PreparedPrincipalInception> {
    let prepared = prepared_test_principal_inception(actor)?;
    anyhow::ensure!(
        prepared.did == actor,
        "deterministic native inception does not reproduce test principal DID"
    );
    let accepted = expect_json(
        server
            .http()
            .post(server.url("/_arkret/root/identity/submit-did-operation"))
            .json(&prepared.submit_body),
        StatusCode::OK,
    )
    .await?;
    anyhow::ensure!(
        matches!(accepted["status"].as_str(), Some("accepted" | "duplicate")),
        "principal inception was not accepted idempotently: {accepted}"
    );
    let resolved = expect_json(
        server
            .http()
            .post(server.url("/_arkret/root/identity/resolve"))
            .json(&serde_json::from_value::<
                arkret_models_identity::identity::IdentityResolveRequestBody,
            >(json!({"did": actor}))?),
        StatusCode::OK,
    )
    .await?;
    anyhow::ensure!(
        resolved["did_document"]["id"].as_str() == Some(actor)
            && resolved["key_log_head"].as_str().is_some(),
        "installed identity anchor is absent from resolved DID document: {resolved}"
    );
    crate::harness::register_event_signing_identity(
        actor,
        test_principal_root_key_seed(actor)?,
        prepared.root_verification_method.clone(),
        server.service_id().clone(),
    );
    Ok(prepared)
}

fn prepared_test_principal_inception(actor: &str) -> Result<PreparedPrincipalInception> {
    let (host, local_id) = test_principal_coordinates(actor)?;
    test_principal_inception(&host, &local_id)
}

fn test_principal_coordinates(actor: &str) -> Result<(String, String)> {
    let (_, remainder) = actor
        .strip_prefix("did:webvh:")
        .and_then(|remainder| remainder.split_once(':'))
        .context("test principal is not a did:webvh DID")?;
    let (method_authority, local_id) = remainder
        .split_once(":webvh:")
        .context("test principal DID has no local id")?;
    let host = method_authority.replace("%3A", ":").replace("%3a", ":");
    Ok((host, local_id.to_owned()))
}

pub(crate) fn test_principal_root_signing_authority(
    actor: &str,
) -> Result<(arkret_wire::DidUrl, [u8; 32])> {
    let prepared = prepared_test_principal_inception(actor)?;
    let verification_method = arkret_wire::DidUrl::new(prepared.root_verification_method)
        .map_err(|error| anyhow::anyhow!("test principal root verification method: {error}"))?;
    Ok((verification_method, test_principal_root_key_seed(actor)?))
}

fn test_principal_root_key_seed(actor: &str) -> Result<[u8; 32]> {
    let (host, local_id) = test_principal_coordinates(actor)?;
    Ok(test_principal_root_seed(&host, &local_id))
}

/// Deterministic founding device signing key for a provisioned test principal.
///
/// The seed matches the development event-signing key of the device's
/// verification method, so Event proofs and the `ak.device.authorize` binding
/// name the same key.
pub fn founding_device_signing_key(actor: &str, device_id: &str) -> SigningKey {
    let method = crate::fixture_did_url(format!("{actor}#{device_id}"));
    SigningKey::from_bytes(&arkret::signatures::development_signing_key_seed(&method))
}

/// How the canonical actor bootstrap opens its first session.
pub enum ActorBootstrapRegistration<'a> {
    /// Bare dev-login session (no account row).
    DevLogin,
    /// Account registration through the embedded WebVH registration gate.
    Account { handle: &'a str },
    /// Account registration plus a primary localpart publication.
    AccountWithLocalpart { handle: &'a str, localpart: &'a str },
}

struct PrincipalBootstrapRecord {
    founding: ProvisionedTestPrincipal,
    /// Additional devices authorized after genesis: device id -> (device
    /// signing key, accepted `ak.device.authorize` Event id).
    additional_devices: BTreeMap<String, (SigningKey, arkret_identifiers::EventId)>,
}

/// Process-local record of principals whose §5.1 genesis unit was already
/// relayed to a given service identity. Keyed by the durable service id (stable
/// across external restarts and chaos respawns on retained storage) so a
/// restarted service replays without a second genesis — the control proof's
/// `issued_at` makes a byte-fresh relay fail `validate_against`, so replay must
/// be skipped wholesale — while a distinct service id always bootstraps its own
/// principals.
static PROVISIONED_PRINCIPALS: LazyLock<
    Mutex<HashMap<(String, String), PrincipalBootstrapRecord>>,
> = LazyLock::new(|| Mutex::new(HashMap::new()));

/// Atomically provision a self-sovereign test principal: deterministic
/// `did:webvh` inception, requested registration/session, and the closed
/// §5.1 PCR genesis unit (`ak.realm.create` purpose=principal_control +
/// `registration_anchor` `ak.device.authorize`) with its bootstrap Seal.
///
/// Scenarios MUST NOT hand-assemble principal DIDs, PCR ids, or authorization
/// Event ids; they consume the returned typed handles. Negative fixtures that
/// need an unauthorized device use the explicitly named opt-out entry points
/// on [`ArkretServer`] instead.
pub async fn bootstrap_registered_actor(
    server: &ArkretServer,
    actor: &str,
    device_id: &str,
    registration: ActorBootstrapRegistration<'_>,
) -> Result<(ProvisionedTestPrincipal, String)> {
    let device_id = canonical_device_id(device_id);
    let device_key = founding_device_signing_key(actor, &device_id);
    let device_method = crate::fixture_did_url(format!("{actor}#{device_id}"));
    let token = match registration {
        ActorBootstrapRegistration::DevLogin => dev_login(server, actor, &device_id).await?,
        ActorBootstrapRegistration::Account { handle } => {
            register_account(server, actor, handle, &device_id).await?
        }
        ActorBootstrapRegistration::AccountWithLocalpart { handle, localpart } => {
            register_account_with_localpart(server, actor, handle, localpart, &device_id).await?
        }
    };
    let key = (server.service_id().as_str().to_owned(), actor.to_owned());
    let cached = PROVISIONED_PRINCIPALS
        .lock()
        .expect("provisioned principal lock")
        .get(&key)
        .map(|record| {
            (
                record.founding.clone(),
                record.additional_devices.get(&device_id).cloned(),
            )
        });
    if let Some((founding, additional)) = cached {
        if device_id == founding.device_id.as_str() {
            register_event_signing_identity(
                actor,
                founding.device_signing_key.to_bytes(),
                device_method.as_str().to_owned(),
                server.service_id().clone(),
            );
            return Ok((founding, token));
        }
        if let Some((additional_key, authorize_event_id)) = additional {
            register_event_signing_identity(
                actor,
                additional_key.to_bytes(),
                device_method.as_str().to_owned(),
                server.service_id().clone(),
            );
            return Ok((
                ProvisionedTestPrincipal {
                    device_id: DeviceId::new(device_id.clone())?,
                    device_signing_key: additional_key,
                    founding_authorize_event_id: authorize_event_id,
                    ..founding
                },
                token,
            ));
        }
        // A second device of an already-provisioned principal is authorized by
        // the founding device through an accepted-device `ak.device.authorize`
        // in the PCR (device-lifecycle.md section 5.2).
        register_event_signing_identity(
            actor,
            founding.device_signing_key.to_bytes(),
            crate::fixture_did_url(format!("{actor}#{}", founding.device_id))
                .as_str()
                .to_owned(),
            server.service_id().clone(),
        );
        let authorize_event_id =
            authorize_additional_principal_device(server, &founding, &device_id, &device_key)
                .await?;
        register_event_signing_identity(
            actor,
            device_key.to_bytes(),
            device_method.as_str().to_owned(),
            server.service_id().clone(),
        );
        PROVISIONED_PRINCIPALS
            .lock()
            .expect("provisioned principal lock")
            .get_mut(&key)
            .expect("provisioned principal record persists")
            .additional_devices
            .insert(
                device_id.clone(),
                (device_key.clone(), authorize_event_id.clone()),
            );
        return Ok((
            ProvisionedTestPrincipal {
                device_id: DeviceId::new(device_id)?,
                device_signing_key: device_key,
                founding_authorize_event_id: authorize_event_id,
                ..founding
            },
            token,
        ));
    }
    let prepared = install_test_principal_control_document(server, actor).await?;
    let bootstrap = bootstrap_test_device_authorization(
        server,
        &token,
        actor,
        &device_id,
        &device_key,
        &prepared,
    )
    .await?;
    register_event_signing_identity(
        actor,
        device_key.to_bytes(),
        device_method.as_str().to_owned(),
        server.service_id().clone(),
    );
    let full_id = DidFullId::new(actor.to_owned())?;
    let principal = ProvisionedTestPrincipal {
        core_id: project_full_id_to_core_id(&full_id)?,
        full_id,
        device_id: DeviceId::new(device_id)?,
        device_signing_key: device_key,
        root_key_seed: test_principal_root_key_seed(actor)?,
        pcr_realm_id: bootstrap.pcr_realm_id,
        founding_authorize_event_id: bootstrap.authorize_event_id,
    };
    PROVISIONED_PRINCIPALS
        .lock()
        .expect("provisioned principal lock")
        .insert(
            key,
            PrincipalBootstrapRecord {
                founding: principal.clone(),
                additional_devices: BTreeMap::new(),
            },
        );
    Ok((principal, token))
}

/// Admit an additional device of an already-provisioned principal into its PCR
/// through the §2.1 server-mediated pairing gate (`ak.gate.account.command.
/// pair_device`): the candidate stages its key at the open short-link surface
/// and signs the pairing challenge, then the founding device authors the
/// accepted-device `ak.device.authorize` Control Move whose `device_signature`
/// is the §5.2.2 target attestation bound to that challenge transcript.
async fn authorize_additional_principal_device(
    server: &ArkretServer,
    founding: &ProvisionedTestPrincipal,
    device_id: &str,
    device_signing_key: &SigningKey,
) -> Result<arkret_identifiers::EventId> {
    let actor = founding.full_id.as_str();
    let created_at = chrono::DateTime::parse_from_rfc3339("2026-05-02T00:00:00.000Z")?
        .with_timezone(&chrono::Utc);
    let new_device_id = DeviceId::new(device_id.to_owned())?;
    let device_multibase =
        ed25519_pubkey_to_did_key_multibase(&device_signing_key.verifying_key().to_bytes());
    let device_public_key =
        NonEmptyString::new(format!("did:key:{device_multibase}")).map_err(anyhow::Error::msg)?;
    let hpke_key = NonEmptyString::new(format!("z6LSCotestFederationHpkeKey:{device_id}"))
        .map_err(anyhow::Error::msg)?;
    let algorithms = vec![
        NonEmptyString::new("ak.hpke_x25519_aead_chacha20poly1305.v1")
            .map_err(anyhow::Error::msg)?,
    ];

    // §2.1 stage: the account-less candidate publishes its key plus a client
    // nonce and receives the short-link handle and server challenge fields.
    let new_device_pubkey = PublicKey {
        kty: NonEmptyString::new("OKP").map_err(anyhow::Error::msg)?,
        kid: NonEmptyString::new(device_id.to_owned()).map_err(anyhow::Error::msg)?,
        algorithm: NonEmptyString::new("Ed25519").map_err(anyhow::Error::msg)?,
        key: Base64UrlString::new(
            URL_SAFE_NO_PAD.encode(device_signing_key.verifying_key().to_bytes()),
        )
        .map_err(anyhow::Error::msg)?,
        key_digest: None,
    };
    let nonce_seed =
        Sha256::digest(format!("cotest:device-pairing-nonce:{actor}:{device_id}").as_bytes());
    let client_nonce = DevicePairingNonce::new(URL_SAFE_NO_PAD.encode(&nonce_seed[..16]))
        .map_err(anyhow::Error::msg)?;
    let stage = serde_json::from_value::<DevicePairingStageOutcome>(
        expect_json(
            server
                .http()
                .post(server.url("/_arkret/open/device-pairing/requests"))
                .json(&DevicePairingStageRequestBody {
                    new_device_pubkey: new_device_pubkey.clone(),
                    client_nonce: client_nonce.clone(),
                    display_name: None,
                    device_metadata: None,
                }),
            StatusCode::OK,
        )
        .await?,
    )?;

    // §2.1.2: the candidate proves possession of its fresh key over the exact
    // server-mediated challenge transcript.
    let challenge = ServerDevicePairingChallenge::from_stage(client_nonce, &stage);
    let challenge_proof =
        sign_server_device_pairing_challenge(&new_device_pubkey, &challenge, device_signing_key)?;

    // §5.2.2: the accepted-device possession attestation binds only the
    // target's own key material and the challenge transcript digest; the
    // authorizing device's Event proof carries the remaining payload fields.
    let attestation = sign_device_pairing_target_attestation(
        UnsignedDevicePairingTargetAttestation::new(
            new_device_id.clone(),
            arkret_wire::DidKey::new(device_public_key.as_str().to_owned())
                .map_err(anyhow::Error::msg)?,
            hpke_key.clone(),
            algorithms.clone(),
            challenge_proof.transcript_digest.clone(),
        )?,
        device_signing_key,
    )?;
    let payload = DeviceAuthorizePayload {
        principal_id: founding.core_id.clone(),
        device_id: new_device_id,
        device_public_key,
        hpke_key: hpke_key.clone(),
        algorithms,
        device_key_algorithm: Some(NonEmptyString::new("Ed25519").map_err(anyhow::Error::msg)?),
        authorized_by: DeviceOrPrincipalRef::DeviceId(founding.device_id.clone()),
        scopes: None,
        not_before: created_at,
        expires_at: None,
        authorization_binding_kind: DeviceAuthorizationBindingKind::AcceptedDevice,
        device_signature: attestation.device_signature.clone(),
        recovery_session_id: None,
    };

    // The gate authenticates the authorizing device, so the exact Event is
    // authored over a founding-device session and relayed verbatim.
    let founding_token = dev_login(server, actor, founding.device_id.as_str()).await?;
    let founding_method = crate::fixture_did_url(format!("{actor}#{}", founding.device_id));
    let authorize_event = crate::harness::prepare_event_submission_with_signing_identity(
        server,
        &founding_token,
        actor,
        founding.pcr_realm_id.as_str(),
        arkret_wire::EventKind::DeviceAuthorize.as_str(),
        serde_json::to_value(&payload)?,
        founding.device_signing_key.to_bytes(),
        &founding_method,
    )
    .await?;
    let outcome = serde_json::from_value::<AccountDevicePairOutcome>(
        expect_json(
            server
                .http()
                .post(server.url("/_arkret/gate/account/device-pair"))
                .bearer_auth(&founding_token)
                .json(&AccountDevicePairRequestBody {
                    pairing_code: stage.pairing_code.clone(),
                    new_device_pubkey,
                    hpke_key,
                    device_signature: attestation.device_signature.clone(),
                    challenge_proof,
                    authorize_event: crate::publication::initial_submission(authorize_event, "")?,
                    display_name: None,
                    device_metadata: None,
                    device_pairing_request_id: Some(stage.device_pairing_request_id.clone()),
                    challenge_transcript: None,
                }),
            StatusCode::OK,
        )
        .await?,
    )?;
    Ok(outcome.authorized_event_ref)
}

/// Publish the current device-signed successor Seal for every accepted Event
/// after this principal's already-accepted PCR frontier.
pub async fn seal_current_principal_control_frontier(
    client: &TestActorClient,
    device_signing_key: &SigningKey,
) -> Result<()> {
    let principal = DidFullId::new(client.actor.clone())?;
    let principal_actor_id = DidCoreId::from(project_full_id_to_core_id(&principal)?);
    let mut selected = None;
    for candidate in client.controlled_realm_ids() {
        let events = client
            .sdk()
            .events_read_all_pages(&candidate)
            .await?
            .events
            .into_iter()
            .enumerate()
            .map(|(index, row)| {
                row.into_event().ok_or_else(|| {
                    anyhow::anyhow!(
                        "controlled Realm history requires complete Events; row {index} for {candidate} is redacted or reference-locked"
                    )
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let is_pcr = events.first().is_some_and(|event| {
            event.actor_id == principal_actor_id
                && event
                    .typed_payload::<arkret_wire::event_spec::RealmCreate>()
                    .is_ok_and(|payload| {
                        payload.object.purpose
                            == arkret_models_collaboration::events_payloads::RealmPurpose::PrincipalControl
                    })
        });
        if is_pcr {
            selected = Some((RealmId::new(candidate)?, events));
            break;
        }
    }
    let (realm_id, mut events) =
        selected.context("client has no accepted event-derived Principal Control Realm")?;
    events.sort_by_key(|event| event.actor_seq);
    anyhow::ensure!(
        events.len() >= 3,
        "PCR successor Seal requires at least one accepted post-genesis Event"
    );
    let frontier_state = serde_json::from_value::<
        arkret_models_collaboration::event_sync::EventsFrontierAccountClientState,
    >(client.realm_seal_frontier(realm_id.as_str()).await?)?;
    let arkret_models_collaboration::event_sync::EventsFrontierView::RealmSeal(frontier) =
        frontier_state.frontier
    else {
        anyhow::bail!("PCR Realm selector returned a non-Seal frontier");
    };
    let device_method = crate::fixture_did_url(format!("{}#{}", client.actor, client.device_id));
    let signer = arkret_signatures::Ed25519PayloadSigner::from_did_key_seed(
        device_signing_key.to_bytes(),
        principal,
        device_method,
    );
    let physical_millis = chrono::Utc::now().timestamp_millis();
    let seal = build_self_principal_linear_successor_seal(
        &events,
        &frontier,
        Hlc::new(format!("{physical_millis:012x}-0000-a13f9c2e"))?,
        &signer,
        &crate::publication::project_cells,
    )?;
    let outcome =
        serde_json::from_value::<arkret_models_collaboration::http_bodies::EventSealSubmitOutcome>(
            expect_json(
                client.post("/_arkret/self/events/seals").json(&seal),
                StatusCode::OK,
            )
            .await?,
        )?;
    anyhow::ensure!(
        outcome.seal_id == seal.id
            && outcome.accepted_event_digests == seal.delta
            && outcome.post_state_root == seal.state_root,
        "principal server returned a mismatched PCR successor Seal outcome"
    );
    Ok(())
}

pub(crate) fn signed_keys_upload_body(
    actor: &str,
    device_id: &str,
    signing_key: &SigningKey,
    one_time_keys: Value,
    fallback_keys: Value,
) -> Result<KeysUploadRequestBody> {
    let one_time_keys = signed_algorithm_key_records(actor, one_time_keys, false)?;
    let fallback_keys = signed_algorithm_key_records(actor, fallback_keys, true)?;
    let unsigned = KeysUploadUnsignedRequest {
        device_id: DeviceId::new(device_id.to_owned()).context("invalid keys/upload device id")?,
        one_time_keys,
        fallback_keys,
    };
    let signing_input = keys_upload_signing_input(&unsigned)?;
    let signature = signing_key.sign(&signing_input);
    Ok(unsigned.into_signed(KeyOperationSignature {
        kid: NonEmptyString::new(format!("{actor}#{device_id}")).unwrap(),
        signature_algorithm: Some(NonEmptyString::new("Ed25519").unwrap()),
        sig: Base64UrlString::new(URL_SAFE_NO_PAD.encode(signature.to_bytes())).unwrap(),
    }))
}

fn signed_algorithm_key_records(
    actor: &str,
    records: Value,
    fallback: bool,
) -> Result<AlgorithmKeyRecords> {
    let Value::Object(records) = records else {
        anyhow::bail!("keys/upload key records must be an object");
    };
    let signing_key = test_device_record_signing_key();
    records
        .into_iter()
        .map(|(record_id, record)| {
            let Value::Object(mut record) = record else {
                anyhow::bail!("keys/upload record `{record_id}` must be an object");
            };
            let algorithm = record
                .get("algorithm")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
                .or_else(|| record_id.split_once(':').map(|(value, _)| value.to_owned()))
                .context("keys/upload record has no algorithm")?;
            let key_id = record
                .get("key_id")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
                .or_else(|| record_id.split_once(':').map(|(_, value)| value.to_owned()))
                .unwrap_or_else(|| record_id.clone());
            record
                .get("key")
                .and_then(Value::as_str)
                .context("keys/upload record has no key")?;
            record.insert("algorithm".to_owned(), json!(algorithm));
            record.insert("key_id".to_owned(), json!(key_id));
            if fallback {
                record.insert("fallback".to_owned(), json!(true));
            }
            let signed_fields = Value::Object(record.clone());
            let signature_input = canonical_json_bytes(&signed_fields)?;
            record.insert(
                "signature".to_owned(),
                json!({
                    "kid": format!("{actor}#device-record-key"),
                    "signature_algorithm": "Ed25519",
                    "sig": URL_SAFE_NO_PAD.encode(signing_key.sign(&signature_input).to_bytes()),
                }),
            );
            let record = serde_json::from_value(Value::Object(record))
                .with_context(|| format!("parse typed keys/upload record `{record_id}`"))?;
            let record_id = NonEmptyString::new(record_id).map_err(anyhow::Error::msg)?;
            Ok((record_id, record))
        })
        .collect()
}

struct TestDeviceAuthorizationBootstrap {
    authorize_event_id: arkret_identifiers::EventId,
    pcr_realm_id: RealmId,
}

async fn bootstrap_test_device_authorization(
    server: &ArkretServer,
    token: &str,
    actor: &str,
    device_id: &str,
    device_signing_key: &SigningKey,
    prepared: &PreparedPrincipalInception,
) -> Result<TestDeviceAuthorizationBootstrap> {
    let (_, remainder) = actor
        .strip_prefix("did:webvh:")
        .and_then(|remainder| remainder.split_once(':'))
        .context("test principal is not a did:webvh DID")?;
    let (method_authority, local_id) = remainder
        .split_once(":webvh:")
        .context("test principal DID has no local id")?;
    let host = method_authority.replace("%3A", ":").replace("%3a", ":");
    let principal = DidFullId::new(actor.to_owned()).context("invalid test principal DID")?;
    let principal_core_id = project_full_id_to_core_id(&principal)?;
    let principal_actor_id = DidCoreId::from(principal_core_id.clone());
    let created_at = chrono::DateTime::parse_from_rfc3339("2026-05-02T00:00:00.000Z")?
        .with_timezone(&chrono::Utc);

    let device_id = DeviceId::new(device_id.to_owned())?;
    let device_multibase =
        ed25519_pubkey_to_did_key_multibase(&device_signing_key.verifying_key().to_bytes());
    let device_public_key =
        NonEmptyString::new(format!("did:key:{device_multibase}")).map_err(anyhow::Error::msg)?;
    let hpke_key =
        NonEmptyString::new("z6LSCotestFederationHpkeKey").map_err(anyhow::Error::msg)?;
    let algorithms = vec![
        NonEmptyString::new("ak.hpke_x25519_aead_chacha20poly1305.v1")
            .map_err(anyhow::Error::msg)?,
    ];
    let mut payload = DeviceAuthorizePayload {
        principal_id: principal_actor_id.clone(),
        device_id: device_id.clone(),
        device_public_key: device_public_key.clone(),
        hpke_key: hpke_key.clone(),
        algorithms: algorithms.clone(),
        device_key_algorithm: Some(NonEmptyString::new("Ed25519").map_err(anyhow::Error::msg)?),
        authorized_by: DeviceOrPrincipalRef::Principal(principal_actor_id.clone()),
        scopes: None,
        not_before: created_at,
        expires_at: None,
        authorization_binding_kind: DeviceAuthorizationBindingKind::RegistrationAnchor,
        device_signature: SignatureMaterial::NonEmptyString(
            NonEmptyString::new("pending").map_err(anyhow::Error::msg)?,
        ),
        recovery_session_id: None,
    };
    payload.device_signature = SignatureMaterial::NonEmptyString(
        NonEmptyString::new(
            URL_SAFE_NO_PAD.encode(
                device_signing_key
                    .sign(&payload.device_possession_signature_input()?)
                    .to_bytes(),
            ),
        )
        .map_err(anyhow::Error::msg)?,
    );
    let payload_value = serde_json::to_value(&payload)?;
    let descriptor = FoundingDeviceDescriptor {
        descriptor_version: 1,
        device_id: device_id.clone(),
        device_key_digest: arkret_identifiers::Hash::new(
            arkret_canonical::canonical::sha256_digest(device_public_key.as_bytes()),
        )?,
        device_public_key: device_public_key.clone(),
        device_key_algorithm: FoundingDeviceKeyAlgorithm::Ed25519,
        device_key_purpose: FoundingDeviceKeyPurpose::EventSigningAndMlsIdentity,
        hpke_key_digest: arkret_identifiers::Hash::new(
            arkret_canonical::canonical::sha256_digest(hpke_key.as_bytes()),
        )?,
        hpke_key,
        hpke_key_algorithm: FoundingDeviceHpkeKeyAlgorithm::X25519,
        algorithms,
        founding_authorize_payload_digest: device_authorize_payload_digest(
            &payload_value,
            arkret_canonical::DigestSuite::Sha256,
        )?,
    };
    let mut create = build_self_principal_pcr_create(
        SelfPrincipalPcrCreateInput {
            principal_id: principal_actor_id.clone(),
            principal_server_id: server.service_id().clone(),
            principal_full_id: principal.clone(),
            initial_resolution: arkret_models_identity::ResolutionCommitment {
                full_id: principal.clone(),
                method_history_head: arkret_canonical::canonical_sha256(&prepared.log_entry)?,
                version_id: prepared.version_id.clone(),
            },
            genesis_salt: test_principal_genesis_salt(&host, &local_id, device_id.as_str())?,
            trust_domain: server.trust_domain().clone(),
            did_inception_ref: EventRef::new(prepared.version_id.clone(), DID_INCEPTION_REF_ROLE),
            founding_device_descriptor: descriptor,
            capability_action_registry_digest: registry_digest(),
            created_at,
            hlc: Hlc::new("01970e589d21-0000-a13f9c2e")?,
        },
        &crate::publication::project_cells,
    )?;
    let root_seed: [u8; 32] =
        Sha256::digest(format!("cotest:webvh:root:{host}:{local_id}").as_bytes()).into();
    let root_did = DidFullId::new(format!("did:key:{}", prepared.root_public_key_multibase))?;
    let root_verification_method =
        crate::fixture_did_url(prepared.root_verification_method.clone());
    let root_signer = arkret_signatures::Ed25519PayloadSigner::from_did_key_seed(
        root_seed,
        root_did,
        root_verification_method.clone(),
    );
    // `build_self_principal_pcr_create` already finalized the genesis; the
    // signer verifies that identity instead of re-deriving one.
    let mut create = create;
    arkret::signatures::sign_event(
        &mut create,
        &root_signer,
        &root_verification_method,
        arkret::signatures::SignEventOptions::new().with_created_at(created_at),
    )?;
    let realm_id = create.realm_id.clone();
    let mut authorize = arkret_wire::test_support::raw_event(
        arkret_wire::EventKind::DeviceAuthorize.as_str(),
        arkret_wire::ScopeRef::Realm {
            realm_id: realm_id.clone(),
        },
        principal_actor_id,
        server.service_id().clone(),
        1,
        Hlc::new("01970e589d21-0001-a13f9c2e")?,
        payload_value,
    )?;
    authorize.created_at = created_at;
    authorize.prev_refs = vec![create.event_id.clone()];
    let device_method = crate::fixture_did_url(format!("{actor}#{device_id}"));
    let device_signer = arkret_signatures::Ed25519PayloadSigner::from_did_key_seed(
        device_signing_key.to_bytes(),
        principal.clone(),
        device_method.clone(),
    );
    let mut authorize = arkret_wire::AuthoredEvent::finalize_with_digest_suite(
        authorize,
        arkret::canonical::DigestSuite::Sha256,
    )
    .map_err(|error| anyhow::anyhow!("fixture envelope failed to finalize: {error}"))?;
    arkret::signatures::sign_event(
        &mut authorize,
        &device_signer,
        &device_method,
        arkret::signatures::SignEventOptions::new().with_created_at(created_at),
    )?;
    let authorize_event_id = authorize.event_id.clone();
    let unit = build_self_principal_pcr_genesis_unit(
        create.into_event(),
        authorize.into_event(),
        &crate::publication::project_cells,
    )?;
    let validated_inception = validate_principal_inception_operation(&prepared.submit_body)?;
    // This harness stands in for the Account Authority and therefore owns the
    // opaque deployment-local account subject. Keep the production domain
    // separator and bind the fixture subject to its stable local account id.
    let mut account_subject_preimage = b"ak.account-subject.v1\n".to_vec();
    account_subject_preimage.extend(canonical_json_bytes(&serde_json::json!({
        "account_authority_id": harness_account_authority_id(),
        "service_account_id": local_id,
    }))?);
    let account_subject = Hash::new(arkret_canonical::canonical::sha256_digest(
        &account_subject_preimage,
    ))?;
    let issued_at = chrono::Utc::now();
    let registration_did_evidence =
        sign_registration_did_evidence_draft(&prepared.submit_body, issued_at, &root_seed)?
            .accept(issued_at)?;
    let control_proof =
        UnsignedIdentityCreationControlProof::new(UnsignedIdentityCreationControlProofBody {
            challenge_id: format!("cotest-pcr-genesis-{local_id}"),
            challenge: format!("cotest-pcr-genesis-challenge-{local_id}"),
            purpose: IdentityBindingPurpose::AccountBindingAndPcrGenesis,
            principal_id: principal_core_id.clone(),
            full_id: principal.clone(),
            account_subject,
            operation_digest: validated_inception.operation_digest.clone(),
            did_version_id: validated_inception.did_version_id.clone(),
            log_head_digest: validated_inception.log_head_digest.clone(),
            control_key_digest: validated_inception.control_key_digest.clone(),
            pcr_realm_id: realm_id.clone(),
            realm_create_payload_digest: Hash::new(canonical_sha256(&unit.create().payload)?)?,
            founding_authorize_payload_digest: Hash::new(canonical_sha256(
                &unit.founding_authorize().payload,
            )?)?,
            initial_session_request_digest: Hash::new(format!("sha256:{}", "0".repeat(64)))?,
            genesis_unit_kinds: PCR_GENESIS_UNIT_KINDS,
            identity_creation_lease_id: format!("cotest-identity-creation-{local_id}"),
            lease_fence: 1,
            dpop_jkt: format!("cotest-dpop-jkt-{local_id}"),
            audience: server.service_id().clone(),
            origin: HARNESS_ACCOUNT_AUTHORITY_ORIGIN.to_owned(),
            trust_domain: server.trust_domain().clone(),
            issued_at,
            expires_at: issued_at + chrono::Duration::minutes(4),
            verification_key_multibase: validated_inception.root_public_key_multibase,
        })?;
    let control_proof = sign_identity_creation_control_proof(control_proof, &root_seed)?;
    let idempotency_key = IdempotencyKey::new(format!("cotest-pcr-genesis-{local_id}"))
        .map_err(anyhow::Error::msg)?;
    let request = arkret_models_collaboration::principal_operations::PcrGenesisSubmitRequestBody {
        account_authority_id: harness_account_authority_id(),
        principal_id: principal_core_id,
        full_id: principal,
        pcr_realm_id: realm_id,
        idempotency_key: idempotency_key.clone(),
        registration_request_digest: Hash::new(format!("sha256:{}", "1".repeat(64)))?,
        did_version_id: validated_inception.did_version_id,
        log_head_digest: validated_inception.log_head_digest,
        control_key_digest: validated_inception.control_key_digest,
        registration_did_operation: prepared.submit_body.clone(),
        registration_did_evidence,
        identity_creation_control_proof: control_proof,
        genesis_unit: unit,
    };
    request.validate()?;
    let accepted = submit_harness_pcr_genesis(server, &request).await?;
    accepted.validate_against(&request)?;
    let seal_physical_millis = chrono::Utc::now().timestamp_millis();
    let bootstrap_seal = build_self_principal_bootstrap_seal(
        request.genesis_unit.create(),
        request.genesis_unit.founding_authorize(),
        Hlc::new(format!("{seal_physical_millis:012x}-0000-a13f9c2e"))?,
        &device_signer,
        &crate::publication::project_cells,
    )?;
    let seal_outcome =
        serde_json::from_value::<arkret_models_collaboration::http_bodies::EventSealSubmitOutcome>(
            expect_json(
                server
                    .http()
                    .post(server.url("/_arkret/self/events/seals"))
                    .bearer_auth(token)
                    .json(&bootstrap_seal),
                StatusCode::OK,
            )
            .await?,
        )?;
    anyhow::ensure!(
        seal_outcome.seal_id == bootstrap_seal.id
            && seal_outcome.accepted_event_digests == bootstrap_seal.delta
            && seal_outcome.post_state_root == bootstrap_seal.state_root,
        "principal server returned a mismatched PCR bootstrap Seal outcome"
    );
    crate::harness::register_event_signing_identity(
        actor,
        device_signing_key.to_bytes(),
        device_method.as_str().to_owned(),
        server.service_id().clone(),
    );

    Ok(TestDeviceAuthorizationBootstrap {
        authorize_event_id,
        pcr_realm_id: request.pcr_realm_id,
    })
}

async fn submit_harness_pcr_genesis(
    server: &ArkretServer,
    request: &arkret_models_collaboration::principal_operations::PcrGenesisSubmitRequestBody,
) -> Result<arkret_models_collaboration::principal_operations::PcrGenesisSubmitOutcome> {
    let body = canonical_json_bytes(request)?;
    let content_digest = format!("sha-256=:{}:", STANDARD.encode(Sha256::digest(&body)));
    let source_service_id = harness_account_authority_id().to_string();
    let destination_service_id = server.service_id().to_string();
    let source_trust_domain = server.trust_domain().as_str().to_owned();
    let destination_trust_domain = source_trust_domain.clone();
    let target_uri = server.url("/_arkret/peer/principal-genesis");
    let target = Url::parse(&target_uri)?;
    let authority = match target.port() {
        Some(port) => format!("{}:{port}", target.host_str().context("peer target host")?),
        None => target.host_str().context("peer target host")?.to_owned(),
    };
    let headers = vec![
        ("content-digest".to_owned(), content_digest.clone()),
        ("source-service-id".to_owned(), source_service_id.clone()),
        (
            "destination-service-id".to_owned(),
            destination_service_id.clone(),
        ),
        (
            "source-trust-domain".to_owned(),
            source_trust_domain.clone(),
        ),
        (
            "destination-trust-domain".to_owned(),
            destination_trust_domain.clone(),
        ),
        (
            "idempotency-key".to_owned(),
            request.idempotency_key.as_str().to_owned(),
        ),
    ];
    let components = vec![
        Component::Method,
        Component::TargetUri,
        Component::Authority,
        Component::Header("content-digest".to_owned()),
        Component::Header("source-service-id".to_owned()),
        Component::Header("destination-service-id".to_owned()),
        Component::Header("source-trust-domain".to_owned()),
        Component::Header("destination-trust-domain".to_owned()),
        Component::Header("idempotency-key".to_owned()),
    ];
    let created = chrono::Utc::now().timestamp();
    let expires = created + 120;
    let key_id = format!(
        "{}#federation-fanout-key",
        harness_account_authority_full_id()
    );
    let signature_input = format!(
        "{};created={created};expires={expires};keyid=\"{key_id}\";alg=\"ed25519\"",
        format_signature_input_component_list("sig1", &components)?
    );
    let parsed_signature_input = parse_signature_input(&signature_input)?;
    let signature_base = canonical_message(
        &SignedRequestParts {
            method: "POST".to_owned(),
            target_uri: target_uri.clone(),
            authority,
            path: target.path().to_owned(),
            headers,
            body_digest: Some(content_digest.clone()),
        },
        &parsed_signature_input,
    )?;
    let account_authority_key = SigningKey::from_bytes(&HARNESS_ACCOUNT_AUTHORITY_KEY_SEED);
    let signature = format!(
        "sig1=:{}:",
        sign_message(&signature_base, &account_authority_key)
    );
    let value = expect_json(
        server
            .http()
            .post(target_uri)
            .header("content-type", "application/json")
            .header("content-digest", content_digest)
            .header("source-service-id", source_service_id)
            .header("destination-service-id", destination_service_id)
            .header("source-trust-domain", source_trust_domain)
            .header("destination-trust-domain", destination_trust_domain)
            .header("idempotency-key", request.idempotency_key.as_str())
            .header("signature-input", signature_input)
            .header("signature", signature)
            .body(body),
        StatusCode::OK,
    )
    .await?;
    serde_json::from_value(value).context("decode harness PCR genesis outcome")
}

pub fn actor_did_for_service_full_id(service_full_id: &DidFullId, actor: &str) -> Result<String> {
    Ok(prepare_actor_inception_for_service_full_id(service_full_id, actor)?.did)
}

/// Prepare the deterministic native WebVH inception used by live principal
/// scenarios without submitting it, so endpoint tests can inspect the exact
/// request and outcome themselves.
pub fn prepare_actor_inception_for_service_full_id(
    service_full_id: &DidFullId,
    actor: &str,
) -> Result<PreparedPrincipalInception> {
    let service_host = did_authority_from_full_id(service_full_id);
    let service_authority = did_web_host_to_url_authority(&service_host);
    let webvh_host = if service_authority.contains('.') {
        service_authority
    } else {
        format!("{service_authority}.cotest.local")
    };
    test_principal_inception(&webvh_host, actor).with_context(|| {
        format!("prepare test principal inception for local id {actor:?} at {webvh_host:?}")
    })
}

/// Convert the percent-encoded port separator required by `did:web` method
/// identifiers back into the HTTP authority form expected by `Url`.
///
/// Keep this conversion local to principal URL construction; federation trust
/// domains come directly from each service's typed describe response.
fn did_web_host_to_url_authority(host: &str) -> String {
    host.replace("%3A", ":").replace("%3a", ":")
}

fn test_principal_inception(host: &str, local_id: &str) -> Result<PreparedPrincipalInception> {
    let endpoint = Url::parse(&format!("https://{host}/"))
        .with_context(|| format!("invalid test principal WebVH host {host}"))?;
    let root_seed = test_principal_root_seed(host, local_id);
    let next_root_seed: [u8; 32] =
        Sha256::digest(format!("cotest:webvh:next-root:{host}:{local_id}").as_bytes()).into();
    let next_root = SigningKey::from_bytes(&next_root_seed);
    let next_root_multibase =
        ed25519_pubkey_to_did_key_multibase(&next_root.verifying_key().to_bytes());
    prepare_principal_inception(&PrincipalInceptionInput {
        provider_endpoint: &endpoint,
        principal_endpoint: &endpoint,
        local_id,
        also_known_as: &[],
        version_time: chrono::DateTime::parse_from_rfc3339("2026-05-01T00:00:00.000Z")?
            .with_timezone(&chrono::Utc),
        root_seed: &root_seed,
        next_root_public_key_multibase: &next_root_multibase,
        witness_policy: None,
    })
    .with_context(|| {
        format!(
            "prepare deterministic native principal inception for local id {local_id:?} at {endpoint}"
        )
    })
}

fn test_principal_root_seed(host: &str, local_id: &str) -> [u8; 32] {
    Sha256::digest(format!("cotest:webvh:root:{host}:{local_id}").as_bytes()).into()
}

/// Deterministic PCR genesis salt per principal/device. Re-provisioning the
/// same actor on a durable server rebuilds the byte-identical genesis unit, so
/// the relay replays the original receipt instead of admitting a second PCR.
fn test_principal_genesis_salt(
    host: &str,
    local_id: &str,
    device_id: &str,
) -> Result<arkret_wire::GenesisSalt> {
    let digest = Sha256::digest(
        format!("cotest:webvh:genesis-salt:{host}:{local_id}:{device_id}").as_bytes(),
    );
    Ok(arkret_wire::GenesisSalt::new(
        URL_SAFE_NO_PAD.encode(digest),
    )?)
}

/// Extract the DID method authority while retaining an encoded local port.
/// Principal inception needs the port to address the local WebVH endpoint.
fn did_authority_from_full_id(service_full_id: &DidFullId) -> String {
    let service_full_id = service_full_id.as_str();
    if let Some(rest) = service_full_id.strip_prefix("did:webvh:") {
        let mut parts = rest.split(':');
        let scid = parts.next().unwrap_or_default();
        if let Some(host) = parts.next()
            && !scid.is_empty()
            && !host.is_empty()
        {
            return host.to_ascii_lowercase();
        }
    }
    if let Some(rest) = service_full_id.strip_prefix("did:web:")
        && let Some(host) = rest.split(':').next()
        && !host.is_empty()
    {
        return host.to_ascii_lowercase();
    }
    service_full_id
        .strip_prefix("did:key:")
        .unwrap_or(service_full_id)
        .to_ascii_lowercase()
        .replace(':', ".")
}
