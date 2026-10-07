use std::collections::{BTreeMap, HashMap};
use std::sync::{LazyLock, Mutex};

use anyhow::{Context, Result};
use arkret_bootstrap::{
    DID_INCEPTION_REF_ROLE, SelfPrincipalPcrCreateInput, build_pcr_genesis_unit,
    build_self_principal_pcr_create,
};
use arkret_canonical::multibase::ed25519_pubkey_to_did_key_multibase;
use arkret_canonical::{canonical_json_bytes, canonical_sha256};
use arkret_identifiers::{DeviceId, Did, RealmId, WebOrigin, project_did_to_core_id};
use arkret_models_collaboration::events_payloads::{
    DeviceAuthorizationBindingKind, DeviceAuthorizePayload, DeviceOrPrincipalRef,
    FoundingDeviceDescriptor, FoundingDeviceHpkeKeyAlgorithm, FoundingDeviceKeyAlgorithm,
    FoundingDeviceKeyPurpose, SignatureMaterial, device_authorize_payload_digest,
};
use arkret_models_crypto::{
    AlgorithmKeyRecords, KeyOperationSignature, KeysUploadRequestBody, KeysUploadUnsignedRequest,
    keys_upload_signing_input,
};
use arkret_models_identity::{
    IdentityBindingPurpose, IdentityCreationControlProofKind, PCR_GENESIS_UNIT_KINDS,
    PrincipalRegistrationAnchor, UnsignedIdentityCreationControlProof,
    UnsignedIdentityCreationControlProofBody,
};
use arkret_signatures::webvh::{
    PreparedPrincipalInception, PrincipalInceptionInput, prepare_principal_inception,
    sign_identity_creation_control_proof, sign_registration_did_evidence_draft,
};
use arkret_wire::{Base64UrlString, Hash, IdempotencyKey, NonEmptyString, SemanticRef};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signer, SigningKey};
use reqwest::StatusCode;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use url::Url;

use crate::harness::{
    ArkretServer, CanonicalJsonBody, ProvisionedTestPrincipal, TestActorClient,
    canonical_device_id, dev_login, expect_json, refresh_typed_event_proof_with_signing_seed,
    register_account_via_dev_login, register_account_with_localpart_via_dev_login,
    register_event_signing_identity,
};

/// Establish Human kind from an accepted, holder-authored PCR ProfileCreate.
/// Account registration and a Standard SessionGrant do not create this
/// create-locked profile current result.
pub async fn create_human_actor_profile(
    client: &TestActorClient,
    display_name: &str,
) -> Result<()> {
    let principal = client
        .principal
        .as_ref()
        .context("the Human client carries its provisioned principal")?;
    let mut event = client
        .author_event(
            principal.pcr_realm_id.as_str(),
            arkret_wire::EventKind::ProfileCreate.as_str(),
            json!({
                "object": {
                    "principal_id": principal.core_id,
                    "actor_kind": "user",
                    "display_name": display_name,
                }
            }),
        )
        .await?;
    event.authorization_ref = None;
    refresh_typed_event_proof_with_signing_seed(
        &mut event,
        principal.device_signing_key.to_bytes(),
    )?;
    let outcome = expect_json(
        client
            .post("/_arkret/self/account/profile")
            .canonical_json(&json!({"profile_event": {"event": event}}))?,
        StatusCode::OK,
    )
    .await?;
    anyhow::ensure!(
        outcome["profile"]["actor_kind"] == "user"
            && outcome["commit"]["event_ref"] == event.event_id.as_str(),
        "PCR Human ProfileCreate was not committed: {outcome}"
    );
    Ok(())
}

pub const HARNESS_ACCOUNT_AUTHORITY_KEY_SEED: [u8; 32] = [0xac; 32];
pub const HARNESS_ACCOUNT_AUTHORITY_ORIGIN: &str = "https://account-authority.cotest.local";
pub const HARNESS_INTERNAL_AUTHORITY_SECRET: &str = "cotest-principal-genesis-private-channel";
pub fn harness_account_authority_public_key_multibase() -> String {
    ed25519_pubkey_to_did_key_multibase(
        &SigningKey::from_bytes(&HARNESS_ACCOUNT_AUTHORITY_KEY_SEED)
            .verifying_key()
            .to_bytes(),
    )
}

/// A Station behind the harness Account Authority.
///
/// Every harness spawn path already registers the Authority endpoint, its
/// delegated assertion key and the deployment-internal channel (secret plus the
/// Authority's own trust domain) unless the caller supplies them
/// (`harness::server::harness_account_authority_env`), so `extra_env` passes
/// through unchanged and the channel values have exactly one source.
pub async fn spawn_with_harness_account_authority(
    name: &str,
    extra_env: &[(&str, &str)],
) -> Result<ArkretServer> {
    ArkretServer::spawn_with_env(name, extra_env).await
}

/// A Station behind the harness Account Authority whose issuer ledger answers
/// SessionGrant introspection, so its principals can hold a Standard grant.
///
/// A self Event requires the authenticated Standard SessionGrant of the exact
/// Account (`account-lifecycle.md` step 8, `api-conventions.md`). The
/// development bearer that `demo_client` / `register_client` return carries no
/// grant, so a scenario that authors Events presents the founding device's
/// grant through [`Self::standard_grant_client`]. Keep this value alive for the
/// whole scenario: dropping it stops the issuer ledger.
pub struct StandardGrantStation {
    pub server: ArkretServer,
    coauth: crate::scenarios::_helpers::bridge::MockCoauthIntrospectionServer,
}

impl StandardGrantStation {
    /// Bind the founding device of `client`'s provisioned principal to one
    /// exact issuer-ledger grant and return a DPoP client presenting it.
    pub fn standard_grant_client(&self, client: &TestActorClient) -> Result<TestActorClient> {
        let principal = client
            .principal
            .as_ref()
            .context("a Standard grant needs the client's provisioned principal")?;
        let grant = crate::scenarios::bridge_contracts::session_grant::mock_session_grant_jwt(
            principal.core_id.as_str(),
            principal.device_id.as_str(),
            self.server.service_id().as_str(),
        );
        self.coauth.bind_founding_device_grant(
            &grant,
            principal.core_id.as_str(),
            principal.device_id.as_str(),
            principal.founding_authorize_event_id.as_str(),
            &principal.device_signing_key.verifying_key(),
        )?;
        self.server
            .client_with_founding_device_grant(principal, grant)
    }
}

pub async fn spawn_with_standard_grant_authority(
    name: &str,
    extra_env: &[(&str, &str)],
) -> Result<StandardGrantStation> {
    let coauth =
        crate::scenarios::_helpers::bridge::MockCoauthIntrospectionServer::spawn_with_internal_secret(
            HARNESS_INTERNAL_AUTHORITY_SECRET,
        )
        .await?;
    let origin = coauth.origin();
    let introspection = coauth.url();
    let mut env = vec![
        ("SOLAND_ACCOUNT_AUTHORITY_URL", origin.as_str()),
        ("SOLAND_DID_RESOLVER_ALLOW_METHODS", "web,webvh,key,uuid"),
        (
            "SOLAND_SESSION_GRANT_INTROSPECTION_URL",
            introspection.as_str(),
        ),
    ];
    env.extend(extra_env.iter().copied().filter(|(key, _)| {
        !matches!(
            *key,
            "SOLAND_ACCOUNT_AUTHORITY_URL"
                | "SOLAND_DID_RESOLVER_ALLOW_METHODS"
                | "SOLAND_SESSION_GRANT_INTROSPECTION_URL"
        )
    }));
    let server = spawn_with_harness_account_authority(name, &env).await?;
    Ok(StandardGrantStation { server, coauth })
}

/// [`spawn_with_harness_account_authority`] on a database the caller owns, for
/// scenarios that must install a labelled fixture row the Station has no
/// admission unit for yet.
pub async fn spawn_with_harness_account_authority_at(
    name: &str,
    database_url: &str,
    extra_env: &[(&str, &str)],
) -> Result<ArkretServer> {
    ArkretServer::spawn_with_database_url(name, database_url, extra_env).await
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
            .json(
                &arkret_models_identity::identity::IdentityResolveRequestBody {
                    did: arkret_wire::Did::new(actor)?,
                    requested_evidence_kinds: Vec::new(),
                },
            ),
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

pub(crate) fn prepared_test_principal_inception(actor: &str) -> Result<PreparedPrincipalInception> {
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

pub fn test_principal_root_signing_authority(
    actor: &str,
) -> Result<(arkret_wire::DidUrl, [u8; 32])> {
    let prepared = prepared_test_principal_inception(actor)?;
    let verification_method = arkret_wire::DidUrl::new(prepared.root_verification_method)
        .map_err(|error| anyhow::anyhow!("test principal root verification method: {error}"))?;
    Ok((verification_method, test_principal_root_key_seed(actor)?))
}

pub(crate) fn test_principal_next_root_seed(actor: &str) -> Result<[u8; 32]> {
    let (host, local_id) = test_principal_coordinates(actor)?;
    Ok(Sha256::digest(format!("cotest:webvh:next-root:{host}:{local_id}").as_bytes()).into())
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
            let token = dev_login(server, actor, &device_id).await?;
            return Ok((founding, token));
        }
        if let Some((additional_key, authorize_event_id)) = additional {
            register_event_signing_identity(
                actor,
                additional_key.to_bytes(),
                device_method.as_str().to_owned(),
                server.service_id().clone(),
            );
            let token = dev_login(server, actor, &device_id).await?;
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
        let token = dev_login(server, actor, &device_id).await?;
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
    let bootstrap =
        bootstrap_test_device_authorization(server, actor, &device_id, &device_key, &prepared)
            .await?;
    register_event_signing_identity(
        actor,
        device_key.to_bytes(),
        device_method.as_str().to_owned(),
        server.service_id().clone(),
    );
    let did = Did::new(actor.to_owned())?;
    let principal = ProvisionedTestPrincipal {
        core_id: project_did_to_core_id(&did)?,
        did,
        device_id: DeviceId::new(device_id)?,
        device_signing_key: device_key,
        root_key_seed: test_principal_root_key_seed(actor)?,
        pcr_realm_id: bootstrap.pcr_realm_id,
        founding_authorize_event_id: bootstrap.authorize_event_id,
    };
    let token = match registration {
        ActorBootstrapRegistration::DevLogin => {
            dev_login(server, actor, principal.device_id.as_str()).await?
        }
        ActorBootstrapRegistration::Account { handle } => {
            register_account_via_dev_login(server, actor, handle, principal.device_id.as_str())
                .await?
        }
        ActorBootstrapRegistration::AccountWithLocalpart { handle, localpart } => {
            register_account_with_localpart_via_dev_login(
                server,
                actor,
                handle,
                localpart,
                principal.device_id.as_str(),
            )
            .await?
        }
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
/// as an `accepted_device` of the current generation (device-lifecycle.md
/// §5.2, §5.4). `ak.gate.account.command.pair_device.v1` and its pending
/// pairing ledger belong to the Account Authority, which relays the frozen
/// `ak.device.authorize` to the owning Station over the private admission
/// channel; this single-process harness stands in for that relay, so the
/// Station's registered accepted-device unit still decides every same-cut
/// check. The founding device signs the complete Event and the new device
/// signs its §5.2.2 possession object. The two-process pairing ledger path
/// (stage, finalize, claim, pair_device) is not exercised here.
async fn authorize_additional_principal_device(
    server: &ArkretServer,
    founding: &ProvisionedTestPrincipal,
    device_id: &str,
    device_signing_key: &SigningKey,
) -> Result<arkret_identifiers::EventId> {
    let actor = founding.did.as_str();
    let new_device_id = DeviceId::new(device_id.to_owned())?;
    let device_multibase =
        ed25519_pubkey_to_did_key_multibase(&device_signing_key.verifying_key().to_bytes());
    let mut hpke = vec![0xec, 0x01];
    hpke.extend(Sha256::digest(
        format!("cotest:device-hpke:{device_id}").as_bytes(),
    ));
    let account =
        arkret_wire::AccountId::new(founding.core_id.clone(), server.service_id().clone());
    let founding_token = dev_login(server, actor, founding.device_id.as_str()).await?;
    let keys: arkret_models_crypto::KeysQueryOutcome = serde_json::from_value(
        expect_json(
            server
                .http()
                .post(server.url("/_arkret/self/keys/query"))
                .bearer_auth(&founding_token)
                .json(&arkret_models_crypto::KeysQueryRequestBody {
                    device_keys: vec![arkret_models_crypto::QueryAccountDeviceSelector {
                        account_id: account.clone(),
                        device_ids: vec![founding.device_id.clone()],
                    }],
                    timeout_ms: None,
                }),
            StatusCode::OK,
        )
        .await?,
    )?;
    keys.validate()?;
    let generation = keys
        .generation_for(&account)
        .context("keys/query omitted the current PCR device generation")?;
    let mut payload = DeviceAuthorizePayload {
        pairing_challenge_transcript_digest: Some(Hash::new(arkret_canonical::sha256_digest(
            format!("cotest:device-pairing:{actor}:{device_id}").as_bytes(),
        ))?),
        device_id: new_device_id,
        device_public_key_did: NonEmptyString::new(format!("did:key:{device_multibase}"))
            .map_err(anyhow::Error::msg)?,
        hpke_key: NonEmptyString::new(arkret_canonical::encode_multibase_base58btc(hpke))
            .map_err(anyhow::Error::msg)?,
        algorithms: vec![
            NonEmptyString::new("ak.hpke_x25519_aead_chacha20poly1305.v1")
                .map_err(anyhow::Error::msg)?,
        ],
        device_key_algorithm: NonEmptyString::new("Ed25519").map_err(anyhow::Error::msg)?,
        authorized_by: DeviceOrPrincipalRef::DeviceId(founding.device_id.clone()),
        scopes: None,
        not_before: arkret::canonical::normalize_timestamp_canonical(chrono::Utc::now()),
        expires_at: None,
        authorization_binding_kind: DeviceAuthorizationBindingKind::AcceptedDevice,
        authorized_generation_ref: generation.current_device_generation_ref,
        device_signature: SignatureMaterial::NonEmptyString(
            NonEmptyString::new("unsigned").map_err(anyhow::Error::msg)?,
        ),
        recovery_session_id: None,
        // `accepted_device` is one of the three branches that MUST NOT carry an
        // install fence (`device-lifecycle.md` section 5.2.3).
        applet_id: None,
    };
    let possession = payload.device_possession_signature_input(&account)?;
    payload.device_signature = SignatureMaterial::NonEmptyString(
        NonEmptyString::new(arkret_canonical::base64url_encode(
            device_signing_key.sign(&possession).to_bytes(),
        ))
        .map_err(anyhow::Error::msg)?,
    );
    let founding_method = crate::fixture_did_url(format!("{actor}#{}", founding.device_id));
    let event = crate::harness::event_envelope_with_chain_and_signing_identity_and_causal_refs(
        actor,
        founding.pcr_realm_id.as_str(),
        arkret_wire::EventKind::DeviceAuthorize.as_str(),
        serde_json::to_value(&payload)?,
        None,
        Vec::new(),
        founding.device_signing_key.to_bytes(),
        &founding_method,
        Some(server.service_id()),
        Vec::new(),
    );
    let outcome: arkret_wire::AuthoritySubmitOutcome = serde_json::from_value(
        expect_json(
            server
                .http()
                .post(server.url("/_soland/account-authority/events/admit"))
                .bearer_auth(HARNESS_INTERNAL_AUTHORITY_SECRET)
                .header("idempotency-key", event.event_id.as_str())
                .json(&arkret_wire::EventAdmissionSubmission::new(event.clone())),
            StatusCode::OK,
        )
        .await?,
    )?;
    match outcome {
        arkret_wire::AuthoritySubmitOutcome::Accepted { commit, .. }
            if commit.event_ref == event.event_id && commit.realm_id == founding.pcr_realm_id =>
        {
            Ok(event.event_id)
        }
        other => anyhow::bail!(
            "the accepted-device authorization of {device_id} was not committed: {other:?}"
        ),
    }
}

/// Read the current signed PCR RealmCommit head after verifying every
/// caller-authored pending Event has actually been accepted. The governance
/// Station, not this device, signs and orders RealmCommits.
pub async fn seal_current_principal_control_frontier(
    client: &TestActorClient,
    device_signing_key: &SigningKey,
) -> Result<arkret_wire::RealmCommitId> {
    seal_principal_control_frontier_with_pending_events(client, device_signing_key, &[]).await
}

pub async fn seal_principal_control_frontier_with_pending_events(
    client: &TestActorClient,
    _device_signing_key: &SigningKey,
    caller_pending_events: &[arkret_wire::Event],
) -> Result<arkret_wire::RealmCommitId> {
    let provisioned = client
        .principal
        .as_ref()
        .context("client has no provisioned Principal Control Realm")?;
    let realm_id = provisioned.pcr_realm_id.clone();
    let stream_ref = arkret_wire::CommitStreamRef::Realm {
        realm_id: realm_id.clone(),
    };
    for event in caller_pending_events {
        anyhow::ensure!(
            event.realm_id == realm_id,
            "caller Event is outside its PCR"
        );
        let accepted = client.sdk().committed_event_get(&event.event_id).await?;
        accepted.validate_shape()?;
        anyhow::ensure!(
            accepted.commit().stream_ref == stream_ref && accepted.reducer_input() == Some(event),
            "caller PCR Event has no exact accepted RealmCommit"
        );
    }
    let tail = client
        .sdk()
        .scan_commit_stream_to_head(realm_id, stream_ref, None, 1000)
        .await?;
    tail.committed_events
        .last()
        .map(|item| item.commit().commit_id.clone())
        .context("PCR has no accepted RealmCommit")
}
pub fn signed_keys_upload_body(
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
    let principal = Did::new(actor.to_owned()).context("invalid test principal DID")?;
    let principal_core_id = project_did_to_core_id(&principal)?;
    let principal_actor_id = principal_core_id.clone();
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
        pairing_challenge_transcript_digest: None,
        device_id: device_id.clone(),
        device_public_key_did: device_public_key.clone(),
        hpke_key: hpke_key.clone(),
        algorithms: algorithms.clone(),
        device_key_algorithm: NonEmptyString::new("Ed25519").map_err(anyhow::Error::msg)?,
        authorized_by: DeviceOrPrincipalRef::Principal(principal_actor_id.clone()),
        scopes: None,
        not_before: created_at,
        expires_at: None,
        authorization_binding_kind: DeviceAuthorizationBindingKind::RegistrationAnchor,
        authorized_generation_ref: 1,
        device_signature: SignatureMaterial::NonEmptyString(
            NonEmptyString::new("pending").map_err(anyhow::Error::msg)?,
        ),
        recovery_session_id: None,
        // `registration_anchor` is one of the three branches that MUST NOT
        // carry an install fence (`device-lifecycle.md` section 5.2.3).
        applet_id: None,
    };
    payload.device_signature = SignatureMaterial::NonEmptyString(
        NonEmptyString::new(
            URL_SAFE_NO_PAD.encode(
                device_signing_key
                    .sign(
                        &payload.device_possession_signature_input(&arkret::AccountId::new(
                            principal_actor_id.clone(),
                            server.service_id().clone(),
                        ))?,
                    )
                    .to_bytes(),
            ),
        )
        .map_err(anyhow::Error::msg)?,
    );
    let payload_value = serde_json::to_value(&payload)?;
    let descriptor = FoundingDeviceDescriptor {
        descriptor_version: 1,
        device_id: device_id.clone(),
        device_public_key_did: device_public_key.clone(),
        device_key_algorithm: FoundingDeviceKeyAlgorithm::Ed25519,
        device_key_purpose: FoundingDeviceKeyPurpose::EventSigningAndMlsIdentity,
        hpke_key,
        hpke_key_algorithm: FoundingDeviceHpkeKeyAlgorithm::X25519,
        algorithms,
        founding_authorize_payload_digest: device_authorize_payload_digest(
            &payload_value,
            arkret_canonical::DigestSuite::Sha256,
        )?,
    };
    let create = build_self_principal_pcr_create(SelfPrincipalPcrCreateInput {
        principal_id: principal_actor_id.clone(),
        governance_station_id: server.service_id().clone(),
        principal_did: principal.clone(),
        initial_resolution: arkret_models_identity::ResolutionCommitment {
            did: principal.clone(),
            method_history_head: arkret_canonical::canonical_sha256(&prepared.log_entry)?,
            version_id: prepared.version_id.clone(),
        },
        genesis_salt: test_principal_genesis_salt(&host, local_id, device_id.as_str())?,
        trust_domain: server.trust_domain().clone(),
        did_inception_ref: SemanticRef::new(prepared.version_id.clone(), DID_INCEPTION_REF_ROLE),
        founding_device_descriptor: descriptor,
        initial_join_rule: arkret_wire::JoinRule::Closed,
        initial_history_access: arkret_wire::HistoryAccess::SinceJoin,
        initial_discoverability: arkret_wire::Discoverability::Secret,
        created_at,
    })?;
    let root_seed: [u8; 32] =
        Sha256::digest(format!("cotest:webvh:root:{host}:{local_id}").as_bytes()).into();
    let root_did = Did::new(format!("did:key:{}", prepared.root_public_key_multibase))?;
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
        arkret::signatures::SignEventOptions::new().with_created_at(created_at),
    )?;
    let realm_id = create.realm_id.clone();
    let authorize = arkret_wire::test_support::raw_event_at(
        arkret_wire::EventKind::DeviceAuthorize.as_str(),
        arkret_wire::ScopeRef::Realm {
            realm_id: realm_id.clone(),
        },
        principal_actor_id,
        server.service_id().clone(),
        payload_value,
        created_at,
    )?;
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
        arkret::signatures::SignEventOptions::new().with_created_at(created_at),
    )?;
    let authorize_event_id = authorize.event_id.clone();
    let unit = build_pcr_genesis_unit(create.into_event(), authorize.into_event())?;
    let principal_registration_anchor = PrincipalRegistrationAnchor::WebvhRegistration {
        registration_did_operation: Box::new(prepared.submit_body.clone()),
        log_entries: vec![serde_json::from_value(prepared.log_entry.clone())?],
        witness_records: Vec::new(),
        normalized_did_document: serde_json::from_value(prepared.log_entry["state"].clone())?,
    };
    let validated_anchor =
        arkret_identity::validate_principal_registration_anchor(&principal_registration_anchor)?;
    // This harness stands in for the Account Authority and therefore owns the
    // opaque deployment-local account subject. Keep the production domain
    // separator and bind the fixture subject to its stable local account id.
    let mut account_subject_preimage = b"ak.account-subject.v1\n".to_vec();
    account_subject_preimage.extend(canonical_json_bytes(&serde_json::json!({
        "account_authority_id": server.service_id(),
        "account_local_id": local_id,
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
            proof_kind: IdentityCreationControlProofKind::DidWebvhInceptionUpdateKey,
            challenge_id: format!("cotest-pcr-genesis-{local_id}"),
            challenge: format!("cotest-pcr-genesis-challenge-{local_id}"),
            purpose: IdentityBindingPurpose::AccountBindingAndPcrGenesis,
            principal_id: principal_core_id.clone(),
            did: principal.clone(),
            account_subject,
            registration_anchor_digest: validated_anchor.registration_anchor_digest.clone(),
            did_version_id: validated_anchor.did_version_id.clone(),
            control_key_digest: validated_anchor.control_key_digest.clone(),
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
            audience_id: server.service_id().clone(),
            origin: WebOrigin::new(server.account_authority_origin())?,
            trust_domain: server.trust_domain().clone(),
            issued_at,
            expires_at: issued_at + chrono::Duration::minutes(4),
            verification_key_multibase: validated_anchor.root_public_key_multibase,
            signature_algorithm: arkret_wire::DetachedSignatureAlgorithm::Ed25519,
        })?;
    let control_proof = sign_identity_creation_control_proof(control_proof, &root_seed)?;
    let idempotency_key = IdempotencyKey::new(format!("cotest-pcr-genesis-{local_id}"))
        .map_err(anyhow::Error::msg)?;
    let request = arkret_models_collaboration::principal_operations::PcrGenesisAdmissionInput {
        account_authority_id: server.service_id().clone(),
        principal_id: principal_core_id,
        did: principal,
        pcr_realm_id: realm_id,
        idempotency_key: idempotency_key.clone(),
        registration_request_digest: Hash::new(format!("sha256:{}", "1".repeat(64)))?,
        did_version_id: validated_anchor.did_version_id,
        control_key_digest: validated_anchor.control_key_digest,
        principal_registration_anchor,
        registration_did_evidence,
        identity_creation_control_proof: control_proof,
        genesis_unit: unit,
    };
    request.validate()?;
    let accepted = submit_harness_pcr_genesis(server, &request).await?;
    accepted.validate_against(&request)?;
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
    request: &arkret_models_collaboration::principal_operations::PcrGenesisAdmissionInput,
) -> Result<arkret_models_collaboration::principal_operations::PcrGenesisAdmissionResult> {
    request.validate()?;
    let value = expect_json(
        server
            .http()
            .post(server.url("/_soland/account-authority/principal-genesis/admit"))
            .bearer_auth(HARNESS_INTERNAL_AUTHORITY_SECRET)
            .header("idempotency-key", request.idempotency_key.as_str())
            .json(request),
        StatusCode::OK,
    )
    .await?;
    serde_json::from_value(value).context("decode private PCR genesis admission result")
}
pub fn actor_did_for_service_did(service_did: &Did, actor: &str) -> Result<String> {
    Ok(prepare_actor_inception_for_service_did(service_did, actor)?.did)
}

/// Prepare the deterministic native WebVH inception used by live principal
/// scenarios without submitting it, so endpoint tests can inspect the exact
/// request and outcome themselves.
pub fn prepare_actor_inception_for_service_did(
    service_did: &Did,
    actor: &str,
) -> Result<PreparedPrincipalInception> {
    let service_host = did_authority_from_did(service_did);
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
fn did_authority_from_did(service_did: &Did) -> String {
    let service_did = service_did.as_str();
    if let Some(rest) = service_did.strip_prefix("did:webvh:") {
        let mut parts = rest.split(':');
        let scid = parts.next().unwrap_or_default();
        if let Some(host) = parts.next()
            && !scid.is_empty()
            && !host.is_empty()
        {
            return host.to_ascii_lowercase();
        }
    }
    if let Some(rest) = service_did.strip_prefix("did:web:")
        && let Some(host) = rest.split(':').next()
        && !host.is_empty()
    {
        return host.to_ascii_lowercase();
    }
    service_did
        .strip_prefix("did:key:")
        .unwrap_or(service_did)
        .to_ascii_lowercase()
        .replace(':', ".")
}
