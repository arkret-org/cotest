use anyhow::{Context, Result};
use arkret_bootstrap::{
    DID_INCEPTION_REF_ROLE, SelfPrincipalPcrCreateInput, build_self_principal_pcr_create,
    build_self_principal_pcr_genesis_unit,
};
use arkret_canonical::multibase::ed25519_pubkey_to_did_key_multibase;
use arkret_canonical::{canonical_json_bytes, canonical_sha256};
use arkret_identifiers::{DeviceId, Did, Hlc, RealmId};
use arkret_models_collaboration::events_payloads::{
    DeviceAuthorizationBindingKind, DeviceAuthorizePayload, DeviceOrPrincipalRef,
    FoundingDeviceDescriptor, FoundingDeviceHpkeKeyAlgorithm, FoundingDeviceKeyAlgorithm,
    FoundingDeviceKeyPurpose, SignatureMaterial, device_authorize_payload_digest,
};
use arkret_models_crypto::{
    AlgorithmKeyRecords, KeyOperationSignature, KeysUploadRequestBody, KeysUploadUnsignedRequest,
    keys_upload_signing_input,
};
use arkret_models_identity::did_document::principal_control_realm_id;
use arkret_signatures::webvh::{
    PreparedPrincipalInception, PrincipalInceptionInput, prepare_principal_inception,
};
use arkret_wire::{
    AuthorizationLeaseIssueOutcome, AuthorizationLeaseIssueRequest, Base64UrlString, Event,
    EventInitialSubmission, EventRef, NonEmptyString,
};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signer, SigningKey};
use reqwest::StatusCode;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use url::Url;

use crate::harness::{ArkretServer, expect_json};

pub(crate) const TEST_ROOT_KEY_SEED: [u8; 32] = [0x51; 32];

fn registry_digest() -> arkret_identifiers::Hash {
    arkret::current_capability_action_registry_digest()
        .expect("embedded capability-action registry")
}

fn test_device_record_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[0x52; 32])
}

async fn install_test_principal_control_document(server: &ArkretServer, actor: &str) -> Result<()> {
    let (_, remainder) = actor
        .strip_prefix("did:webvh:")
        .and_then(|remainder| remainder.split_once(':'))
        .context("test principal is not a did:webvh DID")?;
    let (method_authority, local_id) = remainder
        .split_once(":webvh:")
        .context("test principal DID has no local id")?;
    let host = method_authority.replace("%3A", ":").replace("%3a", ":");
    let prepared = test_principal_inception(&host, local_id)?;
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
        resolved["did_document"]["verificationMethod"]
            .as_array()
            .is_some_and(|methods| methods.iter().any(|method| {
                method["id"].as_str() == Some(prepared.root_verification_method.as_str())
            })),
        "installed identity root is absent from resolved DID document: {resolved}"
    );
    crate::harness::register_event_signing_identity(
        actor,
        TEST_ROOT_KEY_SEED,
        prepared.root_verification_method,
    );
    Ok(())
}

pub async fn authorize_device_public_key(
    server: &ArkretServer,
    token: &str,
    actor: &str,
    device_id: &str,
    device_signing_key: &SigningKey,
) -> Result<()> {
    install_test_principal_control_document(server, actor).await?;
    bootstrap_test_device_authorization(server, token, actor, device_id, device_signing_key)
        .await?;
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
    let device_public_key =
        ed25519_pubkey_to_did_key_multibase(&signing_key.verifying_key().to_bytes());
    Ok(unsigned.into_signed(KeyOperationSignature {
        kid: NonEmptyString::new(format!("did:key:{device_public_key}#{device_public_key}"))
            .unwrap(),
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

async fn bootstrap_test_device_authorization(
    server: &ArkretServer,
    token: &str,
    actor: &str,
    device_id: &str,
    device_signing_key: &SigningKey,
) -> Result<()> {
    let (_, remainder) = actor
        .strip_prefix("did:webvh:")
        .and_then(|remainder| remainder.split_once(':'))
        .context("test principal is not a did:webvh DID")?;
    let (method_authority, local_id) = remainder
        .split_once(":webvh:")
        .context("test principal DID has no local id")?;
    let host = method_authority.replace("%3A", ":").replace("%3a", ":");
    let prepared = test_principal_inception(&host, local_id)?;
    let principal = Did::new(actor.to_owned()).context("invalid test principal DID")?;
    let realm_id = RealmId::new(principal_control_realm_id(&principal))?;
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
        principal_id: principal.clone(),
        device_id: device_id.clone(),
        device_public_key: device_public_key.clone(),
        hpke_key: hpke_key.clone(),
        algorithms: algorithms.clone(),
        device_key_algorithm: Some(NonEmptyString::new("Ed25519").map_err(anyhow::Error::msg)?),
        authorized_by: DeviceOrPrincipalRef::Did(principal.clone()),
        scopes: None,
        not_before: created_at,
        expires_at: None,
        authorization_binding_kind: DeviceAuthorizationBindingKind::RootAnchored,
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
            principal_id: principal.clone(),
            realm_id: realm_id.clone(),
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
    let root_did = Did::new(format!("did:key:{}", prepared.root_public_key_multibase))?;
    let root_verification_method =
        crate::fixture_did_url(prepared.root_verification_method.clone());
    let root_signer = arkret_signatures::Ed25519PayloadSigner::from_did_key_seed(
        root_seed,
        root_did,
        root_verification_method.clone(),
    );
    arkret::signatures::sign_event(
        &mut create,
        &root_signer,
        &root_verification_method,
        arkret::signatures::SignEventOptions::new().with_created_at(created_at),
    )?;
    let mut authorize = arkret_wire::test_support::raw_event(
        arkret_wire::EventKind::DeviceAuthorize.as_str(),
        arkret_wire::ScopeRef::Realm { realm_id },
        principal.clone(),
        1,
        Hlc::new("01970e589d21-0001-a13f9c2e")?,
        payload_value,
    )?;
    authorize.created_at = created_at;
    authorize.prev_refs = vec![create.event_id.clone()];
    authorize.refresh_content_bound_identity()?;
    let device_method = crate::fixture_did_url(format!("{actor}#{device_id}"));
    let device_signer = arkret_signatures::Ed25519PayloadSigner::from_did_key_seed(
        device_signing_key.to_bytes(),
        principal.clone(),
        device_method.clone(),
    );
    arkret::signatures::sign_event(
        &mut authorize,
        &device_signer,
        &device_method,
        arkret::signatures::SignEventOptions::new().with_created_at(created_at),
    )?;
    let _unit = build_self_principal_pcr_genesis_unit(
        create.clone(),
        authorize.clone(),
        &crate::publication::project_cells,
    )?;
    let lease_request = AuthorizationLeaseIssueRequest {
        events: vec![create.clone(), authorize.clone()],
        intents: Vec::new(),
    };
    let idempotency_key = format!(
        "cotest-bootstrap-{}",
        canonical_sha256(&lease_request)?
            .strip_prefix("sha256:")
            .unwrap_or_default()
    );
    let lease_value = expect_json(
        server
            .http()
            .post(server.url("/_arkret/self/authorization-leases"))
            .bearer_auth(token)
            .header("Idempotency-Key", idempotency_key)
            .json(&lease_request),
        StatusCode::OK,
    )
    .await?;
    let lease_outcome: AuthorizationLeaseIssueOutcome =
        serde_json::from_value(lease_value).context("decode founding authorization leases")?;
    lease_outcome
        .validate_against_request(&lease_request)
        .context("validate founding authorization leases")?;
    let [create_lease, authorize_lease] = lease_outcome.authorization_leases.as_slice() else {
        anyhow::bail!("founding authorization lease issue did not preserve unit cardinality");
    };

    let create_event_id = create.event_id.clone();
    let authorize_event_id = authorize.event_id.clone();
    let request = arkret_models_collaboration::http_bodies::EventsSubmitRequestBody::Batch(
        arkret_models_collaboration::http_bodies::EventsSubmitBatchRequestBody {
            events: vec![
                EventInitialSubmission {
                    event: create,
                    authorization_lease: Some(create_lease.clone()),
                    cba_proof_bundles: Vec::new(),
                    control_proposal_ack: None,
                    membership_compensation_evidence: None,
                },
                EventInitialSubmission {
                    event: authorize.clone(),
                    authorization_lease: Some(authorize_lease.clone()),
                    cba_proof_bundles: Vec::new(),
                    control_proposal_ack: None,
                    membership_compensation_evidence: None,
                },
            ],
        },
    );
    let accepted = expect_json(
        server
            .http()
            .post(server.url("/_arkret/self/events"))
            .bearer_auth(token)
            .json(&request),
        StatusCode::OK,
    )
    .await?;
    assert_json_array_contains(&accepted["accepted"], create_event_id.as_str());
    assert_json_array_contains(&accepted["accepted"], authorize_event_id.as_str());

    Ok(())
}

pub fn actor_did_for_service(service_id: &str, actor: &str) -> Result<String> {
    Ok(prepare_actor_inception_for_service(service_id, actor)?.did)
}

/// Prepare the deterministic native WebVH inception used by live principal
/// scenarios without submitting it, so endpoint tests can inspect the exact
/// request and outcome themselves.
pub fn prepare_actor_inception_for_service(
    service_id: &str,
    actor: &str,
) -> Result<PreparedPrincipalInception> {
    let service_host = did_authority_from_service_id(service_id);
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
    let root_seed: [u8; 32] =
        Sha256::digest(format!("cotest:webvh:root:{host}:{local_id}").as_bytes()).into();
    let next_root_seed: [u8; 32] =
        Sha256::digest(format!("cotest:webvh:next-root:{host}:{local_id}").as_bytes()).into();
    let next_root = SigningKey::from_bytes(&next_root_seed);
    let next_root_multibase =
        ed25519_pubkey_to_did_key_multibase(&next_root.verifying_key().to_bytes());
    prepare_principal_inception(&PrincipalInceptionInput {
        principal_endpoint: &endpoint,
        local_id,
        also_known_as: &[],
        version_time: chrono::DateTime::parse_from_rfc3339("2026-05-01T00:00:00.000Z")?
            .with_timezone(&chrono::Utc),
        root_seed: &root_seed,
        next_root_public_key_multibase: &next_root_multibase,
    })
    .with_context(|| {
        format!(
            "prepare deterministic native principal inception for local id {local_id:?} at {endpoint}"
        )
    })
}

/// Extract the DID method authority while retaining an encoded local port.
/// Principal inception needs the port to address the local WebVH endpoint.
fn did_authority_from_service_id(service_id: &str) -> String {
    if let Some(rest) = service_id.strip_prefix("did:webvh:") {
        let mut parts = rest.split(':');
        let scid = parts.next().unwrap_or_default();
        if let Some(host) = parts.next()
            && !scid.is_empty()
            && !host.is_empty()
        {
            return host.to_ascii_lowercase();
        }
    }
    if let Some(rest) = service_id.strip_prefix("did:web:")
        && let Some(host) = rest.split(':').next()
        && !host.is_empty()
    {
        return host.to_ascii_lowercase();
    }
    service_id
        .strip_prefix("did:key:")
        .unwrap_or(service_id)
        .to_ascii_lowercase()
        .replace(':', ".")
}
fn assert_json_array_contains(array: &Value, expected: &str) {
    assert!(
        array
            .as_array()
            .unwrap()
            .iter()
            .any(|value| value.as_str() == Some(expected)),
        "expected accepted Event ids {array} to contain {expected}"
    );
}
