use anyhow::{Context, Result};
use arkret_bootstrap::{
    DID_INCEPTION_REF_ROLE, SelfPrincipalPcrCreateInput, build_self_principal_pcr_create,
    self_principal_bootstrap_submit_request,
};
use arkret_canonical::multibase::ed25519_pubkey_to_did_key_multibase;
use arkret_canonical::{canonical_json_bytes, canonical_sha256};
use arkret_identifiers::{DeviceId, Did, EventId, Hlc, RealmId};
use arkret_models_crypto::{AlgorithmKeyRecords, KeyOperationSignature, KeysUploadRequestBody};
use arkret_models_identity::did_document::principal_control_realm_id;
use arkret_signatures::webvh::{
    PreparedPrincipalInception, PrincipalEnrollmentDelegation, PrincipalInceptionInput,
    prepare_principal_inception,
};
use arkret_wire::{
    AuthorizationLeaseIssueOutcome, AuthorizationLeaseIssueRequest, Base64UrlString, Event,
    EventInitialSubmission, EventRef, NonEmptyString,
};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signer, SigningKey};
use reqwest::StatusCode;
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use url::Url;

use crate::harness::{ArkretServer, expect_json};

pub(crate) const TEST_PRINCIPAL_SIGNING_KEY_SEED: [u8; 32] = [0x51; 32];
const PCR_CREATE_EVENT_ID: &str = "ak:event:01904100-0000-7000-8000-fedc00000a10";
const DEVICE_AUTHORIZE_EVENT_ID: &str = "ak:event:01904100-0000-7000-8000-fedc00000a11";

fn registry_digest() -> arkret_identifiers::Hash {
    arkret::current_capability_action_registry_digest()
        .expect("embedded capability-action registry")
}

fn test_self_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[0x52; 32])
}

fn test_principal_signing_key() -> SigningKey {
    SigningKey::from_bytes(&TEST_PRINCIPAL_SIGNING_KEY_SEED)
}

async fn install_test_principal_control_document(server: &ArkretServer, actor: &str) -> Result<()> {
    let psk_kid = format!("{actor}#cotest-principal-signing-key");
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
            .json(&json!({"did": actor})),
        StatusCode::OK,
    )
    .await?;
    anyhow::ensure!(
        resolved["did_document"]["verificationMethod"]
            .as_array()
            .is_some_and(|methods| methods.iter().any(|method| method["id"] == psk_kid)),
        "installed principal control key is absent from resolved DID document: {resolved}"
    );
    crate::harness::register_event_signing_identity(
        actor,
        TEST_PRINCIPAL_SIGNING_KEY_SEED,
        format!("{actor}#cotest-principal-signing-key"),
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
    let signing_input = keys_upload_signing_input(device_id, &one_time_keys, &fallback_keys)?;
    let signature = signing_key.sign(&signing_input);
    let device_public_key =
        ed25519_pubkey_to_did_key_multibase(&signing_key.verifying_key().to_bytes());
    Ok(KeysUploadRequestBody {
        device_id: DeviceId::new(device_id.to_owned()).context("invalid keys/upload device id")?,
        one_time_keys,
        fallback_keys,
        device_signature: KeyOperationSignature {
            kid: NonEmptyString::new(format!("did:key:{device_public_key}#{device_public_key}"))
                .unwrap(),
            alg: Some(NonEmptyString::new("EdDSA").unwrap()),
            sig: Base64UrlString::new(URL_SAFE_NO_PAD.encode(signature.to_bytes())).unwrap(),
        },
    })
}

fn signed_algorithm_key_records(
    actor: &str,
    records: Value,
    fallback: bool,
) -> Result<AlgorithmKeyRecords> {
    let Value::Object(records) = records else {
        anyhow::bail!("keys/upload key records must be an object");
    };
    let signing_key = test_self_signing_key();
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
                    "kid": format!("{actor}#ak_self_signing_v1"),
                    "alg": "EdDSA",
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

pub(crate) fn keys_upload_signing_input(
    device_id: &str,
    one_time_keys: &impl Serialize,
    fallback_keys: &impl Serialize,
) -> Result<Vec<u8>> {
    let body = json!({
        "device_id": device_id,
        "one_time_keys": one_time_keys,
        "fallback_keys": fallback_keys,
    });
    let canonical = canonical_json_bytes(&body)?;
    let mut input = b"ak.keys-upload-v1\n".to_vec();
    input.extend_from_slice(&canonical);
    Ok(input)
}
async fn bootstrap_test_device_authorization(
    server: &ArkretServer,
    token: &str,
    actor: &str,
    device_id: &str,
    device_signing_key: &SigningKey,
) -> Result<arkret_wire::FederatedDeviceSigningKeyEvidence> {
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

    let mut create = build_self_principal_pcr_create(
        SelfPrincipalPcrCreateInput {
            principal_id: principal.clone(),
            realm_id: realm_id.clone(),
            trust_domain: server.trust_domain().clone(),
            did_inception_ref: EventRef::new(prepared.version_id.clone(), DID_INCEPTION_REF_ROLE),
            capability_action_registry_digest: registry_digest(),
            event_id: EventId::new(PCR_CREATE_EVENT_ID.to_owned())?,
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

    let enrollment_method = format!("{actor}#cotest-device-enrollment-authority");
    let device_public_key =
        ed25519_pubkey_to_did_key_multibase(&device_signing_key.verifying_key().to_bytes());
    let payload = arkret_models_collaboration::events_payloads::device_identity::DeviceAuthorizePayload {
        principal_id: principal.clone(),
        device_id: DeviceId::new(device_id.to_owned())?,
        device_public_key: NonEmptyString::new(device_public_key.clone())
            .map_err(anyhow::Error::msg)?,
        hpke_key: NonEmptyString::new("z6LSCotestFederationHpkeKey").map_err(anyhow::Error::msg)?,
        algorithms: vec![
            NonEmptyString::new("ak.hpke_x25519_aead_chacha20poly1305.v1")
                .map_err(anyhow::Error::msg)?,
            NonEmptyString::new("ak.mls.v1").map_err(anyhow::Error::msg)?,
        ],
        device_key_algorithm: Some(NonEmptyString::new("EdDSA").map_err(anyhow::Error::msg)?),
        authorized_by: arkret_models_collaboration::events_payloads::device_identity::DeviceOrPrincipalRef::Did(principal.clone()),
        scopes: None,
        not_before: created_at,
        expires_at: None,
        device_signature: None,
        proof: None,
        cross_signing_binding: None,
        enrollment_authority_binding: Some(arkret_models_identity::artifacts_device_identity::DeviceEnrollmentAuthorityBinding {
            kind: arkret_models_identity::artifacts_device_identity::DeviceEnrollmentAuthorityBindingKind::ServiceAttested,
            authority_did: principal.clone(),
            authorization_ref: NonEmptyString::new(enrollment_method.clone())
                .map_err(anyhow::Error::msg)?,
        }),
        recovery_session_id: None,
    };
    let mut authorize = Event::new(
        arkret_wire::EventKind::DEVICE_AUTHORIZE,
        arkret_wire::ScopeRef::Realm { realm_id },
        principal.clone(),
        1,
        Hlc::new("01970e589d21-0001-a13f9c2e")?,
        serde_json::to_value(payload)?,
    )?;
    authorize.event_id = EventId::new(DEVICE_AUTHORIZE_EVENT_ID.to_owned())?;
    authorize.created_at = created_at;
    authorize.prev_refs = vec![create.event_id.clone()];
    authorize.executed_by = Some(principal.clone());
    authorize.authorization_ref = Some(enrollment_method.clone());
    let enrollment_seed: [u8; 32] =
        Sha256::digest(format!("cotest:webvh:enrollment:{host}:{local_id}").as_bytes()).into();
    let enrollment_method = crate::fixture_did_url(enrollment_method);
    let enrollment_signer = arkret_signatures::Ed25519PayloadSigner::from_did_key_seed(
        enrollment_seed,
        principal.clone(),
        enrollment_method.clone(),
    );
    arkret::signatures::sign_event(
        &mut authorize,
        &enrollment_signer,
        &enrollment_method,
        arkret::signatures::SignEventOptions::new().with_created_at(created_at),
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

    let request = self_principal_bootstrap_submit_request(
        EventInitialSubmission {
            event: create,
            authorization_lease: create_lease.clone(),
            cba_proof_bundles: Vec::new(),
            control_proposal_receipt: None,
        },
        EventInitialSubmission {
            event: authorize.clone(),
            authorization_lease: authorize_lease.clone(),
            cba_proof_bundles: Vec::new(),
            control_proposal_receipt: None,
        },
        &crate::publication::project_cells,
    )?;
    let accepted = expect_json(
        server
            .http()
            .post(server.url("/_arkret/self/events"))
            .bearer_auth(token)
            .json(&request),
        StatusCode::OK,
    )
    .await?;
    assert_json_array_contains(&accepted["accepted"], PCR_CREATE_EVENT_ID, &accepted);
    assert_json_array_contains(&accepted["accepted"], DEVICE_AUTHORIZE_EVENT_ID, &accepted);

    Ok(arkret_wire::FederatedDeviceSigningKeyEvidence {
        actor_id: principal,
        device_id: DeviceId::new(device_id.to_owned())?,
        verification_method: crate::fixture_did_url(format!("{actor}#{device_id}")),
        device_signing_key: arkret_wire::DidKey::new(format!("did:key:{device_public_key}"))
            .map_err(anyhow::Error::msg)?,
        authorization_accepted_at: chrono::Utc::now(),
        device_authorize_event: Box::new(authorize),
    })
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
    let enrollment_seed: [u8; 32] =
        Sha256::digest(format!("cotest:webvh:enrollment:{host}:{local_id}").as_bytes()).into();
    let next_root = SigningKey::from_bytes(&next_root_seed);
    let enrollment = SigningKey::from_bytes(&enrollment_seed);
    let next_root_multibase =
        ed25519_pubkey_to_did_key_multibase(&next_root.verifying_key().to_bytes());
    let principal_signing_multibase = ed25519_pubkey_to_did_key_multibase(
        &test_principal_signing_key().verifying_key().to_bytes(),
    );
    let enrollment_multibase =
        ed25519_pubkey_to_did_key_multibase(&enrollment.verifying_key().to_bytes());
    prepare_principal_inception(&PrincipalInceptionInput {
        principal_endpoint: &endpoint,
        local_id,
        also_known_as: &[],
        version_time: chrono::DateTime::parse_from_rfc3339("2026-05-01T00:00:00.000Z")?
            .with_timezone(&chrono::Utc),
        root_seed: &root_seed,
        next_root_public_key_multibase: &next_root_multibase,
        enrollment: PrincipalEnrollmentDelegation::SelfAuthority {
            principal_signing_public_key_multibase: &principal_signing_multibase,
            enrollment_public_key_multibase: &enrollment_multibase,
            principal_signing_fragment: Some("cotest-principal-signing-key"),
            enrollment_fragment: Some("cotest-device-enrollment-authority"),
        },
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
fn assert_json_array_contains(array: &Value, expected: &str, context: &Value) {
    assert!(
        array
            .as_array()
            .unwrap()
            .iter()
            .any(|value| value.as_str() == Some(expected)),
        "expected {array} to contain {expected}; response: {context}"
    );
}
