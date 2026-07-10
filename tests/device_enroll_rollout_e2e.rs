use anyhow::{Context, Result, anyhow};
use arkret_core::canonical::canonical_json_bytes;
use arkret_core::{
    ed25519_pubkey_to_did_key_multibase, encode_base58btc, encode_multibase_base58btc,
};
use cotest::harness::{
    ArkretServer, dev_login, expect_api_error, expect_json, refresh_event_proof,
};
use ed25519_dalek::{Signer, SigningKey};
use reqwest::StatusCode;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use url::Url;

const WEBVH_BEARER: &str = "cotest-webvh-enroll-rollout";
const WEBVH_SCID_PLACEHOLDER: &str = "{SCID}";
const WEBVH_METHOD_VERSION: &str = "did:webvh:1.0";

#[tokio::test(flavor = "multi_thread")]
async fn device_enroll_service_attested_event_live_e2e() -> Result<()> {
    let server = ArkretServer::spawn_with_env(
        "device-enroll-rollout",
        &[("SOLAND_EMBEDDED_WEBVH_REGISTRATION_BEARER", WEBVH_BEARER)],
    )
    .await?;

    let authority = did_key_authority([17u8; 32]);
    let registered =
        register_webvh_principal(&server, "alice-enroll-rollout", &authority.did).await?;
    let principal_id = registered["did"]
        .as_str()
        .context("webvh registration response did")?;
    let authorization_ref = format!("{principal_id}#enrollment-authority");
    assert_enrollment_authority_service(&registered, &authorization_ref, &authority.did)?;

    let session_device = "ak:device:01904100-0000-7000-8000-00000000e100";
    let token = dev_login(&server, principal_id, session_device).await?;
    let enrolled_device = "ak:device:01904100-0000-7000-8000-00000000e101";
    let enrolled_device_key = SigningKey::from_bytes(&[41u8; 32]);
    let enrolled_device_public_key = multibase_public_key(&enrolled_device_key);

    let event = service_attested_device_authorize_event(
        principal_id,
        &authority.did,
        &authority.verification_method,
        &authorization_ref,
        enrolled_device,
        &enrolled_device_public_key,
        1,
        "ak:event:01904100-0000-7000-8000-00000000e101",
    )?;
    let accepted = expect_json(
        server
            .http()
            .post(server.url("/_arkret/self/events"))
            .bearer_auth(&token)
            .json(&event),
        StatusCode::OK,
    )
    .await?;
    assert_accepted_event(&accepted, "ak:event:01904100-0000-7000-8000-00000000e101")?;

    let query = expect_json(
        server
            .http()
            .post(server.url("/_arkret/self/keys/query"))
            .bearer_auth(&token)
            .json(&json!({
                "device_keys": {
                    principal_id: [enrolled_device]
                }
            })),
        StatusCode::OK,
    )
    .await?;
    let entry = &query["device_keys"][principal_id][enrolled_device];
    assert_eq!(entry["device_status"], "active", "keys/query: {query}");
    assert_eq!(
        entry["device_signing_key"],
        format!("did:key:{enrolled_device_public_key}"),
        "keys/query: {query}"
    );

    let imposter = did_key_authority([18u8; 32]);
    let rejected_event = service_attested_device_authorize_event(
        principal_id,
        &imposter.did,
        &imposter.verification_method,
        &authorization_ref,
        "ak:device:01904100-0000-7000-8000-00000000e102",
        &multibase_public_key(&SigningKey::from_bytes(&[42u8; 32])),
        2,
        "ak:event:01904100-0000-7000-8000-00000000e102",
    )?;
    expect_api_error(
        server
            .http()
            .post(server.url("/_arkret/self/events"))
            .bearer_auth(&token)
            .json(&rejected_event),
        StatusCode::FORBIDDEN,
        "device_enrollment_authority_not_designated",
    )
    .await?;

    Ok(())
}

struct DidKeyAuthority {
    did: String,
    verification_method: String,
}

fn did_key_authority(seed: [u8; 32]) -> DidKeyAuthority {
    let signing = SigningKey::from_bytes(&seed);
    let multibase = multibase_public_key(&signing);
    let did = format!("did:key:{multibase}");
    let verification_method = format!("{did}#{multibase}");
    DidKeyAuthority {
        did,
        verification_method,
    }
}

fn multibase_public_key(signing_key: &SigningKey) -> String {
    ed25519_pubkey_to_did_key_multibase(&signing_key.verifying_key().to_bytes())
}

async fn register_webvh_principal(
    server: &ArkretServer,
    local_id: &str,
    authority_did: &str,
) -> Result<Value> {
    let did_signing = SigningKey::from_bytes(&[31u8; 32]);
    let update_signing = SigningKey::from_bytes(&[32u8; 32]);
    let body = webvh_registration_body(
        &server.base_url(),
        local_id,
        &did_signing,
        &update_signing,
        authority_did,
    )?;
    expect_json(
        server
            .http()
            .post(server.url("/_soland/root/identity/webvh/register"))
            .bearer_auth(WEBVH_BEARER)
            .json(&body),
        StatusCode::CREATED,
    )
    .await
}

fn webvh_registration_body(
    endpoint: &Url,
    local_id: &str,
    did_signing: &SigningKey,
    update_signing: &SigningKey,
    authority_did: &str,
) -> Result<Value> {
    let (method_authority, _) = authority_pair(endpoint)?;
    let did_public_key_multibase = multibase_public_key(did_signing);
    let update_public_key_multibase = multibase_public_key(update_signing);
    let service_endpoint = endpoint.as_str().trim_end_matches('/').to_owned();
    let version_time = "2026-06-17T00:00:00Z";
    let placeholder_did = format_webvh_did(&method_authority, WEBVH_SCID_PLACEHOLDER, local_id);
    let placeholder_key_id = format!("{placeholder_did}#did-key-1");
    let document_skeleton = webvh_document_value(
        &placeholder_did,
        &placeholder_key_id,
        &did_public_key_multibase,
        local_id,
        &service_endpoint,
        authority_did,
    );
    let entry_skeleton = json!({
        "versionId": format!("0-{WEBVH_SCID_PLACEHOLDER}"),
        "versionTime": version_time,
        "parameters": {
            "scid": WEBVH_SCID_PLACEHOLDER,
            "method": WEBVH_METHOD_VERSION,
            "updateKeys": [update_public_key_multibase.clone()],
        },
        "state": document_skeleton,
    });
    let scid = sha256_multihash_multibase(&canonical_bytes(&entry_skeleton)?);
    let mut log_entry = substitute_scid(&entry_skeleton, &scid)?;
    let version_hash = sha256_multihash_multibase(&canonical_bytes(&strip_for_hash(&log_entry))?);
    if let Value::Object(map) = &mut log_entry {
        map.insert(
            "versionId".to_owned(),
            Value::String(format!("1-{version_hash}")),
        );
    }
    let proof = webvh_log_proof(&log_entry, update_signing, &update_public_key_multibase)?;

    Ok(json!({
        "local_id": local_id,
        "did_public_key_multibase": did_public_key_multibase,
        "update_public_key_multibase": update_public_key_multibase,
        "did_key_id": "did-key-1",
        "update_key_id": "update-key-1",
        "also_known_as": [format!("acct:{local_id}@example.com")],
        "version_time": version_time,
        "device_enrollment_authority_did": authority_did,
        "proof": proof,
    }))
}

fn authority_pair(endpoint: &Url) -> Result<(String, String)> {
    let host = endpoint.host_str().context("endpoint host")?;
    let method_authority = match endpoint.port() {
        Some(port) => format!("{host}%3A{port}"),
        None => host.to_owned(),
    };
    let https_authority = match endpoint.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_owned(),
    };
    Ok((method_authority, https_authority))
}

fn webvh_document_value(
    did: &str,
    did_key_id: &str,
    did_public_key_multibase: &str,
    local_id: &str,
    service_endpoint: &str,
    authority_did: &str,
) -> Value {
    json!({
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": did,
        "verificationMethod": [{
            "id": did_key_id,
            "type": "Multikey",
            "controller": did,
            "publicKeyMultibase": did_public_key_multibase,
        }],
        "authentication": [did_key_id],
        "assertionMethod": [did_key_id],
        "alsoKnownAs": [format!("acct:{local_id}@example.com")],
        "service": [
            {
                "id": format!("{did}#soland"),
                "type": "ArkretPrincipalServer",
                "serviceEndpoint": service_endpoint,
            },
            {
                "id": format!("{did}#enrollment-authority"),
                "type": arkret_core::service::DID_SERVICE_DEVICE_ENROLLMENT_AUTHORITY,
                "serviceEndpoint": authority_did,
            },
        ],
    })
}

fn webvh_log_proof(
    log_entry: &Value,
    update_signing: &SigningKey,
    update_public_key_multibase: &str,
) -> Result<Value> {
    let payload = canonical_bytes(log_entry)?;
    let signature = update_signing.sign(&payload);
    Ok(json!({
        "type": "DataIntegrityProof",
        "cryptosuite": "eddsa-jcs-2022",
        "verificationMethod": format!("did:key:{update_public_key_multibase}#{update_public_key_multibase}"),
        "proofPurpose": "assertionMethod",
        "proofValue": format!("z{}", encode_base58btc(signature.to_bytes())),
    }))
}

fn canonical_bytes(value: &Value) -> Result<Vec<u8>> {
    canonical_json_bytes(value).map_err(|error| anyhow!("{error}"))
}

fn strip_for_hash(value: &Value) -> Value {
    let mut clone = value.clone();
    if let Value::Object(map) = &mut clone {
        map.remove("proof");
        map.remove("versionId");
    }
    clone
}

fn substitute_scid(value: &Value, scid: &str) -> Result<Value> {
    let text = serde_json::to_string(value)?;
    Ok(serde_json::from_str(
        &text.replace(WEBVH_SCID_PLACEHOLDER, scid),
    )?)
}

fn sha256_multihash_multibase(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut multihash = Vec::with_capacity(34);
    multihash.push(0x12);
    multihash.push(0x20);
    multihash.extend_from_slice(&digest);
    encode_multibase_base58btc(multihash)
}

fn format_webvh_did(method_authority: &str, scid: &str, local_id: &str) -> String {
    format!("did:webvh:{scid}:{method_authority}:webvh:{local_id}")
}

fn service_attested_device_authorize_event(
    principal_id: &str,
    authority_did: &str,
    authority_verification_method: &str,
    authorization_ref: &str,
    device_id: &str,
    device_public_key: &str,
    actor_seq: u64,
    event_id: &str,
) -> Result<Value> {
    let principal = arkret::Did::new(principal_id.to_owned())
        .map_err(|error| anyhow!("invalid principal DID: {error}"))?;
    let realm_id = arkret_core::principal_control_realm_id(&principal);
    // Typed wire payload: device-lifecycle.md §5.4 — the enrollment authority
    // attests the device verify key, HPKE sealing key AND the canonical
    // algorithm set. Built on the SDK counterpart so schema drift fails here.
    let authority = arkret_core::Did::new(authority_did.to_owned())
        .map_err(|error| anyhow!("invalid authority DID: {error}"))?;
    let payload = arkret_core::DeviceAuthorizePayload {
        principal_id: arkret_core::Did::new(principal_id.to_owned())
            .map_err(|error| anyhow!("invalid principal DID: {error}"))?,
        device_id: device_id.to_owned(),
        device_public_key: device_public_key.to_owned(),
        hpke_key: "z6LSCotestEnrollHpkeKey".to_owned(),
        algorithms: vec![
            "ak.hpke_x25519_aead_chacha20poly1305.v1".to_owned(),
            "ak.mls.v1".to_owned(),
        ],
        device_key_algorithm: None,
        authorized_by: arkret_core::DeviceOrPrincipalRef::Did(authority.clone()),
        scopes: None,
        not_before: "2026-06-17T00:00:00Z"
            .parse()
            .expect("static timestamp parses"),
        expires_at: None,
        device_signature: None,
        proof: None,
        cross_signing_binding: None,
        bootstrap_binding: None,
        enrollment_authority_binding: Some(arkret_core::DeviceEnrollmentAuthorityBinding {
            kind: arkret_core::DeviceEnrollmentAuthorityBinding::KIND_SERVICE_ATTESTED.to_owned(),
            authority_did: authority,
            authorization_ref: authorization_ref.to_owned(),
        }),
        recovery_session_id: None,
    };
    let payload = serde_json::to_value(&payload)?;
    let mut event = json!({
        "event_id": event_id,
        "kind": "ak.device.authorize",
        "realm_id": realm_id,
        "actor_id": principal_id,
        "actor_seq": actor_seq,
        "created_at": "2026-06-17T00:00:00Z",
        "hlc": format!("01970e589d21-{actor_seq:04x}-a13f9c2e"),
        "prev_refs": [],
        "refs": [],
        "executed_by": authority_did,
        "authorization_ref": authorization_ref,
        "payload": payload,
        "proofs": [{
            "kind": "detached_jws",
            "alg": "EdDSA",
            "verification_method": authority_verification_method,
            "event_digest": "",
            "created_at": "2026-06-17T00:00:00Z",
            "jws": "placeholder"
        }],
    });
    refresh_event_proof(&mut event);
    Ok(event)
}

fn assert_accepted_event(body: &Value, event_id: &str) -> Result<()> {
    let accepted = body["accepted"]
        .as_array()
        .context("events submit accepted array")?;
    if accepted.iter().any(|item| item.as_str() == Some(event_id)) {
        Ok(())
    } else {
        Err(anyhow!("event {event_id} was not accepted: {body}"))
    }
}

fn assert_enrollment_authority_service(
    registered: &Value,
    expected_service_id: &str,
    expected_authority_did: &str,
) -> Result<()> {
    let services = registered["did_document"]["service"]
        .as_array()
        .context("registered did_document.service")?;
    let service = services
        .iter()
        .find(|service| {
            service.get("type").and_then(Value::as_str)
                == Some(arkret_core::service::DID_SERVICE_DEVICE_ENROLLMENT_AUTHORITY)
        })
        .context("ArkretDeviceEnrollmentAuthority service")?;
    assert_eq!(
        service.get("id").and_then(Value::as_str),
        Some(expected_service_id)
    );
    assert_eq!(
        service.get("serviceEndpoint").and_then(Value::as_str),
        Some(expected_authority_did)
    );
    Ok(())
}
