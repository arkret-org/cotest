use anyhow::{Context, Result, anyhow};
use arkret::webvh::{
    PreparedPrincipalInception, PrincipalEnrollmentDelegation, PrincipalInceptionInput,
    prepare_principal_inception,
};
use arkret_bootstrap::{
    DID_INCEPTION_REF_ROLE, SelfPrincipalPcrCreateInput, build_self_principal_pcr_create,
    self_principal_bootstrap_submit_request,
};
use arkret_canonical::multibase::ed25519_pubkey_to_did_key_multibase;
use arkret_identifiers::{Did, EventId, Hlc, RealmId, TypedTrustDomainId};
use arkret_models_collaboration::http_bodies::EventsSubmitRequestBody;
use arkret_signatures::{Ed25519MoveSigner, SignEventOptions, sign_event};
use arkret_wire::{Event, EventRef};
use cotest::harness::{ArkretServer, dev_login, expect_api_error, expect_json};
use ed25519_dalek::SigningKey;
use reqwest::StatusCode;
use serde_json::{Value, json};

#[tokio::test(flavor = "multi_thread")]
async fn device_enroll_service_attested_event_live_e2e() -> Result<()> {
    let server = ArkretServer::spawn("device-enroll-rollout").await?;

    let authority = did_key_authority([17_u8; 32]);
    let registered =
        register_webvh_principal(&server, "alice-enroll-rollout", &authority.did).await?;
    let principal_id = registered.prepared.did.as_str();
    let authorization_ref = format!("{principal_id}#enrollment-authority");
    assert_enrollment_authority_service(
        &registered.did_document,
        &authorization_ref,
        &authority.did,
    )?;

    let enrolled_device = "ak:device:01904100-0000-7000-8000-00000000e101";
    let token = dev_login(&server, principal_id, enrolled_device).await?;
    let enrolled_device_key = SigningKey::from_bytes(&[41_u8; 32]);
    let enrolled_device_public_key = multibase_public_key(&enrolled_device_key);
    let bootstrap = principal_bootstrap_request(
        &registered.prepared,
        &authority,
        &authorization_ref,
        enrolled_device,
        &enrolled_device_public_key,
    )?;
    let create = bootstrap.events[0].clone();
    let authorize = bootstrap.events[1].clone();

    // The identity-root genesis can never be stored by itself.
    expect_api_error(
        server
            .http()
            .post(server.url("/_arkret/self/events"))
            .bearer_auth(&token)
            .json(&create),
        StatusCode::PRECONDITION_FAILED,
        "failed_precondition",
    )
    .await?;

    // Nor may the authority half be submitted alone to trigger the legacy
    // implicit-PCR path.
    expect_api_error(
        server
            .http()
            .post(server.url("/_arkret/self/events"))
            .bearer_auth(&token)
            .json(&authorize),
        StatusCode::CONFLICT,
        "dependency_missing",
    )
    .await?;

    // Slot 1 must reference exactly the slot-0 genesis Event.
    let mut missing_predecessor = authorize.clone();
    missing_predecessor.prev_refs.clear();
    expect_api_error(
        server
            .http()
            .post(server.url("/_arkret/self/events"))
            .bearer_auth(&token)
            .json(&EventsSubmitRequestBody {
                event: None,
                events: vec![create.clone(), missing_predecessor],
            }),
        StatusCode::BAD_REQUEST,
        "schema_violation",
    )
    .await?;

    let mut extra_predecessor = authorize.clone();
    extra_predecessor.prev_refs.push(EventId::new(
        "ak:event:01904100-0000-7000-8000-00000000e199",
    )?);
    expect_api_error(
        server
            .http()
            .post(server.url("/_arkret/self/events"))
            .bearer_auth(&token)
            .json(&EventsSubmitRequestBody {
                event: None,
                events: vec![create.clone(), extra_predecessor],
            }),
        StatusCode::BAD_REQUEST,
        "schema_violation",
    )
    .await?;

    let accepted = expect_json(
        server
            .http()
            .post(server.url("/_arkret/self/events"))
            .bearer_auth(&token)
            .json(&bootstrap),
        StatusCode::OK,
    )
    .await?;
    assert_accepted_event(&accepted, create.event_id.as_str())?;
    assert_accepted_event(&accepted, authorize.event_id.as_str())?;

    // A response can be lost after commit. Byte-identical retry must resolve
    // to the already accepted closed unit rather than duplicating either slot.
    let retried = expect_json(
        server
            .http()
            .post(server.url("/_arkret/self/events"))
            .bearer_auth(&token)
            .json(&bootstrap),
        StatusCode::OK,
    )
    .await?;
    assert_accepted_event(&retried, create.event_id.as_str())?;
    assert_accepted_event(&retried, authorize.event_id.as_str())?;

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

    let imposter = did_key_authority([18_u8; 32]);
    let rejected_event = service_attested_device_authorize_event(
        principal_id,
        &imposter,
        &authorization_ref,
        "ak:device:01904100-0000-7000-8000-00000000e102",
        &multibase_public_key(&SigningKey::from_bytes(&[42_u8; 32])),
        2,
        "ak:event:01904100-0000-7000-8000-00000000e102",
        vec![authorize.event_id.clone()],
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

    let wrong_authorization_ref = format!("{principal_id}#other-enrollment-authority");
    let rejected_event = service_attested_device_authorize_event(
        principal_id,
        &authority,
        &wrong_authorization_ref,
        "ak:device:01904100-0000-7000-8000-00000000e103",
        &multibase_public_key(&SigningKey::from_bytes(&[43_u8; 32])),
        2,
        "ak:event:01904100-0000-7000-8000-00000000e103",
        vec![authorize.event_id],
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
    seed: [u8; 32],
    did: String,
    verification_method: String,
}

fn did_key_authority(seed: [u8; 32]) -> DidKeyAuthority {
    let signing = SigningKey::from_bytes(&seed);
    let multibase = multibase_public_key(&signing);
    let did = format!("did:key:{multibase}");
    let verification_method = format!("{did}#{multibase}");
    DidKeyAuthority {
        seed,
        did,
        verification_method,
    }
}

fn multibase_public_key(signing_key: &SigningKey) -> String {
    ed25519_pubkey_to_did_key_multibase(&signing_key.verifying_key().to_bytes())
}

struct RegisteredPrincipal {
    prepared: PreparedPrincipalInception,
    did_document: Value,
}

async fn register_webvh_principal(
    server: &ArkretServer,
    local_id: &str,
    authority_did: &str,
) -> Result<RegisteredPrincipal> {
    let root_seed = [32_u8; 32];
    let next_root = SigningKey::from_bytes(&[33_u8; 32]);
    let next_root_public_key_multibase = multibase_public_key(&next_root);
    let also_known_as = vec![format!("acct:{local_id}@example.com")];
    let version_time: chrono::DateTime<chrono::Utc> = "2026-06-17T00:00:00.000Z".parse()?;
    let prepared = prepare_principal_inception(&PrincipalInceptionInput {
        principal_endpoint: &server.base_url(),
        local_id,
        also_known_as: &also_known_as,
        version_time,
        root_seed: &root_seed,
        next_root_public_key_multibase: &next_root_public_key_multibase,
        enrollment: PrincipalEnrollmentDelegation::ExternalAuthority { authority_did },
    })?;
    let submitted = expect_json(
        server
            .http()
            .post(server.url("/_arkret/root/identity/submit-did-operation"))
            .json(&prepared.submit_body),
        StatusCode::OK,
    )
    .await?;
    if submitted["did"].as_str() != Some(prepared.did.as_str()) {
        return Err(anyhow!("DID submit outcome drifted: {submitted}"));
    }
    let resolved = expect_json(
        server
            .http()
            .post(server.url("/_arkret/root/identity/resolve"))
            .json(&json!({"did": prepared.did})),
        StatusCode::OK,
    )
    .await?;
    Ok(RegisteredPrincipal {
        prepared,
        did_document: resolved["did_document"].clone(),
    })
}

fn principal_bootstrap_request(
    prepared: &PreparedPrincipalInception,
    authority: &DidKeyAuthority,
    authorization_ref: &str,
    device_id: &str,
    device_public_key: &str,
) -> Result<EventsSubmitRequestBody> {
    let principal = Did::new(prepared.did.clone())?;
    let realm_id =
        RealmId::new(arkret_models_identity::did_document::principal_control_realm_id(&principal))?;
    let created_at = "2026-06-17T00:00:00.000Z".parse()?;
    let mut create = build_self_principal_pcr_create(SelfPrincipalPcrCreateInput {
        principal_id: principal.clone(),
        realm_id,
        trust_domain: TypedTrustDomainId::new("ak:trust_domain:soland.local")?,
        did_inception_ref: EventRef::new(prepared.version_id.clone(), DID_INCEPTION_REF_ROLE),
        event_id: EventId::new("ak:event:01904100-0000-7000-8000-00000000e100")?,
        created_at,
        hlc: Hlc::new("01970e589d21-0000-a13f9c2e")?,
    })?;
    let root_did = Did::new(format!("did:key:{}", prepared.root_public_key_multibase))?;
    let root_signer = Ed25519MoveSigner::from_did_key_seed(
        [32_u8; 32],
        root_did,
        prepared.root_verification_method.clone(),
    );
    sign_event(
        &mut create,
        &root_signer,
        &prepared.root_verification_method,
        SignEventOptions::new().with_created_at(created_at),
    )?;

    let authorize = service_attested_device_authorize_event(
        principal.as_str(),
        authority,
        authorization_ref,
        device_id,
        device_public_key,
        1,
        "ak:event:01904100-0000-7000-8000-00000000e101",
        vec![create.event_id.clone()],
    )?;
    Ok(self_principal_bootstrap_submit_request(create, authorize)?)
}

#[allow(clippy::too_many_arguments)]
fn service_attested_device_authorize_event(
    principal_id: &str,
    authority: &DidKeyAuthority,
    authorization_ref: &str,
    device_id: &str,
    device_public_key: &str,
    actor_seq: u64,
    event_id: &str,
    prev_refs: Vec<EventId>,
) -> Result<Event> {
    let principal = Did::new(principal_id.to_owned())?;
    let realm_id = arkret_models_identity::did_document::principal_control_realm_id(&principal);
    let authority_did = Did::new(authority.did.clone())?;
    let payload = arkret_models_collaboration::events_payloads::device_identity::DeviceAuthorizePayload {
        principal_id: principal.clone(),
        device_id: arkret_identifiers::DeviceId::new(device_id.to_owned())?,
        device_public_key: non_empty(device_public_key)?,
        hpke_key: non_empty("z6LSCotestEnrollHpkeKey")?,
        algorithms: vec![
            non_empty("ak.hpke_x25519_aead_chacha20poly1305.v1")?,
            non_empty("ak.mls.v1")?,
        ],
        device_key_algorithm: Some(non_empty("EdDSA")?),
        authorized_by: arkret_models_collaboration::events_payloads::device_identity::DeviceOrPrincipalRef::Did(authority_did.clone()),
        scopes: None,
        not_before: "2026-06-17T00:00:00.000Z".parse()?,
        expires_at: None,
        device_signature: None,
        proof: None,
        cross_signing_binding: None,
        enrollment_authority_binding: Some(arkret_models_identity::artifacts_device_identity::DeviceEnrollmentAuthorityBinding {
            kind: arkret_models_identity::artifacts_device_identity::DeviceEnrollmentAuthorityBindingKind::ServiceAttested,
            authority_did: authority_did.clone(),
            authorization_ref: non_empty(authorization_ref)?,
        }),
        recovery_session_id: None,
    };
    let created_at = "2026-06-17T00:00:00.000Z".parse()?;
    let mut event = Event::new(
        arkret_wire::events::EventKind::DEVICE_AUTHORIZE,
        RealmId::new(realm_id)?,
        principal,
        actor_seq,
        Hlc::new(format!("01970e589d21-{actor_seq:04x}-a13f9c2e"))?,
        serde_json::to_value(payload)?,
    )?;
    event.event_id = EventId::new(event_id)?;
    event.created_at = created_at;
    event.prev_refs = prev_refs;
    event.executed_by = Some(authority_did.clone());
    event.authorization_ref = Some(authorization_ref.to_owned());
    let authority_signer = Ed25519MoveSigner::from_did_key_seed(
        authority.seed,
        authority_did,
        authority.verification_method.clone(),
    );
    sign_event(
        &mut event,
        &authority_signer,
        &authority.verification_method,
        SignEventOptions::new().with_created_at(created_at),
    )?;
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
    did_document: &Value,
    expected_service_id: &str,
    expected_authority_did: &str,
) -> Result<()> {
    let services = did_document["service"]
        .as_array()
        .context("registered did_document.service")?;
    let service = services
        .iter()
        .find(|service| {
            service.get("type").and_then(Value::as_str)
                == Some(arkret_models_discovery::service_requirements::DID_SERVICE_DEVICE_ENROLLMENT_AUTHORITY)
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

fn non_empty(value: impl Into<String>) -> Result<arkret_wire::NonEmptyString> {
    arkret_wire::NonEmptyString::new(value).map_err(anyhow::Error::msg)
}
