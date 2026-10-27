//! An admitted holder may persist a disabled-route tombstone without inventing a gateway.
use arkret_wire::{ActorPrivateEventSubmitRequestBody, ActorPrivateEventSubmitResponseBody};

use super::*;
use crate::harness::{ArkretServer, TestActorClient, expect_json};

async fn durable(database: &str, event: &arkret_wire::Event) -> Result<Value> {
    let database = database.to_owned();
    let id = event.event_id.to_string();
    tokio::task::spawn_blocking(move || ->Result<Value> {
        let mut db=postgres::Client::connect(&database,postgres::NoTls)?;
        let row=db.query_one("SELECT to_jsonb(e),to_jsonb(r),(SELECT count(*) FROM canonical_events WHERE envelope->>'event_id'=$1),(SELECT count(*) FROM realm_commits WHERE commit_json->>'event_ref'=$1) FROM actor_private_events e JOIN device_push_routes r ON r.accepted_event_id=e.event_id WHERE e.event_id=$1",&[&id])?;
        Ok(json!({"event_original":row.get::<_,Value>(0),"route":row.get::<_,Value>(1),"shared_events":row.get::<_,i64>(2),"realm_commits":row.get::<_,i64>(3)}))
    }).await?
}

pub(super) async fn exercise(
    station: &ArkretServer,
    client: &TestActorClient,
    account: &arkret_wire::AccountId,
) -> Result<Value> {
    let principal = client
        .principal
        .as_ref()
        .context("actual admitted device custody")?;
    let route = arkret_identifiers::new_prefixed_uuid7("native-disabled-route:");
    let payload = arkret_models_identity::device_push_route::DevicePushRoutePayload::Revoked(
        arkret_models_identity::device_push_route::DevicePushRouteRevokedPayload {
            account_id: account.clone(),
            device_id: principal.device_id.clone(),
            push_route: route,
            expected_server_revision: 0,
            revoked: Default::default(),
            updated_at: None,
        },
    );
    let event = client
        .author_event(
            principal.pcr_realm_id.as_str(),
            arkret_wire::EventKind::DevicePushRoute.as_str(),
            json!(payload),
        )
        .await?;
    let request = ActorPrivateEventSubmitRequestBody {
        event: event.clone(),
    };
    request.validate()?;
    let send = || {
        client
            .post("/_arkret/self/actor-private-events")
            .json(&request)
    };
    let response: ActorPrivateEventSubmitResponseBody =
        serde_json::from_value(expect_json(send(), reqwest::StatusCode::OK).await?)?;
    response.validate_for_request(&request)?;
    ensure!(
        matches!(
            &response,
            ActorPrivateEventSubmitResponseBody::DevicePushRoute { revision: 1, .. }
        ),
        "first native tombstone did not advance its actual CAS high-water"
    );
    let database = station
        .owned_database_url()
        .context("native private storage")?;
    let original = durable(database, &event).await?;
    let replay: ActorPrivateEventSubmitResponseBody =
        serde_json::from_value(expect_json(send(), reqwest::StatusCode::OK).await?)?;
    let after = durable(database, &event).await?;
    ensure!(
        replay == response && after == original,
        "private Event retry rewrote its accepted original or incremented revision"
    );
    ensure!(
        original["event_original"]["envelope"] == json!(event)
            && original["event_original"]["outcome"] == json!(response)
            && original["route"]["route_value"] == json!(payload)
            && original["route"]["revoked"] == true
            && original["route"]["revision"] == 1
            && original["shared_events"] == 0
            && original["realm_commits"] == 0,
        "private tombstone is absent, changed, or leaked into shared history"
    );
    let authorization = crate::scenarios::mls_lifecycle_live::accepted_full_view(
        client,
        &principal.founding_authorize_event_id,
    )
    .await?;
    Ok(
        json!({"request":request,"response":response,"replay":replay,"original":original,"after":after,"device_authorization":authorization}),
    )
}

pub(super) fn verify(observations: &NativeOperationObservations, evidence: &Value) -> Result<()> {
    let request: ActorPrivateEventSubmitRequestBody =
        serde_json::from_value(evidence["request"].clone())?;
    let response: ActorPrivateEventSubmitResponseBody =
        serde_json::from_value(evidence["response"].clone())?;
    response.validate_for_request(&request)?;
    let authorization: arkret_wire::CommittedEventFullView =
        serde_json::from_value(evidence["device_authorization"].clone())?;
    verify_native_pcr_commits(observations, &[authorization.clone()])?;
    let device:arkret_models_collaboration::events_payloads::device_identity::DeviceAuthorizePayload=serde_json::from_value(json!(authorization.event.payload))?;
    let proof = request
        .event
        .producer_proof
        .as_ref()
        .context("actual private Event proof")?;
    request
        .event
        .verify_producer_proof_self_consistency(arkret_canonical::DigestSuite::Sha256)?;
    let key = arkret_signatures::PublicKeyMaterial::Ed25519Multibase {
        value: device
            .device_public_key_did
            .as_str()
            .strip_prefix("did:key:")
            .context("accepted device public key")?
            .to_owned(),
    };
    arkret_signatures::Ed25519DetachedJwsVerifier::new().verify_detached_jws(
        &proof.jws,
        &proof.canonical_binding_bytes(&request.event.actor_id)?,
        &key,
    )?;
    ensure!(
        request.event.actor_id == authorization.event.actor_id
            && request.event.realm_id == authorization.event.realm_id
            && proof
                .verification_method
                .as_str()
                .ends_with(&format!("#{}", device.device_id)),
        "private Event has another accepted Account or device signer"
    );
    Ok(())
}
