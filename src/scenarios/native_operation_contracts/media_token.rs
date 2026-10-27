//! A native media ticket is verified against actual admitted Call and issuer state.
use arkret_models_collaboration::call_invitation::{
    CallMediaJoinContext, CallVoluntaryJoinContext, CallVoluntaryJoinKind, CallVoluntaryJoinProof,
};
use arkret_models_collaboration::objects::media::{
    CallMediaTokenExchangeRequestBody, CallMediaTokenExchangeResponseBody, MediaBackendToken,
};

use super::*;
use crate::harness::{ArkretServer, expect_json};
use crate::scenarios::mls_lifecycle_live::{self as mls, Member};

pub(super) async fn exercise(
    station: &ArkretServer,
    alice: &Member,
    realm: &arkret_wire::RealmId,
) -> Result<Value> {
    let grant = crate::scenarios::human_device_producer_live::grant_realm_actions(
        &alice.client,
        station,
        realm.as_str(),
        &alice.account,
        &["ak.call.join"],
    )
    .await?;
    let grant = mls::accepted_full_view(&alice.client, &grant.event_ref).await?;
    let focus_id = "native-media-contract";
    let descriptor=alice.client.author_event(realm.as_str(),arkret_wire::EventKind::RealmMediaService.as_str(),json!({"value":{"service_id":station.service_id(),"foci":[{"focus_id":focus_id,"focus_kind":"arkret_native","token_endpoint":station.base_url().join("/_arkret/self/rtc/token")?,"connect_url":station.base_url()}]}})).await?;
    crate::scenarios::human_device_producer_live::submit_and_expect_commit(
        &alice.client,
        &alice.account,
        alice.device.as_str(),
        &descriptor,
    )
    .await?;
    let descriptor = mls::accepted_full_view(&alice.client, &descriptor.event_id).await?;
    let call = alice
        .client
        .author_event(
            realm.as_str(),
            arkret_wire::EventKind::CallCreate.as_str(),
            json!({"initial_state":"connecting"}),
        )
        .await?;
    crate::scenarios::human_device_producer_live::submit_and_expect_commit(
        &alice.client,
        &alice.account,
        alice.device.as_str(),
        &call,
    )
    .await?;
    let call_id = arkret_wire::CallId::from_event_id(&call.event_id);
    let call = mls::accepted_full_view(&alice.client, &call.event_id).await?;
    let focus = alice
        .client
        .author_event(
            realm.as_str(),
            arkret_wire::EventKind::CallState.as_str(),
            json!({"call_id":call_id,"focus":{"mode":"sfu","session_focus":focus_id}}),
        )
        .await?;
    crate::scenarios::human_device_producer_live::submit_and_expect_commit(
        &alice.client,
        &alice.account,
        alice.device.as_str(),
        &focus,
    )
    .await?;
    let focus = mls::accepted_full_view(&alice.client, &focus.event_id).await?;
    let now = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let mut entropy = [0u8; 32];
    getrandom::fill(&mut entropy).context("native media voluntary intent entropy")?;
    let nonce = arkret_canonical::base64url_encode(entropy);
    let mut request = CallMediaTokenExchangeRequestBody {
        realm_id: realm.clone(),
        call_id,
        actor_id: alice.actor.clone(),
        device_id: alice.device.clone(),
        focus_id: focus_id.into(),
        capability_refs: Vec::new(),
        desired_media: None,
        join_context: CallMediaJoinContext::Voluntary(CallVoluntaryJoinContext {
            kind: CallVoluntaryJoinKind::Voluntary,
            created_at: now,
            expires_at: now + chrono::Duration::seconds(60),
            nonce: nonce.clone(),
            proof: CallVoluntaryJoinProof {
                verification_method: alice.method.to_string(),
                jws: String::new(),
            },
        }),
    };
    arkret_signatures::call_invitation::sign_call_voluntary_join(&mut request, &alice.key)?;
    let response: CallMediaTokenExchangeResponseBody = serde_json::from_value(
        expect_json(
            alice.client.post("/_arkret/self/rtc/token").json(&request),
            reqwest::StatusCode::OK,
        )
        .await?,
    )?;
    let verified_at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let database = station
        .owned_database_url()
        .context("native media nonce ledger")?
        .to_owned();
    let actor = json!(alice.actor);
    let device = alice.device.to_string();
    let original=tokio::task::spawn_blocking(move || ->Result<Value> {let mut db=postgres::Client::connect(&database,postgres::NoTls)?;let row=db.query_one("SELECT to_jsonb(n) FROM call_voluntary_join_nonces n WHERE subject_actor_id=$1 AND subject_device_id=$2 AND nonce=$3",&[&actor,&device,&nonce])?;Ok(row.get(0))}).await??;
    Ok(
        json!({"request":request,"response":response,"verified_at":arkret_canonical::format_timestamp_canonical(verified_at),"grant":grant,"descriptor":descriptor,"call":call,"focus":focus,"nonce_original":original}),
    )
}

pub(super) fn verify(observations: &NativeOperationObservations, evidence: &Value) -> Result<()> {
    use ed25519_dalek::Verifier as _;
    let request: CallMediaTokenExchangeRequestBody =
        serde_json::from_value(evidence["request"].clone())?;
    let response: CallMediaTokenExchangeResponseBody =
        serde_json::from_value(evidence["response"].clone())?;
    let views = ["grant", "descriptor", "call", "focus"]
        .into_iter()
        .map(|key| serde_json::from_value(evidence[key].clone()))
        .collect::<std::result::Result<Vec<arkret_wire::CommittedEventFullView>, _>>()?;
    verify_native_station_commits(observations, &views)?;
    let MediaBackendToken::ArkretNative(token) = &response.backend_token else {
        anyhow::bail!("native issuer returned no verifiable native token")
    };
    let method = &response.participant_binding.issuer_kid;
    let did = arkret_identity::verification_method_did(method.as_str())?;
    let service = arkret_identifiers::project_did_to_core_id(&did)?;
    ensure!(
        views[1]
            .event
            .payload
            .get("value")
            .and_then(|v| v.get("service_id"))
            == Some(&json!(service)),
        "media issuer was not selected by the actual accepted Realm descriptor"
    );
    let key = native_station_key(observations, method, token.payload.issued_at)?;
    let key = ed25519_dalek::VerifyingKey::from_bytes(&key.ed25519_bytes()?)?;
    let anchors = arkret_signatures::media::MediaServiceAnchors::new([(service, did)])?
        .with_keys([(method.to_string(), key)])?;
    let now = arkret_canonical::parse_timestamp_canonical(
        evidence["verified_at"]
            .as_str()
            .context("actual verification instant")?,
    )?;
    arkret_signatures::media::verify_call_media_token_outcome(&request, &response, &anchors, now)?;
    ensure!(
        &token.kid == method
            && token.payload.participant_id == response.participant_id
            && token.payload.call_id == request.call_id
            && token.payload.focus_id == request.focus_id
            && token.payload.expires_at == response.expires_at,
        "backend token split its signed native participant tuple"
    );
    key.verify(
        &arkret_canonical::canonical_json_bytes(&token.payload)?,
        &ed25519_dalek::Signature::from_slice(&arkret_canonical::base64url_decode(
            &token.signature,
        )?)?,
    )?;
    Ok(())
}
