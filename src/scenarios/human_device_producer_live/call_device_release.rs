//! A real accepted Device revoke between backend preparation and token release.

use arkret_models_collaboration::call_invitation::{
    CallMediaJoinContext, CallVoluntaryJoinContext, CallVoluntaryJoinKind, CallVoluntaryJoinProof,
};
use arkret_models_collaboration::objects::media::CallMediaTokenExchangeRequestBody;

fn nonce() -> Result<String> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(anyhow::Error::msg)?;
    Ok(arkret_canonical::base64url_encode(bytes))
}

use super::*;

pub(super) async fn run(
    station: &ArkretServer,
    author: &TestActorClient,
    device_client: &TestActorClient,
    account: &AccountId,
    pause: &std::path::Path,
    revoke: impl std::future::Future<Output = Result<()>>,
) -> Result<()> {
    let realm = create_public_realm(author, "Call Device final cut", &[station]).await?;
    grant_realm_actions(author, station, &realm, account, &["ak.call.join"]).await?;
    let endpoint = station
        .base_url()
        .join("/_arkret/self/rtc/token")?
        .to_string();
    let media = author
        .author_event(
            &realm,
            EventKind::RealmMediaService.as_str(),
            json!({
                "value":{"service_id":station.service_id(),"foci":[{
                    "focus_id":"device-final-cut","focus_kind":"arkret_native",
                    "token_endpoint":endpoint,"connect_url":station.base_url()
                }]}
            }),
        )
        .await?;
    submit_and_expect_commit(author, account, DEVICE_A, &media).await?;
    let call = author
        .author_event(
            &realm,
            EventKind::CallCreate.as_str(),
            json!({"initial_state":"connecting"}),
        )
        .await?;
    submit_and_expect_commit(author, account, DEVICE_A, &call).await?;
    let call_id = arkret_wire::CallId::from_event_id(&call.event_id);
    let focus = author
        .author_event(
            &realm,
            EventKind::CallState.as_str(),
            json!({
                "call_id":call_id,"focus":{"mode":"sfu","session_focus":"device-final-cut"}
            }),
        )
        .await?;
    submit_and_expect_commit(author, account, DEVICE_A, &focus).await?;
    let now = arkret_canonical::canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let principal = author
        .principal
        .as_ref()
        .context("the actual founding PCR")?;
    let mut request = CallMediaTokenExchangeRequestBody {
        realm_id: realm.parse()?,
        call_id,
        actor_id: ActorId::account(account.clone()),
        device_id: DEVICE_C.parse()?,
        focus_id: "device-final-cut".into(),
        capability_refs: Vec::new(),
        desired_media: None,
        join_context: CallMediaJoinContext::Voluntary(CallVoluntaryJoinContext {
            kind: CallVoluntaryJoinKind::Voluntary,
            created_at: now,
            expires_at: now + chrono::Duration::seconds(60),
            nonce: nonce()?,
            proof: CallVoluntaryJoinProof {
                verification_method: format!("{}#{DEVICE_C}", principal.did),
                jws: String::new(),
            },
        }),
    };
    let key = ed25519_dalek::SigningKey::from_bytes(&DEVICE_C_SEED);
    arkret_signatures::call_invitation::sign_call_voluntary_join(&mut request, &key)?;
    let positive = expect_json(
        device_client.post("/_arkret/self/rtc/token").json(&request),
        StatusCode::OK,
    )
    .await?;
    ensure!(positive["device_id"] == DEVICE_C && positive["actor_id"] == json!(request.actor_id));
    if let CallMediaJoinContext::Voluntary(context) = &mut request.join_context {
        context.nonce = nonce()?;
    }
    arkret_signatures::call_invitation::sign_call_voluntary_join(&mut request, &key)?;
    let digest: arkret_wire::Hash = arkret_canonical::canonical_sha256(&request)?.parse()?;
    std::fs::write(pause, serde_json::to_vec(&digest)?)?;
    let token = expect_json(
        device_client.post("/_arkret/self/rtc/token").json(&request),
        StatusCode::CONFLICT,
    );
    let raced = async {
        tokio::time::timeout(Duration::from_secs(10), async {
            while !pause.with_extension("reached").exists() {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .context("actual Device token did not reach its final cut")?;
        revoke.await?;
        std::fs::remove_file(pause)?;
        Ok::<(), anyhow::Error>(())
    };
    let (response, raced) = tokio::join!(token, raced);
    raced?;
    let response = response?;
    ensure!(response["type"] == "https://arkret.org/problems/failed_precondition");
    ensure!(
        response["detail"]
            .as_str()
            .is_some_and(|detail| detail.contains("device authority changed")),
        "Device final cut hit another refusal: {response}"
    );
    eprintln!(
        "[call-device-final-cut] actual_token_positive=1 prepared_before_accepted_device_revoke=1 final_release_denied=1"
    );
    Ok(())
}
