//! Real classified blob, accepted policy and usable read-only native bearer URL.
use arkret_models_collaboration::governance::realm_lifecycle::RealmAssetPrivacyPolicyPayload;
use arkret_models_collaboration::objects::blob::{
    BlobPresignEnvelope, BlobPresignRequestBody, BlobPresignResponseBody, BlobUploadResponseBody,
};
use arkret_wire::{EventKind, RealmId};

use super::*;
use crate::harness::expect_json;
const SCOPE: [&str; 1] = ["ak.self.blob.command.presign.v1"];

async fn policy(
    actor: &crate::harness::TestActorClient,
    realm: &RealmId,
    allowed: bool,
) -> Result<arkret_wire::CommittedEventFullView> {
    let payload: RealmAssetPrivacyPolicyPayload = serde_json::from_value(
        json!({"value":{"direct_download_allowed":allowed,"client_digest_check_required":true}}),
    )?;
    let event = actor
        .author_event(
            realm.as_str(),
            EventKind::RealmAssetPrivacyPolicy.as_str(),
            serde_json::to_value(payload)?,
        )
        .await?;
    let account = event
        .actor_id
        .as_account_id()
        .context("native policy owner Account")?;
    crate::scenarios::human_device_producer_live::submit_and_expect_commit(
        actor,
        account,
        &actor.device_id,
        &event,
    )
    .await?;
    crate::scenarios::mls_lifecycle_live::accepted_full_view(actor, &event.event_id).await
}
async fn originals(database: &str, blob: &str) -> Result<Value> {
    let database = database.to_owned();
    let blob = blob.to_owned();
    tokio::task::spawn_blocking(move || -> Result<Value> {
        let mut db = postgres::Client::connect(&database, postgres::NoTls)?;
        let record: Value = db
            .query_one("SELECT to_jsonb(b) FROM blobs b WHERE id=$1", &[&blob])?
            .get(0);
        Ok(json!({"blob":record}))
    })
    .await?
}

pub(super) async fn run() -> Result<()> {
    let (result,observations)=observe(async {
        let deployment=crate::scenarios::agent_runtime_live::coauth_session_evidence::actual_agent_deployment("native-blob-presign").await?;
        let realm:RealmId=crate::scenarios::human_device_producer_live::create_realm_with_join_rule(&deployment.controller,"Native bearer object","closed",&[&deployment.station]).await?.parse()?;
        let realm_genesis=crate::scenarios::mls_lifecycle_live::accepted_full_view(&deployment.controller,&arkret_wire::EventId::from_digest(arkret_canonical::DigestSuite::Sha256,realm.digest_bytes())).await?;
        let allowed=policy(&deployment.controller,&realm,true).await?;
        let content=arkret_canonical::canonical_json_bytes(&json!({"message":"Actual native presigned object","realm_id":realm,"request_id":arkret_identifiers::new_prefixed_uuid7("ak:request:")}))?;
        let upload_value=expect_json(deployment.controller.post("/_arkret/self/blob/upload").multipart(crate::scenarios::delivery_media::blob_upload_form(&content,"application/json")?.text("realm_id",realm.to_string())),reqwest::StatusCode::OK).await?;
        let uploaded:BlobUploadResponseBody=serde_json::from_value(upload_value.clone())?;
        ensure!(uploaded.size_bytes==content.len() as u64 && uploaded.blob_ref.as_str().ends_with(arkret_canonical::sha256_digest(&content).trim_start_matches("sha256:")),"blob receipt does not bind the actual uploaded bytes");
        let receipt=uploaded.upload_receipt.as_ref().context("native upload receipt absent")?;
        let request=BlobPresignRequestBody {blob_ref:uploaded.blob_ref.clone(),realm_id:Some(realm.clone()),max_age_seconds:Some(90),purpose:Some("download".into())};
        let before=chrono::Utc::now();
        let value=expect_json(deployment.controller.post("/_arkret/self/blob/presign").json(&request),reqwest::StatusCode::OK).await?;
        let issued:BlobPresignResponseBody=serde_json::from_value(value.clone())?;
        let after=chrono::Utc::now();
        let url:reqwest::Url=issued.url.parse()?;ensure!(url.origin()==deployment.station.base_url().origin() && url.path()=="/_arkret/self/blob/get","presign handed off to an unowned origin or wrong operation");
        let pairs=url.query_pairs().into_owned().collect::<std::collections::BTreeMap<_,_>>();
        let encoded=pairs.get("presign").context("native URL omitted its real envelope")?;
        let envelope:BlobPresignEnvelope=serde_json::from_slice(&arkret_canonical::base64url_decode(encoded)?)?;
        let payload=&envelope.payload;
        ensure!(envelope.proof.kind=="detached_jws" && payload.blob_ref==uploaded.blob_ref && payload.realm_id.as_ref()==Some(&realm) && payload.issuer_id==*deployment.station.service_id() && payload.purpose=="download" && payload.scheme=="ak.blob.presign.v1" && payload.access_scope.method==["GET","HEAD"] && payload.access_scope.byte_range.is_none() && payload.issued_at>=before-chrono::Duration::seconds(1) && payload.issued_at<=after && payload.expires_at==issued.expires_at && payload.expires_at-payload.issued_at==chrono::Duration::seconds(90) && arkret_canonical::base64url_decode(&payload.nonce)?.len()>=16,"native envelope lost its actual object, authority, freshness or read-only scope");
        let get=deployment.station.http().get(issued.url.clone()).send().await?;ensure!(get.status()==reqwest::StatusCode::OK,"native bearer URL was unusable: {}",get.status());let fetched=get.bytes().await?;ensure!(fetched.as_ref()==content,"native URL did not return the actual accepted blob");
        let repeated=deployment.station.http().get(issued.url.clone()).send().await?.error_for_status()?.bytes().await?;ensure!(repeated.as_ref()==content,"ordinary media URL was consumed as a single-use nonce");
        let head=deployment.station.http().head(issued.url.clone()).send().await?.error_for_status()?;let head_length=head.headers().get("content-length").context("HEAD length absent")?.to_str()?.parse::<usize>()?;ensure!(head_length==content.len() && head.bytes().await?.is_empty(),"HEAD did not preserve the exact object metadata");
        let tightened=policy(&deployment.controller,&realm,false).await?;
        let denied=deployment.station.http().get(issued.url.clone()).send().await?;let denied_status=denied.status();let denied_body:Value=denied.json().await?;ensure!(denied_status==reqwest::StatusCode::NOT_FOUND,"issued URL survived accepted policy tightening");
        let database=deployment.station.owned_database_url().context("native blob storage absent")?;
        let durable=originals(database,uploaded.blob_ref.as_str()).await?;
        Ok::<_,anyhow::Error>(json!({"realm_id":realm,"realm_genesis":realm_genesis,"allowed":allowed,"tightened":tightened,"upload":uploaded,"upload_receipt":receipt,"content_base64url":arkret_canonical::base64url_encode(&content),"content_digest":arkret_canonical::sha256_digest(&content),"request":request,"issued":issued,"envelope":envelope,"fetched_base64url":arkret_canonical::base64url_encode(&fetched),"repeated_base64url":arkret_canonical::base64url_encode(&repeated),"head_length":head_length,"denied_status":denied_status.as_u16(),"denied":denied_body,"originals":durable,"processes":[deployment.coauth.server.native_process_identity()?,deployment.station.native_process_identity()?]}))
    }).await;
    retain_attempt("blob-presign", &observations)?;
    let mut artifact = result?;
    validate_exchange_schemas(&observations, &SCOPE)?;
    let uploaded: BlobUploadResponseBody = serde_json::from_value(artifact["upload"].clone())?;
    let receipt = uploaded
        .upload_receipt
        .as_ref()
        .context("native upload original absent")?;
    let receipt_key =
        native_station_key(&observations, &receipt.signature.kid, receipt.received_at)?;
    ensure!(
        receipt.signature.signature_algorithm == "Ed25519",
        "upload changed signature algorithm"
    );
    arkret_signatures::proof::verify_ed25519_raw_transcript_signature(
        &arkret_canonical::canonical_json_bytes(
            &json!({"blob_ref":receipt.blob_ref,"size_bytes":receipt.size_bytes,"received_at":receipt.received_at,"issuer_id":receipt.issuer_id}),
        )?,
        &receipt.signature.signature,
        &receipt_key,
    )?;
    let envelope: BlobPresignEnvelope = serde_json::from_value(artifact["envelope"].clone())?;
    let method = arkret_wire::DidUrl::new(format!(
        "{}#notary-key",
        observations.accepted_identity_material[0]["account_authority_history"]["did"]
            .as_str()
            .context("native issuer history absent")?
    ))
    .map_err(anyhow::Error::msg)?;
    let key = native_station_key(&observations, &method, envelope.payload.issued_at)?;
    arkret_signatures::Ed25519DetachedJwsVerifier::new().verify_detached_jws(
        &envelope.proof.jws,
        &arkret_canonical::canonical_json_bytes(&envelope.payload)?,
        &key,
    )?;
    let views = ["realm_genesis", "allowed", "tightened"]
        .into_iter()
        .map(|name| serde_json::from_value(artifact[name].clone()))
        .collect::<std::result::Result<Vec<arkret_wire::CommittedEventFullView>, _>>()?;
    verify_native_station_commits(&observations, &views)?;
    for view in &views {
        ensure!(
            view.commit.governance_generation == 0
                && view.commit.authority_ref
                    == arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(
                        views[0].event.event_id.clone()
                    ),
            "blob policy changed its accepted Realm governor"
        );
    }
    artifact["case"] = json!("blob_presign");

    artifact["scope"] = json!(SCOPE);
    artifact["observations"] = serde_json::to_value(observations)?;
    if let Some(directory) = std::env::var_os("COTEST_NATIVE_OPERATION_EVIDENCE_DIR") {
        std::fs::write(
            std::path::PathBuf::from(directory).join("blob-presign.json"),
            serde_json::to_vec_pretty(&artifact)?,
        )?;
    }
    for operation in SCOPE {
        println!("native operation contract passed: {operation}");
    }
    Ok(())
}
