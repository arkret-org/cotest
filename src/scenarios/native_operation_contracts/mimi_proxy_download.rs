//! Genuine public assets, accepted Room originals and provider-signed download.
use arkret_models_collaboration::mimi_operations::{
    MimiProxyDownloadRequestBody, MimiProxyDownloadResponseBody,
};
use arkret_models_collaboration::objects::blob::{BlobPresignEnvelope, BlobUploadResponseBody};
use arkret_models_collaboration::objects::interop::ProviderDirectory;
use arkret_wire::{BlobRef, CommittedEventFullView, EventKind, RealmId};

use super::*;
use crate::harness::{ArkretServer, TestActorClient, expect_json};
use crate::scenarios::mls_lifecycle_live as mls;

mod effects;

const OPERATION: &str = "ak.open.mimi.command.proxy_download.v1";
const SCOPE: [&str; 1] = [OPERATION];

async fn accept(
    actor: &TestActorClient,
    realm: &RealmId,
    kind: EventKind,
    payload: Value,
) -> Result<CommittedEventFullView> {
    let event = actor
        .author_event(realm.as_str(), kind.as_str(), payload)
        .await?;
    let account = event
        .actor_id
        .as_account_id()
        .context("actual native Account")?;
    crate::scenarios::human_device_producer_live::submit_and_expect_commit(
        actor,
        account,
        &actor.device_id,
        &event,
    )
    .await?;
    let original = mls::accepted_full_view(actor, &event.event_id).await?;
    ensure!(
        original.event == event,
        "native admission rewrote its signed original"
    );
    Ok(original)
}

async fn policy(
    actor: &TestActorClient,
    realm: &RealmId,
    mode: &str,
    direct: bool,
) -> Result<CommittedEventFullView> {
    let payload: arkret_models_collaboration::governance::realm_lifecycle::RealmAssetPrivacyPolicyPayload =
        serde_json::from_value(json!({"value":{
            "download_mode":mode,"direct_download_allowed":direct,
            "client_digest_check_required":true
        }}))?;
    accept(
        actor,
        realm,
        EventKind::RealmAssetPrivacyPolicy,
        serde_json::to_value(payload)?,
    )
    .await
}

async fn upload(
    actor: &TestActorClient,
    bytes: &[u8],
    realm: Option<&RealmId>,
) -> Result<BlobUploadResponseBody> {
    let mut form = crate::scenarios::delivery_media::blob_upload_form(bytes, "application/json")?;
    if let Some(realm) = realm {
        form = form.text("realm_id", realm.to_string());
    }
    let value = expect_json(
        actor.post("/_arkret/self/blob/upload").multipart(form),
        reqwest::StatusCode::OK,
    )
    .await?;
    let receipt: BlobUploadResponseBody = serde_json::from_value(value)?;
    ensure!(
        receipt.blob_ref == BlobRef::from_bytes(bytes) && receipt.size_bytes == bytes.len() as u64,
        "native upload changed the actual bytes or content address"
    );
    ensure!(
        receipt.upload_receipt.is_some(),
        "native upload lacks its signed original receipt"
    );
    Ok(receipt)
}

async fn proxy(
    station: &ArkretServer,
    provider: &str,
    room: &str,
    path: &str,
    request: &MimiProxyDownloadRequestBody,
) -> Result<(reqwest::StatusCode, Value)> {
    crate::scenarios::mimi_facade_live::signed_post_inner(
        station,
        path,
        Some(room),
        provider,
        &serde_json::to_value(request)?,
        None,
    )
    .await
}

#[expect(
    clippy::too_many_arguments,
    reason = "Bind refusal to its real provider, exact request and original state cut"
)]
async fn refuse(
    station: &ArkretServer,
    realm: &RealmId,
    refs: &[BlobRef],
    provider: &str,
    room: &str,
    path: &str,
    name: &str,
    request: &MimiProxyDownloadRequestBody,
    expected_status: u16,
    expected_code: arkret_wire::ErrorCode,
) -> Result<Value> {
    let database = station
        .owned_database_url()
        .context("native asset database")?;
    let before = effects::snapshot(database, realm, refs).await?;
    let (status, body) = proxy(station, provider, room, path, request).await?;
    let problem: arkret_wire::Problem = serde_json::from_value(body.clone())?;
    ensure!(
        status.as_u16() == expected_status && problem.error_code() == Some(expected_code),
        "native MIMI {name} returned {status}: {body}"
    );
    ensure!(
        body.get("download_ref").is_none(),
        "a refusal returned an asset URL"
    );
    let after = effects::snapshot(database, realm, refs).await?;
    ensure!(
        after == before,
        "refused native asset request changed its source or issuance originals"
    );
    Ok(
        json!({"name":name,"request":request,"status":status.as_u16(),"body":body,"before":before,"after":after}),
    )
}

fn anonymous_client(station: &ArkretServer) -> Result<reqwest::Client> {
    let ca = station.tls_ca_path().context("owned HTTPS Station CA")?;
    Ok(reqwest::Client::builder()
        .tls_backend_rustls()
        .tls_certs_only(reqwest::Certificate::from_pem_bundle(&std::fs::read(ca)?)?)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(30))
        .build()?)
}

async fn download(
    station: &ArkretServer,
    issued: &MimiProxyDownloadResponseBody,
    content: &[u8],
) -> Result<Value> {
    ensure!(
        issued.download_request_headers.is_empty(),
        "public native download borrowed provider/user credentials"
    );
    let url: reqwest::Url = issued.download_ref.as_str().parse()?;
    ensure!(
        url.origin() == station.base_url().origin()
            && url.path().ends_with("/_arkret/self/blob/get")
            && url.username().is_empty()
            && url.password().is_none()
            && url.fragment().is_none(),
        "proxy returned an unowned URL or object-store redirect"
    );
    let client = anonymous_client(station)?;
    let get_request = client.get(url.clone()).build()?;
    ensure!(
        !get_request.headers().contains_key("authorization")
            && !get_request.headers().contains_key("cookie"),
        "public reader has a private credential"
    );
    let anonymous_headers = get_request
        .headers()
        .iter()
        .map(|(name, value)| Ok((name.as_str().to_owned(), value.to_str()?.to_owned())))
        .collect::<Result<std::collections::BTreeMap<String, String>>>()?;
    let response = client.execute(get_request).await?;
    let get_status = response.status();
    let fetched = response.bytes().await?;
    ensure!(
        get_status == reqwest::StatusCode::OK && fetched.as_ref() == content,
        "native proxy URL did not return its actual public bytes"
    );
    let repeated = client.get(url.clone()).send().await?;
    let repeated_status = repeated.status();
    let repeated = repeated.bytes().await?;
    ensure!(
        repeated_status == reqwest::StatusCode::OK && repeated.as_ref() == content,
        "ordinary public asset URL became a single-use permission"
    );
    let head = client.head(url.clone()).send().await?;
    let head_status = head.status();
    let length = head
        .headers()
        .get("content-length")
        .context("native HEAD length")?
        .to_str()?
        .parse::<usize>()?;
    ensure!(
        head_status == reqwest::StatusCode::OK
            && length == content.len()
            && head.bytes().await?.is_empty(),
        "native HEAD changed the accepted asset metadata"
    );
    let pairs = url
        .query_pairs()
        .into_owned()
        .collect::<std::collections::BTreeMap<_, _>>();
    ensure!(
        pairs.len() == 3
            && pairs.get("blob_ref") == Some(&BlobRef::from_bytes(content).to_string())
            && pairs.get("purpose").map(String::as_str) == Some("download"),
        "native URL changed its object or purpose"
    );
    let envelope: BlobPresignEnvelope =
        serde_json::from_slice(&arkret_canonical::base64url_decode(
            pairs.get("presign").context("native presign envelope")?,
        )?)?;
    Ok(
        json!({"url":url,"get_status":get_status.as_u16(),"repeated_status":repeated_status.as_u16(),
        "head_status":head_status.as_u16(),"head_length":length,"anonymous_request_headers":anonymous_headers,"fetched_base64url":arkret_canonical::base64url_encode(&fetched),
        "repeated_base64url":arkret_canonical::base64url_encode(&repeated),"envelope":envelope}),
    )
}

pub(super) async fn run() -> Result<()> {
    let (result, observations) = observe(crate::harness::heap_future(|| async {
        let tag = arkret_identifiers::new_prefixed_uuid7("ak:request:");
        let content = arkret_canonical::canonical_json_bytes(&json!({"case":"native-public-asset","request_id":tag}))?;
        let private = arkret_canonical::canonical_json_bytes(&json!({"case":"native-realm-asset","request_id":tag}))?;
        let unlisted = arkret_canonical::canonical_json_bytes(&json!({"case":"native-unlisted-asset","request_id":tag}))?;
        let orphan = arkret_canonical::canonical_json_bytes(&json!({"case":"native-unreferenced-asset","request_id":tag}))?;
        let refs = [BlobRef::from_bytes(&content),BlobRef::from_bytes(&private),BlobRef::from_bytes(&unlisted),BlobRef::from_bytes(&orphan)];
        let allowlist = [refs[0].clone(),refs[1].clone(),refs[3].clone()];
        let mut deployment = crate::scenarios::agent_runtime_live::coauth_session_evidence::actual_agent_deployment(
            "native-mimi-public-asset").await?;
        let station = &mut deployment.station;
        let actor = &deployment.controller;
        let realm: RealmId = crate::scenarios::human_device_producer_live::create_realm_with_join_rule(
            actor,"Actual MIMI public asset","closed",&[station]).await?.parse()?;
        let genesis = mls::accepted_full_view(actor,&arkret_wire::EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,realm.digest_bytes())).await?;
        let strand = actor.default_strand_id(realm.as_str())?;
        let empty_directory = expect_json(station.http().get(station.url("/_arkret/open/mimi/provider-directory")),reqwest::StatusCode::OK).await?;
        let empty: ProviderDirectory = serde_json::from_value(empty_directory.clone())?;
        empty.validate()?;
        ensure!(!empty.mimi.features.iter().any(|v|v == "proxy_download")
            && !empty.mimi.endpoints.iter().any(|v|v.endpoint_id == "proxy_download"),
            "empty public deployment advertised an unavailable download capability");
        let initial_room = format!("{}/rooms/{strand}",empty.mimi.provider_id);
        let initial_request: MimiProxyDownloadRequestBody = serde_json::from_value(json!({"asset_ref":refs[0],
            "requester_id":station.service_id(),"strand_id":strand}))?;
        let empty_refusal = refuse(station,&realm,&refs,empty.mimi.provider_id.as_str(),&initial_room,
            "/_arkret/open/mimi/proxy-download","empty_configuration",&initial_request,501,arkret_wire::ErrorCode::UnsupportedFeature).await?;
        station.restart_with_public_blob_refs(&allowlist).await?;
        let directory_value = expect_json(station.http().get(station.url("/_arkret/open/mimi/provider-directory")),reqwest::StatusCode::OK).await?;
        let directory: ProviderDirectory = serde_json::from_value(directory_value.clone())?;
        directory.validate()?;
        ensure!(directory.service_id == *station.service_id() && directory.mimi.features.iter().any(|v|v == "proxy_download"),
            "configured facade did not advertise its actual proxy capability");
        let endpoint = directory.mimi.endpoints.iter().filter(|row|row.endpoint_id == "proxy_download").collect::<Vec<_>>();
        let [endpoint] = endpoint.as_slice() else {anyhow::bail!("signed proxy endpoint is not unique")};
        let path = endpoint.relative_path.as_str();
        let effective = reqwest::Url::parse(&directory.mimi.base_url)?.join(path)?;
        ensure!(effective.origin() == station.base_url().origin()
            && arkret_wire::ServiceOperationId::from_http_request("POST",effective.path()).is_some_and(|op|op.as_str() == OPERATION),
            "signed directory did not select the registered same-origin proxy operation");
        let provider = directory.mimi.provider_id.as_str();
        let room = format!("{provider}/rooms/{strand}");
        // This accepted non-E2EE room has no invented group or MLS material.
        let binding_payload = json!({"profile":"ak.profile.mimi_interop.v1","mimi_room_uri":room,
            "binding_scope":{"realm_id":realm,"strand_id":strand},"hub_provider_id":station.service_id(),
            "local_provider_role":"hub","status":"accepted"});
        let allowed = policy(actor,&realm,"direct",true).await?;
        let uploaded = upload(actor,&content,None).await?;
        let private_upload = upload(actor,&private,Some(&realm)).await?;
        let unlisted_upload = upload(actor,&unlisted,None).await?;
        let orphan_upload = upload(actor,&orphan,None).await?;
        let message = accept(actor,&realm,EventKind::MessageCreate,json!({"strand_id":strand,"track_name":"discussion",
            "content":arkret::ContentBlock::text("Genuine native public asset references"),
            "blob_refs":[refs[0],refs[1],refs[2]]})).await?;
        let request: MimiProxyDownloadRequestBody = serde_json::from_value(json!({"asset_ref":refs[0],
            "requester_id":station.service_id(),"strand_id":strand}))?;
        let unapproved = refuse(station,&realm,&refs,provider,&room,path,"unapproved_room",&request,404,arkret_wire::ErrorCode::NotFound).await?;
        let binding = accept(actor,&realm,EventKind::MimiRoomBinding,binding_payload.clone()).await?;
        let database = station.owned_database_url().context("owned MIMI asset database")?;
        let before = effects::snapshot(database,&realm,&refs).await?;
        let issued_before = chrono::Utc::now();
        let (status, response) = proxy(station,provider,&room,path,&request).await?;
        let issued_after = chrono::Utc::now();
        ensure!(status == reqwest::StatusCode::OK,"native MIMI proxy refused its actual public asset: {status} {response}");
        let issued: MimiProxyDownloadResponseBody = serde_json::from_value(response.clone())?;
        let downloaded = download(station,&issued,&content).await?;
        let after = effects::snapshot(database,&realm,&refs).await?;
        effects::verify_issuance(&before,&after,station.service_id())?;
        let unsigned_before = effects::snapshot(database, &realm, &refs).await?;
        let unsigned = actor.post(path).json(&request).send().await?;
        let unsigned_status = unsigned.status();
        let unsigned_body: Value = unsigned.json().await?;
        let unsigned_problem: arkret_wire::Problem = serde_json::from_value(unsigned_body.clone())?;
        ensure!(unsigned_status == reqwest::StatusCode::UNAUTHORIZED
            && unsigned_problem.error_code() == Some(arkret_wire::ErrorCode::HttpSignatureRequired),
            "a real user session replaced the required provider transport signature");
        let unsigned_after = effects::snapshot(database, &realm, &refs).await?;
        ensure!(unsigned_after == unsigned_before, "unsigned MIMI request changed durable asset state");
        let unsigned_refusal = json!({"name":"unsigned_session","request":request,"status":unsigned_status.as_u16(),
            "body":unsigned_body,"before":unsigned_before,"after":unsigned_after});
        let mut refusals = vec![empty_refusal,unapproved,unsigned_refusal];
        for (name,reference,status,code) in [
            ("unlisted",&refs[2],501,arkret_wire::ErrorCode::UnsupportedFeature),
            ("private",&refs[1],404,arkret_wire::ErrorCode::NotFound),
            ("unreferenced",&refs[3],404,arkret_wire::ErrorCode::NotFound),
        ] {
            let mut changed = request.clone();
            changed.asset_ref = reference.to_string().try_into().map_err(anyhow::Error::msg)?;
            refusals.push(refuse(station,&realm,&refs,provider,&room,path,name,&changed,status,code).await?);
        }
        let mut mismatch = request.clone();
        mismatch.requester_id = deployment.account.principal_id.clone();
        refusals.push(refuse(station,&realm,&refs,provider,&room,path,"requester",&mismatch,403,arkret_wire::ErrorCode::CapabilityDenied).await?);
        let mut range = request.clone();
        range.range = Some(arkret_wire::NonEmptyString::new("bytes=0-3").map_err(anyhow::Error::msg)?);
        refusals.push(refuse(station,&realm,&refs,provider,&room,path,"range",&range,501,arkret_wire::ErrorCode::UnsupportedFeature).await?);
        let mut ohttp = request.clone();
        ohttp.ohttp_context = Some(serde_json::from_value(json!({"context_id":"native-refused-ohttp",
            "request_digest":arkret_canonical::canonical_sha256(&request)?}))?);
        refusals.push(refuse(station,&realm,&refs,provider,&room,path,"ohttp",&ohttp,501,arkret_wire::ErrorCode::UnsupportedFeature).await?);
        let mut uri = request.clone();
        uri.asset_ref = arkret_wire::NonEmptyString::new("file:///native-proxy-private-asset").map_err(anyhow::Error::msg)?;
        refusals.push(refuse(station,&realm,&refs,provider,&room,path,"egress",&uri,403,arkret_wire::ErrorCode::CapabilityDenied).await?);
        let mut missing = request.clone();
        missing.strand_id = None;
        refusals.push(refuse(station,&realm,&refs,provider,&room,path,"missing_room",&missing,501,arkret_wire::ErrorCode::UnsupportedFeature).await?);
        let tightened = policy(actor,&realm,"provider_proxy",false).await?;
        refusals.push(refuse(station,&realm,&refs,provider,&room,path,"policy",&request,404,arkret_wire::ErrorCode::NotFound).await?);
        let restored = policy(actor,&realm,"direct",true).await?;
        let mut terminal_payload = binding_payload;
        terminal_payload["status"] = json!("revoked");
        let revoked = accept(actor,&realm,EventKind::MimiRoomBinding,terminal_payload).await?;
        refusals.push(refuse(station,&realm,&refs,provider,&room,path,"revoked_room",&request,404,arkret_wire::ErrorCode::NotFound).await?);
        let final_originals = effects::snapshot(database,&realm,&refs).await?;
        let processes = json!([deployment.coauth.server.native_process_identity()?,station.native_process_identity()?]);
        station.restart_with_public_blob_refs(&[]).await?;
        let cold_directory_value = expect_json(station.http().get(station.url("/_arkret/open/mimi/provider-directory")),reqwest::StatusCode::OK).await?;
        let cold_directory: ProviderDirectory = serde_json::from_value(cold_directory_value.clone())?;
        cold_directory.validate()?;
        ensure!(!cold_directory.mimi.features.iter().any(|v|v == "proxy_download")
            && !cold_directory.mimi.endpoints.iter().any(|v|v.endpoint_id == "proxy_download"),
            "withdrawn public deployment still advertised download");
        let cold_originals = effects::snapshot(station.owned_database_url().context("cold native asset database")?,&realm,&refs).await?;
        ensure!(cold_originals == final_originals,"configuration restart rewrote accepted asset originals");
        refusals.push(refuse(station,&realm,&refs,provider,&room,path,"withdrawn_configuration",&request,501,arkret_wire::ErrorCode::UnsupportedFeature).await?);
        let withdrawn_at = chrono::Utc::now();
        ensure!(issued.expires_at.is_some_and(|expires|withdrawn_at < expires),
            "withdrawal check must precede the original presign expiry");
        let denied = anonymous_client(station)?.get(issued.download_ref.as_str()).send().await?;
        let denied_status = denied.status();
        let denied_body: Value = denied.json().await?;
        let denied_problem: arkret_wire::Problem = serde_json::from_value(denied_body.clone())?;
        ensure!(denied_status == reqwest::StatusCode::NOT_FOUND && denied_problem.error_code() == Some(arkret_wire::ErrorCode::NotFound),
            "old public URL survived explicit deployment allowlist withdrawal");
        Ok::<_,anyhow::Error>(json!({"case":"mimi_proxy_download","scope":SCOPE,"station":station.service_id(),
            "realm_id":realm,"strand_id":strand,"room":room,"allowlist":allowlist,"directory":directory_value,
            "empty_directory":empty_directory,"cold_directory":cold_directory_value,
            "content_base64url":arkret_canonical::base64url_encode(&content),"content_digest":arkret_canonical::sha256_digest(&content),
            "upload":uploaded,"private_upload":private_upload,"unlisted_upload":unlisted_upload,"orphan_upload":orphan_upload,
            "genesis":genesis,"binding":binding,"message":message,"allowed":allowed,"tightened":tightened,"restored":restored,
            "revoked":revoked,"request":request,"response":response,"issued_before":issued_before,"issued_after":issued_after,
            "download":downloaded,"before":before,"after":after,"refusals":refusals,"final_originals":final_originals,
            "cold_originals":cold_originals,"withdrawn_get_at":withdrawn_at,"withdrawn_get_status":denied_status.as_u16(),"withdrawn_get_body":denied_body,
            "cold_process":station.native_process_identity()?,"processes":processes}))
    })).await;
    retain_attempt("mimi-proxy-download", &observations)?;
    let mut evidence = result?;
    validate_exchange_schemas(&observations, &SCOPE)?;
    verify(&observations, &evidence)?;
    evidence["observations"] = serde_json::to_value(observations)?;
    if let Some(directory) = std::env::var_os("COTEST_NATIVE_OPERATION_EVIDENCE_DIR") {
        std::fs::write(
            std::path::PathBuf::from(directory).join("mimi-proxy-download.json"),
            serde_json::to_vec_pretty(&evidence)?,
        )?;
    }
    println!("native operation contract passed: {OPERATION}");
    Ok(())
}

fn verify(observations: &NativeOperationObservations, evidence: &Value) -> Result<()> {
    use arkret_signatures::http_signature::Component;
    let directory: ProviderDirectory = serde_json::from_value(evidence["directory"].clone())?;
    directory.validate()?;
    for field in ["empty_directory", "directory", "cold_directory"] {
        let source: ProviderDirectory = serde_json::from_value(evidence[field].clone())?;
        source.validate()?;
        let proof = &source.proof.0;
        ensure!(
            proof.payload_digest == source.payload_digest()?,
            "directory capability projection changed"
        );
        let key = native_station_key(observations, &proof.verification_method, proof.created_at)?;
        arkret_signatures::Ed25519DetachedJwsVerifier::new().verify_detached_jws(
            &proof.jws,
            &source.proof_binding_bytes()?,
            &key,
        )?;
    }
    let mut count = 0;
    for exchange in &observations.exchanges {
        if exchange.operation_id.as_str() != OPERATION {
            continue;
        }
        super::verify_native_station_http_request(
            observations,
            exchange,
            &[
                Component::Header("provider-id".into()),
                Component::Header("mimi-room-uri".into()),
            ],
        )?;
        ensure!(
            exchange.request_body == evidence["request"]
                && exchange.response_body == evidence["response"]
                && exchange
                    .explicit_request_headers
                    .get("provider-id")
                    .map(String::as_str)
                    == Some(directory.mimi.provider_id.as_str())
                && exchange
                    .explicit_request_headers
                    .get("source-service-id")
                    .map(String::as_str)
                    == Some(directory.service_id.as_str())
                && exchange
                    .explicit_request_headers
                    .get("destination-service-id")
                    .map(String::as_str)
                    == Some(directory.service_id.as_str())
                && exchange
                    .explicit_request_headers
                    .get("mimi-room-uri")
                    .map(String::as_str)
                    == evidence["room"].as_str(),
            "proxy exchange lost its exact source, request or original response"
        );
        count += 1;
    }
    ensure!(
        count == 1,
        "native proxy needs one actual advertised successful operation"
    );
    let envelope: BlobPresignEnvelope =
        serde_json::from_value(evidence["download"]["envelope"].clone())?;
    let payload = &envelope.payload;
    let before: chrono::DateTime<chrono::Utc> =
        serde_json::from_value(evidence["issued_before"].clone())?;
    let after: chrono::DateTime<chrono::Utc> =
        serde_json::from_value(evidence["issued_after"].clone())?;
    let issued: MimiProxyDownloadResponseBody =
        serde_json::from_value(evidence["response"].clone())?;
    ensure!(
        envelope.proof.kind == "detached_jws"
            && envelope.proof.kid == format!("{}#notary-key", directory.service_id)
            && payload.issuer_id == directory.service_id
            && payload.audience_hint.as_ref() == Some(&directory.service_id)
            && payload.blob_ref.as_str()
                == evidence["upload"]["blob_ref"]
                    .as_str()
                    .context("actual upload reference")?
            && payload.realm_id.is_none()
            && payload.scheme == "ak.blob.presign.v1"
            && payload.purpose == "download"
            && payload.access_scope.method == ["GET", "HEAD"]
            && payload.access_scope.byte_range.is_none()
            && payload.issued_at >= before - chrono::Duration::seconds(1)
            && payload.issued_at <= after
            && payload.expires_at - payload.issued_at == chrono::Duration::seconds(300)
            && issued.expires_at == Some(payload.expires_at)
            && arkret_canonical::base64url_decode(&payload.nonce)?.len() >= 16,
        "public capability changed its actual object, issuer, audience, read scope or finite lifetime"
    );
    let did =
        arkret_identity::verification_method_did(directory.proof.0.verification_method.as_str())?;
    let method =
        arkret_wire::DidUrl::new(format!("{did}#notary-key")).map_err(anyhow::Error::msg)?;
    let key = native_station_key(observations, &method, payload.issued_at)?;
    arkret_signatures::Ed25519DetachedJwsVerifier::new().verify_detached_jws(
        &envelope.proof.jws,
        &arkret_canonical::canonical_json_bytes(payload)?,
        &key,
    )?;
    for field in [
        "upload",
        "private_upload",
        "unlisted_upload",
        "orphan_upload",
    ] {
        let upload: BlobUploadResponseBody = serde_json::from_value(evidence[field].clone())?;
        let receipt = upload
            .upload_receipt
            .context("actual signed upload receipt")?;
        let key = native_station_key(observations, &receipt.signature.kid, receipt.received_at)?;
        ensure!(
            receipt.signature.signature_algorithm == "Ed25519",
            "upload signature algorithm changed"
        );
        arkret_signatures::proof::verify_ed25519_raw_transcript_signature(
            &arkret_canonical::canonical_json_bytes(
                &json!({"blob_ref":receipt.blob_ref,"size_bytes":receipt.size_bytes,
                "received_at":receipt.received_at,"issuer_id":receipt.issuer_id}),
            )?,
            &receipt.signature.signature,
            &key,
        )?;
    }
    let originals = [
        "genesis",
        "binding",
        "message",
        "allowed",
        "tightened",
        "restored",
        "revoked",
    ]
    .into_iter()
    .map(|field| serde_json::from_value(evidence[field].clone()))
    .collect::<std::result::Result<Vec<CommittedEventFullView>, _>>()?;
    verify_native_station_commits(observations, &originals)?;
    Ok(())
}
