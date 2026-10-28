//! Distinct native Stations retain one actual cross-Station KeyPackage claim.
use arkret_models_crypto::*;

use super::*;
use crate::harness::expect_json;

const SCOPE: [&str; 5] = [
    "ak.peer.keys.keypackages.command.claim.v1",
    "ak.peer.keys.keypackages.read.claim.v1",
    "ak.peer.events.command.submit.v1",
    "ak.peer.strand.watch.command.audit_read.v1",
    "ak.peer.mls.command.attest_add.v1",
];

async fn await_source_claim(
    alice: &crate::harness::TestActorClient,
    request: &KeyPackagesClaimRequestBody,
) -> Result<(KeyPackagesClaimResponseBody, Vec<Value>)> {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(90);
    let mut pending = Vec::new();
    loop {
        // Keep the original participant intent, request identity and canonical
        // body. Each transport retry gets fresh session proof, never a new claim.
        let response = crate::harness::send_recorded(
            alice
                .post("/_arkret/self/keys/keypackages/claim")
                .header("Idempotency-Key", request.claim_request_id.as_str())
                .json(request),
        )
        .await?;
        if response.status == reqwest::StatusCode::OK {
            let original = serde_json::from_value(response.json()?)?;
            return Ok((original, pending));
        }
        let problem = response.json()?;
        ensure!(
            response.status == reqwest::StatusCode::CONFLICT
                && problem["reason_detail"] == "dependency_unavailable"
                && problem["detail"]
                    == "remote KeyPackage claim has been durably accepted for relay",
            "native source claim failed outside its durable relay boundary: {}",
            response.context()
        );
        pending.push(json!({"status":response.status.as_u16(),"problem":problem,
            "body_base64url":arkret_canonical::base64url_encode(&response.body)}));
        ensure!(
            tokio::time::Instant::now() < deadline,
            "native relay has no final claim original after 90 seconds; pending is not coverage"
        );
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
}

pub(super) async fn peer(
    receiver: &crate::harness::ArkretServer,
    source: &crate::harness::ArkretServer,
    path: &str,
    body: &impl serde::Serialize,
    key: Option<&str>,
) -> Result<Value> {
    let raw = arkret_canonical::canonical_json_bytes(body)?;
    let request = receiver.signed_peer_post_request_with_idempotency_key(
        source,
        path,
        &raw,
        receiver.service_id(),
        key,
    )?;
    let frozen = request
        .try_clone()
        .context("actual buffered cross-Station claim")?;
    let response = receiver.http().execute(request).await?;
    let status = response.status();
    let raw = response.bytes().await?;
    ensure!(
        status == reqwest::StatusCode::OK,
        "native cross-Station {path}: {status} {}",
        String::from_utf8_lossy(&raw)
    );
    cotest_test_support::operation_observation::record_response(
        Some(&frozen),
        status.as_u16(),
        &raw,
    )?;
    Ok(serde_json::from_slice(&raw)?)
}

pub(super) async fn run() -> Result<()> {
    let (result,observations)=observe(crate::harness::heap_future(||async {
        let mut source=crate::harness::heap_future(||crate::scenarios::agent_runtime_live::coauth_session_evidence::actual_agent_deployment("native-peer-claim-source")).await?;
        let mut destination=crate::harness::heap_future(||crate::scenarios::agent_runtime_live::coauth_session_evidence::actual_agent_deployment("native-peer-claim-destination")).await?;
        ensure!(source.station.service_id()!=destination.station.service_id() && source.account!=destination.account,"peer claim requires two independent native identities and Account lineages");
        source.station.restart_with_federation_mesh(&[destination.station.url("")]).await?;
        destination.station.restart_with_federation_mesh(&[source.station.url("")]).await?;
        let alice=super::mls_interop::member(source.controller.clone(),source.station.service_id())?;
        let bob=super::mls_interop::member(destination.controller.clone(),destination.station.service_id())?;
        let stations=[&source.station,&destination.station];
        let realm:arkret_wire::RealmId=crate::scenarios::human_device_producer_live::create_realm_with_join_rule(&alice.client,"Native cross-Station KeyPackage claim","public",&stations).await?.parse()?;
        let genesis=crate::scenarios::mls_lifecycle_live::accepted_full_view(&alice.client,&realm.event_id()).await?;
        crate::scenarios::human_device_producer_live::prepare_join(&bob.client,realm.as_str(),&source.station,&arkret_identifiers::new_prefixed_uuid7("ak:request:"),arkret_models_collaboration::governance::realm_join_intake::RealmJoinIntent::MemberJoin).await?;
        let join=bob.client.author_event(realm.as_str(),arkret_wire::EventKind::MemberState.as_str(),crate::scenarios::human_device_producer_live::membership_payload(realm.as_str(),bob.account.clone(),arkret_models_collaboration::governance::membership_invite::MembershipPayloadState::Join,"native remote KeyPackage participant")?).await?;
        crate::scenarios::human_device_producer_live::submit_and_expect_commit(&bob.client,&bob.account,bob.device.as_str(),&join).await?;
        let membership=crate::scenarios::mls_lifecycle_live::accepted_full_view(&alice.client,&join.event_id).await?;
        let peer_event=crate::harness::heap_future(||super::peer_events::exercise(&destination.station,&source.station,&membership)).await?;
        let peer_watch=crate::harness::heap_future(||super::peer_watch::exercise(&source.station,&destination.station,&alice,&bob,&realm)).await?;
        let bob_identity=bob.mls_identity()?;
        let material=bob_identity.key_package_record()?;
        let upload=bob_identity.signed_key_packages_upload_request(std::slice::from_ref(&material),bob.method.as_str())?;
        let uploaded:KeyPackagesUploadResponseBody=serde_json::from_value(expect_json(bob.client.post("/_arkret/self/keys/keypackages/upload").json(&upload),reqwest::StatusCode::OK).await?)?;
        ensure!(uploaded.accepted_count==1 && uploaded.rejections.is_empty(),"native target did not accept its actual single-use original");
        let group=arkret_wire::ScopeRef::Realm {realm_id:realm.clone()}.canonical_mls_group_id()?;
        let mut entropy=[0u8;16];getrandom::fill(&mut entropy).context("native cross-Station claim entropy")?;
        let mut request=crate::scenarios::mls_lifecycle_live::claim_request_between(&alice,&source.station,&destination.station,&bob,&realm,group.as_str(),entropy,chrono::Duration::minutes(4))?;
        request.target_keypackage_ref=Some(arkret_wire::KeyPackageRef::new(material.keypackage_ref.as_str()).map_err(anyhow::Error::msg)?);
        let signed=keypackage_claim_authorization_signing_bytes(&request.unsigned_request(),&request.service_binding,&request.requester_authorization)?;
        use ed25519_dalek::Signer as _;
        let PeerKeyPackageRequesterAuthorization::Device {signature,..}=&mut request.requester_authorization else {anyhow::bail!("native Human requester lost its accepted Device")};
        signature.signature=arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(alice.key.sign(&signed).to_bytes())).map_err(anyhow::Error::msg)?;
        // The real source Station first checks its current requester and performs
        // its own signed peer delivery. Only its accepted original is replayed.
        let (issued,relay_pending)=await_source_claim(&alice.client,&request).await?;
        issued.validate_shape().map_err(anyhow::Error::msg)?;
        let recovered=peer(&destination.station,&source.station,"/_arkret/peer/keys/keypackages/claim",&request,Some(request.claim_request_id.as_str())).await?;
        let typed:PeerKeyPackagesClaimQueryResponseBody=serde_json::from_value(recovered.clone())?;typed.validate_shape().map_err(anyhow::Error::msg)?;
        ensure!(typed.state==PeerKeyPackagesClaimQueryState::Claimed && json!(typed.claim_outcome)==json!(issued),"peer recovery split the real source's accepted material");
        let query=PeerKeyPackagesClaimQueryRequestBody {claim_request_id:request.claim_request_id.clone(),request_digest:arkret_wire::Hash::new(arkret_canonical::canonical_sha256(&request)?)?};
        let queried=peer(&destination.station,&source.station,"/_arkret/peer/keys/keypackages/claims/query",&query,None).await?;
        ensure!(queried==recovered,"native peer query changed its actual original");
        let database=destination.station.owned_database_url().context("native target claim ledger")?.to_owned();let id=request.claim_request_id.to_string();let source_id=source.station.service_id().to_string();let reference=material.keypackage_ref.to_string();
        let originals=tokio::task::spawn_blocking(move ||->Result<Value>{let mut db=postgres::Client::connect(&database,postgres::NoTls)?;let ledger:Value=db.query_one("SELECT to_jsonb(c) FROM peer_keypackage_claims c WHERE source_id=$1 AND claim_request_id=$2",&[&source_id,&id])?.get(0);let package:Value=db.query_one("SELECT to_jsonb(k) FROM mls_key_packages k WHERE keypackage_ref=$1",&[&reference])?.get(0);Ok(json!({"ledger":ledger,"package":package}))}).await??;
        ensure!(originals["ledger"]["state"]=="claimed" && originals["ledger"]["outcome"]==json!(issued) && originals["package"]["claimed_by_mls_group_id"]==json!(group),"native destination has no actual single-use CAS or immutable original");
        let database=source.station.owned_database_url().context("native source relay ledger")?.to_owned();let id=request.claim_request_id.to_string();let source_id=source.station.service_id().to_string();
        let source_original=tokio::task::spawn_blocking(move ||->Result<Value>{let mut db=postgres::Client::connect(&database,postgres::NoTls)?;Ok(db.query_one("SELECT to_jsonb(c) FROM peer_keypackage_claims c WHERE source_id=$1 AND claim_request_id=$2",&[&source_id,&id])?.get(0))}).await??;
        ensure!(source_original["state"]=="claimed" && source_original["outcome"]==json!(issued),"source did not capture the destination's actual final original");
        let mls_add=crate::harness::heap_future(||super::mls_attest_add::exercise(&source.station,&destination.station,&alice,&bob,bob_identity,&realm,&issued)).await?;
        Ok::<_,anyhow::Error>(json!({"mls_add":mls_add,"peer_watch":peer_watch,"peer_event":peer_event,"request":request,"issued":issued,"relay_pending":relay_pending,"source_original":source_original,"recovered":recovered,"query":query,"queried":queried,"material":material,"upload":upload,"uploaded":uploaded,"genesis":genesis,"membership":membership,"originals":originals,"source_description":alice.client.sdk().describe().await?,"destination_description":bob.client.sdk().describe().await?,"processes":[source.coauth.server.native_process_identity()?,source.station.native_process_identity()?,destination.coauth.server.native_process_identity()?,destination.station.native_process_identity()?]}))
    })).await;
    retain_attempt("peer-keypackage-claims", &observations)?;
    let mut artifact = result?;
    validate_exchange_schemas(&observations, &SCOPE)?;
    let issued: KeyPackagesClaimResponseBody = serde_json::from_value(artifact["issued"].clone())?;
    verify_native_station_keypackage_signature(
        &observations,
        &issued.claim_receipt.signature,
        issued.claim_receipt.claimed_at,
        &peer_keypackage_claim_receipt_signing_bytes(&issued.claim_receipt)?,
    )?;
    verify_native_station_commits(
        &observations,
        &[
            serde_json::from_value(artifact["genesis"].clone())?,
            serde_json::from_value(artifact["membership"].clone())?,
        ],
    )?;
    for exchange in observations
        .exchanges
        .iter()
        .filter(|row| SCOPE.contains(&row.operation_id.as_str()))
    {
        let mut required = vec![
            arkret_signatures::http_signature::Component::Header("source-trust-domain".into()),
            arkret_signatures::http_signature::Component::Header("destination-trust-domain".into()),
        ];
        if exchange.operation_id.as_str() == SCOPE[0] {
            required.push(arkret_signatures::http_signature::Component::Header(
                "idempotency-key".into(),
            ));
        }
        verify_native_station_http_request(&observations, exchange, &required)?;
        ensure!(
            exchange.explicit_request_headers["source-service-id"]
                != exchange.explicit_request_headers["destination-service-id"],
            "peer qualification accidentally reused one logical Station"
        );
    }
    super::peer_events::verify(&observations, &artifact["peer_event"])?;
    super::peer_watch::verify(&observations, &artifact["peer_watch"])?;
    super::mls_attest_add::verify(&observations, &artifact["mls_add"])?;
    artifact["case"] = json!("peer_keypackage_claims");

    artifact["scope"] = json!(SCOPE);
    artifact["observations"] = json!(observations);
    if let Some(directory) = std::env::var_os("COTEST_NATIVE_OPERATION_EVIDENCE_DIR") {
        std::fs::write(
            std::path::PathBuf::from(directory).join("peer-keypackage-claims.json"),
            serde_json::to_vec_pretty(&artifact)?,
        )?;
    }
    for operation in SCOPE {
        println!("native operation contract passed: {operation}");
    }
    Ok(())
}
