//! Real single-use MIMI claim and the destination native CAS ledger.
use arkret_models_crypto::*;
use ed25519_dalek::Signer as _;

use super::*;
use crate::harness::{ArkretServer, expect_json};
use crate::scenarios::mls_lifecycle_live::{self as mls, Member};

pub(super) async fn exercise(
    station: &ArkretServer,
    alice: &Member,
    bob: &Member,
    realm: &arkret_wire::RealmId,
    group: &arkret_wire::MlsGroupId,
    room: &str,
) -> Result<Value> {
    let identity = bob.mls_identity()?;
    let material = identity.key_package_record()?;
    let upload = identity
        .signed_key_packages_upload_request(std::slice::from_ref(&material), bob.method.as_str())?;
    let uploaded = expect_json(
        bob.client
            .post("/_arkret/self/keys/keypackages/upload")
            .json(&upload),
        reqwest::StatusCode::OK,
    )
    .await?;
    let accepted: KeyPackagesUploadResponseBody = serde_json::from_value(uploaded.clone())?;
    ensure!(
        accepted.accepted_count == 1 && accepted.rejections.is_empty(),
        "MIMI package original was not accepted"
    );
    let mut entropy = [0u8; 16];
    getrandom::fill(&mut entropy).context("native MIMI claim entropy")?;
    let mut request = mls::claim_request_between(
        alice,
        station,
        station,
        bob,
        realm,
        group.as_str(),
        entropy,
        chrono::Duration::minutes(4),
    )?;
    request.required_capabilities = vec![
        arkret_wire::NonEmptyString::new("ak.content.v1").map_err(anyhow::Error::msg)?,
        arkret_wire::NonEmptyString::new("mimi.content.v1").map_err(anyhow::Error::msg)?,
    ];
    request.target_keypackage_ref = Some(
        arkret_wire::KeyPackageRef::new(material.keypackage_ref.as_str())
            .map_err(anyhow::Error::msg)?,
    );
    let bytes = keypackage_claim_authorization_signing_bytes(
        &request.unsigned_request(),
        &request.service_binding,
        &request.requester_authorization,
    )?;
    let PeerKeyPackageRequesterAuthorization::Device { signature, .. } =
        &mut request.requester_authorization
    else {
        anyhow::bail!("native participant must retain its exact device authorization")
    };
    signature.signature = arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(
        alice.key.sign(&bytes).to_bytes(),
    ))
    .map_err(anyhow::Error::msg)?;
    let request_wire = json!(request);
    let post = || {
        crate::scenarios::mimi_facade_live::signed_post_inner(
            station,
            "/_arkret/open/mimi/key-material",
            Some(room),
            station.service_id().as_str(),
            &request_wire,
            None,
        )
    };
    let (status, accepted) = post().await?;
    ensure!(
        status == reqwest::StatusCode::OK,
        "MIMI material was refused: {status} {accepted}"
    );
    let (status, replay) = post().await?;
    ensure!(
        status == reqwest::StatusCode::OK && replay == accepted,
        "MIMI claim retry changed its original"
    );
    let typed: PeerKeyPackagesClaimQueryResponseBody = serde_json::from_value(accepted.clone())?;
    typed.validate_shape().map_err(anyhow::Error::msg)?;
    ensure!(
        typed.state == PeerKeyPackagesClaimQueryState::Claimed
            && typed.claim_request_id == request.claim_request_id,
        "MIMI did not reach the actual claimed state"
    );
    let outcome = typed
        .claim_outcome
        .context("actual material-bearing outcome")?;
    let [claim] = outcome.claims.as_slice() else {
        anyhow::bail!("MIMI must reserve exactly its actual single-use package")
    };
    ensure!(
        claim.keypackage_ref == material.keypackage_ref.as_str()
            && claim.device_id.as_ref() == Some(&bob.device)
            && claim.actor_id == bob.actor
            && claim.device_authorize_event_id.as_ref() == Some(&bob.authorize_event_id),
        "MIMI changed actual package or endpoint binding"
    );
    let database = station
        .owned_database_url()
        .context("owned MIMI ledger")?
        .to_owned();
    let claim_id = request.claim_request_id.to_string();
    let source = station.service_id().to_string();
    let reference = material.keypackage_ref.to_string();
    let originals=tokio::task::spawn_blocking(move||->Result<Value>{let mut db=postgres::Client::connect(&database,postgres::NoTls)?;let ledger:Value=db.query_one("SELECT to_jsonb(c) FROM peer_keypackage_claims c WHERE source_id=$1 AND claim_request_id=$2",&[&source,&claim_id])?.get(0);let package:Value=db.query_one("SELECT to_jsonb(k) FROM mls_key_packages k WHERE keypackage_ref=$1",&[&reference])?.get(0);Ok(json!({"ledger":ledger,"package":package}))}).await??;
    ensure!(
        originals["ledger"]["state"] == "claimed"
            && originals["ledger"]["outcome"] == json!(outcome)
            && originals["package"]["claimed_by_mls_group_id"] == json!(group),
        "MIMI native CAS did not retain its actual accepted original"
    );
    Ok(
        json!({"room":room,"trust_domain":station.trust_domain(),"upload":upload,"uploaded":uploaded,"material":material,"request":request,"accepted":accepted,"replay":replay,"originals":originals}),
    )
}
pub(super) fn verify(observations: &NativeOperationObservations, evidence: &Value) -> Result<()> {
    let accepted: PeerKeyPackagesClaimQueryResponseBody =
        serde_json::from_value(evidence["accepted"].clone())?;
    let outcome = accepted
        .claim_outcome
        .context("actual MIMI claim original")?;
    let request: KeyPackagesClaimRequestBody = serde_json::from_value(evidence["request"].clone())?;
    ensure!(
        json!(outcome.claim_receipt.request) == json!(request.unsigned_request()),
        "MIMI claim receipt changed signed participant request"
    );
    use arkret_signatures::http_signature::Component;
    for exchange in observations
        .exchanges
        .iter()
        .filter(|row| row.operation_id.as_str() == "ak.open.mimi.exchange.request_key_material.v1")
    {
        let required = [
            "source-trust-domain",
            "destination-trust-domain",
            "idempotency-key",
            "provider-id",
            "mimi-room-uri",
        ]
        .map(|name| Component::Header(name.into()));
        verify_native_station_http_request(observations, exchange, &required)?;
        let headers = &exchange.explicit_request_headers;
        ensure!(
            headers.get("source-trust-domain").map(String::as_str)
                == evidence["trust_domain"].as_str()
                && headers.get("destination-trust-domain").map(String::as_str)
                    == evidence["trust_domain"].as_str(),
            "MIMI claim changed its actual deployment trust domain"
        );
        ensure!(
            headers.get("idempotency-key").map(String::as_str)
                == Some(request.claim_request_id.as_str())
                && headers.get("provider-id") == headers.get("source-service-id")
                && headers.get("mimi-room-uri").map(String::as_str) == evidence["room"].as_str(),
            "MIMI claim changed its exact ledger key, source or accepted room"
        );
    }
    verify_native_station_keypackage_signature(
        observations,
        &outcome.claim_receipt.signature,
        outcome.claim_receipt.claimed_at,
        &peer_keypackage_claim_receipt_signing_bytes(&outcome.claim_receipt)?,
    )
}
