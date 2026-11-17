//! A package comes only from the actual native physical worker completion.

use arkret_models_collaboration::governance::erasure::{
    ErasureReceiptAcceptanceStatus, ErasureReceiptPackage,
};

use super::*;

pub(super) async fn exercise(
    source: &mut Deployment,
    target: &mut Deployment,
    package: &ErasureReceiptPackage,
    source_resolution: &arkret_models_identity::AuthenticatedServiceResolution,
    target_resolution: &arkret_models_identity::AuthenticatedServiceResolution,
) -> Result<Value> {
    transport::verify_package(package, source_resolution)?;
    let key = arkret_identifiers::new_prefixed_uuid7("ak:request:");
    let (first_bytes, accepted) = transport::post(
        &target.station,
        &source.station,
        "/_arkret/peer/erasure-receipts",
        package,
        &key,
    )
    .await?;
    let first = transport::verify_acceptance(package, &accepted, target_resolution)?;
    ensure!(
        first.status == ErasureReceiptAcceptanceStatus::Accepted,
        "first receipt was not a new actual receiver acceptance"
    );
    target.station.restart_external_process().await?;
    let (replay_bytes, replay) = transport::post(
        &target.station,
        &source.station,
        "/_arkret/peer/erasure-receipts",
        package,
        &key,
    )
    .await?;
    ensure!(
        first_bytes == replay_bytes && accepted == replay,
        "same-key receipt retry changed original acknowledgement bytes"
    );
    let different_key = arkret_identifiers::new_prefixed_uuid7("ak:request:");
    let (_, duplicate) = transport::post(
        &target.station,
        &source.station,
        "/_arkret/peer/erasure-receipts",
        package,
        &different_key,
    )
    .await?;
    let duplicate_typed = transport::verify_acceptance(package, &duplicate, target_resolution)?;
    ensure!(
        duplicate_typed.status == ErasureReceiptAcceptanceStatus::Duplicate
            && duplicate_typed.accepted_at == first.accepted_at,
        "new-key duplicate lost original acceptance time or truthful status"
    );
    let path = format!(
        "/_arkret/peer/erasure-receipts/{}",
        package.receipt.receipt_id
    );
    let request = target.station.signed_peer_get_request(
        &source.station,
        &path,
        target.station.service_id(),
    )?;
    let (status, bytes) = transport::send(&target.station, request).await?;
    ensure!(
        status == 200,
        "qualified receiver package lookup returned {status}"
    );
    let fetched: ErasureReceiptPackage = serde_json::from_slice(&bytes)?;
    ensure!(
        fetched == *package,
        "receiver lookup changed the original physical package"
    );
    let receiver_originals =
        originals::receiver(&target.station, &package.receipt.receipt_id).await?;
    let before_refusal = receiver_originals.clone();
    let mut invalid = package.clone();
    invalid.receipt.proofs[0].signature = "forged receipt proof".into();
    let raw = arkret_canonical::canonical_json_bytes(&invalid)?;
    let invalid_key = arkret_identifiers::new_prefixed_uuid7("ak:request:");
    let request = target
        .station
        .signed_peer_post_request_with_idempotency_key(
            &source.station,
            "/_arkret/peer/erasure-receipts",
            &raw,
            target.station.service_id(),
            Some(&invalid_key),
        )?;
    let (invalid_status, invalid_body) = transport::send(&target.station, request).await?;
    ensure!(
        invalid_status == 400,
        "forged receipt proof returned {invalid_status}"
    );
    ensure!(
        originals::receiver(&target.station, &package.receipt.receipt_id).await? == before_refusal,
        "forged receipt changed original acceptance or lookup custody"
    );
    Ok(
        json!({"source_id":source.station.service_id(),"receiver_id":target.station.service_id(),"package":package,
        "accepted":accepted,"replay":replay,"duplicate":duplicate,"fetched":fetched,"receiver_originals":receiver_originals,
        "invalid":{"status":invalid_status,"body":serde_json::from_slice::<Value>(&invalid_body)?,"originals_before":before_refusal,"originals_after":originals::receiver(&target.station,&package.receipt.receipt_id).await?}}),
    )
}
