//! Real signed transports, kept byte-for-byte in the native observation owner.

use super::*;

pub(super) async fn send(
    receiver: &crate::harness::ArkretServer,
    request: reqwest::Request,
) -> Result<(u16, Vec<u8>)> {
    let frozen = request
        .try_clone()
        .context("buffered signed native request")?;
    let response = receiver.http().execute(request).await?;
    let status = response.status().as_u16();
    let bytes = response.bytes().await?.to_vec();
    cotest_test_support::operation_observation::record_response(Some(&frozen), status, &bytes)?;
    Ok((status, bytes))
}

pub(super) async fn post(
    receiver: &crate::harness::ArkretServer,
    source: &crate::harness::ArkretServer,
    path: &str,
    body: &(impl serde::Serialize + Sync),
    key: &str,
) -> Result<(Vec<u8>, Value)> {
    let bytes = arkret_canonical::canonical_json_bytes(body)?;
    let request = receiver.signed_peer_post_request_with_idempotency_key(
        source,
        path,
        &bytes,
        receiver.service_id(),
        Some(key),
    )?;
    let (status, bytes) = send(receiver, request).await?;
    ensure!(
        status == 200,
        "native signed POST {path} returned {status}: {}",
        String::from_utf8_lossy(&bytes)
    );
    let value = serde_json::from_slice(&bytes)?;
    Ok((bytes, value))
}

pub(super) fn verify_object_signature(
    resolution: &arkret_models_identity::AuthenticatedServiceResolution,
    method: &arkret_wire::DidUrl,
    at: chrono::DateTime<chrono::Utc>,
    bytes: &[u8],
    jws: &str,
) -> Result<()> {
    arkret_identity::verify_authenticated_service_resolution_history(
        resolution,
        &resolution.service_id,
        at,
    )?;
    let document =
        arkret_identity::authenticated_service_document_at(resolution, &resolution.service_id, at)?;
    arkret_identity::validate_verification_method_relationship(
        &document,
        method,
        &document.id,
        arkret_identity::DidVerificationRelationship::AssertionMethod,
    )?;
    let key = arkret_identity::public_key_material_from_document(&document, method)?;
    arkret_signatures::Ed25519DetachedJwsVerifier::new().verify_detached_jws(jws, bytes, &key)?;
    Ok(())
}

pub(super) fn verify_package(
    package: &arkret_models_collaboration::governance::erasure::ErasureReceiptPackage,
    resolution: &arkret_models_identity::AuthenticatedServiceResolution,
) -> Result<()> {
    package.validate_bindings()?;
    package.receipt.validate_proof_payload_digests()?;
    ensure!(
        package.receipt.issuer_id == resolution.service_id && !package.receipt.proofs.is_empty(),
        "completed receipt has no exact issuer proof"
    );
    for proof in &package.receipt.proofs {
        verify_object_signature(
            resolution,
            &proof.verification_method,
            package
                .receipt
                .issued_at
                .unwrap_or(package.receipt.completed_at),
            &package.receipt.canonical_proof_input()?,
            &proof.signature,
        )?;
    }
    Ok(())
}

pub(super) fn verify_acceptance(
    package: &arkret_models_collaboration::governance::erasure::ErasureReceiptPackage,
    value: &Value,
    resolution: &arkret_models_identity::AuthenticatedServiceResolution,
) -> Result<arkret_models_collaboration::governance::erasure::ErasureReceiptAcceptance> {
    use arkret_models_collaboration::governance::erasure::ErasureReceiptSubmitResponseBody;
    let ErasureReceiptSubmitResponseBody::Accepted(acceptance) =
        serde_json::from_value(value.clone())?
    else {
        anyhow::bail!("receipt transport refused actual Completed");
    };
    ensure!(
        acceptance.issuer_id == package.receipt.issuer_id
            && acceptance.receiver_id == resolution.service_id
            && acceptance.receipt_id == package.receipt.receipt_id
            && acceptance.receipt_digest == package.computed_receipt_digest()?,
        "receipt acknowledgement changed its exact package or receiver"
    );
    verify_object_signature(
        resolution,
        &acceptance.proof.verification_method,
        acceptance.accepted_at,
        &acceptance.signing_input_bytes()?,
        &acceptance.proof.jws,
    )?;
    Ok(acceptance)
}
