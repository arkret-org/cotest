//! Terminal `DELETE /_arkret/self/keys/backups/{id}`.
//!
//! §7.8.1 made this a high-risk authority: the service issues a durable
//! single-use challenge, and the client signs the canonical delete-intent
//! transcript with a principal control key, a device quorum or a trusted
//! recovery service. There is no development ownership string any more, so the
//! scenario drives the real two-call flow and verifies that a synthetic key
//! outside the exact principal authority pair fails closed.

use anyhow::{Result, anyhow};
use arkret_canonical::canonical::canonical_json_bytes;
use arkret_models_crypto::{
    KeyBackupDeleteProof, KeysBackupsDeleteChallenge, KeysBackupsDeleteRequestBody,
    KeysBackupsIssueDeleteChallengeRequestBody,
};
use arkret_wire::{
    AuditReasonText, Base64UrlString, PayloadProof, PayloadProofPurpose, proof_kind,
};
use ed25519_dalek::SigningKey;
use reqwest::StatusCode;

use super::key_backups::BACKUP_ID;
use crate::harness::{ArkretServer, expect_api_error, expect_json};
use crate::scenarios::identity_test_support::test_principal_root_signing_authority;

pub async fn run(server: &ArkretServer, token: &str, actor_id: &str) -> Result<()> {
    let request_id = Base64UrlString::new("Y290ZXN0LWJhY2t1cC1kZWxldGUtMDE".to_owned())
        .map_err(|error| anyhow!("delete request_id: {error}"))?;
    let reason = AuditReasonText::new("user_requested")
        .map_err(|error| anyhow!("delete reason: {error}"))?;

    // 1. The service mints the challenge. Every freshness value in the transcript is server-side,
    //    so nothing here may be caller-chosen.
    let challenge = expect_json(
        server
            .http()
            .post(server.url(&format!(
                "/_arkret/self/keys/backups/{BACKUP_ID}/delete-challenge"
            )))
            .bearer_auth(token)
            .json(&KeysBackupsIssueDeleteChallengeRequestBody {
                request_id: request_id.clone(),
            }),
        StatusCode::OK,
    )
    .await?;
    let challenge: KeysBackupsDeleteChallenge = serde_json::from_value(challenge)?;

    // 2. Sign the one canonical delete-intent transcript with the principal control key.
    let (verification_method, root_key_seed) = test_principal_root_signing_authority(actor_id)?;
    let transcript = challenge.delete_intent_transcript(Some(reason.as_str()));
    let canonical = canonical_json_bytes(&transcript)
        .map_err(|error| anyhow!("delete-intent transcript is not canonical: {error}"))?;
    let jws = arkret_signatures::sign_ed25519_detached_jws(
        &SigningKey::from_bytes(&root_key_seed),
        &canonical,
    )?;
    let proof = PayloadProof {
        kind: proof_kind::DETACHED_JWS.to_owned(),
        verification_method,
        payload_digest: challenge
            .delete_intent_digest(Some(reason.as_str()))
            .map_err(|error| anyhow!("delete-intent digest: {error}"))?,
        created_at: challenge.issued_at,
        domain: None,
        audience: None,
        proof_purpose: Some(PayloadProofPurpose::IssuerAttestation),
        jws,
    };

    let body = KeysBackupsDeleteRequestBody {
        request_id,
        challenge_id: challenge.challenge_id.clone(),
        proof: KeyBackupDeleteProof::PrincipalSigning { proof },
        reason: Some(reason),
    };
    expect_api_error(
        server
            .http()
            .delete(server.url(&format!("/_arkret/self/keys/backups/{BACKUP_ID}")))
            .bearer_auth(token)
            .header("Idempotency-Key", "protocol-payloads-key-backup-delete")
            .json(&body),
        StatusCode::FORBIDDEN,
        "capability_denied",
    )
    .await?;

    let backup_list = expect_json(
        server
            .http()
            .get(server.url("/_arkret/self/keys/backups"))
            .bearer_auth(token),
        StatusCode::OK,
    )
    .await?;
    assert!(
        backup_list["backups"]
            .as_array()
            .is_some_and(|backups| backups
                .iter()
                .any(|backup| backup["backup_id"] == BACKUP_ID)),
        "denied delete must leave the backup intact: {backup_list}"
    );
    Ok(())
}
