//! Opaque locator lifecycle and the actual Station acceptance signature.

use anyhow::{Context, Result, ensure};
use arkret_models_collaboration::governance::invite_addressing::*;
use arkret_signatures::{Ed25519DetachedJwsVerifier, PublicKeyMaterial};
use reqwest::{Response, StatusCode};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::harness::{ArkretServer, CanonicalJsonBody, TestActorClient};

async fn private_json<T: serde::de::DeserializeOwned>(response: Response) -> Result<T> {
    if response.status() != StatusCode::OK {
        anyhow::bail!(
            "locator command failed: {} {}",
            response.status(),
            response.text().await?
        );
    }
    ensure!(
        response
            .headers()
            .get("cache-control")
            .context("locator cache control")?
            == "private, no-store",
        "locator command allowed secret caching"
    );
    Ok(response.json().await?)
}

async fn resolve(station: &ArkretServer, token: &str) -> Result<Response> {
    Ok(station
        .http()
        .post(station.url("/_arkret/open/invite-locators/resolve"))
        .canonical_json(&InviteLocatorResolveRequestBody::new(token))?
        .send()
        .await?)
}

async fn fingerprint(response: Response) -> Result<(StatusCode, String, Value)> {
    let status = response.status();
    let content = response
        .headers()
        .get("content-type")
        .context("locator refusal content-type")?
        .to_str()?
        .to_owned();
    let mut value = response.json::<Value>().await?;
    let _: arkret_wire::Problem = serde_json::from_value(value.clone())?;
    value
        .as_object_mut()
        .context("locator refusal object")?
        .remove("instance");
    Ok((status, content, value))
}

fn verify(
    station: &ArkretServer,
    holder: &TestActorClient,
    issue: &InviteLocatorIssueResponseBody,
    locator: &PrincipalLocator,
) -> Result<()> {
    locator.validate_minimal()?;
    ensure!(
        locator.account_id.principal_id.as_str() == crate::harness::actor_core_id(&holder.actor)?
            && &locator.account_id.station_id == station.service_id(),
        "locator did not bind the holder account"
    );
    ensure!(
        locator.expires_at == issue.expires_at
            && locator.locator_ref_digest.as_str()
                == format!(
                    "sha256:{}",
                    hex::encode(Sha256::digest(issue.locator_token.as_bytes()))
                ),
        "locator secret digest or expiry mismatch"
    );
    ensure!(
        matches!(&locator.service_resolution,arkret_models_identity::ServiceResolutionCarrier::ResolutionUrl {resolution_url} if resolution_url==&station.url(&arkret_models_identity::canonical_service_resolution_path(station.service_id()))),
        "locator changed its canonical service route"
    );
    let key = PublicKeyMaterial::Ed25519Raw {
        bytes: station
            .federation_signing_key()?
            .verifying_key()
            .to_bytes()
            .to_vec(),
    };
    let proof = locator
        .proofs
        .iter()
        .find(|p| p.proof_purpose == PrincipalLocatorProofPurpose::RecipientServiceAcceptance)
        .context("Station locator acceptance proof")?;
    Ed25519DetachedJwsVerifier::new().verify_detached_jws(
        &proof.proof.jws,
        &locator.proof_signing_bytes(&proof.proof)?,
        &key,
    )?;
    Ok(())
}

async fn command<T: Serialize>(holder: &TestActorClient, path: &str, body: &T) -> Result<Response> {
    Ok(holder.post(path).canonical_json(body)?.send().await?)
}

pub(super) async fn exercise(station: &ArkretServer, holder: &TestActorClient) -> Result<()> {
    let issue_path = "/_arkret/self/invite-locators";
    let rotate_path = "/_arkret/self/invite-locators/rotate";
    let revoke_path = "/_arkret/self/invite-locators/revoke";
    let hint = PrincipalLocatorDisplayHint {
        display_name_hint: Some("Cotest locator".into()),
        avatar_blob_ref: None,
    };
    let started = chrono::Utc::now();
    let issued: InviteLocatorIssueResponseBody = private_json(
        command(
            holder,
            issue_path,
            &InviteLocatorIssueRequestBody {
                ttl_seconds: Some(60),
                one_time_use: Some(false),
                display_hint: Some(hint.clone()),
            },
        )
        .await?,
    )
    .await?;
    ensure!(
        issued.locator_token.len() == 32
            && arkret_canonical::base64url_decode(&issued.locator_token)?.len() == 24
            && serde_json::from_slice::<Value>(&arkret_canonical::base64url_decode(
                &issued.locator_token
            )?)
            .is_err(),
        "locator token is not an opaque 192-bit secret"
    );
    let ttl = (issued.expires_at - started).num_seconds();
    ensure!(
        (55..=65).contains(&ttl),
        "locator expiry did not use requested TTL"
    );
    let query = station
        .http()
        .post(format!(
            "{}?locator_token={}",
            station.url("/_arkret/open/invite-locators/resolve"),
            issued.locator_token
        ))
        .json(&InviteLocatorResolveRequestBody::new(&issued.locator_token))
        .send()
        .await?;
    ensure!(
        query.status() == StatusCode::BAD_REQUEST,
        "locator token query leak was accepted"
    );
    let path = station
        .http()
        .post(station.url(&format!(
            "/_arkret/open/invite-locators/resolve/{}",
            issued.locator_token
        )))
        .json(&InviteLocatorResolveRequestBody::new(&issued.locator_token))
        .send()
        .await?;
    ensure!(
        path.status() == StatusCode::NOT_FOUND,
        "locator token path leak was accepted"
    );
    let response = resolve(station, &issued.locator_token).await?;
    ensure!(
        response.status() == StatusCode::OK,
        "issued locator not resolved"
    );
    let locator: PrincipalLocator = response.json().await?;
    verify(station, holder, &issued, &locator)?;
    ensure!(
        locator.display_hint == Some(hint.clone()),
        "issued display hint lost"
    );
    let rotated: InviteLocatorIssueResponseBody = private_json(
        command(
            holder,
            rotate_path,
            &InviteLocatorRotateRequestBody {
                locator_id: issued.locator_id.clone(),
                ttl_seconds: None,
                one_time_use: None,
                display_hint: None,
            },
        )
        .await?,
    )
    .await?;
    ensure!(
        rotated.locator_token != issued.locator_token
            && !rotated.one_time_use
            && (rotated.expires_at - locator.issued_at).num_milliseconds() >= 60_000,
        "rotation did not preserve TTL or replace the secret"
    );
    let unknown = arkret_canonical::base64url_encode([0x5b; 24]);
    let missing = fingerprint(resolve(station, &unknown).await?).await?;
    ensure!(
        missing.0 == StatusCode::NOT_FOUND
            && fingerprint(resolve(station, &issued.locator_token).await?).await? == missing,
        "rotated locator disclosed a different absence shape"
    );
    let next: PrincipalLocator = resolve(station, &rotated.locator_token)
        .await?
        .error_for_status()?
        .json()
        .await?;
    verify(station, holder, &rotated, &next)?;
    ensure!(
        next.display_hint == Some(hint),
        "rotation lost retained display hint"
    );
    let revoke = InviteLocatorRevokeRequestBody {
        locator_id: rotated.locator_id,
    };
    let first: InviteLocatorRevokeResponseBody = command(holder, revoke_path, &revoke)
        .await?
        .error_for_status()?
        .json()
        .await?;
    let retry: InviteLocatorRevokeResponseBody = command(holder, revoke_path, &revoke)
        .await?
        .error_for_status()?
        .json()
        .await?;
    ensure!(
        first == retry
            && fingerprint(resolve(station, &rotated.locator_token).await?).await? == missing,
        "locator revoke was not idempotent or disclosed secret history"
    );
    for ttl in [59, 3601] {
        let response = command(
            holder,
            issue_path,
            &InviteLocatorIssueRequestBody {
                ttl_seconds: Some(ttl),
                ..Default::default()
            },
        )
        .await?;
        ensure!(
            response.status() == StatusCode::BAD_REQUEST,
            "out-of-range locator TTL accepted"
        );
    }
    let fresh: InviteLocatorIssueResponseBody = private_json(
        command(
            holder,
            issue_path,
            &InviteLocatorIssueRequestBody {
                ttl_seconds: Some(120),
                display_hint: Some(PrincipalLocatorDisplayHint {
                    display_name_hint: Some("Clear me".into()),
                    avatar_blob_ref: None,
                }),
                ..Default::default()
            },
        )
        .await?,
    )
    .await?;
    let one: InviteLocatorIssueResponseBody = private_json(
        command(
            holder,
            rotate_path,
            &InviteLocatorRotateRequestBody {
                locator_id: fresh.locator_id,
                ttl_seconds: Some(60),
                one_time_use: Some(true),
                display_hint: Some(None),
            },
        )
        .await?,
    )
    .await?;
    ensure!(one.one_time_use, "rotation lost one-time semantics");
    let (a, b) = tokio::try_join!(
        resolve(station, &one.locator_token),
        resolve(station, &one.locator_token)
    )?;
    let mut statuses = [a.status().as_u16(), b.status().as_u16()];
    statuses.sort();
    ensure!(
        statuses == [200, 404],
        "one-time locator did not atomically admit exactly one resolver"
    );
    let success = if a.status() == StatusCode::OK { a } else { b };
    let one_locator: PrincipalLocator = success.json().await?;
    verify(station, holder, &one, &one_locator)?;
    ensure!(
        one_locator.display_hint.is_none(),
        "explicit null did not clear locator display hint"
    );
    Ok(())
}
