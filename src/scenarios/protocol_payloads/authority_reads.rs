//! Live nonce-bound authority bundle and verified Realm stream scan.

use anyhow::{Context, Result, ensure};
use reqwest::StatusCode;
use serde_json::json;
use sha2::{Digest, Sha256};

use super::snapshot_head_disclosure::{SnapshotAuthor, snapshot_author};
use crate::scenarios::identity_test_support::actor_did_for_service_did;

/// A fresh nonce-bound authority bundle and every page of the Realm stream
/// scan come from the live Station's canonical routes, decode as the closed
/// SDK types, and verify through Garth's generation-bound replica: the bundle
/// chain and current assertion under the Station's historical did:webvh key,
/// and each page's Commit signatures and Event bindings before any head moves.
/// Tampered rows, a stale nonce, a foreign Account and an unknown Realm are
/// refused.
pub async fn live_authority_bundle_and_scan_verify_through_garth() -> Result<()> {
    let SnapshotAuthor {
        _coauth,
        server,
        author,
    } = snapshot_author("authority-bundle-scan", "authority-erin").await?;
    let bootstrap = author
        .create_realm_bootstrap_with(json!({
            "title": "Verified scan",
            "summary": "Verified scan",
            "public": false,
            "plaintext_visible_services": []
        }))
        .await?;
    let realm = bootstrap["realm_id"].as_str().context("realm_id")?;
    let realm_id = arkret_wire::RealmId::new(realm.to_owned())?;
    author.create_default_strand(realm).await?;
    let realm_stream = arkret_wire::CommitStreamRef::Realm {
        realm_id: realm_id.clone(),
    };

    let nonce = fresh_nonce(realm)?;
    let request = arkret_wire::AuthorityBundleRequest {
        realm_id: realm_id.clone(),
        nonce: nonce.clone(),
    };
    // The open route answers without a session, uncacheable, as the closed
    // bundle schema.
    let raw = server
        .http()
        .post(server.url("/_arkret/open/realm-authority/bundle"))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(arkret_canonical::canonical_json_bytes(&request)?)
        .send()
        .await?;
    if raw.status() != StatusCode::OK {
        anyhow::bail!(
            "open bundle status {}: {}",
            raw.status(),
            raw.text().await.unwrap_or_default()
        );
    }
    ensure!(
        raw.headers()
            .get(reqwest::header::CACHE_CONTROL)
            .is_some_and(|value| value == "no-store"),
        "authority bundle must be Cache-Control: no-store"
    );
    let raw_bundle: arkret_wire::RealmAuthorityBundle = raw
        .json()
        .await
        .context("open bundle must decode as the closed SDK bundle")?;
    raw_bundle.validate_for_request(&request, chrono::Utc::now())?;

    let http = author.sdk();
    let authority = garth::AuthorityClient::new(http.clone());
    let bundle = authority.resolve_authority(&request).await?;
    ensure!(
        bundle.current_service_id.as_str() == server.service_id().as_str()
            && bundle.current_generation == 0
            && bundle.authority_transitions.is_empty()
            && bundle.realm_stream_head.stream_ref == realm_stream
            && bundle.realm_stream_head.stream_position == 8,
        "bundle must bind genesis to the current nine-Commit head"
    );
    let freshness =
        arkret_identity::RealmAuthorityFreshness::new(chrono::Utc::now(), nonce.clone());
    let keys = garth::fetch_historical_station_key_directory(&http, &bundle, None, None).await?;
    let mut replica = garth::RealmReplica::new(realm_id.clone());
    replica.install_verified_authority(&request, bundle.clone(), &freshness, &keys)?;

    let stale = arkret_identity::RealmAuthorityFreshness::new(
        chrono::Utc::now(),
        fresh_nonce("another request")?,
    );
    ensure!(
        garth::RealmReplica::new(realm_id.clone())
            .install_verified_authority(&request, bundle.clone(), &stale, &keys)
            .is_err(),
        "a bundle must not verify under another request's nonce"
    );

    let mut after = None;
    let mut positions = Vec::new();
    let mut floor = None;
    loop {
        let scan = arkret_wire::StreamScanRequest {
            realm_id: realm_id.clone(),
            stream_ref: realm_stream.clone(),
            direction: arkret_wire::StreamScanDirection::After(after),
            limit: 4,
        };
        let page = authority.scan(&scan).await.context("live self scan")?;
        if after.is_none() {
            let page_keys =
                garth::fetch_historical_station_key_directory(&http, &bundle, Some(&page), None)
                    .await?;
            let mut tampered = page.clone();
            let arkret_wire::CommittedEventView::Full(first) = tampered
                .committed_events
                .get_mut(1)
                .context("second genesis-page row")?
            else {
                anyhow::bail!("the founder's own rows are disclosed in full");
            };
            first.commit.signature.signed_digest =
                arkret_wire::Hash::new(format!("sha256:{}", "f".repeat(64)))?;
            let mut untouched = garth::RealmReplica::new(realm_id.clone());
            untouched.install_verified_authority(&request, bundle.clone(), &freshness, &keys)?;
            ensure!(
                untouched
                    .apply_verified_scan(&scan, tampered, &freshness, &page_keys)
                    .is_err()
                    && untouched.verified_head(&realm_stream).is_none(),
                "a page with one bad Commit signature must not move any head"
            );
        }
        if let Some(page_floor) = &page.readable_floor {
            ensure!(
                floor.as_ref().is_none_or(|seen| seen == page_floor),
                "readable floor changed across pages"
            );
            floor = Some(page_floor.clone());
        }
        let page_keys =
            garth::fetch_historical_station_key_directory(&http, &bundle, Some(&page), None)
                .await?;
        let truncated = page.truncated;
        let verified = replica.apply_verified_scan(&scan, page, &freshness, &page_keys)?;
        positions.extend(
            verified
                .rows()
                .iter()
                .map(|item| item.commit().stream_position),
        );
        let head = replica
            .verified_head(&realm_stream)
            .context("verified page must install a head")?
            .clone();
        after = Some(head.stream_position);
        if !truncated {
            break;
        }
    }
    ensure!(
        positions == (0..=8).collect::<Vec<u64>>(),
        "verified scan must cover the whole founding chain: {positions:?}"
    );
    ensure!(
        replica.verified_head(&realm_stream) == Some(&bundle.realm_stream_head),
        "verified tail must end at the bundle's Realm head"
    );
    let floor = floor.context("the lower end must carry its readable floor")?;
    ensure!(
        floor.oldest_position == 0
            && floor.floor_reason == arkret_wire::ReadableFloorReason::StreamStart
            && floor.floor_commit_id == bundle.genesis_commit.commit_id,
        "the founder's floor is the genesis Commit"
    );

    // Registered refusals: a foreign Account has no readable interval, and a
    // Realm this Station does not govern has no bundle here.
    let stranger = server
        .demo_client(
            &actor_did_for_service_did(server.service_did(), "authority-frank")?,
            "ak:device:01904100-0000-7000-8000-0000000000a4",
        )
        .await?;
    let scan = arkret_wire::StreamScanRequest {
        realm_id: realm_id.clone(),
        stream_ref: realm_stream.clone(),
        direction: arkret_wire::StreamScanDirection::After(None),
        limit: 4,
    };
    expect_problem(
        stranger
            .post("/_arkret/self/streams/scan")
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(arkret_canonical::canonical_json_bytes(&scan)?),
        StatusCode::FORBIDDEN,
        "capability_denied",
    )
    .await?;
    let unknown = arkret_wire::AuthorityBundleRequest {
        realm_id: arkret_wire::RealmId::from_event_id(&arkret_wire::EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [0x42; 32],
        )),
        nonce,
    };
    expect_problem(
        server
            .http()
            .post(server.url("/_arkret/open/realm-authority/bundle"))
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(arkret_canonical::canonical_json_bytes(&unknown)?),
        StatusCode::FORBIDDEN,
        "capability_denied",
    )
    .await?;
    Ok(())
}

fn fresh_nonce(seed: &str) -> Result<arkret_wire::Base64UrlString> {
    use base64::Engine as _;
    let digest: [u8; 32] = Sha256::digest(
        format!(
            "{seed}:{}",
            chrono::Utc::now()
                .timestamp_nanos_opt()
                .context("nonce clock")?
        )
        .as_bytes(),
    )
    .into();
    arkret_wire::Base64UrlString::new(
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest),
    )
    .map_err(anyhow::Error::msg)
}

async fn expect_problem(
    request: reqwest::RequestBuilder,
    status: StatusCode,
    code: &str,
) -> Result<()> {
    let response = request.send().await?;
    ensure!(
        response.status() == status,
        "expected {status} {code}, got {}",
        response.status()
    );
    let body: serde_json::Value = response.json().await?;
    ensure!(
        body["type"] == format!("https://arkret.org/problems/{code}"),
        "expected {code}: {body}"
    );
    Ok(())
}
