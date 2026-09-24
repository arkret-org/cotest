use anyhow::{Context, Result, ensure};
use ed25519_dalek::SigningKey;
use reqwest::StatusCode;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::harness::{ArkretServer, TestActorClient, expect_json, expect_status};
use crate::scenarios::_helpers::bridge::MockCoauthIntrospectionServer;
use crate::scenarios::bridge_contracts::session_grant::mock_session_grant_jwt;
use crate::scenarios::identity_test_support::{
    HARNESS_INTERNAL_AUTHORITY_SECRET, actor_did_for_service_did,
    spawn_with_harness_account_authority,
};

/// A Station behind the harness Coauth plus one founding-device author whose
/// standard DPoP session grant is bound at that Coauth.
pub(super) struct SnapshotAuthor {
    pub(super) _coauth: MockCoauthIntrospectionServer,
    pub(super) server: ArkretServer,
    pub(super) author: TestActorClient,
}

pub(super) async fn snapshot_author(server_name: &str, actor: &str) -> Result<SnapshotAuthor> {
    let coauth = MockCoauthIntrospectionServer::spawn_with_internal_secret(
        HARNESS_INTERNAL_AUTHORITY_SECRET,
    )
    .await?;
    let origin = coauth.origin();
    let introspection = coauth.url();
    let server = spawn_with_harness_account_authority(
        server_name,
        &[
            ("SOLAND_ACCOUNT_AUTHORITY_URL", origin.as_str()),
            ("SOLAND_DID_RESOLVER_ALLOW_METHODS", "web,webvh,key,uuid"),
            (
                "SOLAND_SESSION_GRANT_INTROSPECTION_URL",
                introspection.as_str(),
            ),
        ],
    )
    .await?;
    let actor_id = actor_did_for_service_did(server.service_did(), actor)?;
    let client = server
        .demo_client(&actor_id, "ak:device:01904100-0000-7000-8000-0000000000a1")
        .await?;
    let principal = client.principal.as_ref().context("founding principal")?;
    let grant = mock_session_grant_jwt(
        principal.core_id.as_str(),
        principal.device_id.as_str(),
        server.service_id().as_str(),
    );
    coauth.bind_founding_device_grant(
        &grant,
        principal.core_id.as_str(),
        principal.device_id.as_str(),
        principal.founding_authorize_event_id.as_str(),
        &principal.device_signing_key.verifying_key(),
    )?;
    let author = server.client_with_founding_device_grant(principal, grant)?;
    Ok(SnapshotAuthor {
        _coauth: coauth,
        server,
        author,
    })
}

pub async fn narrow_snapshot_head_discloses_only_complete_creator_cut() -> Result<()> {
    let SnapshotAuthor {
        _coauth,
        server,
        author,
    } = snapshot_author("snapshot-head-disclosure", "snapshot-alice").await?;
    let bootstrap = author
        .create_realm_bootstrap_with(json!({
            "title": "Snapshot disclosure",
            "summary": "Snapshot disclosure",
            "public": false,
            "plaintext_visible_services": []
        }))
        .await?;
    let realm_id = bootstrap["realm_id"].as_str().context("realm_id")?;
    ensure!(
        bootstrap["event_response"]["commits"]
            .as_array()
            .is_some_and(|commits| commits.len() == 7),
        "baseline bootstrap must accept exactly seven Events: {bootstrap}"
    );
    let head_path = "/_arkret/self/realm-state-snapshot/head";
    let genesis_snapshot = expect_json(
        author.get(head_path).query(&[("realm_id", realm_id)]),
        StatusCode::OK,
    )
    .await?;
    let genesis_typed: arkret_wire::RealmStateSnapshot =
        serde_json::from_value(genesis_snapshot.clone())
            .context("seven-Commit head must be a signed wire snapshot")?;
    ensure!(
        genesis_typed.visible_stream_heads.len() == 1
            && genesis_typed.visible_stream_heads[0].stream_position == 6
            && genesis_typed.current_state_entries.len() == 8,
        "seven-Commit creator cut is incomplete: {genesis_snapshot}"
    );
    verify_test_notary_snapshot(&genesis_typed)?;
    // The head was issued at its cut: the exact original object is now
    // readable by reference, byte-for-byte, and never re-signed.
    let genesis_by_ref = read_by_ref(&author, &genesis_typed.snapshot_id, realm_id).await?;
    ensure_same_object(&genesis_typed, &genesis_by_ref)?;
    author.create_default_strand(realm_id).await?;
    let snapshot = expect_json(
        author.get(head_path).query(&[("realm_id", realm_id)]),
        StatusCode::OK,
    )
    .await?;
    let typed: arkret_wire::RealmStateSnapshot = serde_json::from_value(snapshot.clone())
        .context("head must be the complete signed wire snapshot")?;
    ensure!(
        typed.realm_id.as_str() == realm_id,
        "wrong Realm in snapshot: {snapshot}"
    );
    ensure!(
        typed.visible_stream_heads[0].stream_position == 8,
        "creator cut must include bootstrap, Strand create, and default-Strand Commit: {snapshot}"
    );
    ensure!(
        typed.current_state_entries.len() == 10,
        "creator cut must disclose all ten typed current results: {snapshot}"
    );
    ensure!(
        snapshot["visible_stream_heads"]
            .as_array()
            .is_some_and(|heads| heads.len() == 1),
        "single-stream creator cut omitted or added a stream head: {snapshot}"
    );
    ensure!(
        snapshot["retention_and_history_floor"]["stream_floors"]
            .as_array()
            .is_some_and(|floors| floors.len() == 1),
        "creator cut omitted its history floor: {snapshot}"
    );
    ensure!(
        snapshot["signature"].is_object(),
        "unsigned snapshot: {snapshot}"
    );
    verify_test_notary_snapshot(&typed)?;
    // A newer head does not replace the earlier exact reference: both stay
    // readable while the creator's join revision is unchanged.
    ensure!(
        typed.snapshot_id != genesis_typed.snapshot_id,
        "a later cut must be a distinct exact snapshot"
    );
    ensure_same_object(
        &genesis_typed,
        &read_by_ref(&author, &genesis_typed.snapshot_id, realm_id).await?,
    )?;
    ensure_same_object(
        &typed,
        &read_by_ref(&author, &typed.snapshot_id, realm_id).await?,
    )?;
    let never_issued = arkret_wire::RealmSnapshotId::from_digest([0x5a; 32]);
    expect_status(
        by_ref_request(&author, &never_issued, realm_id),
        StatusCode::SERVICE_UNAVAILABLE,
    )
    .await?;
    let stranger = server
        .demo_client(
            &actor_did_for_service_did(server.service_did(), "snapshot-mallory")?,
            "ak:device:01904100-0000-7000-8000-0000000000a2",
        )
        .await?;
    // Every authorization failure of the exact read is the universal
    // capability_denied surface; the operation registers no not_found.
    expect_status(
        by_ref_request(&stranger, &genesis_typed.snapshot_id, realm_id),
        StatusCode::FORBIDDEN,
    )
    .await?;

    let with_plaintext = author
        .create_realm_with(json!({
            "title": "Extra current family",
            "summary": "Extra current family",
            "public": false,
            "plaintext_visible_services": [server.service_id()]
        }))
        .await?;
    let with_plaintext_id = with_plaintext["realm_id"]
        .as_str()
        .context("plaintext Realm id")?;
    ensure!(
        with_plaintext["event_response"]["commits"]
            .as_array()
            .is_some_and(|commits| commits.len() == 8),
        "facet bootstrap must accept eight Events before the Strand pair: {with_plaintext}"
    );
    expect_status(
        author
            .get(head_path)
            .query(&[("realm_id", with_plaintext_id)]),
        StatusCode::SERVICE_UNAVAILABLE,
    )
    .await?;
    // An exact ref is bound to its Realm: naming it under another Realm the
    // caller can read is unavailable, never a substitute object.
    expect_status(
        by_ref_request(&author, &genesis_typed.snapshot_id, with_plaintext_id),
        StatusCode::SERVICE_UNAVAILABLE,
    )
    .await?;
    Ok(())
}

/// A Snapshot issued at `/head` is read back through Garth's typed by-ref
/// client only because the live describe advertises the exact-read bundle,
/// byte-identical to the issued object even after the Realm moves on, and its
/// signature verifies under the Station key taken from the Station's complete
/// live did:webvh history at the Snapshot's signing time (no test constant,
/// no current document). Registered refusals surface as typed Garth refusals.
///
/// The fresh authority bundle and verified Realm tail over the same live
/// Station are exercised by `authority_reads`.
pub async fn exact_snapshot_by_ref_reads_through_garth_with_historical_station_key() -> Result<()> {
    let SnapshotAuthor {
        _coauth,
        server,
        author,
    } = snapshot_author("snapshot-by-ref-typed", "snapshot-carol").await?;
    let bootstrap = author
        .create_realm_bootstrap_with(json!({
            "title": "Snapshot by ref",
            "summary": "Snapshot by ref",
            "public": false,
            "plaintext_visible_services": []
        }))
        .await?;
    let realm = bootstrap["realm_id"].as_str().context("realm_id")?;
    let realm_id = arkret_wire::RealmId::new(realm.to_owned())?;
    let issued: arkret_wire::RealmStateSnapshot = serde_json::from_value(
        expect_json(
            author
                .get("/_arkret/self/realm-state-snapshot/head")
                .query(&[("realm_id", realm)]),
            StatusCode::OK,
        )
        .await?,
    )
    .context("issued head must be a closed signed snapshot")?;
    // The earlier exact reference stays readable after the Realm moves on.
    author.create_default_strand(realm).await?;

    let http = author.sdk();
    let describe = http
        .describe_for_role(arkret_wire::ServiceKind::Station)
        .await
        .context("live Station describe")?;
    ensure!(
        garth::exact_snapshot_read_advertised(&describe),
        "live Station must advertise the exact snapshot read bundle"
    );
    let authority = garth::AuthorityClient::new(http.clone());
    let snapshot = authority
        .exact_snapshot(&describe, &realm_id, &issued.snapshot_id)
        .await
        .context("typed by-ref read")?;
    ensure_same_object(&issued, &snapshot)?;

    let signer_did =
        arkret_identity::verification_method_did(snapshot.signature.verification_method.as_str())?;
    ensure!(
        signer_did.as_str().starts_with("did:webvh:"),
        "the Station must sign with a method-native historical DID: {signer_did}"
    );
    let signer_id = arkret_wire::project_did_to_core_id(&signer_did)?;
    ensure!(
        signer_id.as_str() == server.service_id().as_str(),
        "the Snapshot signer must be the governing Station"
    );
    let resolution = http
        .open_service_resolution(&signer_id)
        .await
        .context("live Station service resolution")?;
    let document = arkret_identity::authenticated_service_document_at(
        &resolution,
        &signer_id,
        snapshot.signature.created_at,
    )
    .context("Station history at the Snapshot signing time")?;
    arkret_identity::validate_verification_method_relationship(
        &document,
        &snapshot.signature.verification_method,
        &signer_did,
        arkret_identity::DidVerificationRelationship::AssertionMethod,
    )?;
    let key = arkret_identity::resolve_verification_method_key_from_document(
        &document,
        snapshot.signature.verification_method.as_str(),
    )?
    .public_key;
    let unsigned = arkret_canonical::unsigned_value(&snapshot, &["signature"])?;
    arkret_signatures::detached_object::verify_detached_object_signature(
        &snapshot.signature,
        &unsigned,
        arkret_wire::DetachedSignatureContext::RealmSnapshot,
        &key,
    )
    .context("Snapshot must verify under the historical Station key")?;
    let mut tampered = snapshot.clone();
    tampered.signature.signed_digest =
        arkret_wire::Hash::new(format!("sha256:{}", "f".repeat(64)))?;
    ensure!(
        arkret_signatures::detached_object::verify_detached_object_signature(
            &tampered.signature,
            &arkret_canonical::unsigned_value(&tampered, &["signature"])?,
            arkret_wire::DetachedSignatureContext::RealmSnapshot,
            &key,
        )
        .is_err(),
        "a tampered by-ref object must not verify"
    );
    ensure!(
        arkret_identity::authenticated_service_document_at(
            &resolution,
            &signer_id,
            snapshot.signature.created_at - chrono::Duration::days(3650),
        )
        .is_err(),
        "no Station key exists before the Station's inception"
    );

    let never_issued = arkret_wire::RealmSnapshotId::from_digest([0x5b; 32]);
    let unavailable = authority
        .exact_snapshot(&describe, &realm_id, &never_issued)
        .await
        .unwrap_err();
    ensure!(
        matches!(
            unavailable,
            garth::Error::ExactSnapshotRefused(garth::ExactSnapshotRefusal::Unavailable)
        ),
        "never-issued ref must be the registered unavailable refusal: {unavailable}"
    );
    let stranger = server
        .demo_client(
            &actor_did_for_service_did(server.service_did(), "snapshot-dave")?,
            "ak:device:01904100-0000-7000-8000-0000000000a3",
        )
        .await?;
    let hidden = garth::AuthorityClient::new(stranger.sdk())
        .exact_snapshot(&describe, &realm_id, &snapshot.snapshot_id)
        .await
        .unwrap_err();
    ensure!(
        matches!(
            hidden,
            garth::Error::ExactSnapshotRefused(garth::ExactSnapshotRefusal::CapabilityDenied)
        ),
        "another Account must receive the universal capability_denied refusal: {hidden}"
    );
    let mut unadvertised = describe.clone();
    unadvertised
        .supported_operation_bundles
        .retain(|bundle| bundle != "ak.operation_bundle.station.snapshot_exact_read.v1");
    let not_advertised = authority
        .exact_snapshot(&unadvertised, &realm_id, &snapshot.snapshot_id)
        .await
        .unwrap_err();
    ensure!(
        matches!(
            not_advertised,
            garth::Error::ExactSnapshotRefused(garth::ExactSnapshotRefusal::NotAdvertised)
        ),
        "without the advertised bundle the by-ref read must not be attempted"
    );
    Ok(())
}

/// One fresh Account subscribe with a Realm-detail filter; returns the whole
/// first frame after it passes the SDK's closed frame contract.
async fn account_detail_frame(
    client: &crate::harness::TestActorClient,
    filter: serde_json::Value,
) -> Result<arkret_models_collaboration::sync_frames::account_subscribe::AccountSubscribeFrame> {
    let filter = String::from_utf8(arkret_canonical::canonical_json_bytes(&filter)?)?;
    let response = client
        .get("/_arkret/self/account/subscribe")
        .query(&[("filter", filter.as_str())])
        .send()
        .await?;
    let status = response.status();
    let body = response.text().await?;
    ensure!(
        status == StatusCode::OK,
        "account subscribe {status}: {body}"
    );
    let line = body
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .context("account subscribe returned no frame")?;
    let frame: arkret_models_collaboration::sync_frames::account_subscribe::AccountSubscribeFrame =
        serde_json::from_str(line).with_context(|| format!("closed Account frame: {line}"))?;
    frame
        .validate()
        .map_err(|error| anyhow::anyhow!("Account frame contract: {error}: {line}"))?;
    Ok(frame)
}

fn realm_detail(
    frame: &arkret_models_collaboration::sync_frames::account_subscribe::AccountSubscribeFrame,
    realm_id: &str,
) -> Result<arkret_models_collaboration::sync_frames::account_subscribe::RealmSyncEntry> {
    ensure!(
        frame.kind
            == arkret_models_collaboration::sync_frames::account_subscribe::AccountSubscribeFrameKind::Delta,
        "Realm detail must arrive in a delta frame: {:?}",
        frame.kind
    );
    frame
        .realms
        .as_ref()
        .and_then(|realms| realms.entries.get(realm_id))
        .cloned()
        .context("the requested Realm detail is absent")
}

fn window_positions(
    entry: &arkret_models_collaboration::sync_frames::account_subscribe::RealmSyncEntry,
) -> Vec<u64> {
    entry
        .committed_events
        .iter()
        .flatten()
        .map(|row| row.commit().stream_position)
        .collect()
}

/// Fresh Soland + real PostgreSQL: an Account frame filtered to one Realm with
/// a limited `window_limit` names an `after_committed_prefix` basis only when
/// `/head` already issued the exact snapshot at the window's anchor; that
/// `snapshot_ref` reads back by reference as the same signed object. Without
/// a prior issuance the limited window is `preview_only` with no basis. The
/// retired `timeline_limit` member and an unprovable Circle selection are
/// refused rather than degraded.
pub async fn limited_account_window_names_issued_basis_or_is_preview_only() -> Result<()> {
    use arkret_models_collaboration::sync_frames::account_sync::StreamWindowAnchorKind;

    let SnapshotAuthor {
        _coauth,
        server: _server,
        author,
    } = snapshot_author("account-window-basis", "window-erin").await?;
    let bootstrap = author
        .create_realm_bootstrap_with(json!({
            "title": "Window basis",
            "summary": "Window basis",
            "public": false,
            "plaintext_visible_services": []
        }))
        .await?;
    let realm_id = bootstrap["realm_id"]
        .as_str()
        .context("realm_id")?
        .to_owned();
    let issued: arkret_wire::RealmStateSnapshot = serde_json::from_value(
        expect_json(
            author
                .get("/_arkret/self/realm-state-snapshot/head")
                .query(&[("realm_id", realm_id.as_str())]),
            StatusCode::OK,
        )
        .await?,
    )
    .context("issued head must be a closed signed snapshot")?;
    let anchor = issued
        .visible_stream_heads
        .first()
        .cloned()
        .context("issued head names its stream head")?;
    ensure!(anchor.stream_position == 6, "bootstrap head is position 6");
    author.create_default_strand(&realm_id).await?;

    let frame =
        account_detail_frame(&author, json!({"realm_ids": [realm_id], "window_limit": 2})).await?;
    let entry = realm_detail(&frame, &realm_id)?;
    let [window] = entry.streams.as_deref().context("stream windows")? else {
        anyhow::bail!("a single-member Realm has exactly its Realm stream window");
    };
    ensure!(
        window.limited && window.complete && window.window_limit == 2,
        "the limited window must be complete at its own ceiling: {window:?}"
    );
    ensure!(window.next_position == 9, "window head is position 8");
    ensure!(
        window.preview_only.is_none(),
        "an exact reserved basis is not preview: {window:?}"
    );
    let basis = window
        .window_start_basis
        .as_ref()
        .context("an issued anchor snapshot yields a basis")?;
    ensure!(
        basis.anchor_kind == StreamWindowAnchorKind::AfterCommittedPrefix
            && basis.anchor_position == Some(anchor.stream_position)
            && basis.anchor_commit_ref.as_ref() == Some(&anchor.commit_id)
            && basis.snapshot_ref == issued.snapshot_id
            && basis.governance_generation == issued.governance_generation,
        "the basis must name the exact issued anchor snapshot: {basis:?}"
    );
    ensure!(
        window_positions(&entry) == vec![7, 8],
        "the window delivers the last two Commits"
    );
    let first = entry
        .committed_events
        .as_ref()
        .and_then(|rows| rows.first())
        .context("window rows")?;
    ensure!(
        first.commit().previous_commit_ref.as_ref() == Some(&anchor.commit_id),
        "the first window row continues the basis anchor"
    );
    ensure!(
        entry.window_snapshot_cursor.is_some(),
        "the frozen window names its identity"
    );
    let current = entry.current.as_ref().context("same-cut current")?;
    ensure!(
        current.realm_id.as_str() == realm_id
            && current.governance_generation == issued.governance_generation
            && current.stream_heads.len() == 1
            && current.stream_heads[0].stream_position == 8
            && current.stream_heads[0].commit_id == window.head_commit_ref,
        "current must be the window head cut: {current:?}"
    );
    // The basis reads back by reference as the exact issued signed object.
    // (This Station's notary seed is not the one `read_by_ref` pins, so the
    // exact-object comparison against the verified `/head` body stands in.)
    let by_ref: arkret_wire::RealmStateSnapshot = serde_json::from_value(
        expect_json(
            by_ref_request(&author, &basis.snapshot_ref, &realm_id),
            StatusCode::OK,
        )
        .await?,
    )
    .context("by-ref body must be a closed signed snapshot")?;
    ensure_same_object(&issued, &by_ref)?;
    // The window's current equals the signed current of a fresh head at 8.
    let at_head: arkret_wire::RealmStateSnapshot = serde_json::from_value(
        expect_json(
            author
                .get("/_arkret/self/realm-state-snapshot/head")
                .query(&[("realm_id", realm_id.as_str())]),
            StatusCode::OK,
        )
        .await?,
    )?;
    ensure!(
        at_head.current_state_entries == current.entries,
        "window current differs from the signed head current at the same cut"
    );

    // The whole readable history fits: not limited, no basis needed.
    let whole = realm_detail(
        &account_detail_frame(&author, json!({"realm_ids": [realm_id]})).await?,
        &realm_id,
    )?;
    let whole_window = &whole.streams.as_deref().context("window")?[0];
    ensure!(
        !whole_window.limited
            && whole_window.preview_only.is_none()
            && whole_window.window_start_basis.is_none()
            && window_positions(&whole) == (0..=8).collect::<Vec<_>>(),
        "default window_limit 20 delivers the whole stream: {whole_window:?}"
    );

    // No snapshot was ever issued for this Realm: preview only.
    let unissued = author
        .create_realm_bootstrap_with(json!({
            "title": "Window preview",
            "summary": "Window preview",
            "public": false,
            "plaintext_visible_services": []
        }))
        .await?;
    let unissued_id = unissued["realm_id"]
        .as_str()
        .context("realm_id")?
        .to_owned();
    author.create_default_strand(&unissued_id).await?;
    let preview = realm_detail(
        &account_detail_frame(
            &author,
            json!({
                "realm_ids": [unissued_id],
                "stream_refs": [{"kind": "realm", "realm_id": unissued_id}],
                "window_limit": 2
            }),
        )
        .await?,
        &unissued_id,
    )?;
    let preview_window = &preview.streams.as_deref().context("window")?[0];
    ensure!(
        preview_window.limited
            && preview_window.preview_only == Some(true)
            && preview_window.window_start_basis.is_none()
            && window_positions(&preview) == vec![7, 8],
        "a limited window without an issued anchor is preview only: {preview_window:?}"
    );

    // An unprovable Circle selection is refused, not silently dropped.
    let circle = arkret_wire::CircleId::from_event_id(&arkret_wire::EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        [0x5c; 32],
    ));
    let refused = realm_detail(
        &account_detail_frame(
            &author,
            json!({
                "realm_ids": [realm_id],
                "stream_refs": [{"kind": "circle", "realm_id": realm_id, "circle_id": circle}]
            }),
        )
        .await?,
        &realm_id,
    )?;
    ensure!(
        refused.streams.is_none()
            && refused.unavailable.is_some_and(|unavailable| {
                unavailable.error_code
                    == arkret_models_collaboration::sync_frames::demand_sync::RealmDetailErrorCode::TemporarilyUnavailable
            }),
        "an unserved Circle selection is an explicit unavailable detail"
    );

    // The retired filter member has no alias.
    let retired = String::from_utf8(arkret_canonical::canonical_json_bytes(
        &json!({"realm_ids": [realm_id], "timeline_limit": 2}),
    )?)?;
    expect_status(
        author
            .get("/_arkret/self/account/subscribe")
            .query(&[("filter", retired.as_str())]),
        StatusCode::BAD_REQUEST,
    )
    .await?;
    Ok(())
}

/// Every frame of one bounded Account subscribe, each past the SDK's closed
/// frame contract.
async fn account_detail_frames(
    client: &crate::harness::TestActorClient,
    filter: &serde_json::Value,
    after: Option<&str>,
) -> Result<Vec<arkret_models_collaboration::sync_frames::account_subscribe::AccountSubscribeFrame>>
{
    let filter = String::from_utf8(arkret_canonical::canonical_json_bytes(filter)?)?;
    let mut query = vec![("filter", filter.as_str())];
    if let Some(after) = after {
        query.push(("after", after));
    }
    let response = client
        .get("/_arkret/self/account/subscribe")
        .query(&query)
        .send()
        .await?;
    let status = response.status();
    let body = response.text().await?;
    ensure!(
        status == StatusCode::OK,
        "account subscribe {status}: {body}"
    );
    body.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(|line| {
            let frame: arkret_models_collaboration::sync_frames::account_subscribe::AccountSubscribeFrame =
                serde_json::from_str(line).with_context(|| format!("closed Account frame: {line}"))?;
            frame
                .validate()
                .map_err(|error| anyhow::anyhow!("Account frame contract: {error}: {line}"))?;
            Ok(frame)
        })
        .collect()
}

/// Fresh Soland + real PostgreSQL, one Account batch over two Realms with a
/// limited `window_limit`: a Realm with more Commits than the window and no
/// issued anchor snapshot arrives `preview_only`, beside a Realm whose whole
/// history fits. Inkson's Account frame verifier must not reject the batch:
/// it backfills the preview stream with a verified replay from genesis over
/// the live scan and authority bundle and only then treats that stream as
/// exact, while the sibling Realm verifies as ordinary full history. A forged
/// preview row still fails closed.
///
/// Soland currently proves Account windows only for the single-member
/// bootstrap cut (seven or nine Commits), so the product's 20-row window
/// cannot be exceeded live yet; `window_limit` 8 produces the same shape.
pub async fn preview_account_window_backfills_without_failing_its_sibling_realm() -> Result<()> {
    let SnapshotAuthor {
        _coauth,
        server: _server,
        author,
    } = snapshot_author("account-window-preview-backfill", "window-frank").await?;
    let bootstrap = |title: &str| {
        json!({
            "title": title,
            "summary": title,
            "public": false,
            "plaintext_visible_services": []
        })
    };
    let preview_id = author
        .create_realm_bootstrap_with(bootstrap("Preview backfill"))
        .await?["realm_id"]
        .as_str()
        .context("preview realm_id")?
        .to_owned();
    author.create_default_strand(&preview_id).await?;
    let sibling_id = author
        .create_realm_bootstrap_with(bootstrap("Verified sibling"))
        .await?["realm_id"]
        .as_str()
        .context("sibling realm_id")?
        .to_owned();

    // Soland answers one Realm detail per subscribe turn; continue on the
    // returned cursor until both details arrived, as one projected batch.
    let filter = json!({"realm_ids": [preview_id, sibling_id], "window_limit": 8});
    let mut batch = Vec::new();
    let mut after: Option<String> = None;
    for _ in 0..4 {
        for frame in account_detail_frames(&author, &filter, after.as_deref()).await? {
            after = frame.cursor.clone().or(after);
            batch.push(frame);
        }
        let seen = |realm: &str| {
            batch.iter().any(|frame| {
                frame
                    .realms
                    .as_ref()
                    .is_some_and(|realms| realms.entries.contains_key(realm))
            })
        };
        if seen(&preview_id) && seen(&sibling_id) {
            break;
        }
    }
    let frame_of = |realm: &str| {
        batch
            .iter()
            .find(|frame| {
                frame
                    .realms
                    .as_ref()
                    .is_some_and(|realms| realms.entries.contains_key(realm))
            })
            .with_context(|| format!("the Account batch carries the {realm} detail"))
    };
    let preview_frame = frame_of(&preview_id)?;
    let sibling_frame = frame_of(&sibling_id)?;
    let preview = realm_detail(preview_frame, &preview_id)?;
    let preview_window = &preview
        .streams
        .as_deref()
        .with_context(|| format!("preview window: {preview:?}"))?[0];
    ensure!(
        preview_window.limited
            && preview_window.preview_only == Some(true)
            && preview_window.window_start_basis.is_none()
            && window_positions(&preview) == (1..=8).collect::<Vec<_>>()
            && preview.current.is_some(),
        "a limited window without an issued anchor is preview only: {preview_window:?}"
    );
    let sibling = realm_detail(sibling_frame, &sibling_id)?;
    let sibling_window = &sibling
        .streams
        .as_deref()
        .with_context(|| format!("sibling window: {sibling:?}"))?[0];
    ensure!(
        !sibling_window.limited
            && sibling_window.preview_only.is_none()
            && window_positions(&sibling) == (0..=6).collect::<Vec<_>>(),
        "the seven-Commit sibling fits its window: {sibling_window:?}"
    );

    let http = author.sdk();
    // Inkson verifies every frame of the batch before projecting any; a
    // preview frame must not reject the batch.
    let mut verified = Vec::new();
    for frame in &batch {
        verified.push(
            inkson::realm_events_engine::verify_account_frame_commits(&http, frame)
                .await
                .context("a preview window must not fail the Account batch")?,
        );
    }
    let proof_of = |target: &arkret_models_collaboration::sync_frames::account_subscribe::AccountSubscribeFrame| {
        batch
            .iter()
            .position(|frame| std::ptr::eq(frame, target))
            .map(|index| &verified[index])
            .context("verified frame")
    };
    let sibling_proof = proof_of(sibling_frame)?;
    let verified = proof_of(preview_frame)?;
    let preview_stream = arkret_wire::CommitStreamRef::Realm {
        realm_id: arkret_wire::RealmId::new(preview_id.clone())?,
    };
    let sibling_stream = arkret_wire::CommitStreamRef::Realm {
        realm_id: arkret_wire::RealmId::new(sibling_id.clone())?,
    };
    ensure!(
        verified.preview_streams().is_empty()
            && verified.resolved_preview_streams()
                == &std::collections::BTreeSet::from([preview_stream.clone()]),
        "the creator's genesis replay settles the preview stream as exact"
    );
    let positions = |stream: &arkret_wire::CommitStreamRef| {
        verified
            .pages()
            .iter()
            .chain(sibling_proof.pages())
            .flat_map(|page| page.rows())
            .filter(|row| &row.commit().stream_ref == stream)
            .map(|row| row.commit().stream_position)
            .collect::<Vec<_>>()
    };
    ensure!(
        positions(&preview_stream) == (0..=8).collect::<Vec<_>>()
            && positions(&sibling_stream) == (0..=6).collect::<Vec<_>>(),
        "both streams are verified from genesis through their window heads"
    );
    ensure!(
        sibling_proof.preview_streams().is_empty()
            && sibling_proof.resolved_preview_streams().is_empty(),
        "the full-history sibling has no preview stream"
    );
    ensure!(
        realm_detail(&verified.product_frame(preview_frame), &preview_id)?.current
            == preview.current
            && realm_detail(&sibling_proof.product_frame(sibling_frame), &sibling_id)?.current
                == sibling.current,
        "a backfilled preview stream keeps its same-cut current"
    );

    let mut forged = preview_frame.clone();
    let rows = forged
        .realms
        .as_mut()
        .and_then(|realms| realms.entries.get_mut(&preview_id))
        .and_then(|entry| entry.committed_events.as_mut())
        .context("preview rows")?;
    let arkret_wire::CommittedEventView::Full(row) = &mut rows[0] else {
        anyhow::bail!("the creator reads full preview rows");
    };
    row.commit.commit_id = arkret_wire::RealmCommitId::from_digest([0x5d; 32]);
    let Err(error) =
        inkson::realm_events_engine::verify_account_frame_commits(&http, &forged).await
    else {
        anyhow::bail!("a forged preview row must fail closed");
    };
    ensure!(
        error
            .to_string()
            .contains("differs from verified stream row"),
        "forged preview row failed for another reason: {error}"
    );
    Ok(())
}

/// Fresh Soland + real PostgreSQL, the live floor-tail shape: `/head` signs
/// the seven-Commit creator bootstrap, the creator then adds a default
/// Strand (StrandCreate + `ak.realm.set_default_strand`), and a
/// `window_limit` 2 Account window names that issued snapshot as its
/// `after_committed_prefix` basis. Inkson's Account frame verifier reads the
/// basis by reference through Garth, verifies the two-Commit tail and folds
/// it through the typed Strand and default-Strand reducers to exactly the
/// Station's same-cut current (the signed `/head` at the window head),
/// without failing the frame. A current that contradicts the fold still
/// fails closed.
pub async fn limited_window_strand_tail_folds_to_exact_current_through_inkson() -> Result<()> {
    use arkret_models_collaboration::sync_frames::account_sync::StreamWindowAnchorKind;

    let SnapshotAuthor {
        _coauth,
        server: _server,
        author,
    } = snapshot_author("account-window-strand-tail", "window-grace").await?;
    let bootstrap = author
        .create_realm_bootstrap_with(json!({
            "title": "Strand tail",
            "summary": "Strand tail",
            "public": false,
            "plaintext_visible_services": []
        }))
        .await?;
    let realm_id = bootstrap["realm_id"]
        .as_str()
        .context("realm_id")?
        .to_owned();
    let issued: arkret_wire::RealmStateSnapshot = serde_json::from_value(
        expect_json(
            author
                .get("/_arkret/self/realm-state-snapshot/head")
                .query(&[("realm_id", realm_id.as_str())]),
            StatusCode::OK,
        )
        .await?,
    )
    .context("issued head must be a closed signed snapshot")?;
    ensure!(
        issued.visible_stream_heads.len() == 1
            && issued.visible_stream_heads[0].stream_position == 6,
        "bootstrap head is position 6"
    );
    let strand_id = author.create_default_strand(&realm_id).await?;

    let frame =
        account_detail_frame(&author, json!({"realm_ids": [realm_id], "window_limit": 2})).await?;
    let entry = realm_detail(&frame, &realm_id)?;
    let [window] = entry.streams.as_deref().context("stream windows")? else {
        anyhow::bail!("a single-member Realm has exactly its Realm stream window");
    };
    ensure!(
        window.preview_only.is_none()
            && window.window_start_basis.as_ref().is_some_and(|basis| {
                basis.anchor_kind == StreamWindowAnchorKind::AfterCommittedPrefix
                    && basis.snapshot_ref == issued.snapshot_id
            })
            && window_positions(&entry) == vec![7, 8],
        "the window must name the issued anchor and carry the Strand tail: {window:?}"
    );
    let current = entry.current.as_ref().context("same-cut current")?;

    let http = author.sdk();
    let verified = inkson::realm_events_engine::verify_account_frame_commits(&http, &frame)
        .await
        .context("a StrandCreate/default-Strand tail must fold, not fail the frame")?;
    let typed_realm = arkret_wire::RealmId::new(realm_id.clone())?;
    let stream = arkret_wire::CommitStreamRef::Realm {
        realm_id: typed_realm.clone(),
    };
    ensure!(
        verified.unresolved_streams().is_empty() && verified.preview_streams().is_empty(),
        "the snapshot window settles as exact"
    );
    ensure!(
        verified
            .pages()
            .iter()
            .flat_map(|page| page.rows())
            .filter(|row| row.commit().stream_ref == stream)
            .map(|row| row.commit().stream_position)
            .collect::<Vec<_>>()
            == vec![7, 8],
        "the verified tail is exactly the two Commits after the issued head"
    );
    let folded = verified
        .floor_current(&typed_realm)
        .context("the verified floor and tail install an exact current")?;
    ensure!(
        folded.len() == 10 && folded == current.entries.as_slice(),
        "the installed current must be the Station's same-cut current: {folded:?}"
    );
    let strand = arkret_wire::StrandId::new(strand_id)?;
    ensure!(
        folded.iter().any(|row| matches!(
            row,
            arkret_wire::TypedCurrentResult::Value {
                selector: arkret_wire::CurrentSelector::RealmSetDefaultStrand,
                value,
                ..
            } if value == &json!({"default_strand_id": strand})
        )) && folded.iter().any(|row| matches!(
            row,
            arkret_wire::TypedCurrentResult::Value {
                selector: arkret_wire::CurrentSelector::Strand { strand_id },
                ..
            } if strand_id == &strand
        )),
        "the fold must carry the new Strand and the default pointer"
    );
    let at_head: arkret_wire::RealmStateSnapshot = serde_json::from_value(
        expect_json(
            author
                .get("/_arkret/self/realm-state-snapshot/head")
                .query(&[("realm_id", realm_id.as_str())]),
            StatusCode::OK,
        )
        .await?,
    )?;
    ensure!(
        at_head.current_state_entries.len() == folded.len()
            && folded
                .iter()
                .all(|row| at_head.current_state_entries.contains(row)),
        "the fold must equal the signed head current at the window head"
    );
    ensure!(
        realm_detail(&verified.product_frame(&frame), &realm_id)?.current == entry.current,
        "the exact window keeps its same-cut current"
    );

    let mut forged = frame.clone();
    forged
        .realms
        .as_mut()
        .and_then(|realms| realms.entries.get_mut(&realm_id))
        .and_then(|entry| entry.current.as_mut())
        .context("forged current")?
        .entries
        .pop();
    let Err(error) =
        inkson::realm_events_engine::verify_account_frame_commits(&http, &forged).await
    else {
        anyhow::bail!("a current that contradicts the verified fold must fail closed");
    };
    ensure!(
        error
            .to_string()
            .contains("verified floor and readable tail"),
        "forged current failed for another reason: {error}"
    );
    Ok(())
}

fn by_ref_request(
    client: &crate::harness::TestActorClient,
    snapshot_id: &arkret_wire::RealmSnapshotId,
    realm_id: &str,
) -> reqwest::RequestBuilder {
    client
        .get(&format!(
            "/_arkret/self/realm-state-snapshot/{}",
            snapshot_id.as_str()
        ))
        .query(&[("realm_id", realm_id)])
}

async fn read_by_ref(
    client: &crate::harness::TestActorClient,
    snapshot_id: &arkret_wire::RealmSnapshotId,
    realm_id: &str,
) -> Result<arkret_wire::RealmStateSnapshot> {
    let body = expect_json(
        by_ref_request(client, snapshot_id, realm_id),
        StatusCode::OK,
    )
    .await?;
    let snapshot: arkret_wire::RealmStateSnapshot =
        serde_json::from_value(body).context("by-ref body must be a closed signed snapshot")?;
    ensure!(
        &snapshot.snapshot_id == snapshot_id && snapshot.realm_id.as_str() == realm_id,
        "by-ref response IDs differ from the request"
    );
    verify_test_notary_snapshot(&snapshot)?;
    Ok(snapshot)
}

fn ensure_same_object(
    issued: &arkret_wire::RealmStateSnapshot,
    read: &arkret_wire::RealmStateSnapshot,
) -> Result<()> {
    ensure!(
        arkret_canonical::canonical_json_bytes(issued)?
            == arkret_canonical::canonical_json_bytes(read)?,
        "by-ref must return the exact issued signed object"
    );
    Ok(())
}

fn verify_test_notary_snapshot(snapshot: &arkret_wire::RealmStateSnapshot) -> Result<()> {
    let seed: [u8; 32] = Sha256::digest(b"cotest:notary:snapshot-head-disclosure").into();
    let public_key = arkret_signatures::PublicKeyMaterial::Ed25519Raw {
        bytes: SigningKey::from_bytes(&seed)
            .verifying_key()
            .to_bytes()
            .to_vec(),
    };
    let unsigned = arkret_canonical::unsigned_value(snapshot, &["signature"])?;
    arkret_signatures::detached_object::verify_detached_object_signature(
        &snapshot.signature,
        &unsigned,
        arkret_wire::DetachedSignatureContext::RealmSnapshot,
        &public_key,
    )
    .context("Snapshot detached signature does not verify against the test Station notary")?;
    let mut identity = serde_json::to_value(snapshot)?;
    let object = identity
        .as_object_mut()
        .context("Snapshot identity object")?;
    object.remove("signature");
    object.remove("snapshot_id");
    let derived = arkret_wire::RealmSnapshotId::from_digest(arkret_canonical::sha256_bytes(
        &arkret_canonical::canonical_json_bytes(&identity)?,
    ));
    ensure!(
        snapshot.snapshot_id == derived,
        "Snapshot ID does not address its canonical identity body"
    );
    Ok(())
}
