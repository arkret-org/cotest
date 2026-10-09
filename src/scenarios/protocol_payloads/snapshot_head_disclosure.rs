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
pub struct SnapshotAuthor {
    pub _coauth: MockCoauthIntrospectionServer,
    pub server: ArkretServer,
    pub author: TestActorClient,
}

pub async fn snapshot_author(server_name: &str, actor: &str) -> Result<SnapshotAuthor> {
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
    // The optional plaintext-services facet is a disclosed Realm singleton:
    // eight bootstrap Commits plus the Strand pair are a complete cut.
    let facet_snapshot = expect_json(
        author
            .get(head_path)
            .query(&[("realm_id", with_plaintext_id)]),
        StatusCode::OK,
    )
    .await?;
    let facet_typed: arkret_wire::RealmStateSnapshot =
        serde_json::from_value(facet_snapshot.clone())
            .context("facet head must be a signed wire snapshot")?;
    ensure!(
        facet_typed.visible_stream_heads.len() == 1
            && facet_typed.visible_stream_heads[0].stream_position == 9
            && facet_typed.current_state_entries.len() == 11
            && facet_typed.current_state_entries.iter().any(|row| matches!(
                row,
                arkret_wire::TypedCurrentRow::Value {
                    selector: arkret_wire::CurrentSelector::RealmPlaintextVisibleServices,
                    ..
                }
            )),
        "facet cut must disclose the plaintext-services row: {facet_snapshot}"
    );
    verify_test_notary_snapshot(&facet_typed)?;
    // A plain-text message (the facet admits this Station for message
    // content) is part of the same founder cut: the next head carries its
    // `message_revision` row at the message Commit.
    let strand_id = author.default_strand_id(with_plaintext_id)?;
    author
        .send_message(with_plaintext_id, &strand_id, "hello")
        .await?;
    let with_message: arkret_wire::RealmStateSnapshot = serde_json::from_value(
        expect_json(
            author
                .get(head_path)
                .query(&[("realm_id", with_plaintext_id)]),
            StatusCode::OK,
        )
        .await?,
    )
    .context("head after a message must be a signed wire snapshot")?;
    ensure!(
        with_message.visible_stream_heads[0].stream_position == 10
            && with_message.current_state_entries.len() == 12
            && with_message
                .current_state_entries
                .iter()
                .any(|row| matches!(
                    row,
                    arkret_wire::TypedCurrentRow::Value {
                        selector: arkret_wire::CurrentSelector::MessageRevision { .. },
                        revision,
                        ..
                    } if revision.stream_position == 10
                )),
        "head after a message must disclose its message_revision: {with_message:?}"
    );
    verify_test_notary_snapshot(&with_message)?;
    ensure_same_object(
        &with_message,
        &read_by_ref(&author, &with_message.snapshot_id, with_plaintext_id).await?,
    )?;
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
pub async fn account_detail_frame(
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

pub fn realm_detail(
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

pub fn window_positions(
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
/// a limited `window_limit` names a committed-prefix basis only when `/head`
/// already issued the exact snapshot at the window's anchor; that
/// `snapshot_ref` reads back by reference as the same signed object. Without
/// a prior issuance the limited window is `preview_only` with no basis. The
/// retired `timeline_limit` member and an unprovable Circle selection are
/// refused rather than degraded.
pub async fn limited_account_window_names_issued_basis_or_is_preview_only() -> Result<()> {
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
        basis.anchor_position == anchor.stream_position
            && basis.anchor_commit_ref == anchor.commit_id
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

/// Fresh Soland + real PostgreSQL, one Account batch over two Realms with a
/// limited `window_limit`: a Realm with more Commits than the window and no
/// issued anchor snapshot arrives `preview_only`, beside a Realm whose whole
/// history fits. Inkson's Account frame verifier must not reject the batch:
/// it backfills the preview stream with a verified replay from genesis over
/// the live scan and authority bundle and only then treats that stream as
/// exact, while the sibling Realm verifies as ordinary full history. A forged
/// preview row still fails closed. `window_limit` 8 keeps the Realm short;
/// the product's 20-row window over a longer message tail is exercised by
/// `message_tail_window_beyond_twenty_commits_verifies_through_inkson`.

/// Fresh Soland + real PostgreSQL, the live floor-tail shape: `/head` signs
/// the seven-Commit creator bootstrap, the creator then adds a default
/// Strand (StrandCreate + `ak.realm.set_default_strand`), and a
/// `window_limit` 2 Account window names that issued snapshot as the basis
/// for its committed prefix. Inkson's Account frame verifier reads the
/// basis by reference through Garth, verifies the two-Commit tail and keeps
/// the Station's same-cut current (equal to the signed `/head` at the window
/// head) without failing the frame; the client never folds typed current
/// itself. A current row sourced outside the verified cut fails closed.

/// Fresh Soland + real PostgreSQL, a founder Realm longer than the product's
/// default 20-row Account window: the plaintext-facet bootstrap, a default
/// Strand and one message, a `/head` issued at that message Commit (position
/// 10), then twenty more messages. The default window delivers positions
/// 11..=30 and names the
/// issued snapshot, which already carries a `message_revision` row, as the
/// basis for its committed prefix. Inkson verifies the signed floor rows, the
/// twenty-Commit message tail and the same-cut current without failing the
/// frame, and the fresh signed head at the window head equals that current.

/// Fresh Soland + real PostgreSQL, a `restricted` founder Realm whose join
/// policy declares an automatic claim gate: `/head` signs the complete cut
/// (the policy bundle carries the join policy the Station evaluated at
/// admission), and after a default Strand a `window_limit` 2 Account window
/// names that snapshot as its basis. Inkson installs the signed join policy
/// and restricted join rule without evaluating the gate itself.

pub fn by_ref_request(
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

pub async fn read_by_ref(
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

pub fn ensure_same_object(
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

pub fn verify_test_notary_snapshot(snapshot: &arkret_wire::RealmStateSnapshot) -> Result<()> {
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
