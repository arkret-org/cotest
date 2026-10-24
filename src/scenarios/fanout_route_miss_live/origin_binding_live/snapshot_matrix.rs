//! Exact signed historical baselines across three actual Station processes.

use arkret_wire::{
    CommitStreamRef, RealmStateSnapshot, StreamScanDirection, StreamScanRequestBody,
};

use super::*;
use crate::harness::{CanonicalJsonBody, expect_json};
use crate::scenarios::circle_poll_scope_live::{circle_create, circle_event, join_circle};

mod privacy;
mod withheld;

async fn snapshot(client: &TestActorClient, realm: &RealmId) -> Result<RealmStateSnapshot> {
    let deadline = tokio::time::Instant::now() + HELD_WINDOW;
    loop {
        match client.sdk().realm_state_snapshot_head(realm).await {
            Ok(snapshot) => return Ok(snapshot),
            Err(arkret_http_client::Error::Api { status: 503, error })
                if error.error_code()
                    == Some(arkret_wire::ErrorCode::RealmStateSnapshotUnavailable)
                    && tokio::time::Instant::now() < deadline =>
            {
                // A member read schedules native convergence when its durable
                // cut trails the governor. Retry only this registered current
                // read; an exact historical refusal is never replaced/retried.
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(error) => return Err(error.into()),
        }
    }
}

fn assert_hidden_private_stream(
    snapshot: &RealmStateSnapshot,
    stream: &CommitStreamRef,
) -> Result<()> {
    ensure!(
        !snapshot
            .visible_stream_heads
            .iter()
            .any(|head| &head.stream_ref == stream),
        "hidden private stream disclosed its head"
    );
    ensure!(
        !snapshot
            .retention_and_history_floor
            .stream_floors
            .iter()
            .any(|floor| &floor.stream_ref == stream),
        "hidden private stream disclosed its floor"
    );
    let id = match stream {
        CommitStreamRef::Circle { circle_id, .. } => circle_id.as_str(),
        CommitStreamRef::Sidecar { sidecar_id, .. } => sidecar_id.as_str(),
        _ => bail!("private-scope assertion needs a Circle or Sidecar"),
    };
    ensure!(
        !serde_json::to_string(snapshot)?.contains(id),
        "hidden private identifier leaked through a typed current row"
    );
    Ok(())
}

async fn private_sidecar(
    client: &TestActorClient,
    account: &arkret_wire::AccountId,
    realm: &RealmId,
) -> Result<CommitStreamRef> {
    use arkret_models_collaboration::sidecar_operations::*;
    let operation_id =
        arkret_wire::ProtocolOperationId::new("ak:operation:snapshot-tenure-sidecar")
            .map_err(anyhow::Error::msg)?;
    let request = SidecarEnsureRequestBody::Prepare(SidecarEnsurePrepareRequestBody {
        phase: SidecarEnsurePreparePhase::Prepare,
        operation_id: operation_id.clone(),
        idempotency_key: arkret_wire::IdempotencyKey::new("snapshot-tenure-sidecar-prepare")
            .map_err(anyhow::Error::msg)?,
        source_realm_id: realm.clone(),
        controller_account_id: account.clone(),
        context_ref: SidecarContextRef::Strand {
            strand_id: client.default_strand_id(realm.as_str())?.parse()?,
        },
    });
    let request = client.verify_publication(request)?;
    let SidecarEnsureResponseBody::PreparedNew(prepared) =
        client.sdk().agent_sidecar_ensure(&request).await?
    else {
        bail!("fresh private Sidecar must prepare its registered atomic unit");
    };
    let request = SidecarEnsureRequestBody::Commit(SidecarEnsureCommitRequestBody {
        phase: SidecarEnsureCommitPhase::Commit,
        operation_id,
        idempotency_key: arkret_wire::IdempotencyKey::new("snapshot-tenure-sidecar-commit")
            .map_err(anyhow::Error::msg)?,
        reservation_handle: prepared.reservation_handle,
        create_event: client.sign_prepared_contact_event(
            &prepared.create_event_draft,
            EventKind::SidecarCreate.as_str(),
        )?,
        context_attach_event: client.sign_prepared_contact_event(
            &prepared.context_attach_event_draft,
            EventKind::SidecarContextAttach.as_str(),
        )?,
    });
    let request = client.verify_publication(request)?;
    let SidecarEnsureResponseBody::Accepted(accepted) =
        client.sdk().agent_sidecar_ensure(&request).await?
    else {
        bail!("private Sidecar atomic unit was not accepted");
    };
    Ok(CommitStreamRef::Sidecar {
        realm_id: realm.clone(),
        sidecar_id: accepted.sidecar_id,
    })
}

pub async fn run() -> Result<()> {
    crate::harness::heap_future(run_matrix).await
}

async fn run_matrix() -> Result<()> {
    let successor =
        database("snapshot-matrix-successor")?.context("three independent databases required")?;
    let mut fixture =
        manual_current_origin_fixture_with_successor("snapshot-three-station", Some(&successor))
            .await?;
    // Pin complete deployment locators once every real Station is running.
    // Endpoint-only discovery can still be pending when governance moves;
    // these hints do not replace DID, Describe or Realm authority verification.
    let peers: Vec<Vec<String>> = (0..3)
        .map(|index| {
            (0..3)
                .filter(|other| *other != index)
                .map(|other| {
                    let server = fixture.group.server(other);
                    format!(
                        "{}|{}|{}",
                        server.service_id(),
                        server.base_url(),
                        server.trust_domain()
                    )
                })
                .collect()
        })
        .collect();
    for (index, endpoints) in peers.iter().enumerate() {
        fixture
            .group
            .server_mut(index)
            .restart_with_federation_peers(endpoints)
            .await?;
    }
    let realm = RealmId::new(fixture.realm.clone())?;
    let actor = ActorId::account(fixture.alice_account.clone());
    let mut circles = Vec::new();
    for index in 0..2 {
        let circle = circle_create(
            &fixture.alice,
            &fixture.realm,
            &actor,
            &format!("Snapshot private {index}"),
            &format!("Private-{index}"),
        )
        .await?;
        join_circle(&fixture.alice, &fixture.realm, &circle, &actor).await?;
        circles.push(circle);
    }
    let target = CommitStreamRef::Circle {
        realm_id: realm.clone(),
        circle_id: circles[0].clone(),
    };
    let unrelated = CommitStreamRef::Circle {
        realm_id: realm.clone(),
        circle_id: circles[1].clone(),
    };
    let sidecar = private_sidecar(&fixture.alice, &fixture.alice_account, &realm).await?;
    let issued = snapshot(&fixture.alice, &realm).await?;
    ensure!(issued.governance_generation == 0);
    ensure!(
        issued
            .visible_stream_heads
            .iter()
            .any(|h| h.stream_ref == target)
    );
    ensure!(
        issued
            .visible_stream_heads
            .iter()
            .any(|h| h.stream_ref == unrelated)
    );
    ensure!(
        issued
            .visible_stream_heads
            .iter()
            .any(|head| head.stream_ref == sidecar)
    );
    let outsider = snapshot(&fixture.bob, &realm).await?;
    ensure!(
        !outsider
            .visible_stream_heads
            .iter()
            .any(|head| head.stream_ref == sidecar)
    );
    assert_hidden_private_stream(&outsider, &target)?;
    assert_hidden_private_stream(&outsider, &sidecar)?;
    let opening_join = issued.current_state_entries.iter().find_map(|row| {
        let arkret_wire::CurrentState::Value { selector, revision, .. } = row;
        matches!(selector, arkret_wire::CurrentSelector::MemberState { actor_id } if actor_id == &actor).then(|| revision.commit_id.clone())
    }).context("original accepted opening membership")?;
    let history_request = arkret_models_collaboration::governance::realm_join_intake::PeerRealmJoinBootstrapRequestBody {
        request_id: arkret_wire::RequestId::new("ak:request:01904100-0000-7000-8000-0000000000b1").map_err(anyhow::Error::msg)?,
        realm_id: realm.clone(), member_account_id: fixture.alice_account.clone(), membership_commit_id: opening_join,
        history_stream_ref: Some(target.clone()),
    };
    let (history_status, history_body) = fixture
        .group
        .server(0)
        .signed_peer_post(
            fixture.group.server(0),
            "/_arkret/peer/realm-joins/bootstrap",
            &arkret_canonical::canonical_json_bytes(&history_request)?,
            fixture.group.server(0).service_id(),
        )
        .await?;
    ensure!(
        history_status == StatusCode::OK,
        "source history issuance {history_status}: {}",
        String::from_utf8_lossy(&history_body)
    );
    let history_outcome: arkret_models_collaboration::governance::realm_join_intake::PeerRealmJoinBootstrapResponseBody = serde_json::from_slice(&history_body)?;
    ensure!(history_outcome.request_id == history_request.request_id);
    let stream_history = history_outcome.snapshot;
    stream_history.validate_purpose()?;
    ensure!(
        stream_history.purpose == arkret_wire::RealmSnapshotPurpose::StreamHistory
            && stream_history
                .history_basis
                .as_ref()
                .is_some_and(|signed| signed.account_id == fixture.alice_account
                    && signed.stream_ref == target)
    );
    assert_hidden_private_stream(&stream_history, &unrelated)?;
    assert_hidden_private_stream(&stream_history, &sidecar)?;
    let history_bytes = arkret_canonical::canonical_json_bytes(&stream_history)?;
    let original_bytes = arkret_canonical::canonical_json_bytes(&issued)?;
    let hidden_request = StreamScanRequestBody {
        realm_id: realm.clone(),
        stream_ref: target.clone(),
        direction: StreamScanDirection::After(None),
        limit: 2,
    };
    privacy::assert_hidden_scans(&fixture, &[target.clone(), sidecar.clone()], 0).await?;

    let (change, changed) = {
        let (old, new) = fixture.group.server_pair_mut(0, 2);
        activate_realm_successor(
            old,
            new,
            &fixture.alice,
            &fixture.alice_account,
            &fixture.realm,
            &fixture._governance_database.connect_url,
            &successor.connect_url,
        )
        .await?
    };
    let outcomes = replicate(
        fixture.group.server(1),
        fixture.group.server(2),
        &replication_body(&fixture.alice, &change, &changed).await?,
    )
    .await?;
    ensure!(
        matches!(
            outcomes.as_slice(),
            [CommittedEventReplicationOutcome::Stored {}
                | CommittedEventReplicationOutcome::Duplicate {}]
        ),
        "handoff replication did not settle: {outcomes:?}"
    );
    ensure_same_commit(
        &changed,
        &wait_held(&fixture.bob, &change.event_id, HELD_WINDOW).await?,
    )?;
    let current = snapshot(&fixture.alice, &realm).await?;
    ensure!(
        current.governance_generation == 1
            && current.signature.verification_method != issued.signature.verification_method,
        "head did not switch to the verified successor"
    );
    ensure!(
        current
            .visible_stream_heads
            .iter()
            .any(|head| head.stream_ref == sidecar)
    );
    let outsider_after_handoff = snapshot(&fixture.bob, &realm).await?;
    ensure!(outsider_after_handoff.governance_generation == 1);
    assert_hidden_private_stream(&outsider_after_handoff, &target)?;
    assert_hidden_private_stream(&outsider_after_handoff, &sidecar)?;
    privacy::assert_hidden_scans(&fixture, &[target.clone(), sidecar.clone()], 2).await?;
    let historical = fixture
        .alice
        .sdk()
        .realm_state_snapshot_by_ref(&realm, &issued.snapshot_id)
        .await?;
    ensure!(
        arkret_canonical::canonical_json_bytes(&historical)? == original_bytes,
        "handoff rewrote the exact old-tenure original"
    );

    let mut nonce = [0u8; 32];
    getrandom::fill(&mut nonce).map_err(anyhow::Error::msg)?;
    let request = RealmAuthorityBundleRequestBody {
        realm_id: realm.clone(),
        nonce: Base64UrlString::new(arkret_canonical::base64url_encode(nonce))
            .map_err(anyhow::Error::msg)?,
    };
    let http = fixture.alice.sdk();
    let authority = garth::AuthorityClient::new(http.clone());
    let description = http
        .describe_for_role(arkret_wire::ServiceKind::Station)
        .await?;
    ensure!(
        authority
            .exact_snapshot(&description, &realm, &issued.snapshot_id)
            .await?
            == issued
    );
    let bundle = authority.resolve_authority(&request).await?;
    ensure!(bundle.current_generation == 1 && bundle.authority_transitions.len() == 1);
    let freshness =
        arkret_identity::RealmAuthorityFreshness::new(chrono::Utc::now(), request.nonce.clone());
    // Fetch each actual Station's complete method-native carrier over its
    // registered resolution endpoint. The independent directory verifier
    // authenticates every historical method at its original signing cut.
    let mut resolutions = std::collections::BTreeMap::new();
    for index in [0, 2] {
        let station = fixture.group.server(index);
        let resolution = station
            .sdk()?
            .open_service_resolution(station.service_id())
            .await?;
        ensure!(&resolution.service_id == station.service_id());
        resolutions.insert(resolution.service_id.clone(), resolution);
    }
    let keys =
        garth::historical_station_key_directory(&bundle, None, Some(&historical), &resolutions)?;
    let current_keys =
        garth::historical_station_key_directory(&bundle, None, Some(&current), &resolutions)?;
    let history_keys = garth::historical_station_key_directory(
        &bundle,
        None,
        Some(&stream_history),
        &resolutions,
    )?;
    let mut audit = garth::RealmReplica::new(realm.clone());
    audit.install_verified_authority(&request, bundle, &freshness, &keys)?;
    let mut current_audit = audit.clone();
    let mut history_audit = audit.clone();
    audit.install_verified_snapshot_heads(&historical, &issued.snapshot_id, &freshness, &keys)?;
    let prior = audit.clone();
    ensure!(
        audit
            .install_verified_current_snapshot_heads(&historical, &freshness, &keys)
            .is_err(),
        "old-tenure original was accepted as current head"
    );
    ensure!(audit == prior);
    current_audit.install_verified_current_snapshot_heads(&current, &freshness, &current_keys)?;
    let established = current_audit.clone();
    ensure!(
        current_audit
            .install_verified_snapshot_heads(&historical, &issued.snapshot_id, &freshness, &keys)
            .is_err(),
        "historical original replaced an established verified replay head"
    );
    ensure!(current_audit == established);

    history_audit.install_verified_snapshot_heads(
        &stream_history,
        &stream_history.snapshot_id,
        &freshness,
        &history_keys,
    )?;
    ensure!(
        history_audit
            .install_verified_current_snapshot_heads(&stream_history, &freshness, &history_keys)
            .is_err()
    );
    withheld::run(&fixture, &successor.connect_url).await?;

    let leave = circle_event(&fixture.alice, &fixture.realm, &circles[1], EventKind::CircleMemberState,
        json!({"circle_id":circles[1],"member_id":actor,"membership":"leave","expected_membership":"join"})).await?;
    submit_and_expect_commit(&fixture.alice, &fixture.alice_account, ALICE_DEVICE, &leave).await?;
    let after = snapshot(&fixture.alice, &realm).await?;
    ensure!(
        after
            .visible_stream_heads
            .iter()
            .any(|h| h.stream_ref == target)
    );
    ensure!(
        after
            .visible_stream_heads
            .iter()
            .any(|head| head.stream_ref == sidecar)
    );
    ensure!(
        !after
            .visible_stream_heads
            .iter()
            .any(|h| h.stream_ref == unrelated)
    );
    let refused = authority
        .exact_snapshot(&description, &realm, &issued.snapshot_id)
        .await;
    ensure!(
        matches!(
            refused,
            Err(garth::Error::ExactSnapshotRefused(
                garth::ExactSnapshotRefusal::Unavailable
            ))
        ),
        "unrelated scope revocation must return the registered whole-original unavailable result: {refused:?}"
    );
    ensure!(
        arkret_canonical::canonical_json_bytes(
            &authority
                .exact_snapshot(&description, &realm, &stream_history.snapshot_id)
                .await?
        )? == history_bytes,
        "unrelated scope loss must not withdraw the target's independent original"
    );
    let target_page = fixture
        .alice
        .sdk()
        .scan_commit_stream(&hidden_request)
        .await?;
    target_page.validate_for_request(&hidden_request)?;
    ensure!(
        !target_page.committed_events.is_empty(),
        "target stream lost its independent read authority"
    );
    let sidecar_request = StreamScanRequestBody {
        realm_id: realm.clone(),
        stream_ref: sidecar.clone(),
        direction: StreamScanDirection::After(None),
        limit: 10,
    };
    let sidecar_page = fixture
        .alice
        .sdk()
        .scan_commit_stream(&sidecar_request)
        .await?;
    sidecar_page.validate_for_request(&sidecar_request)?;
    ensure!(!sidecar_page.committed_events.is_empty());
    fixture
        .group
        .server_mut(2)
        .restart_external_process()
        .await?;
    let recovered = snapshot(&fixture.alice, &realm).await?;
    ensure!(recovered.governance_generation == 1);
    ensure!(
        recovered
            .visible_stream_heads
            .iter()
            .any(|head| head.stream_ref == target)
            && recovered
                .visible_stream_heads
                .iter()
                .any(|head| head.stream_ref == sidecar),
        "successor restart lost a still-readable private stream"
    );
    ensure!(matches!(
        authority
            .exact_snapshot(&description, &realm, &issued.snapshot_id)
            .await,
        Err(garth::Error::ExactSnapshotRefused(
            garth::ExactSnapshotRefusal::Unavailable
        ))
    ));
    fixture
        .group
        .server_mut(0)
        .restart_external_process()
        .await?;
    ensure!(
        arkret_canonical::canonical_json_bytes(
            &authority
                .exact_snapshot(&description, &realm, &stream_history.snapshot_id)
                .await?
        )? == history_bytes,
        "Account Station cold restart lost the issued independent history original"
    );
    println!(
        "[stream-history-snapshot] three_station_processes=1 three_databases=1 private_circle_and_sidecar=1 complete_private_handoff=1 generation=1 original_old_signature_verified=1 old_head_refused=1 unrelated_circle_revoked=1 target_and_sidecar_still_readable=1 full_original_unavailable=1 independent_target_original_retained=1 successor_restart=1 account_station_restart=1"
    );
    Ok(())
}
