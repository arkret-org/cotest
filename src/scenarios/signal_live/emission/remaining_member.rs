//! Independent accepted members on one Station through real MLS repairs.

use arkret::{MlsCommitPayload, MlsGovernanceBindingPayload};
use arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest;
use arkret_wire::{AuthoritySubmitOutcome, MlsCommitSubmission, MlsGroupCurrent};

use super::*;
use crate::scenarios::_helpers::bridge::MockCoauthIntrospectionServer;
use crate::scenarios::cross_station_mls_welcome::{
    claim_for, join_through_invite, publish_one, wait_for_welcome,
};
use crate::scenarios::human_device_producer_live::{ensure_commit_signed_by, grant_message_create};
use crate::scenarios::message_mls_cross_station_live::install_bindings;
use crate::scenarios::mls_lifecycle_live::{
    accepted_full_view, canonical, claimed_keypackage_record, fresh_uuid_v7, post_json,
    signed_welcome,
};

async fn current(url: &str, realm: &RealmId) -> Result<MlsGroupCurrent> {
    let url = url.to_owned();
    let scope = ScopeRef::Realm {
        realm_id: realm.clone(),
    };
    let selector = serde_json::to_value(arkret_wire::CurrentSelector::MlsGroup {
        scope_ref: scope.clone(),
    })?;
    let scope = serde_json::to_value(scope)?;
    let realm = realm.to_string();
    tokio::task::spawn_blocking(move || -> Result<_> {
        let mut db = postgres::Client::connect(&url, postgres::NoTls)?;
        // The governing Station owns reducer results; the member Station
        // consumes the verified source snapshot's existing typed current row.
        let rows = db.query(
            "SELECT value FROM mls_group_current_results WHERE realm_id=$1 AND value->'effective_scope'=$2 \
             UNION ALL SELECT value FROM replica_authorization_rows WHERE realm_id=$1 AND selector=$3",
            &[&realm, &scope, &selector],
        ).context("read actual governing or verified replica MLS current")?;
        ensure!(rows.len() == 1, "expected one actual MLS current, got {}", rows.len());
        Ok(serde_json::from_value(rows[0].get(0))?)
    }).await?
}

async fn receive(
    rail: &mut Rail,
    expected: &SignalEnvelope,
) -> Result<arkret_models_collaboration::SignalDeliveryAuthority> {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match rail
                .next()
                .await?
                .context("qualified recipient rail remains open")?
            {
                SignalStreamFrame::Heartbeat => {}
                SignalStreamFrame::Signal {
                    envelope,
                    delivery_authority,
                } => {
                    ensure!(
                        arkret_canonical::canonical_json_bytes(&envelope)?
                            == arkret_canonical::canonical_json_bytes(expected)?,
                        "recipient receives the exact original encrypted envelope"
                    );
                    return Ok(delivery_authority);
                }
                frame => anyhow::bail!("unexpected recipient frame: {frame:?}"),
            }
        }
    })
    .await?
}

async fn opening_prefix(url: &str, realm: &RealmId) -> Result<serde_json::Value> {
    let url = url.to_owned();
    let realm = realm.to_string();
    tokio::task::spawn_blocking(move || -> Result<_> {
        let mut db = postgres::Client::connect(&url, postgres::NoTls)?;
        Ok(db.query_one("SELECT jsonb_build_array(a.member_account_id,a.join_commit_id) FROM replica_stream_anchors a JOIN realm_commits c ON c.commit_id=a.join_commit_id WHERE a.realm_id=$1 AND c.stream_ref->>'kind'='realm'", &[&realm])?.get(0))
    }).await?
}

async fn unchanged_footprint(
    url: &str,
    before: &serde_json::Value,
    boundary: Boundary,
    stage: &str,
    station: usize,
) -> Result<()> {
    let after = acceptance_rows(url).await?;
    if after == *before {
        return Ok(());
    }
    let changed: Vec<_> = before
        .as_object()
        .context("acceptance footprint is an object")?
        .iter()
        .filter_map(|(table, rows)| (after.get(table) != Some(rows)).then_some(table))
        .collect();
    if let Some(root) = std::env::var_os("COTEST_SERVICE_LOG_DIR") {
        let root = std::path::PathBuf::from(root).join(format!("signal-emission-{boundary:?}"));
        std::fs::create_dir_all(&root)?;
        for (phase, rows) in [("before", before), ("after", &after)] {
            std::fs::write(
                root.join(format!("{stage}-station-{station}-{phase}.json")),
                serde_json::to_vec_pretty(rows)?,
            )?;
        }
    }
    anyhow::bail!("{stage} changed Station {station} acceptance tables: {changed:?}")
}

fn exact_device_query_effects(
    before: &serde_json::Value,
    after: &serde_json::Value,
    sender: &Member,
) -> Result<usize> {
    for (table, rows) in before.as_object().context("acceptance footprint object")? {
        if table != "account_device_signer_evidence" {
            ensure!(
                after.get(table) == Some(rows),
                "device query changed {table}"
            );
        }
    }
    let original = before["account_device_signer_evidence"]
        .as_array()
        .context("original retained signer evidence")?;
    let current = after["account_device_signer_evidence"]
        .as_array()
        .context("current retained signer evidence")?;
    ensure!(
        original.iter().all(|row| current.contains(row)),
        "immutable signer evidence was changed"
    );
    let added: Vec<_> = current
        .iter()
        .filter(|row| !original.contains(row))
        .collect();
    ensure!(
        !added.is_empty(),
        "actual current device query retains fresh evidence"
    );
    for row in &added {
        let evidence: arkret_models_identity::AccountDeviceSignerEvidence =
            serde_json::from_value(row["evidence_json"].clone())?;
        arkret_identity::account_device_signer_evidence::verify_historical_account_device_signer_evidence(
            &evidence,
            &sender.account,
            &sender.device,
        )?;
        ensure!(serde_json::to_value(evidence.signer_evidence_ref()?)? == row["evidence_ref"]);
        ensure!(
            evidence
                .device_projection_attestation
                .attestation
                .device_authorize_event_id
                == sender.authorize_event_id
        );
    }
    Ok(added.len())
}

async fn accept_mls(
    alice: &Member,
    x: &ArkretServer,
    event: &arkret_wire::Event,
    welcomes: Vec<arkret_wire::MlsWelcomeDelivery>,
) -> Result<arkret_wire::CommittedEventFullView> {
    let submission = SelfAuthoritySubmitRequest::MlsCommit(MlsCommitSubmission {
        commit_event: event.clone(),
        welcomes,
        idempotency_key: arkret_wire::UuidV7::new(fresh_uuid_v7().parse()?)?,
    });
    submission.validate()?;
    let (status, submitted) = post_json(&alice.client, &submission).await?;
    ensure!(
        status == reqwest::StatusCode::OK,
        "actual MLS transition: {status} {submitted}"
    );
    let AuthoritySubmitOutcome::Accepted { commit, .. } = serde_json::from_value(submitted)? else {
        anyhow::bail!("MLS transition was not accepted")
    };
    ensure_commit_signed_by(&commit, x)?;
    let accepted = accepted_full_view(&alice.client, &event.event_id).await?;
    ensure!(accepted.event == *event && accepted.commit == commit);
    Ok(accepted)
}

#[expect(
    clippy::too_many_arguments,
    reason = "Actual accepted device, MLS and Station fixture"
)]
pub(crate) async fn exercise(
    alice: &Member,
    bob: &Member,
    alice_group: &mut ArkretMlsGroup,
    bob_group: &mut ArkretMlsGroup,
    realm: &RealmId,
    strand: &str,
    x: &ArkretServer,
    y: &ArkretServer,
    coauth: &MockCoauthIntrospectionServer,
    urls: &[&str; 2],
    pause_file: &Path,
    boundary: Boundary,
) -> Result<()> {
    let carol = Member::provision(
        y,
        coauth,
        "signal-remaining-carol",
        "ak:device:01904100-0000-7000-8000-000000002804",
    )
    .await?;
    ensure!(
        carol.account != bob.account
            && carol.actor != bob.actor
            && carol.device != bob.device
            && carol.key.verifying_key() != bob.key.verifying_key()
    );
    ensure!(carol.account.station_id == bob.account.station_id);
    join_through_invite(
        alice,
        x,
        &carol,
        realm.as_str(),
        "ak:request:019b0000-0000-7000-8000-000000002805",
        'd',
    )
    .await?;
    grant_message_create(&alice.client, x, realm.as_str(), &carol.account).await?;
    let identity = publish_one(&carol).await?;
    let scope = ScopeRef::Realm {
        realm_id: realm.clone(),
    };
    let group_id = scope.canonical_mls_group_id()?;
    let (claim, ..) = claim_for(alice, x, y, &carol, realm, &group_id, 0x82).await?;
    ensure!(claim.claims.len() == 1 && claim.claims[0].actor_id == carol.actor);
    ensure!(claim.claims[0].device_authorize_event_id.as_ref() == Some(&carol.authorize_event_id));
    let dirty = current(urls[0], realm).await?;
    ensure!(
        dirty.epoch == 1
            && dirty.effective_scope == scope
            && dirty.current_key_access_revision > dirty.covered_key_access_revision,
        "Carol's accepted join advances the existing scope revision"
    );
    // Membership is the sole revision writer. Cover its accepted change with
    // a real update before the separate Add submission can be admitted.
    let repair_binding = MlsGovernanceBindingPayload::new(
        scope.clone(),
        Some(dirty.current_mls_commit_event_ref.clone()),
        1,
        2,
        dirty.current_key_access_revision,
    )?;
    let repair = alice_group.self_update_commit_with_governance_binding(&repair_binding)?;
    let repair_payload = MlsCommitPayload::new(
        dirty.current_mls_commit_event_ref.clone(),
        dirty.current_key_access_revision,
        &repair,
        repair_binding,
    )?;
    let repair_event = alice
        .client
        .author_event(
            realm.as_str(),
            EventKind::MlsCommit.as_str(),
            canonical(serde_json::to_value(repair_payload)?)?,
        )
        .await?;
    let repaired = accept_mls(alice, x, &repair_event, vec![]).await?;
    ensure!(alice_group.install_accepted_commit(&repaired, &dirty)? == 2);
    wait_for_replica_cut(urls[1], &repaired.commit).await?;
    ensure!(accepted_full_view(&bob.client, &repair_event.event_id).await? == repaired);
    ensure!(bob_group.install_accepted_commit(&repaired, &dirty)? == 2);
    install_bindings(alice_group, &[alice, bob]).await?;
    install_bindings(bob_group, &[alice, bob]).await?;
    let base = current(urls[0], realm).await?;
    ensure!(
        base.epoch == 2
            && base.effective_scope == scope
            && base.current_key_access_revision == base.covered_key_access_revision
    );
    let binding = MlsGovernanceBindingPayload::new(
        scope,
        Some(base.current_mls_commit_event_ref.clone()),
        2,
        3,
        base.current_key_access_revision,
    )?;
    let add = alice_group.add_member_with_governance_binding(
        &claimed_keypackage_record(&claim.claims[0], &carol)?,
        &binding,
    )?;
    let payload = MlsCommitPayload::new(
        base.current_mls_commit_event_ref.clone(),
        base.current_key_access_revision,
        &add.commit,
        binding,
    )?;
    let event = alice
        .client
        .author_event(
            realm.as_str(),
            EventKind::MlsCommit.as_str(),
            canonical(serde_json::to_value(payload)?)?,
        )
        .await?;
    let welcome = signed_welcome(alice, &event, &carol, &add.welcome)?;
    let accepted = accept_mls(alice, x, &event, vec![welcome.clone()]).await?;
    let commit = &accepted.commit;
    ensure!(alice_group.install_accepted_commit(&accepted, &base)? == 3);
    wait_for_replica_cut(urls[1], commit).await?;
    ensure!(accepted_full_view(&bob.client, &event.event_id).await? == accepted);
    ensure!(bob_group.install_accepted_commit(&accepted, &base)? == 3);
    wait_for_welcome(&carol, &welcome).await?;
    let remote = accepted_full_view(&carol.client, &event.event_id).await?;
    ensure!(remote == accepted);
    let mut carol_group =
        ArkretMlsGroup::join_from_verified_welcome_delivery(identity, &welcome, &remote)?;
    for group in [&mut *alice_group, &mut *bob_group, &mut carol_group] {
        install_bindings(group, &[alice, bob, &carol]).await?;
        group.verify_installed_historical_base(&accepted, &event.event_id)?;
        ensure!(group.active_author_leaves().len() == 3 && group.epoch() == 3);
    }
    wait_for_delivery(urls[0], &accepted.commit).await?;
    let state = &event.event_id;
    let head = &commit.commit_id;
    // Each boundary exercises both production transports, swapping roles.
    let bob_websocket = matches!(boundary, Boundary::BanWithRemainingMember);
    let mut bob_rail = if bob_websocket {
        Rail::WebSocket(Box::new(
            super::super::super::websocket_live::LiveSignalReader::connect(
                y,
                &bob.client,
                realm.as_str(),
            )
            .await?,
        ))
    } else {
        Rail::Http(bob.client.sdk().signal_subscribe_frames().await?)
    };
    let mut carol_rail = if bob_websocket {
        Rail::Http(carol.client.sdk().signal_subscribe_frames().await?)
    } else {
        Rail::WebSocket(Box::new(
            super::super::super::websocket_live::LiveSignalReader::connect(
                y,
                &carol.client,
                realm.as_str(),
            )
            .await?,
        ))
    };
    for rail in [&mut bob_rail, &mut carol_rail] {
        ensure!(matches!(
            rail.next().await?,
            Some(SignalStreamFrame::Heartbeat)
        ));
    }
    let control = envelope(
        alice,
        alice_group,
        realm,
        strand,
        state,
        head,
        SignalClass::Session,
        30,
    )?;
    let paths = arm(pause_file, &control, &[&bob.account, &carol.account])?;
    ensure!(alice.client.sdk().signal_send(&control).await?.accepted);
    for path in &paths {
        reached(path, &control).await?;
    }
    for path in &paths {
        std::fs::remove_file(path)?;
        outcome(path, &control, true).await?;
    }
    for (index, (member, group, rail)) in [
        (bob, &*bob_group, &mut bob_rail),
        (&carol, &carol_group, &mut carol_rail),
    ]
    .into_iter()
    .enumerate()
    {
        let authority = receive(rail, &control).await?;
        verify_plaintext(alice, member, group, &control, &authority, state, head, 30)?;
        retain_observation(
            &paths[index],
            boundary,
            if index == 0 {
                "bob-control"
            } else {
                "carol-control"
            },
        )?;
    }
    let queued = envelope(
        alice,
        alice_group,
        realm,
        strand,
        state,
        head,
        SignalClass::Session,
        31,
    )?;
    let paths = arm(pause_file, &queued, &[&bob.account, &carol.account])?;
    let before = [counts(urls[0], realm).await?, counts(urls[1], realm).await?];
    ensure!(alice.client.sdk().signal_send(&queued).await?.accepted);
    for path in &paths {
        reached(path, &queued).await?;
    }
    for (index, url) in urls.iter().enumerate() {
        let after = counts(url, realm).await?;
        ensure!(
            after[0..2] == before[index][0..2] && after[2] == before[index][2] + 1,
            "one exact envelope per Station, independent of the recipient count"
        );
    }
    let prefix = opening_prefix(urls[1], realm).await?;
    ensure!(prefix[0] == serde_json::to_value(&bob.account)?);
    let departed = transition(alice, bob, realm, boundary).await?;
    ensure_commit_signed_by(&departed, x)?;
    wait_for_replica_cut(urls[1], &departed).await?;
    ensure!(
        accepted_full_view(&carol.client, &departed.event_ref)
            .await?
            .commit
            == departed
    );
    // Source delivery marking is a legitimate transition effect. Settle it
    // before checking that the frame decisions themselves are read-only.
    wait_for_delivery(urls[0], &departed).await?;
    let snapshots = [
        acceptance_rows(urls[0]).await?,
        acceptance_rows(urls[1]).await?,
    ];
    let settled = [counts(urls[0], realm).await?, counts(urls[1], realm).await?];
    for path in &paths {
        std::fs::remove_file(path)?;
    }
    outcome(&paths[0], &queued, false).await?;
    outcome(&paths[1], &queued, false).await?;
    // The membership revision invalidates old-epoch sends for the whole
    // scope. Carol's remaining membership is not a stale-MLS exception.
    carol_rail.quiet().await?;
    bob_rail.quiet().await?;
    retain_observation(&paths[0], boundary, "bob-closed")?;
    retain_observation(&paths[1], boundary, "carol-epoch-blocked")?;
    for (index, url) in urls.iter().enumerate() {
        ensure!(counts(url, realm).await? == settled[index]);
        unchanged_footprint(url, &snapshots[index], boundary, "queued", index).await?;
    }
    // Restore a complete accepted MLS basis, removing Bob's exact Actor.
    // Only Alice and Carol may install the new accepted transition.
    let dirty = current(urls[0], realm).await?;
    ensure!(
        dirty.epoch == 3 && dirty.current_key_access_revision > dirty.covered_key_access_revision
    );
    let remove_binding = MlsGovernanceBindingPayload::new(
        dirty.effective_scope.clone(),
        Some(state.clone()),
        3,
        4,
        dirty.current_key_access_revision,
    )?;
    let remove = alice_group.remove_members_by_actor_with_governance_binding(
        std::slice::from_ref(&bob.actor),
        &remove_binding,
    )?;
    let remove_payload = MlsCommitPayload::new(
        state.clone(),
        dirty.current_key_access_revision,
        &remove.commit,
        remove_binding,
    )?;
    let remove_event = alice
        .client
        .author_event(
            realm.as_str(),
            EventKind::MlsCommit.as_str(),
            canonical(serde_json::to_value(remove_payload)?)?,
        )
        .await?;
    let removed = accept_mls(alice, x, &remove_event, vec![]).await?;
    ensure!(alice_group.install_accepted_commit(&removed, &dirty)? == 4);
    wait_for_replica_cut(urls[1], &removed.commit).await?;
    ensure!(
        opening_prefix(urls[1], realm).await? == prefix,
        "refresh via Carol retains Bob's original verified prefix"
    );
    ensure!(accepted_full_view(&carol.client, &remove_event.event_id).await? == removed);
    ensure!(carol_group.install_accepted_commit(&removed, &dirty)? == 4);
    for group in [&mut *alice_group, &mut carol_group] {
        install_bindings(group, &[alice, &carol]).await?;
        group.verify_installed_historical_base(&removed, &remove_event.event_id)?;
        ensure!(group.epoch() == 4 && group.active_author_leaves().len() == 2);
    }
    for url in urls {
        let ready = current(url, realm).await?;
        ensure!(
            ready.epoch == 4
                && ready.current_key_access_revision == ready.covered_key_access_revision
                && ready.current_mls_commit_event_ref == remove_event.event_id
        );
    }
    wait_for_delivery(urls[0], &removed.commit).await?;
    if let Rail::WebSocket(rail) = &mut carol_rail {
        rail.wait_for_committed_event(&removed).await?;
    }
    // HTTP responses are bounded, cursorless leases. The queued decision was
    // observed on the original connection. Open a fresh standard lease before
    // the new-epoch send, proving departure remains fenced across reconnect.
    for (member, rail) in [(bob, &mut bob_rail), (&carol, &mut carol_rail)] {
        if let Rail::Http(stream) = rail {
            *stream = member.client.sdk().signal_subscribe_frames().await?;
            ensure!(matches!(
                stream.next_frame().await?,
                Some(SignalStreamFrame::Heartbeat)
            ));
        }
    }
    let before_query = [
        acceptance_rows(urls[0]).await?,
        acceptance_rows(urls[1]).await?,
    ];
    let settled = [counts(urls[0], realm).await?, counts(urls[1], realm).await?];
    // A fresh, fully qualified send still fans out to the same Station.
    let fresh = envelope(
        alice,
        alice_group,
        realm,
        strand,
        &remove_event.event_id,
        &removed.commit.commit_id,
        SignalClass::Session,
        32,
    )?;
    let fresh_probe = arm(pause_file, &fresh, &[&carol.account])?.remove(0);
    if matches!(carol_rail, Rail::WebSocket(_)) {
        std::fs::write(fresh_probe.with_extension("skip"), [])?;
    }
    ensure!(alice.client.sdk().signal_send(&fresh).await?.accepted);
    reached(&fresh_probe, &fresh).await?;
    // The registered current-device lookup legitimately retains fresh signed
    // evidence at its origin. Measure that effect separately, then freeze all
    // accepting tables before releasing the actual recipient frame gate.
    let snapshots = [
        acceptance_rows(urls[0]).await?,
        acceptance_rows(urls[1]).await?,
    ];
    let query_evidence_added = exact_device_query_effects(&before_query[0], &snapshots[0], alice)?;
    ensure!(
        snapshots[1] == before_query[1],
        "recipient query changes no accepting rows"
    );
    std::fs::remove_file(&fresh_probe)?;
    outcome(&fresh_probe, &fresh, true).await?;
    retain_observation(&fresh_probe, boundary, "carol-fresh")?;
    let authority = receive(&mut carol_rail, &fresh).await?;
    verify_plaintext(
        alice,
        &carol,
        &carol_group,
        &fresh,
        &authority,
        &remove_event.event_id,
        &removed.commit.commit_id,
        32,
    )?;
    bob_rail.quiet().await?;
    // The remote recipient's final sender check performs a second registered
    // keys/query at the origin. Verify every retained immutable evidence root
    // cryptographically; all other accepting tables must still be identical.
    let origin_after = acceptance_rows(urls[0]).await?;
    let total_query_evidence_added =
        exact_device_query_effects(&before_query[0], &origin_after, alice)?;
    ensure!(total_query_evidence_added >= query_evidence_added);
    let frame_gate_query_evidence_added = total_query_evidence_added - query_evidence_added;
    for (index, url) in urls.iter().enumerate() {
        let after = counts(url, realm).await?;
        ensure!(after[0..2] == settled[index][0..2] && after[2] == settled[index][2] + 1);
        if index != 0 {
            unchanged_footprint(url, &snapshots[index], boundary, "fresh", index).await?;
        }
    }
    for rail in [&mut bob_rail, &mut carol_rail] {
        if let Rail::WebSocket(rail) = rail {
            rail.finish().await?;
        }
    }
    eprintln!(
        "[signal-remaining-member] boundary={boundary:?} independent_accepted_actors=3 control_epoch=3 control_decrypted=2 same_queued_digest=1 old_epoch_final_gate_denied_before_ttl=2 accepted_remove_epoch=4 remaining_mls_leaves=2 fresh_peer_relay_carol_decrypted=1 bob_no_data_frames=1 canonical_acceptance_rows_unchanged=2 sender_query_evidence_added={query_evidence_added} frame_gate_query_evidence_added={frame_gate_query_evidence_added} complete_immutable_evidence_verified=1 http_and_websocket=1"
    );
    Ok(())
}
