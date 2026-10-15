//! Actual first-stored peer replay through two independent Stations.

use super::*;

async fn manual_current_origin_fixture(name: &str) -> Result<CurrentOriginFixture> {
    manual_current_origin_fixture_with_successor(name, None).await
}

pub(super) async fn manual_current_origin_fixture_with_successor(
    name: &str,
    successor: Option<&EphemeralPg>,
) -> Result<CurrentOriginFixture> {
    let governance_database = database(name)?.context("federation replay requires PostgreSQL")?;
    let member_database = database(name)?.context("federation replay requires PostgreSQL")?;
    ensure!(governance_database.connect_url != member_database.connect_url);
    let coauth = MockCoauthIntrospectionServer::spawn_with_internal_secret(
        HARNESS_INTERNAL_AUTHORITY_SECRET,
    )
    .await?;
    let mut source_env = station_env(&governance_database.connect_url, &coauth);
    for (key, value) in &mut source_env {
        if key == "COLAND_FEDERATION_OUTBOUND" {
            *value = "0".to_owned();
        }
    }
    let mut environments = vec![
        source_env,
        station_env(&member_database.connect_url, &coauth),
    ];
    if let Some(successor) = successor {
        let mut environment = station_env(&successor.connect_url, &coauth);
        for (key, value) in &mut environment {
            if key == "COLAND_FEDERATION_OUTBOUND" {
                *value = "0".to_owned();
            }
        }
        environments.push(environment);
    }
    let group = TestServerGroup::try_multi_external_with_node_envs(name, &environments)
        .await?
        .context("independent actual Coland processes required")?;
    let (alice, alice_account) =
        standard_client(group.server(0), &coauth, "replay-alice", ALICE_DEVICE).await?;
    let (bob, bob_account) =
        standard_client(group.server(1), &coauth, "replay-bob", BOB_DEVICE).await?;
    let mut plaintext_services = vec![group.server(0), group.server(1)];
    if successor.is_some() {
        plaintext_services.push(group.server(2));
    }
    let realm = create_realm_with_join_rule(
        &alice,
        "Federation first stored replay",
        "public",
        &plaintext_services,
    )
    .await?;
    prepare_join(
        &bob,
        &realm,
        group.server(0),
        "ak:request:019b0000-0000-7000-8000-000000002505",
        RealmJoinIntent::MemberJoin,
    )
    .await?;
    let join = bob
        .author_event(
            &realm,
            EventKind::MemberState.as_str(),
            membership_payload(
                &realm,
                bob_account.clone(),
                MembershipPayloadState::Join,
                "manual replay member",
            )?,
        )
        .await?;
    let joined = submit_and_expect_commit(&bob, &bob_account, BOB_DEVICE, &join).await?;
    ensure_commit_signed_by(&joined, group.server(0))?;
    let joined_body = replication_body(&alice, &join, &joined).await?;
    let outcomes = replicate(group.server(1), group.server(0), &joined_body).await?;
    ensure!(matches!(
        outcomes.as_slice(),
        [PeerCommittedReplicationOutcomeRecord::Stored {}
            | PeerCommittedReplicationOutcomeRecord::Duplicate {}]
    ));
    ensure_same_commit(
        &joined,
        &wait_held(&bob, &join.event_id, HELD_WINDOW).await?,
    )?;
    wait_for_titled_row(&bob, &realm, "Federation first stored replay").await?;
    Ok(CurrentOriginFixture {
        alice,
        bob,
        alice_account,
        realm,
        group,
        _coauth: coauth,
        _governance_database: governance_database,
        _member_database: member_database,
    })
}

pub async fn run_federation_first_stored_outcome_replay_live() -> Result<()> {
    first_stored_outcome_replay(true).await
}

pub async fn run_federation_no_header_first_stored_replay_live() -> Result<()> {
    first_stored_outcome_replay(false).await
}

async fn first_stored_outcome_replay(with_header: bool) -> Result<()> {
    let mut fixture = manual_current_origin_fixture("federation-first-stored-replay").await?;
    let strand = fixture.alice.default_strand_id(&fixture.realm)?;
    let (event, commit) = alice_message(
        &fixture.alice,
        &fixture.alice_account,
        &fixture.realm,
        &strand,
        "first stored outcome must survive exact replay",
    )
    .await?;
    let body = replication_body(&fixture.alice, &event, &commit).await?;
    let request = fixture
        .group
        .server(1)
        .signed_peer_post_request_with_idempotency_key(
            fixture.group.server(0),
            PEER_EVENTS,
            &body,
            fixture.group.server(1).service_id(),
            with_header.then_some("federation-original-stored-outcome"),
        )?;
    let original = fixture
        .group
        .server(1)
        .http()
        .execute(request.try_clone().context("clone frozen request")?)
        .await?;
    ensure!(original.status() == StatusCode::OK);
    let original: PeerAuthoritySubmitOutcome = original.json().await?;
    ensure!(
        matches!(&original,PeerAuthoritySubmitOutcome::CommittedReplication(value)
        if matches!(value.replication_outcomes.as_slice(),[PeerCommittedReplicationOutcomeRecord::Stored {}])),
        "first actual ingress was not Stored: {original:?}"
    );
    let before =
        crate::scenarios::_helpers::acceptance_footprint::acceptance_rows_with_agent_stores(
            &fixture._member_database.connect_url,
            true,
        )
        .await?;
    let response = fixture
        .group
        .server(1)
        .http()
        .execute(request.try_clone().context("replay frozen request")?)
        .await?;
    ensure!(response.status() == StatusCode::OK);
    let replay: PeerAuthoritySubmitOutcome = response.json().await?;
    ensure!(
        replay == original,
        "exact unchanged-basis replay changed first Stored into another outcome: original {original:?}, replay {replay:?}"
    );
    ensure!(
        crate::scenarios::_helpers::acceptance_footprint::acceptance_rows_with_agent_stores(
            &fixture._member_database.connect_url,
            true
        )
        .await?
            == before,
        "exact peer replay changed the full accepted/business snapshot"
    );
    ensure_same_commit(
        &commit,
        &wait_held(&fixture.bob, &event.event_id, HELD_WINDOW).await?,
    )?;
    fixture
        .group
        .server_mut(1)
        .restart_external_process()
        .await?;
    let restarted_before = snapshot(&fixture).await?;
    let restarted = fixture
        .group
        .server(1)
        .http()
        .execute(request.try_clone().context("clone request after restart")?)
        .await?;
    ensure!(restarted.status() == StatusCode::OK);
    let restarted: PeerAuthoritySubmitOutcome = restarted.json().await?;
    ensure!(
        restarted == original,
        "durable first Stored receipt was lost on restart"
    );
    ensure!(
        snapshot(&fixture).await? == restarted_before,
        "durable replay after restart changed business state"
    );
    Ok(())
}

pub(super) async fn snapshot(fixture: &CurrentOriginFixture) -> Result<Value> {
    crate::scenarios::_helpers::acceptance_footprint::acceptance_rows_with_agent_stores(
        &fixture._member_database.connect_url,
        true,
    )
    .await
}

pub async fn run_federation_ordered_items_replay_live() -> Result<()> {
    use arkret_models_collaboration::governance::plaintext_visibility::{
        PlaintextServiceVisibility, PlaintextVisibleService, PlaintextVisibleServicesPayload,
    };
    let fixture = manual_current_origin_fixture("federation-ordered-replay").await?;
    let strand = fixture.alice.default_strand_id(&fixture.realm)?;
    let (event, commit) = alice_message(
        &fixture.alice,
        &fixture.alice_account,
        &fixture.realm,
        &strand,
        "message before same-request policy cut",
    )
    .await?;
    let policy = PlaintextVisibleServicesPayload::new(
        [0, 1]
            .into_iter()
            .map(|index| {
                PlaintextVisibleService::new(
                    fixture.group.server(index).service_id().clone(),
                    "station",
                    vec![arkret_wire::PlaintextDataClassKind::MessageContent],
                    vec!["updated but still authorized message policy".to_owned()],
                    PlaintextServiceVisibility::PrivatePlaintext,
                )
            })
            .collect(),
    );
    let policy_event = fixture
        .alice
        .author_event(
            &fixture.realm,
            EventKind::RealmPlaintextVisibleServices.as_str(),
            policy.to_value()?,
        )
        .await?;
    let policy_commit = submit_and_expect_commit(
        &fixture.alice,
        &fixture.alice_account,
        ALICE_DEVICE,
        &policy_event,
    )
    .await?;
    let mut replications = Vec::new();
    for (event, commit) in [(&event, &commit), (&policy_event, &policy_commit)] {
        let body = replication_body(&fixture.alice, event, commit).await?;
        match serde_json::from_slice::<PeerAuthoritySubmitRequest>(&body)? {
            PeerAuthoritySubmitRequest::CommittedReplication(value) => {
                replications.extend(value.replications)
            }
            _ => bail!("typed replication helper changed branch"),
        }
    }
    let body = PeerAuthoritySubmitRequest::CommittedReplication(PeerCommittedReplicationRequest {
        branch: CommittedReplicationBranch::CommittedReplication,
        replications,
    });
    body.validate()?;
    let body = arkret_canonical::canonical_json_bytes(&body)?;
    let request = fixture
        .group
        .server(1)
        .signed_peer_post_request_with_idempotency_key(
            fixture.group.server(0),
            PEER_EVENTS,
            &body,
            fixture.group.server(1).service_id(),
            Some("ordered-first-stored-replay"),
        )?;
    let response = fixture
        .group
        .server(1)
        .http()
        .execute(request.try_clone().context("freeze ordered request")?)
        .await?;
    ensure!(response.status() == StatusCode::OK);
    let first: PeerAuthoritySubmitOutcome = response.json().await?;
    ensure!(
        matches!(&first, PeerAuthoritySubmitOutcome::CommittedReplication(value)
        if matches!(value.replication_outcomes.as_slice(),
            [PeerCommittedReplicationOutcomeRecord::Stored {}, PeerCommittedReplicationOutcomeRecord::Stored {}])),
        "ordered first ingress did not store both actual items: {first:?}"
    );
    let before = snapshot(&fixture).await?;
    let response = fixture.group.server(1).http().execute(request).await?;
    ensure!(response.status() == StatusCode::OK);
    let replay: PeerAuthoritySubmitOutcome = response.json().await?;
    ensure!(
        replay == first,
        "post-request basis lost an earlier Stored: {first:?} vs {replay:?}"
    );
    ensure!(
        snapshot(&fixture).await? == before,
        "ordered replay changed business state"
    );
    ensure_same_commit(
        &commit,
        &wait_held(&fixture.bob, &event.event_id, HELD_WINDOW).await?,
    )?;
    ensure_same_commit(
        &policy_commit,
        &wait_held(&fixture.bob, &policy_event.event_id, HELD_WINDOW).await?,
    )?;
    Ok(())
}

async fn prepared_message_request(
    fixture: &CurrentOriginFixture,
    key: &str,
) -> Result<(reqwest::Request, Event, RealmCommit, Vec<u8>)> {
    let strand = fixture.alice.default_strand_id(&fixture.realm)?;
    let (event, commit) = alice_message(
        &fixture.alice,
        &fixture.alice_account,
        &fixture.realm,
        &strand,
        key,
    )
    .await?;
    let body = replication_body(&fixture.alice, &event, &commit).await?;
    let request = fixture
        .group
        .server(1)
        .signed_peer_post_request_with_idempotency_key(
            fixture.group.server(0),
            PEER_EVENTS,
            &body,
            fixture.group.server(1).service_id(),
            Some(key),
        )?;
    Ok((request, event, commit, body))
}

pub async fn run_federation_concurrent_first_stored_live() -> Result<()> {
    let fixture = manual_current_origin_fixture("federation-concurrent-replay").await?;
    let (request, event, commit, body) =
        prepared_message_request(&fixture, "concurrent-first-stored").await?;
    let before = snapshot(&fixture).await?;
    let first = request
        .try_clone()
        .context("clone first concurrent request")?;
    let second = request
        .try_clone()
        .context("clone second concurrent request")?;
    let third = request
        .try_clone()
        .context("clone third concurrent request")?;
    let http = fixture.group.server(1).http();
    let (first, second, third) = tokio::join!(
        http.execute(first),
        http.execute(second),
        http.execute(third)
    );
    for response in [first?, second?, third?] {
        ensure!(response.status() == StatusCode::OK);
        let answer: PeerAuthoritySubmitOutcome = response.json().await?;
        ensure!(
            matches!(&answer, PeerAuthoritySubmitOutcome::CommittedReplication(value)
            if matches!(value.replication_outcomes.as_slice(), [PeerCommittedReplicationOutcomeRecord::Stored {}])),
            "concurrent exact request lost first Stored outcome: {answer:?}"
        );
    }
    let after = snapshot(&fixture).await?;
    for table in ["canonical_events", "realm_commits"] {
        ensure!(
            after[table].as_array().context("after rows")?.len()
                == before[table].as_array().context("before rows")?.len() + 1,
            "concurrent requests created more than one {table} row"
        );
    }
    let url = fixture._member_database.connect_url.clone();
    let hash = arkret_canonical::sha256_digest(&body).as_str().to_owned();
    tokio::task::spawn_blocking(move || -> Result<()> {
        let mut client = postgres::Client::connect(&url, postgres::NoTls)?;
        let row = client.query_one("SELECT count(*),bool_and(expires_at-created_at=interval '24 hours') FROM idempotency_keys WHERE operation_id='ak.peer.events.command.submit.v1' AND request_hash=$1", &[&hash])?;
        ensure!(row.get::<_,i64>(0)==1 && row.get::<_,Option<bool>>(1)==Some(true),
            "concurrent first writer did not preserve one original 24-hour receipt");
        Ok(())
    }).await??;
    let response = http.execute(request).await?;
    ensure!(response.status() == StatusCode::OK);
    ensure!(
        snapshot(&fixture).await? == after,
        "later exact replay changed the concurrent winner's effects"
    );
    ensure_same_commit(
        &commit,
        &wait_held(&fixture.bob, &event.event_id, HELD_WINDOW).await?,
    )?;
    Ok(())
}

pub async fn run_federation_receipt_rollback_live() -> Result<()> {
    let fixture = manual_current_origin_fixture("federation-receipt-rollback").await?;
    let (request, event, commit, body) =
        prepared_message_request(&fixture, "receipt-failure-replay").await?;
    let before = snapshot(&fixture).await?;
    let url = fixture._member_database.connect_url.clone();
    let hash = arkret_canonical::sha256_digest(&body).as_str().to_owned();
    let mut connection = tokio::task::spawn_blocking(move || -> Result<_> {
        let mut client = postgres::Client::connect(&url, postgres::NoTls)?;
        // The owned test database injects an actual failing receipt INSERT;
        // no accepted authority, Event or policy row is seeded or altered.
        client.batch_execute("CREATE FUNCTION harness_peer_receipt_abort() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.operation_id='ak.peer.events.command.submit.v1' THEN RAISE EXCEPTION 'owned test receipt INSERT failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER harness_peer_receipt_abort BEFORE INSERT ON idempotency_keys FOR EACH ROW EXECUTE FUNCTION harness_peer_receipt_abort()")?;
        Ok(client)
    }).await??;
    let response = fixture
        .group
        .server(1)
        .http()
        .execute(
            request
                .try_clone()
                .context("freeze failed receipt request")?,
        )
        .await?;
    ensure!(
        response.status().is_server_error(),
        "injected receipt failure was not rejected: {}",
        response.status()
    );
    ensure!(
        snapshot(&fixture).await? == before,
        "failed receipt INSERT leaked accepted or business rows"
    );
    connection = tokio::task::spawn_blocking(move || -> Result<_> {
        let count: i64 = connection.query_one("SELECT count(*) FROM idempotency_keys WHERE request_hash=$1", &[&hash])?.get(0);
        ensure!(count==0, "rollback retained a poisoned peer receipt");
        connection.batch_execute("DROP TRIGGER harness_peer_receipt_abort ON idempotency_keys; DROP FUNCTION harness_peer_receipt_abort()")?;
        Ok(connection)
    }).await??;
    tokio::task::spawn_blocking(move || drop(connection)).await?;
    let response = fixture.group.server(1).http().execute(request).await?;
    ensure!(response.status() == StatusCode::OK);
    let answer: PeerAuthoritySubmitOutcome = response.json().await?;
    ensure!(
        matches!(&answer, PeerAuthoritySubmitOutcome::CommittedReplication(value)
        if matches!(value.replication_outcomes.as_slice(), [PeerCommittedReplicationOutcomeRecord::Stored {}])),
        "exact retry after rollback lost actual first Stored: {answer:?}"
    );
    ensure_same_commit(
        &commit,
        &wait_held(&fixture.bob, &event.event_id, HELD_WINDOW).await?,
    )?;
    Ok(())
}

pub(super) async fn first_stored_request(
    fixture: &CurrentOriginFixture,
    key: &str,
) -> Result<(reqwest::Request, Event, RealmCommit)> {
    let strand = fixture.alice.default_strand_id(&fixture.realm)?;
    let (event, commit) = alice_message(
        &fixture.alice,
        &fixture.alice_account,
        &fixture.realm,
        &strand,
        key,
    )
    .await?;
    let body = replication_body(&fixture.alice, &event, &commit).await?;
    let request = fixture
        .group
        .server(1)
        .signed_peer_post_request_with_idempotency_key(
            fixture.group.server(0),
            PEER_EVENTS,
            &body,
            fixture.group.server(1).service_id(),
            Some(key),
        )?;
    let response = fixture
        .group
        .server(1)
        .http()
        .execute(request.try_clone().context("freeze first Stored request")?)
        .await?;
    ensure!(response.status() == StatusCode::OK);
    let outcome: PeerAuthoritySubmitOutcome = response.json().await?;
    ensure!(
        matches!(&outcome, PeerAuthoritySubmitOutcome::CommittedReplication(value)
        if matches!(value.replication_outcomes.as_slice(),
            [PeerCommittedReplicationOutcomeRecord::Stored {}])),
        "expected actual first Stored: {outcome:?}"
    );
    ensure_same_commit(
        &commit,
        &wait_held(&fixture.bob, &event.event_id, HELD_WINDOW).await?,
    )?;
    Ok((request, event, commit))
}

pub async fn run_federation_changed_basis_replay_live() -> Result<()> {
    use arkret_models_collaboration::governance::plaintext_visibility::{
        PlaintextServiceVisibility, PlaintextVisibleService, PlaintextVisibleServicesPayload,
    };
    let fixture = manual_current_origin_fixture("federation-changed-basis-replay").await?;
    let (request, event, commit) = first_stored_request(&fixture, "changed-basis-replay").await?;
    let policy = PlaintextVisibleServicesPayload::new(vec![PlaintextVisibleService::new(
        fixture.group.server(0).service_id().clone(),
        "station",
        vec![arkret_wire::PlaintextDataClassKind::MessageContent],
        vec!["Realm messages".to_owned()],
        PlaintextServiceVisibility::PrivatePlaintext,
    )]);
    let policy_event = fixture
        .alice
        .author_event(
            &fixture.realm,
            EventKind::RealmPlaintextVisibleServices.as_str(),
            policy.to_value()?,
        )
        .await?;
    let policy_commit = submit_and_expect_commit(
        &fixture.alice,
        &fixture.alice_account,
        ALICE_DEVICE,
        &policy_event,
    )
    .await?;
    let outcome = replicate(
        fixture.group.server(1),
        fixture.group.server(0),
        &replication_body(&fixture.alice, &policy_event, &policy_commit).await?,
    )
    .await?;
    ensure!(
        matches!(
            outcome.as_slice(),
            [PeerCommittedReplicationOutcomeRecord::Stored {}]
        ),
        "real basis-changing policy was not stored: {outcome:?}"
    );
    ensure_same_commit(
        &policy_commit,
        &wait_held(&fixture.bob, &policy_event.event_id, HELD_WINDOW).await?,
    )?;
    let before = snapshot(&fixture).await?;
    let response = fixture.group.server(1).http().execute(request).await?;
    ensure!(
        response.status() == StatusCode::OK,
        "transport must still authenticate"
    );
    let denied: PeerAuthoritySubmitOutcome = response.json().await?;
    ensure!(
        matches!(&denied, PeerAuthoritySubmitOutcome::CommittedReplication(value)
        if matches!(value.replication_outcomes.as_slice(),
            [PeerCommittedReplicationOutcomeRecord::Rejected { reason_code }]
            if reason_code == "capability_denied")),
        "changed basis replay bypassed full authorization: {denied:?}"
    );
    ensure!(
        snapshot(&fixture).await? == before,
        "denied basis replay changed business state"
    );
    ensure_same_commit(
        &commit,
        &wait_held(&fixture.bob, &event.event_id, HELD_WINDOW).await?,
    )?;
    println!(
        "FEDERATION_FIXTURE /cases/2 changed authorization basis: real accepted policy, current valid transport, capability_denied, full snapshot unchanged"
    );
    Ok(())
}

pub async fn run_federation_revoked_key_before_cache_live() -> Result<()> {
    let mut fixture = manual_current_origin_fixture("federation-key-revoke-before-cache").await?;
    let (request, event, commit) =
        first_stored_request(&fixture, "key-revoke-before-cache").await?;
    let signed_at = Instant::now();
    let old_key = current_federation_key(fixture.group.server(0)).await?;
    let (seed, _) = test_service_signing_key("first-stored-revoke-successor");
    fixture
        .group
        .server_mut(0)
        .restart_external_process_with_notary_signing_key(&seed)
        .await?;
    ensure!(current_federation_key(fixture.group.server(0)).await? != old_key);
    let strand = fixture.alice.default_strand_id(&fixture.realm)?;
    let (fresh_event, fresh_commit) = alice_message(
        &fixture.alice,
        &fixture.alice_account,
        &fixture.realm,
        &strand,
        "prove current successor transport",
    )
    .await?;
    let outcome = replicate(
        fixture.group.server(1),
        fixture.group.server(0),
        &replication_body(&fixture.alice, &fresh_event, &fresh_commit).await?,
    )
    .await?;
    ensure!(
        matches!(
            outcome.as_slice(),
            [PeerCommittedReplicationOutcomeRecord::Stored {}]
        ),
        "current successor failed actual transport and storage: {outcome:?}"
    );
    ensure_same_commit(
        &fresh_commit,
        &wait_held(&fixture.bob, &fresh_event.event_id, HELD_WINDOW).await?,
    )?;
    let before = snapshot(&fixture).await?;
    let url = fixture._member_database.connect_url.clone();
    let original_hash = arkret_canonical::sha256_digest(
        request
            .body()
            .and_then(reqwest::Body::as_bytes)
            .context("frozen revoked request lost its exact body")?,
    )
    .as_str()
    .to_owned();
    let lock = tokio::task::spawn_blocking(move || -> Result<postgres::Client> {
        let mut client = postgres::Client::connect(&url, postgres::NoTls)?;
        let count: i64 = client.query_one(
            "SELECT count(*) FROM idempotency_keys WHERE operation_id='ak.peer.events.command.submit.v1' AND request_hash=$1 AND response_body->'outcome'->>'status'='stored'",
            &[&original_hash])?.get(0);
        ensure!(count == 1, "the exact first Stored request has no unique durable receipt");
        client.batch_execute("BEGIN; LOCK TABLE idempotency_keys IN ACCESS EXCLUSIVE MODE")?;
        Ok(client)
    }).await??;
    for case in ["/cases/0", "/cases/3"] {
        ensure!(
            signed_at.elapsed() < Duration::from_secs(240),
            "revocation proof reached signature expiry"
        );
        let response = tokio::time::timeout(
            Duration::from_secs(10),
            fixture
                .group
                .server(1)
                .http()
                .execute(request.try_clone().context("exact revoked request")?),
        )
        .await
        .context("authentication accessed the locked cache before rejecting revoked key")??;
        let status = response.status();
        let problem: arkret_wire::Problem = response.json().await?;
        ensure!(
            !status.is_success()
                && problem.error_code() == Some(arkret_wire::ErrorCode::SignatureInvalid),
            "revoked exact request failed with wrong reason: {status} {problem:?}"
        );
        ensure!(
            snapshot(&fixture).await? == before,
            "revoked request changed business state"
        );
        println!(
            "FEDERATION_FIXTURE {case}: signature_invalid with cache ACCESS EXCLUSIVE lock held; exact frozen request; full snapshot unchanged"
        );
    }
    tokio::task::spawn_blocking(move || drop(lock)).await?;
    ensure_same_commit(
        &commit,
        &wait_held(&fixture.bob, &event.event_id, HELD_WINDOW).await?,
    )?;
    Ok(())
}
