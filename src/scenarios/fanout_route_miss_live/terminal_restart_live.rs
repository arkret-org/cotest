//! Actual retained Station process restarts, not storage-adapter reconstruction.

use arkret_models_collaboration::governance::realm_lifecycle::RealmTombstonePayload;

use super::*;

async fn sql(url: &str, statement: &str) -> Result<()> {
    let url = url.to_owned();
    let statement = statement.to_owned();
    tokio::task::spawn_blocking(move || -> Result<()> {
        postgres::Client::connect(&url, postgres::NoTls)?.batch_execute(&statement)?;
        Ok(())
    })
    .await?
}

async fn fanout(url: &str, commit: &RealmCommit) -> Result<Vec<Value>> {
    let url = url.to_owned();
    let event = commit.event_ref.to_string();
    tokio::task::spawn_blocking(move || -> Result<_> {
        let mut connection = postgres::Client::connect(&url, postgres::NoTls)?;
        Ok(connection.query(
            "SELECT to_jsonb(r) FROM federation_outbox r WHERE realm_fanout->'source_event_ids' ? $1 ORDER BY id",
            &[&event],
        )?.into_iter().map(|row| row.get(0)).collect())
    }).await?
}

/// Capture accepting effects and the independent general signer-query cache.
async fn acceptance_rows(url: &str) -> Result<Value> {
    let url = url.to_owned();
    tokio::task::spawn_blocking(move || -> Result<_> {
        let mut connection = postgres::Client::connect(&url, postgres::NoTls)?;
        let mut transaction = connection.build_transaction().isolation_level(postgres::IsolationLevel::RepeatableRead).start()?;
        let tables = transaction.query("SELECT tablename::text FROM pg_tables WHERE schemaname='public' AND (tablename LIKE '%current_results' OR tablename IN ('canonical_events','realm_commits','realm_authorities','federation_outbox','event_federation_outbox','replica_stream_anchors','replica_authorization_rows','replica_authorization_cuts','account_summary_current','account_summary_versions','account_summary_clock','current_result_heads','current_result_versions','direct_conversation_founding_slots','agent_producer_signer_keys','account_device_signer_evidence','account_device_committed_evidence','forwarded_producer_device_evidence','forwarded_producer_agent_evidence','governance_unscoped_signer_evidence')) ORDER BY tablename", &[])?;
        let mut snapshot = serde_json::Map::new();
        for table in tables {
            let name: String = table.get(0);
            ensure!(name.bytes().all(|byte| byte.is_ascii_lowercase() || byte == b'_'));
            let statement = format!("SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),'[]'::jsonb) FROM public.{name} r");
            snapshot.insert(name, transaction.query_one(&statement, &[])?.get(0));
        }
        for name in ["canonical_events", "realm_commits", "realm_authorities", "federation_outbox", "event_federation_outbox", "replica_stream_anchors", "replica_authorization_cuts", "member_state_current_results", "account_summary_current"] {
            ensure!(snapshot.contains_key(name), "acceptance footprint lacks {name}");
        }
        transaction.commit()?;
        Ok(Value::Object(snapshot))
    }).await?
}

async fn tombstone(fixture: &CurrentOriginFixture) -> Result<(Event, RealmCommit)> {
    let successor = fixture
        .alice
        .create_realm("Terminal restart successor")
        .await?;
    let event = fixture
        .alice
        .author_event(
            &fixture.realm,
            EventKind::RealmTombstone.as_str(),
            RealmTombstonePayload::new(RealmId::new(successor)?, "migration").to_value()?,
        )
        .await?;
    let commit =
        submit_and_expect_commit(&fixture.alice, &fixture.alice_account, ALICE_DEVICE, &event)
            .await?;
    Ok((event, commit))
}

fn ensure_ordinary_refusal_rows(
    before: &Value,
    mut after: Value,
    client: &TestActorClient,
) -> Result<()> {
    let old = before["account_device_signer_evidence"]
        .as_array()
        .context("old signer cache")?;
    let rows = after["account_device_signer_evidence"]
        .as_array()
        .context("new signer cache")?;
    ensure!(
        old.iter().all(|row| rows.contains(row)),
        "refusal changed existing signer evidence"
    );
    ensure!(
        rows.len() <= old.len() + 1,
        "refusal retained more than one general signer query root"
    );
    let principal = client
        .principal
        .as_ref()
        .context("refused device principal")?;
    let account = AccountId::new(principal.core_id.clone(), client.service_id().parse()?);
    for row in rows.iter().filter(|row| !old.contains(row)) {
        let evidence: arkret_models_identity::AccountDeviceSignerEvidence =
            serde_json::from_value(row["evidence_json"].clone())?;
        evidence.validate_binding(&account, &principal.device_id)?;
        ensure!(row["evidence_ref"] == serde_json::to_value(evidence.signer_evidence_ref()?)?);
    }
    after["account_device_signer_evidence"] = before["account_device_signer_evidence"].clone();
    ensure!(
        &after == before,
        "refused ordinary request mutated accepting rows or forward evidence"
    );
    Ok(())
}

fn ensure_same_intent(before: &Value, after: &Value) -> Result<()> {
    for key in [
        "id",
        "peer_id",
        "endpoint",
        "idempotency_key",
        "payload_json",
        "realm_fanout",
        "created_at",
    ] {
        ensure!(
            before[key] == after[key],
            "restart changed frozen intent {key}"
        );
    }
    Ok(())
}

async fn qualified_ordinary_candidate(
    fixture: &CurrentOriginFixture,
) -> Result<(Event, RealmCommit, Event)> {
    let principal = fixture.bob.principal.as_ref().context("member principal")?;
    let account = AccountId::new(
        principal.core_id.clone(),
        fixture.group.server(1).service_id().clone(),
    );
    let grant = crate::scenarios::human_device_producer_live::grant_realm_actions(
        &fixture.alice,
        fixture.group.server(0),
        &fixture.realm,
        &account,
        &["ak.message.create"],
    )
    .await?;
    ensure_same_commit(
        &grant,
        &wait_held(&fixture.bob, &grant.event_ref, HELD_WINDOW).await?,
    )?;
    fixture.bob.remember_grant(
        &fixture.realm,
        arkret_wire::GrantId::from_event_id(&grant.event_ref).as_str(),
        &["ak.message.create"],
    );
    let control = fixture
        .bob
        .author_event(
            &fixture.realm,
            EventKind::MessageCreate.as_str(),
            message_create_text_payload(
                &fixture.alice.default_strand_id(&fixture.realm)?,
                "qualified member writer",
            )?,
        )
        .await?;
    let commit = submit_and_expect_commit(&fixture.bob, &account, BOB_DEVICE, &control).await?;
    ensure_same_commit(
        &commit,
        &wait_held(&fixture.bob, &control.event_id, HELD_WINDOW).await?,
    )?;
    let candidate = fixture
        .bob
        .author_event(
            &fixture.realm,
            EventKind::MessageCreate.as_str(),
            message_create_text_payload(
                &fixture.alice.default_strand_id(&fixture.realm)?,
                "prepared member write after restart",
            )?,
        )
        .await?;
    Ok((control, commit, candidate))
}

pub async fn pending_terminal_survives_restart(route_miss: bool) -> Result<()> {
    let name = if route_miss {
        "terminal-pending-route-restart"
    } else {
        "terminal-pending-delivery-restart"
    };
    let Some(mut fixture) = current_origin_fixture(name).await? else {
        return Ok(());
    };
    let (control, control_commit, fresh) = qualified_ordinary_candidate(&fixture).await?;
    let source_url = &fixture._governance_database.connect_url;
    fixture.group.server_mut(1).stop_external_process().await?;
    // Hold only the scheduling timestamp so acceptance's initial state can be
    // observed before killing the source. The production payload is untouched.
    sql(source_url, "CREATE FUNCTION hold_terminal_schedule() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN NEW.next_attempt_at := (extract(epoch FROM clock_timestamp()) * 1000)::bigint + 60000; RETURN NEW; END $$; CREATE TRIGGER hold_terminal_schedule BEFORE INSERT ON federation_outbox FOR EACH ROW EXECUTE FUNCTION hold_terminal_schedule()").await?;
    if route_miss {
        sql(source_url, "DELETE FROM service_route_cache").await?;
    }
    let (event, commit) = tombstone(&fixture).await?;
    let before = fanout(source_url, &commit).await?;
    ensure!(
        before.len() == 1,
        "terminal must freeze exactly one recipient Station"
    );
    ensure!(
        before[0]["state"]
            == if route_miss {
                "pending_route"
            } else {
                "pending"
            },
        "wrong initial terminal intent state: {}",
        before[0]
    );
    ensure!(before[0]["attempts"] == 0);
    let exact_body = replication_body(&fixture.alice, &event, &commit).await?;
    ensure!(
        before[0]["payload_json"].as_str().map(str::as_bytes) == Some(exact_body.as_slice()),
        "source intent must contain exact canonical SDK request"
    );
    fixture.group.server_mut(0).stop_external_process().await?;
    ensure!(
        fanout(source_url, &commit).await? == before,
        "killing the source changed durable intent"
    );
    sql(source_url, "DROP TRIGGER hold_terminal_schedule ON federation_outbox; DROP FUNCTION hold_terminal_schedule(); UPDATE federation_outbox SET next_attempt_at=0 WHERE state IN ('pending','pending_route')").await?;
    fixture.group.server_mut(1).start_external_process().await?;
    fixture.group.server_mut(0).start_external_process().await?;
    ensure_same_commit(
        &commit,
        &wait_held(&fixture.bob, &event.event_id, ROUTE_MISS_WINDOW).await?,
    )?;
    let deadline = Instant::now() + HELD_WINDOW;
    loop {
        let after = fanout(source_url, &commit).await?;
        ensure!(after.len() == 1);
        ensure_same_intent(&before[0], &after[0])?;
        if after[0]["state"] == "delivered" {
            break;
        }
        ensure!(
            Instant::now() < deadline,
            "restarted source did not settle terminal delivery"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    // Restart the installed receiver as well; both duplicate transport and a
    // fresh ordinary candidate must retain the terminal fence.
    fixture
        .group
        .server_mut(1)
        .restart_external_process()
        .await?;
    let receiver_url = &fixture._member_database.connect_url;
    let installed = acceptance_rows(receiver_url).await?;
    let source_installed = acceptance_rows(source_url).await?;
    let response = fixture
        .bob
        .post("/_arkret/self/events")
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(arkret_canonical::canonical_json_bytes(
            &crate::publication::initial_submission(control, "")?,
        )?)
        .send()
        .await?;
    let status = response.status();
    let replay: arkret_wire::AuthoritySubmitOutcome = response.json().await?;
    ensure!(
        status == StatusCode::OK
            && matches!(replay, arkret_wire::AuthoritySubmitOutcome::Accepted { commit, .. } if commit == control_commit),
        "accepted ordinary original lost its exact outcome after terminal restart"
    );
    ensure!(acceptance_rows(receiver_url).await? == installed);
    ensure!(acceptance_rows(source_url).await? == source_installed);
    for _ in 0..2 {
        ensure!(matches!(
            replicate(
                fixture.group.server(1),
                fixture.group.server(0),
                &exact_body
            )
            .await?
            .as_slice(),
            [PeerCommittedReplicationOutcomeRecord::Duplicate {}]
        ));
        ensure!(
            acceptance_rows(receiver_url).await? == installed,
            "terminal replay after restart has fresh acceptance effects"
        );
    }
    let response = fixture
        .bob
        .post("/_arkret/self/events")
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(arkret_canonical::canonical_json_bytes(
            &crate::publication::initial_submission(fresh, "")?,
        )?)
        .send()
        .await?;
    let status = response.status();
    let problem: arkret_wire::Problem = response.json().await?;
    ensure!(
        status.is_client_error() && problem.problem_type.ends_with("failed_precondition"),
        "terminal restart ordinary write: {status} {problem:?}"
    );
    ensure!(
        problem
            .extensions
            .get("reason_code")
            .and_then(Value::as_str)
            != Some("realm_terminal_state")
    );
    ensure_ordinary_refusal_rows(
        &installed,
        acceptance_rows(receiver_url).await?,
        &fixture.bob,
    )?;
    eprintln!(
        "[terminal-restart] initial_state={} source_process_restart=1 receiver_process_restart=2 exact_key_body_basis_preserved=1 signed_delivery=1 duplicate_zero_acceptance_effects=2 ordinary_write_denied=1",
        if route_miss {
            "pending_route"
        } else {
            "pending_delivery"
        }
    );
    Ok(())
}

pub async fn departure_survives_restart(ban: bool) -> Result<()> {
    let name = if ban {
        "terminal-ban-restart"
    } else {
        "terminal-leave-restart"
    };
    let Some(mut fixture) = current_origin_fixture(name).await? else {
        return Ok(());
    };
    let (_, _, ordinary) = qualified_ordinary_candidate(&fixture).await?;
    let principal = fixture.bob.principal.as_ref().context("member principal")?;
    let account = AccountId::new(
        principal.core_id.clone(),
        fixture.group.server(1).service_id().clone(),
    );
    let author = if ban { &fixture.alice } else { &fixture.bob };
    let author_account = if ban {
        &fixture.alice_account
    } else {
        &account
    };
    let device = if ban { ALICE_DEVICE } else { BOB_DEVICE };
    let removal = author
        .author_event(
            &fixture.realm,
            EventKind::MemberState.as_str(),
            membership_payload(
                &fixture.realm,
                account.clone(),
                if ban {
                    MembershipPayloadState::Ban
                } else {
                    MembershipPayloadState::Leave
                },
                "terminal restart departure",
            )?,
        )
        .await?;
    let removal_commit = submit_and_expect_commit(author, author_account, device, &removal).await?;
    wait_not_listed(&fixture.bob, &fixture.realm, ROUTE_MISS_WINDOW).await?;
    let removal_body = replication_body(author, &removal, &removal_commit).await?;
    fixture
        .group
        .server_mut(1)
        .restart_external_process()
        .await?;
    wait_not_listed(&fixture.bob, &fixture.realm, HELD_WINDOW).await?;
    let receiver_url = &fixture._member_database.connect_url;
    let departed = acceptance_rows(receiver_url).await?;
    let member = departed["member_state_current_results"]
        .as_array()
        .context("member current rows")?
        .iter()
        .find(|row| {
            row["realm_id"] == fixture.realm
                && row["member_id"] == ActorId::account(account.clone()).to_string()
        })
        .context("departed member row")?;
    ensure!(member["membership"] == if ban { "ban" } else { "leave" });
    ensure!(member["current_commit_id"] == removal_commit.commit_id.as_str());
    ensure!(
        departed["realm_bootstrap_current_results"]
            .as_array()
            .context("Realm lifecycle rows")?
            .iter()
            .all(|row| {
                row["realm_id"] != fixture.realm
                    || (row["result_family"] != "realm_tombstone"
                        && row["result_family"] != "realm_destroy")
            }),
        "departure forged a Realm terminal projection"
    );
    for _ in 0..2 {
        ensure!(matches!(
            replicate(
                fixture.group.server(1),
                fixture.group.server(0),
                &removal_body
            )
            .await?
            .as_slice(),
            [PeerCommittedReplicationOutcomeRecord::Duplicate {}]
        ));
        ensure!(acceptance_rows(receiver_url).await? == departed);
    }
    let (terminal, terminal_commit) = tombstone(&fixture).await?;
    ensure!(
        fanout(&fixture._governance_database.connect_url, &terminal_commit)
            .await?
            .is_empty(),
        "departed holder received a new terminal obligation"
    );
    let terminal_body = replication_body(&fixture.alice, &terminal, &terminal_commit).await?;
    for _ in 0..2 {
        ensure!(
            matches!(replicate(fixture.group.server(1), fixture.group.server(0), &terminal_body).await?.as_slice(), [PeerCommittedReplicationOutcomeRecord::Rejected { reason_code }] if reason_code == "capability_denied"),
            "restarted departure holder accepted late terminal"
        );
        ensure!(
            acceptance_rows(receiver_url).await? == departed,
            "late terminal changed departed acceptance rows"
        );
    }
    let source_before = acceptance_rows(&fixture._governance_database.connect_url).await?;
    let response = fixture
        .bob
        .post("/_arkret/self/events")
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(arkret_canonical::canonical_json_bytes(
            &crate::publication::initial_submission(ordinary, "")?,
        )?)
        .send()
        .await?;
    let status = response.status();
    let problem: arkret_wire::Problem = response.json().await?;
    ensure!(
        status.is_client_error()
            && problem.problem_type.ends_with("failed_precondition")
            && problem
                .detail
                .contains("held stream has no live hosted-member authority"),
        "restarted departure must deny at origin live gate: {status} {problem:?}"
    );
    ensure_ordinary_refusal_rows(
        &departed,
        acceptance_rows(receiver_url).await?,
        &fixture.bob,
    )?;
    ensure!(
        acceptance_rows(&fixture._governance_database.connect_url).await? == source_before,
        "departed origin forwarded a fresh write"
    );
    eprintln!(
        "[terminal-restart] departure={} actual_receiver_process_restart=1 durable_membership_revision=1 duplicate_zero_acceptance_effects=2 no_later_terminal_intent=1 late_signed_terminal_denied=2 origin_live_forward_denied=1",
        if ban { "ban" } else { "leave" }
    );
    Ok(())
}
