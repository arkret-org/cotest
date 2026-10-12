//! Signed terminal/departure fanout repairs its authorized Full/Withheld prefix.

use arkret_models_collaboration::authority_commit::PeerStreamScanOutcome;
use arkret_wire::{StreamScanDirection, StreamScanRequest};

use super::frozen_authority_live::{hold_schedule, release, settled};
use super::terminal_restart_live::{ensure_same_intent, fanout, sql, tombstone};
use super::*;
use crate::scenarios::_helpers::acceptance_footprint::acceptance_rows;

async fn commit_row(url: &str, commit: &RealmCommit) -> Result<Option<Value>> {
    let url = url.to_owned();
    let id = commit.commit_id.to_string();
    tokio::task::spawn_blocking(move || -> Result<_> {
        let mut connection = postgres::Client::connect(&url, postgres::NoTls)?;
        Ok(connection
            .query_opt(
                "SELECT to_jsonb(r) FROM realm_commits r WHERE commit_id=$1",
                &[&id],
            )?
            .map(|row| row.get(0)))
    })
    .await?
}

async fn wait_commit(url: &str, commit: &RealmCommit) -> Result<Value> {
    let deadline = Instant::now() + HELD_WINDOW;
    loop {
        if let Some(row) = commit_row(url, commit).await? {
            ensure!(row["commit_json"] == serde_json::to_value(commit)?);
            return Ok(row);
        }
        ensure!(
            Instant::now() < deadline,
            "recovery did not hold {}",
            commit.commit_id
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Fault only writes above the admitted stage, never the admission decision.
async fn gate_through(url: &str, commit: &RealmCommit, position: u64, install: bool) -> Result<()> {
    let stream = arkret_canonical::canonical_json_string(&commit.stream_ref)?;
    sql(url, &format!(
        "CREATE OR REPLACE FUNCTION gate_gap_recovery() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.realm_id='{}' AND NEW.stream_ref='{}'::jsonb AND NEW.stream_position>{position} THEN RAISE EXCEPTION 'test-owned gap recovery write fault'; END IF; RETURN NEW; END $$; {}",
        commit.realm_id, stream,
        if install { "CREATE TRIGGER gate_gap_recovery BEFORE INSERT ON realm_commits FOR EACH ROW EXECUTE FUNCTION gate_gap_recovery()" } else { "" }
    )).await
}

async fn pending_gap(url: &str, commit: &RealmCommit, prior_attempts: i64) -> Result<Value> {
    let deadline = Instant::now() + HELD_WINDOW;
    loop {
        let rows = fanout(url, commit).await?;
        ensure!(rows.len() == 1);
        let row = &rows[0];
        if row["attempts"]
            .as_i64()
            .is_some_and(|count| count > prior_attempts)
            && row["state"] == "pending"
            && row["last_http_status"] == 200
        {
            let answer: PeerAuthoritySubmitOutcome = serde_json::from_str(
                row["last_response_excerpt"]
                    .as_str()
                    .context("signed peer gap response")?,
            )?;
            ensure!(
                matches!(answer, PeerAuthoritySubmitOutcome::CommittedReplication(value)
                if matches!(value.replication_outcomes.as_slice(),
                    [PeerCommittedReplicationOutcomeRecord::Rejected { reason_code }]
                        if reason_code == "dependency_missing")),
                "missing predecessor was not rejected at the continuity boundary: {row}"
            );
            ensure!(row["semantic_attempts"] == 0 && row["completed_at"].is_null());
            return Ok(row.clone());
        }
        ensure!(
            Instant::now() < deadline,
            "original fanout did not retain its gap retry: {row}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn scan(
    fixture: &CurrentOriginFixture,
    request: &StreamScanRequest,
) -> Result<PeerStreamScanOutcome> {
    let body = arkret_canonical::canonical_json_bytes(request)?;
    let (status, answer) = fixture
        .group
        .server(0)
        .signed_peer_post(
            fixture.group.server(1),
            "/_arkret/peer/streams/scan",
            &body,
            fixture.group.server(0).service_id(),
        )
        .await?;
    ensure!(
        status == StatusCode::OK,
        "authorized peer scan: {status} {}",
        String::from_utf8_lossy(&answer)
    );
    let page: PeerStreamScanOutcome = serde_json::from_slice(&answer)?;
    page.validate_for_request(request)?;
    Ok(page)
}

fn withheld_effect(before: &Value, after: &Value, commit: &RealmCommit) -> Result<()> {
    let mut expected = before.clone();
    let old = before["realm_commits"]
        .as_array()
        .context("old held chain")?;
    let new = after["realm_commits"]
        .as_array()
        .context("new held chain")?;
    ensure!(new.len() == old.len() + 1 && old.iter().all(|row| new.contains(row)));
    let additions: Vec<_> = new.iter().filter(|row| !old.contains(row)).collect();
    ensure!(
        additions.len() == 1
            && additions[0]["event_pk"].is_null()
            && additions[0]["commit_json"] == serde_json::to_value(commit)?
    );
    expected["realm_commits"] = after["realm_commits"].clone();
    // A continuity-only node cannot preserve the old authorization cut.
    let old_cuts = before["replica_authorization_cuts"]
        .as_array()
        .context("old authorization cuts")?;
    let new_cuts = after["replica_authorization_cuts"]
        .as_array()
        .context("new authorization cuts")?;
    ensure!(new_cuts.iter().all(|row| old_cuts.contains(row)));
    for row in old_cuts.iter().filter(|row| !new_cuts.contains(row)) {
        ensure!(
            row["realm_id"] == commit.realm_id.as_str()
                && row["source_stream_ref"] == serde_json::to_value(&commit.stream_ref)?
                && row["head_stream_position"]
                    .as_u64()
                    .is_some_and(|position| position < commit.stream_position)
        );
    }
    expected["replica_authorization_cuts"] = after["replica_authorization_cuts"].clone();
    ensure!(
        expected == *after,
        "Withheld changed more than its chain node and stale authorization cut"
    );
    Ok(())
}

fn no_terminal_label(rows: &Value, realm: &str) -> Result<()> {
    ensure!(
        rows["realm_bootstrap_current_results"]
            .as_array()
            .context("lifecycle rows")?
            .iter()
            .all(|row| row["realm_id"] != realm
                || (row["result_family"] != "realm_tombstone"
                    && row["result_family"] != "realm_destroy")),
        "departure synthesized Realm terminal state"
    );
    Ok(())
}

async fn closure_checks(
    fixture: &mut CurrentOriginFixture,
    target: &Event,
    commit: &RealmCommit,
    body: &[u8],
    departure: Option<bool>,
) -> Result<Value> {
    let source_url = fixture._governance_database.connect_url.clone();
    let receiver_url = fixture._member_database.connect_url.clone();
    fixture
        .group
        .server_mut(1)
        .restart_external_process()
        .await?;
    let installed = acceptance_rows(&receiver_url).await?;
    let replay_request = terminal_restart_live::frozen_duplicate_request(
        fixture.group.server(1),
        fixture.group.server(0),
        body,
    )
    .await?;
    for _ in 0..2 {
        terminal_restart_live::replay_frozen_duplicate(fixture.group.server(1), &replay_request)
            .await?;
        ensure!(
            acceptance_rows(&receiver_url).await? == installed,
            "exact replay after gap repair changed acceptance rows"
        );
    }
    let principal = fixture.bob.principal.as_ref().context("hosted member")?;
    let bob_account = AccountId::new(
        principal.core_id.clone(),
        fixture.group.server(1).service_id().clone(),
    );
    if let Some(ban) = departure {
        let member = installed["member_state_current_results"]
            .as_array()
            .context("membership rows")?
            .iter()
            .find(|row| {
                row["realm_id"] == fixture.realm
                    && row["member_id"] == ActorId::account(bob_account.clone()).to_string()
            })
            .context("terminating member current")?;
        ensure!(member["membership"] == if ban { "ban" } else { "leave" });
        ensure!(member["current_commit_id"] == commit.commit_id.as_str());
        no_terminal_label(&installed, &fixture.realm)?;
        let after = alice_message(
            &fixture.alice,
            &fixture.alice_account,
            &fixture.realm,
            &fixture.alice.default_strand_id(&fixture.realm)?,
            "private post-departure gap exclusion",
        )
        .await?;
        let (terminal, terminal_commit) = tombstone(fixture).await?;
        ensure!(fanout(&source_url, &after.1).await?.is_empty());
        ensure!(fanout(&source_url, &terminal_commit).await?.is_empty());
        let request = StreamScanRequest {
            realm_id: commit.realm_id.clone(),
            stream_ref: commit.stream_ref.clone(),
            direction: StreamScanDirection::After(Some(commit.stream_position)),
            limit: 128,
        };
        let page = scan(fixture, &request).await?;
        ensure!(
            page.committed_events.is_empty()
                && !page.truncated
                && page.producer_signer_facts.is_empty(),
            "departure scan exposed a post-cut Commit, even as Withheld"
        );
        let mut reverse = request.clone();
        reverse.direction = StreamScanDirection::Before(None);
        reverse.limit = 1;
        let page = scan(fixture, &reverse).await?;
        ensure!(
            matches!(page.committed_events.as_slice(), [CommittedEventView::Full(row)]
            if row.event == *target && row.commit == *commit),
            "reverse scan crossed the departure cut"
        );
        ensure!(
            after.1.previous_commit_ref.as_ref() == Some(&commit.commit_id)
                && after.1.stream_position == commit.stream_position + 1
        );
        let late_message = replication_body(&fixture.alice, &after.0, &after.1).await?;
        let late_terminal = replication_body(&fixture.alice, &terminal, &terminal_commit).await?;
        // Both positions exceed the verified membership interval. Current
        // recipient authority is checked before continuity/cache access;
        // a post-cut gap cannot restore or disclose replication eligibility.
        for late in [&late_message, &late_terminal] {
            let expected = "capability_denied";
            for _ in 0..2 {
                let outcome =
                    replicate(fixture.group.server(1), fixture.group.server(0), late).await?;
                ensure!(
                    matches!(outcome.as_slice(),
                    [PeerCommittedReplicationOutcomeRecord::Rejected { reason_code }] if reason_code == expected),
                    "post-departure signed replica expected {expected}, received {outcome:?}"
                );
                ensure!(acceptance_rows(&receiver_url).await? == installed);
            }
        }
        ensure!(
            commit_row(&receiver_url, &after.1).await?.is_none()
                && commit_row(&receiver_url, &terminal_commit).await?.is_none()
        );
    } else {
        let lifecycle = installed["realm_bootstrap_current_results"]
            .as_array()
            .context("terminal rows")?
            .iter()
            .find(|row| {
                row["realm_id"] == fixture.realm && row["result_family"] == "realm_tombstone"
            })
            .context("verified terminal fence")?;
        let payload: arkret_models_collaboration::governance::realm_lifecycle::RealmTombstonePayload =
            serde_json::from_value(serde_json::to_value(&target.payload)?)?;
        ensure!(
            lifecycle["current_commit_id"] == commit.commit_id.as_str()
                && lifecycle["value"] == payload.to_value()?
        );
    }
    // The same member already completed a real signed join at this Origin.
    let candidate = fixture
        .bob
        .author_event(
            &fixture.realm,
            EventKind::MessageCreate.as_str(),
            message_create_text_payload(
                &fixture.alice.default_strand_id(&fixture.realm)?,
                "ordinary write after closed gap",
            )?,
        )
        .await?;
    let source_before = acceptance_rows(&source_url).await?;
    let response = fixture
        .bob
        .post("/_arkret/self/events")
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(arkret_canonical::canonical_json_bytes(
            &crate::publication::initial_submission(candidate, "")?,
        )?)
        .send()
        .await?;
    let status = response.status();
    let problem: arkret_wire::Problem = response.json().await?;
    ensure!(
        status.is_client_error() && problem.problem_type.ends_with("failed_precondition"),
        "closed gap ordinary proxy: {status} {problem:?}"
    );
    if departure.is_some() {
        ensure!(
            problem
                .detail
                .contains("held stream has no live hosted-member authority")
        );
    }
    ensure!(
        problem
            .extensions
            .get("reason_code")
            .and_then(Value::as_str)
            != Some("realm_terminal_state")
    );
    ensure!(
        acceptance_rows(&source_url).await? == source_before,
        "closed Origin forwarded a new Event"
    );
    super::terminal_restart_live::ensure_ordinary_refusal_rows(
        &installed,
        acceptance_rows(&receiver_url).await?,
        &fixture.bob,
    )?;
    Ok(installed)
}

pub async fn recover(departure: Option<bool>) -> Result<()> {
    let name = match departure {
        None => "terminal-missing-predecessor",
        Some(false) => "departure-leave-gap",
        Some(true) => "departure-ban-gap",
    };
    let Some(mut fixture) = Box::pin(current_origin_fixture_with_plaintext(name, false)).await?
    else {
        return Ok(());
    };
    let source_url = fixture._governance_database.connect_url.clone();
    let receiver_url = fixture._member_database.connect_url.clone();
    let principal = fixture
        .bob
        .principal
        .as_ref()
        .context("member grant principal")?;
    let bob_account = AccountId::new(
        principal.core_id.clone(),
        fixture.group.server(1).service_id().clone(),
    );
    let grant = crate::scenarios::human_device_producer_live::grant_realm_actions(
        &fixture.alice,
        fixture.group.server(0),
        &fixture.realm,
        &bob_account,
        &["ak.message.create"],
    )
    .await?;
    ensure_same_commit(
        &grant,
        &wait_held(&fixture.bob, &grant.event_ref, HELD_WINDOW).await?,
    )?;
    settled(&source_url, &grant, "delivered").await?;
    fixture.bob.remember_grant(
        &fixture.realm,
        arkret_wire::GrantId::from_event_id(&grant.event_ref).as_str(),
        &["ak.message.create"],
    );
    // Finish the opening join before freezing every new outbox schedule.
    let initial = acceptance_rows(&receiver_url).await?;
    let head: RealmCommit = serde_json::from_value(
        initial["realm_commits"]
            .as_array()
            .context("initial chain")?
            .iter()
            .filter(|row| row["realm_id"] == fixture.realm)
            .max_by_key(|row| row["stream_position"].as_u64())
            .context("initial held head")?["commit_json"]
            .clone(),
    )?;
    settled(&source_url, &head, "delivered").await?;
    hold_schedule(&source_url, false).await?;
    let (carol, carol_account) = standard_client(
        fixture.group.server(0),
        &fixture._coauth,
        "gap-carol",
        CAROL_DEVICE,
    )
    .await?;
    let predecessor = carol
        .author_event(
            &fixture.realm,
            EventKind::MemberState.as_str(),
            membership_payload(
                &fixture.realm,
                carol_account.clone(),
                MembershipPayloadState::Join,
                "full gap predecessor",
            )?,
        )
        .await?;
    let predecessor_commit =
        submit_and_expect_commit(&carol, &carol_account, CAROL_DEVICE, &predecessor).await?;
    let (private, private_commit) = alice_message(
        &fixture.alice,
        &fixture.alice_account,
        &fixture.realm,
        &fixture.alice.default_strand_id(&fixture.realm)?,
        "withheld plaintext gap secret",
    )
    .await?;
    ensure!(predecessor_commit.stream_position == head.stream_position + 1);
    private_commit.validate_successor_of(&predecessor_commit)?;
    ensure!(
        fanout(&source_url, &private_commit).await?.is_empty(),
        "private plaintext created an unauthorized intent"
    );
    let (target, target_commit) = if let Some(ban) = departure {
        let principal = fixture.bob.principal.as_ref().context("departing member")?;
        let bob_account = AccountId::new(
            principal.core_id.clone(),
            fixture.group.server(1).service_id().clone(),
        );
        let event = fixture
            .alice
            .author_event(
                &fixture.realm,
                EventKind::MemberState.as_str(),
                membership_payload(
                    &fixture.realm,
                    bob_account,
                    if ban {
                        MembershipPayloadState::Ban
                    } else {
                        MembershipPayloadState::Leave
                    },
                    "last hosted member with gap",
                )?,
            )
            .await?;
        let commit =
            submit_and_expect_commit(&fixture.alice, &fixture.alice_account, ALICE_DEVICE, &event)
                .await?;
        (event, commit)
    } else {
        tombstone(&fixture).await?
    };
    target_commit.validate_successor_of(&private_commit)?;
    let frozen = fanout(&source_url, &target_commit).await?;
    ensure!(frozen.len() == 1 && frozen[0]["attempts"] == 0 && frozen[0]["semantic_attempts"] == 0);
    let body = replication_body(&fixture.alice, &target, &target_commit).await?;
    ensure!(frozen[0]["payload_json"].as_str().map(str::as_bytes) == Some(body.as_slice()));
    let request = StreamScanRequest {
        realm_id: target_commit.realm_id.clone(),
        stream_ref: target_commit.stream_ref.clone(),
        direction: StreamScanDirection::After(Some(head.stream_position)),
        limit: 128,
    };
    let authorized = scan(&fixture, &request).await?;
    ensure!(
        matches!(authorized.committed_events.as_slice(),
        [CommittedEventView::Full(first), CommittedEventView::Withheld(hidden), CommittedEventView::Full(last)]
        if first.event == predecessor && first.commit == predecessor_commit
            && hidden.commit == private_commit && last.event == target && last.commit == target_commit),
        "governor did not provide the exact authorized Full/Withheld/Full prefix: {authorized:?}"
    );
    ensure!(
        authorized
            .producer_signer_facts
            .iter()
            .all(|entry| entry.target.commit_id != private_commit.commit_id)
    );
    ensure!(!serde_json::to_string(&authorized)?.contains("withheld plaintext gap secret"));
    gate_through(&receiver_url, &target_commit, head.stream_position, true).await?;
    let before = acceptance_rows(&receiver_url).await?;
    release(&source_url, &frozen[0]).await?;
    let first_retry = pending_gap(&source_url, &target_commit, 0).await?;
    ensure_same_intent(&frozen[0], &first_retry)?;
    ensure!(
        acceptance_rows(&receiver_url).await? == before,
        "discontinuous target or faulted repair mutated accepting rows"
    );
    ensure!(commit_row(&receiver_url, &target_commit).await?.is_none());
    gate_through(
        &receiver_url,
        &target_commit,
        predecessor_commit.stream_position,
        false,
    )
    .await?;
    release(&source_url, &first_retry).await?;
    wait_commit(&receiver_url, &predecessor_commit).await?;
    ensure!(commit_row(&receiver_url, &private_commit).await?.is_none());
    let full_prefix = acceptance_rows(&receiver_url).await?;
    ensure!(
        full_prefix["canonical_events"]
            .as_array()
            .context("Full originals")?
            .iter()
            .any(|row| row["envelope"] == serde_json::to_value(&predecessor).unwrap())
    );
    gate_through(
        &receiver_url,
        &target_commit,
        private_commit.stream_position,
        false,
    )
    .await?;
    release(
        &source_url,
        &fanout(&source_url, &target_commit).await?.remove(0),
    )
    .await?;
    wait_commit(&receiver_url, &private_commit).await?;
    let withheld_prefix = acceptance_rows(&receiver_url).await?;
    withheld_effect(&full_prefix, &withheld_prefix, &private_commit)?;
    ensure!(commit_row(&receiver_url, &target_commit).await?.is_none());
    ensure!(
        matches!(fixture.bob.sdk().committed_event_get(&private.event_id).await?,
        CommittedEventView::Withheld(row) if row.commit == private_commit)
    );
    sql(
        &receiver_url,
        "DROP TRIGGER gate_gap_recovery ON realm_commits; DROP FUNCTION gate_gap_recovery()",
    )
    .await?;
    release(
        &source_url,
        &fanout(&source_url, &target_commit).await?.remove(0),
    )
    .await?;
    let delivered = settled(&source_url, &target_commit, "delivered").await?;
    ensure_same_intent(&frozen[0], &delivered)?;
    ensure!(
        delivered["attempts"]
            .as_i64()
            .is_some_and(|count| count >= 2)
            && delivered["semantic_attempts"] == 0
            && delivered["last_http_status"] == 200
    );
    let answer: PeerAuthoritySubmitOutcome = serde_json::from_str(
        delivered["last_response_excerpt"]
            .as_str()
            .context("successful retry response")?,
    )?;
    ensure!(
        matches!(answer, PeerAuthoritySubmitOutcome::CommittedReplication(value)
        if matches!(value.replication_outcomes.as_slice(), [PeerCommittedReplicationOutcomeRecord::Stored {} | PeerCommittedReplicationOutcomeRecord::Duplicate {}]))
    );
    ensure!(wait_commit(&receiver_url, &target_commit).await?["event_pk"].is_number());
    let original_predecessor = fanout(&source_url, &predecessor_commit).await?.remove(0);
    release(&source_url, &original_predecessor).await?;
    let prior = settled(
        &source_url,
        &predecessor_commit,
        if departure.is_some() {
            "cancelled_authority_lost"
        } else {
            "delivered"
        },
    )
    .await?;
    ensure_same_intent(&original_predecessor, &prior)?;
    let installed = Box::pin(closure_checks(
        &mut fixture,
        &target,
        &target_commit,
        &body,
        departure,
    ))
    .await?;
    let evidence = json!({"scenario":name,"head_before":head,"full_predecessor":predecessor_commit,
        "withheld_commit":private_commit,"target":target_commit,"authorized_page":authorized,
        "frozen_intent":frozen[0],"first_dependency_retry":first_retry,"delivered_intent":delivered,
        "before_gap":before,"full_prefix":full_prefix,"withheld_prefix":withheld_prefix,"after_restart":installed});
    let directory =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("artifacts/terminal-gap-recovery");
    std::fs::create_dir_all(&directory)?;
    std::fs::write(
        directory.join(format!("{name}.json")),
        serde_json::to_vec_pretty(&evidence)?,
    )?;
    eprintln!(
        "[terminal-gap] boundary={name} actual_tls_stations=2 signed_dispatcher_dependency_missing=1 discontinuous_target_zero_acceptance_writes=1 authorized_full_predecessor=1 withheld_exact_chain_only=1 stale_cut_invalidated=1 original_key_body_basis_retry=1 receiver_process_restart=1 duplicate_zero_effects=2 departure_scan_terminal_history_excluded={} origin_proxy_closed=1",
        usize::from(departure.is_some())
    );
    Ok(())
}
