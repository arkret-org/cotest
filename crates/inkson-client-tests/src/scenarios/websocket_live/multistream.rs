//! More than one hint page through the unmodified native Realm follower.

use arkret_wire::{ActorId, CommitStreamRef, EventKind, RealmId, StrandId};
use cotest::scenarios::circle_parent_membership_live::grant_circle_actions;
use cotest::scenarios::circle_poll_scope_live::{circle_create, circle_event};
use cotest::scenarios::human_device_producer_live::{
    create_realm_with_join_rule, membership_payload, prepare_join, station_env,
    submit_and_expect_commit, wait_for_committed,
};
use cotest::scenarios::mls_lifecycle_live::Member;
use serde_json::json;

use super::*;

pub async fn run() -> Result<()> {
    cotest::harness::heap_future(|| run_matrix(65)).await
}

pub async fn run_busy_cut() -> Result<()> {
    cotest::harness::heap_future(|| run_matrix(2)).await
}

async fn wait_member_snapshot(
    client: &cotest::harness::TestActorClient,
    realm: &RealmId,
) -> Result<arkret_wire::RealmStateSnapshot> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(120);
    loop {
        match client.sdk().realm_state_snapshot_head(realm).await {
            Ok(snapshot) => {
                let repeated = client.sdk().realm_state_snapshot_head(realm).await?;
                for emitted in [&snapshot, &repeated] {
                    let retained = client
                        .sdk()
                        .realm_state_snapshot_by_ref(realm, &emitted.snapshot_id)
                        .await?;
                    ensure!(
                        arkret_canonical::canonical_json_bytes(&serde_json::to_value(emitted)?)?
                            == arkret_canonical::canonical_json_bytes(&serde_json::to_value(
                                retained
                            )?)?,
                        "a member head must retain its complete exact by-ref original"
                    );
                }
                let same_cut = snapshot.realm_id == repeated.realm_id
                    && snapshot.governance_generation == repeated.governance_generation
                    && snapshot.visible_stream_heads == repeated.visible_stream_heads
                    && snapshot.current_state_entries == repeated.current_state_entries
                    && snapshot.retention_and_history_floor == repeated.retention_and_history_floor
                    && snapshot.signature.verification_method
                        == repeated.signature.verification_method;
                if same_cut {
                    ensure!(
                        snapshot.snapshot_id == repeated.snapshot_id,
                        "an unchanged member cut must reuse its retained original"
                    );
                }
                eprintln!(
                    "[2133-snapshot-ref] exact_roundtrips=2 same_cut_reused={}",
                    usize::from(same_cut)
                );
                ensure!(
                    snapshot
                        .retention_and_history_floor
                        .stream_floors
                        .iter()
                        .filter(|floor| matches!(floor.stream_ref, CommitStreamRef::Circle { .. }))
                        .all(|floor| floor.oldest_position > 0),
                    "the remote member must retain its since-join Circle floors"
                );
                return Ok(snapshot);
            }
            Err(arkret_http_client::Error::Api { status: 503, error })
                if error.error_code()
                    == Some(arkret_wire::ErrorCode::RealmStateSnapshotUnavailable)
                    && tokio::time::Instant::now() < deadline =>
            {
                // Native replica convergence can lag a replicated grant. Wait
                // for the complete cut used by the parent-membership lookup.
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(error) => return Err(error.into()),
        }
    }
}

async fn join_at_parent(
    client: &cotest::harness::TestActorClient,
    realm: &str,
    circle: &arkret_wire::CircleId,
    actor: &ActorId,
    parent: &arkret_wire::CurrentRevision,
) -> Result<()> {
    let join = circle_event(
        client,
        realm,
        circle,
        EventKind::CircleMemberState,
        json!({
            "circle_id":circle,"member_id":actor,"membership":"join",
            "parent_membership_revision":parent,"expected_membership":null
        }),
    )
    .await?;
    cotest::harness::expect_json(
        client
            .post(&format!("/_arkret/self/circles/{circle}/members"))
            .json(
                &arkret_models_collaboration::governance::circle::CircleMemberRequestBody {
                    member_event: arkret_wire::EventAdmissionSubmission::new(join),
                },
            ),
        reqwest::StatusCode::OK,
    )
    .await?;
    Ok(())
}

// These are later, independent read-only cuts, not the failed HTTP read's cut.
// The exact Grant is selected by its fixture inputs, never by a latest-row or
// error-message heuristic. No returned private identifier is printed verbatim.
const GRANT_FAILURE_GOVERNANCE_SQL: &str = r"
BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET LOCAL statement_timeout='500ms';
SET LOCAL lock_timeout='250ms';
WITH matches AS (
    SELECT c.commit_json->>'event_ref' AS event_ref,c.commit_id,c.stream_position
    FROM canonical_events e JOIN realm_commits c ON c.event_pk=e.pk
    WHERE e.realm_id=:'realm' AND e.kind='ak.capability.grant' AND e.state='committed'
      AND e.scope_ref=:'stream'::jsonb AND c.realm_id=:'realm' AND c.stream_key=:'stream_key'
      AND c.stream_ref=:'stream'::jsonb AND e.envelope->>'event_id'=c.commit_json->>'event_ref'
      AND e.envelope->'actor_id'=:'issuer'::jsonb
      AND e.envelope->'payload'->'grant'->'issuer_id'=:'issuer'::jsonb
      AND e.envelope->'payload'->'grant'->'subject'=:'subject'::jsonb
      AND e.envelope->'payload'->'grant'->'actions'=:'actions'::jsonb
      AND e.envelope->'payload'->'grant'->'resources'=:'resources'::jsonb
), exact AS (
    SELECT event_ref,commit_id,stream_position FROM matches WHERE (SELECT COUNT(*) FROM matches)=1
), head AS (
    SELECT commit_id,stream_position FROM realm_commits
    WHERE realm_id=:'realm' AND stream_key=:'stream_key'
    ORDER BY stream_position DESC LIMIT 1
), outbox AS (
    SELECT o.state,o.attempts,o.semantic_attempts,o.last_http_status,
      o.last_error_code IS NOT NULL AS error_present,
      o.realm_fanout->'authority_witnesses' @> jsonb_build_array(jsonb_build_object(
        'member_id',:'subject'::jsonb,'membership_event_ref',:'join_ref')) AS exact_join_witness
    FROM federation_outbox o CROSS JOIN exact g
    WHERE o.peer_id=:'peer' AND o.realm_fanout->>'realm_id'=:'realm'
      AND o.realm_fanout->'source_event_ids' @> jsonb_build_array(g.event_ref)
)
SELECT jsonb_build_array(txid_current_snapshot()::text,
    (SELECT event_ref FROM exact),(SELECT commit_id FROM exact),(SELECT commit_id FROM head),
    jsonb_build_array(
      (SELECT COUNT(*) FROM matches),(SELECT stream_position FROM exact),
      (SELECT stream_position FROM head),(SELECT COUNT(*) FROM outbox),
      (SELECT COUNT(*) FROM outbox WHERE state='pending'),
      (SELECT COUNT(*) FROM outbox WHERE state='pending_route'),
      (SELECT COUNT(*) FROM outbox WHERE state='leased'),
      (SELECT COUNT(*) FROM outbox WHERE state='delivered'),
      (SELECT COUNT(*) FROM outbox WHERE state='cancelled_authority_lost'),
      (SELECT MAX(attempts) FROM outbox),(SELECT MAX(semantic_attempts) FROM outbox),
      (SELECT MAX(last_http_status) FROM outbox),
      (SELECT COUNT(*) FROM outbox WHERE exact_join_witness),
      (SELECT COUNT(*) FROM outbox WHERE error_present),
      (SELECT COUNT(*) FROM outbox WHERE state NOT IN
         ('pending','pending_route','leased','delivered','cancelled_authority_lost'))));
COMMIT;
";

const GRANT_FAILURE_MEMBER_SQL: &str = r"
BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET LOCAL statement_timeout='500ms';
SET LOCAL lock_timeout='250ms';
WITH target AS (
    SELECT c.commit_id,c.stream_position,c.event_pk,c.stream_ref
    FROM realm_commits c WHERE c.realm_id=:'realm' AND c.stream_key=:'stream_key'
      AND c.commit_json->>'event_ref'=:'event_ref'
), anchor AS (
    SELECT a.anchor_commit_id,a.anchor_stream_position,a.join_commit_id,
      j.stream_position AS opening_position FROM replica_stream_anchors a
    JOIN realm_commits j ON j.commit_id=a.join_commit_id
    WHERE a.realm_id=:'realm' AND a.stream_key=:'stream_key'
      AND j.realm_id=a.realm_id AND j.stream_key=a.stream_key
), member AS (
    SELECT membership,current_commit_id,current_stream_position FROM member_state_current_states
    WHERE realm_id=:'realm' AND member_id=:'subject_key'
), head AS (
    SELECT commit_id,stream_position FROM realm_commits
    WHERE realm_id=:'realm' AND stream_key=:'stream_key'
    ORDER BY stream_position DESC LIMIT 1
), outbox AS (
    SELECT state,attempts,semantic_attempts,last_http_status FROM federation_outbox
    WHERE peer_id=:'governance_peer' AND realm_fanout->>'realm_id'=:'realm'
      AND realm_fanout->'source_event_ids' @> jsonb_build_array(:'event_ref'::text)
)
SELECT jsonb_build_array(txid_current_snapshot()::text,(SELECT commit_id FROM head),
    jsonb_build_array(
      (SELECT COUNT(*) FROM canonical_events e WHERE e.realm_id=:'realm'
         AND e.envelope->>'event_id'=:'event_ref' AND e.state='committed'),
      (SELECT COUNT(*) FROM target c JOIN canonical_events e ON e.pk=c.event_pk
         WHERE e.state='committed' AND e.envelope->>'event_id'=:'event_ref'),
      (SELECT COUNT(*) FROM target WHERE event_pk IS NULL),
      (SELECT COUNT(*) FROM target WHERE commit_id=:'commit_id'
         AND stream_position=:'position'::bigint AND stream_ref=:'stream'::jsonb),
      (SELECT COUNT(*) FROM anchor),
      (SELECT COUNT(*) FROM anchor WHERE anchor_commit_id IS NOT NULL),
      (SELECT COUNT(*) FROM anchor a JOIN realm_commits j ON j.commit_id=a.join_commit_id
         WHERE j.commit_json->>'event_ref'=:'join_ref'),
      (SELECT anchor_stream_position FROM anchor),(SELECT opening_position FROM anchor),
      (SELECT stream_position FROM head),(SELECT COUNT(*) FROM member),
      (SELECT COUNT(*) FROM member WHERE membership='join'),
      (SELECT COUNT(*) FROM member WHERE membership='join' AND current_commit_id=:'parent_commit'
         AND current_stream_position=:'parent_position'::bigint),
      (SELECT current_stream_position FROM member),
      (SELECT COUNT(*) FROM member m JOIN realm_commits j ON j.commit_id=m.current_commit_id
         JOIN canonical_events e ON e.pk=j.event_pk
         WHERE m.membership='join' AND e.state='committed' AND j.realm_id=m.realm_id
           AND j.stream_key=:'stream_key' AND j.stream_position=m.current_stream_position
           AND e.envelope->>'event_id'=:'join_ref'),
      (SELECT COUNT(*) FROM target t CROSS JOIN member m
         WHERE t.stream_position>=m.current_stream_position),
      (SELECT COUNT(*) FROM member m CROSS JOIN anchor a
         WHERE m.current_stream_position>=a.opening_position),
      (SELECT COUNT(*) FROM realm_bootstrap_current_states
         WHERE realm_id=:'realm' AND state_family='realm_history_access' AND value=to_jsonb('since_join'::text)),
      (SELECT COUNT(*) FROM circle_member_state_current_states
         WHERE realm_id=:'realm' AND circle_id=:'circle' AND member_id=:'subject_key'
           AND membership='join'),
      (SELECT COUNT(*) FROM outbox),
      (SELECT COUNT(*) FROM outbox WHERE state='pending'),
      (SELECT COUNT(*) FROM outbox WHERE state='pending_route'),
      (SELECT COUNT(*) FROM outbox WHERE state='leased'),
      (SELECT COUNT(*) FROM outbox WHERE state='delivered'),
      (SELECT COUNT(*) FROM outbox WHERE state='cancelled_authority_lost'),
      (SELECT MAX(attempts) FROM outbox),(SELECT MAX(semantic_attempts) FROM outbox),
      (SELECT MAX(last_http_status) FROM outbox)));
COMMIT;
";

/// Keep the child owned until it exits, including after a timeout. Never let a
/// background database reader outlive the fixture's database/reset leases.
async fn grant_failure_sql_cut(
    database: &str,
    sql: &'static str,
    variables: &[(String, String)],
) -> Option<serde_json::Value> {
    use std::process::Stdio;

    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let mut command = tokio::process::Command::new(
        std::env::var_os("COTEST_PSQL").unwrap_or_else(|| "psql".into()),
    );
    command
        .args([
            "-X",
            "-qAt",
            "-w",
            "--set=ON_ERROR_STOP=1",
            "--pset=pager=off",
        ])
        .arg("--dbname")
        .arg(database)
        .env("PGCONNECT_TIMEOUT", "1")
        .env("PGCLIENTENCODING", "UTF8")
        .env(
            "PGOPTIONS",
            "-c default_transaction_read_only=on -c statement_timeout=500 -c lock_timeout=250",
        )
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    for (name, value) in variables {
        command.arg("--set").arg(format!("{name}={value}"));
    }
    let mut child = command.spawn().ok()?;
    let captured = tokio::time::timeout(Duration::from_secs(2), async {
        let mut input = child.stdin.take().context("diagnostic input unavailable")?;
        input.write_all(sql.as_bytes()).await?;
        input.shutdown().await?;
        drop(input);
        let mut bytes = Vec::new();
        child
            .stdout
            .take()
            .context("diagnostic output unavailable")?
            .take(16_385)
            .read_to_end(&mut bytes)
            .await?;
        ensure!(bytes.len() <= 16_384, "diagnostic output limit");
        ensure!(child.wait().await?.success(), "diagnostic capture failed");
        Ok::<_, anyhow::Error>(serde_json::from_slice::<serde_json::Value>(&bytes)?)
    })
    .await;
    if let Ok(Ok(value)) = captured {
        Some(value)
    } else {
        // Nothing about the command, DSN, SQL, or its errors is rendered.
        let _ = child.kill().await;
        let _ = child.wait().await;
        None
    }
}

fn grant_failure_number_facts(
    value: &serde_json::Value,
    names: &[&str],
) -> Option<serde_json::Value> {
    let values = value.as_array()?;
    if values.len() != names.len()
        || values
            .iter()
            .any(|value| !value.is_null() && value.as_u64().is_none())
    {
        return None;
    }
    Some(serde_json::Value::Object(
        names
            .iter()
            .zip(values)
            .map(|(name, value)| ((*name).to_owned(), value.clone()))
            .collect(),
    ))
}

fn grant_failure_cut_hash(value: &serde_json::Value) -> Option<String> {
    value
        .as_str()
        .map(|value| arkret_canonical::sha256_hex(value.as_bytes()))
}

struct GrantReadFailureContext<'a> {
    governance_database: &'a str,
    member_database: &'a str,
    realm: &'a RealmId,
    circle: &'a arkret_wire::CircleId,
    issuer: &'a ActorId,
    subject: &'a ActorId,
    peer: &'a arkret_wire::DidCoreId,
    governance_peer: &'a arkret_wire::DidCoreId,
    join_ref: &'a arkret_wire::EventId,
    parent: &'a arkret_wire::CurrentRevision,
}

async fn capture_grant_read_failure(
    context: &GrantReadFailureContext<'_>,
) -> Result<serde_json::Value> {
    let stream = CommitStreamRef::Realm {
        realm_id: context.realm.clone(),
    };
    let subject = serde_json::to_string(context.subject)?;
    let mut variables = vec![
        ("realm".into(), context.realm.to_string()),
        ("circle".into(), context.circle.to_string()),
        ("stream".into(), serde_json::to_string(&stream)?),
        (
            "stream_key".into(),
            String::from_utf8(arkret_canonical::canonical_json_bytes(&stream)?)?,
        ),
        ("issuer".into(), serde_json::to_string(context.issuer)?),
        ("subject".into(), subject),
        ("subject_key".into(), context.subject.to_string()),
        ("peer".into(), context.peer.to_string()),
        (
            "governance_peer".into(),
            context.governance_peer.to_string(),
        ),
        ("join_ref".into(), context.join_ref.to_string()),
        ("parent_commit".into(), context.parent.commit_id.to_string()),
        (
            "parent_position".into(),
            context.parent.stream_position.to_string(),
        ),
        (
            "actions".into(),
            serde_json::to_string(&["ak.circle.member.add", "ak.mls.genesis"])?,
        ),
        (
            "resources".into(),
            serde_json::to_string(&json!([
                {"kind":"circle","realm_id":context.realm,"circle_id":context.circle}
            ]))?,
        ),
    ];
    let mut diagnostic = json!({
        "phase":"grant_circle_actions_failed", "is_failed_http_cut":false,
        "cross_database_same_cut":false,"original_helper_stage_unknown":true,
        "authorization_decision_computed":false,
        "governance":{"capture_ok":false,"same_readonly_cut":false},
        "member":{"capture_ok":false,"same_readonly_cut":false}
    });
    let Some(governance) = grant_failure_sql_cut(
        context.governance_database,
        GRANT_FAILURE_GOVERNANCE_SQL,
        &variables,
    )
    .await
    else {
        return Ok(diagnostic);
    };
    let rows = governance
        .as_array()
        .filter(|row| row.len() == 5)
        .context("diagnostic shape")?;
    let facts = grant_failure_number_facts(
        &rows[4],
        &[
            "matching_grants",
            "grant_position",
            "head_position",
            "outbox_rows",
            "outbox_pending",
            "outbox_pending_route",
            "outbox_leased",
            "outbox_delivered",
            "outbox_authority_lost",
            "outbox_max_attempts",
            "outbox_max_semantic_attempts",
            "outbox_max_http_status",
            "outbox_exact_join_witness_rows",
            "outbox_error_present_rows",
            "outbox_other_state_rows",
        ],
    )
    .context("diagnostic scalars")?;
    diagnostic["governance"] = json!({
        "capture_ok":true,"same_readonly_cut":true,
        "snapshot_sha256":grant_failure_cut_hash(&rows[0]).context("diagnostic snapshot")?,
        "head_sha256":grant_failure_cut_hash(&rows[3]),"inputs":facts
    });
    // Zero or ambiguous matches stay unknown; neither permits a guessed read.
    if diagnostic["governance"]["inputs"]["matching_grants"].as_u64() != Some(1) {
        return Ok(diagnostic);
    }
    let event = arkret_wire::EventId::new(
        rows[1]
            .as_str()
            .context("diagnostic Event reference")?
            .to_owned(),
    )?;
    let commit: arkret_wire::RealmCommitId = rows[2]
        .as_str()
        .context("diagnostic Commit reference")?
        .parse()?;
    let position = diagnostic["governance"]["inputs"]["grant_position"]
        .as_u64()
        .context("diagnostic position")?;
    diagnostic["governance"]["event_sha256"] =
        json!(arkret_canonical::sha256_hex(event.as_str().as_bytes()));
    diagnostic["governance"]["commit_sha256"] =
        json!(arkret_canonical::sha256_hex(commit.as_str().as_bytes()));
    variables.extend([
        ("event_ref".into(), event.to_string()),
        ("commit_id".into(), commit.to_string()),
        ("position".into(), position.to_string()),
    ]);
    if let Some(member) = grant_failure_sql_cut(
        context.member_database,
        GRANT_FAILURE_MEMBER_SQL,
        &variables,
    )
    .await
    {
        let rows = member
            .as_array()
            .filter(|row| row.len() == 3)
            .context("diagnostic shape")?;
        let facts = grant_failure_number_facts(
            &rows[2],
            &[
                "committed_original_rows",
                "full_pair_rows",
                "chain_node_rows",
                "exact_commit_rows",
                "anchor_with_opening_rows",
                "anchored_rows",
                "anchor_exact_join_rows",
                "anchor_position",
                "opening_position",
                "head_position",
                "member_current_rows",
                "member_join_rows",
                "exact_parent_revision_rows",
                "member_current_position",
                "current_join_original_rows",
                "target_at_or_after_current_join_rows",
                "current_join_at_or_after_opening_rows",
                "since_join_history_rows",
                "circle_join_rows",
                "outbox_rows",
                "outbox_pending",
                "outbox_pending_route",
                "outbox_leased",
                "outbox_delivered",
                "outbox_authority_lost",
                "outbox_max_attempts",
                "outbox_max_semantic_attempts",
                "outbox_max_http_status",
            ],
        )
        .context("diagnostic scalars")?;
        diagnostic["member"] = json!({
            "capture_ok":true,"same_readonly_cut":true,
            "snapshot_sha256":grant_failure_cut_hash(&rows[0]).context("diagnostic snapshot")?,
            "head_sha256":grant_failure_cut_hash(&rows[1]),"floor_inputs_only":true,"inputs":facts
        });
    }
    Ok(diagnostic)
}

async fn run_matrix(circle_count: usize) -> Result<()> {
    let beyond_hint_page = circle_count > 64;
    let label = if beyond_hint_page {
        "multistream-native"
    } else {
        "snapshot-busy-native"
    };
    let transcript = if beyond_hint_page {
        "2133-multistream"
    } else {
        "2133-snapshot-busy"
    };
    let initial_streams = circle_count + 1;
    let log_directory = std::env::var_os("COTEST_SERVICE_LOG_DIR").map(std::path::PathBuf::from);
    let _transcript =
        cotest::transcripts::init_transcript_writer(transcript, log_directory.as_deref())?;
    let governance_database =
        database("multistream-governance")?.context("actual PostgreSQL is required")?;
    let member_database =
        database("multistream-account")?.context("independent PostgreSQL is required")?;
    let issuer = MockCoauthIntrospectionServer::spawn_with_internal_secret(
        HARNESS_INTERNAL_AUTHORITY_SECRET,
    )
    .await?;
    let group = cotest::harness::TestServerGroup::try_multi_external_with_node_envs(
        label,
        &[
            station_env(&governance_database.connect_url, &issuer),
            station_env(&member_database.connect_url, &issuer),
        ],
    )
    .await?
    .context("two actual Station processes required")?;
    let governor = group.server(0);
    let server = group.server(1);
    let mut alice_member = Member::provision(
        governor,
        &issuer,
        "multistream-alice",
        "ak:device:01904100-0000-7000-8000-000000003301",
    )
    .await?;
    let mut bob_member = Member::provision(
        server,
        &issuer,
        "multistream-bob",
        "ak:device:01904100-0000-7000-8000-000000003302",
    )
    .await?;
    let mut alice = alice_member.client.clone();
    let account_id = alice_member.account.clone();
    let mut bob = bob_member.client.clone();
    let realm = create_realm_with_join_rule(
        &alice,
        "More than 64 independent streams",
        "public",
        &[governor, server],
    )
    .await?;
    let realm_id = RealmId::new(realm.clone())?;
    let actor = ActorId::account(account_id.clone());
    prepare_join(
        &bob,
        &realm,
        governor,
        "ak:request:01904100-0000-7000-8000-000000003303",
        arkret_models_collaboration::governance::realm_join_intake::RealmJoinIntent::MemberJoin,
    )
    .await?;
    let join = bob.author_event(&realm,EventKind::MemberState.as_str(),membership_payload(&realm,
        bob_member.account.clone(),arkret_models_collaboration::governance::membership_invite::MembershipPayloadState::Join,
        "native remote multistream member")?).await?;
    submit_and_expect_commit(&bob, &bob_member.account, &bob.device_id, &join).await?;
    wait_for_committed(&bob, &join.event_id).await?;
    // These exact accepted parent joins remain unchanged throughout the fixture.
    // Each signed Circle command still asks the production server to check them.
    let alice_parent = alice
        .sdk()
        .realm_state_snapshot_head(&realm_id)
        .await?
        .parent_membership_revision(&actor)
        .context("Alice accepted parent join")?;
    let bob_parent = wait_member_snapshot(&bob, &realm_id)
        .await?
        .parent_membership_revision(&bob_member.actor)
        .context("Bob accepted parent join")?;
    let mut last_reissue = tokio::time::Instant::now();
    let mut reissues = 0usize;
    for index in 0..circle_count {
        if last_reissue.elapsed() >= Duration::from_secs(180) {
            alice = governor
                .reissue_mock_native_host_session(&alice, &issuer)
                .await?;
            bob = server
                .reissue_mock_native_host_session(&bob, &issuer)
                .await?;
            alice_member.client = alice.clone();
            bob_member.client = bob.clone();
            last_reissue = tokio::time::Instant::now();
            reissues += 1;
            eprintln!(
                "[2133-multistream-session] distinct_mock_issuer_grant_pairs={reissues} predecessor_expiry_unchanged=1"
            );
        }
        let circle = circle_create(
            &alice,
            &realm,
            &actor,
            &format!("Independent {index}"),
            &format!("Stream-{index}"),
        )
        .await?;
        join_at_parent(&alice, &realm, &circle, &actor, &alice_parent).await?;
        if let Err(error) = grant_circle_actions(&alice_member, &realm, &circle, &bob_member).await
        {
            let captured = capture_grant_read_failure(&GrantReadFailureContext {
                governance_database: &governance_database.connect_url,
                member_database: &member_database.connect_url,
                realm: &realm_id,
                circle: &circle,
                issuer: &alice_member.actor,
                subject: &bob_member.actor,
                peer: server.service_id(),
                governance_peer: governor.service_id(),
                join_ref: &join.event_id,
                parent: &bob_parent,
            })
            .await
            .unwrap_or_else(|_| {
                json!({
                    "phase":"grant_circle_actions_failed","capture_ok":false,
                    "is_failed_http_cut":false,"cross_database_same_cut":false,
                    "original_helper_stage_unknown":true,"authorization_decision_computed":false
                })
            });
            use std::io::Write as _;
            let _ = writeln!(
                std::io::stderr().lock(),
                "[multistream-grant-read-diagnostic] {captured}"
            );
            return Err(error);
        }
        join_at_parent(&bob, &realm, &circle, &bob_member.actor, &bob_parent).await?;
        if (index + 1) % 10 == 0 {
            eprintln!(
                "[2133-multistream-setup] accepted_circle_joins={}",
                index + 1
            );
        }
    }
    alice = governor
        .reissue_mock_native_host_session(&alice, &issuer)
        .await?;
    bob = server
        .reissue_mock_native_host_session(&bob, &issuer)
        .await?;
    alice_member.client = alice.clone();
    bob_member.client = bob.clone();
    reissues += 1;
    eprintln!(
        "[2133-multistream-session] distinct_mock_issuer_grant_pairs={reissues} native_observation_session_fresh=1 predecessor_expiry_unchanged=1"
    );
    let prepared = wait_member_snapshot(&bob, &realm_id).await?;
    ensure!(prepared.visible_stream_heads.len() == initial_streams);
    let streams = tokio::time::timeout(Duration::from_secs(120), async {
        loop {
            let streams = bob
                .sdk()
                .realm_streams_page(&realm_id, None, 500)
                .await?
                .streams;
            if streams.len() == initial_streams {
                return Ok::<_, anyhow::Error>(streams);
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    })
    .await
    .context("all actual remote Circle joins become discoverable")??;
    ensure!(
        streams.len() == initial_streams,
        "discovery did not enumerate every Circle plus Realm"
    );
    let target = streams
        .iter()
        .rev()
        .find(|s| matches!(s.stream_ref, CommitStreamRef::Circle { .. }))
        .context("last Circle stream")?
        .stream_ref
        .clone();
    ensure!(
        !beyond_hint_page || streams.iter().position(|s| s.stream_ref == target).unwrap() >= 64,
        "the target must be beyond the first hint page"
    );
    let CommitStreamRef::Circle { circle_id, .. } = &target else {
        unreachable!()
    };
    let strand = circle_event(
        &alice,
        &realm,
        circle_id,
        EventKind::StrandCreate,
        json!({"object":{
            "schema":"ak.schema.strand.v1","realm_id":realm,"scope_circle_id":circle_id,
            "tracks":{"discussion":{"is_primary":true,"profile":"discussion"}},
            "metadata":{"title":"Outside first hint page"},"state":"active","created_by":actor
        }}),
    )
    .await?;
    submit_and_expect_commit(&alice, &account_id, &alice.device_id, &strand).await?;
    let strand_id = StrandId::from_event_id(&strand.event_id);
    let busy_stream = streams
        .iter()
        .find(|s| matches!(s.stream_ref, CommitStreamRef::Circle { .. }))
        .context("first-page busy Circle")?
        .stream_ref
        .clone();
    let CommitStreamRef::Circle {
        circle_id: busy_circle,
        ..
    } = &busy_stream
    else {
        unreachable!()
    };
    let busy_strand = circle_event(
        &alice,
        &realm,
        busy_circle,
        EventKind::StrandCreate,
        json!({"object":{
            "schema":"ak.schema.strand.v1","realm_id":realm,"scope_circle_id":busy_circle,
            "tracks":{"discussion":{"is_primary":true,"profile":"discussion"}},
            "metadata":{"title":"First-page busy hints"},"state":"active","created_by":actor
        }}),
    )
    .await?;
    submit_and_expect_commit(&alice, &account_id, &alice.device_id, &busy_strand).await?;
    let busy_strand_id = StrandId::from_event_id(&busy_strand.event_id);
    let _native =
        crate::conformance::account_blocklist_projection::native_account_session(&bob).await?;
    let current = bob
        .sdk()
        .current_principal(&arkret_models_identity::CurrentPrincipalRequestBody {
            request_id: arkret_wire::RequestId::new(format!(
                "ak:request:{}",
                crate::scenarios::mls_lifecycle_live::fresh_uuid_v7()
            ))?,
            account_id: bob_member.account.clone(),
        })
        .await?;
    let principal = bob.principal.as_ref().context("native principal")?;
    let account: inkson::config::ActiveAccountContext = serde_json::from_value(json!({
        "profile_id":"multistream-native","authority":current.account_id,
        "principal_control_realm_id":current.principal_control_realm_id,
        "resolution":current.resolution_projection,"device_id":principal.device_id,"server_url":server.base_url()
    }))?;
    let initial = alice.sdk().realm_state_snapshot_head(&realm_id).await?;
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("native-state.json");
    let mut local = inkson::LocalStateStore::with_path(&path);
    local.switch_active_account(&account)?;
    let local = Arc::new(std::sync::Mutex::new(local));
    let read = local.clone();
    let store = inkson::realm_events_engine::StateStoreHandle::new(
        move |reader| reader(&read.lock().unwrap()),
        move |writer| writer(&mut local.lock().unwrap()),
    );
    let metrics = server
        .did_boundary_metrics()?
        .context("actual subscription request counters")?;
    let before = metrics.snapshot().await?;
    let effect = inkson::realm_events_engine::EffectRegistry::default().register(
        inkson::realm_events_engine::EffectKey {
            owner: inkson::realm_events_engine::EffectOwner::Realm {
                account: account.profile_id.clone(),
                realm: realm.clone(),
            },
            name: "multistream-live".into(),
            generation: 0,
        },
    );
    let base = server.base_url().to_string();
    let selected = realm.clone();
    let epoch = value_cell(0u64);
    let ctx = inkson::realm_events_engine::RealmEventsEngineContext {
        websocket_rail: inkson::realm_events_engine::WebSocketRail::default(),
        base_url: inkson::realm_events_engine::ValueReader::new(move || base.clone()),
        token: value_cell(bob.session().credential().to_owned()),
        state_store: store.clone(),
        selected_realm_id: inkson::realm_events_engine::ValueReader::new(move || selected.clone()),
        route_enabled: inkson::realm_events_engine::ValueReader::new(|| true),
        realm_live_epoch: epoch.clone(),
        message_stream_hub: None,
        profiles: inkson::realm_events_engine::ValueReader::new(|| {
            inkson::config::MultiProfileConfig {
                active_profile_id: Some("multistream-native".into()),
                profiles: vec![],
            }
        }),
        effect: effect.clone(),
    };
    let http = bob.sdk();
    let runner = inkson::realm_events_engine::run_realm_events_engine_with_transport(
        0,
        inkson::realm_events_engine::ValueReader::new(|| 0),
        realm.clone(),
        ctx,
        move |_| {
            let http = http.clone();
            async move { Ok(http) }
        },
    );
    tokio::pin!(runner);
    let observation = async {
        for expected in &initial.visible_stream_heads {
            wait_head(&store, expected).await.with_context(|| {
                format!(
                    "initial stream {:?}, retained {:?}",
                    expected,
                    stored_head(&store, &expected.stream_ref)
                )
            })?;
        }
        eprintln!(
            "[2133-multistream] initial_streams={initial_streams} all_signed_heads_durable=1"
        );
        for busy in [false, true] {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(100);
            let busy_writes = std::cell::Cell::new(0usize);
            let busy_head = std::cell::RefCell::new(None);
            let target_finished = std::cell::Cell::new(false);
            // The first-page writer starts before the outside-page target and
            // remains active through its actual catch-up. Drain its last real
            // admission instead of cancelling a possibly committed request.
            let pressure = async {
                while busy && !target_finished.get() {
                    let message = circle_event(&alice,&realm,busy_circle,EventKind::MessageCreate,json!({
                        "strand_id":busy_strand_id,"track_name":"discussion",
                        "content":{"kind":"ak.content.text","body":format!("First-page busy hint {}",busy_writes.get())}
                    })).await?;
                    let accepted =
                        submit_and_expect_commit(&alice, &account_id, &alice.device_id, &message)
                            .await?;
                    let _ = busy_head.replace(Some(arkret_wire::CommitStreamHead {
                        stream_ref: busy_stream.clone(),
                        stream_position: accepted.stream_position,
                        commit_id: accepted.commit_id,
                    }));
                    busy_writes.set(busy_writes.get() + 1);
                    tokio::time::sleep(Duration::from_millis(400)).await;
                }
                Ok::<(), anyhow::Error>(())
            };
            let observe_target = async {
                while busy && busy_writes.get() == 0 {
                    ensure!(
                        tokio::time::Instant::now() < deadline,
                        "first-page pressure never started"
                    );
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                let event = circle_event(&alice,&realm,circle_id,EventKind::MessageCreate,json!({
                    "strand_id":strand_id,"track_name":"discussion",
                    "content":{"kind":"ak.content.text","body":if busy {"busy target"} else {"idle target"}}
                })).await?;
                let commit =
                    submit_and_expect_commit(&alice, &account_id, &alice.device_id, &event).await?;
                let expected = arkret_wire::CommitStreamHead {
                    stream_ref: target.clone(),
                    stream_position: commit.stream_position,
                    commit_id: commit.commit_id,
                };
                let required_busy_writes = if busy { busy_writes.get() + 1 } else { 0 };
                while stored_head(&store, &target).as_ref() != Some(&expected)
                    || busy_writes.get() < required_busy_writes
                {
                    ensure!(
                        tokio::time::Instant::now() < deadline,
                        "outside-page target starved while busy={busy}"
                    );
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                target_finished.set(true);
                Ok::<(), anyhow::Error>(())
            };
            tokio::try_join!(observe_target, pressure)?;
            ensure!(
                !busy || busy_writes.get() >= 2,
                "busy evidence requires accepted hints before and after the target"
            );
            let last_busy_head = busy_head.borrow().clone();
            if let Some(head) = last_busy_head {
                wait_head(&store, &head).await.with_context(|| {
                    format!(
                        "draining the last actual busy admission {:?}, retained {:?}",
                        head,
                        stored_head(&store, &head.stream_ref)
                    )
                })?;
                eprintln!("[2133-multistream] busy_tail_drained=1");
            }
            eprintln!(
                "[2133-multistream] busy={busy} target_beyond_64={} exact_head_installed=1 busy_writes={}",
                usize::from(beyond_hint_page),
                busy_writes.get()
            );
        }
        let circle = circle_create(
            &alice,
            &realm,
            &actor,
            "First-screen absent new stream",
            "New-stream",
        )
        .await?;
        join_at_parent(&alice, &realm, &circle, &actor, &alice_parent).await?;
        grant_circle_actions(&alice_member, &realm, &circle, &bob_member).await?;
        join_at_parent(&bob, &realm, &circle, &bob_member.actor, &bob_parent).await?;
        eprintln!("[2133-multistream] new_circle_join_accepted=1");
        let final_cut = alice.sdk().realm_state_snapshot_head(&realm_id).await?;
        let new_stream = CommitStreamRef::Circle {
            realm_id: realm_id.clone(),
            circle_id: circle,
        };
        let expected = final_cut
            .visible_stream_heads
            .iter()
            .find(|h| h.stream_ref == new_stream)
            .context("new head")?;
        wait_head(&store, expected).await.with_context(|| {
            format!(
                "new Circle {:?}, retained {:?}",
                expected,
                stored_head(&store, &expected.stream_ref)
            )
        })?;
        eprintln!("[2133-multistream] new_circle_head_durable=1");
        for head in &final_cut.visible_stream_heads {
            wait_head(&store, head).await.with_context(|| {
                format!(
                    "final independent stream {:?}, retained {:?}",
                    head,
                    stored_head(&store, &head.stream_ref)
                )
            })?;
        }
        eprintln!(
            "[2133-multistream] final_streams={} all_signed_heads_durable=1",
            initial_streams + 1
        );
        ensure!(final_cut.visible_stream_heads.len() == initial_streams + 1);
        ensure!(epoch.get() > 0);
        tokio::time::timeout(Duration::from_secs(75), async {
            loop {
                if requests(&metrics.snapshot().await?, SUBSCRIBE_OP)
                    - requests(&before, SUBSCRIBE_OP)
                    >= if beyond_hint_page { 2 } else { 1 }
                {
                    return Ok::<(), anyhow::Error>(());
                }
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        })
        .await
        .context("actual HTTP subscription rollover")??;
        Ok::<(), anyhow::Error>(())
    };
    tokio::pin!(observation);
    let (result, runner_ended) = tokio::select! {
        result=&mut observation=>(result,false),
        _=&mut runner=>(Err(anyhow::anyhow!("native follower ended before matrix completion")),true),
    };
    if let Err(error) = &result {
        eprintln!("[2133-multistream-failure] observation={error:#}");
    }
    if runner_ended {
        return result;
    }
    effect.cancel();
    let cancellation = tokio::time::timeout(Duration::from_secs(8), &mut runner)
        .await
        .context("native follower cancellation");
    if let Err(error) = &cancellation {
        eprintln!("[2133-multistream-failure] cancellation={error:#}");
    }
    result?;
    cancellation?;
    let retained = store.read(|state| state.load().verified_commit_stream_cursors.clone());
    let mut cold = inkson::LocalStateStore::with_path(&path);
    cold.switch_active_account(&account)?;
    ensure!(
        cold.load().verified_commit_stream_cursors == retained,
        "cold native storage changed independent stream checkpoints"
    );
    eprintln!(
        "[2133-multistream] actual_station_processes=2 independent_databases=2 remote_governance=1 new_scope_discovered=1 http_rollover={} cold_checkpoints_preserved=1",
        usize::from(beyond_hint_page)
    );
    Ok(())
}
