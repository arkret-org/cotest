//! Circle disclosure and audited writes through independent real Stations.
use arkret_models_collaboration::authority_commit::{
    AuditPairedEventAcceptanceOutcome, AuditPairedEventUnitKind, AuditPairedEventUnitSubmission,
};
use arkret_models_collaboration::strand_watch_operations::{
    WatchAuditReadRequestBody, WatchAuditReadResponseBody,
};
use arkret_wire::{AccountId, CommittedEventFullView, EventAdmissionSubmission, SemanticRef};
use serde_json::json;

use super::*;
use crate::harness::{ArkretServer, CanonicalJsonBody};
use crate::scenarios::circle_poll_scope_live::{circle_create, circle_event};

#[expect(
    clippy::too_many_arguments,
    reason = "Circle disclosure matrix binds independent principals and exact parent revisions"
)]
pub(super) async fn run(
    alice: &TestActorClient,
    alice_account: &AccountId,
    bob: &TestActorClient,
    bob_account: &AccountId,
    owner: &TestActorClient,
    governor: &ArkretServer,
    origin: &ArkretServer,
    realm: &str,
    parents: &[(AccountId, arkret_wire::CurrentRevision)],
) -> Result<()> {
    let owner_actor = ActorId::account(AccountId::new(
        owner.principal.as_ref().context("owner")?.core_id.clone(),
        governor.service_id().clone(),
    ));
    let circle = circle_create(owner, realm, &owner_actor, "Watch Circle", "Watch").await?;
    let owner_parent = owner
        .parent_membership_revision(realm, &owner_actor)
        .await?;
    join(
        owner,
        governor,
        realm,
        &circle,
        &owner_actor,
        serde_json::from_value(owner_parent)?,
    )
    .await?;
    for member in [alice_account, bob_account] {
        grant_realm_actions(
            owner,
            governor,
            realm,
            member,
            &[
                "ak.circle.member.add",
                "ak.strand.watch.set",
                "ak.event.read",
            ],
        )
        .await?;
    }
    let bob_actor = ActorId::account(bob_account.clone());
    let bob_join = join(
        bob,
        origin,
        realm,
        &circle,
        &bob_actor,
        parents
            .iter()
            .find(|(a, _)| a == bob_account)
            .context("Bob accepted parent join")?
            .1
            .clone(),
    )
    .await?;
    let strand_event = circle_event(
        owner,
        realm,
        &circle,
        EventKind::StrandCreate,
        json!({"object":{"schema":"ak.schema.strand.v1","realm_id":realm,"scope_circle_id":circle,
            "tracks":{"discussion":{"is_primary":true,"profile":"discussion"}},
            "metadata":{"title":"Circle Watch"},"state":"active","created_by":owner_actor}}),
    )
    .await?;
    submit_and_expect_commit(
        owner,
        owner_actor.as_account_id().context("owner Account")?,
        &owner.device_id,
        &strand_event,
    )
    .await?;
    let strand = StrandId::from_event_id(&strand_event.event_id);
    let selector = StrandWatchCurrentRequestBody {
        realm_id: realm.parse()?,
        strand_id: strand.clone(),
        watcher_actor_id: bob_actor.clone(),
    };
    ensure!(matches!(
        read(bob, &selector).await?,
        StrandWatchCurrentResponseBody::NeverWritten { .. }
    ));
    let own = circle_event(
        bob,
        realm,
        &circle,
        EventKind::StrandWatchSet,
        json!({"strand_id":strand,"watcher_actor_id":bob_actor,"level":"participating"}),
    )
    .await?;
    let own_submission = submit_and_expect_commit(bob, bob_account, &bob.device_id, &own).await;
    if own_submission.is_err() {
        diagnose_join_basis(
            origin,
            &bob_join.event,
            Some(&bob_join.commit),
            "first_circle_watch_failed",
        )
        .await;
    }
    let own_commit = own_submission?;
    current(
        read(bob, &selector).await?,
        &own_commit,
        StrandWatchValue::Set(StrandWatchExpectedValue {
            level: StrandWatchLevel::Participating,
            level_public: None,
        }),
    )?;
    let writer = ActorId::account(alice_account.clone());
    let request = WatchAuditReadRequestBody { audit_submission: EventAdmissionSubmission::new(circle_event(alice, realm, &circle,
        EventKind::AuditAccessed, json!({"access_kind":"watch_audit_read","writer_actor_id":writer,"target_actor_id":bob_actor,
            "target_ref":strand,"purpose":"Circle disclosure cut","accessed_at":arkret_canonical::format_timestamp_canonical(chrono::Utc::now())})).await?) };
    expect_api_error(
        alice
            .post("/_arkret/self/strands/watch/audit-read")
            .canonical_json(&request)?,
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await?;
    expect_api_error(
        alice
            .post("/_arkret/self/strands/watch/current")
            .json(&StrandWatchCurrentRequestBody {
                watcher_actor_id: writer.clone(),
                ..selector.clone()
            }),
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await?;
    let alice_parent = parents
        .iter()
        .find(|(a, _)| a == alice_account)
        .context("Alice accepted parent join")?
        .1
        .clone();
    join(alice, origin, realm, &circle, &writer, alice_parent.clone()).await?;
    let observed: WatchAuditReadResponseBody = serde_json::from_value(
        expect_json(
            alice
                .post("/_arkret/self/strands/watch/audit-read")
                .canonical_json(&request)?,
            StatusCode::OK,
        )
        .await?,
    )?;
    observed.validate_for_request(&request, 0)?;
    let business = circle_event(alice, realm, &circle, EventKind::StrandWatchSet,
        json!({"strand_id":strand,"watcher_actor_id":bob_actor,"level":"all","expected_value":{"level":"participating"}})).await?;
    let mut audit = circle_event(alice, realm, &circle, EventKind::AuditAccessed,
        json!({"access_kind":"watch_set_others","writer_actor_id":writer,"target_actor_id":bob_actor,"target_ref":strand,
            "paired_event_id":business.event_id,"purpose":"Circle others pair","accessed_at":arkret_canonical::format_timestamp_canonical(chrono::Utc::now())})).await?;
    audit.semantic_refs.push(SemanticRef::new(
        business.event_id.to_string(),
        "audit_pair",
    ));
    crate::harness::refresh_typed_event_proof(&mut audit)?;
    let pair = AuditPairedEventUnitSubmission {
        unit_kind: AuditPairedEventUnitKind::AuditPairedEvent,
        events: [business, audit].map(EventAdmissionSubmission::new),
    };
    pair.validate()?;
    let outcome: AuditPairedEventAcceptanceOutcome = serde_json::from_value(
        expect_json(
            alice.post("/_arkret/self/events").canonical_json(&pair)?,
            StatusCode::OK,
        )
        .await?,
    )?;
    outcome.validate_for_request(&pair)?;
    ensure!(
        matches!(read(bob, &selector).await?, StrandWatchCurrentResponseBody::Current { current_state: result, .. } if matches!(result.value, StrandWatchValue::Set(StrandWatchExpectedValue {level:StrandWatchLevel::All, ..})))
    );
    let leave = circle_event(alice, realm, &circle, EventKind::CircleMemberState,
        json!({"circle_id":circle,"member_id":writer,"membership":"leave","expected_membership":"join"})).await?;
    submit_and_expect_commit(alice, alice_account, &alice.device_id, &leave).await?;
    expect_api_error(
        alice
            .post("/_arkret/self/strands/watch/audit-read")
            .canonical_json(&request)?,
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await?;
    let typed_realm: RealmId = realm.parse()?;
    let grant=owner.author_event(realm,EventKind::CapabilityGrant.as_str(),json!({"grant":{
        "schema":"ak.schema.capability.v1","realm_id":realm,"issuer_id":owner_actor,"subject":writer,
        "actions":["ak.circle.audit"],"resources":[{"kind":"strand","realm_id":realm,"circle_id":circle,"strand_id":strand}],
        "constraints":[{"constraint_kind":"scope_limitation","effect":"allow","allowed_circle_ids":[circle]}],
        "issuer_authority_refs":[{"kind":"realm_root","realm_id":realm,"authority_event_ref":typed_realm.event_id(),"authority_generation":"0"}],
        "issued_at":arkret_canonical::format_timestamp_canonical(chrono::Utc::now())}})).await?;
    let granted = submit_and_expect_commit(
        owner,
        owner_actor.as_account_id().context("owner Account")?,
        &owner.device_id,
        &grant,
    )
    .await?;
    let explicit=WatchAuditReadRequestBody {audit_submission:EventAdmissionSubmission::new(circle_event(alice,realm,&circle,EventKind::AuditAccessed,
        json!({"access_kind":"watch_audit_read","writer_actor_id":writer,"target_actor_id":bob_actor,"target_ref":strand,
            "purpose":"Explicit nonmember Circle audit","accessed_at":arkret_canonical::format_timestamp_canonical(chrono::Utc::now())})).await?)};
    let allowed: WatchAuditReadResponseBody = serde_json::from_value(
        expect_json(
            alice
                .post("/_arkret/self/strands/watch/audit-read")
                .canonical_json(&explicit)?,
            StatusCode::OK,
        )
        .await?,
    )?;
    allowed.validate_for_request(&explicit, 0)?;
    let revoke=owner.author_event(realm,EventKind::CapabilityRevoke.as_str(),json!({"grant_id":arkret_wire::GrantId::from_event_id(&grant.event_id),
        "expected_revision":{"commit_id":granted.commit_id,"stream_position":granted.stream_position}})).await?;
    submit_and_expect_commit(
        owner,
        owner_actor.as_account_id().context("owner Account")?,
        &owner.device_id,
        &revoke,
    )
    .await?;
    expect_api_error(
        alice
            .post("/_arkret/self/strands/watch/audit-read")
            .canonical_json(&explicit)?,
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await?;
    for (subject, action) in [
        (bob_actor.clone(), "ak.circle.member.add.others"),
        (owner_actor.clone(), "ak.circle.member.manage"),
    ] {
        let permission=owner.author_event(realm,EventKind::CapabilityGrant.as_str(),json!({"grant":{
            "schema":"ak.schema.capability.v1","realm_id":realm,"issuer_id":owner_actor,"subject":subject,
            "actions":[action],"resources":[{"kind":"circle","realm_id":realm,"circle_id":circle}],
            "constraints":[{"constraint_kind":"scope_limitation","effect":"allow","allowed_circle_ids":[circle]}],
            "issuer_authority_refs":[{"kind":"realm_root","realm_id":realm,"authority_event_ref":typed_realm.event_id(),"authority_generation":"0"}],
            "issued_at":arkret_canonical::format_timestamp_canonical(chrono::Utc::now())}})).await?;
        submit_and_expect_commit(
            owner,
            owner_actor.as_account_id().context("owner Account")?,
            &owner.device_id,
            &permission,
        )
        .await?;
    }
    grant_realm_actions(
        owner,
        governor,
        realm,
        owner_actor.as_account_id().context("owner Account")?,
        &["ak.audit.accessed"],
    )
    .await?;
    let parent = parents
        .iter()
        .find(|(a, _)| a == alice_account)
        .context("Alice parent")?
        .1
        .clone();
    member_pair(
        bob,
        realm,
        &circle,
        &bob_actor,
        &writer,
        serde_json::json!({"circle_id":circle,"member_id":writer,
        "membership":"join","expected_membership":"leave","parent_membership_revision":parent}),
    )
    .await?;
    member_pair(
        owner,
        realm,
        &circle,
        &owner_actor,
        &writer,
        serde_json::json!({"circle_id":circle,"member_id":writer,
        "membership":"leave","expected_membership":"join"}),
    )
    .await?;
    println!(
        "[circle-watch] real_two_stations=1 self_read_write=1 invisible_denied=1 audited_pair=1 leave_hides_frozen_read=1"
    );
    Ok(())
}

async fn join(
    client: &TestActorClient,
    station: &ArkretServer,
    realm: &str,
    circle: &arkret_wire::CircleId,
    actor: &ActorId,
    parent: arkret_wire::CurrentRevision,
) -> Result<CommittedEventFullView> {
    let joined = circle_event(
        client,
        realm,
        circle,
        EventKind::CircleMemberState,
        serde_json::json!({"circle_id":circle,"member_id":actor,
        "membership":"join","parent_membership_revision":parent,"expected_membership":null}),
    )
    .await?;
    let outcome = expect_json(
        client
            .post(&format!("/_arkret/self/circles/{circle}/members"))
            .canonical_json(
                &arkret_models_collaboration::governance::circle::CircleMemberRequestBody {
                    member_event: EventAdmissionSubmission::new(joined.clone()),
                },
            )?,
        StatusCode::OK,
    )
    .await?;
    ensure!(
        outcome["membership"] == "join" && outcome["circle_id"] == circle.as_str(),
        "Circle membership was not committed: {outcome}"
    );
    // A friendly membership response is not the accepted original. Read the
    // original without resubmitting it: a second write could hide a rejected
    // first submission behind a later successful admission.
    let accepted = async {
        let CommittedEventView::Full(full) =
            client.sdk().committed_event_get(&joined.event_id).await?
        else {
            bail!("Circle join original is withheld from its own member");
        };
        full.validate_shape()?;
        ensure!(
            full.event == joined
                && full.commit.event_ref == joined.event_id
                && full.commit.realm_id == joined.realm_id
                && full.commit.stream_ref
                    == CommitStreamRef::from_scope(
                        &joined.scope_ref,
                        Some(joined.realm_id.clone())
                    )?,
            "Circle join response has no exact accepted original in its scope stream"
        );
        Ok::<_, anyhow::Error>(full)
    }
    .await;
    if accepted.is_err() {
        diagnose_join_basis(station, &joined, None, "circle_join_original_unavailable").await;
    }
    accepted
}

async fn diagnose_join_basis(
    station: &ArkretServer,
    joined: &Event,
    accepted: Option<&RealmCommit>,
    phase: &'static str,
) {
    let mut diagnostic = json!({
        "phase":phase,
        "capture_ok":false,
        "same_readonly_cut":false,
        "is_failed_admission_cut":false,
        "snapshot_sha256":null,
        "accepted_join_commit_sha256":accepted.map(|commit|
            arkret_canonical::sha256_hex(commit.commit_id.as_str().as_bytes())),
        "facts":null
    });
    if let Some(url) = station.configured_database_url()
        && let arkret_wire::ScopeRef::Circle { circle_id, .. } = &joined.scope_ref
    {
        let url = url.to_owned();
        let realm = joined.realm_id.to_string();
        let circle = circle_id.to_string();
        let actor = joined.actor_id.to_string();
        let service = station.service_id().to_string();
        let event_id = joined.event_id.to_string();
        let original = serde_json::to_value(joined);
        if let Ok(original) = original {
            let captured = tokio::task::spawn_blocking(move || -> Result<serde_json::Value> {
                let mut config = url.parse::<postgres::Config>()?;
                config
                    .connect_timeout(std::time::Duration::from_secs(2))
                    .options("-c default_transaction_read_only=on -c statement_timeout=2000 -c lock_timeout=500");
                let mut database = config.connect(postgres::NoTls)?;
                let mut cut = database.build_transaction()
                    .isolation_level(postgres::IsolationLevel::RepeatableRead)
                    .read_only(true).start()?;
                let row = cut.query_one(
                    "WITH anchors AS (
                        SELECT a.anchor_commit_id,c.stream_ref FROM replica_stream_anchors a
                        JOIN realm_commits c ON c.commit_id=a.join_commit_id WHERE a.realm_id=$1
                    ), member AS (
                        SELECT * FROM circle_member_state_current_states
                        WHERE realm_id=$1 AND circle_id=$2 AND member_id=$3
                    ), original AS (
                        SELECT c.commit_id FROM realm_commits c JOIN canonical_events e ON e.pk=c.event_pk
                        WHERE c.realm_id=$1 AND c.commit_json->>'event_ref'=$5
                          AND e.state='committed' AND e.envelope=$6
                    )
                    SELECT txid_current_snapshot()::text,jsonb_build_object(
                        'realm_anchor_rows',(SELECT count(*) FROM anchors WHERE stream_ref->>'kind'='realm'),
                        'realm_anchored_rows',(SELECT count(*) FROM anchors WHERE stream_ref->>'kind'='realm' AND anchor_commit_id IS NOT NULL),
                        'circle_anchor_rows',(SELECT count(*) FROM anchors WHERE stream_ref->>'kind'='circle' AND stream_ref->>'circle_id'=$2),
                        'circle_anchored_rows',(SELECT count(*) FROM anchors WHERE stream_ref->>'kind'='circle' AND stream_ref->>'circle_id'=$2 AND anchor_commit_id IS NOT NULL),
                        'own_parent_rows',(SELECT count(*) FROM member_state_current_states WHERE realm_id=$1 AND member_id=$3),
                        'own_parent_join_rows',(SELECT count(*) FROM member_state_current_states WHERE realm_id=$1 AND member_id=$3 AND membership='join'),
                        'own_circle_member_rows',(SELECT count(*) FROM member),
                        'own_circle_join_rows',(SELECT count(*) FROM member WHERE membership='join'),
                        'own_parent_revision_exact',(SELECT bool_or(circle_member_parent_join_current(realm_id,member_id,value)) FROM member),
                        'circle_active_rows',(SELECT count(*) FROM circle_current_states WHERE realm_id=$1 AND circle_id=$2 AND value->>'state'='active'),
                        'exact_accepted_join_original_rows',(SELECT count(*) FROM original),
                        'own_current_matches_original',(SELECT bool_or(current_commit_id IN (SELECT commit_id FROM original)) FROM member),
                        'local_live_realm_join_rows',(SELECT count(*) FROM member_state_current_states WHERE realm_id=$1 AND membership='join' AND member_id::jsonb->'account_id'->>'station_id'=$4),
                        'local_live_circle_join_rows',(SELECT count(*) FROM circle_member_state_current_states cm
                            JOIN member_state_current_states rm ON rm.realm_id=cm.realm_id AND rm.member_id=cm.member_id
                            JOIN circle_current_states c ON c.realm_id=cm.realm_id AND c.circle_id=cm.circle_id
                            WHERE cm.realm_id=$1 AND cm.circle_id=$2 AND cm.membership='join' AND rm.membership='join'
                              AND circle_member_parent_join_current(cm.realm_id,cm.member_id,cm.value)
                              AND c.value->>'state'='active' AND cm.member_id::jsonb->'account_id'->>'station_id'=$4)
                    )",
                    &[&realm, &circle, &actor, &service, &event_id, &original],
                )?;
                let snapshot: String = row.try_get(0)?;
                let facts: serde_json::Value = row.try_get(1)?;
                cut.commit()?;
                Ok(json!({"snapshot_sha256":arkret_canonical::sha256_hex(snapshot.as_bytes()),"facts":facts}))
            }).await;
            if let Ok(Ok(captured)) = captured {
                diagnostic["capture_ok"] = json!(true);
                diagnostic["same_readonly_cut"] = json!(true);
                diagnostic["snapshot_sha256"] = captured["snapshot_sha256"].clone();
                diagnostic["facts"] = captured["facts"].clone();
            }
        }
    }
    // This later, read-only cut is not the failed admission's transaction.
    // Capture faults and stderr failures must never replace the original error.
    use std::io::Write as _;
    let _ = writeln!(
        std::io::stderr().lock(),
        "[circle-watch-basis-diagnostic] {diagnostic}"
    );
}

async fn member_pair(
    client: &TestActorClient,
    realm: &str,
    circle: &arkret_wire::CircleId,
    actor: &ActorId,
    member: &ActorId,
    payload: serde_json::Value,
) -> Result<()> {
    let business =
        circle_event(client, realm, circle, EventKind::CircleMemberState, payload).await?;
    let mut audit=circle_event(client,realm,circle,EventKind::AuditAccessed,serde_json::json!({"access_kind":"circle_member_set_others",
        "writer_actor_id":actor,"target_actor_id":member,"target_ref":circle,"paired_event_id":business.event_id,
        "purpose":"Circle membership paired administration","accessed_at":arkret_canonical::format_timestamp_canonical(chrono::Utc::now())})).await?;
    audit.semantic_refs.push(SemanticRef::new(
        business.event_id.to_string(),
        "audit_pair",
    ));
    crate::harness::refresh_typed_event_proof(&mut audit)?;
    let unit = AuditPairedEventUnitSubmission {
        unit_kind: AuditPairedEventUnitKind::AuditPairedEvent,
        events: [business, audit].map(EventAdmissionSubmission::new),
    };
    unit.validate()?;
    let outcome: AuditPairedEventAcceptanceOutcome = serde_json::from_value(
        expect_json(
            client.post("/_arkret/self/events").canonical_json(&unit)?,
            StatusCode::OK,
        )
        .await?,
    )?;
    outcome.validate_for_request(&unit)?;
    println!("[circle-member-pair] actual_business_and_audit_commits=2 full_unit=1");
    Ok(())
}
