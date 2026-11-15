//! Native root/Grant continuity across the existing signed handoff fixture.
use anyhow::{Context, Result, ensure};
use arkret_wire::{ActorId, ErrorCode, Event, GrantId, RealmCommitId};
use serde_json::{Value, json};

use crate::harness::TestActorClient;
use crate::scenarios::human_device_producer_live::submit_and_expect_commit;
use crate::scenarios::peer_semantic_union_live::realm_business_footprint;

pub(super) struct GrantContinuity {
    root: Value,
    watch_grants: Value,
    grant: GrantId,
    original_commit: RealmCommitId,
    old_revoke: Event,
}

fn actor(client: &TestActorClient) -> Result<ActorId> {
    Ok(ActorId::account(arkret_wire::AccountId::new(
        client
            .principal
            .as_ref()
            .context("native principal")?
            .core_id
            .clone(),
        client.service_id().parse()?,
    )))
}

async fn source_rows(database: &str, realm: &str, watcher: &ActorId) -> Result<(Value, Value)> {
    let database = database.to_owned();
    let realm = realm.to_owned();
    let watcher = serde_json::to_value(watcher)?;
    tokio::task::spawn_blocking(move || -> Result<_> {
        let mut db = postgres::Client::connect(&database, postgres::NoTls)?;
        let mut read = db.build_transaction().read_only(true).isolation_level(postgres::IsolationLevel::RepeatableRead).start()?;
        let root: Value = read.query_one("SELECT jsonb_build_object('controller_actor_id',controller_actor_id,'controller_epoch',controller_epoch,'authority_generation',authority_generation::text,'authority_event_ref',authority_event_ref) FROM realm_authority_root_current_states WHERE realm_id=$1", &[&realm])?.get(0);
        let grants: Value = read.query_one("SELECT COALESCE(jsonb_agg(to_jsonb(g) ORDER BY grant_id),'[]'::jsonb) FROM capability_grant_current_states g WHERE realm_id=$1 AND value->'subject'=$2 AND value->'actions' ? 'ak.strand.watch.set' AND status='active'", &[&realm,&watcher])?.get(0);
        ensure!(grants.as_array().is_some_and(|rows|!rows.is_empty()), "native watcher has no actual old Grant source");
        read.commit()?;
        Ok((root,grants))
    }).await?
}

async fn current_grant(database: &str, realm: &str, grant: &GrantId) -> Result<Value> {
    let database = database.to_owned();
    let realm = realm.to_owned();
    let grant = grant.to_string();
    tokio::task::spawn_blocking(move || -> Result<Value> {
        let mut db = postgres::Client::connect(&database, postgres::NoTls)?;
        Ok(db.query_one("SELECT to_jsonb(g) FROM capability_grant_current_states g WHERE realm_id=$1 AND grant_id=$2", &[&realm,&grant])?.get(0))
    }).await?
}

pub(super) async fn prepare(
    owner: &TestActorClient,
    watcher: &TestActorClient,
    database: &str,
    realm: &str,
) -> Result<GrantContinuity> {
    let grant: GrantId = owner
        .grant_realm_actions_to_client(realm, watcher, &["ak.message.create"])
        .await?
        .parse()?;
    let row = current_grant(database, realm, &grant).await?;
    let original_commit: RealmCommitId = row["current_commit_id"]
        .as_str()
        .context("Grant current Commit")?
        .parse()?;
    let old_revoke = owner
        .author_event(
            realm,
            "ak.capability.revoke",
            json!({
                "grant_id":grant,"expected_commit_id":original_commit,
            }),
        )
        .await?;
    let (root, watch_grants) = source_rows(database, realm, &actor(watcher)?).await?;
    Ok(GrantContinuity {
        root,
        watch_grants,
        grant,
        original_commit,
        old_revoke,
    })
}

impl GrantContinuity {
    pub(super) async fn assert_after_handoff(
        &self,
        owner: &TestActorClient,
        watcher: &TestActorClient,
        database: &str,
        realm: &str,
    ) -> Result<()> {
        let (root, watch_grants) = source_rows(database, realm, &actor(watcher)?).await?;
        ensure!(
            root == self.root,
            "governance-only handoff changed controller, epoch or delegation anchor/generation"
        );
        ensure!(
            watch_grants == self.watch_grants,
            "old lawful watch source was rewritten or invalidated by a governance-only handoff"
        );
        // This old scalar remains legal after handoff while its exact row is
        // unchanged. Advance that row natively before rejecting the old write.
        let relinquish = watcher
            .author_event(
                realm,
                "ak.capability.relinquish",
                json!({
                    "grant_id":self.grant,"expected_commit_id":self.original_commit,
                }),
            )
            .await?;
        let watcher_actor = actor(watcher)?;
        let commit = submit_and_expect_commit(
            watcher,
            watcher_actor.as_account_id().context("watcher Account")?,
            &watcher.device_id,
            &relinquish,
        )
        .await?;
        ensure!(
            commit.governance_generation == 1,
            "Grant was not advanced by the new native governor"
        );
        let row = current_grant(database, realm, &self.grant).await?;
        ensure!(
            row["status"] == "relinquished"
                && row["current_commit_id"] == commit.commit_id.as_str(),
            "native relinquishment did not advance the exact row"
        );
        let before = realm_business_footprint(database, realm).await?;
        let response = owner
            .post("/_arkret/self/events")
            .json(&crate::publication::initial_submission(
                self.old_revoke.clone(),
                "",
            )?)
            .send()
            .await?;
        let status = response.status();
        let problem: arkret_wire::Problem = response.json().await?;
        ensure!(
            status == reqwest::StatusCode::CONFLICT
                && problem.error_code() == Some(ErrorCode::CasConflict),
            "old signed write was not refused by actual CAS after row advance: {status} {problem:?}"
        );
        ensure!(
            realm_business_footprint(database, realm).await? == before,
            "old-tenure signed stale write mutated the new governor's authority state"
        );
        println!(
            "[grant-handoff] original_root_and_delegation_generation_preserved=1 old_watch_source_exercised=1 original_scalar_valid_until_row_advance=1 old_signed_scalar_refused_by_new_governor=1 rejection_zero_effects=1"
        );
        Ok(())
    }
}
