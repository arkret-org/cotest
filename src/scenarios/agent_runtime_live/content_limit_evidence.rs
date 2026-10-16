//! Actual constrained write effects with current conditions and atomic quotas.

use super::content_grant_evidence::GrantFixture;
use super::*;
use crate::harness::{CanonicalJsonBody, expect_api_error};
use crate::scenarios::_helpers::acceptance_footprint::acceptance_rows_with_agent_stores;

async fn quota_rows(scene: &GrantFixture) -> Result<serde_json::Value> {
    let database = scene
        .deployment
        .station
        .owned_database_url()
        .context("owned Station database")?
        .to_owned();
    tokio::task::spawn_blocking(move || -> Result<_> {
        let mut db = postgres::Client::connect(&database, postgres::NoTls)?;
        Ok(db.query_one("SELECT jsonb_build_object('counters',(SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text),'[]') FROM capability_quota_counters t),'buckets',(SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text),'[]') FROM capability_quota_buckets t),'consumptions',(SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text),'[]') FROM capability_quota_consumptions t))", &[])?.get(0))
    }).await?
}

fn consumed(rows: &serde_json::Value, grant: &arkret_wire::GrantId) -> Result<i64> {
    rows["counters"]
        .as_array()
        .context("actual quota counters")?
        .iter()
        .filter(|row| row["grant_id"] == grant.as_str())
        .map(|row| row["consumed"].as_i64().context("actual consumed count"))
        .sum()
}

async fn refused_message(
    scene: &GrantFixture,
    runtime: &TestActorClient,
    event: &Event,
    status: StatusCode,
    code: &str,
) -> Result<()> {
    let database = scene
        .deployment
        .station
        .owned_database_url()
        .context("owned Station database")?;
    let before = acceptance_rows_with_agent_stores(database, true).await?;
    let quota = quota_rows(scene).await?;
    expect_api_error(
        runtime
            .post("/_arkret/self/events")
            .canonical_json(&arkret_wire::EventAdmissionSubmission::new(event.clone()))?,
        status,
        code,
    )
    .await?;
    ensure!(
        acceptance_rows_with_agent_stores(database, true).await? == before,
        "constrained refusal changed accepted/current/Agent/delivery state"
    );
    ensure!(
        quota_rows(scene).await? == quota,
        "constrained refusal left a quota reservation or consumption effect"
    );
    scene.read_exact(runtime).await?;
    Ok(())
}

async fn quota_exhaustion(scene: &GrantFixture) -> Result<()> {
    let quota = serde_json::from_value(
        json!({"constraint_kind":"quota","constraint_subkind":"rate",
        "effect":"allow","max_operations":1,"period":"P1D","constraint_scope":"per_realm"}),
    )?;
    let grant = scene
        .grant_with_constraints(&scene.a, &["ak.message.create"], vec![quota])
        .await?;
    let initial = quota_rows(scene).await?;
    ensure!(consumed(&initial, &grant)? == 0);
    let (runtime, claims) = scene.issue().await?;
    ensure!(
        claims
            .scopes
            .iter()
            .any(|action| action == "ak.message.create")
    );
    ensure!(
        claims.scope_details.as_ref().context("quota source refs")?["capability_grant_refs"]
            == json!([grant])
    );
    ensure!(
        quota_rows(scene).await? == initial,
        "session issuance consumed a write quota"
    );
    let first = scene
        .commit_message(&runtime, &scene.a, &grant, "Only admitted quota write")
        .await?;
    let charged = quota_rows(scene).await?;
    ensure!(consumed(&charged, &grant)? == 1);
    ensure!(
        charged["consumptions"]
            .as_array()
            .context("durable quota identities")?
            .iter()
            .filter(|row| row["grant_id"] == grant.as_str())
            .count()
            == 1
    );
    let original = scene
        .deployment
        .controller
        .sdk()
        .committed_event_get(&first.event_id)
        .await?;
    let database = scene
        .deployment
        .station
        .owned_database_url()
        .context("owned Station database")?;
    let before_retry = acceptance_rows_with_agent_stores(database, true).await?;
    let retry: AuthoritySubmitOutcome = serde_json::from_value(
        expect_json(
            runtime
                .post("/_arkret/self/events")
                .canonical_json(&arkret_wire::EventAdmissionSubmission::new(first.clone()))?,
            StatusCode::OK,
        )
        .await?,
    )?;
    ensure!(
        matches!(retry, AuthoritySubmitOutcome::Accepted { status: AuthorityCommitStatus::Duplicate, commit }
        if &commit == original.commit())
    );
    ensure!(
        quota_rows(scene).await? == charged,
        "exact accepted retry charged quota again"
    );
    ensure!(
        acceptance_rows_with_agent_stores(database, true).await? == before_retry,
        "exact accepted retry altered business state"
    );
    let fresh = scene.message(&scene.a, &grant, "Fresh write beyond the actual quota")?;
    refused_message(
        scene,
        &runtime,
        &fresh,
        StatusCode::TOO_MANY_REQUESTS,
        arkret_wire::ErrorCode::RATE_LIMITED,
    )
    .await?;
    ensure!(consumed(&quota_rows(scene).await?, &grant)? == 1);
    scene.revoke(&grant).await?;
    println!(
        "[agent-payload-quota] actual_accepted_rate_grant=1 issue_did_not_consume=1 real_message_committed=1 actual_counter_and_consumption_one=1 exact_retry_same_commit_no_second_charge=1 fresh_exhausted_write_429=1 full_business_and_all_quota_tables_noop=1 original_credential_still_reads=1"
    );
    Ok(())
}

async fn temporal_condition(scene: &GrantFixture) -> Result<()> {
    use arkret_models_collaboration::governance::grant_constraint::{
        GrantConstraint, GrantConstraintEffect, GrantConstraintKind,
    };
    let until =
        arkret_canonical::normalize_timestamp_canonical(Utc::now()) + chrono::Duration::seconds(20);
    let mut condition =
        GrantConstraint::new(GrantConstraintKind::Temporal, GrantConstraintEffect::Allow);
    condition.not_before = Some(Utc::now() - chrono::Duration::minutes(1));
    condition.expires_at = Some(until);
    let grant = scene
        .grant_with_constraints(&scene.a, &["ak.message.create"], vec![condition])
        .await?;
    let (runtime, claims) = scene.issue().await?;
    ensure!(
        claims
            .scopes
            .iter()
            .any(|action| action == "ak.message.create")
    );
    ensure!(
        claims
            .scope_details
            .as_ref()
            .context("condition source refs")?["capability_grant_refs"]
            == json!([grant])
    );
    scene
        .commit_message(
            &runtime,
            &scene.a,
            &grant,
            "Actual write inside the accepted temporal window",
        )
        .await?;
    let remaining = (until + chrono::Duration::milliseconds(200) - Utc::now())
        .to_std()
        .unwrap_or_default();
    tokio::time::sleep(remaining).await;
    ensure!(Utc::now() > until);
    scene.read_exact(&runtime).await?;
    let fresh = scene.message(
        &scene.a,
        &grant,
        "Fresh write after its action condition closed",
    )?;
    refused_message(
        scene,
        &runtime,
        &fresh,
        StatusCode::FORBIDDEN,
        arkret_wire::ErrorCode::CAPABILITY_DENIED,
    )
    .await?;
    scene.revoke(&grant).await?;
    println!(
        "[agent-payload-condition] actual_accepted_temporal_grant=1 real_write_inside_window=1 original_credential_and_selection_retained=1 independent_read_after_window_succeeds=1 fresh_original_signed_write_refused=1 complete_business_and_quota_noop=1 no_revocation_used_to_trigger_condition=1"
    );
    Ok(())
}

pub(super) async fn run_payload_limits(scene: &GrantFixture) -> Result<()> {
    quota_exhaustion(scene).await?;
    temporal_condition(scene).await
}
