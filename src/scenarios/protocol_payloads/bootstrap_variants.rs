//! Ordinary Realm bootstrap variants carrying a join policy.
//!
//! `join-policy.md` §2–§3: a `restricted` Realm must declare at least one
//! automatic gate, and a `parent_membership` gate needs active
//! `join_gate_from` links the Realm being created cannot have yet. The
//! governing Station admits the first shape as one atomic unit and refuses the
//! others with zero writes.

use anyhow::{Context, Result, ensure};
use reqwest::StatusCode;
use serde_json::{Value, json};

use super::snapshot_head_disclosure::{SnapshotAuthor, snapshot_author};

async fn refusal(response: reqwest::Response) -> Result<(StatusCode, Value)> {
    let status = response.status();
    let body = response.json::<Value>().await.unwrap_or(Value::Null);
    Ok((status, body))
}

pub async fn ordinary_bootstrap_admits_a_restricted_join_policy_and_refuses_unprovable_gates()
-> Result<()> {
    let SnapshotAuthor {
        _coauth,
        server,
        author,
    } = snapshot_author("bootstrap-join-policy", "join-policy-fay").await?;
    let issuer = server.service_id().to_string();

    let accepted = author
        .create_realm_bootstrap_with(json!({
            "title": "Restricted by claim",
            "join_rule": "restricted",
            "plaintext_visible_services": [],
            "join_policy": {
                "gates": [{
                    "gate_id": "employee",
                    "kind": "claim_required",
                    "required_claims": ["employee"],
                    "trusted_issuer_ids": [issuer]
                }],
                "combinator": "all"
            }
        }))
        .await
        .context("restricted bootstrap with an automatic claim gate")?;
    ensure!(
        accepted["event_response"]["status"] == "committed",
        "restricted bootstrap must commit as one unit: {accepted}"
    );

    // Only hard gates: `restricted` would admit exactly the `public` set.
    let (status, body) = refusal(
        author
            .post_realm_bootstrap(json!({
                "title": "Restricted without automatic gate",
                "join_rule": "restricted",
                "plaintext_visible_services": [],
                "join_policy": {
                    "gates": [{
                        "gate_id": "web-only",
                        "kind": "principal_admission",
                        "allowed_did_methods": ["did:web", "did:webvh"]
                    }],
                    "combinator": "all"
                }
            }))
            .await?,
    )
    .await?;
    ensure!(
        status == StatusCode::CONFLICT
            && body["type"] == "https://arkret.org/problems/failed_precondition"
            && body["reason_code"] == "join_rule_policy_mismatch",
        "restricted bootstrap without an automatic gate: {status} {body}"
    );

    // A parent_membership source needs an active join_gate_from link.
    let source = accepted["realm_id"].as_str().context("realm_id")?;
    let (status, body) = refusal(
        author
            .post_realm_bootstrap(json!({
                "title": "Parent gated",
                "join_rule": "restricted",
                "plaintext_visible_services": [],
                "join_policy": {
                    "gates": [{
                        "gate_id": "parent",
                        "kind": "parent_membership",
                        "membership_source_realm_ids": [source],
                        "require_min_membership": "join"
                    }],
                    "combinator": "all"
                }
            }))
            .await?,
    )
    .await?;
    ensure!(
        status == StatusCode::CONFLICT
            && body["type"] == "https://arkret.org/problems/failed_precondition",
        "parent_membership bootstrap without join_gate_from links: {status} {body}"
    );
    Ok(())
}

/// The replacement for synthetic accepted-state injection goes through the
/// ordinary authority operation with the accepted device's real producer proof.
pub async fn ordinary_bootstrap_retry_preserves_the_exact_commits_and_conflict_writes_nothing()
-> Result<()> {
    use arkret_models_collaboration::authority_commit::{
        SelfAuthoritySubmitOutcome, SelfAuthoritySubmitRequest,
    };
    use arkret_wire::{CommitStreamRef, CommittedEventView, RealmId};

    use crate::harness::{
        expect_json, ordinary_realm_bootstrap_submission, realm_bootstrap_event_batch_for_device,
        realm_create_payload_for_station,
    };

    let SnapshotAuthor {
        _coauth,
        server,
        author,
    } = snapshot_author("bootstrap-retry", "bootstrap-retry-reader").await?;
    let draft = realm_create_payload_for_station(
        author.service_id(),
        &json!({
            "title":"Formal fixture bootstrap", "plaintext_visible_services":[],
        }),
    )?;
    let (realm, events) = realm_bootstrap_event_batch_for_device(
        &author.actor,
        &author.device_id,
        server.service_id(),
        draft,
    )?;
    let request = ordinary_realm_bootstrap_submission(events)?;
    request.validate()?;
    let first = expect_json(
        author.post("/_arkret/self/events").json(&request),
        StatusCode::OK,
    )
    .await?;
    let first_typed: SelfAuthoritySubmitOutcome = serde_json::from_value(first.clone())?;
    first_typed.validate_for_request(&SelfAuthoritySubmitRequest::OrdinaryRealmBootstrap(
        request.clone(),
    ))?;
    ensure!(first["status"] == "committed", "{first}");
    let replay = expect_json(
        author.post("/_arkret/self/events").json(&request),
        StatusCode::OK,
    )
    .await?;
    let replay_typed: SelfAuthoritySubmitOutcome = serde_json::from_value(replay.clone())?;
    replay_typed.validate_for_request(&SelfAuthoritySubmitRequest::OrdinaryRealmBootstrap(
        request.clone(),
    ))?;
    ensure!(
        replay["status"] == "duplicate" && replay["commits"] == first["commits"],
        "exact retry must preserve first acceptance coordinates: {replay}"
    );
    let realm = RealmId::new(realm)?;
    let stream = CommitStreamRef::Realm {
        realm_id: realm.clone(),
    };
    let before = author
        .sdk()
        .scan_commit_stream_to_head(realm.clone(), stream.clone(), None, 100)
        .await?;
    ensure!(
        before.committed_events.len() == request.events.len(),
        "entire bootstrap unit must be visible"
    );
    for (position, (row, submitted)) in before
        .committed_events
        .iter()
        .zip(&request.events)
        .enumerate()
    {
        let CommittedEventView::Full(full) = row else {
            anyhow::bail!("founder's bootstrap Event withheld")
        };
        ensure!(
            full.event == submitted.event
                && full.commit.event_ref == submitted.event.event_id
                && full.commit.stream_position == position as u64,
            "every accepted Event needs its exact contiguous RealmCommit"
        );
    }
    let conflict = ordinary_realm_bootstrap_submission(
        request
            .events
            .into_iter()
            .map(|submission| submission.event)
            .collect(),
    )?;
    let problem = expect_json(
        author.post("/_arkret/self/events").json(&conflict),
        StatusCode::CONFLICT,
    )
    .await?;
    ensure!(
        problem["status"] == 409,
        "different bootstrap intent cannot replace existing unit: {problem}"
    );
    let after = author
        .sdk()
        .scan_commit_stream_to_head(realm, stream, None, 100)
        .await?;
    ensure!(
        after.committed_events == before.committed_events,
        "rejected bootstrap intent must leave Events and RealmCommits unchanged"
    );
    Ok(())
}
