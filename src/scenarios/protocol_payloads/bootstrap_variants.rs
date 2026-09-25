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
