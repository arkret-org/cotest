//! Live acceptance for the per-holder new-source quota that guards the invite
//! quarantine inbox (`identity/consent-model.md` sections 6.1.1.1 to 6.1.1.4).
//!
//! Covers `ak.vector.invite.new_source_quota_holder_admission.v1` and
//! `ak.vector.invite.new_source_quota_effective_bounds.v1`.
//!
//! Every assertion is taken from the **holder's** `ak.account.invite_quarantine`
//! cell, because the requester side is designed to be indistinguishable: an
//! admitted quarantine, a quota drop, a TTL drop, an unknown holder and a policy
//! deny all return the same opaque `deferred`. Checking the requester's response
//! could therefore never tell an enforced quota from an unenforced one, while a
//! missing cell entry can.

use anyhow::{Context, Result, ensure};
use arkret_models_collaboration::governance::invite_addressing::InviteReceivePolicy;
use arkret_wire::{AccountDataKey, InviteReceiveAction, NewSourceQuotaOverride};
use reqwest::StatusCode;
use serde_json::Value;

use crate::harness::{ArkretServer, TestActorClient, expect_json};
use crate::scenarios::identity_test_support::actor_did_for_service_did;
use crate::scenarios::invite_service_fanout_live::{
    account_data_row, create_and_dispatch_explicit_invite, set_explicit_address_behavior,
};

/// Deployment ceiling used by both runs. The short window is deliberately long
/// enough that no test step can slide out of it, so a missing entry can only be
/// the quota and never an expiry race.
const WINDOW_SECONDS: &str = "3600";
const PER_WINDOW: &str = "2";
const RETENTION_SECONDS: &str = "7200";
const PER_RETENTION: &str = "3";

fn quota_env() -> Vec<(&'static str, &'static str)> {
    vec![
        ("SOLAND_RECEIVE_POLICY_NEW_SOURCE_WINDOW_SECONDS", WINDOW_SECONDS),
        ("SOLAND_RECEIVE_POLICY_NEW_SOURCE_DEFAULT_PER_WINDOW", PER_WINDOW),
        ("SOLAND_RECEIVE_POLICY_NEW_SOURCE_MAX_PER_WINDOW", "10"),
        ("SOLAND_RECEIVE_POLICY_NEW_SOURCE_RETENTION_SECONDS", RETENTION_SECONDS),
        (
            "SOLAND_RECEIVE_POLICY_NEW_SOURCE_DEFAULT_PER_RETENTION",
            PER_RETENTION,
        ),
        ("SOLAND_RECEIVE_POLICY_NEW_SOURCE_MAX_PER_RETENTION", "200"),
    ]
}

/// Distinct source principals recorded in the holder's quarantine cell.
async fn quarantined_sources(holder: &TestActorClient) -> Result<Vec<String>> {
    let row = match account_data_row(holder, AccountDataKey::ACCOUNT_INVITE_QUARANTINE).await {
        Ok(row) => row,
        // No cell at all is the legitimate "nothing was ever admitted" state.
        Err(_) => return Ok(Vec::new()),
    };
    let entries = row.content["quarantine_entries"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    Ok(entries
        .iter()
        .filter_map(|entry| {
            entry["source_peer_principal_id"]
                .as_str()
                .map(str::to_owned)
        })
        .collect())
}

/// Every branch of this scenario must stay inside the opaque equivalence class.
fn assert_opaque_deferred(outcome: &Value) -> Result<()> {
    ensure!(
        outcome["status"] == "deferred" && outcome.get("disclosed_outcome").is_none(),
        "new-source quota changed the requester-visible outcome: {outcome}"
    );
    Ok(())
}

async fn holder_with_quarantine_policy(
    server: &ArkretServer,
    label: &str,
) -> Result<TestActorClient> {
    let holder_did = actor_did_for_service_did(server.service_did(), label)?;
    let holder = server
        .register_client(
            &holder_did,
            label,
            "ak:device:01904100-0000-7000-8000-0000000000c1",
        )
        .await
        .context("bootstrap holder client")?;
    set_explicit_address_behavior(&holder, InviteReceiveAction::Quarantine)
        .await
        .context("bind quarantine receive policy")?;
    Ok(holder)
}

async fn inviter(server: &ArkretServer, label: &str, device_suffix: u8) -> Result<TestActorClient> {
    server
        .demo_client(
            &actor_did_for_service_did(server.service_did(), label)?,
            &format!("ak:device:01904100-0000-7000-8000-0000000000{device_suffix:02x}"),
        )
        .await
        .with_context(|| format!("bootstrap inviter {label}"))
}

/// `ak.vector.invite.new_source_quota_holder_admission.v1`.
pub async fn new_source_quota_holder_admission_run() -> Result<()> {
    let server = ArkretServer::spawn_with_env("invite-new-source-quota", &quota_env()).await?;
    let holder = holder_with_quarantine_policy(&server, "bob-new-source-quota").await?;

    // Two distinct new sources fit under the short-window ceiling.
    let first = inviter(&server, "alice-new-source-quota-1", 0xd1).await?;
    let second = inviter(&server, "alice-new-source-quota-2", 0xd2).await?;
    for (peer, label) in [(&first, "quota first source"), (&second, "quota second source")] {
        let dispatched = create_and_dispatch_explicit_invite(peer, &holder, label).await?;
        assert_opaque_deferred(&dispatched.outcome)?;
    }
    let admitted = quarantined_sources(&holder).await?;
    ensure!(
        admitted.len() == 2,
        "the two sources inside the ceiling were not both admitted: {admitted:?}"
    );

    // A third distinct new source is over the short-window ceiling. It must be
    // dropped silently: absent from the cell, unchanged on the wire.
    let third = inviter(&server, "alice-new-source-quota-3", 0xd3).await?;
    let over_quota = create_and_dispatch_explicit_invite(&third, &holder, "quota third source")
        .await
        .context("dispatch the over-quota source")?;
    assert_opaque_deferred(&over_quota.outcome)?;
    let after_denial = quarantined_sources(&holder).await?;
    ensure!(
        after_denial.len() == 2,
        "an over-quota new source reached the quarantine cell: {after_denial:?}"
    );

    // An already-charged source is not a new source: a second contact from it
    // is still admitted even though the window is full. This is what separates
    // a real seen-source ledger from a plain per-holder counter.
    let repeat = create_and_dispatch_explicit_invite(&first, &holder, "quota repeat source")
        .await
        .context("dispatch a repeat contact from an already-admitted source")?;
    assert_opaque_deferred(&repeat.outcome)?;
    let after_repeat = quarantined_sources(&holder).await?;
    ensure!(
        after_repeat.len() == 3,
        "a repeat contact from an admitted source was charged as a new source: {after_repeat:?}"
    );

    Ok(())
}

/// `ak.vector.invite.new_source_quota_effective_bounds.v1`.
///
/// The holder override may only make the holder less reachable. Setting it to
/// `0` locks the inbox to zero new sources even though the deployment default
/// would admit two.
pub async fn new_source_quota_effective_bounds_run() -> Result<()> {
    let server = ArkretServer::spawn_with_env("invite-new-source-bounds", &quota_env()).await?;
    let holder = holder_with_quarantine_policy(&server, "bob-new-source-bounds").await?;
    set_new_source_quota_override(&holder, 0, 0)
        .await
        .context("publish the zero new-source override")?;

    let peer = inviter(&server, "alice-new-source-bounds-1", 0xe1).await?;
    let locked = create_and_dispatch_explicit_invite(&peer, &holder, "bounds locked source")
        .await
        .context("dispatch under a zero override")?;
    assert_opaque_deferred(&locked.outcome)?;
    let sources = quarantined_sources(&holder).await?;
    ensure!(
        sources.is_empty(),
        "a zero new-source override still admitted a source: {sources:?}"
    );

    Ok(())
}

/// Publish the holder-private `new_source_quota` override on top of whatever
/// receive policy the holder already has.
async fn set_new_source_quota_override(
    holder: &TestActorClient,
    per_window: u64,
    per_retention: u64,
) -> Result<()> {
    let current = expect_json(
        holder.get("/_arkret/self/invite-receive-policy"),
        StatusCode::OK,
    )
    .await?;
    let mut policy: InviteReceivePolicy = serde_json::from_value(current)
        .context("invite-receive-policy response is not an InviteReceivePolicy")?;
    policy.new_source_quota = Some(NewSourceQuotaOverride {
        new_sources_per_window: Some(per_window),
        new_sources_per_retention: Some(per_retention),
    });
    let updated = expect_json(
        holder
            .put("/_arkret/self/invite-receive-policy")
            .json(&policy),
        StatusCode::OK,
    )
    .await?;
    let updated: InviteReceivePolicy = serde_json::from_value(updated)
        .context("updated invite-receive-policy is not an InviteReceivePolicy")?;
    ensure!(
        updated.new_source_quota == policy.new_source_quota,
        "Station rewrote the holder new_source_quota override"
    );
    Ok(())
}
