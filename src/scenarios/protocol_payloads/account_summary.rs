//! The creator's Account realm list follows the committed Realm.
//!
//! Account summary rows are derived from the Realm's typed current results in
//! the same transaction as the Commit that changes them, so the realm list a
//! fresh Account subscribe returns is exactly the committed state -- before
//! and after a Soland restart.

use anyhow::{Context, Result, ensure};
use arkret_models_collaboration::sync_frames::account_subscribe::AccountSubscribeFrame;
use arkret_models_collaboration::sync_frames::demand_sync::{RealmListMembership, RealmListRow};
use reqwest::StatusCode;
use serde_json::json;

use super::snapshot_head_disclosure::{SnapshotAuthor, snapshot_author};

const TITLE: &str = "Account summary";

/// Every frame of one bounded Account subscribe, each past the SDK's closed
/// frame contract.
async fn account_frames(
    client: &crate::harness::TestActorClient,
    after: Option<&str>,
) -> Result<Vec<AccountSubscribeFrame>> {
    let mut request = client.get("/_arkret/self/account/subscribe");
    if let Some(after) = after {
        request = request.query(&[("after", after)]);
    }
    let response = request.send().await?;
    let status = response.status();
    let body = response.text().await?;
    ensure!(
        status == StatusCode::OK,
        "account subscribe {status}: {body}"
    );
    body.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(|line| {
            let frame: AccountSubscribeFrame = serde_json::from_str(line)
                .with_context(|| format!("closed Account frame: {line}"))?;
            frame
                .validate()
                .map_err(|error| anyhow::anyhow!("Account frame contract: {error}: {line}"))?;
            Ok(frame)
        })
        .collect()
}

fn last_cursor(frames: &[AccountSubscribeFrame]) -> Result<String> {
    frames
        .iter()
        .rev()
        .find_map(|frame| frame.cursor.clone())
        .context("Account subscribe returned no continuation cursor")
}

/// The Realm's row in the initial realm-list page.
fn listed_row(frames: &[AccountSubscribeFrame], realm_id: &str) -> Result<RealmListRow> {
    frames
        .iter()
        .filter_map(|frame| frame.realm_list.as_ref())
        .flat_map(|page| page.items.iter())
        .find(|row| row.realm_id.as_str() == realm_id)
        .cloned()
        .with_context(|| format!("realm list omits the created Realm: {frames:?}"))
}

/// The Realm's upsert in the realm-list changes after a cursor.
fn changed_row(frames: &[AccountSubscribeFrame], realm_id: &str) -> Result<RealmListRow> {
    frames
        .iter()
        .filter_map(|frame| frame.realm_list_changes.as_ref())
        .flat_map(|changes| changes.upserts.iter())
        .filter(|row| row.realm_id.as_str() == realm_id)
        .max_by_key(|row| row.revision)
        .cloned()
        .with_context(|| format!("realm list changes omit the Realm: {frames:?}"))
}

/// Fresh Soland + real PostgreSQL: the creator's Account subscribe lists the
/// new Realm with its committed title as a joined member; committing the
/// default Strand publishes a newer revision carrying `default_strand_id`;
/// after Soland restarts, a fresh Account subscribe lists the same row.
pub async fn account_summary_follows_bootstrap_default_strand_and_restart() -> Result<()> {
    let SnapshotAuthor {
        _coauth,
        mut server,
        author,
    } = snapshot_author("account-summary", "summary-alice").await?;
    let bootstrap = author
        .create_realm_bootstrap_with(json!({
            "title": TITLE,
            "summary": TITLE,
            "public": false,
            "plaintext_visible_services": []
        }))
        .await?;
    let realm_id = bootstrap["realm_id"]
        .as_str()
        .context("realm_id")?
        .to_owned();

    let initial = account_frames(&author, None).await?;
    let founded = listed_row(&initial, &realm_id)?;
    ensure!(
        founded.membership == RealmListMembership::Join
            && founded.title.as_deref() == Some(TITLE)
            && founded.default_strand_id.is_none(),
        "the bootstrap summary must be the joined creator with the committed title: {founded:?}"
    );

    let strand_id = author.create_default_strand(&realm_id).await?;
    let after_default = account_frames(&author, Some(&last_cursor(&initial)?)).await?;
    let pointed = changed_row(&after_default, &realm_id)?;
    ensure!(
        pointed.revision > founded.revision
            && pointed.membership == RealmListMembership::Join
            && pointed.title.as_deref() == Some(TITLE)
            && pointed
                .default_strand_id
                .as_ref()
                .is_some_and(|id| id.as_str() == strand_id),
        "the default Strand Commit must publish a newer summary revision: {pointed:?}"
    );

    server.restart_external_process().await?;
    let restarted = account_frames(&author, None).await?;
    let after_restart = listed_row(&restarted, &realm_id)?;
    ensure!(
        after_restart == pointed,
        "the committed summary must survive a restart unchanged: {after_restart:?} != {pointed:?}"
    );
    Ok(())
}
