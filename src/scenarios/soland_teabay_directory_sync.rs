//! CT-8 — Soland + Teabay directory sync latency.
//!
//! Spec:
//!   - `arkret-spec/spec/v1/zh/discovery/discovery-directory.md` §2 — Directory Service ingest
//!     contract; principal servers push actor / space announces, directory indexes them, search
//!     queries return fresh fields within the ingest latency budget.
//!   - `arkret-spec/spec/v1/zh/discovery/profiles-presence.md` §2 — `ck.profile.update`
//!     (display_name / bio / avatar_url) writes actor projection on the principal; the directory
//!     MUST observe the new fields within the publish-to-search latency budget (target ≤ 30s for
//!     the canonical "edit profile, then friend finds you" UX strand).
//!
//! Scenario walk-through (when fully wired):
//!   1. Boot soland (principal server) and teabay (directory) with teabay's discovery ingest
//!      subscribed to soland's announce stream (push mode per directory describe).
//!   2. Register alice on soland; alice updates her profile via `POST
//!      /_soland/self/account/profile` with new `display_name` and `bio` (the soland endpoint
//!      exists today — `soland/src/routing/identity/account.rs::update_profile`).
//!   3. Soland persists the update and emits the announce event; teabay's ingest worker picks it
//!      up.
//!   4. Within 30s (use `eventually` from the harness with a 30s timeout + 500ms poll), `POST
//!      /_cokret/find/directory/search-actors` on the *teabay* base URL with `{"query": "<new
//!      display_name>"}` returns alice with the new display_name and bio fields.
//!   5. Repeat for a profile update to a different field (avatar_url) — asserts that re-indexing
//!      handles partial updates, not just first-write.
//!
//! ──────────────────────────────────────────────────────────────────────────
//! Status: scenario body wired to CT-6's `FourServiceStack`. Test entrypoint
//! is still `#[ignore]` because the full stack needs docker + sibling
//! coauth/starid/teabay binaries + a `DATABASE_URL` for teabay's Postgres.
//! When those prereqs are present the test boots the stack and runs the
//! profile-update → directory-reindex assertion below.
//!
//! Track: `_claude_todos.md` row CT-8.

use std::time::Duration;

use anyhow::{Result, anyhow, bail};
use serde_json::{Value, json};

use crate::harness::eventually;
use crate::scenarios::_helpers::four_service_bootstrap::{FourServiceConfig, bootstrap_required};

/// CT-8 scenario probe. Boots the 4-service stack, drives a profile update
/// on soland, and verifies teabay's directory search reflects the new
/// fields within the publish-to-search latency budget (30s per spec).
pub async fn soland_teabay_directory_sync_run() -> Result<()> {
    let stack = bootstrap_required(FourServiceConfig::new("ct8-dir-sync")).await?;
    stack.assert_healthy().await?;

    let teabay = stack
        .teabay
        .as_ref()
        .ok_or_else(|| anyhow!("CT-8: teabay handle missing after bootstrap_required succeeded"))?;
    let teabay_base = teabay.base_url.trim_end_matches('/').to_owned();
    let teabay_search_url = format!("{teabay_base}/_cokret/find/directory/search-actors");

    // Register alice on soland — gives us a bearer token for the profile
    // update call below.
    let alice = stack
        .soland
        .register_client(
            "did:web:alice.example",
            "@alice",
            "ak:device:01904100-0000-7000-8000-0000000000a1",
        )
        .await?;

    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?;

    // Baseline: nobody named "Alice Wonderland" yet.
    let before: Value = http
        .post(&teabay_search_url)
        .json(&json!({"query": "Alice Wonderland"}))
        .send()
        .await?
        .json()
        .await?;
    let empty = before["results"]
        .as_array()
        .map(|a| a.is_empty())
        .unwrap_or(true);
    if !empty {
        bail!(
            "CT-8: teabay baseline returned non-empty results before profile update: {}",
            before
        );
    }

    // Drive the profile update on soland (`alice.post` bearer-auths
    // automatically with the registered dev token).
    let profile_resp = alice
        .post("/_soland/self/account/profile")
        .json(&json!({
            "display_name": "Alice Wonderland",
            "bio": "Down the rabbit hole.",
        }))
        .send()
        .await?;
    if !profile_resp.status().is_success() {
        bail!(
            "CT-8: soland profile update failed with status {}",
            profile_resp.status()
        );
    }

    // Within 30s, teabay should reflect the new fields.
    eventually(
        "teabay reflects new display_name",
        Duration::from_secs(30),
        Duration::from_millis(500),
        || async {
            let after: Value = http
                .post(&teabay_search_url)
                .json(&json!({"query": "Alice Wonderland"}))
                .send()
                .await?
                .json()
                .await?;
            let hit = after["results"]
                .as_array()
                .and_then(|a| a.first())
                .cloned()
                .ok_or_else(|| anyhow!("not yet indexed"))?;
            if hit["did"] != "did:web:alice.example" {
                bail!("wrong actor: {hit}");
            }
            if hit["display_name"] != "Alice Wonderland" {
                bail!("display_name not updated: {hit}");
            }
            if hit["bio"] != "Down the rabbit hole." {
                bail!("bio not updated: {hit}");
            }
            Ok(())
        },
    )
    .await?;

    Ok(())
}
