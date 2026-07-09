//! SOD-1 — Sodmin device revoke cascade workflow.
//!
//! Spec:
//!   - `arkret-spec/spec/v1/zh/identity/account-lifecycle.md` §3 (device lifecycle), §9 (session
//!     revocation, paraphrased): revoking a device MUST produce a device list update, and E2EE
//!     clients MUST stop sharing new keys with the revoked device. Revocation MUST also invalidate
//!     any soland session bound to that device.
//!
//! Scenario walk-through (when fully wired):
//!   1. Boot soland + coauth + sodmin (admin UI) in the same docker network. Register alice on
//!      coauth with device dev_A; alice logs in via soland's dev-login on dev_A and obtains an
//!      session credential.
//!   2. Smoke: GET /_soland/self/account/me on soland with alice's token → 200. GET coauth
//!      `/api/admin/v1/accounts/{alice}/devices` lists dev_A with `is_revoked=false`.
//!   3. Open sodmin (Dioxus admin UI) in playwright; sign in as admin; navigate to alice's account
//!      → devices panel.
//!   4. Click "Revoke" on dev_A; confirm modal; wait for success toast.
//!   5. Assert coauth state via API (no UI scraping):
//!        - GET /api/admin/v1/accounts/{alice}/devices → dev_A `is_revoked=true` with a
//!          `revoked_at` timestamp.
//!   6. Assert cascade to soland session: GET /_soland/self/account/me on soland with alice's old
//!      token → 401 `unauthenticated` (soland MUST observe the device revocation and reject the
//!      session).
//!   7. (Optional) Re-login on dev_A → still 401 / device revoked (depending on whether
//!      re-registration is allowed; spec is ambiguous here).
//!
//! ──────────────────────────────────────────────────────────────────────────
//! Status: scaffolded as `#[ignore]`.
//!
//! Prerequisite blockers:
//!   * No Rust-side spawner for sodmin (Dioxus admin UI). Playwright scaffolding lives only under
//!     `cotest/e2e/` (TypeScript), driven by `scripts/run-joint-e2e.ps1`; there is no Rust harness
//!     for headless-browser-driving sodmin from inside a `cargo test`. The existing playwright
//!     scenarios under `cotest/e2e/tests/` are separate from the Rust cotest suite.
//!   * No coauth+sodmin joint bootstrap from `CokretServer` / `TestServerGroup`. The
//!     `_helpers/coauth_bootstrap.rs` module handles coauth alone, not sodmin.
//!   * Sodmin device revoke strand itself: the admin route `POST
//!     /api/admin/v1/accounts/{account_id}/devices/{device_id}/revoke` exists in coauth (per
//!     `sodmin/src/api/coauth_devices_admin.rs`), so once a bootstrap is present this scenario
//!     could bypass the UI and call the API directly as a stepping stone. That would not exercise
//!     the click-strand but would prove the cascade — file as a follow-up if/when the UI driver is
//!     too costly.
//!   * Soland session-invalidation-on-device-revoke cascade is the real unknown: soland does not
//!     currently subscribe to coauth device revocation events. The §9 "device list update MUST" +
//!     the 401-after-revoke expectation in step 6 is the load-bearing assert — verify with a
//!     `--ignored` run after the cascade lands.
//!
//! Track: `_claude_todos.md` row SOD-1.

use anyhow::Result;

/// SOD-1 scenario probe. See module docs for the full walk-through and
/// prerequisite blockers.
pub async fn sodmin_device_revoke_cascade_run() -> Result<()> {
    // When ready:
    //
    //   let stack = bootstrap_soland_coauth_sodmin("sod1-revoke").await?;
    //
    //   // Step 1: register alice + login on soland
    //   let alice_did = "did:web:alice.example";
    //   let alice_token = register_account(&stack.soland, alice_did,
    //                                       "@alice", "dev_A").await?;
    //
    //   // Step 2: smoke
    //   expect_json(stack.soland.http()
    //                  .get(stack.soland.url("/_soland/self/account/me"))
    //                  .bearer_auth(&alice_token),
    //               StatusCode::OK).await?;
    //   let devices = expect_json(stack.coauth_http()
    //                  .get(stack.coauth_url(&format!(
    //                      "/api/admin/v1/accounts/{alice_did}/devices"))),
    //                  StatusCode::OK).await?;
    //   assert_eq!(devices["devices"][0]["is_revoked"], false);
    //
    //   // Step 3-4: drive sodmin admin UI via playwright
    //   let browser = stack.playwright_browser().await?;
    //   let page = browser.new_page().await?;
    //   page.goto(&stack.sodmin_url("/")).await?;
    //   sodmin_admin_login(&page, &stack).await?;
    //   page.goto(&stack.sodmin_url(
    //       &format!("/admin/accounts/{alice_did}/devices"))).await?;
    //   page.locator(&format!("[data-device-id='dev_A'] [data-action='revoke']"))
    //       .click().await?;
    //   page.locator("[data-confirm='revoke-device']").click().await?;
    //   page.locator("[data-toast-status='success']")
    //       .wait_for(WaitForOptions::default().timeout(10_000.0))
    //       .await?;
    //
    //   // Step 5: coauth state shows revoked
    //   let devices_after = expect_json(stack.coauth_http()
    //                  .get(stack.coauth_url(&format!(
    //                      "/api/admin/v1/accounts/{alice_did}/devices"))),
    //                  StatusCode::OK).await?;
    //   assert_eq!(devices_after["devices"][0]["device_id"], "dev_A");
    //   assert_eq!(devices_after["devices"][0]["is_revoked"], true);
    //   assert!(devices_after["devices"][0]["revoked_at"].is_string());
    //
    //   // Step 6: cascade — alice's old soland session is now invalid
    //   expect_status(
    //       stack.soland.http().get(stack.soland.url("/_soland/self/account/me"))
    //                   .bearer_auth(&alice_token),
    //       StatusCode::UNAUTHORIZED,
    //   ).await?;

    unimplemented!(
        "SOD-1 sodmin device revoke cascade — blocked on (a) Rust \
         spawner for sodmin Dioxus UI + playwright integration, \
         (b) joint soland+coauth+sodmin bootstrap helper, and \
         (c) soland session-invalidation-on-device-revoke cascade \
         (see module docs + _claude_todos.md SOD-1)."
    )
}
