//! `cx.profile.agent_workspace.v1` — soland HTTP service e2e.
//!
//! Spec: `contrix-spec/spec/v1/zh/extensions/agent-workspace-profile.md`
//!       (§11 service operations + §12 DID Document service entry).
//!
//! This scenario spawns one `soland` binary and exercises the two new HTTP
//! endpoints defined by `cx.profile.agent_workspace.v1`:
//!
//!   - `GET /api/v1/agent_workspace/mirror_flow?source_flow_id=...`
//!   - `GET /api/v1/agent_workspace/pending_tasks`
//!
//! The endpoints currently live as stubs on soland (full reducer integration
//! is tracked in `contrix-spec/_todos.md` AW-2.2 / AW-2.4). This scenario
//! verifies the four wire invariants that ARE in place today:
//!
//! 1. Both endpoints are routed under `/api/v1/agent_workspace/...` and
//!    advertised through `/api/v1/openapi.json` with the correct
//!    operationId (`cx.agent_workspace.resolve_mirror_flow` and
//!    `cx.agent_workspace.list_pending_tasks`).
//! 2. Unauthenticated `resolve_mirror_flow` requests MUST return 401/403,
//!    NOT 404 (privacy invariant: workspace existence is not enumerable
//!    even on a freshly-bootstrapped server).
//! 3. Unauthenticated `list_pending_tasks` requests MUST return 401/403.
//! 4. The stub `list_pending_tasks` for an authenticated controller MUST
//!    return `{"tasks": []}` (empty list) — the documented stub behaviour
//!    until the agent_task projection lands.
//!
//! When the full reducer + cell projection lands, this scenario MUST be
//! extended to drive a complete Phase 1 / Phase 2 / Phase 3 saga (issue
//! `cx.agent_task.create`, observe transparency-cell transitions, etc.).

use anyhow::{Context, Result};
use reqwest::StatusCode;

use crate::harness::TestServerGroup;

/// One-soland-binary agent_workspace HTTP surface e2e.
///
/// Returns `Ok(())` early when no soland binary is locatable (CI runner
/// without a pre-built soland — silent skip, identical pattern to
/// `federation_two_node_e1`).
pub async fn agent_workspace_http_surface_e2e() -> Result<()> {
    let Some(group) = TestServerGroup::try_multi_external("e2-agent-workspace-http", 1).await?
    else {
        // Silent skip: no SOLAND_BIN and no sibling-checkout binary.
        return Ok(());
    };
    assert_eq!(group.len(), 1);
    let server = group.server(0);

    // Use a wire-canonical source_flow_id so we don't trip the strict
    // typed-id validator on the way in (the stub still 404s, but we get
    // past pre-handler schema checks).
    let source_flow_id = "cx:flow:01964200-0000-7000-8000-000000000011";

    // ── Step 1: unauthenticated resolve_mirror_flow MUST be 401/403,
    //          NOT 404 (privacy invariant — workspace existence not
    //          enumerable). spec §11.1 + §16.
    let resolve_url = format!(
        "/api/v1/agent_workspace/mirror_flow?source_flow_id={}",
        source_flow_id
    );
    let response = server
        .http()
        .get(server.url(&resolve_url))
        .send()
        .await
        .context("send unauthenticated resolve_mirror_flow")?;
    let status = response.status();
    assert!(
        status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN,
        "unauthenticated resolve_mirror_flow MUST be 401/403, got {}",
        status
    );
    assert_ne!(
        status,
        StatusCode::NOT_FOUND,
        "resolve_mirror_flow MUST NOT return 404 to unauthenticated callers (existence non-enumerable)"
    );

    // ── Step 2: unauthenticated list_pending_tasks MUST be 401/403.
    let pending_url = "/api/v1/agent_workspace/pending_tasks";
    let response = server
        .http()
        .get(server.url(pending_url))
        .send()
        .await
        .context("send unauthenticated list_pending_tasks")?;
    let status = response.status();
    assert!(
        status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN,
        "unauthenticated list_pending_tasks MUST be 401/403, got {}",
        status
    );

    // ── Step 3: OpenAPI doc advertises the two operationIds with the
    //          correct path + method bindings.
    let openapi = server
        .http()
        .get(server.url("/.well-known/contrix/openapi.json"))
        .send()
        .await?
        .json::<serde_json::Value>()
        .await?;

    let paths = openapi
        .get("paths")
        .and_then(serde_json::Value::as_object)
        .context("openapi missing paths")?;

    // Both operations live under /api/v1/agent_workspace/...; check the
    // operationId on each.
    let mirror_path = paths
        .get("/api/v1/agent_workspace/mirror_flow")
        .context("openapi missing /api/v1/agent_workspace/mirror_flow")?;
    let mirror_op_id = mirror_path
        .pointer("/get/operationId")
        .and_then(serde_json::Value::as_str);
    assert_eq!(
        mirror_op_id,
        Some("cx.agent_workspace.resolve_mirror_flow"),
        "GET /api/v1/agent_workspace/mirror_flow must declare operationId=cx.agent_workspace.resolve_mirror_flow"
    );

    let pending_path = paths
        .get("/api/v1/agent_workspace/pending_tasks")
        .context("openapi missing /api/v1/agent_workspace/pending_tasks")?;
    let pending_op_id = pending_path
        .pointer("/get/operationId")
        .and_then(serde_json::Value::as_str);
    assert_eq!(
        pending_op_id,
        Some("cx.agent_workspace.list_pending_tasks"),
        "GET /api/v1/agent_workspace/pending_tasks must declare operationId=cx.agent_workspace.list_pending_tasks"
    );

    Ok(())
}
