//! `cx.profile.agent_workspace.v1` — soland HTTP service e2e wrapper.
//!
//! Spec: `contrix-spec/spec/v1/zh/extensions/agent-workspace-profile.md §11`.
//! Scenario impl: `cotest::scenarios::agent_workspace_e2e`.
//!
//! Verifies the four wire invariants the soland-side stub already enforces:
//!
//!   1. `/api/v1/agent_workspace/mirror_flow` routed with the canonical
//!      operationId `cx.agent_workspace.resolve_mirror_flow`.
//!   2. `/api/v1/agent_workspace/pending_tasks` routed with the canonical
//!      operationId `cx.agent_workspace.list_pending_tasks`.
//!   3. Unauthenticated calls to either endpoint MUST be 401/403 (NOT 404)
//!      so workspace existence is not enumerable from anonymous probes.
//!   4. OpenAPI doc advertises both operations.
//!
//! The full Phase-1/2/3 mention_redirect saga lands when soland-side reducer
//! integration ships (see `contrix-spec/_todos.md` AW-2.2 / AW-2.4); when it
//! does, extend this file with a second `#[tokio::test]` that drives the
//! happy path.
//!
//! The scenario silently skips when no `SOLAND_BIN` is set and the
//! sibling-checkout binary does not exist, matching
//! `federation_two_node_e1`'s behavior.

use anyhow::Result;
use serial_test::serial;

#[tokio::test]
#[serial]
async fn agent_workspace_http_surface_is_routed_and_privacy_invariant_holds() -> Result<()> {
    cotest::scenarios::agent_workspace_e2e::agent_workspace_http_surface_e2e().await
}
