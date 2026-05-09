//! E1 Round 24 — federation two-node start scaffolding.
//!
//! Goal: spin up two real `soland` binaries on independent ports/blob roots,
//! confirm they negotiate basic federation handshake (`/api/v1/server/describe`
//! reachable on both, distinct service DIDs), and provide a docked entrypoint
//! that future rounds will extend with cross-server Move replay, anchor
//! verification, and federation transcript-diff scenarios.
//!
//! TODO(e1-federation): the actual two-node Move-replay scenario is intentionally
//! deferred — round 24 lands the harness only. Future rounds will:
//!   * exchange a sample governance Move from server_a to server_b via the
//!     `/api/v1/federation/forward-move` endpoint and assert the lattice
//!     reduction is identical on both nodes;
//!   * run an MLS commit on server_a, sync the covered_frontier ref to
//!     server_b, and assert E2EE messages from b decrypt under the shared
//!     epoch on both sides;
//!   * federation transcript-diff: capture HTTP transcripts on both nodes
//!     and assert symmetric replay (no node-local divergence).

use anyhow::Result;
use reqwest::StatusCode;

use crate::harness::{TestServerGroup, expect_json};

/// Spawns two `soland` instances and runs the round-24 federation harness
/// scaffolding: distinct service DIDs, both nodes reachable, identity-resolve
/// works on each. Subsequent rounds will graft the actual two-node Move-replay
/// scenario onto this scaffold (TODO(e1-federation)).
pub async fn two_node_federation_harness_starts() -> Result<()> {
    let group = TestServerGroup::multi("e1-federation-two-node", 2).await?;
    assert_eq!(group.len(), 2, "two-node group must have exactly 2 servers");

    let server_a = group.server(0);
    let server_b = group.server(1);

    // Both nodes MUST be independently reachable and report their own
    // service_did via the describe endpoint.
    let describe_a = expect_json(
        server_a.http().get(server_a.url("/api/v1/server/describe")),
        StatusCode::OK,
    )
    .await?;
    let describe_b = expect_json(
        server_b.http().get(server_b.url("/api/v1/server/describe")),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(describe_a["service_type"], "principal_server");
    assert_eq!(describe_b["service_type"], "principal_server");
    assert_ne!(
        server_a.service_did(),
        server_b.service_did(),
        "two-node federation requires distinct service DIDs"
    );

    // TODO(e1-federation): exchange a federated governance Move between the
    // two nodes via /api/v1/federation/forward-move and assert that the
    // resulting lattice reduction (cell state) is identical on both sides.
    // This requires:
    //   1. server_a posts a Move to its own /api/v1/spaces/<id>/moves;
    //   2. server_a forwards the canonical Move bytes to server_b via
    //      /api/v1/federation/forward-move;
    //   3. server_b reduces the Move into its mirror of the cell;
    //   4. cotest fetches /api/v1/spaces/<id>/cells/<cell> from both nodes
    //      and asserts the same canonical state_subject + value.

    // TODO(e1-federation): run an MLS genesis on server_a and a member-add
    // commit on server_b; assert covered_frontier accumulates the same
    // governance refs on both nodes.

    // TODO(e1-federation): capture transcripts on both nodes, run
    // symmetric-replay diff, and assert no node-local divergence in the
    // federated subgraph.

    Ok(())
}
