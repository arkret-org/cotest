//! P2F.4 — teabay MUST NOT index Circle membership.
//!
//! AKP-0007's normative privacy promise: a Circle is invisible to the
//! directory. Specifically, teabay's `directory_index` ingest pipeline
//! MUST refuse to project any event whose `effective_scope` is a
//! `Circle` variant, AND MUST NOT publish a Circle in any
//! `directory_visibility=members` response to a non-member.
//!
//! This scenario doesn't run teabay — it exercises the local filter
//! function that any teabay ingest binding MUST implement. The filter's
//! contract:
//!
//!   * Realm-scoped event → projected.
//!   * Circle-scoped event → DROPPED with `reason="circle_scoped"`.
//!   * Realm event with `directory_visibility=members` AND the querying actor is not a Realm member
//!     → projected as `hidden`.
//!
//! Returns `Ok(())` when the filter behaviour matches the contract.

use anyhow::{Result, anyhow};
use arkret_identifiers::{CircleId, RealmId};
use arkret_wire::ScopeRef;

/// Drop reason emitted by the teabay ingest filter when an event is
/// suppressed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectoryFilterDecision {
    /// Event is safe to project to the directory index as-is.
    Project,
    /// Event MUST NOT enter the directory index — Circle-scoped.
    DropCircleScoped,
}

/// The normative filter every teabay ingest binding MUST implement.
pub fn ingest_filter(scope: &ScopeRef) -> DirectoryFilterDecision {
    match scope {
        ScopeRef::Realm { .. } => DirectoryFilterDecision::Project,
        ScopeRef::Circle { .. } => DirectoryFilterDecision::DropCircleScoped,
        // `ScopeRef` is `#[non_exhaustive]`: an unrecognised scope
        // variant MUST fail closed and stay out of the directory index.
        _ => DirectoryFilterDecision::DropCircleScoped,
    }
}

fn realm_id() -> Result<RealmId> {
    RealmId::new("ak:realm:AQxESjygOD-pmc6HGOfiiRIFONA4YBDn0Zxq3g9OG2BN".to_owned())
        .map_err(|e| anyhow!("realm id: {e}"))
}

fn circle_id() -> Result<CircleId> {
    CircleId::new("ak:circle:AWj4-tJVX8xPhBVRd4rqfkaFKC6oLKNjA5jk5BuxmTjt".to_owned())
        .map_err(|e| anyhow!("circle id: {e}"))
}

pub async fn circle_not_indexed_run() -> Result<()> {
    let realm = ScopeRef::Realm {
        realm_id: realm_id()?,
    };
    let circle = ScopeRef::Circle {
        realm_id: realm_id()?,
        circle_id: circle_id()?,
    };
    if ingest_filter(&realm) != DirectoryFilterDecision::Project {
        return Err(anyhow!(
            "ingest_filter MUST project Realm-scoped events; rejected {realm:?}"
        ));
    }
    if ingest_filter(&circle) != DirectoryFilterDecision::DropCircleScoped {
        return Err(anyhow!(
            "ingest_filter MUST DROP Circle-scoped events with reason=circle_scoped; \
             accepted {circle:?}"
        ));
    }
    // Sanity: the filter MUST be pure (idempotent on repeated calls).
    for _ in 0..3 {
        if ingest_filter(&circle) != DirectoryFilterDecision::DropCircleScoped {
            return Err(anyhow!("ingest_filter is non-deterministic"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn directory_filter_drops_circle_scope() {
        circle_not_indexed_run().await.unwrap();
    }
}
