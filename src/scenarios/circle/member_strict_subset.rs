//! P2F.3 — Circle.members MUST be a strict subset of Realm.members.
//!
//! Drives `Circle::assert_members_strict_subset` directly with:
//!   - an accepted case (Circle members ⊂ Realm members),
//!   - the empty Realm degenerate accept (no members on either side),
//!   - a rejected case (Circle member not in Realm) — must surface
//!     `CircleScopeError::MemberNotInRealm` with the offending `DidCoreId`.
//!
//! The error name pin protects callers that match on the variant to map
//! to wire reason code `circle_member_must_be_realm_member`.

use anyhow::{Result, anyhow};
use arkret_identifiers::DidCoreId;
use arkret_models_collaboration::governance::circle::{Circle, CircleScopeError};

fn did(local: &str) -> Result<DidCoreId> {
    format!("did:web:{local}.example")
        .parse()
        .map_err(|e| anyhow!("did {local}: {e}"))
}

pub async fn member_strict_subset_run() -> Result<()> {
    let alice = did("alice")?;
    let bob = did("bob")?;
    let carol = did("carol")?;
    let mallory = did("mallory")?;

    let realm = vec![alice.clone(), bob.clone(), carol];

    // Accept: Circle members ⊂ Realm members.
    let circle_ok = vec![alice.clone(), bob];
    Circle::assert_members_strict_subset(&circle_ok, &realm)
        .map_err(|e| anyhow!("strict-subset accept failed: {e}"))?;

    // Accept the degenerate empty case (Circle ⊆ Realm trivially).
    Circle::assert_members_strict_subset(&[], &realm)
        .map_err(|e| anyhow!("empty-circle accept failed: {e}"))?;
    Circle::assert_members_strict_subset(&[], &[])
        .map_err(|e| anyhow!("empty-realm-empty-circle accept failed: {e}"))?;

    // Reject: mallory is not in the Realm.
    let circle_bad = vec![alice, mallory.clone()];
    match Circle::assert_members_strict_subset(&circle_bad, &realm) {
        Ok(()) => Err(anyhow!(
            "strict-subset MUST reject `mallory` ∉ realm; got Ok"
        )),
        Err(CircleScopeError::MemberNotInRealm { circle_member }) => {
            if circle_member.as_str() == mallory.as_str() {
                Ok(())
            } else {
                Err(anyhow!(
                    "expected MemberNotInRealm(mallory); got MemberNotInRealm({})",
                    circle_member.as_str()
                ))
            }
        }
        Err(e) => Err(anyhow!(
            "expected CircleScopeError::MemberNotInRealm, got: {e}"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn strict_subset_accept_and_reject() {
        member_strict_subset_run().await.unwrap();
    }
}
