//! §11.8 — eligibility tri-state + revocation.
//!
//! A capability grant has three states — `active`, `paused`,
//! `revoked` — and the lifecycle MUST close the loop on capability
//! cache invalidation. `revoked` is terminal; transitioning from
//! `revoked` to either of the other two MUST be rejected.

use anyhow::{Result, anyhow};

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum GrantState {
    Active,
    Paused,
    Revoked,
}

/// Legal transitions in the tri-state lifecycle.
fn transition_allowed(from: GrantState, to: GrantState) -> bool {
    use GrantState::*;
    matches!(
        (from, to),
        (Active, Paused)
            | (Active, Revoked)
            | (Paused, Active)
            | (Paused, Revoked)
            | (Active, Active)
            | (Paused, Paused)
            | (Revoked, Revoked)
    )
}

pub async fn eligibility_tristate_and_revocation_run() -> Result<()> {
    // Legal transitions.
    for (from, to) in [
        (GrantState::Active, GrantState::Paused),
        (GrantState::Paused, GrantState::Active),
        (GrantState::Active, GrantState::Revoked),
        (GrantState::Paused, GrantState::Revoked),
    ] {
        if !transition_allowed(from, to) {
            return Err(anyhow!(
                "eligibility tri-state regression: {from:?} → {to:?} should be legal"
            ));
        }
    }

    // Revocation is terminal.
    for to in [GrantState::Active, GrantState::Paused] {
        if transition_allowed(GrantState::Revoked, to) {
            return Err(anyhow!(
                "Revoked is terminal but {to:?} accepted as next state"
            ));
        }
    }

    // TODO(P4-impl): live vector — attach a grant, pause it, observe
    // floria's capability cache loses the entry; resume, attempts at
    // the agent surface succeed; revoke, the cache is purged and any
    // future attempts return `capability_denied`.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn tri_state_transitions_pinned() {
        eligibility_tristate_and_revocation_run().await.unwrap();
    }
}
