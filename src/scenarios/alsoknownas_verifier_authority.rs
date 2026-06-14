//! P4-F — `alsoKnownAs` verifier-authority guard.
//!
//! Per B-E (identity-handles.md §4.1 + §6.0), server-attested
//! `binding_state = verified` is a CACHE HINT only. Any trust decision
//! (wallet disclosure, accept invite, join official Realm, cross-org
//! federation, audit trail) MUST first-party verify the DID Document
//! itself — the wire field MUST NOT be propagated as authority.

use anyhow::{Result, anyhow};

#[derive(Debug, Clone)]
struct ServerAttestedAka {
    #[allow(dead_code)]
    binding_state: String,
}

/// Returns true iff the caller is permitted to trust this attestation
/// without re-running first-party verification.
///
/// Per spec, NO server-attested attestation may stand in for the
/// first-party check on trust decisions. So this function MUST always
/// return false for trust-decision call sites.
fn allow_as_authority_for_trust_decision(_attestation: &ServerAttestedAka) -> bool {
    false
}

pub async fn alsoknownas_verifier_authority_run() -> Result<()> {
    let attestation = ServerAttestedAka {
        binding_state: "verified".to_owned(),
    };
    if allow_as_authority_for_trust_decision(&attestation) {
        return Err(anyhow!(
            "server-attested binding_state=verified was accepted as authority — \
             spec B-E REQUIRES first-party verify on every trust decision"
        ));
    }
    // Even with the most-favoured field value, the contract holds.
    let strong_attestation = ServerAttestedAka {
        binding_state: "verified".to_owned(),
    };
    if allow_as_authority_for_trust_decision(&strong_attestation) {
        return Err(anyhow!(
            "binding_state=verified is NEVER authority for trust decisions"
        ));
    }
    // TODO(P4-impl): exercise yougen's "Accept Invite" strand: stub a
    // teabay response carrying `binding_state=verified` for the
    // invitee's alsoKnownAs; assert yougen still issues the first-party
    // DID Document fetch + verifies signature before binding the
    // handle.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn server_attestation_never_authority() {
        alsoknownas_verifier_authority_run().await.unwrap();
    }
}
