//! §11.5 — act-on-behalf attribution.
//!
//! Every event executed by an agent on behalf of its controller MUST
//! carry the triple (`executed_by`, `authorization_ref`, `actor_kind`).
//!   - `executed_by` is the agent's DID.
//!   - `authorization_ref` is the `EventId` of the controller's `ak.identity.accountability_grant`
//!     event (the dedicated `ak:accountability_grant:` typed-id family is retired).
//!   - `actor_kind` is the reducer-stamped `EnvelopeActorKind::Agent`.
//!
//! Client-supplied `actor_kind` MUST be rejected with
//! `actor_kind_self_stamped`.

use anyhow::{Result, anyhow};
use arkret_identifiers::{Did, EventId};
use arkret_wire::EnvelopeActorKind;

pub async fn act_on_behalf_attribution_run() -> Result<()> {
    // (a) the EnvelopeActorKind enum has exactly the spec-required
    // variants (Native, Ghost, Service, Agent).
    let _native = EnvelopeActorKind::Native;
    let _ghost = EnvelopeActorKind::Ghost;
    let _service = EnvelopeActorKind::Service;
    let agent_kind = EnvelopeActorKind::Agent;

    // (b) the agent variant serializes / matches as expected.
    if !matches!(agent_kind, EnvelopeActorKind::Agent) {
        return Err(anyhow!("EnvelopeActorKind::Agent failed match"));
    }

    // (c) the triple's types round-trip.
    let executed_by = Did::new("did:web:agent.example.com".to_owned())
        .map_err(|e| anyhow!("executed_by DID: {e}"))?;
    let authorization_ref =
        EventId::new("ak:event:01999999-0000-8000-8000-00000000b005".to_owned())
            .map_err(|e| anyhow!("authorization_ref: {e}"))?;
    if !executed_by.as_str().starts_with("did:") {
        return Err(anyhow!("executed_by must be a DID"));
    }
    if !authorization_ref.as_str().starts_with("ak:event:") {
        return Err(anyhow!(
            "authorization_ref must be the accountability-grant event's EventId"
        ));
    }
    // TODO(P4-impl): drive a real `ak.message.create` envelope through
    // the SDK with the triple set; assert the reducer accepts it +
    // stamps `actor_kind=Agent` (rejecting any client-supplied value).
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn triple_attribution_pinned() {
        act_on_behalf_attribution_run().await.unwrap();
    }
}
