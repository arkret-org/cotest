//! Private invite delivery helpers (spec `zh/sync/invite-addressing.md` §7).
//!
//! `governance-objects.md` §5.3 keeps the invite token off the Invite read
//! model: it is transport material delivered on the holder-private
//! account-data cell `ak.account.invite_delivery` (spec registration pending,
//! arkret-work spec-gap 0448). The conforming client flow is: the holder opts
//! the introduction kind into its receive-policy allowlist (§5), the inviter
//! dispatches the already-accepted `ak.invite.create` (§7), and the invitee
//! reads the credential back from its own account-data list.

use anyhow::{Context, Result, bail};
use arkret_models_collaboration::governance::invite_addressing::{
    IntroductionEvidence, InviteAddress, InviteDeliveryRequestBody, InviteReceivePolicy,
};
use arkret_models_collaboration::http_bodies::EventsResolveRequestBody;
use arkret_models_identity::ServiceResolutionCarrier;
use reqwest::StatusCode;

use super::{TestActorClient, actor_core_id, expect_json};

/// Account-data key the Principal Server writes delivered invite credentials
/// under. Server-owned: clients never write this key.
const INVITE_DELIVERY_ACCOUNT_DATA_KEY: &str = "ak.account.invite_delivery";

/// Run the §7 client dispatch for an already-accepted `ak.invite.create` on a
/// same-service target and read the delivered invite token back from the
/// invitee's actor-private account-data cell.
///
/// `invite_event_id` is the accepted Event id; `invite_id` is its
/// Event-derived Invite id as listed by `/_arkret/self/authz/invites`.
pub async fn dispatch_accepted_invite_and_read_token(
    inviter: &TestActorClient,
    invitee: &TestActorClient,
    invite_event_id: &str,
    invite_id: &str,
    introduction_evidence: IntroductionEvidence,
) -> Result<String> {
    opt_in_introduction_kind(invitee, introduction_evidence.kind()).await?;
    let invite_event = resolve_accepted_event(inviter, invite_event_id).await?;
    dispatch_invite(
        inviter,
        invitee,
        invite_event,
        introduction_evidence,
        invite_event_id,
    )
    .await?;
    read_delivered_invite_token(invitee, invite_id).await
}

/// §5 — the protocol default receive policy fails closed on unknown
/// introduction kinds, so the holder explicitly allowlists the kind this
/// delivery carries; otherwise the receive chain drops it before any notify.
async fn opt_in_introduction_kind(invitee: &TestActorClient, kind: &str) -> Result<()> {
    let current = expect_json(
        invitee.get("/_arkret/self/invite-receive-policy"),
        StatusCode::OK,
    )
    .await?;
    let mut policy: InviteReceivePolicy = serde_json::from_value(current)
        .context("invite-receive-policy response is not an InviteReceivePolicy")?;
    if policy
        .holder_allowed_introduction_kinds
        .iter()
        .any(|allowed| allowed == kind)
    {
        return Ok(());
    }
    policy
        .holder_allowed_introduction_kinds
        .push(kind.to_owned());
    expect_json(
        invitee
            .put("/_arkret/self/invite-receive-policy")
            .json(&policy),
        StatusCode::OK,
    )
    .await?;
    Ok(())
}

/// §7 — the client fills `invite_event` by reading the accepted Event back
/// through `ak.self.events.read.resolve`; re-authoring from local state cannot
/// be guaranteed byte-identical to the persisted canonical bytes.
async fn resolve_accepted_event(
    inviter: &TestActorClient,
    event_id: &str,
) -> Result<arkret_wire::Event> {
    let resolved = expect_json(
        inviter
            .query("/_arkret/self/events/resolve")
            .json(&EventsResolveRequestBody {
                event_ids: vec![arkret_identifiers::EventId::new(event_id.to_owned())?],
                event_digests: Vec::new(),
                seal_refs: Vec::new(),
                include_payload: Some(true),
            }),
        StatusCode::OK,
    )
    .await?;
    let event = resolved["events"]
        .as_array()
        .and_then(|events| events.first())
        .cloned()
        .ok_or_else(|| {
            anyhow::anyhow!("accepted invite Event {event_id} did not resolve: {resolved}")
        })?;
    serde_json::from_value(event).context("resolved invite Event is not a wire Event")
}

async fn dispatch_invite(
    inviter: &TestActorClient,
    invitee: &TestActorClient,
    invite_event: arkret_wire::Event,
    introduction_evidence: IntroductionEvidence,
    idempotency_key: &str,
) -> Result<()> {
    let service_id = arkret_identifiers::DidCoreId::new(inviter.service_id().to_owned())?;
    // This carrier is byte-for-byte the one `invite_create_payload` commits to
    // in the invite payload (§7 step 6 equality), so both sides read the same
    // normalizer.
    let service_resolution = ServiceResolutionCarrier::CurrentRecordUrl {
        current_record_url: format!(
            "https://cotest.invalid{}",
            arkret_models_identity::canonical_service_current_record_path(&service_id)
        ),
        pinned_record_digest: None,
    };
    let invitee_core = arkret_identifiers::DidCoreId::new(actor_core_id(&invitee.actor)?)?;
    let delivery = InviteDeliveryRequestBody::new(
        invite_event,
        InviteAddress::principal_server(invitee_core, service_id, service_resolution),
        introduction_evidence,
        idempotency_key,
    );
    let dispatched = expect_json(
        inviter
            .post("/_arkret/self/invites/dispatch")
            .json(&delivery),
        StatusCode::OK,
    )
    .await?;
    if dispatched["status"].as_str() != Some("accepted") {
        bail!("invite dispatch was not accepted: {dispatched}");
    }
    Ok(())
}

/// Read the delivered credential from the invitee's holder-private
/// account-data cell. The cell is the durable source of truth; the to-device
/// `ak.account_data.update` fanout is only a nudge, and the holder-readable
/// list surface (`ak.self.account_data.read.list`) returns every non-internal
/// cell without the single-key registration gate.
async fn read_delivered_invite_token(invitee: &TestActorClient, invite_id: &str) -> Result<String> {
    let listed = expect_json(invitee.get("/_arkret/self/account_data"), StatusCode::OK).await?;
    let entries = listed["entries"].as_array().cloned().unwrap_or_default();
    let cell = entries
        .iter()
        .find(|entry| entry["account_data_key"].as_str() == Some(INVITE_DELIVERY_ACCOUNT_DATA_KEY));
    let token = cell
        .and_then(|entry| entry["content"]["entries"].as_array())
        .and_then(|cell_entries| {
            cell_entries
                .iter()
                .find(|entry| entry["invite_id"].as_str() == Some(invite_id))
        })
        .and_then(|entry| entry["invite_token"].as_str())
        .map(str::to_owned);
    token.ok_or_else(|| {
        anyhow::anyhow!(
            "no delivered invite credential for {invite_id} in the invitee account-data list: {}",
            serde_json::to_string_pretty(&entries).unwrap_or_default()
        )
    })
}
