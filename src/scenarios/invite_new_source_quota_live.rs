//! Live acceptance for the per-holder new-source quota that guards the invite
//! quarantine inbox (`identity/consent-model.md` sections 6.1.1.1 to 6.1.1.4).
//!
//! Covers `ak.vector.invite.new_source_quota_holder_admission.v1` and
//! `ak.vector.invite.new_source_quota_effective_bounds.v1`.
//!
//! Every deployment ceiling and every expected outcome below is read out of the
//! canonical fixture `invite-new-source-quota-fixture.json`. This scenario owns
//! only the live wiring: it never restates a threshold or a decision, so a
//! PostgreSQL-backed Station is measured against the same bytes the offline
//! fixture runner executes.
//!
//! Every assertion is taken from the **holder's** `ak.account.invite_quarantine`
//! cell, because the requester side is designed to be indistinguishable: an
//! admitted quarantine, a quota drop, a TTL drop, an unknown holder and a policy
//! deny all return the same opaque `deferred`. Checking the requester's response
//! could therefore never tell an enforced quota from an unenforced one, while a
//! missing cell entry can.

use std::collections::BTreeMap;

use anyhow::{Context, Result, ensure};
use arkret_models_collaboration::governance::invite_addressing::InviteReceivePolicy;
use arkret_wire::{AccountDataKey, InviteReceiveAction, NewSourceQuotaOverride};
use reqwest::StatusCode;
use serde_json::Value;

use crate::conformance::{CanonicalAdmissionCase, canonical_admission_case};
use crate::harness::{ArkretServer, TestActorClient, actor_core_id, expect_json};
use crate::scenarios::identity_test_support::actor_did_for_service_did;
use crate::scenarios::invite_service_fanout_live::{
    account_data_row, create_and_dispatch_explicit_invite, set_explicit_address_behavior,
};

/// The one admission timeline whose ledger and cell both start empty and whose
/// contacts all fall inside a single short window, so a live Station can replay
/// it without controlling the clock.
const REPLAYABLE_ADMISSION_CASE: &str =
    "short_window_ceiling_admits_then_drops_while_a_charged_source_still_enters";
const ZERO_OVERRIDE_CASE: &str = "zero_holder_override_locks_the_inbox";

/// Distinct source principals recorded in the holder's quarantine cell, oldest
/// first and with repeats preserved: a repeat contact from an already-charged
/// source is a second entry, not a second charge.
async fn quarantined_sources(holder: &TestActorClient) -> Result<Vec<String>> {
    let row = match account_data_row(holder, AccountDataKey::ACCOUNT_INVITE_QUARANTINE).await {
        Ok(row) => row,
        // No cell at all is the legitimate "nothing was ever admitted" state.
        Err(_) => return Ok(Vec::new()),
    };
    let entries = row.content["quarantine_entries"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    Ok(entries
        .iter()
        .filter_map(|entry| {
            entry["source_peer_principal_id"]
                .as_str()
                .map(str::to_owned)
        })
        .collect())
}

/// Every branch of this scenario must stay inside the opaque equivalence class.
fn assert_opaque_deferred(outcome: &Value) -> Result<()> {
    ensure!(
        outcome["status"] == "deferred" && outcome.get("disclosed_outcome").is_none(),
        "new-source quota changed the requester-visible outcome: {outcome}"
    );
    Ok(())
}

async fn holder_with_quarantine_policy(
    server: &ArkretServer,
    label: &str,
) -> Result<TestActorClient> {
    let holder_did = actor_did_for_service_did(server.service_did(), label)?;
    let holder = server
        .register_client(
            &holder_did,
            label,
            "ak:device:01904100-0000-7000-8000-0000000000c1",
        )
        .await
        .context("bootstrap holder client")?;
    set_explicit_address_behavior(&holder, InviteReceiveAction::Quarantine)
        .await
        .context("bind quarantine receive policy")?;
    Ok(holder)
}

async fn inviter(server: &ArkretServer, label: &str, device_suffix: u8) -> Result<TestActorClient> {
    server
        .demo_client(
            &actor_did_for_service_did(server.service_did(), label)?,
            &format!("ak:device:01904100-0000-7000-8000-0000000000{device_suffix:02x}"),
        )
        .await
        .with_context(|| format!("bootstrap inviter {label}"))
}

async fn spawn_under_canonical_ceiling(
    name: &str,
    case: &CanonicalAdmissionCase,
) -> Result<ArkretServer> {
    ensure!(
        case.starts_from_empty_state,
        "{}: a live replay needs a timeline that starts from an empty ledger and cell",
        case.name
    );
    let environment = case.deployment_environment();
    let borrowed = environment
        .iter()
        .map(|(key, value)| (*key, value.as_str()))
        .collect::<Vec<_>>();
    ArkretServer::spawn_with_env(name, &borrowed).await
}

/// `ak.vector.invite.new_source_quota_holder_admission.v1`.
pub async fn new_source_quota_holder_admission_run() -> Result<()> {
    let case = canonical_admission_case(REPLAYABLE_ADMISSION_CASE)?;
    let server = spawn_under_canonical_ceiling("invite-new-source-quota", &case).await?;
    let holder = holder_with_quarantine_policy(&server, "bob-new-source-quota").await?;

    // One live peer per canonical source alias. A repeated alias reuses the
    // same peer, which is what makes the fourth contact a seen source rather
    // than a fifth stranger.
    let mut peers: BTreeMap<String, TestActorClient> = BTreeMap::new();
    let mut principals: BTreeMap<String, String> = BTreeMap::new();
    for (index, contact) in case.contacts.iter().enumerate() {
        if !peers.contains_key(&contact.source) {
            let label = format!("alice-new-source-quota-{}", contact.source);
            let peer = inviter(&server, &label, 0xd1 + index as u8).await?;
            principals.insert(contact.source.clone(), actor_core_id(&peer.actor)?);
            peers.insert(contact.source.clone(), peer);
        }

        // A distinct label per contact keeps each dispatch its own invite, so a
        // repeat from one source is a second delivery rather than an exact
        // replay that section 6.1.1.4 excludes from quota evaluation.
        let label = format!("quota contact {index} from {}", contact.source);
        let peer = &peers[&contact.source];
        let dispatched = create_and_dispatch_explicit_invite(peer, &holder, &label)
            .await
            .with_context(|| {
                format!(
                    "dispatch canonical contact[{index}] from {}",
                    contact.source
                )
            })?;
        assert_opaque_deferred(&dispatched.outcome)?;

        let expected = case
            .quarantine_entry_sources_after(index + 1)
            .iter()
            .map(|alias| principals[alias].clone())
            .collect::<Vec<_>>();
        let observed = quarantined_sources(&holder).await?;
        ensure!(
            observed == expected,
            "{}: after contact[{index}] ({} {:?}) the quarantine cell is {observed:?}, the canonical fixture declares {expected:?}",
            case.name,
            contact.source,
            contact.expected_decision
        );
    }

    Ok(())
}

/// `ak.vector.invite.new_source_quota_effective_bounds.v1`.
///
/// The holder override may only make the holder less reachable. The canonical
/// fixture pins the zero override to zero admissions even though the deployment
/// default would admit more.
pub async fn new_source_quota_effective_bounds_run() -> Result<()> {
    let case = canonical_admission_case(ZERO_OVERRIDE_CASE)?;
    let holder_override = case
        .holder_override
        .clone()
        .context("the canonical zero-override case must publish a holder override")?;
    let server = spawn_under_canonical_ceiling("invite-new-source-bounds", &case).await?;
    let holder = holder_with_quarantine_policy(&server, "bob-new-source-bounds").await?;
    set_new_source_quota_override(&holder, &holder_override)
        .await
        .context("publish the canonical holder override")?;

    for (index, contact) in case.contacts.iter().enumerate() {
        let peer = inviter(
            &server,
            &format!("alice-new-source-bounds-{}", contact.source),
            0xe1 + index as u8,
        )
        .await?;
        let label = format!("bounds contact {index} from {}", contact.source);
        let dispatched = create_and_dispatch_explicit_invite(&peer, &holder, &label)
            .await
            .with_context(|| format!("dispatch canonical contact[{index}] under the override"))?;
        assert_opaque_deferred(&dispatched.outcome)?;
    }

    ensure!(
        case.quarantine_entry_sources.is_empty(),
        "{}: the canonical zero-override case must expect an empty quarantine cell",
        case.name
    );
    let sources = quarantined_sources(&holder).await?;
    ensure!(
        sources.is_empty(),
        "a zero new-source override still admitted a source: {sources:?}"
    );

    Ok(())
}

/// Publish the holder-private `new_source_quota` override on top of whatever
/// receive policy the holder already has.
async fn set_new_source_quota_override(
    holder: &TestActorClient,
    quota_override: &NewSourceQuotaOverride,
) -> Result<()> {
    let current = expect_json(
        holder.get("/_arkret/self/invite-receive-policy"),
        StatusCode::OK,
    )
    .await?;
    let mut policy: InviteReceivePolicy = serde_json::from_value(current)
        .context("invite-receive-policy response is not an InviteReceivePolicy")?;
    policy.new_source_quota = Some(quota_override.clone());
    let updated = expect_json(
        holder
            .put("/_arkret/self/invite-receive-policy")
            .json(&policy),
        StatusCode::OK,
    )
    .await?;
    let updated: InviteReceivePolicy = serde_json::from_value(updated)
        .context("updated invite-receive-policy is not an InviteReceivePolicy")?;
    ensure!(
        updated.new_source_quota == policy.new_source_quota,
        "Station rewrote the holder new_source_quota override"
    );
    Ok(())
}
