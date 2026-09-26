//! Live acceptance for the per-holder new-source quota that guards the holder
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
//! Every assertion is taken from the **holder's** `ak.account.holder_quarantine`
//! cell, because the requester side is designed to be indistinguishable: an
//! admitted quarantine, a quota drop, a TTL drop, an unknown holder and a policy
//! deny all return the same opaque `deferred`. Checking the requester's response
//! could therefore never tell an enforced quota from an unenforced one, while a
//! missing cell entry can.

use std::collections::BTreeMap;

use anyhow::{Context, Result, ensure};
use arkret_models_collaboration::consent_operations::ConsentRequestRequestBody;
use arkret_models_collaboration::governance::invite_addressing::InviteReceivePolicy;
use arkret_wire::{
    AccountDataKey, AccountId, ConsentProfile, ConsentRequestScope, DidCoreId, InviteReceiveAction,
    NewSourceQuotaOverride,
};
use reqwest::StatusCode;
use serde_json::Value;

use crate::conformance::{
    CanonicalAdmissionCase, NewSourceQuotaDecision, canonical_admission_case,
};
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
/// `ak.vector.invite.new_source_quota_holder_admission.v1` step 7: the holder
/// runs the `require_explicit_consent` profile, so the quota never evaluates.
const REQUIRE_EXPLICIT_CONSENT_CASE: &str =
    "require_explicit_consent_profile_has_no_quarantine_face";

/// Distinct source principals recorded in the holder's quarantine cell, oldest
/// first and with repeats preserved: a repeat contact from an already-charged
/// source is a second entry, not a second charge.
async fn quarantined_sources(holder: &TestActorClient) -> Result<Vec<String>> {
    let row = match account_data_row(holder, AccountDataKey::ACCOUNT_HOLDER_QUARANTINE).await {
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
        .standard_register_client(
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
        .standard_client(
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

/// `ak.vector.invite.new_source_quota_holder_admission.v1` step 7
/// (`consent-model.md` section 6.1 step 2).
///
/// The holder publishes `invite_receive_policy.consent_profile =
/// require_explicit_consent`, the only carrier of that profile. Every contact
/// without verified `consent_grant` evidence is then silently dropped on the
/// holder Station: the quarantine cell stays empty, the quota never charges,
/// and the requester still observes the same opaque `deferred` without a
/// `disclosed_outcome` — the profile itself is not observable.
pub async fn new_source_quota_require_explicit_consent_run() -> Result<()> {
    let case = canonical_admission_case(REQUIRE_EXPLICIT_CONSENT_CASE)?;
    ensure!(
        case.requires_explicit_consent,
        "{}: the canonical case must declare the require_explicit_consent profile",
        case.name
    );
    ensure!(
        case.quarantine_entry_sources.is_empty(),
        "{}: the canonical case must end with an empty quarantine cell",
        case.name
    );
    let server = spawn_under_canonical_ceiling("invite-require-explicit-consent", &case).await?;
    let holder = holder_with_quarantine_policy(&server, "bob-require-explicit-consent").await?;
    set_consent_profile(&holder, ConsentProfile::RequireExplicitConsent).await?;

    let mut peers: BTreeMap<String, TestActorClient> = BTreeMap::new();
    for (index, contact) in case.contacts.iter().enumerate() {
        ensure!(
            contact.expected_decision == NewSourceQuotaDecision::NotEvaluated,
            "{}: contact[{index}] from {} must never reach the quota chokepoint under this profile",
            case.name,
            contact.source
        );
        if !peers.contains_key(&contact.source) {
            let label = format!("alice-require-explicit-consent-{}", contact.source);
            let peer = inviter(&server, &label, 0xe1 + index as u8).await?;
            peers.insert(contact.source.clone(), peer);
        }
        let label = format!("explicit consent contact {index} from {}", contact.source);
        let dispatched =
            create_and_dispatch_explicit_invite(&peers[&contact.source], &holder, &label)
                .await
                .with_context(|| {
                    format!(
                        "dispatch canonical contact[{index}] from {}",
                        contact.source
                    )
                })?;
        assert_opaque_deferred(&dispatched.outcome)?;
        let observed = quarantined_sources(&holder).await?;
        ensure!(
            observed.is_empty(),
            "{}: after contact[{index}] ({}) the quarantine cell is {observed:?}; the require_explicit_consent profile has no quarantine face",
            case.name,
            contact.source
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

/// Publish the holder's consent profile through its only carrier,
/// `invite_receive_policy.consent_profile`, and read it back unchanged.
async fn set_consent_profile(holder: &TestActorClient, profile: ConsentProfile) -> Result<()> {
    let current = expect_json(
        holder.get("/_arkret/self/invite-receive-policy"),
        StatusCode::OK,
    )
    .await?;
    let mut policy: InviteReceivePolicy = serde_json::from_value(current)
        .context("invite-receive-policy response is not an InviteReceivePolicy")?;
    policy.consent_profile = profile;
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
        updated.consent_profile == profile,
        "Station rewrote the holder consent_profile"
    );
    Ok(())
}

/// Pending-review entries of one `surface_kind`, oldest first, as
/// `(source_peer_principal_id, consent_scope)` pairs.
async fn quarantine_entries_of(
    holder: &TestActorClient,
    surface_kind: &str,
) -> Result<Vec<(String, String)>> {
    let row = match account_data_row(holder, AccountDataKey::ACCOUNT_HOLDER_QUARANTINE).await {
        Ok(row) => row,
        Err(_) => return Ok(Vec::new()),
    };
    let entries = row.content["quarantine_entries"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    Ok(entries
        .iter()
        .filter(|entry| entry["surface_kind"] == surface_kind)
        .filter_map(|entry| {
            Some((
                entry["source_peer_principal_id"].as_str()?.to_owned(),
                entry["consent_scope"].as_str()?.to_owned(),
            ))
        })
        .collect())
}

/// Submit `ak.self.consent.command.request.v1` and assert the opaque outcome.
///
/// The response is byte-identical for admission, quota drop, TTL drop, unknown
/// holder and policy deny, so it is asserted as a constant here and every real
/// assertion is taken from the holder's cell.
async fn request_consent(
    requester: &TestActorClient,
    holder: &TestActorClient,
    service_did: &str,
    consent_scope: ConsentRequestScope,
) -> Result<()> {
    let body = ConsentRequestRequestBody {
        holder_account_id: AccountId::new(
            DidCoreId::new(actor_core_id(&holder.actor)?)?,
            DidCoreId::new(actor_core_id(service_did)?)?,
        ),
        consent_scope,
    };
    let outcome = expect_json(
        requester.post("/_arkret/self/consent/request").json(&body),
        StatusCode::OK,
    )
    .await?;
    ensure!(
        outcome == serde_json::json!({ "accepted_for_processing": true }),
        "consent request returned something other than the closed opaque outcome: {outcome}"
    );
    Ok(())
}

/// `ak.vector.invite.quarantine_disclosure_indistinguishable.v1`, the
/// `consent_request` branch.
///
/// `ak.self.consent.command.request.v1` is no longer a shell: a non-invite scope
/// that clears the section 6.1.1 chokepoint writes exactly one entry whose
/// `surface_kind` is `consent_request`, that entry carries neither Event ref nor
/// digest, and a repeat while it is live is a no-op rather than a second entry.
pub async fn consent_request_quarantine_branch_run() -> Result<()> {
    let case = canonical_admission_case(REPLAYABLE_ADMISSION_CASE)?;
    let server = spawn_under_canonical_ceiling("consent-request-quarantine", &case).await?;
    let holder = holder_with_quarantine_policy(&server, "bob-consent-request").await?;
    let requester = inviter(&server, "alice-consent-request", 0xf1).await?;
    let service_did = server.service_did().as_str().to_owned();

    request_consent(
        &requester,
        &holder,
        &service_did,
        ConsentRequestScope::VideoCall,
    )
    .await?;
    let requester_core = actor_core_id(&requester.actor)?;
    ensure!(
        quarantine_entries_of(&holder, "consent_request").await?
            == vec![(requester_core.clone(), "video_call".to_owned())],
        "a consent request that cleared the chokepoint must write exactly one consent_request entry"
    );
    ensure!(
        quarantine_entries_of(&holder, "invite_delivery")
            .await?
            .is_empty(),
        "a consent request must not be recorded as an invite delivery"
    );

    // Section 6.1.1.4, consent_request branch: deduplication is live-entry
    // uniqueness over (account_id, source_peer_principal_id, consent_scope).
    // The operation has no idempotency key and no nonce, so there is nothing
    // else it could dedupe on.
    request_consent(
        &requester,
        &holder,
        &service_did,
        ConsentRequestScope::VideoCall,
    )
    .await?;
    ensure!(
        quarantine_entries_of(&holder, "consent_request")
            .await?
            .len()
            == 1,
        "a repeat request while the entry is live must be a no-op, not a second entry"
    );

    // A different scope is a different live key, so it is a second pending item.
    request_consent(
        &requester,
        &holder,
        &service_did,
        ConsentRequestScope::VoiceCall,
    )
    .await?;
    ensure!(
        quarantine_entries_of(&holder, "consent_request").await?
            == vec![
                (requester_core.clone(), "video_call".to_owned()),
                (requester_core, "voice_call".to_owned()),
            ],
        "a second scope from the same requester is its own live key"
    );

    // The registered body pins the scope away from `invite`: an invite belongs
    // to invite delivery, and this branch has no representation for it. Caller
    // shape rejection is not a holder signal.
    let baseline = ConsentRequestRequestBody {
        holder_account_id: AccountId::new(
            DidCoreId::new(actor_core_id(&holder.actor)?)?,
            DidCoreId::new(actor_core_id(&service_did)?)?,
        ),
        consent_scope: ConsentRequestScope::VoiceCall,
    };
    let invalid_invite_scope = arkret_test_kit::wire_negative_from_sdk(&baseline, |body| {
        body["consent_scope"] = serde_json::json!("invite");
    })?;
    let refused = requester
        .post("/_arkret/self/consent/request")
        .json(&invalid_invite_scope)
        .send()
        .await?;
    ensure!(
        refused.status().is_client_error(),
        "an invite-scope consent request must be refused at the request boundary, got {}",
        refused.status()
    );

    // The cell is the only observable, and the refused request added nothing.
    ensure!(
        quarantine_entries_of(&holder, "consent_request")
            .await?
            .len()
            == 2,
        "a refused invite-scope request must not touch the cell"
    );
    Ok(())
}

/// `contact-and-direct-conversation.md` section 1.1 -- Contact shares the
/// chokepoint, not the carrier.
///
/// The carrier half is asserted live here: a stranger's first Contact request
/// forms the Contact `pending_incoming` head and leaves the holder quarantine
/// cell at zero entries, on either `surface_kind`. Giving Contact a quarantine
/// entry would put a second parallel review carrier in front of the same fact
/// and let it fight the Contact state machine.
///
/// The billing half is live as well: Contact consumes the first slot, an invite
/// consumes the second, and a third source's Contact request is hidden from the
/// holder while its requester-local `pending_outgoing` head remains durable.
pub async fn contact_first_contact_bills_the_shared_quota_run() -> Result<()> {
    let case = canonical_admission_case(REPLAYABLE_ADMISSION_CASE)?;
    let server = spawn_under_canonical_ceiling("contact-shared-quota", &case).await?;
    let holder = holder_with_quarantine_policy(&server, "bob-contact-shared-quota").await?;
    let stranger = inviter(&server, "alice-contact-shared-quota", 0xf5).await?;

    stranger
        .request_contact(&holder.actor)
        .await
        .context("a stranger's first Contact request")?;
    ensure!(
        quarantine_entries_of(&holder, "consent_request")
            .await?
            .is_empty()
            && quarantine_entries_of(&holder, "invite_delivery")
                .await?
                .is_empty(),
        "a Contact request has its own pending_incoming state and MUST NOT get a second parallel review carrier"
    );
    let contacts = expect_json(holder.get("/_arkret/self/contacts"), StatusCode::OK).await?;
    ensure!(
        serde_json::to_string(&contacts)?.contains(&actor_core_id(&stranger.actor)?),
        "the first Contact request must still form the holder's pending_incoming head: {contacts}"
    );

    // An ordinary invite delivery still writes its own branch into the same
    // cell, so the emptiness above is the Contact rule and not a dead cell.
    let inviter_peer = inviter(&server, "alice-contact-shared-quota-invite", 0xf6).await?;
    let dispatched =
        create_and_dispatch_explicit_invite(&inviter_peer, &holder, "contact carrier control")
            .await?;
    assert_opaque_deferred(&dispatched.outcome)?;
    ensure!(
        quarantine_entries_of(&holder, "invite_delivery")
            .await?
            .len()
            == 1
            && quarantine_entries_of(&holder, "consent_request")
                .await?
                .is_empty(),
        "invite delivery writes the invite_delivery branch while Contact writes nothing here"
    );

    // The Contact and invite above exhaust the canonical short-window ceiling.
    // A third source receives the ordinary requester-side outcome and retains
    // its pending_outgoing head, but the holder must not receive a corresponding
    // pending_incoming head.
    let over_quota = inviter(&server, "alice-contact-shared-quota-dropped", 0xf7).await?;
    over_quota
        .request_contact(&holder.actor)
        .await
        .context("an over-quota same-Station Contact request")?;
    let holder_contacts = expect_json(holder.get("/_arkret/self/contacts"), StatusCode::OK).await?;
    ensure!(
        !serde_json::to_string(&holder_contacts)?.contains(&actor_core_id(&over_quota.actor)?),
        "an over-quota Contact request established a holder-visible pending_incoming head: {holder_contacts}"
    );
    let requester_contacts =
        expect_json(over_quota.get("/_arkret/self/contacts"), StatusCode::OK).await?;
    ensure!(
        serde_json::to_string(&requester_contacts)?.contains(&actor_core_id(&holder.actor)?),
        "dropping the holder's pending_incoming head also erased the requester's pending_outgoing head: {requester_contacts}"
    );
    ensure!(
        quarantine_entries_of(&holder, "invite_delivery")
            .await?
            .len()
            == 1,
        "the over-quota Contact request must not create or evict a quarantine entry"
    );
    Ok(())
}
