//! Durable device-revocation gate and client lifecycle conformance.

use std::collections::BTreeSet;

use anyhow::{Context as _, Result, anyhow, bail};
use arkret_wire::{
    AcceptedDevicePossessionProof, AcceptedDevicePossessionProofContext,
    AcceptedDeviceRefreshPossessionPurpose, AccountId, Base64UrlString,
    DEVICE_REVOCATION_DENIED_ACTIONS, DeviceId, DeviceRevocationGateActionClass,
    DeviceRevocationGateCheckOutcome, DeviceRevocationGateCheckRequestBody,
    DeviceRevocationGateDecision, DeviceRevocationGateDecisionReceipt, DidCoreId, DidUrl, EventId,
    Hash, SessionGrantId, UnsignedAcceptedDeviceRefreshPossessionProof,
};
use chrono::{DateTime, Duration, TimeZone as _, Utc};

use super::load_fixture_value;

const FIXTURE: &str = "device-revocation-pending-fixture.json";

const REQUIRED_CASES: [&str; 13] = [
    "first_canonical_acceptance_enters_pending_atomically",
    "unauthorized_proposal_has_zero_private_read_or_write",
    "pending_blocks_closed_action_set_on_every_profile",
    "session_issuer_uses_origin_ps_linearization_receipt",
    "exact_replay_does_not_duplicate_or_extend_pending",
    "multiple_distinct_proposals_are_independent",
    "sealed_and_pending_records_remain_jointly_visible",
    "gate_record_bound_is_closed_without_truncation",
    "gate_receipt_decision_shapes_are_closed",
    "only_exact_rejected_command_outcome_clears_last_pending",
    "overdue_stays_blocked_and_alerts",
    "command_outcome_is_unique_in_confirmed_sequence",
    "seal_makes_revocation_permanent_and_triggers_erasure",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct GenerationMaterial {
    session: bool,
    keypackages: bool,
    to_device: bool,
    recovery: bool,
}

impl GenerationMaterial {
    fn apply_gate(self, decision: DeviceRevocationGateDecision) -> Self {
        match decision {
            DeviceRevocationGateDecision::Revoked => Self {
                session: false,
                keypackages: false,
                to_device: false,
                recovery: self.recovery,
            },
            DeviceRevocationGateDecision::Allow
            | DeviceRevocationGateDecision::RevocationPending
            | DeviceRevocationGateDecision::AuthorityMismatch
            | DeviceRevocationGateDecision::GenerationMismatch => self,
        }
    }
}

pub fn run_device_revocation_pending_suite() -> Result<()> {
    validate_semantic_fixture()?;
    validate_receipt_decision_matrix()?;
    validate_receipt_shape_is_closed_in_both_directions()?;
    validate_exact_request_and_intent_binding()?;
    validate_receipt_freshness_at_issuer_commit()?;
    validate_client_pending_and_revoked_material_lifecycle()
}

fn validate_semantic_fixture() -> Result<()> {
    let fixture = load_fixture_value(FIXTURE)?;
    if fixture["suite"] != "device_revocation_pending_state"
        || fixture["runner"]["kind"] != "named_suite"
        || fixture["runner"]["entrypoint"] != "ak.suite.device.revocation_pending_state.v1"
    {
        bail!("device revocation fixture runner identity drifted");
    }

    let cases = fixture["semantic_cases"]
        .as_array()
        .context("device revocation fixture semantic_cases")?;
    let names = cases
        .iter()
        .map(|case| {
            case["name"]
                .as_str()
                .context("device revocation semantic case name")
        })
        .collect::<Result<BTreeSet<_>>>()?;
    for required in REQUIRED_CASES {
        if !names.contains(required) {
            bail!("device revocation fixture is missing semantic case {required}");
        }
    }
    // This verifies the fixture contract, not the server's classifier wiring.
    let historical = cases
        .iter()
        .find(|case| case["name"] == "historical_eligibility_is_recomputed_from_confirmed_closures")
        .context("device revocation historical eligibility case")?;
    if historical["given"]
        != "the same original Event and verified historical authorization instance"
        || historical["expected"] != "classification_depends_on_exact_closure_membership"
        || historical["classification_cases"]
            != serde_json::json!([
                {
                    "closure_membership": "included_in_all_applicable_closures",
                    "classification": "eligible"
                },
                {
                    "closure_membership": "excluded_by_a_complete_applicable_closure",
                    "classification": "quarantined"
                },
                {
                    "closure_membership": "necessary_frontier_evidence_missing",
                    "classification": "pending"
                }
            ])
    {
        bail!("historical fixture must classify the same Event from exact closure evidence");
    }
    let invariants = historical["invariants"]
        .as_array()
        .context("historical eligibility invariants")?;
    for required in [
        "Event identity and original evidence are unchanged across cases",
        "receiver accepted_at and arrival order do not decide persistent eligibility",
        "historical import does not repeat live side effects",
    ] {
        if !invariants.iter().any(|invariant| invariant == required) {
            bail!("historical eligibility fixture is missing invariant: {required}");
        }
    }

    let blocking = cases
        .iter()
        .find(|case| case["name"] == "pending_blocks_closed_action_set_on_every_profile")
        .context("device revocation five-action case")?;
    let fixture_actions = blocking["denied_actions"]
        .as_array()
        .context("device revocation denied_actions")?;
    let sdk_actions = serde_json::to_value(DEVICE_REVOCATION_DENIED_ACTIONS)?;
    if fixture_actions != sdk_actions.as_array().context("SDK denied action array")? {
        bail!("fixture denied_actions diverge from the SDK canonical five-action set");
    }

    // `device-lifecycle.md` §2.2 closes the receipt in both directions: there is
    // no "verify the proof when one is present, otherwise pass" path, so the
    // fixture contract must state the rejection for a carried proof member and
    // for arrival outside the registered deployment-internal channel.
    let receipt_shapes = cases
        .iter()
        .find(|case| case["name"] == "gate_receipt_decision_shapes_are_closed")
        .context("device revocation gate receipt shape case")?;
    let receipt_invariants = receipt_shapes["invariants"]
        .as_array()
        .context("gate receipt shape invariants")?;
    for required in [
        "a receipt carrying a proof or a verification_method member is rejected",
        "a receipt that did not arrive over the registered deployment-internal authenticated channel is rejected",
    ] {
        if !receipt_invariants
            .iter()
            .any(|invariant| invariant == required)
        {
            bail!("gate receipt fixture is missing closed-channel invariant: {required}");
        }
    }
    Ok(())
}

fn validate_receipt_decision_matrix() -> Result<()> {
    let request = request(DeviceRevocationGateActionClass::SessionGrantIssue, 'a')?;
    for decision in [
        DeviceRevocationGateDecision::Allow,
        DeviceRevocationGateDecision::RevocationPending,
        DeviceRevocationGateDecision::Revoked,
        DeviceRevocationGateDecision::AuthorityMismatch,
        DeviceRevocationGateDecision::GenerationMismatch,
    ] {
        let receipt = channel_receipt(&request, decision, 30)?;
        // The outcome is exactly the closed receipt: authenticity and integrity
        // come from the registered deployment-internal authenticated channel,
        // so there is no signature member left for a consumer to check.
        let outcome = DeviceRevocationGateCheckOutcome {
            decision_receipt: receipt.clone(),
        };
        outcome.validate_for_request(&request)?;

        let has_blocker = receipt.blocking_proposal_digest.is_some();
        let has_seal = receipt.covering_seal_id.is_some();
        match decision {
            DeviceRevocationGateDecision::RevocationPending if has_blocker && !has_seal => {}
            DeviceRevocationGateDecision::Revoked if has_seal && !has_blocker => {}
            DeviceRevocationGateDecision::Allow
            | DeviceRevocationGateDecision::AuthorityMismatch
            | DeviceRevocationGateDecision::GenerationMismatch
                if !has_blocker && !has_seal => {}
            _ => bail!("device revocation receipt accepted an open decision witness branch"),
        }
    }

    let overlong = channel_receipt(&request, DeviceRevocationGateDecision::Allow, 31);
    if overlong.is_ok() {
        bail!("device revocation receipt lifetime exceeded 30 seconds");
    }
    Ok(())
}

/// `device-lifecycle.md` §2.2 / `service-http-binding.md` §2.2.3: the gate
/// receipt is closed in both directions. A `proof` or `verification_method`
/// member rejects the whole receipt — and the whole enclosing outcome — rather
/// than being verified or ignored, so no consumer can grow a "signed receipts
/// are also accepted" branch back.
fn validate_receipt_shape_is_closed_in_both_directions() -> Result<()> {
    let request = request(DeviceRevocationGateActionClass::SessionGrantIssue, 'f')?;
    let receipt = channel_receipt(&request, DeviceRevocationGateDecision::Allow, 30)?;
    let canonical = serde_json::to_value(&receipt)?;
    let round_trip: DeviceRevocationGateDecisionReceipt = serde_json::from_value(canonical.clone())
        .context("the closed channel receipt must round-trip unchanged")?;
    if round_trip != receipt {
        bail!("closed gate receipt did not round-trip to the same value");
    }

    for (member, value) in [
        (
            "proof",
            serde_json::json!({
                "verification_method": "did:web:ps.example#service-key",
                "created_at": "2026-04-12T00:00:00.000Z",
                "jws": "ZXhhbXBsZQ"
            }),
        ),
        (
            "verification_method",
            serde_json::json!("did:web:ps.example#service-key"),
        ),
    ] {
        let mut carried = canonical.clone();
        carried
            .as_object_mut()
            .context("gate receipt object")?
            .insert(member.to_owned(), value);
        if serde_json::from_value::<DeviceRevocationGateDecisionReceipt>(carried.clone()).is_ok() {
            bail!(
                "gate receipt accepted a `{member}` member; the internal-channel receipt shape must reject it outright"
            );
        }
        // Rejection is whole-receipt: a consumer must not strip the forbidden
        // member and keep the decision.
        let outcome = serde_json::json!({ "decision_receipt": carried });
        if serde_json::from_value::<DeviceRevocationGateCheckOutcome>(outcome).is_ok() {
            bail!("gate check outcome accepted a receipt carrying `{member}`");
        }
    }
    Ok(())
}

fn validate_exact_request_and_intent_binding() -> Result<()> {
    let request = request(DeviceRevocationGateActionClass::SessionGrantRefresh, 'b')?;
    let receipt = channel_receipt(&request, DeviceRevocationGateDecision::Allow, 30)?;
    let first = serde_json::to_vec(&receipt)?;
    let replay = serde_json::to_vec(&receipt)?;
    if first != replay {
        bail!("exact gate receipt replay was not byte-identical");
    }

    let mut wrong_intent = request.clone();
    wrong_intent.intent_digest = hash('c')?;
    if receipt.validate_for_request(&wrong_intent).is_ok() {
        bail!("gate receipt validated for a different immutable grant intent");
    }

    let mut wrong_generation = request;
    *wrong_generation
        .expected_device_generation_ref
        .as_mut()
        .context("refresh request generation binding")? += 1;
    if receipt.validate_for_request(&wrong_generation).is_ok() {
        bail!("gate receipt validated for a different device generation");
    }
    Ok(())
}

fn validate_receipt_freshness_at_issuer_commit() -> Result<()> {
    let request = request(DeviceRevocationGateActionClass::SessionGrantIssue, 'd')?;
    let allow = channel_receipt(&request, DeviceRevocationGateDecision::Allow, 30)?;
    if !allows_issuer_commit(
        &allow,
        &request,
        allow.expires_at - Duration::milliseconds(1),
    )? {
        bail!("fresh exact allow receipt did not permit issuer commit");
    }
    if allows_issuer_commit(&allow, &request, allow.expires_at)? {
        bail!("receipt remained usable at its exclusive expiry boundary");
    }

    let pending = channel_receipt(
        &request,
        DeviceRevocationGateDecision::RevocationPending,
        30,
    )?;
    if allows_issuer_commit(&pending, &request, pending.linearized_at)? {
        bail!("revocation_pending receipt permitted an issuer write");
    }
    Ok(())
}

fn validate_client_pending_and_revoked_material_lifecycle() -> Result<()> {
    let material = GenerationMaterial {
        session: true,
        keypackages: true,
        to_device: true,
        recovery: true,
    };
    if material.apply_gate(DeviceRevocationGateDecision::RevocationPending) != material {
        bail!("pending revocation erased client generation material");
    }
    let revoked = material.apply_gate(DeviceRevocationGateDecision::Revoked);
    if revoked.session || revoked.keypackages || revoked.to_device || !revoked.recovery {
        bail!("sealed revocation did not erase only generation-specific client material");
    }
    Ok(())
}

fn allows_issuer_commit(
    receipt: &DeviceRevocationGateDecisionReceipt,
    request: &DeviceRevocationGateCheckRequestBody,
    commit_at: DateTime<Utc>,
) -> Result<bool> {
    receipt.validate_for_request(request)?;
    Ok(receipt.decision == DeviceRevocationGateDecision::Allow && commit_at < receipt.expires_at)
}

fn request(
    action_class: DeviceRevocationGateActionClass,
    intent: char,
) -> Result<DeviceRevocationGateCheckRequestBody> {
    let expected_event_id =
        "ak:event:AfAnsJqSlM9bHVI7P1QBMOEW3p5P1PNQu7BBMpiSnD_e".parse::<EventId>()?;
    let (expected_device_authorize_event_id, expected_device_generation_ref) = if matches!(
        action_class,
        DeviceRevocationGateActionClass::SessionGrantIssue
            | DeviceRevocationGateActionClass::ReturningSessionGrantIssue
    ) {
        (None, None)
    } else {
        (Some(expected_event_id), Some(7))
    };
    let principal_id = DidCoreId::new("ak:did_core:webvh:z6mkfixture")?;
    let account_id = AccountId::new(principal_id, DidCoreId::new("ak:did_core:web:ps.example")?);
    let device_id: DeviceId = "ak:device:0196419b-0000-7000-8000-000000000001".parse()?;
    let intent_digest = hash(intent)?;
    let accepted_device_possession_proof =
        if action_class == DeviceRevocationGateActionClass::SessionGrantRefresh {
            Some(AcceptedDevicePossessionProof::Refresh(
                UnsignedAcceptedDeviceRefreshPossessionProof {
                    context: AcceptedDevicePossessionProofContext::V1,
                    purpose: AcceptedDeviceRefreshPossessionPurpose::SessionGrantRefresh,
                    predecessor_session_grant_id: SessionGrantId::from_issuance_digest(
                        arkret_canonical::sha256_bytes(b"fixture predecessor"),
                    ),
                    account_id: account_id.clone(),
                    device_id: device_id.clone(),
                    audience_id: DidCoreId::new("ak:did_core:web:ps.example")?,
                    holder_jkt: "A".repeat(43),
                    session_intent_digest: intent_digest.clone(),
                    issued_at: at(0)?,
                    expires_at: at(0)? + Duration::minutes(5),
                    verification_method: DidUrl::new("did:webvh:z6mkfixture#device-key-1")
                        .map_err(anyhow::Error::msg)?,
                }
                .attach_signature(
                    Base64UrlString::new(arkret_canonical::base64url_encode([0x5a; 64]))
                        .map_err(anyhow::Error::msg)?,
                )?,
            ))
        } else {
            None
        };
    Ok(DeviceRevocationGateCheckRequestBody {
        account_id,
        device_id,
        expected_device_authorize_event_id,
        expected_device_generation_ref,
        action_class,
        intent_digest,
        accepted_device_possession_proof,
        requested_at: at(0)?,
    })
}

/// Build the receipt exactly as the origin Station hands it to the account's
/// bound Account Authority over the registered deployment-internal
/// authenticated channel: no detached proof and no verification method.
fn channel_receipt(
    request: &DeviceRevocationGateCheckRequestBody,
    decision: DeviceRevocationGateDecision,
    lifetime_seconds: i64,
) -> Result<DeviceRevocationGateDecisionReceipt> {
    let target_event_id =
        "ak:event:AfAnsJqSlM9bHVI7P1QBMOEW3p5P1PNQu7BBMpiSnD_e".parse::<EventId>()?;
    let (target_device_authorize_event_id, target_device_generation_ref) =
        if decision == DeviceRevocationGateDecision::Allow {
            (Some(target_event_id), Some(7))
        } else {
            (None, None)
        };
    let accepted_device_possession_proof_digest = request
        .accepted_device_possession_proof
        .as_ref()
        .map(AcceptedDevicePossessionProof::proof_digest)
        .transpose()?;
    let receipt = DeviceRevocationGateDecisionReceipt {
        account_id: request.account_id.clone(),
        device_id: request.device_id.clone(),
        target_device_authorize_event_id,
        target_device_generation_ref,
        action_class: request.action_class,
        intent_digest: request.intent_digest.clone(),
        accepted_device_possession_proof_digest,
        decision,
        linearization_seq: 9,
        linearized_at: at(1)?,
        expires_at: at(1)? + Duration::seconds(lifetime_seconds),
        blocking_proposal_digest: (decision == DeviceRevocationGateDecision::RevocationPending)
            .then(|| hash('e'))
            .transpose()?,
        covering_seal_id: (decision == DeviceRevocationGateDecision::Revoked)
            .then(|| format!("ak:seal:sha256:{}", "c".repeat(64)).parse())
            .transpose()?,
    };
    receipt.validate()?;
    Ok(receipt)
}

fn hash(byte: char) -> Result<Hash> {
    Hash::new(format!("sha256:{}", byte.to_string().repeat(64))).map_err(Into::into)
}

fn at(seconds: i64) -> Result<DateTime<Utc>> {
    Utc.timestamp_opt(1_776_000_000 + seconds, 0)
        .single()
        .ok_or_else(|| anyhow!("invalid fixture timestamp"))
}
