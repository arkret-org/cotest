//! Durable device-revocation gate and client lifecycle conformance.

use std::collections::BTreeSet;

use anyhow::{Context as _, Result, anyhow, bail};
use arkret_wire::{
    DEVICE_REVOCATION_DENIED_ACTIONS, DeviceRevocationGateActionClass,
    DeviceRevocationGateCheckOutcome, DeviceRevocationGateCheckRequestBody,
    DeviceRevocationGateDecision, DeviceRevocationGateDecisionReceipt, DidCoreId, DidUrl, EventId,
    Hash, PrincipalAuthorityKey, UnsignedDeviceRevocationGateDecisionReceipt,
};
use chrono::{DateTime, Duration, TimeZone as _, Utc};
use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _};

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
    "gate_receipt_decision_shapes_and_proof_are_closed",
    "only_exact_signed_reject_clears_last_pending",
    "overdue_stays_blocked_and_alerts",
    "reject_and_seal_terminal_race_is_serialized",
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
    if !names.contains("historical_admission_is_not_retroactively_invalidated") {
        bail!("device revocation fixture lost the historical admission cutoff case");
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
        let receipt = signed_receipt(&request, decision, 30)?;
        let outcome = DeviceRevocationGateCheckOutcome {
            decision_receipt: receipt.clone(),
        };
        outcome.validate_for_request(&request)?;
        verify_receipt_signature(&receipt)?;

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

    let overlong = signed_receipt(&request, DeviceRevocationGateDecision::Allow, 31);
    if overlong.is_ok() {
        bail!("device revocation receipt lifetime exceeded 30 seconds");
    }
    Ok(())
}

fn validate_exact_request_and_intent_binding() -> Result<()> {
    let request = request(DeviceRevocationGateActionClass::SessionGrantRefresh, 'b')?;
    let receipt = signed_receipt(&request, DeviceRevocationGateDecision::Allow, 30)?;
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
    let allow = signed_receipt(&request, DeviceRevocationGateDecision::Allow, 30)?;
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

    let pending = signed_receipt(
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
    verify_receipt_signature(receipt)?;
    Ok(receipt.decision == DeviceRevocationGateDecision::Allow && commit_at < receipt.expires_at)
}

fn request(
    action_class: DeviceRevocationGateActionClass,
    intent: char,
) -> Result<DeviceRevocationGateCheckRequestBody> {
    let expected_event_id =
        "ak:event:AfAnsJqSlM9bHVI7P1QBMOEW3p5P1PNQu7BBMpiSnD_e".parse::<EventId>()?;
    let (expected_device_authorize_event_id, expected_device_generation_ref) =
        if action_class == DeviceRevocationGateActionClass::SessionGrantIssue {
            (None, None)
        } else {
            (Some(expected_event_id), Some(7))
        };
    Ok(DeviceRevocationGateCheckRequestBody {
        principal_authority: PrincipalAuthorityKey::new(
            DidCoreId::new("ak:did_core:webvh:z6mkfixture")?,
            DidCoreId::new("ak:did_core:web:ps.example")?,
        ),
        device_id: "ak:device:0196419b-0000-7000-8000-000000000001".parse()?,
        expected_device_authorize_event_id,
        expected_device_generation_ref,
        action_class,
        intent_digest: hash(intent)?,
        requested_at: at(0)?,
    })
}

fn signed_receipt(
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
    let unsigned = UnsignedDeviceRevocationGateDecisionReceipt {
        principal_authority: request.principal_authority.clone(),
        device_id: request.device_id.clone(),
        target_device_authorize_event_id,
        target_device_generation_ref,
        action_class: request.action_class,
        intent_digest: request.intent_digest.clone(),
        decision,
        linearization_seq: 9,
        linearized_at: at(1)?,
        expires_at: at(1)? + Duration::seconds(lifetime_seconds),
        blocking_proposal_digest: (decision == DeviceRevocationGateDecision::RevocationPending)
            .then(|| hash('e'))
            .transpose()?,
        covering_seal_id: (decision == DeviceRevocationGateDecision::Revoked)
            .then(|| "ak:seal:AZk4PXzJ6MpkxXnYTUmgXzeIYNd0Wfnz3N0hwLHNV6Xq".parse())
            .transpose()?,
        verification_method: DidUrl::new("did:web:ps.example#service-key")
            .map_err(anyhow::Error::msg)?,
    };
    let metadata = unsigned.proof_metadata()?;
    let signing_bytes = unsigned.proof_signing_bytes(&metadata)?;
    let signature = SigningKey::from_bytes(&[0x42; 32]).sign(&signing_bytes);
    let proof = metadata.finalize(arkret_canonical::base64url_encode(signature.to_bytes()))?;
    unsigned.attach_proof(proof).map_err(Into::into)
}

fn verify_receipt_signature(receipt: &DeviceRevocationGateDecisionReceipt) -> Result<()> {
    receipt.verify_proof_with(|proof, bytes| {
        let encoded = arkret_canonical::base64url_decode(&proof.jws)
            .map_err(|error| arkret_wire::Error::Protocol(error.to_string()))?;
        let signature = Signature::from_slice(&encoded)
            .map_err(|error| arkret_wire::Error::Protocol(error.to_string()))?;
        SigningKey::from_bytes(&[0x42; 32])
            .verifying_key()
            .verify(bytes, &signature)
            .map_err(|_| arkret_wire::Error::Protocol("invalid fixture receipt proof".to_owned()))
    })?;
    Ok(())
}

fn hash(byte: char) -> Result<Hash> {
    Hash::new(format!("sha256:{}", byte.to_string().repeat(64))).map_err(Into::into)
}

fn at(seconds: i64) -> Result<DateTime<Utc>> {
    Utc.timestamp_opt(1_776_000_000 + seconds, 0)
        .single()
        .ok_or_else(|| anyhow!("invalid fixture timestamp"))
}
