//! Exact-device revocation admission conformance against the current in-process SDK contract.

use anyhow::{Result, bail};
use arkret_wire::{
    AccountId, DeviceId, DeviceRevocationAdmissionDecision, DeviceRevocationAdmissionInput,
    DeviceRevocationAdmissionOutcome, DeviceRevocationAdmissionRecord,
    DeviceRevocationDeniedAction, DidCoreId, EventId, Hash, RealmCommitId, SessionGrantAdmission,
    SessionGrantAdmissionBlockReason,
};
use chrono::{DateTime, Duration, TimeZone as _, Utc};

pub fn run_device_revocation_pending_suite() -> Result<()> {
    let request = request()?;
    request.validate()?;
    for decision in [
        DeviceRevocationAdmissionDecision::Allow,
        DeviceRevocationAdmissionDecision::RevocationPending,
        DeviceRevocationAdmissionDecision::Revoked,
        DeviceRevocationAdmissionDecision::AuthorityMismatch,
        DeviceRevocationAdmissionDecision::GenerationMismatch,
    ] {
        let result = result(&request, decision)?;
        result.validate_for_request(&request)?;
        let admitted = result.session_grant_admission(&request, at(1)?)?;
        match (decision, admitted) {
            (
                DeviceRevocationAdmissionDecision::Allow,
                SessionGrantAdmission::Authorized {
                    device_generation_ref: 7,
                    ..
                },
            )
            | (
                DeviceRevocationAdmissionDecision::AuthorityMismatch,
                SessionGrantAdmission::DeviceSetupRequired,
            )
            | (
                DeviceRevocationAdmissionDecision::RevocationPending,
                SessionGrantAdmission::Blocked {
                    reason: SessionGrantAdmissionBlockReason::RevocationPending,
                },
            )
            | (
                DeviceRevocationAdmissionDecision::Revoked,
                SessionGrantAdmission::Blocked {
                    reason: SessionGrantAdmissionBlockReason::Revoked,
                },
            )
            | (
                DeviceRevocationAdmissionDecision::GenerationMismatch,
                SessionGrantAdmission::Blocked {
                    reason: SessionGrantAdmissionBlockReason::GenerationMismatch,
                },
            ) => {}
            _ => bail!("revocation admission decision did not preserve typed issuer control flow"),
        }
        if result.session_grant_admission(&request, at(31)?).is_ok() {
            bail!("expired revocation admission result permitted issuer use");
        }
    }

    let allow = result(&request, DeviceRevocationAdmissionDecision::Allow)?;
    let mut wrong_intent = request.clone();
    wrong_intent.intent_digest = hash('b')?;
    if allow.validate_for_request(&wrong_intent).is_ok() {
        bail!("admission record accepted another immutable intent");
    }
    let mut wrong_generation = request.clone();
    wrong_generation.expected_device_generation_ref = Some(8);
    if allow.validate_for_request(&wrong_generation).is_ok() {
        bail!("allow silently upgraded an expected device generation");
    }
    let mut malformed = allow.admission_record.clone();
    malformed.target_device_authorize_event_id = None;
    if malformed.validate().is_ok() {
        bail!("allow without its exact authorization binding was accepted");
    }
    let mut overlong = allow.admission_record.clone();
    overlong.expires_at += Duration::seconds(1);
    if overlong.validate().is_ok() {
        bail!("admission result exceeded the 30-second freshness bound");
    }
    let mut forged = serde_json::to_value(&allow.admission_record)?;
    forged["proof"] = serde_json::json!({});
    if serde_json::from_value::<DeviceRevocationAdmissionRecord>(forged).is_ok() {
        bail!("Station-local admission record accepted an unknown proof member");
    }
    Ok(())
}

fn request() -> Result<DeviceRevocationAdmissionInput> {
    Ok(DeviceRevocationAdmissionInput {
        account_id: AccountId::new(
            DidCoreId::new("ak:did_core:webvh:z6mkfixture")?,
            DidCoreId::new("ak:did_core:web:ps.example")?,
        ),
        device_id: "ak:device:0196419b-0000-7000-8000-000000000001".parse::<DeviceId>()?,
        expected_device_authorize_event_id: Some(event_id()?),
        expected_device_generation_ref: Some(7),
        action_class: DeviceRevocationDeniedAction::SessionGrantIssueOrRefresh,
        intent_digest: hash('a')?,
        accepted_device_possession_proof: None,
        requested_at: at(0)?,
    })
}

fn result(
    request: &DeviceRevocationAdmissionInput,
    decision: DeviceRevocationAdmissionDecision,
) -> Result<DeviceRevocationAdmissionOutcome> {
    let allowed = decision == DeviceRevocationAdmissionDecision::Allow;
    let revoked = decision == DeviceRevocationAdmissionDecision::Revoked;
    Ok(DeviceRevocationAdmissionOutcome {
        admission_record: DeviceRevocationAdmissionRecord {
            account_id: request.account_id.clone(),
            device_id: request.device_id.clone(),
            target_device_authorize_event_id: allowed.then(event_id).transpose()?,
            target_device_generation_ref: allowed.then_some(7),
            action_class: request.action_class,
            intent_digest: request.intent_digest.clone(),
            accepted_device_possession_proof_digest: None,
            decision,
            linearization_seq: 9,
            linearized_at: at(1)?,
            expires_at: at(1)? + Duration::seconds(30),
            accepted_commit_id: revoked.then(|| RealmCommitId::from_digest([9_u8; 32])),
        },
    })
}

fn event_id() -> Result<EventId> {
    Ok("ak:event:AfAnsJqSlM9bHVI7P1QBMOEW3p5P1PNQu7BBMpiSnD_e".parse()?)
}

fn hash(byte: char) -> Result<Hash> {
    Ok(Hash::new(format!(
        "sha256:{}",
        byte.to_string().repeat(64)
    ))?)
}

fn at(seconds: i64) -> Result<DateTime<Utc>> {
    Ok(Utc
        .timestamp_opt(1_776_000_000 + seconds, 0)
        .single()
        .ok_or_else(|| anyhow::anyhow!("invalid timestamp"))?)
}
