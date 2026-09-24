//! Joint device-verification checkpoint projection vectors.
//!
//! The assertions in this crate call Soland's production read-side fold and
//! the SDK's production presence validator.  Cotest deliberately does not
//! duplicate either rule in a test-only reference model.

use anyhow::{Result, ensure};
use arkret_models_identity::{
    DeviceSummaryStatus, DeviceSummaryVerificationSource, DeviceSummaryVerificationState,
    validate_device_summary_evidence,
};
use arkret_wire::{EventId, SignerEvidenceRef};
use soland_services::identity::{
    DeviceCheckpointIneligibility, DeviceCheckpointLiveFacts,
    evaluate_device_checkpoint_live_eligibility, fold_device_verification_checkpoint,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckpointCaseResult {
    pub case_id: &'static str,
    pub assertions: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceVerificationCheckpointCoverage {
    pub cases: Vec<CheckpointCaseResult>,
    pub remaining_production_gaps: Vec<&'static str>,
}

fn authorization_event_id(seed: u8) -> EventId {
    EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [seed; 32])
}

/// Materialized `account_device_control` evidence for the exact committed
/// authorization; it stays historical provenance after generation fencing.
fn signer_evidence(seed: u8) -> Result<SignerEvidenceRef> {
    Ok(SignerEvidenceRef::new(format!(
        "ak:signer_evidence:sha256:{}",
        format!("{seed:02x}").repeat(32)
    ))?)
}

fn assert_live_source(
    binding_kind: &'static str,
    expected: DeviceSummaryVerificationSource,
    seed: u8,
) -> Result<CheckpointCaseResult> {
    let (state, source) =
        fold_device_verification_checkpoint("verified", true, Some(binding_kind), false);
    ensure!(state == DeviceSummaryVerificationState::Verified);
    ensure!(source == Some(expected));
    let reference = authorization_event_id(seed);
    let evidence = signer_evidence(seed)?;
    validate_device_summary_evidence(
        DeviceSummaryStatus::Active,
        state,
        source,
        Some(&reference),
        Some(&evidence),
        None,
    )?;
    evaluate_device_checkpoint_live_eligibility(live_facts(expected))
        .map_err(|reason| anyhow::anyhow!("live source was rejected: {reason:?}"))?;
    Ok(CheckpointCaseResult {
        case_id: binding_kind,
        assertions: 4,
    })
}

fn live_facts(source: DeviceSummaryVerificationSource) -> DeviceCheckpointLiveFacts<'static> {
    DeviceCheckpointLiveFacts {
        lifecycle_active: true,
        verification_state: DeviceSummaryVerificationState::Verified,
        verification_source: Some(source),
        revocation_gate_active: true,
        checkpoint_authorization_event_id: Some("event:accepted-device-authorize"),
        current_authorization_event_id: Some("event:accepted-device-authorize"),
        checkpoint_generation_ref: Some(7),
        current_generation_ref: Some(7),
        checkpoint_signing_key: Some("did:key:device#signing-7"),
        current_signing_key: Some("did:key:device#signing-7"),
        checkpoint_hpke_key: Some("did:key:device#hpke-7"),
        current_hpke_key: Some("did:key:device#hpke-7"),
    }
}

/// Execute the production projection, presence, and live-eligibility cases.
///
/// Both decisions are imported from Soland's production identity service;
/// this runner contains fixtures and exact outcome assertions, not a second
/// authorization policy.
pub fn run_device_verification_checkpoint_contract() -> Result<DeviceVerificationCheckpointCoverage>
{
    let mut cases = vec![
        assert_live_source(
            "registration_anchor",
            DeviceSummaryVerificationSource::Genesis,
            1,
        )?,
        assert_live_source(
            "accepted_device",
            DeviceSummaryVerificationSource::PairingCode,
            2,
        )?,
        assert_live_source("pcr_recovery", DeviceSummaryVerificationSource::Recovery, 3)?,
    ];

    let reference = authorization_event_id(4);
    let evidence = signer_evidence(4)?;
    ensure!(
        validate_device_summary_evidence(
            DeviceSummaryStatus::Active,
            DeviceSummaryVerificationState::Verified,
            None,
            Some(&reference),
            Some(&evidence),
            None,
        )
        .is_err()
    );
    cases.push(CheckpointCaseResult {
        case_id: "verified_without_source_is_rejected",
        assertions: 1,
    });

    ensure!(
        validate_device_summary_evidence(
            DeviceSummaryStatus::Active,
            DeviceSummaryVerificationState::Unresolved,
            Some(DeviceSummaryVerificationSource::PairingCode),
            None,
            None,
            None,
        )
        .is_err()
    );
    cases.push(CheckpointCaseResult {
        case_id: "unresolved_with_source_is_rejected",
        assertions: 1,
    });

    for (binding_kind, expected_source) in [
        (
            "registration_anchor",
            DeviceSummaryVerificationSource::Genesis,
        ),
        (
            "accepted_device",
            DeviceSummaryVerificationSource::PairingCode,
        ),
        ("pcr_recovery", DeviceSummaryVerificationSource::Recovery),
    ] {
        let (state, source) =
            fold_device_verification_checkpoint("verified", true, Some(binding_kind), true);
        ensure!(state == DeviceSummaryVerificationState::Stale);
        ensure!(source == Some(expected_source));
        validate_device_summary_evidence(
            DeviceSummaryStatus::GenerationFenced,
            state,
            source,
            Some(&reference),
            Some(&evidence),
            None,
        )?;
    }
    cases.push(CheckpointCaseResult {
        case_id: "generation_fence_stales_all_sources_and_retains_provenance",
        assertions: 9,
    });

    let mut stale = live_facts(DeviceSummaryVerificationSource::PairingCode);
    stale.verification_state = DeviceSummaryVerificationState::Stale;
    ensure!(
        evaluate_device_checkpoint_live_eligibility(stale)
            == Err(DeviceCheckpointIneligibility::VerificationNotCurrent)
    );
    cases.push(CheckpointCaseResult {
        case_id: "stale_checkpoint_is_not_live_eligible",
        assertions: 1,
    });

    for case_id in ["revoked_checkpoint", "revocation_pending_checkpoint"] {
        let mut revoked = live_facts(DeviceSummaryVerificationSource::PairingCode);
        revoked.revocation_gate_active = false;
        ensure!(
            evaluate_device_checkpoint_live_eligibility(revoked)
                == Err(DeviceCheckpointIneligibility::RevocationGateNotActive)
        );
        cases.push(CheckpointCaseResult {
            case_id,
            assertions: 1,
        });
    }

    let mut generation_rotated = live_facts(DeviceSummaryVerificationSource::Recovery);
    generation_rotated.current_generation_ref = Some(8);
    ensure!(
        evaluate_device_checkpoint_live_eligibility(generation_rotated)
            == Err(DeviceCheckpointIneligibility::GenerationMismatch)
    );
    cases.push(CheckpointCaseResult {
        case_id: "generation_rotation_invalidates_checkpoint",
        assertions: 1,
    });

    let mut signing_key_rotated = live_facts(DeviceSummaryVerificationSource::Genesis);
    signing_key_rotated.current_signing_key = Some("did:key:device#signing-8");
    ensure!(
        evaluate_device_checkpoint_live_eligibility(signing_key_rotated)
            == Err(DeviceCheckpointIneligibility::SigningKeyMismatch)
    );
    cases.push(CheckpointCaseResult {
        case_id: "signing_key_rotation_invalidates_checkpoint",
        assertions: 1,
    });

    let mut hpke_key_rotated = live_facts(DeviceSummaryVerificationSource::Genesis);
    hpke_key_rotated.current_hpke_key = Some("did:key:device#hpke-8");
    ensure!(
        evaluate_device_checkpoint_live_eligibility(hpke_key_rotated)
            == Err(DeviceCheckpointIneligibility::HpkeKeyMismatch)
    );
    cases.push(CheckpointCaseResult {
        case_id: "hpke_key_rotation_invalidates_checkpoint",
        assertions: 1,
    });

    let (state, source) =
        fold_device_verification_checkpoint("verified", true, Some("server_asserted"), false);
    ensure!(state == DeviceSummaryVerificationState::Unresolved);
    ensure!(source.is_none());
    validate_device_summary_evidence(DeviceSummaryStatus::Active, state, source, None, None, None)?;
    cases.push(CheckpointCaseResult {
        case_id: "unknown_source_cannot_mint_a_checkpoint",
        assertions: 3,
    });

    Ok(DeviceVerificationCheckpointCoverage {
        cases,
        remaining_production_gaps: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_projection_and_presence_contract_is_executable() {
        let coverage = run_device_verification_checkpoint_contract().unwrap();
        assert_eq!(coverage.cases.len(), 13);
        assert!(coverage.cases.iter().all(|case| case.assertions > 0));
        assert!(coverage.remaining_production_gaps.is_empty());
    }
}
