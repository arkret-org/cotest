//! Real account-auth recovery, accepted native units and issuer generation fences.
use anyhow::{Context, Result, ensure};
use arkret_models_collaboration::events_payloads::{
    DeviceAuthorizationBindingKind, DeviceAuthorizePayload, DeviceOrPrincipalRef,
    DeviceReanchorPayload, SignatureMaterial, device_authorize_payload_digest,
};
use arkret_models_crypto::*;
use arkret_wire::*;
use chrono::Utc;
use ed25519_dalek::Signer as _;

use crate::harness::{
    CanonicalJsonBody as _, TestActorClient, event_envelope_for_device, expect_json,
};
use crate::scenarios::_helpers::canonical_api::CanonicalApiFixture;
use crate::scenarios::security_rotation_live::{
    RotationAuthor, create_verified_recovery_unlock_session_bound,
};

fn base64url(value: impl Into<String>) -> Result<Base64UrlString> {
    Base64UrlString::new(value).map_err(anyhow::Error::msg)
}
fn nonempty(value: impl Into<String>) -> Result<NonEmptyString> {
    NonEmptyString::new(value).map_err(anyhow::Error::msg)
}
fn verification_method(value: impl Into<String>) -> Result<DidUrl> {
    DidUrl::new(value).map_err(anyhow::Error::msg)
}
fn sign(key: &ed25519_dalek::SigningKey, bytes: &[u8]) -> Result<Base64UrlString> {
    base64url(arkret_canonical::base64url_encode(
        key.sign(bytes).to_bytes(),
    ))
}
fn unique(prefix: &str) -> String {
    arkret_identifiers::new_prefixed_uuid7(prefix)
}

pub(crate) struct CompletedCandidate {
    pub(crate) candidate: TestActorClient,
    gate: arkret_http_client::Client,
    pub(crate) request: arkret_models_identity::RecoveryCompletionGrantRequestBody,
    pub(crate) completion: RecoveryTransactionCompletion,
    pub(crate) handoff: cotest_test_support::provisioning::AccountHandoff,
}

pub(crate) struct PreparedCandidate {
    pub(crate) candidate: TestActorClient,
    gate: arkret_http_client::Client,
    pub(crate) create: RecoveryTransactionCreateRequestBody,
    initial: arkret_models_identity::InitialSessionGrantIntent,
    handoff: cotest_test_support::provisioning::AccountHandoff,
}

pub(crate) async fn complete_native(
    fixture: &CanonicalApiFixture,
    recovery_method: &DidUrl,
    recovery_seed: [u8; 32],
) -> Result<CompletedCandidate> {
    prepare_native(fixture, recovery_method, recovery_seed)
        .await?
        .submit_native()
        .await
}

/// Freeze the actual verified Session and signed R before its single native POST.
/// Fault tests use this same production request, without manufacturing accepted C.
pub(crate) async fn prepare_native(
    fixture: &CanonicalApiFixture,
    recovery_method: &DidUrl,
    recovery_seed: [u8; 32],
) -> Result<PreparedCandidate> {
    let (candidate, gate, initial, handoff, grant_ref) = fixture.recovery_candidate().await?;
    let custody = candidate.principal.as_ref().context("candidate custody")?;
    let author = RotationAuthor::from_client(&candidate)?;
    let session = create_verified_recovery_unlock_session_bound(
        &candidate,
        &author,
        recovery_method,
        recovery_seed,
        custody.device_signing_key.to_bytes(),
        (
            grant_ref,
            base64url(initial.session_public_key.thumbprint_sha256()?)?,
        ),
        crate::scenarios::_helpers::coauth_bootstrap::JOINT_TRUST_DOMAIN.parse()?,
    )
    .await?;
    let session: RecoverySession = serde_json::from_value(
        expect_json(
            candidate.get(&format!(
                "/_arkret/root/identity/recovery-sessions/{}",
                session.recovery_session_id
            )),
            reqwest::StatusCode::OK,
        )
        .await?,
    )?;
    ensure!(
        session.state == RecoverySessionState::Verified,
        "real recovery factor did not verify"
    );
    let now = arkret_canonical::normalize_timestamp_canonical(Utc::now());
    let next = session
        .current_device_generation_ref
        .checked_add(1)
        .context("generation overflow")?;
    let hpke = arkret_crypto::identity_root::derive_identity_recovery_key_material(
        &custody.device_signing_key.to_bytes(),
        0,
    )?;
    let mut authorize = DeviceAuthorizePayload {
        expected_control_commit_id: None,
        expected_device_commit_id: None,
        device_id: custody.device_id.clone(),
        device_public_key_did: nonempty(format!(
            "did:key:{}",
            arkret_canonical::ed25519_pubkey_to_did_key_multibase(
                custody.device_signing_key.verifying_key().as_bytes()
            )
        ))?,
        hpke_key: nonempty(hpke.backup_hpke_public_key_multikey.clone())?,
        algorithms: vec![
            nonempty("Ed25519")?,
            nonempty("HPKE-X25519-HKDF-SHA256-AES128GCM")?,
        ],
        device_key_algorithm: nonempty("Ed25519")?,
        authorized_by: DeviceOrPrincipalRef::Principal(session.account_id.principal_id.clone()),
        scopes: None,
        not_before: now,
        expires_at: None,
        authorization_binding_kind: DeviceAuthorizationBindingKind::PcrRecovery,
        authorized_generation_ref: next,
        device_signature: SignatureMaterial::NonEmptyString(nonempty("AA")?),
        recovery_session_id: Some(session.recovery_session_id.clone()),
        pairing_challenge_transcript_digest: None,
        applet_id: None,
    };
    authorize.device_signature = SignatureMaterial::NonEmptyString(nonempty(
        sign(
            &custody.device_signing_key,
            &authorize.device_possession_signature_input(&session.account_id)?,
        )?
        .as_str(),
    )?);
    let reanchor = DeviceReanchorPayload {
        account_id: session.account_id.clone(),
        recovery_authority_kind: RecoveryAuthorityKind::PcrPolicy,
        recovery_policy_id: session.policy_id.clone(),
        recovery_policy_version: session.policy_version,
        recovery_session_id: session.recovery_session_id.clone(),
        previous_device_generation: session.current_device_generation_ref,
        new_device_generation: next,
        did_root_evidence_digest: None,
        replacement_authorize_payload_digest: device_authorize_payload_digest(
            &serde_json::to_value(&authorize)?,
            arkret_canonical::DigestSuite::Sha256,
        )?,
    };
    let events = [
        event_envelope_for_device(
            custody.did.as_str(),
            custody.device_id.as_str(),
            &session.account_id.station_id,
            custody.pcr_realm_id.as_str(),
            EventKind::DeviceReanchor.as_str(),
            serde_json::to_value(reanchor)?,
        ),
        event_envelope_for_device(
            custody.did.as_str(),
            custody.device_id.as_str(),
            &session.account_id.station_id,
            custody.pcr_realm_id.as_str(),
            EventKind::DeviceAuthorize.as_str(),
            serde_json::to_value(authorize)?,
        ),
    ];
    let proof = session
        .proof_summary
        .as_ref()
        .context("verified recovery proof absent")?;
    let method = verification_method(format!("{}#{}", custody.did, custody.device_id))?;
    let mut receipt = RecoveryReceipt {
        schema: SchemaId::RECOVERY_RECEIPT_V1.to_owned(),
        receipt_id: unique("ak:receipt:").parse()?,
        transaction_id: unique("ak:transaction:").parse()?,
        account_id: session.account_id.clone(),
        expires_at: session.expires_at,
        recovery_session_id: session.recovery_session_id.clone(),
        session_grant_ref: session.session_grant_ref.clone(),
        session_grant_cnf_jkt: session.session_grant_cnf_jkt.clone(),
        policy_id: session.policy_id.clone(),
        policy_version: session.policy_version,
        trust_domain: session.trust_domain.clone(),
        new_device_id: custody.device_id.clone(),
        identity_model: RecoveryIdentityModel::PcrPolicy,
        recovery_authority_kind: RecoveryAuthorityKind::PcrPolicy,
        previous_model_generation_ref: session.current_device_generation_ref,
        new_model_generation_ref: next,
        proof_summary: RecoveryProofSummary {
            kind: proof.kind,
            proof_digest: proof.proof_digest.clone(),
            quorum_participant_count: None,
        },
        recovery_unit: RecoveryUnit {
            predecessor_ref: session.realm_stream_head.commit_id.clone(),
            events: events.map(EventAdmissionSubmission::new),
        },
        unlocked_backups: Vec::new(),
        welcome_count: 0,
        welcome_realm_summaries: None,
        outcome: RecoveryReceiptOutcome::Completed,
        outcome_reason_code: None,
        started_at: session.created_at,
        completed_at: arkret_canonical::normalize_timestamp_canonical(Utc::now()),
        signature_proof: RecoveryReceiptSignatureProof {
            verification_method: method.clone(),
            signature_algorithm: "Ed25519".into(),
            signature: base64url("A".repeat(86))?,
        },
    };
    receipt.validate_for_session(&session, receipt.completed_at)?;
    receipt.signature_proof.signature = sign(
        &custody.device_signing_key,
        &receipt.signature_transcript_bytes()?,
    )?;
    let create = RecoveryTransactionCreateRequestBody::new(receipt)?;
    Ok(PreparedCandidate {
        candidate,
        gate,
        create,
        initial,
        handoff,
    })
}

impl PreparedCandidate {
    pub(crate) async fn submit_native(self) -> Result<CompletedCandidate> {
        let body = SecurityTransactionCreateRequestBody::Recovery(self.create.clone());
        let candidate = &self.candidate;
        let create = &self.create;
        let completion: RecoveryTransactionCompletion = serde_json::from_value(
            expect_json(
                candidate
                    .post("/_arkret/self/security-transactions")
                    .canonical_json(&body)?,
                reqwest::StatusCode::OK,
            )
            .await?,
        )?;
        completion.validate_for_request(create)?;
        let replay: RecoveryTransactionCompletion = serde_json::from_value(
            expect_json(
                candidate
                    .post("/_arkret/self/security-transactions")
                    .canonical_json(&body)?,
                reqwest::StatusCode::OK,
            )
            .await?,
        )?;
        ensure!(
            completion == replay,
            "single-submit Recovery response-loss replay changed its native closure"
        );
        self.finish(completion)
    }

    pub(crate) fn finish(
        self,
        completion: RecoveryTransactionCompletion,
    ) -> Result<CompletedCandidate> {
        completion.validate_for_request(&self.create)?;
        let Self {
            candidate,
            gate,
            create,
            initial,
            handoff,
        } = self;
        let receipt = create.recovery_receipt;
        let custody = candidate.principal.as_ref().context("candidate custody")?;
        let method = verification_method(format!("{}#{}", custody.did, custody.device_id))?;
        // The ordinary client sends only frozen R to AA. C is carried from the
        // original Station to AA by the existing authenticated server channel.
        let proof_at = arkret_canonical::normalize_timestamp_canonical(Utc::now());
        let handoff_expires =
            chrono::DateTime::parse_from_rfc3339(&handoff.expires_at)?.with_timezone(&Utc);
        let mut possession = AcceptedDeviceIssuePossessionProof {
            context: AcceptedDevicePossessionProofContext::V1,
            purpose: AcceptedDeviceIssuePossessionPurpose::RecoveryCompletionGrantIssue,
            request_id: unique("ak:request:").parse()?,
            account_subject: handoff.account_subject.clone(),
            account_handoff_grant_digest: Hash::new(arkret_canonical::sha256_digest(
                handoff.account_handoff_grant.as_bytes(),
            ))?,
            account_id: receipt.account_id.clone(),
            device_id: custody.device_id.clone(),
            audience_id: initial.audience_id.clone(),
            holder_jkt: initial.session_public_key.thumbprint_sha256()?,
            session_intent_digest:
                arkret_models_identity::RecoveryCompletionGrantRequestBody::session_intent_digest(
                    &receipt, &initial,
                )?,
            issued_at: proof_at,
            expires_at: (proof_at + chrono::Duration::seconds(300)).min(handoff_expires),
            verification_method: method,
            signature: base64url("A".repeat(86))?,
        };
        possession.signature = sign(
            &custody.device_signing_key,
            &possession.canonical_signing_bytes()?,
        )?;
        let request = arkret_models_identity::RecoveryCompletionGrantRequestBody::new(
            receipt, initial, possession,
        )?;
        Ok(CompletedCandidate {
            candidate,
            gate,
            request,
            completion,
            handoff,
        })
    }
}

pub(crate) struct RecoveryAuthority {
    pub(crate) method: DidUrl,
    pub(crate) seed: [u8; 32],
    pub(crate) policy_event: Event,
}

pub(crate) async fn prepare_recovery_authority(
    founding: &TestActorClient,
) -> Result<RecoveryAuthority> {
    prepare_recovery_authority_with_trusted_service(founding, None).await
}

pub(crate) async fn prepare_recovery_authority_with_trusted_service(
    founding: &TestActorClient,
    service: Option<TrustedRecoveryServiceEntry>,
) -> Result<RecoveryAuthority> {
    let author = RotationAuthor::from_client(founding)?;
    let custody = founding.principal.as_ref().context("founding custody")?;
    let method = verification_method(format!("{}#offline-recovery", custody.did))?;
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).context("obtain recovery authority OS entropy")?;
    let event = author.recovery_unlock_policy(&unique("ak:policy:"), &method, seed)?;
    let mut policy: RecoveryPolicy = serde_json::from_value(event.payload["value"].clone())?;
    policy.trust_domain =
        crate::scenarios::_helpers::coauth_bootstrap::JOINT_TRUST_DOMAIN.parse()?;
    let backup = arkret_crypto::identity_root::derive_identity_recovery_key_material(&seed, 0)?;
    let Some(RecoveryMethod::RecoveryUnlock { keys }) = policy.methods.first_mut() else {
        anyhow::bail!("missing recovery key")
    };
    keys[0].backup_hpke.public_key_multibase = backup.backup_hpke_public_key_multikey.clone();
    if let Some(service) = service {
        policy.methods.push(RecoveryMethod::TrustedRecoveryService {
            services: vec![service],
        });
    }
    policy.signature_proof.signature = sign(
        &custody.device_signing_key,
        &recovery_policy_signature_transcript_bytes(&policy)?,
    )?;
    let event = founding
        .author_event(
            custody.pcr_realm_id.as_str(),
            EventKind::PolicySet.as_str(),
            serde_json::json!({"policy_id":policy.policy_id,"value":policy}),
        )
        .await?;
    let response =
        crate::scenarios::security_rotation_live::publish_recovery_policy(founding, &event).await?;
    ensure!(
        response.status().is_success(),
        "real recovery policy publication failed: {} {}",
        response.status(),
        response.text().await?
    );
    Ok(RecoveryAuthority {
        method,
        seed,
        policy_event: event,
    })
}

pub(super) async fn verify_recovery_generation_boundary(
    fixture: &CanonicalApiFixture,
    authority: &RecoveryAuthority,
) -> Result<()> {
    let custody = fixture
        .client
        .principal
        .as_ref()
        .context("original custody")?;
    // The first accepted completion is held before issuance. A second real
    // recovery advances the native generation, so no replay record can mask
    // whether the issuer checked the first replacement's current binding.
    let stale = complete_native(fixture, &authority.method, authority.seed).await?;
    let current = complete_native(fixture, &authority.method, authority.seed).await?;
    ensure!(
        stale
            .request
            .terminal_receipt
            .new_model_generation_ref
            .checked_add(1)
            == Some(current.request.terminal_receipt.new_model_generation_ref)
            && stale
                .completion
                .completion_attestation
                .device_authorization_event_ref
                .event_id
                != current
                    .completion
                    .completion_attestation
                    .device_authorization_event_ref
                    .event_id,
        "two native recoveries did not accept distinct consecutive generations"
    );
    let refused = super::require_device_denial(
        stale
            .gate
            .issue_recovery_completion_grant(&stale.request)
            .await
            .map_err(anyhow::Error::from),
        "recovery-completion",
    )?;
    ensure!(
        matches!(
            refused.as_str(),
            "device_revoked" | "device_revocation_pending" | "device_generation_fenced"
        ),
        "stale recovery completion did not reach its real current-device/generation fence: {refused}"
    );
    let accepted = current
        .gate
        .issue_recovery_completion_grant(&current.request)
        .await?;
    let grant = accepted.issued_session;
    grant.validate_binding(
        &current.request.terminal_receipt.session_grant_ref.issuer_id,
        &current.request.terminal_receipt.account_id,
        &current.request.initial_session.audience_id,
        &current.request.initial_session.session_public_key,
        chrono::Utc::now(),
    )?;
    ensure!(
        grant.account_id == current.request.terminal_receipt.account_id
            && grant.device_id.as_ref() == Some(&current.request.terminal_receipt.new_device_id)
            && grant.issuer_id == current.request.terminal_receipt.session_grant_ref.issuer_id,
        "completion changed the full Account, issuer or accepted replacement Device"
    );
    garth::SessionGrantState::from_initial_registration_outcome(
        &current.request.initial_session,
        grant.clone(),
        accepted.issued_at,
    )?;
    let mut accepted_principal = current
        .candidate
        .principal
        .clone()
        .context("replacement custody")?;
    accepted_principal.founding_authorize_event_id = current
        .completion
        .completion_attestation
        .device_authorization_event_ref
        .event_id
        .clone();
    let client = fixture.server.actor_client(
        current.candidate.principal.as_ref().unwrap().did.as_str(),
        current
            .candidate
            .principal
            .as_ref()
            .unwrap()
            .device_id
            .as_str(),
        match current.candidate.session() {
            crate::harness::ClientSession::Canonical { signing_key, .. } => {
                crate::harness::ClientSession::Canonical {
                    grant: grant.session_grant.as_str().to_owned(),
                    signing_key: signing_key.clone(),
                }
            }
            _ => anyhow::bail!("recovery used a development bearer"),
        },
        Some(accepted_principal),
    )?;
    let projection = client
        .sdk()
        .current_principal(&arkret_models_identity::CurrentPrincipalRequestBody {
            request_id: unique("ak:request:").parse()?,
            account_id: current.completion.completion_attestation.account_id.clone(),
        })
        .await?;
    ensure!(
        projection.principal_control_realm_id == custody.pcr_realm_id,
        "recovery replaced the PCR lineage"
    );
    let original = crate::scenarios::mls_lifecycle_live::accepted_full_view(
        &client,
        &current
            .completion
            .completion_attestation
            .device_authorization_event_ref
            .event_id,
    )
    .await?;
    ensure!(
        original.commit.governance_generation == 0
            && original.commit.realm_id == custody.pcr_realm_id,
        "native recovery changed Human PCR tenure or lost its accepted history"
    );
    println!(
        "[2343-coauth-recovery] actual_restricted_grants=2 accepted_recovery_units=2 stale_completion_denied=1 current_completion_standard=1 account_station_preserved=1"
    );
    Ok(())
}
