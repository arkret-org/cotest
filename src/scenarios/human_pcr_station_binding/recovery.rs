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

use crate::harness::{TestActorClient, event_envelope_for_device, expect_json};
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

struct CompletedCandidate {
    candidate: TestActorClient,
    gate: arkret_http_client::Client,
    request: RecoveryCompletionGrantRequestBody,
}

async fn complete_native(
    fixture: &CanonicalApiFixture,
    recovery_method: &DidUrl,
    recovery_seed: [u8; 32],
) -> Result<CompletedCandidate> {
    let (candidate, gate, initial) = fixture.recovery_candidate().await?;
    let custody = candidate.principal.as_ref().context("candidate custody")?;
    let encoded = candidate
        .session()
        .credential()
        .split('.')
        .nth(1)
        .context("restricted claims")?;
    let claims: arkret_models_identity::SignedSessionGrantClaims =
        serde_json::from_slice(&arkret_canonical::base64url_decode(encoded)?)?;
    ensure!(
        claims.credential_class
            == arkret_models_identity::SessionGrantCredentialClass::RecoverySession,
        "issuer did not return a restricted grant"
    );
    let author = RotationAuthor::from_client(&candidate)?;
    let session = create_verified_recovery_unlock_session_bound(
        &candidate,
        &author,
        recovery_method,
        recovery_seed,
        custody.device_signing_key.to_bytes(),
        (
            claims.grant_id,
            base64url(claims.session_public_key.thumbprint_sha256()?)?,
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
        expected_control_revision: None,
        expected_device_revision: None,
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
    let intent = PcrPolicyRecoveryIntent {
        recovery_session_id: session.recovery_session_id.clone(),
        replacement_device_id: custody.device_id.clone(),
        previous_model_generation_ref: session.current_device_generation_ref,
        new_model_generation_ref: next,
        terminal_receipt_id: unique("ak:receipt:").parse()?,
        reanchor_commit_intent: RecoveryCommitIntent {
            realm_id: custody.pcr_realm_id.clone(),
            predecessor_ref: session.realm_stream_head.commit_id.clone(),
            unit_event_digests: [
                Hash::new(
                    events[0]
                        .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)?,
                )?,
                Hash::new(
                    events[1]
                        .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)?,
                )?,
            ],
        },
        reanchor_unit: PreparedEventUnit::new(
            arkret_canonical::DigestSuite::Sha256,
            EventsSubmitBatchRequestBody {
                events: events
                    .into_iter()
                    .map(EventAdmissionSubmission::new)
                    .collect(),
            },
        )?,
    };
    let request = RecoveryTransactionCreateRequestBody::new(
        unique("ak:transaction:").parse()?,
        session.account_id.clone(),
        session.expires_at,
        intent,
    )?;
    let mut transaction = crate::scenarios::security_rotation_live::create(
        &candidate,
        &SecurityTransactionCreateRequestBody::Recovery(request),
    )
    .await?;
    let SecurityTransactionPreparedPlan::Recovery(plan) = &transaction.prepared_plan else {
        anyhow::bail!("wrong native recovery plan")
    };
    let method = verification_method(format!("{}#{}", custody.did, custody.device_id))?;
    let mut receipt = RecoveryReceipt {
        schema: SchemaId::RECOVERY_RECEIPT_V1.to_owned(),
        receipt_id: plan.binding.terminal_receipt_id.clone(),
        transaction_id: transaction.transaction_id.clone(),
        transaction_request_digest: transaction.request_digest.clone(),
        prepared_plan_digest: transaction.prepared_plan_digest.clone(),
        account_id: session.account_id.clone(),
        recovery_session_id: session.recovery_session_id.clone(),
        policy_id: session.policy_id,
        policy_version: session.policy_version,
        trust_domain: session.trust_domain,
        new_device_id: custody.device_id.clone(),
        identity_model: RecoveryIdentityModel::PcrPolicy,
        recovery_authority_kind: RecoveryAuthorityKind::PcrPolicy,
        previous_model_generation_ref: plan.previous_model_generation_ref,
        new_model_generation_ref: plan.new_model_generation_ref,
        authorization_event_id: plan.binding.authorize_event_id.clone(),
        reanchor_event_id: plan.binding.reanchor_event_id.clone(),
        proof_summary: RecoveryProofSummary {
            kind: RecoveryProofKind::RecoveryUnlock,
            proof_digest: plan.proof_digest.clone(),
            quorum_participant_count: None,
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
            signature: base64url("AA")?,
        },
        extra: Default::default(),
    };
    receipt.signature_proof.signature = sign(
        &custody.device_signing_key,
        &receipt.signature_transcript_bytes()?,
    )?;
    let mut attestation = ClientStepAttestation {
        step: SecurityTransactionStep::CommitRecoveryUnit,
        output_ref: receipt.receipt_id.to_string(),
        transaction_id: transaction.transaction_id.clone(),
        transaction_request_digest: transaction.request_digest.clone(),
        prepared_plan_digest: transaction.prepared_plan_digest.clone(),
        artifact: ClientStepAttestationArtifact::Recovery(RecoveryTerminalCommit {
            recovery_receipt: receipt.clone(),
        }),
        signature_proof: ClientStepAttestationSignatureProof {
            verification_method: method,
            signature_algorithm: "Ed25519".into(),
            signature: base64url("AA")?,
        },
    };
    attestation.signature_proof.signature =
        sign(&custody.device_signing_key, &attestation.signing_bytes()?)?;
    let continued = SecurityTransactionContinueRequestBody {
        request_digest: transaction.request_digest.clone(),
        prepared_plan_digest: transaction.prepared_plan_digest.clone(),
        expected_accepted_step_count: 0,
        client_attestation: attestation,
    };
    transaction = serde_json::from_value(
        expect_json(
            candidate
                .post(&format!(
                    "/_arkret/self/security-transactions/{}/continue",
                    transaction.transaction_id
                ))
                .json(&continued),
            reqwest::StatusCode::OK,
        )
        .await?,
    )?;
    let Some(SecurityTransactionTerminalOutcome::Completed {
        completion_attestation: Some(completion),
        ..
    }) = &transaction.terminal_outcome
    else {
        anyhow::bail!("recovery did not complete: {transaction:?}")
    };
    let mut request = RecoveryCompletionGrantRequestBody {
        transaction_id: transaction.transaction_id,
        transaction_request_digest: transaction.request_digest,
        terminal_receipt: serde_json::to_value(receipt)?,
        completion_attestation: completion.clone(),
        device_authorization_event_id: completion.device_authorization_event_ref.event_id.clone(),
        new_model_generation_ref: completion.new_model_generation_ref,
        initial_session: serde_json::to_value(initial)?,
        canonical_request_digest: Hash::new(format!("sha256:{}", "0".repeat(64)))?,
    };
    request.canonical_request_digest = request.expected_canonical_request_digest()?;
    request.validate_structural()?;
    Ok(CompletedCandidate {
        candidate,
        gate,
        request,
    })
}

pub(super) struct RecoveryAuthority {
    method: DidUrl,
    seed: [u8; 32],
}

pub(super) async fn prepare_recovery_authority(
    founding: &TestActorClient,
) -> Result<RecoveryAuthority> {
    let author = RotationAuthor::from_client(founding)?;
    let custody = founding.principal.as_ref().context("founding custody")?;
    let method = verification_method(format!("{}#offline-recovery", custody.did))?;
    let seed = [0x43; 32];
    let event = author.recovery_unlock_policy(&unique("ak:policy:"), &method, seed)?;
    let mut policy: RecoveryPolicy = serde_json::from_value(event.payload["value"].clone())?;
    policy.trust_domain =
        crate::scenarios::_helpers::coauth_bootstrap::JOINT_TRUST_DOMAIN.parse()?;
    let backup = arkret_crypto::identity_root::derive_identity_recovery_key_material(&seed, 0)?;
    let Some(RecoveryMethod::RecoveryUnlock { keys }) = policy.methods.first_mut() else {
        anyhow::bail!("missing recovery key")
    };
    keys[0].backup_hpke.public_key_multibase = backup.backup_hpke_public_key_multikey.clone();
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
    Ok(RecoveryAuthority { method, seed })
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
        stale.request.new_model_generation_ref.checked_add(1)
            == Some(current.request.new_model_generation_ref)
            && stale.request.device_authorization_event_id
                != current.request.device_authorization_event_id,
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
    let grant: arkret_models_collaboration::session_grants::SessionGrantResponseBody =
        serde_json::from_value(accepted.session_grant_outcome)?;
    ensure!(
        grant.account_id == current.request.completion_attestation.account_id
            && grant.device_id.as_ref()
                == Some(&current.request.completion_attestation.replacement_device_id),
        "recovery changed Account or Device"
    );
    let encoded = grant
        .session_grant
        .split('.')
        .nth(1)
        .context("completed grant claims")?;
    let claims: arkret_models_identity::SignedSessionGrantClaims =
        serde_json::from_slice(&arkret_canonical::base64url_decode(encoded)?)?;
    ensure!(
        claims.credential_class == arkret_models_identity::SessionGrantCredentialClass::Standard
            && claims
                .device_binding
                .as_ref()
                .is_some_and(|binding| binding.authorization_event_id
                    == current.request.device_authorization_event_id
                    && binding.model_generation_ref == current.request.new_model_generation_ref),
        "completion grant did not bind the actual accepted authorization and generation"
    );
    let mut accepted_principal = current
        .candidate
        .principal
        .clone()
        .context("replacement custody")?;
    accepted_principal.founding_authorize_event_id =
        current.request.device_authorization_event_id.clone();
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
                    grant: grant.session_grant,
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
            account_id: current.request.completion_attestation.account_id.clone(),
        })
        .await?;
    ensure!(
        projection.principal_control_realm_id == custody.pcr_realm_id,
        "recovery replaced the PCR lineage"
    );
    let original = crate::scenarios::mls_lifecycle_live::accepted_full_view(
        &client,
        &current.request.device_authorization_event_id,
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
