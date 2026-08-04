//! Real enrollment-authority (B-model) recovery against the four-service stack.
//!
//! Initial account acceptance uses debug-gated setup seams, but DID inception,
//! founding PCR bootstrap, recovery sessions, proofs, and every recovery
//! transaction participant run through their standard HTTP operations.

use std::sync::Arc;

use anyhow::{Context as _, Result, anyhow};
use arkret_canonical::multibase::ed25519_pubkey_to_did_key_multibase;
use arkret_http_client::{Auth, ClientBuilder};
use arkret_models_crypto::TypedSecurityTransactionContinueRequest;
use arkret_wire::{
    IssueAuthorityTicketStep, RecoveryAuthorityTicketIssueRequest, RecoveryBinding,
    SecurityTransaction, SecurityTransactionBinding, SecurityTransactionCreateRequest,
    SecurityTransactionState, SecurityTransactionStep,
};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use cotest::harness::NonProtocolTestBody;
use cotest::scenarios::_helpers::four_service_bootstrap::{FourServiceConfig, bootstrap_required};
use ed25519_dalek::SigningKey;
use serde_json::{Value, json};
use serial_test::serial;
use sha2::{Digest as _, Sha256};

const RECOVERY_WORDS: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
const FOUNDING_DEVICE: &str = "ak:device:019b0000-0000-7000-8000-00000000b001";
const REPLACEMENT_DEVICE: &str = "ak:device:019b0000-0000-7000-8000-00000000b002";

fn dpop_public_jwk(signing: &SigningKey) -> Value {
    json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "x": URL_SAFE_NO_PAD.encode(signing.verifying_key().as_bytes()),
        "use": "sig",
        "key_ops": ["verify"],
        "alg": "Ed25519",
    })
}

fn dpop_jkt(signing: &SigningKey) -> String {
    let canonical = format!(
        "{{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"{}\"}}",
        URL_SAFE_NO_PAD.encode(signing.verifying_key().as_bytes())
    );
    URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes()))
}

fn authority_ticket_request(
    transaction: &SecurityTransaction,
) -> Result<RecoveryAuthorityTicketIssueRequest> {
    let SecurityTransactionBinding::Recovery(RecoveryBinding::EnrollmentAuthority(binding)) =
        &transaction.binding
    else {
        return Err(anyhow!(
            "authority ticket requires an enrollment-authority recovery"
        ));
    };
    Ok(RecoveryAuthorityTicketIssueRequest {
        transaction_id: transaction.transaction_id.clone(),
        transaction_request_digest: transaction.request_digest.clone(),
        prepared_plan_digest: transaction.prepared_plan_digest.clone(),
        authority_ticket_id: binding.authority_ticket_id.clone(),
        expected_next_step: IssueAuthorityTicketStep::IssueAuthorityTicket,
    })
}

fn recovery_client(
    principal_base: &url::Url,
    grant_jwt: &str,
    signing_key: &SigningKey,
) -> Result<arkret_http_client::Client> {
    Ok(ClientBuilder::new(principal_base.clone())
        .allow_insecure_localhost()
        .auth(Auth::Dpop(garth::session::dpop::access_token_auth(
            grant_jwt.to_owned(),
            signing_key.clone(),
        )))
        .build()?)
}

async fn post_json(
    http: &reqwest::Client,
    url: String,
    body: NonProtocolTestBody,
) -> Result<Value> {
    let response = http.post(&url).json(&body).send().await?;
    let status = response.status();
    let text = response.text().await?;
    if !status.is_success() {
        return Err(anyhow!("{url} returned {status}: {text}"));
    }
    serde_json::from_str(&text).with_context(|| format!("decode response from {url}: {text}"))
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
#[ignore = "requires current coauth/starid/teabay/soland binaries plus DATABASE_URL and COTEST_SOLAND_DATABASE_URL"]
async fn enrollment_authority_recovery_uses_real_joint_bootstrap() -> Result<()> {
    let soland_database_url = std::env::var("COTEST_SOLAND_DATABASE_URL").context(
        "COTEST_SOLAND_DATABASE_URL is required: this restart recovery gate must not use Soland's in-memory store",
    )?;
    let mut config = FourServiceConfig::new("joint-enrollment-authority-recovery");
    config.soland_database_url = Some(soland_database_url);
    let mut stack = bootstrap_required(config).await?;
    stack.assert_healthy().await?;
    let principal_base = stack.soland.base_url().clone();
    let coauth_base = stack
        .coauth_base_url()
        .context("required Coauth service is absent")?
        .trim_end_matches('/')
        .to_owned();
    let principal = ClientBuilder::new(principal_base.clone())
        .allow_insecure_localhost()
        .build()?;
    let authority_describe = reqwest::Client::new()
        .get(format!("{coauth_base}/_arkret/describe"))
        .send()
        .await
        .context("request Coauth describe directly")?;
    let authority_status = authority_describe.status();
    let authority_body = authority_describe
        .text()
        .await
        .context("read Coauth describe response")?;
    anyhow::ensure!(
        authority_status.is_success(),
        "Coauth describe returned {authority_status}: {authority_body}"
    );
    let description = principal.describe().await?;
    let account_authority = description
        .auth_metadata
        .account_authority
        .as_ref()
        .context("Soland describe omitted account authority")?;
    let enrollment_authority_did = account_authority
        .enrollment_authority_did
        .as_ref()
        .context("Soland describe omitted enrollment authority DID")?;
    let gate_account_base = account_authority.gate_account_base.trim_end_matches('/');
    let recovery_material =
        arkret::identity_root::derive_identity_recovery_key_material_from_bip39(
            RECOVERY_WORDS,
            "",
            0,
        )?;
    let bootstrap = inkson::fresh_device_recovery::prepare_joint_principal_bootstrap(
        principal_base.as_str(),
        gate_account_base,
        "joint-recovery",
        enrollment_authority_did.as_str(),
        description.trust_domain.as_str(),
        FOUNDING_DEVICE,
        RECOVERY_WORDS,
    )?;
    let inception = principal
        .identity_submit_did_operation(&bootstrap.did_operation()?)
        .await?;
    let head = inception
        .head_event_digest
        .as_ref()
        .context("DID inception omitted accepted head")?;

    let device_key = SigningKey::from_bytes(&[0x42; 32]);
    let holder_jkt = dpop_jkt(&device_key);
    let http = reqwest::Client::new();
    let binding = post_json(
        &http,
        format!("{coauth_base}/_coauth/account/test/debug/bind-principal"),
        NonProtocolTestBody::new(json!({
            "actor_id": bootstrap.principal_id(),
            "audience": description.service_id,
            "key_log_head": head,
            "enrollment_authority_ref": bootstrap.enrollment_authority_ref()?,
            "account_handle": "joint-recovery",
        })),
    )
    .await?;
    assert_eq!(binding["actor_id"], bootstrap.principal_id());
    assert_eq!(
        binding["enrollment_authority_did"],
        enrollment_authority_did.as_str()
    );

    let grant = post_json(
        &http,
        format!("{coauth_base}/_coauth/account/test/debug/issue-dpop-grant"),
        NonProtocolTestBody::new(json!({
            "actor_id": bootstrap.principal_id(),
            "device_id": FOUNDING_DEVICE,
            "dpop_jwk": dpop_public_jwk(&device_key),
            "audience": description.service_id,
        })),
    )
    .await?;
    assert_eq!(grant["dpop_jkt"], holder_jkt);
    let grant_jwt = grant["grant_jwt"]
        .as_str()
        .context("debug grant omitted JWT")?;
    let account = ClientBuilder::new(url::Url::parse(&coauth_base)?)
        .allow_insecure_localhost()
        .auth(Auth::Dpop(garth::session::dpop::access_token_auth(
            grant_jwt.to_owned(),
            device_key.clone(),
        )))
        .build()?;
    let principal_authed = ClientBuilder::new(principal_base.clone())
        .allow_insecure_localhost()
        .auth(Auth::Dpop(garth::session::dpop::access_token_auth(
            grant_jwt.to_owned(),
            device_key.clone(),
        )))
        .build()?;
    let signer = inkson::event_signer::build_ed25519_device_signer(
        device_key.to_bytes(),
        bootstrap.principal_id(),
        FOUNDING_DEVICE,
    );
    inkson::fresh_device_recovery::execute_joint_principal_bootstrap(
        &bootstrap,
        RECOVERY_WORDS,
        ed25519_pubkey_to_did_key_multibase(device_key.verifying_key().as_bytes()),
        recovery_material.backup_hpke_public_key_multikey.clone(),
        &signer,
        &account,
        &principal_authed,
    )
    .await?;
    let backup_id = inkson::fresh_device_recovery::establish_joint_recovery_policy_and_backup(
        principal_authed.clone(),
        bootstrap.principal_id(),
        FOUNDING_DEVICE,
        RECOVERY_WORDS,
        device_key.to_bytes(),
        Arc::new(signer),
    )
    .await?;
    assert!(backup_id.starts_with("ak:backup:"));

    let document = principal
        .identity_document(bootstrap.principal_id(), None)
        .await?;
    assert_eq!(
        document.did_document.get("id").and_then(Value::as_str),
        Some(bootstrap.principal_id())
    );
    assert!(
        inception
            .operation_ref
            .as_deref()
            .is_some_and(|reference| reference.ends_with(bootstrap.version_id()))
    );

    // A lost-device recovery starts from a new local holder key. The founding
    // grant above exists only to establish the fixture and is not reused.
    let replacement_key = SigningKey::from_bytes(&[0x43; 32]);
    let replacement_holder_jkt = dpop_jkt(&replacement_key);
    let replacement_grant = post_json(
        &http,
        format!("{coauth_base}/_coauth/account/test/debug/issue-dpop-grant"),
        NonProtocolTestBody::new(json!({
            "actor_id": bootstrap.principal_id(),
            "device_id": REPLACEMENT_DEVICE,
            "dpop_jwk": dpop_public_jwk(&replacement_key),
            "audience": description.service_id,
        })),
    )
    .await?;
    let replacement_grant_jwt = replacement_grant["grant_jwt"]
        .as_str()
        .context("replacement debug grant omitted JWT")?;
    let mut recovery_http =
        recovery_client(&principal_base, replacement_grant_jwt, &replacement_key)?;
    let replacement_signer = Arc::new(inkson::event_signer::build_ed25519_device_signer(
        replacement_key.to_bytes(),
        bootstrap.principal_id(),
        REPLACEMENT_DEVICE,
    ));
    inkson::secure_key_store::store_signing_seed_scoped(
        inkson::secure_key_store::default_secure_key_store("inkson").as_ref(),
        Some(bootstrap.principal_id()),
        &replacement_key.to_bytes(),
    )?;
    inkson::event_signer::replace_active_signer(Some(Arc::clone(&replacement_signer)));
    let prepared =
        inkson::fresh_device_recovery::prepare_joint_enrollment_authority_recovery_from_words(
            recovery_http.clone(),
            principal_base.as_str(),
            bootstrap.principal_id(),
            REPLACEMENT_DEVICE,
            description.trust_domain.clone(),
            RECOVERY_WORDS,
            &replacement_holder_jkt,
        )
        .await?;
    let recovery_session_id = prepared.verified_session.recovery_session_id.clone();
    let backup_classes_unlocked = inkson::mls::account_recovery::unlock_joint_recovery_backups(
        recovery_http.clone(),
        &prepared.verified_session,
        RECOVERY_WORDS,
    )
    .await?;
    assert!(
        !backup_classes_unlocked.is_empty(),
        "real recovery restore must unlock at least one active backup"
    );
    let create = SecurityTransactionCreateRequest::Recovery(prepared.create_request);
    let mut transaction = recovery_http.create_security_transaction(&create).await?;
    let exact_create = recovery_http.create_security_transaction(&create).await?;
    assert_eq!(
        serde_json::to_value(&transaction)?,
        serde_json::to_value(&exact_create)?,
        "byte-identical create replay must return the first durable outcome"
    );
    let mut conflicting_create = create.clone();
    let SecurityTransactionCreateRequest::Recovery(conflicting) = &mut conflicting_create else {
        unreachable!("recovery create")
    };
    conflicting.expires_at += chrono::Duration::milliseconds(1);
    let create_conflict = recovery_http
        .create_security_transaction(&conflicting_create)
        .await
        .expect_err("same transaction id with different bytes must conflict");
    assert!(
        create_conflict.to_string().contains("duplicate_conflict"),
        "unexpected create conflict: {create_conflict}"
    );
    assert_eq!(transaction.state, SecurityTransactionState::Pending);
    let SecurityTransactionBinding::Recovery(binding) = &transaction.binding else {
        return Err(anyhow!("joint recovery created a rotation transaction"));
    };
    assert_eq!(binding.recovery_session_id(), &recovery_session_id);
    let fixed_transaction_id = transaction.transaction_id.clone();
    let fixed_request_digest = transaction.request_digest.clone();
    let fixed_plan_digest = transaction.prepared_plan_digest.clone();
    let holder_seed = URL_SAFE_NO_PAD.encode(replacement_key.to_bytes());
    let mut consumed_holder_jti = None;
    for _ in 0..8 {
        let Some(step) = transaction.next_required_step else {
            break;
        };
        if step == SecurityTransactionStep::IssueTerminalReceipt {
            break;
        }
        let accepted_before = transaction.accepted_steps.len();
        transaction = match step {
            SecurityTransactionStep::IssueAuthorityTicket => {
                let request = authority_ticket_request(&transaction)?;
                recovery_http
                    .issue_recovery_authority_ticket(&request)
                    .await?;
                stack
                    .soland
                    .restart_external_process()
                    .await
                    .context("restart coordinator after durable authority ticket")?;
                recovery_http =
                    recovery_client(&principal_base, replacement_grant_jwt, &replacement_key)?;
                let replayed = recovery_http
                    .issue_recovery_authority_ticket(&request)
                    .await?;
                let replayed_again = recovery_http
                    .issue_recovery_authority_ticket(&request)
                    .await?;
                assert_eq!(
                    serde_json::to_value(&replayed)?,
                    serde_json::to_value(&replayed_again)?,
                    "authority-ticket response loss must replay the first durable ticket"
                );
                recovery_http
                    .get_security_transaction(&transaction.transaction_id)
                    .await?
            }
            SecurityTransactionStep::AuthorizeRecoveryDevice => {
                let ticket = recovery_http
                    .issue_recovery_authority_ticket(&authority_ticket_request(&transaction)?)
                    .await?;
                let participant_request =
                    inkson::fresh_device_recovery::joint_recovery_device_authorization_request(
                        &transaction,
                        ticket,
                        &prepared.account_authority_endpoint,
                        &holder_seed,
                        &replacement_holder_jkt,
                    )?;
                let proof_payload = participant_request
                    .holder_proof
                    .proof_jwt
                    .split('.')
                    .nth(1)
                    .context("holder proof JWT omitted payload")?;
                let proof_claims: serde_json::Value =
                    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(proof_payload)?)?;
                consumed_holder_jti = Some(
                    proof_claims["jti"]
                        .as_str()
                        .context("holder proof JWT omitted jti")?
                        .to_owned(),
                );
                let authority_endpoint =
                    format!("{coauth_base}/_arkret/gate/account/recovery-device-authorizations");
                let mut tampered_candidate = participant_request.clone();
                tampered_candidate.authorization_preimage.did_entry_digest =
                    arkret_wire::Hash::new(format!("sha256:{}", "0".repeat(64)))?;
                let tampered_candidate_response = http
                    .post(&authority_endpoint)
                    .json(&tampered_candidate)
                    .send()
                    .await?;
                assert!(
                    !tampered_candidate_response.status().is_success(),
                    "Coauth must reject a candidate DID entry digest changed after preparation"
                );
                let mut rotated_authority = participant_request.clone();
                let unexpected_authority =
                    arkret_wire::Did::new("did:web:rotated-authority.invalid".to_owned())?;
                rotated_authority.ticket.account_authority_id = unexpected_authority.clone();
                rotated_authority
                    .authorization_preimage
                    .account_authority_id = unexpected_authority;
                let rotated_authority_response = http
                    .post(&authority_endpoint)
                    .json(&rotated_authority)
                    .send()
                    .await?;
                assert!(
                    !rotated_authority_response.status().is_success(),
                    "Coauth must reject an authority identity changed after ticket issuance"
                );
                let request = TypedSecurityTransactionContinueRequest {
                    request_digest: transaction.request_digest.clone(),
                    prepared_plan_digest: transaction.prepared_plan_digest.clone(),
                    expected_next_step: step,
                    client_attestation: None,
                    participant_request: Some(participant_request),
                };
                recovery_http
                    .continue_security_transaction(&transaction.transaction_id, &request)
                    .await?;
                stack
                    .soland
                    .restart_external_process()
                    .await
                    .context("restart coordinator after durable authority outcome")?;
                recovery_http =
                    recovery_client(&principal_base, replacement_grant_jwt, &replacement_key)?;
                recovery_http
                    .continue_security_transaction(&transaction.transaction_id, &request)
                    .await?
            }
            SecurityTransactionStep::PublishDidEntry
            | SecurityTransactionStep::SubmitReanchorUnit => {
                let request = TypedSecurityTransactionContinueRequest {
                    request_digest: transaction.request_digest.clone(),
                    prepared_plan_digest: transaction.prepared_plan_digest.clone(),
                    expected_next_step: step,
                    client_attestation: None,
                    participant_request: None,
                };
                recovery_http
                    .continue_security_transaction(&transaction.transaction_id, &request)
                    .await?;
                stack
                    .soland
                    .restart_external_process()
                    .await
                    .with_context(|| format!("restart coordinator after durable {step:?}"))?;
                recovery_http =
                    recovery_client(&principal_base, replacement_grant_jwt, &replacement_key)?;
                recovery_http
                    .continue_security_transaction(&transaction.transaction_id, &request)
                    .await?
            }
            unexpected => return Err(anyhow!("unexpected B recovery step {unexpected:?}")),
        };
        let fetched = recovery_http
            .get_security_transaction(&fixed_transaction_id)
            .await?;
        assert_eq!(
            serde_json::to_value(&transaction)?,
            serde_json::to_value(&fetched)?,
            "{step:?} replay after client restart must equal the durable resource"
        );
        assert_eq!(
            transaction.accepted_steps.len(),
            accepted_before + 1,
            "{step:?} response loss must append exactly one accepted step"
        );
        assert_eq!(transaction.transaction_id, fixed_transaction_id);
        assert_eq!(transaction.request_digest, fixed_request_digest);
        assert_eq!(transaction.prepared_plan_digest, fixed_plan_digest);
    }
    assert_eq!(
        transaction.next_required_step,
        Some(SecurityTransactionStep::IssueTerminalReceipt)
    );
    assert_eq!(
        transaction.state,
        SecurityTransactionState::AwaitingDeviceAttestation
    );
    let completed_at = chrono::Utc::now();
    let terminal = inkson::fresh_device_recovery::sign_terminal_receipt_continue(
        &transaction,
        inkson::fresh_device_recovery::RecoveryTerminalObservation {
            policy_id: prepared.verified_session.policy_id.clone(),
            policy_version: prepared.verified_session.policy_version,
            trust_domain: prepared.verified_session.trust_domain.clone(),
            proof_summary: arkret_models_crypto::RecoveryProofSummary {
                kind: prepared.proof_summary.kind,
                proof_digest: prepared.proof_summary.proof_digest.clone(),
                quorum_participant_count: None,
                share_ids: None,
            },
            backup_classes_unlocked,
            welcome_count: 0,
            welcome_realm_summary: None,
            started_at: prepared.verified_session.created_at,
            completed_at,
        },
        replacement_signer.as_ref(),
    )?;
    let different_terminal = inkson::fresh_device_recovery::sign_terminal_receipt_continue(
        &transaction,
        inkson::fresh_device_recovery::RecoveryTerminalObservation {
            policy_id: prepared.verified_session.policy_id.clone(),
            policy_version: prepared.verified_session.policy_version,
            trust_domain: prepared.verified_session.trust_domain.clone(),
            proof_summary: arkret_models_crypto::RecoveryProofSummary {
                kind: prepared.proof_summary.kind,
                proof_digest: prepared.proof_summary.proof_digest.clone(),
                quorum_participant_count: None,
                share_ids: None,
            },
            backup_classes_unlocked: terminal
                .client_attestation
                .as_ref()
                .and_then(|attestation| match &attestation.artifact {
                    arkret_models_crypto::ClientStepAttestationArtifact::RecoveryReceipt(
                        receipt,
                    ) => Some(receipt.backup_classes_unlocked.clone()),
                    _ => None,
                })
                .context("terminal receipt omitted backup classes")?,
            welcome_count: 0,
            welcome_realm_summary: None,
            started_at: prepared.verified_session.created_at,
            completed_at: completed_at + chrono::Duration::milliseconds(1),
        },
        replacement_signer.as_ref(),
    )?;
    recovery_http
        .continue_security_transaction(&transaction.transaction_id, &terminal)
        .await?;
    stack
        .soland
        .restart_external_process()
        .await
        .context("restart coordinator after durable terminal receipt")?;
    recovery_http = recovery_client(&principal_base, replacement_grant_jwt, &replacement_key)?;
    transaction = recovery_http
        .continue_security_transaction(&transaction.transaction_id, &terminal)
        .await?;
    assert_eq!(transaction.state, SecurityTransactionState::Completed);
    assert!(transaction.next_required_step.is_none());
    assert!(
        transaction
            .terminal_result
            .as_ref()
            .and_then(|result| result.completion_attestation.as_ref())
            .is_some(),
        "completed recovery must carry a durable completion attestation"
    );
    let exact_terminal = recovery_http
        .continue_security_transaction(&transaction.transaction_id, &terminal)
        .await?;
    assert_eq!(
        serde_json::to_value(&transaction)?,
        serde_json::to_value(&exact_terminal)?,
        "byte-identical terminal replay must return the first completion"
    );
    let terminal_conflict = recovery_http
        .continue_security_transaction(&transaction.transaction_id, &different_terminal)
        .await
        .expect_err("different terminal bytes must conflict");
    assert!(
        terminal_conflict.to_string().contains("duplicate_conflict")
            || terminal_conflict.to_string().contains("terminal"),
        "unexpected terminal conflict: {terminal_conflict}"
    );

    let second_prepared =
        inkson::fresh_device_recovery::prepare_joint_enrollment_authority_recovery_from_words(
            recovery_http.clone(),
            principal_base.as_str(),
            bootstrap.principal_id(),
            REPLACEMENT_DEVICE,
            description.trust_domain,
            RECOVERY_WORDS,
            &replacement_holder_jkt,
        )
        .await?;
    let second_create = SecurityTransactionCreateRequest::Recovery(second_prepared.create_request);
    let second_transaction = recovery_http
        .create_security_transaction(&second_create)
        .await?;
    let second_ticket = recovery_http
        .issue_recovery_authority_ticket(&authority_ticket_request(&second_transaction)?)
        .await?;
    let mut replayed_jti_request =
        inkson::fresh_device_recovery::joint_recovery_device_authorization_request(
            &second_transaction,
            second_ticket,
            &second_prepared.account_authority_endpoint,
            &holder_seed,
            &replacement_holder_jkt,
        )?;
    let replayed_jti_proof = arkret_signatures::DpopProofRequest::new(
        "POST",
        &second_prepared.account_authority_endpoint,
    )
    .nonce(replayed_jti_request.canonical_request_digest.as_str())
    .jti(
        consumed_holder_jti
            .as_deref()
            .context("first authority request did not record its holder JTI")?,
    );
    replayed_jti_request.holder_proof.proof_jwt =
        arkret_signatures::build_dpop_proof(&replayed_jti_proof, &replacement_key)?.header_value;
    let replayed_jti_response = http
        .post(format!(
            "{coauth_base}/_arkret/gate/account/recovery-device-authorizations"
        ))
        .json(&replayed_jti_request)
        .send()
        .await?;
    let replayed_jti_status = replayed_jti_response.status();
    let replayed_jti_body = replayed_jti_response.text().await?;
    assert!(
        !replayed_jti_status.is_success() && replayed_jti_body.contains("already consumed"),
        "Coauth must reject a consumed holder JTI on a different transaction; \
         status={replayed_jti_status}, body={replayed_jti_body}"
    );
    Ok(())
}
