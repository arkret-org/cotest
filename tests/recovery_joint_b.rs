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
        "alg": "EdDSA",
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

async fn post_json(http: &reqwest::Client, url: String, body: Value) -> Result<Value> {
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
#[ignore = "requires current coauth/starid/teabay/soland binaries and PostgreSQL"]
async fn enrollment_authority_recovery_uses_real_joint_bootstrap() -> Result<()> {
    let stack = bootstrap_required(FourServiceConfig::new(
        "joint-enrollment-authority-recovery",
    ))
    .await?;
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
        json!({
            "actor_id": bootstrap.principal_id(),
            "audience": description.service_id,
            "key_log_head": head,
            "enrollment_authority_ref": bootstrap.enrollment_authority_ref()?,
            "account_handle": "joint-recovery",
        }),
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
        json!({
            "actor_id": bootstrap.principal_id(),
            "device_id": FOUNDING_DEVICE,
            "dpop_jwk": dpop_public_jwk(&device_key),
            "audience": description.service_id,
        }),
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
        json!({
            "actor_id": bootstrap.principal_id(),
            "device_id": REPLACEMENT_DEVICE,
            "dpop_jwk": dpop_public_jwk(&replacement_key),
            "audience": description.service_id,
        }),
    )
    .await?;
    let replacement_grant_jwt = replacement_grant["grant_jwt"]
        .as_str()
        .context("replacement debug grant omitted JWT")?;
    let recovery_http = ClientBuilder::new(principal_base.clone())
        .allow_insecure_localhost()
        .auth(Auth::Dpop(garth::session::dpop::access_token_auth(
            replacement_grant_jwt.to_owned(),
            replacement_key.clone(),
        )))
        .build()?;
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
    inkson::event_signer::replace_active_signer(Some(replacement_signer));
    let recovery_session_id;
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
    recovery_session_id = prepared.verified_session.recovery_session_id.clone();
    let mut transaction = recovery_http
        .create_security_transaction(&SecurityTransactionCreateRequest::Recovery(
            prepared.create_request,
        ))
        .await?;
    assert_eq!(transaction.state, SecurityTransactionState::Pending);
    let SecurityTransactionBinding::Recovery(binding) = &transaction.binding else {
        return Err(anyhow!("joint recovery created a rotation transaction"));
    };
    assert_eq!(binding.recovery_session_id(), &recovery_session_id);
    let holder_seed = URL_SAFE_NO_PAD.encode(replacement_key.to_bytes());
    for _ in 0..8 {
        let Some(step) = transaction.next_required_step else {
            break;
        };
        if step == SecurityTransactionStep::IssueTerminalReceipt {
            break;
        }
        transaction = match step {
            SecurityTransactionStep::IssueAuthorityTicket => {
                recovery_http
                    .issue_recovery_authority_ticket(&authority_ticket_request(&transaction)?)
                    .await?;
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
                recovery_http
                    .continue_security_transaction(
                        &transaction.transaction_id,
                        &TypedSecurityTransactionContinueRequest {
                            request_digest: transaction.request_digest.clone(),
                            prepared_plan_digest: transaction.prepared_plan_digest.clone(),
                            expected_next_step: step,
                            client_attestation: None,
                            participant_request: Some(participant_request),
                        },
                    )
                    .await?
            }
            SecurityTransactionStep::PublishDidEntry
            | SecurityTransactionStep::SubmitReanchorUnit => {
                recovery_http
                    .continue_security_transaction(
                        &transaction.transaction_id,
                        &TypedSecurityTransactionContinueRequest {
                            request_digest: transaction.request_digest.clone(),
                            prepared_plan_digest: transaction.prepared_plan_digest.clone(),
                            expected_next_step: step,
                            client_attestation: None,
                            participant_request: None,
                        },
                    )
                    .await?
            }
            unexpected => return Err(anyhow!("unexpected B recovery step {unexpected:?}")),
        };
    }
    assert_eq!(
        transaction.next_required_step,
        Some(SecurityTransactionStep::IssueTerminalReceipt)
    );
    assert_eq!(
        transaction.state,
        SecurityTransactionState::AwaitingDeviceAttestation
    );
    Ok(())
}
