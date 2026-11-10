//! Accepted controller recovery recipients shared by native live fixtures.

use anyhow::{Context as _, Result, ensure};
use arkret_models_crypto::*;
use arkret_wire::{AccountId, ActorId, DidUrl, ScopeRef};
use chrono::Utc;
use ed25519_dalek::Signer as _;
use serde_json::json;

pub fn controller_history_custody(
    account: &AccountId,
    summary: &RecoveryPolicySummary,
) -> Result<AgentHistoryCustody> {
    summary.validate_shape()?;
    let policy = summary
        .policy
        .as_ref()
        .context("controller policy original absent")?;
    policy.validate_shape()?;
    let now = Utc::now();
    ensure!(
        summary.account_id == *account
            && policy.account_id == *account
            && policy.policy_id == summary.policy_id
            && policy.version == summary.version
            && policy.not_before.is_none_or(|at| at <= now)
            && policy.expires_at.is_none_or(|at| at > now),
        "controller policy mismatch"
    );
    let mut recipients = policy
        .methods
        .iter()
        .filter_map(|method| match method {
            RecoveryMethod::RecoveryUnlock { keys } => Some(keys),
            _ => None,
        })
        .flatten()
        .filter(|key| {
            key.not_before <= now
                && key.expires_at > now
                && key.revoked_at.is_none_or(|at| at > now)
                && key.backup_hpke.not_before <= now
                && key.backup_hpke.expires_at > now
                && key.backup_hpke.revoked_at.is_none_or(|at| at > now)
                && key
                    .backup_hpke
                    .hpke_suites
                    .contains(&arkret::RecoveryBackupHpkeSuite::X25519AeadChacha20Poly1305V1)
        });
    let recipient = recipients
        .next()
        .context("controller lacks active backup-HPKE recipient")?;
    ensure!(
        recipients.next().is_none(),
        "controller backup-HPKE recipient is ambiguous"
    );
    Ok(AgentHistoryCustody {
        custodian_actor_id: ActorId::account(account.clone()),
        recovery_policy_ref: RecoveryPolicyRef {
            policy_id: summary.policy_id.clone(),
            policy_version: summary.version,
        },
        recipient_key_ref: recipient.backup_hpke.key_agreement_ref.clone(),
    })
}

/// This is fixture enrollment through the actual native policy endpoint. It
/// does not grant a new identity or substitute a local policy for acceptance.
#[allow(clippy::too_many_arguments)]
pub async fn ensure_controller_recovery_policy(
    http: &arkret_http_client::Client,
    account: &AccountId,
    pcr: &arkret_wire::RealmId,
    did: &str,
    device_method: &DidUrl,
    trust_domain: &arkret_wire::TrustDomainId,
    signing_key: &ed25519_dalek::SigningKey,
    recovery_mnemonic: &str,
) -> Result<AgentHistoryCustody> {
    let source = http
        .own_station_result_client()?
        .context("native controller source required")?;
    source.check_session()?;
    ensure!(
        source.session()?.account_id() == account && &source.binding().trust_domain == trust_domain,
        "controller recovery policy belongs to another native source"
    );
    let current: RecoveryPolicyStatusView =
        http.get("/_arkret/root/identity/recovery-policy").await?;
    source.check_session()?;
    current.validate_shape()?;
    ensure!(
        current.account_id.as_ref() == Some(account),
        "recovery policy reader returned another Account"
    );
    let previous = current.active_policy;
    if let Some(summary) = &previous {
        if let Ok(custody) = controller_history_custody(account, summary) {
            source.check_session()?;
            return Ok(custody);
        }
    }
    let material = arkret::identity_root::derive_identity_recovery_key_material_from_bip39(
        recovery_mnemonic,
        "",
        0,
    )?;
    let issued = arkret::canonical::normalize_timestamp_canonical(Utc::now());
    let expires = issued + chrono::Duration::days(3650);
    let proof_ref = DidUrl::new(format!("{did}#recovery-proof-0")).map_err(anyhow::Error::msg)?;
    let backup_ref = DidUrl::new(format!("{did}#backup-hpke-0")).map_err(anyhow::Error::msg)?;
    let policy_id = arkret::new_prefixed_uuid7("ak:policy:");
    let version = previous
        .as_ref()
        .map(|policy| policy.version.checked_add(1))
        .unwrap_or(Some(1))
        .context("recovery policy version exhausted")?;
    let mut policy: RecoveryPolicy = serde_json::from_value(json!({
        "schema":"ak.schema.recovery_policy.v1", "policy_id":policy_id,
        "account_id":account, "version":version,
        "supersedes_id":previous.as_ref().map(|policy| &policy.policy_id),
        "trust_domain":trust_domain, "issued_at":issued,
        "signature_proof":{"verification_method":device_method,
            "signature_algorithm":"Ed25519", "signature":"AA"},
        "methods":[{"kind":"recovery_unlock","keys":[{
            "verification_method":proof_ref,
            "public_key_multibase":material.recovery_proof_public_key_multikey,
            "signature_algorithm":"Ed25519", "not_before":issued, "expires_at":expires,
            "backup_hpke":{"key_agreement_ref":backup_ref,
                "key_agreement_algorithm":"X25519",
                "public_key_multibase":material.backup_hpke_public_key_multikey,
                "hpke_suites":["ak.hpke_x25519_aead_chacha20poly1305.v1"],
                "use":"backup_hpke", "not_before":issued,"expires_at":expires}
        }]}]
    }))?;
    policy.signature_proof.signature =
        arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(
            signing_key
                .sign(&recovery_policy_signature_transcript_bytes(&policy)?)
                .to_bytes(),
        ))
        .map_err(anyhow::Error::msg)?;
    let mut event = arkret_event_draft::TypedEventDraft::<arkret_wire::event_spec::PolicySet>::new(
        ScopeRef::Realm {
            realm_id: pcr.clone(),
        },
        ActorId::account(account.clone()),
        serde_json::from_value(json!({"policy_id":policy_id,"value":policy}))?,
    )?
    .author_with_digest_suite(issued, arkret_canonical::DigestSuite::Sha256)?;
    let signer = arkret_signatures::Ed25519PayloadSigner::new(
        signing_key.clone(),
        arkret_wire::Did::new(did)?,
        device_method.clone(),
    );
    arkret_signatures::sign_event(
        &mut event,
        &signer,
        arkret_signatures::SignEventOptions::new().with_created_at(issued),
    )?;
    let context = arkret_identity::ProducerVerificationContext {
        actor: ActorId::account(account.clone()),
        verification_method: device_method.clone(),
        public_key: arkret_signatures::PublicKeyMaterial::Ed25519Raw {
            bytes: signing_key.verifying_key().to_bytes().to_vec(),
        },
        digest_suite: arkret_canonical::DigestSuite::Sha256,
    };
    let submission = arkret_identity::VerifiedSubmission::verify(
        arkret_wire::EventAdmissionSubmission::new(event.into_event()),
        |_| Ok(context.clone()),
    )?;
    source.check_session()?;
    let published = http.publish_recovery_policy(&submission).await?;
    source.check_session()?;
    ensure!(
        published.account_id == *account
            && published.policy_id.to_string() == policy_id
            && published.version == version,
        "recovery policy acceptance names another original"
    );
    let accepted: RecoveryPolicyStatusView =
        http.get("/_arkret/root/identity/recovery-policy").await?;
    source.check_session()?;
    accepted.validate_shape()?;
    ensure!(
        accepted.account_id.as_ref() == Some(account),
        "accepted policy belongs to another Account"
    );
    let active = accepted
        .active_policy
        .as_ref()
        .context("accepted recovery policy absent")?;
    ensure!(
        active.policy_id.to_string() == policy_id && active.version == version,
        "recovery policy changed after publication"
    );
    controller_history_custody(account, active)
}
