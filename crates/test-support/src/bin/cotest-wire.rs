//! Thin CLI over `cotest_test_support::wire`.
//!
//! Every command below is one function in that module, called identically by
//! the Rust provisioning code. This file exists so the TypeScript side can
//! reach the same oracle through stdin/stdout.

use anyhow::{Context, Result, bail};
use cotest_test_support::mls_wire;
use cotest_test_support::wire::{self, EventDigestMode};

fn main() -> Result<()> {
    let command = std::env::args().nth(1).context("missing command")?;
    let input = wire::read_stdin_json()?;

    let output = match command.as_str() {
        "canonical-json" => wire::canonical_json(input)?,
        "sha256-canonical-json" => wire::sha256_canonical_json(input)?,
        "did-document-digest" => wire::did_document_digest(input)?,
        "event-envelope-proof" => wire::event_proof(input, EventDigestMode::RawCanonicalJson)?,
        "event-derived-id" => wire::event_derived_id(input)?,
        "historical-human-signer-query" => wire::historical_human_signer_query(input)?,
        "historical-human-signer-fact" => wire::historical_human_signer_fact(input)?,
        "event-envelope-parse" => wire::event_envelope_parse(input)?,
        "verify-realm-state-snapshot" => wire::verify_realm_state_snapshot(input)?,
        "mimi-consent-proof" => wire::mimi_consent_proof(input)?,
        "mimi-request-consent-proof" => wire::mimi_request_consent_proof(input)?,
        "invite-subject-proof" => wire::invite_subject_proof(input)?,
        "key-backup-auth-signature" => wire::key_backup_auth_signature(input)?,
        "mls-keypackage-upload-entry" => wire::mls_keypackage_upload_entry(input)?,
        "mls-keypackages" => mls_wire::mls_keypackages(input)?,
        "mls-genesis" => mls_wire::mls_genesis(input)?,
        "mls-keypackage-claim-request" => mls_wire::mls_keypackage_claim_request(input)?,
        "mls-add-member" => mls_wire::mls_add_member(input)?,
        "mls-welcome-delivery" => mls_wire::mls_welcome_delivery(input)?,
        "mls-install-commit" => mls_wire::mls_install_commit(input)?,
        "mls-join-welcome" => mls_wire::mls_join_welcome(input)?,
        "mls-encrypt-message" => mls_wire::mls_encrypt_message(input)?,
        "mls-encrypt-signal" => mls_wire::mls_encrypt_signal(input)?,
        "mls-open-signals" => mls_wire::mls_open_signals(input)?,
        "principal-control-realm-id" => wire::principal_control_realm(input)?,
        "webvh-placeholder-did" => wire::webvh_placeholder_did_command(input)?,
        "webvh-genesis" => wire::webvh_genesis(input)?,
        "webvh-verify-log" => wire::webvh_verify_log(input)?,
        "account-handoff-outcome" => wire::account_handoff_outcome(input)?,
        "account-handoff-request" => wire::account_handoff_request(input)?,
        "principal-registration-fixture" => wire::principal_registration_fixture(input)?,
        "identity-creation-register-request" => wire::identity_creation_register_request(input)?,
        "device-pairing-target-proof" => wire::device_pairing_target_proof(input)?,
        "device-pairing-approval" => wire::device_pairing_approval(input)?,
        "human-session-grant-request" => wire::human_session_grant_request(input)?,
        "managed-actor-author" => wire::managed_actor_author(input)?,
        "validate-applet-authority-material" => wire::validate_applet_authority_material(input)?,
        _ => bail!("unknown cotest-wire command {command:?}"),
    };

    println!("{}", serde_json::to_string(&output)?);
    Ok(())
}
