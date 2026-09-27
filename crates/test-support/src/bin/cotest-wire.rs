//! Thin CLI over `cotest_test_support::wire`.
//!
//! Every command below is one function in that module, called identically by
//! the Rust provisioning code. This file exists so the TypeScript side can
//! reach the same oracle through stdin/stdout.

use anyhow::{Context, Result, bail};
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
        "event-envelope-parse" => wire::event_envelope_parse(input)?,
        "verify-realm-state-snapshot" => wire::verify_realm_state_snapshot(input)?,
        "mimi-consent-proof" => wire::mimi_consent_proof(input)?,
        "mimi-request-consent-proof" => wire::mimi_request_consent_proof(input)?,
        "invite-subject-proof" => wire::invite_subject_proof(input)?,
        "mls-keypackage-upload-entry" => wire::mls_keypackage_upload_entry(input)?,
        "principal-control-realm-id" => wire::principal_control_realm(input)?,
        "webvh-placeholder-did" => wire::webvh_placeholder_did_command(input)?,
        "webvh-genesis" => wire::webvh_genesis(input)?,
        "webvh-verify-log" => wire::webvh_verify_log(input)?,
        "account-handoff-outcome" => wire::account_handoff_outcome(input)?,
        "account-handoff-request" => wire::account_handoff_request(input)?,
        "principal-registration-fixture" => wire::principal_registration_fixture(input)?,
        "identity-creation-register-request" => wire::identity_creation_register_request(input)?,
        "managed-actor-author" => wire::managed_actor_author(input)?,
        _ => bail!("unknown cotest-wire command {command:?}"),
    };

    println!("{}", serde_json::to_string(&output)?);
    Ok(())
}
