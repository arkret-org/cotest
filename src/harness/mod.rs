//! Complement-style black-box conformance harness for Arkret servers.
//!
//! This module is organized into focused submodules:
//! - [`server`]: [`ArkretServer`]/[`TestServerGroup`] process/Docker orchestration.
//! - [`client`]: [`TestActorClient`] and its request helpers.
//! - [`assertions`]: HTTP assertion family and the recording/transcript machinery.
//! - [`event_builder`]: token-based event constructors and account helpers.
//! - [`proof`]: canonical event digest / proof refresh.

use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::Result;
use serde_json::{Value, json};

mod assertions;
mod client;
mod event_builder;
mod proof;
mod server;
mod wire_body;

pub use assertions::{
    RecordedResponse, account_subscribe_delta_from_text, eventually,
    expect_account_subscribe_delta, expect_account_subscribe_realm_delta, expect_api_error,
    expect_audit_action, expect_indistinguishable_api_errors, expect_json, expect_response,
    expect_status, expect_text,
};
pub use client::TestActorClient;
pub use event_builder::{
    add_member, add_member_with_signing_seed, create_realm, create_realm_with_signing_seed,
    dev_login, device_message_send_request, encrypted_envelope, event_envelope,
    event_envelope_at_frontier_with_signing_seed, event_envelope_with_signing_seed,
    event_envelope_with_signing_seed_and_verification_method, realm_bootstrap_event_batch,
    realm_bootstrap_event_batch_with_signing_seed, register_account,
    register_event_signing_identity, send_message, submit_event, submit_event_with_signing_seed,
    submit_event_with_signing_seed_and_verification_method,
};
pub(crate) use event_builder::{
    event_envelope_with_chain, invite_create_payload, member_join_payload_value,
    member_transition_payload, message_create_text_payload, message_create_text_payload_for_strand,
    message_redact_payload, message_revise_text_payload, parse_strand_id,
};
pub use proof::{
    attach_signal_proof, attach_signal_proof_value, refresh_event_proof,
    refresh_event_proof_with_signing_seed, refresh_typed_event_proof,
    refresh_typed_event_proof_with_signing_seed,
};
pub use server::{ArkretServer, TestServerGroup};
pub(crate) use server::{ReservedPort, reserve_port};
pub use wire_body::{NonProtocolTestBody, wire_negative_from_sdk};

static NEXT_EVENT_SEQ: AtomicU64 = AtomicU64::new(1);

/// The placeholder SCID used by fixture `did:webvh` identifiers.
///
/// `did:webvh` is the v1 core default method for both service and principal
/// DIDs (identity-did.md); the fixture SCID form matches the spec conformance
/// vectors and the e2e side's `uniqueUser()` / `env.ts` migration
/// (`did:webvh:z6mkfixture:<host>`). Live scenarios rely on soland's dev mode
/// not performing online SCID resolution — these fixture DIDs have no real
/// `did.jsonl`. `did:web` is reserved for explicit no-history / negative
/// fixtures only.
pub(crate) const FIXTURE_WEBVH_SCID: &str = "z6mkfixture";

/// Build a fixture `did:webvh:<scid>:<host>` DID for `host`.
///
/// `host` is the DID's HTTP authority (e.g. `soland.cotest.local`,
/// `alice.example`). soland derives the federation trust domain from the host
/// segment that follows the SCID, so callers pass the bare host and the SCID is
/// supplied here.
pub(crate) fn fixture_webvh_did(host: &str) -> String {
    format!("did:webvh:{FIXTURE_WEBVH_SCID}:{host}")
}

pub(crate) fn canonical_device_id(input: &str) -> String {
    if input.starts_with("ak:device:") {
        return input.to_owned();
    }

    let suffix = match input {
        "dev_admin" => "00000000ad01",
        "dev_alice" => "0000000000a1",
        "dev_alice2" => "0000000000a2",
        "dev_alice_b" => "0000000000ab",
        "dev_bad" => "000000000bad",
        "dev_bob" => "0000000000b0",
        "dev_bob2" => "0000000000b2",
        "dev_bob_a" => "0000000000ba",
        "dev_bob_b" => "0000000000bb",
        "dev_bob_d3" => "000000000bd3",
        "dev_carol" => "000000000ca0",
        "dev_chaos_midwrite" => "00000000c0de",
        "dev_dave" => "000000000da0",
        "dev_in" => "0000000000e1",
        "dev_missing" => "00000000dead",
        "dev_other" => "0000000000f0",
        "dev_outsider" => "00000000e005",
        "dev_probe_circle" => "00000000e007",
        "dev_probe_realm" => "00000000e006",
        "dev_realm_only" => "00000000e002",
        "dev_x" => "0000000000e4",
        "dev_y" => "0000000000e3",
        _ => return format!("ak:device:01904100-0000-7000-8000-{:012x}", fnv1a_48(input)),
    };
    format!("ak:device:01904100-0000-7000-8000-{suffix}")
}

fn fnv1a_48(input: &str) -> u64 {
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in input.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash & 0x0000_ffff_ffff_ffff
}

/// Canonical `ak.member.state` join payload shared by the harness `add_member`
/// helpers so the member.state default shape lives in one place.
pub(crate) fn member_join_payload(realm_id: &str, actor_id: &str) -> Value {
    member_join_payload_value(realm_id, actor_id).expect("valid cotest member.join payload")
}

fn next_typed_id(kind: &str) -> String {
    let seq = NEXT_EVENT_SEQ.fetch_add(1, Ordering::Relaxed);
    format!("ak:{kind}:01999999-0000-7000-8000-{seq:012x}")
}

/// Normalise a single `plaintext_visible_services` entry into the spec-typed
/// `plaintext_visible_services_payload` `services[]` item shape
/// (`event-payload.schema.json#/$defs/plaintext_visible_services_payload`).
///
/// A bare DID string carries no declared `data_classes`, so soland's realm
/// projection records an empty per-service class map and fails closed on any
/// private-realm plaintext send. The harness default therefore declares the
/// common plaintext data classes for the service. Entries that are already
/// objects (callers that hand-build a typed service) pass through unchanged.
fn normalize_plaintext_visible_service(entry: &Value) -> Value {
    if entry.is_object() {
        return entry.clone();
    }
    match entry.as_str() {
        Some(service_id) => json!({
            "service_id": service_id,
            "service_kind": "principal_server",
            "data_classes": [
                "message_content",
                "strand_content",
                "attachment_plaintext",
                "attachment_preview",
                "thumbnail",
                "full_text_index",
                "search_snippet",
                "notification_summary",
                "inbox_preview",
                "history_preview"
            ],
            "purposes": ["cotest-harness-default"],
            "visibility": "private_plaintext"
        }),
        None => entry.clone(),
    }
}

pub(crate) fn realm_create_payload(
    actor: &str,
    service_id: &str,
    realm_id: &str,
    input: &Value,
) -> Result<(
    arkret_models_collaboration::events_payloads::RealmCreatePayload,
    Option<
        arkret_models_collaboration::governance::plaintext_visibility::PlaintextVisibleServicesPayload,
    >,
)>{
    let title = input
        .get("title")
        .and_then(Value::as_str)
        .filter(|title| !title.trim().is_empty())
        .unwrap_or("Cotest Realm");
    let summary = input
        .get("summary")
        .and_then(Value::as_str)
        .unwrap_or(title);
    let public = input
        .get("public")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let discoverability = input
        .get("discoverability")
        .and_then(Value::as_str)
        .unwrap_or(if public { "public" } else { "listed" });
    let join_rule = input
        .get("join_rule")
        .and_then(Value::as_str)
        .unwrap_or("invite");
    let history_visibility = input
        .get("history_visibility")
        .and_then(Value::as_str)
        .unwrap_or("shared");
    let encryption_profile = input
        .get("encryption_profile")
        .and_then(Value::as_str)
        .unwrap_or("none");
    // soland grants plaintext data classes per declared service (it reads the
    // typed `services[].data_classes` map, not a bare DID list — see
    // RealmMetaRecord::allows_plaintext_data_class). A flat DID string projects
    // to an EMPTY data-class map, so every private-realm plaintext send would
    // fail closed with `capability_denied` (403). Normalise each entry to the
    // spec-typed `plaintext_visible_services_payload` item shape; pre-typed
    // objects (e.g. the media-plaintext scenarios) pass through unchanged.
    // A Realm declares the conformance profiles it participates in through
    // `schema_refs` (`capabilities.md` section 3.2): a profile-gated action is
    // owner-grantable exactly when its profile is declared here. Callers that
    // exercise profile actions pass the profile id alongside the base schema.
    let schema_refs = input
        .get("schema_refs")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_else(|| vec![json!("ak.schema.realm.v1")]);
    let plaintext_visible_services = input
        .get("plaintext_visible_services")
        .cloned()
        .filter(Value::is_array)
        .unwrap_or_else(|| json!([service_id]));
    let services = plaintext_visible_services
        .as_array()
        .into_iter()
        .flatten()
        .map(|entry| {
            serde_json::from_value::<
                arkret_models_collaboration::governance::plaintext_visibility::PlaintextVisibleService,
            >(normalize_plaintext_visible_service(entry))
        })
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let plaintext_visible_services = (!services.is_empty()).then(|| {
        arkret_models_collaboration::governance::plaintext_visibility::PlaintextVisibleServicesPayload::new(services)
    });

    let created_by = arkret_identifiers::Did::new(actor.to_owned())?;
    let notary_did = arkret_identifiers::Did::new(service_id.to_owned())?;
    let notary = arkret_wire::notary::NotaryValue::single_did_with_org(
        notary_did.clone(),
        vec![arkret_identifiers::Did::new(
            "did:webvh:z6mkfixture:recovery.soland.local".to_owned(),
        )?],
        arkret_identifiers::Did::new(
            "did:webvh:z6mkfixture:organization.primary.soland.local".to_owned(),
        )?,
        vec![arkret_identifiers::Did::new(
            "did:webvh:z6mkfixture:organization.recovery.soland.local".to_owned(),
        )?],
    );
    let mut realm = arkret_models_collaboration::objects::realm::Realm::new(
        arkret_identifiers::RealmId::new(realm_id.to_owned())?,
        title,
        created_by,
        arkret_identifiers::TypedTrustDomainId::new("ak:trust_domain:soland.local".to_owned())?,
        arkret_wire::CORE_REDUCER_PROFILE,
        arkret_models_collaboration::objects::realm::NotaryProfile::SingleDid,
        notary,
        arkret::current_capability_action_registry_digest()?,
    );
    realm.summary = Some(summary.to_owned());
    realm.schema_refs = serde_json::from_value(Value::Array(schema_refs))?;
    realm.default_discoverability = serde_json::from_value(json!(discoverability))?;
    realm.default_join_rule = serde_json::from_value(json!(join_rule))?;
    realm.history_visibility = serde_json::from_value(json!(history_visibility))?;
    realm.encryption_profile = serde_json::from_value(json!(encryption_profile))?;
    realm.security_class = Some(serde_json::from_value(json!("standard"))?);
    realm.federation_policy = Some(serde_json::from_value(json!("restricted"))?);
    realm.created_at = chrono::DateTime::parse_from_rfc3339("2026-05-02T00:00:00.000Z")?
        .with_timezone(&chrono::Utc);
    if let Some(sync_endpoints) = input.get("sync_endpoints").filter(|value| value.is_array()) {
        realm.sync_endpoints = serde_json::from_value(sync_endpoints.clone())?;
    }
    realm.validate_kind_invariants()?;
    // R3.1: a create payload carries no object id — the Realm id is derived
    // from the genesis Event (spec realm-and-space.md section 2.5.0).
    realm.id = None;
    Ok((
        arkret_models_collaboration::events_payloads::RealmCreatePayload::new(realm),
        plaintext_visible_services,
    ))
}
