//! Complement-style black-box conformance harness for Cokret servers.
//!
//! This module is organized into focused submodules:
//! - [`server`]: [`CokretServer`]/[`TestServerGroup`] process/Docker orchestration.
//! - [`client`]: [`TestActorClient`] and its request helpers.
//! - [`assertions`]: HTTP assertion family and the recording/transcript machinery.
//! - [`event_builder`]: token-based event constructors and account helpers.
//! - [`proof`]: canonical event digest / proof refresh.

use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::{Value, json};

mod assertions;
mod client;
mod event_builder;
mod proof;
mod server;

pub use assertions::{
    RecordedResponse, account_subscribe_delta_from_text, eventually,
    expect_account_subscribe_delta, expect_api_error, expect_audit_action,
    expect_indistinguishable_api_errors, expect_json, expect_response, expect_status, expect_text,
};
pub use client::TestActorClient;
pub use event_builder::{
    add_member, create_realm, dev_login, encrypted_envelope, event_envelope, register_account,
    send_message, submit_event,
};
// `canonical_event_digest` has no current caller outside `proof`, but the
// harness contract keeps it reachable as `crate::harness::canonical_event_digest`.
#[allow(unused_imports)]
pub(crate) use proof::canonical_event_digest;
pub(crate) use proof::refresh_event_proof;
pub use proof::{attach_ephemeral_proof, attach_ephemeral_proof_value};
pub use server::{CokretServer, TestServerGroup};
pub(crate) use server::{ReservedPort, reserve_port};

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
    if input.starts_with("ck:device:") {
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
        _ => return format!("ck:device:01904100-0000-7000-8000-{:012x}", fnv1a_48(input)),
    };
    format!("ck:device:01904100-0000-7000-8000-{suffix}")
}

fn fnv1a_48(input: &str) -> u64 {
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in input.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash & 0x0000_ffff_ffff_ffff
}

/// Canonical `ck.member.state` join payload shared by the harness `add_member`
/// helpers so the member.state default shape lives in one place.
pub(crate) fn member_join_payload(realm_id: &str, actor_id: &str) -> Value {
    json!({
        "realm_id": realm_id,
        "actor_id": actor_id,
        "membership": "join",
        "delivery_status": "unroutable"
    })
}

fn next_typed_id(kind: &str) -> String {
    let seq = NEXT_EVENT_SEQ.fetch_add(1, Ordering::Relaxed);
    format!("ck:{kind}:01999999-0000-7000-8000-{seq:012x}")
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
        Some(service_did) => json!({
            "service_did": service_did,
            "service_type": "principal_server",
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

fn realm_create_payload(actor: &str, service_did: &str, realm_id: &str, input: &Value) -> Value {
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
    let plaintext_visible_services = input
        .get("plaintext_visible_services")
        .cloned()
        .filter(Value::is_array)
        .unwrap_or_else(|| json!([service_did]));
    let plaintext_visible_services = Value::Array(
        plaintext_visible_services
            .as_array()
            .map(|items| {
                items
                    .iter()
                    .map(normalize_plaintext_visible_service)
                    .collect()
            })
            .unwrap_or_default(),
    );

    let mut object = json!({
        "id": realm_id,
        "schema": "ck.schema.realm.v1",
        "title": title,
        "summary": summary,
        "created_by": actor,
        "trust_domain": "ck:trust_domain:soland.local",
        "schema_refs": ["ck.schema.realm.v1"],
        "default_discoverability": discoverability,
        "default_join_rule": join_rule,
        "history_visibility": history_visibility,
        "encryption_profile": encryption_profile,
        "plaintext_visible_services": plaintext_visible_services,
        "security_class": "standard",
        "federation_policy": "restricted",
        "notary_profile": "single_did",
        "digest_algorithm": "sha256",
        "notary": {
            "type": "single_did",
            "did": actor,
            "recovery_members": ["did:webvh:z6mkfixture:recovery.soland.local"],
            "controller_organization": "did:webvh:z6mkfixture:organization.primary.soland.local",
            "recovery_controller_organizations": [
                "did:webvh:z6mkfixture:organization.recovery.soland.local"
            ],
        },
        "created_at": "2026-05-02T00:00:00Z",
    });
    // Realm-level `sync_endpoints` (ck.schema.realm.v1#/properties/sync_endpoints):
    // shared notary / sync / mirror / federation-peer service bindings. Passed
    // through verbatim so federation tests can authorise a peer service as a
    // `federation_peer` endpoint (member-delivery-binding.md §7 — orthogonal to
    // member-level delivery_binding).
    if let Some(sync_endpoints) = input.get("sync_endpoints").filter(|value| value.is_array()) {
        object
            .as_object_mut()
            .expect("realm object literal")
            .insert("sync_endpoints".to_owned(), sync_endpoints.clone());
    }
    json!({ "object": object })
}
