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
pub(crate) use server::free_port;
pub use server::{CokretServer, TestServerGroup};

static NEXT_EVENT_SEQ: AtomicU64 = AtomicU64::new(1);

/// Canonical `ck.member.state` join payload shared by the harness `add_member`
/// helpers so the member.state default shape lives in one place.
pub(crate) fn member_join_payload(actor_id: &str) -> Value {
    json!({
        "actor_id": actor_id,
        "membership": "join",
        "delivery_status": "unroutable"
    })
}

fn next_typed_id(kind: &str) -> String {
    let seq = NEXT_EVENT_SEQ.fetch_add(1, Ordering::Relaxed);
    format!("ck:{kind}:01999999-0000-7000-8000-{seq:012x}")
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
    let plaintext_visible_services = input
        .get("plaintext_visible_services")
        .cloned()
        .filter(Value::is_array)
        .unwrap_or_else(|| json!([service_did]));

    json!({
        "object": {
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
            "anchor_profile": "single_did",
            "digest_algorithm": "sha256",
            "anchorer": {
                "type": "single_did",
                "did": actor,
                "recovery_members": ["did:web:recovery.soland.local"],
                "controller_organization": "did:web:organization.primary.soland.local",
                "recovery_controller_organizations": [
                    "did:web:organization.recovery.soland.local"
                ],
            },
            "created_at": "2026-05-02T00:00:00Z",
        },
    })
}
