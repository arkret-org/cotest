//! Complement-style black-box conformance harness for Arkret servers.
//!
//! This module is organized into focused submodules:
//! - [`server`]: [`ArkretServer`]/[`TestServerGroup`] process/Docker orchestration.
//! - [`client`]: [`TestActorClient`] and its request helpers.
//! - [`assertions`]: HTTP assertion family and the recording/transcript machinery.
//! - [`event_builder`]: token-based event constructors and account helpers.
//! - [`invite_delivery`]: private invite dispatch / credential read-back helpers.
//! - [`proof`]: canonical event digest / proof refresh.

use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::Result;
use serde_json::{Value, json};

mod assertions;
mod client;
mod event_builder;
mod invite_delivery;
mod principal;
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
    add_member, auth_context_key_id, create_realm, create_realm_with_signing_seed,
    default_event_verification_method, dev_login, device_message_send_request, encrypted_envelope,
    event_envelope, event_envelope_at_frontier_with_signing_seed, event_envelope_with_signing_seed,
    event_envelope_with_signing_seed_and_verification_method, head_eq_precondition,
    moderation_report_request, realm_bootstrap_event_batch,
    realm_bootstrap_event_batch_with_signing_seed, register_account,
    register_account_with_localpart, register_event_signing_identity, send_message, submit_event,
    submit_event_with_signing_seed_and_verification_method,
};
pub(crate) use event_builder::{
    event_envelope_with_chain, invite_create_payload, member_join_payload_value,
    member_transition_payload, message_create_text_payload, message_create_text_payload_for_strand,
    message_redact_payload, message_revise_text_payload, parse_strand_id,
    prepare_event_submission_with_signing_identity,
};
pub use invite_delivery::dispatch_accepted_invite_and_read_token;
pub use principal::ProvisionedTestPrincipal;
pub use proof::{
    attach_signal_proof, attach_signal_proof_value, refresh_typed_event_proof,
    refresh_typed_event_proof_with_signing_seed,
};
pub use server::{ArkretServer, TestServerGroup};
pub(crate) use server::{ReservedPort, reserve_port};
pub use wire_body::{CanonicalJsonBody, NonProtocolTestBody, wire_negative_from_sdk};

static NEXT_EVENT_SEQ: AtomicU64 = AtomicU64::new(1);

pub fn query_method() -> reqwest::Method {
    reqwest::Method::from_bytes(b"QUERY").expect("QUERY is a valid HTTP method")
}

pub fn actor_core_id(actor: &str) -> Result<String> {
    let full_id = arkret_identifiers::DidFullId::new(actor.to_owned())?;
    Ok(arkret_identifiers::project_full_id_to_core_id(&full_id)?.to_string())
}

/// Read the one canonical Event id from a single-Event submit outcome.
///
/// Exact replay reports the id in `duplicate[]`; first admission reports it in
/// `accepted[]`. The retired top-level `event_id` mirror is deliberately not
/// recognized.
pub fn submitted_event_id(outcome: &Value) -> Result<arkret_identifiers::EventId> {
    let accepted = outcome
        .get("accepted")
        .and_then(Value::as_array)
        .into_iter()
        .flatten();
    let duplicate = outcome
        .get("duplicate")
        .and_then(Value::as_array)
        .into_iter()
        .flatten();
    let mut ids = accepted.chain(duplicate);
    let first = ids.next().and_then(Value::as_str).ok_or_else(|| {
        anyhow::anyhow!("single-Event submit outcome names no accepted/duplicate Event: {outcome}")
    })?;
    if ids.next().is_some() {
        anyhow::bail!(
            "single-Event submit outcome names multiple accepted/duplicate Events: {outcome}"
        );
    }
    Ok(arkret_identifiers::EventId::new(first.to_owned())?)
}

pub fn events_frontier_request_body(
    actor_id: &str,
    realm_id: Option<&str>,
) -> Result<arkret_models_collaboration::event_query::EventsFrontierRequestBody> {
    Ok(
        arkret_models_collaboration::event_query::EventsFrontierRequestBody {
            actor_id: arkret_identifiers::DidFullId::new(actor_id.to_owned())
                .and_then(|full_id| arkret_identifiers::project_full_id_to_core_id(&full_id))?,
            realm_id: realm_id
                .map(|value| arkret_identifiers::RealmId::new(value.to_owned()))
                .transpose()?,
        },
    )
}

pub fn events_query_for_realm(
    realm_id: &str,
    limit: u32,
) -> Result<arkret_models_collaboration::event_query::EventsQueryPostRequestBody> {
    Ok(
        arkret_models_collaboration::event_query::EventsQueryPostRequestBody {
            realms: vec![arkret_identifiers::RealmId::new(realm_id.to_owned())?],
            limit: Some(limit),
            ..Default::default()
        },
    )
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

pub(crate) fn next_typed_id(kind: &str) -> String {
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

#[derive(Clone)]
pub struct RealmBootstrapDraft {
    pub create: arkret_models_collaboration::events_payloads::RealmCreatePayload,
    pub profile: arkret_models_collaboration::events_payloads::RealmProfile,
    pub policy_bundle:
        arkret_models_collaboration::events_payloads::realm::RealmPolicyBundlePayload,
    pub join_rule:
        arkret_models_collaboration::governance::realm_lifecycle::RealmJoinRulePayload,
    pub history_access:
        arkret_models_collaboration::governance::realm_lifecycle::HistoryAccessPayload,
    pub discovery:
        arkret_models_collaboration::governance::realm_lifecycle::RealmDiscoveryPayload,
    pub alias:
        Option<arkret_models_collaboration::governance::realm_governance::RealmAliasPayload>,
    pub plaintext_visible_services: Option<
        arkret_models_collaboration::governance::plaintext_visibility::PlaintextVisibleServicesPayload,
    >,
    pub delivery_binding_policy:
        arkret_models_collaboration::events_payloads::realm::RealmDeliveryBindingPolicyPayload,
}

pub fn realm_create_payload(service_id: &str, input: &Value) -> Result<RealmBootstrapDraft> {
    let notary_actor_id = arkret_identifiers::DidCoreId::new(service_id.to_owned())?;
    realm_create_payload_with_notary(
        service_id,
        input,
        crate::fixture_notary_signer(notary_actor_id),
    )
}

pub fn realm_create_payload_with_notary(
    service_id: &str,
    input: &Value,
    notary_signer: arkret_wire::NotarySignerDescriptor,
) -> Result<RealmBootstrapDraft> {
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
    let history_access_value = input
        .get("history_access")
        .and_then(Value::as_str)
        .unwrap_or("since_join");
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

    let notary = arkret_wire::notary::NotaryValue::SingleSigner {
        signer: notary_signer,
        recovery_members: vec![crate::fixture_notary_signer(
            arkret_identifiers::DidCoreId::new("ak:did_core:web:recovery.soland.local")?,
        )],
        controller_organization: Some(arkret_identifiers::DidCoreId::new(
            "ak:did_core:web:organization.primary.soland.local",
        )?),
        recovery_controller_organizations: vec![arkret_identifiers::DidCoreId::new(
            "ak:did_core:web:organization.recovery.soland.local",
        )?],
    };
    let genesis_salt = input
        .get("genesis_salt")
        .and_then(Value::as_str)
        .map(arkret_wire::GenesisSalt::new)
        .transpose()?
        .unwrap_or(arkret_wire::GenesisSalt::generate()?);
    let trust_domain = input
        .get("trust_domain")
        .and_then(Value::as_str)
        .unwrap_or("ak:trust_domain:soland.local");
    let genesis = arkret_models_collaboration::events_payloads::RealmGenesis::event_derived(
        arkret_models_collaboration::events_payloads::RealmPurpose::Collaboration,
        genesis_salt,
        arkret_identifiers::TrustDomainId::new(trust_domain.to_owned())?,
        serde_json::from_value(Value::Array(schema_refs))?,
        arkret_wire::CORE_REDUCER_PROFILE,
        arkret_canonical::DigestSuite::Sha256,
        serde_json::from_value(json!("standard"))?,
        serde_json::from_value(json!(encryption_profile))?,
        notary,
        arkret::current_capability_action_registry_digest()?,
    )?;
    let mut profile = arkret_models_collaboration::events_payloads::RealmProfile::new(title)?;
    profile.summary = Some(summary.to_owned());
    let mut policy_bundle =
        arkret_models_collaboration::events_payloads::realm::RealmPolicyBundlePayload::new(1);
    // `content_scheme` is frozen by the accepted MLS group Genesis and is not a
    // policy-bundle component (realm-and-space.md section 2.3).
    let encryption_floor = if encryption_profile == "mls_rfc9420" {
        arkret_models_collaboration::governance::circle::EncryptionFloor::E2eeRequired
    } else {
        arkret_models_collaboration::governance::circle::EncryptionFloor::AllowPlaintext
    };
    policy_bundle.content_encryption_floor = Some(encryption_floor);
    policy_bundle.metadata_encryption_floor = Some(encryption_floor);
    policy_bundle.federation_policy = Some(serde_json::from_value(
        input
            .get("federation_policy")
            .cloned()
            .unwrap_or_else(|| json!("restricted")),
    )?);
    policy_bundle.validate()?;
    let history_access =
        arkret_models_collaboration::governance::realm_lifecycle::HistoryAccessPayload::initialize(
            serde_json::from_value(json!(history_access_value))?,
        );
    history_access.validate()?;
    let alias = input
        .get("alias")
        .and_then(Value::as_str)
        .map(|value| {
            let authority_service_full_id = input
                .get("alias_authority_service_full_id")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    arkret_wire::WireError::Protocol(
                        "cotest Realm bootstrap alias requires alias_authority_service_full_id"
                            .to_owned(),
                    )
                })?;
            let authority = arkret_models_collaboration::objects::realm_alias::RealmAlias::authority_domain_for_service(authority_service_full_id)?;
            let alias = arkret_models_collaboration::objects::realm_alias::RealmAlias::prepare_under_authority(value, &authority)?;
            Ok::<_, arkret_wire::WireError>(
                arkret_models_collaboration::governance::realm_governance::RealmAliasPayload::declaration(alias),
            )
        })
        .transpose()?;
    let delivery_binding_policy = input
        .get("delivery_binding_policy")
        .cloned()
        .map(serde_json::from_value)
        .transpose()?
        .unwrap_or(
            arkret_models_collaboration::events_payloads::realm::RealmDeliveryBindingPolicyPayload {
                realm_id: None,
                allowed_binding_sources: None,
                did_document_default_allowed: None,
                allowed_recipient_services: None,
                required_endorsers: None,
                unroutable_membership_allowed: Some(true),
                rebind_authorization: None,
                handover_grace_seconds: None,
                expires_after_seconds: None,
            },
        );
    Ok(RealmBootstrapDraft {
        create: arkret_models_collaboration::events_payloads::RealmCreatePayload::new(genesis),
        profile,
        policy_bundle,
        join_rule:
            arkret_models_collaboration::governance::realm_lifecycle::RealmJoinRulePayload::new(
                serde_json::from_value(json!(join_rule))?,
            ),
        history_access,
        discovery:
            arkret_models_collaboration::governance::realm_lifecycle::RealmDiscoveryPayload::new(
                serde_json::from_value(json!(discoverability))?,
            ),
        alias,
        plaintext_visible_services,
        delivery_binding_policy,
    })
}
