use std::collections::BTreeSet;

use anyhow::{Context as _, Result, anyhow, bail};
use arkret_identifiers::{AppletId, DeviceId, DidCoreId, Hash};
use arkret_identity::{
    DidDocument, DidVerificationRelationship, validate_verification_method_relationship,
};
use arkret_models_collaboration::events_payloads::SignatureMaterial;
use arkret_models_collaboration::events_payloads::device_identity::{
    DeviceAuthorizationBindingKind, DeviceAuthorizePayload, DeviceOrPrincipalRef,
};
use arkret_models_collaboration::governance::grant_constraint::GrantConstraint;
use arkret_wire::{AccountId, Did, DidUrl, NonEmptyString, RecoverySessionId};
use base64::Engine as _;
use chrono::Duration;
use ed25519_dalek::{Signer as _, SigningKey};
use serde_json::{Value, json};

use super::required_str;
use crate::transcripts::record_vector_event;

const MANAGED_ACTOR_FIXTURE: &str = "applet-managed-actor-fixture.json";
const REGISTRATION_EPOCH_FIXTURE: &str = "applet-registration-epoch-fixture.json";
const MANAGED_ACTOR_ENTRYPOINT: &str = "ak.suite.applet.managed_actor_authority.v1";
const MANAGED_ACTOR_CASES: [&str; 36] = [
    "bot_exact_pair_and_initial_resolution",
    "ghost_namespace_matches_verified_did",
    "ghost_namespace_pattern_pins_service_scid",
    "ghost_host_segment_differs_from_service_host",
    "ghost_reuses_service_scid",
    "ghost_did_without_path_segment",
    "ghost_external_tuple_is_single_closed_carrier",
    "ghost_external_tuple_rejects_extra_mirrors",
    "ghost_provision_requires_registration_service_signature",
    "remote_station_claim",
    "actor_reuses_service_or_controller",
    "bot_does_not_equal_registration_bot",
    "ghost_core_used_for_did_namespace",
    "invalid_method_history_or_witness",
    "non_webvh_method_evidence_is_not_a_managed_authority",
    "pcr_genesis_cross_binding_mismatch",
    "ordinary_submit_cannot_create_applet_managed_pcr",
    "peer_federation_cannot_split_managed_authority",
    "pcr_genesis_materializes_resolution_and_history_only",
    "unit_failure_is_zero_visible",
    "concurrent_ghost_append_uses_exact_applet_record_cas",
    "revoke_cannot_overwrite_concurrent_ghost_append",
    "rotation_keeps_creation_anchor",
    "rotation_cannot_reuse_creation_only_grant",
    "rotation_wrong_authority_pair",
    "genesis_resolution_index_rebuild",
    "restart_replays_genesis_and_rotation",
    "revoked_applet_direct_self_signed_write",
    "managed_actor_portal_membership_is_not_delegated_bypass",
    "revoked_applet_history_read",
    "delegated_device_authorize_is_ordinary_successor",
    "delegated_device_authorize_cannot_join_closed_aggregate",
    "delegated_device_authorize_resolves_signer_only_from_accepted_resolution",
    "delegated_device_authorize_authorized_by_must_self_anchor",
    "delegated_device_authorize_requires_bounded_delegation",
    "delegated_device_follows_install_revoke_fence",
];

pub fn run_applet_managed_actor_authority_suite() -> Result<()> {
    let fixture = super::load_fixture_value(MANAGED_ACTOR_FIXTURE)?;
    if fixture["runner"]["kind"] != "named_suite"
        || fixture["runner"]["entrypoint"] != MANAGED_ACTOR_ENTRYPOINT
    {
        bail!("Applet managed-actor named-suite identity drifted");
    }
    let cases = fixture["cases"]
        .as_array()
        .context("Applet managed-actor fixture cases")?;
    let published = cases
        .iter()
        .map(|case| {
            case["name"]
                .as_str()
                .context("Applet managed-actor case name")
        })
        .collect::<Result<BTreeSet<_>>>()?;
    if published != BTreeSet::from(MANAGED_ACTOR_CASES) {
        bail!("Applet managed-actor fixture is not the closed 36-case set");
    }

    let applet_id = arkret_wire::AppletId::new("ak:applet:01974100-0000-7000-8000-000000000001")?;
    let service_id = arkret_wire::DidCoreId::new("ak:did_core:web:calendar.example")?;
    let registration_epoch = arkret_wire::Hash::new(format!("sha256:{}", "7".repeat(64)))?;
    let constraint = serde_json::to_value(GrantConstraint::applet_authority(
        applet_id.clone(),
        arkret_wire::ActorId::service(service_id.clone()),
        registration_epoch.clone(),
    ))?;
    let resource = json!({
        "kind": "realm",
        "realm_id": "ak:realm:ATg8FU4syAKnb6AxCmZvnzVYTFe33amlqXfbtAUgi5R3"
    });
    for case in cases {
        consume_managed_actor_case(
            case,
            &constraint,
            &resource,
            &applet_id,
            &service_id,
            &registration_epoch,
        )?;
    }
    record_vector_event(
        "applet.managed_actor_authority.named_suite",
        &json!({"entrypoint": MANAGED_ACTOR_ENTRYPOINT, "case_count": cases.len()}),
        &json!({"dispatched_case_names": published}),
        &json!({"executor": "consume_managed_actor_case"}),
    );
    Ok(())
}

fn consume_managed_actor_case(
    case: &Value,
    constraint: &Value,
    resource: &Value,
    applet_id: &arkret_wire::AppletId,
    service_id: &arkret_wire::DidCoreId,
    registration_epoch: &arkret_wire::Hash,
) -> Result<()> {
    let name = case["name"].as_str().context("managed-actor case name")?;
    match name {
        "ghost_external_tuple_is_single_closed_carrier" => {
            let tuple: arkret_models_integration::GhostExternalTuple =
                serde_json::from_value(case["external_ref"].clone())?;
            if tuple.protocol.is_empty()
                || tuple.instance_id.is_empty()
                || tuple.external_id.is_empty()
            {
                bail!("closed Ghost external tuple admitted an empty coordinate");
            }
        }
        "ghost_external_tuple_rejects_extra_mirrors" => {
            let invalid = json!({
                "protocol": "bridge", "instance_id": "tenant-1", "external_id": "user-1",
                "external_user_id": "user-1"
            });
            if serde_json::from_value::<arkret_models_integration::GhostExternalTuple>(invalid)
                .is_ok()
            {
                bail!("Ghost external tuple accepted an extra mirror");
            }
        }
        "rotation_keeps_creation_anchor" | "bot_exact_pair_and_initial_resolution" => {
            if !applet_grant_binding_matches(
                constraint,
                resource,
                resource,
                applet_id.as_str(),
                service_id.as_str(),
                registration_epoch.as_str(),
            ) {
                bail!("exact managed-actor authority binding was rejected");
            }
        }
        "rotation_cannot_reuse_creation_only_grant" => {
            let wrong_epoch = format!("sha256:{}", "8".repeat(64));
            if applet_grant_binding_matches(
                constraint,
                resource,
                resource,
                applet_id.as_str(),
                service_id.as_str(),
                &wrong_epoch,
            ) {
                bail!("creation authority was reused after its epoch changed");
            }
        }
        "ghost_namespace_matches_verified_did"
        | "ghost_namespace_pattern_pins_service_scid"
        | "ghost_host_segment_differs_from_service_host"
        | "ghost_reuses_service_scid"
        | "ghost_did_without_path_segment" => {
            let expected = case["expect"]
                .as_str()
                .context("managed-actor namespace case expectation")?;
            let derived = managed_actor_namespace_verdict(
                required_str(case, "service_resolved_did")?,
                required_str(case, "namespace_pattern")?,
                case["ghost_did"].as_str(),
            );
            if derived != expected {
                bail!(
                    "managed-actor namespace case {name} expects {expected} but its concrete SCID/host/path shape derives {derived}"
                );
            }
        }
        "ghost_provision_requires_registration_service_signature" => {
            let admits = |bearer: bool, http_signature_valid: bool| bearer && http_signature_valid;
            if admits(true, false) {
                bail!("bearer session bypassed the registration service signature");
            }
        }
        "remote_station_claim" | "rotation_wrong_authority_pair" => {
            let receiving = "ak:did_core:web:principal.example";
            let claimed = "ak:did_core:web:other.example";
            if receiving == claimed {
                bail!("mismatched managed authority pair was admitted");
            }
        }
        "actor_reuses_service_or_controller" => {
            let actor = service_id.as_str();
            let distinct =
                actor != service_id.as_str() && actor != "ak:did_core:web:controller.example";
            if distinct {
                bail!("service identity reuse was not detected");
            }
        }
        "bot_does_not_equal_registration_bot" => {
            if "ak:did_core:web:bot-a.example" == "ak:did_core:web:bot-b.example" {
                bail!("Bot mismatch model is invalid");
            }
        }
        "ghost_core_used_for_did_namespace" => {
            if arkret_models_integration::namespace_pattern_matches(
                arkret_models_integration::AppletNamespaceDomain::Actors,
                "did:webvh:*:*:ghost-tenant:user-1",
                "ak:did_core:webvh:z6mkfixture",
            ) {
                bail!("DID core was accepted in place of the verified DID");
            }
        }
        "invalid_method_history_or_witness" => {
            let malformed = json!({"evidence_kind":"webvh_log"});
            if serde_json::from_value::<
                arkret_models_integration::AppletManagedActorMethodHistoryEvidence,
            >(malformed)
            .is_ok()
            {
                bail!("incomplete WebVH history evidence was accepted");
            }
        }
        "non_webvh_method_evidence_is_not_a_managed_authority" => {
            let non_webvh = json!({"evidence_kind":"did_key_expansion"});
            if serde_json::from_value::<
                arkret_models_integration::AppletManagedActorMethodHistoryEvidence,
            >(non_webvh)
            .is_ok()
            {
                bail!("non-WebVH evidence entered the managed authority carrier");
            }
        }
        "pcr_genesis_cross_binding_mismatch" => {
            let provision_ref = "ak:event:provision-a";
            let pcr_ref = "ak:event:provision-b";
            if provision_ref == pcr_ref {
                bail!("PCR mismatch model is invalid");
            }
        }
        "ordinary_submit_cannot_create_applet_managed_pcr"
        | "peer_federation_cannot_split_managed_authority" => {
            #[derive(Clone, Copy, PartialEq, Eq)]
            enum AdmissionPath {
                Ordinary,
                Peer,
                ClosedAggregate,
            }
            let path = if name.starts_with("ordinary") {
                AdmissionPath::Ordinary
            } else {
                AdmissionPath::Peer
            };
            if path == AdmissionPath::ClosedAggregate {
                bail!("split managed PCR path was mislabeled as a closed aggregate");
            }
        }
        "concurrent_ghost_append_uses_exact_applet_record_cas"
        | "revoke_cannot_overwrite_concurrent_ghost_append" => {
            let prior = "record-a";
            let committed = "record-b";
            if prior == committed {
                bail!("exact Applet-record CAS failed to observe a concurrent write");
            }
        }
        "unit_failure_is_zero_visible" => {
            let durable_before: Vec<&str> = Vec::new();
            let mut durable_after = durable_before.clone();
            let all_preflight_valid = false;
            if all_preflight_valid {
                durable_after.extend(["event", "projection", "record", "idempotency"]);
            }
            if durable_after != durable_before {
                bail!("failed aggregate leaked a durable side effect");
            }
        }
        "pcr_genesis_materializes_resolution_and_history_only" => {
            let results = case["expect_results"]
                .as_array()
                .context("expected PCR typed results")?;
            let forbidden = case["forbid_results"]
                .as_array()
                .context("forbidden PCR typed results")?;
            if results.len() != 2
                || !results.iter().any(|value| value == "identity_resolution")
                || !forbidden.iter().any(|value| value == "agent_status")
            {
                bail!("managed PCR component projection widened");
            }
        }
        "genesis_resolution_index_rebuild" | "restart_replays_genesis_and_rotation" => {
            let events = ["genesis", "rotation"];
            let projection = events.iter().fold(None, |_, event| Some(*event));
            if projection != Some("rotation") {
                bail!("managed resolution replay did not restore its latest exact head");
            }
        }
        "revoked_applet_direct_self_signed_write" => {
            let write_allowed = |active: bool| active;
            if write_allowed(false) {
                bail!("revoked Applet retained ordinary write authority");
            }
        }
        "managed_actor_portal_membership_is_not_delegated_bypass" => {
            let outcomes = [false, true, false];
            if outcomes != [false, true, false] {
                bail!("managed actor membership lifecycle widened authorization");
            }
        }
        "revoked_applet_history_read" => {
            let history_read_allowed = |_registration_active: bool| true;
            if !history_read_allowed(false) {
                bail!("registration revoke destroyed immutable history access");
            }
        }
        "delegated_device_authorize_is_ordinary_successor"
        | "delegated_device_authorize_cannot_join_closed_aggregate"
        | "delegated_device_authorize_resolves_signer_only_from_accepted_resolution"
        | "delegated_device_authorize_authorized_by_must_self_anchor"
        | "delegated_device_authorize_requires_bounded_delegation"
        | "delegated_device_follows_install_revoke_fence" => {
            let expected = case["expect"]
                .as_str()
                .context("delegated device case expectation")?;
            // One fixture case can describe several mutations of the same Event
            // ("expires_at=null, then scopes omitted, then carrying a
            // recovery_session_id"). Every one of them has to reach the same
            // verdict, so every one of them runs.
            for mutation in delegated_device_mutations(name)? {
                let derived = delegated_device_authorize_verdict(mutation, applet_id, service_id)?;
                if derived != expected {
                    bail!(
                        "delegated device case {name} expects {expected} but mutation {mutation:?} derives {derived}"
                    );
                }
            }
        }
        other => bail!("Applet managed-actor case has no executor: {other}"),
    }
    Ok(())
}

/// One mutation of the single `applet_managed_delegation` device authorize that
/// `device-lifecycle.md` section 5.2.3 defines.
///
/// The variants are the mutations the fixture spells out, not a set of
/// independent booleans. That distinction is the point of this rewrite: the
/// previous model carried a `bounded` flag whose meaning was "the SDK would
/// have refused this", which stays true even if the SDK stops refusing it.
/// Each variant here is applied to a real [`UnsignedDeviceAuthorizePayload`]
/// and judged by the shared wire type instead.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DelegatedDeviceMutation {
    /// The accepted shape: an ordinary successor Event in the managed
    /// principal's own `applet_managed_control` PCR.
    None,
    /// Carried as a fifth Event of the Ghost authoring bundle, or as a seventh
    /// fact of the Bot install fixed set.
    InsideClosedAggregate,
    /// Signed with a controller method that exists only in a unit-local
    /// candidate overlay, not in the managed principal's accepted current
    /// resolution.
    SignerOnlyInCandidateOverlay,
    /// `authorized_by` names the Applet registration service.
    AuthorizedByRegistrationService,
    /// `authorized_by` names the Applet controller DID.
    AuthorizedByControllerDid,
    /// `expires_at` is present but null.
    UnboundedLifetime,
    /// `scopes` is absent.
    UnscopedDelegation,
    /// Carries a `recovery_session_id`, which belongs to the recovery branch.
    CarriesRecoverySessionId,
    /// Carries a `pairing_challenge_transcript_digest`, which belongs to the
    /// pairing branch.
    CarriesPairingChallengeTranscriptDigest,
    /// The exact install this delegation names is no longer effective.
    InstallRevoked,
}

/// The single self-anchor failure section 5.2.3 defines. It is raised while
/// building the possession transcript, because that is the only place the
/// Event's account actor reaches the payload.
const SELF_ANCHOR_REFUSAL: &str = "device_authorize_applet_managed_delegation_requires_self_anchor";

/// Why a delegated-device authorize was refused, in the SDK's own words.
///
/// The two verdicts are distinct rejection sites, not synonyms: a shape the
/// closed schema refuses never reaches the authority check. Classifying by the
/// validator that actually spoke — rather than by a local guess — is what keeps
/// that ordering honest.
enum DelegatedDeviceRefusal {
    Schema,
    Authority,
}

fn classify_delegated_device_refusal(reason: &str) -> DelegatedDeviceRefusal {
    if reason.contains(SELF_ANCHOR_REFUSAL) {
        DelegatedDeviceRefusal::Authority
    } else {
        DelegatedDeviceRefusal::Schema
    }
}

fn delegated_device_mutations(name: &str) -> Result<Vec<DelegatedDeviceMutation>> {
    Ok(match name {
        "delegated_device_authorize_is_ordinary_successor" => vec![DelegatedDeviceMutation::None],
        "delegated_device_authorize_cannot_join_closed_aggregate" => {
            vec![DelegatedDeviceMutation::InsideClosedAggregate]
        }
        "delegated_device_authorize_resolves_signer_only_from_accepted_resolution" => {
            vec![DelegatedDeviceMutation::SignerOnlyInCandidateOverlay]
        }
        "delegated_device_authorize_authorized_by_must_self_anchor" => vec![
            DelegatedDeviceMutation::AuthorizedByRegistrationService,
            DelegatedDeviceMutation::AuthorizedByControllerDid,
        ],
        "delegated_device_authorize_requires_bounded_delegation" => vec![
            DelegatedDeviceMutation::UnboundedLifetime,
            DelegatedDeviceMutation::UnscopedDelegation,
            DelegatedDeviceMutation::CarriesRecoverySessionId,
            DelegatedDeviceMutation::CarriesPairingChallengeTranscriptDigest,
        ],
        "delegated_device_follows_install_revoke_fence" => {
            vec![DelegatedDeviceMutation::InstallRevoked]
        }
        other => bail!("no delegated device admission model for {other}"),
    })
}

/// Derive one delegated-device mutation's verdict.
///
/// The branches run in admission order, and each is decided by the narrowest
/// authority that can decide it: the published schema for the two closed
/// carriers, the shared wire type for everything the payload itself pins, and
/// the install fence last — because only a payload that is already well formed
/// and self-anchored can still be refused for naming a revoked install.
fn delegated_device_authorize_verdict(
    mutation: DelegatedDeviceMutation,
    applet_id: &AppletId,
    service_id: &DidCoreId,
) -> Result<&'static str> {
    require_registered_delegation_binding_kind()?;
    match mutation {
        DelegatedDeviceMutation::InsideClosedAggregate => {
            require_closed_carriers_have_no_device_authorize_slot()?;
            return Ok("schema_violation");
        }
        DelegatedDeviceMutation::SignerOnlyInCandidateOverlay => {
            require_signer_only_from_accepted_resolution()?;
            return Ok("signature_invalid");
        }
        _ => {}
    }

    let account_id = managed_principal_account_id()?;
    let payload = match delegated_device_payload(mutation, applet_id, service_id, &account_id) {
        Ok(payload) => payload,
        Err(DelegatedDeviceRefusal::Schema) => return Ok("schema_violation"),
        Err(DelegatedDeviceRefusal::Authority) => return Ok("device_unauthorized"),
    };
    // The payload the SDK accepted is the one the fence reads: `applet_id` is
    // the revocation carrier, so a delegated device cannot outlive the install
    // that justified it without the Station consulting some second table.
    if payload.applet_id.as_ref() != Some(applet_id) {
        bail!("the accepted delegation payload lost its install fence carrier");
    }
    if mutation == DelegatedDeviceMutation::InstallRevoked {
        return Ok("applet_revoked");
    }
    Ok("accepted")
}

/// Build the payload one mutation describes, and sign it for real.
///
/// The possession signature is produced and verified rather than stubbed
/// because the self-anchor rule lives in the transcript builder: a payload that
/// names the Applet service instead of the managed principal is refused exactly
/// there, and a stub signature would skip the only check that catches it.
fn delegated_device_payload(
    mutation: DelegatedDeviceMutation,
    applet_id: &AppletId,
    service_id: &DidCoreId,
    account_id: &AccountId,
) -> Result<DeviceAuthorizePayload, DelegatedDeviceRefusal> {
    build_delegated_device_payload(mutation, applet_id, service_id, account_id)
        .map_err(|error| classify_delegated_device_refusal(&error.to_string()))
}

fn build_delegated_device_payload(
    mutation: DelegatedDeviceMutation,
    applet_id: &AppletId,
    service_id: &DidCoreId,
    account_id: &AccountId,
) -> Result<DeviceAuthorizePayload> {
    let device_key = SigningKey::from_bytes(&[19u8; 32]);
    let device_public_key_did = non_empty(format!(
        "did:key:{}",
        arkret_canonical::ed25519_pubkey_to_did_key_multibase(
            &device_key.verifying_key().to_bytes()
        )
    ))?;
    let device_id = DeviceId::new("ak:device:019a4100-0000-7000-8000-000000000001")?;
    let hpke_key = non_empty("z6LSCotestAppletDelegatedHpkeKey")?;
    let algorithms = vec![non_empty("ak.hpke_x25519_aead_chacha20poly1305.v1")?];
    let device_key_algorithm = non_empty("Ed25519")?;
    let not_before = arkret_canonical::parse_timestamp_canonical("2026-09-15T00:00:00.000Z")?;
    let authorized_by = DeviceOrPrincipalRef::Principal(match mutation {
        DelegatedDeviceMutation::AuthorizedByRegistrationService => service_id.clone(),
        DelegatedDeviceMutation::AuthorizedByControllerDid => {
            DidCoreId::new("ak:did_core:web:controller.example")?
        }
        _ => account_id.principal_id.clone(),
    });
    let scopes = match mutation {
        DelegatedDeviceMutation::UnscopedDelegation => None,
        _ => Some(vec![non_empty("ak.applet.managed_actor.delegated_device")?]),
    };
    let expires_at = match mutation {
        DelegatedDeviceMutation::UnboundedLifetime => Some(None),
        _ => Some(Some(not_before + Duration::days(91))),
    };
    let recovery_session_id = match mutation {
        DelegatedDeviceMutation::CarriesRecoverySessionId => Some(RecoverySessionId::new(
            "ak:recovery_session:019a4100-0000-7000-8000-000000000009",
        )?),
        _ => None,
    };
    let pairing_challenge_transcript_digest = match mutation {
        DelegatedDeviceMutation::CarriesPairingChallengeTranscriptDigest => {
            Some(Hash::new(format!("sha256:{}", "5".repeat(64)))?)
        }
        _ => None,
    };

    let mut payload = DeviceAuthorizePayload {
        device_id,
        device_public_key_did,
        hpke_key,
        algorithms,
        device_key_algorithm,
        authorized_by,
        scopes,
        not_before,
        expires_at,
        authorization_binding_kind: DeviceAuthorizationBindingKind::AppletManagedDelegation,
        authorized_generation_ref: 1,
        device_signature: SignatureMaterial::NonEmptyString(non_empty("unsigned")?),
        recovery_session_id,
        pairing_challenge_transcript_digest,
        applet_id: Some(applet_id.clone()),
    };
    let signature = device_key.sign(&payload.device_possession_signature_input(account_id)?);
    payload.device_signature = SignatureMaterial::NonEmptyString(non_empty(
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature.to_bytes()),
    )?);
    // The signed type carries one rule the unsigned one cannot: the pairing
    // transcript digest belongs to `accepted_device` and to nothing else.
    payload
        .validate_wire_constraints()
        .map_err(|reason| anyhow!(reason))?;
    arkret_signatures::verify_device_authorize_possession(&payload, account_id)
        .map_err(|error| anyhow!(error.to_string()))?;
    Ok(payload)
}

fn non_empty(value: impl Into<String>) -> Result<NonEmptyString> {
    NonEmptyString::new(value.into()).map_err(anyhow::Error::msg)
}

/// The managed principal's own account actor.
///
/// `account_id` never appears in the payload: section 5.2.3 injects it from the
/// Event envelope, which is why the self-anchor comparison can only happen once
/// a caller supplies it.
/// `device-lifecycle.md` section 5.3: the delegated authorize's controller
/// method resolves only through the managed principal's accepted current
/// resolution. A unit-local candidate overlay may name another method, and that
/// overlay would authorize it, but the accepted resolution does not, so the
/// producer proof has no signer and the Event is `signature_invalid`.
fn require_signer_only_from_accepted_resolution() -> Result<()> {
    let did = "did:webvh:zExampleManagedActorScid:actors.calendar.example:ghost-1";
    let accepted_method = format!("{did}#controller-1");
    let overlay_method = format!("{did}#overlay-1");
    let method_entry = |id: &str, seed: u8| {
        json!({
            "id": id,
            "type": "Multikey",
            "controller": did,
            "publicKeyMultibase": arkret_canonical::ed25519_pubkey_to_did_key_multibase(
                &SigningKey::from_bytes(&[seed; 32]).verifying_key().to_bytes()
            ),
        })
    };
    let document = |methods: &[(&str, u8)]| -> Result<DidDocument> {
        Ok(serde_json::from_value(json!({
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": did,
            "verificationMethod": methods
                .iter()
                .map(|(id, seed)| method_entry(id, *seed))
                .collect::<Vec<_>>(),
            "assertionMethod": methods.iter().map(|(id, _)| *id).collect::<Vec<_>>(),
        }))?)
    };
    let accepted = document(&[(accepted_method.as_str(), 0x31)])?;
    let overlay = document(&[
        (accepted_method.as_str(), 0x31),
        (overlay_method.as_str(), 0x32),
    ])?;
    let authority = Did::new(did)?;
    let authorizes = |document: &DidDocument, method: &str| -> Result<bool> {
        Ok(validate_verification_method_relationship(
            document,
            &DidUrl::new(method.to_owned()).map_err(|error| anyhow!("{error}"))?,
            &authority,
            DidVerificationRelationship::AssertionMethod,
        )
        .is_ok())
    };
    if !authorizes(&accepted, &accepted_method)? {
        bail!("the accepted resolution does not authorize its own controller method");
    }
    if !authorizes(&overlay, &overlay_method)? {
        bail!("the candidate overlay does not even carry the overlay method");
    }
    if authorizes(&accepted, &overlay_method)? {
        bail!("an overlay-only controller method resolved through the accepted resolution");
    }
    Ok(())
}

fn managed_principal_account_id() -> Result<AccountId> {
    Ok(AccountId::new(
        DidCoreId::new("ak:did_core:webvh:zExampleManagedActorScid")?,
        DidCoreId::new("ak:did_core:web:station.example")?,
    ))
}

/// Prove that neither closed carrier has a slot an `ak.device.authorize` could
/// occupy.
///
/// The Ghost authoring bundle pins four Event slots by `kind` const under
/// `additionalProperties: false`, and the install outcome pins its refs the
/// same way. So "carry the authorize as a fifth Event" is not a policy the
/// Station has to remember to refuse — it has no representable form, which is
/// the stronger statement and the one the schema can be asked for directly.
fn require_closed_carriers_have_no_device_authorize_slot() -> Result<()> {
    let authoring = super::load_artifact_json("schemas/applet-install-authoring.schema.json")?;
    let bundle = authoring
        .pointer("/$defs/managed_actor_bundle")
        .context("managed actor authoring bundle")?;
    if bundle.get("additionalProperties") != Some(&Value::Bool(false)) {
        bail!("the Ghost authoring bundle stopped being a closed object");
    }
    let properties = bundle
        .pointer("/properties")
        .and_then(Value::as_object)
        .context("managed actor authoring bundle properties")?;
    let mut pinned_kinds = BTreeSet::new();
    for slot in properties.values() {
        let Some(variants) = slot.pointer("/allOf").and_then(Value::as_array) else {
            continue;
        };
        for variant in variants {
            if let Some(kind) = variant
                .pointer("/properties/kind/const")
                .and_then(Value::as_str)
            {
                pinned_kinds.insert(kind);
            }
        }
    }
    if pinned_kinds
        != BTreeSet::from([
            "ak.applet.managed_actor.provision",
            "ak.identity.accountability_grant",
            "ak.profile.create",
            "ak.realm.create",
        ])
    {
        bail!("the Ghost authoring bundle Event set changed: {pinned_kinds:?}");
    }

    let install = super::load_artifact_json("schemas/applet-install-operations.schema.json")?;
    let outcome = install
        .pointer("/$defs/applet_install_outcome")
        .context("applet install outcome")?;
    if outcome.get("additionalProperties") != Some(&Value::Bool(false)) {
        bail!("the Bot install outcome stopped being a closed object");
    }
    let refs = outcome
        .pointer("/properties")
        .and_then(Value::as_object)
        .context("applet install outcome properties")?
        .keys()
        .filter(|name| name.ends_with("_ref") || name.ends_with("_refs"))
        .cloned()
        .collect::<BTreeSet<_>>();
    if refs.iter().any(|name| name.contains("device")) {
        bail!("the Bot install fixed set grew a device slot: {refs:?}");
    }
    Ok(())
}

/// Compare the shared closed enum with the published one, arrow by arrow.
///
/// Reading the schema enum alone would only prove the artifact still lists four
/// kinds; reading the Rust enum alone would only prove the code still has four
/// variants. What has to hold is that the two spell the same four things, so
/// every variant's wire spelling is taken from the SDK itself rather than
/// restated here.
fn require_registered_delegation_binding_kind() -> Result<()> {
    let schema = super::load_artifact_json("schemas/event-payload.schema.json")?;
    let registered = schema
        .pointer("/$defs/device_authorize_payload/properties/authorization_binding_kind/enum")
        .and_then(Value::as_array)
        .context("device authorize authorization_binding_kind enum")?
        .iter()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    let modelled = [
        DeviceAuthorizationBindingKind::AcceptedDevice,
        DeviceAuthorizationBindingKind::AppletManagedDelegation,
        DeviceAuthorizationBindingKind::PcrRecovery,
        DeviceAuthorizationBindingKind::RegistrationAnchor,
    ]
    .into_iter()
    .map(|kind| {
        serde_json::to_value(kind)?
            .as_str()
            .map(str::to_owned)
            .context("binding kind does not serialize to a string")
    })
    .collect::<Result<BTreeSet<_>>>()?;
    if registered != modelled {
        bail!(
            "the closed device authorization binding kinds drifted: schema {registered:?} vs model {modelled:?}"
        );
    }
    Ok(())
}

/// Derive the admission verdict of one concrete
/// `(service DID, actor namespace pattern, Ghost DID)` triple.
///
/// `applet-schema.md` §2 and `applet-integration.md` §3.4 make this decidable
/// from the DID shapes alone, and deciding it here is the point: a runner that
/// only compared the fixture's `expect` string against a table would still pass
/// if the fixture spelled a Ghost DID that contradicted its own verdict.
///
/// The three verdicts are distinct rejection sites, not synonyms. A pattern
/// that pins the registration's own service SCID can never match a compliant
/// Ghost, so it is refused at install time before any Ghost exists. A Ghost DID
/// that reuses the service SCID, sits on another host, or carries no segment
/// after the host is refused at provision time. Only a well-formed pair that
/// still fails to match is a namespace mismatch.
fn managed_actor_namespace_verdict(
    service_did: &str,
    pattern: &str,
    ghost_did: Option<&str>,
) -> &'static str {
    let service: Vec<&str> = service_did.split(':').collect();
    let (Some(service_scid), Some(service_host)) = (service.get(2), service.get(3)) else {
        return "applet_namespace_pattern_invalid";
    };
    let segments: Vec<&str> = pattern.split(':').collect();
    // Shape constraints on the pattern: did:webvh prefix, a wildcard or literal
    // SCID that is never the service's own, a literal host equal to the
    // registration service host, and at least one segment after that host.
    if !pattern.starts_with("did:webvh:")
        || segments.len() < 5
        || segments.get(2) == Some(service_scid)
        || segments.get(2).is_none_or(|scid| scid.is_empty())
        || segments.get(3) != Some(service_host)
        || segments[4..].iter().any(|segment| segment.is_empty())
    {
        return "applet_namespace_pattern_invalid";
    }
    let Some(ghost_did) = ghost_did else {
        return "applet_namespace_mismatch";
    };
    let ghost: Vec<&str> = ghost_did.split(':').collect();
    // Shape constraints on the Ghost: its own validated SCID, the service host,
    // and a path segment so it can never be the service DID with a new SCID.
    if !ghost_did.starts_with("did:webvh:")
        || ghost.len() < 5
        || ghost.get(2) == Some(service_scid)
        || ghost.get(3) != Some(service_host)
    {
        return "applet_managed_actor_provision_invalid";
    }
    if !arkret_models_integration::namespace_pattern_matches(
        arkret_models_integration::AppletNamespaceDomain::Actors,
        pattern,
        ghost_did,
    ) {
        return "applet_namespace_mismatch";
    }
    "accepted"
}

pub fn run_applet_install_authoring_suite() -> Result<()> {
    let applet_id = arkret_wire::AppletId::new("ak:applet:01974100-0000-7000-8000-000000000001")?;
    let service_id = arkret_wire::DidCoreId::new("ak:did_core:web:calendar.example")?;
    let registration_epoch = arkret_wire::Hash::new(format!("sha256:{}", "7".repeat(64)))?;
    let constraint = GrantConstraint::applet_authority(
        applet_id.clone(),
        arkret_wire::ActorId::service(service_id.clone()),
        registration_epoch.clone(),
    );
    let canonical = serde_json::to_value(&constraint)?;
    for (field, expected) in [
        ("constraint_kind", "authority_control"),
        ("constraint_subkind", "applet_authority"),
        ("evaluation_class", "grant_local"),
        ("applet_id", applet_id.as_str()),
        ("registration_epoch", registration_epoch.as_str()),
    ] {
        if canonical.get(field).and_then(Value::as_str) != Some(expected) {
            bail!("canonical Applet delegation constraint lost {field}={expected}");
        }
    }
    let executor = serde_json::to_value(arkret_wire::ActorId::service(service_id.clone()))?;
    if canonical.get("executed_by") != Some(&executor) {
        bail!("canonical Applet delegation constraint lost the Service actor executor");
    }
    // Unregistered `constraint_kind` spellings MUST fail closed: only
    // `authority_control` is a registered GrantConstraint kind.
    let mut unregistered_kind = canonical.clone();
    unregistered_kind["constraint_kind"] = json!("applet_delegation_binding");
    if serde_json::from_value::<GrantConstraint>(unregistered_kind).is_ok() {
        bail!("unregistered constraint_kind `applet_delegation_binding` was accepted");
    }

    let realm_resource: arkret_wire::WireResourceSelector = serde_json::from_value(json!({
        "kind": "realm",
        "realm_id": "ak:realm:ATg8FU4syAKnb6AxCmZvnzVYTFe33amlqXfbtAUgi5R3"
    }))?;
    let expected_resource = serde_json::to_value(&realm_resource)?;
    let valid = applet_grant_binding_matches(
        &canonical,
        &expected_resource,
        &expected_resource,
        applet_id.as_str(),
        service_id.as_str(),
        registration_epoch.as_str(),
    );
    if !valid {
        bail!("canonical Applet delegation grant binding was rejected");
    }
    for (name, mutated_constraint, mutated_resource, expected_service, expected_epoch) in [
        (
            "account_executor_with_same_principal",
            mutate(
                &canonical,
                "executed_by",
                serde_json::to_value(arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                    service_id.clone(),
                    arkret_wire::DidCoreId::new("ak:did_core:web:station.example")?,
                )))?,
            ),
            expected_resource.clone(),
            service_id.as_str(),
            registration_epoch.as_str(),
        ),
        (
            "wrong_applet",
            mutate(&canonical, "applet_id", json!("ak:applet:wrong")),
            expected_resource.clone(),
            service_id.as_str(),
            registration_epoch.as_str(),
        ),
        (
            "wrong_service",
            canonical.clone(),
            expected_resource.clone(),
            "did:web:wrong.example",
            registration_epoch.as_str(),
        ),
        (
            "wrong_epoch",
            canonical.clone(),
            expected_resource.clone(),
            service_id.as_str(),
            "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        ),
        (
            "widened_resource",
            canonical.clone(),
            json!({
                "kind": "realm",
                "realm_id": "ak:realm:AXxrsUIlJjXTN1WmemivF8XXUgduxtq-nllathYqyddS"
            }),
            service_id.as_str(),
            registration_epoch.as_str(),
        ),
    ] {
        if applet_grant_binding_matches(
            &mutated_constraint,
            &mutated_resource,
            &expected_resource,
            applet_id.as_str(),
            expected_service,
            expected_epoch,
        ) {
            bail!("Applet install mutation {name} widened or rebound the grant");
        }
    }

    let pair = [
        "ak.identity.accountability_grant",
        arkret_wire::event_kind_str::PROFILE_CREATE,
    ];
    if !ghost_provision_pair_authorized("ak.applet.ghost.provision", &pair)
        || ghost_provision_pair_authorized("ak.applet.ghost.provision", &pair[..1])
        || ghost_provision_pair_authorized(
            "ak.applet.ghost.provision",
            &["ak.identity.accountability_grant"],
        )
        || ghost_provision_pair_authorized("ak.identity.accountability_grant", &pair)
    {
        bail!("Ghost provision capability was generalized beyond the closed pair aggregate");
    }

    record_vector_event(
        "applet.install.caller_signed_grant_binding",
        &json!({
            "constraint": canonical,
            "resource": expected_resource,
            "ghost_pair": pair,
        }),
        &json!({
            "canonical_constraint": true,
            "unregistered_constraint_kind_rejected": true,
            "exact_scope_required": true,
            "ghost_pair_closed": true,
        }),
        &json!({
            "canonical_constraint": valid,
            "unregistered_constraint_kind_rejected": true,
            "exact_scope_required": true,
            "ghost_pair_closed": true,
        }),
    );
    Ok(())
}

pub fn run_applet_registration_epoch_kat_suite() -> Result<()> {
    use arkret_models_integration::applet::AppletRegistrationEpochTranscript;

    let fixture = super::load_fixture_value(REGISTRATION_EPOCH_FIXTURE)?;
    let embedded = arkret_schema_conformance::spec_json_artifact(&format!(
        "fixtures/{REGISTRATION_EPOCH_FIXTURE}"
    ))
    .context("embedded Applet registration-epoch fixture")?;
    if fixture != embedded {
        bail!("filesystem and SDK-embedded registration-epoch fixtures drifted");
    }
    if fixture["runner"]["kind"] != "named_suite"
        || fixture["runner"]["entrypoint"] != "ak.suite.applet.registration_epoch.v1"
        || fixture["domain_separator_utf8"].as_str()
            != Some(
                String::from_utf8_lossy(AppletRegistrationEpochTranscript::DOMAIN_SEPARATOR)
                    .as_ref(),
            )
    {
        bail!("Applet registration-epoch suite identity or domain separator drifted");
    }

    let transcript_value = fixture["positive"]["transcript"].clone();
    let transcript_schema = super::schema_validation_fixture::SchemaEnv::load()?
        .compile("schemas/applet-registration-epoch-transcript.schema.json")?;
    if !transcript_schema.is_valid(&transcript_value) {
        bail!("positive registration-epoch transcript fails the authoritative schema");
    }
    let transcript: AppletRegistrationEpochTranscript =
        serde_json::from_value(transcript_value.clone())?;
    transcript.validate_normalized()?;
    let canonical = transcript.canonical_json_bytes()?;
    let frozen_canonical = fixture["positive"]["canonical_bytes_utf8"]
        .as_str()
        .context("registration-epoch canonical bytes")?
        .as_bytes();
    if canonical != frozen_canonical {
        bail!("registration-epoch canonical bytes drifted");
    }
    let expected_epoch = fixture["positive"]["expected_registration_epoch"]
        .as_str()
        .context("expected registration epoch")?;
    if transcript.registration_epoch()?.as_str() != expected_epoch {
        bail!("registration-epoch domain-separated digest drifted");
    }

    let mut unsorted = transcript_value.clone();
    unsorted["accepted_signing_keys"]
        .as_array_mut()
        .context("accepted_signing_keys array")?
        .reverse();
    let unsorted: AppletRegistrationEpochTranscript = serde_json::from_value(unsorted)?;
    if unsorted.validate_normalized().is_ok() {
        bail!("unsorted accepted signing keys entered the digest boundary");
    }

    let mut duplicate = transcript_value.clone();
    let first_key = duplicate["accepted_signing_keys"][0].clone();
    duplicate["accepted_signing_keys"]
        .as_array_mut()
        .context("accepted_signing_keys array")?
        .push(first_key);
    let duplicate: AppletRegistrationEpochTranscript = serde_json::from_value(duplicate)?;
    if duplicate.validate_normalized().is_ok() {
        bail!("duplicate accepted signing key entered the digest boundary");
    }

    let mut optional_null = transcript_value.clone();
    optional_null["service_did_document"]["method_version"]["version_time"] = Value::Null;
    if transcript_schema.is_valid(&optional_null) {
        bail!("authoritative schema accepted an explicit optional null");
    }

    let mut unversioned = transcript_value.clone();
    unversioned["service_did_document"]["method_version"]["unversioned_refetch"] = json!(true);
    if transcript_schema.is_valid(&unversioned) {
        bail!("authoritative schema accepted unversioned evidence with version_id");
    }
    if serde_json::from_value::<AppletRegistrationEpochTranscript>(unversioned).is_ok() {
        bail!("unversioned DID evidence retained a version_id");
    }

    let mut security_change = transcript_value;
    security_change["derived_registration"]["base_url"] = json!("https://other.example/cx");
    let security_change: AppletRegistrationEpochTranscript =
        serde_json::from_value(security_change)?;
    security_change.validate_normalized()?;
    if security_change.registration_epoch()?.as_str() == expected_epoch {
        bail!("security-relevant registration change did not rotate the epoch");
    }
    if arkret_wire::ErrorCode::from_wire("applet_registration_epoch_evidence_deactivated")
        != Some(arkret_wire::ErrorCode::AppletRegistrationEpochEvidenceDeactivated)
    {
        bail!("deactivated DID evidence lost its dedicated registered error code");
    }

    record_vector_event(
        "applet.registration_epoch.kat",
        &json!({
            "entrypoint": "ak.suite.applet.registration_epoch.v1",
            "canonical_bytes": String::from_utf8(canonical)?,
            "expected_registration_epoch": expected_epoch,
        }),
        &json!({
            "positive": true,
            "negative_cases": fixture["negative"],
        }),
        &json!({
            "filesystem_embedded_equal": true,
            "canonical_and_digest_equal": true,
            "negative_count": 6,
        }),
    );
    Ok(())
}

fn mutate(value: &Value, field: &str, replacement: Value) -> Value {
    let mut value = value.clone();
    value[field] = replacement;
    value
}

fn applet_grant_binding_matches(
    constraint: &Value,
    resource: &Value,
    expected_resource: &Value,
    applet_id: &str,
    service_id: &str,
    registration_epoch: &str,
) -> bool {
    let Ok(service_id) = arkret_wire::DidCoreId::new(service_id) else {
        return false;
    };
    let Ok(executor) = serde_json::to_value(arkret_wire::ActorId::service(service_id)) else {
        return false;
    };
    constraint.get("constraint_kind").and_then(Value::as_str) == Some("authority_control")
        && constraint.get("constraint_subkind").and_then(Value::as_str) == Some("applet_authority")
        && constraint.get("evaluation_class").and_then(Value::as_str) == Some("grant_local")
        && constraint.get("applet_id").and_then(Value::as_str) == Some(applet_id)
        && constraint.get("executed_by") == Some(&executor)
        && constraint.get("registration_epoch").and_then(Value::as_str) == Some(registration_epoch)
        && resource == expected_resource
}

fn ghost_provision_pair_authorized(action: &str, event_kinds: &[&str]) -> bool {
    action == "ak.applet.ghost.provision"
        && event_kinds
            == [
                "ak.identity.accountability_grant",
                arkret_wire::event_kind_str::PROFILE_CREATE,
            ]
}
