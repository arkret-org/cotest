//! The `cotest-wire` oracle, as a library.
//!
//! These were private functions inside the binary. The canonical provisioning
//! module needs the same protocol material the TypeScript side gets through the
//! CLI — the DID operation, the PCR genesis unit, the register request — and it
//! would be absurd for a Rust caller to reach them by spawning a subprocess and
//! parsing JSON back. The binary is now a thin dispatcher over this module, so
//! both callers run exactly the same code.
//!
//! The signatures stay `Value -> Result<Value>` for now. They are the CLI's
//! contract, and changing them here would mean changing that contract in the
//! same breath as moving the code.

use std::io::{self, Read};

use anyhow::{Context, Result, bail, ensure};
use arkret_canonical as canonical;
use arkret_identifiers::{ConsentId, DeviceId, Did, DidCoreId, Hash, project_did_to_core_id};
use arkret_models_collaboration::governance::membership_invite::{
    InviteClaimBindingProof, InviteSubjectProof, InviteSubjectProofBody,
};
use arkret_models_collaboration::mimi_operations::{
    MimiConsentDecision, MimiRequestConsentRequestBody, MimiUpdateConsentRequestBody,
};
use arkret_wire::{
    AccountId, Audience, AuditReasonText, DidUrl, Event, EventAdmissionSubmission, NonEmptyString,
    PayloadProof, ProducerEventProof, proof_kind,
};
use base64::Engine as _;
use chrono::{Timelike as _, Utc};
use ed25519_dalek::{Signer as _, SigningKey};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// Fixture inputs only; all protocol carriers and cryptography belong to SDK.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RealmActorInceptionFixture {
    base_url: String,
    local_id: String,
    root_seed_b64url: String,
    next_root_public_key_multibase: String,
    control_seed_b64url: String,
    version_created_at: chrono::DateTime<Utc>,
}

pub fn realm_actor_inception(input: Value) -> Result<Value> {
    let input: RealmActorInceptionFixture = serde_json::from_value(input)?;
    let root = signing_key_from_seed(&input.root_seed_b64url)?;
    let control = signing_key_from_seed(&input.control_seed_b64url)?;
    let endpoint = input.base_url.parse()?;
    let inception = arkret_signatures::webvh::prepare_realm_actor_inception(
        &arkret_signatures::webvh::RealmActorInceptionInput {
            principal_endpoint: &endpoint,
            local_id: &input.local_id,
            version_created_at: input.version_created_at,
            root_seed: &root.to_bytes(),
            next_root_public_key_multibase: &input.next_root_public_key_multibase,
            controller_public_key: &control.verifying_key().to_bytes(),
        },
    )?;
    Ok(
        json!({"did":inception.did,"scid":inception.did.split(':').nth(2),
        "versionId":inception.version_id,"entry":inception.log_entry,
        "didDocument":inception.log_entry["state"]}),
    )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AppletRealmActorAuthorFixture {
    authoring_request: Value,
    applet_package: arkret::AppletPackage,
    inception: Value,
    control_seed_b64url: String,
    request_id: String,
    service_signing_seed_b64url: String,
    service_verification_method: DidUrl,
    station_id: DidCoreId,
    station_verification_method: DidUrl,
    station_public_jwk: Value,
}

/// Author one current RealmActor Event; never reconstruct the retired bundle.
pub fn applet_realm_actor_author(input: Value) -> Result<Value> {
    let input: AppletRealmActorAuthorFixture = serde_json::from_value(input)?;
    let failure = |status, error| json!({"status":status,"error":error});
    let request: arkret::AppletManagedActorAuthoringRequest =
        match serde_json::from_value(input.authoring_request.clone()) {
            Ok(value) => value,
            Err(_) => return Ok(failure(400, "authoring_request_coordinate_mismatch")),
        };
    let now = canonical::normalize_timestamp_canonical(Utc::now());
    if request.issued_at >= request.expires_at || now >= request.expires_at {
        return Ok(failure(410, "authoring_request_expired"));
    }
    if request.validate_bindings().is_err()
        || request.issued_at > now
        || request.governance_station_id != input.station_id
        || request.basis.service_id() != &input.applet_package.service_id
    {
        return Ok(failure(400, "authoring_request_coordinate_mismatch"));
    }
    let station_key = input
        .station_public_jwk
        .get("x")
        .and_then(Value::as_str)
        .context("Station JWK omits x")?;
    let station_key = canonical::base64url_decode(station_key)?;
    if request.proof.verification_method != input.station_verification_method
        || arkret_signatures::Ed25519DetachedJwsVerifier::new()
            .verify_detached_jws(
                &request.proof.jws,
                &request.proof_binding_bytes()?,
                &arkret_signatures::PublicKeyMaterial::Ed25519Raw { bytes: station_key },
            )
            .is_err()
    {
        return Ok(failure(400, "authoring_request_proof_invalid"));
    }
    let basis = &input.authoring_request["basis"];
    if basis["applet_id"] != json!(input.applet_package.applet_id)
        || basis["package_digest"] != json!(input.applet_package.package_digest)
        || input.service_verification_method
            != input.applet_package.webhook_signature_policy.key_ref
    {
        return Ok(failure(400, "authoring_request_coordinate_mismatch"));
    }
    let document: arkret_models_identity::DidDocument =
        serde_json::from_value(input.inception["didDocument"].clone())?;
    let entry = input.inception["entry"].clone();
    let head = canonical::canonical_sha256(&entry)?;
    let version = input.inception["versionId"]
        .as_str()
        .context("inception version absent")?;
    let method =
        DidUrl::new(format!("{}#managed-controller", document.id)).map_err(anyhow::Error::msg)?;
    let control = signing_key_from_seed(&input.control_seed_b64url)?;
    let scope: arkret_wire::ScopeRef = serde_json::from_value(basis["effective_scope"].clone())?;
    let actor = arkret_wire::ActorId::realm(arkret_wire::RealmActorId::new(
        scope.realm_id().clone(),
        project_did_to_core_id(&document.id)?,
    ));
    let mut candidate = json!({
        "schema":arkret::RealmActorCreatePayload::SCHEMA,"actor_id":actor,
        "applet_id":input.applet_package.applet_id,"service_id":input.applet_package.service_id,
        "actor_role":if request.purpose == arkret::AppletManagedActorPurpose::ProvisionBot {"bot"}else{"ghost"},
        "request_id":input.request_id,"creation_scope":scope,
        "registration_ref":basis["registration_event_ref"],"creation_authorization_ref":basis["authorization_ref"],
        "initial_resolution":{"did":document.id,"method_history_head":head,"version_id":version},
        "method_history_evidence":{"evidence_kind":"webvh_log",
            "boundary":{"from_method_history_head":head,"from_version_id":version,"to_method_history_head":head,"to_version_id":version},
            "evidence":{"kind":"ak.did.binding_evidence.v1","method":"webvh",
                "document_digest":arkret_models_identity::normalized_did_document_digest(&document)?,
                "method_proofs":[{"kind":"webvh_log","history_head":head,"witnesses":[],
                    "witness_proofs_digest":canonical::canonical_sha256(&Vec::<Value>::new())?}]},
            "log_entries":[entry],"witness_records":[]},
        "control_method_kid":method,"expires_at":request.expires_at,
        "recovery":{"kind":"manager_native","enabled":true},
    });
    if request.purpose == arkret::AppletManagedActorPurpose::ProvisionGhost {
        candidate["external_ref"] = basis["external_ref"].clone();
    } else if basis["request_id"] != candidate["request_id"] {
        return Ok(failure(400, "authoring_request_coordinate_mismatch"));
    }
    let transcript: arkret::RealmActorCreationTranscript =
        serde_json::from_value(candidate.clone())?;
    candidate["control_signature"] =
        serde_json::to_value(arkret_signatures::detached_object::sign_detached_object(
            &transcript,
            arkret_wire::DetachedSignatureContext::RealmActorCreation,
            method,
            now,
            &control,
        )?)?;
    let signer = arkret_signatures::Ed25519PayloadSigner::new(
        signing_key_from_seed(&input.service_signing_seed_b64url)?,
        Did::new(
            input
                .service_verification_method
                .as_str()
                .split('#')
                .next()
                .context("service DID absent")?,
        )?,
        input.service_verification_method,
    );
    let event = arkret::author_realm_actor_create(
        serde_json::from_value(candidate)?,
        canonical::DigestSuite::Sha256,
        now,
        &signer,
    )?;
    Ok(json!({"create_event":event}))
}

#[cfg(test)]
mod realm_actor_fixture_tests {
    use super::*;

    fn inception(seed: u8, control: u8) -> Value {
        realm_actor_inception(json!({
            "base_url":"https://applet.example/","local_id":format!("actor-{seed}"),
            "root_seed_b64url":canonical::base64url_encode([seed;32]),
            "next_root_public_key_multibase":canonical::ed25519_pubkey_to_did_key_multibase(
                SigningKey::from_bytes(&[seed+1;32]).verifying_key().as_bytes()),
            "control_seed_b64url":canonical::base64url_encode([control;32]),
            "version_created_at":canonical::format_timestamp_canonical(Utc::now()),
        }))
        .unwrap()
    }

    fn author_input(ghost: bool) -> Value {
        let service_inception = inception(21, 23);
        let document: arkret_models_identity::DidDocument =
            serde_json::from_value(service_inception["didDocument"].clone()).unwrap();
        let service = project_did_to_core_id(&document.id).unwrap();
        let service_method = DidUrl::new(format!("{}#managed-controller", document.id)).unwrap();
        let mut package = arkret::AppletPackage::new(
            "fixture",
            arkret_wire::AppletId::new("ak:applet:01904100-0000-7000-8000-bbbbbbbbbbbb").unwrap(),
            service.clone(),
            document.id.clone(),
            service.clone(),
            "https://applet.example/",
            vec!["bridge".into()],
            arkret::AppletWireNamespaces::default(),
        );
        package.webhook_signature_policy.key_ref = service_method.clone();
        package.endpoint_policy = serde_json::from_value(json!({
            "endpoints":[{"method":"POST","path":"/_arkret/edge/applet/transactions","authentication_kind":"webhook_signature"}]
        }))
        .unwrap();
        let evidence = arkret::AppletRegistrationEpochEvidence::from_did_document(
            &document,
            arkret::AppletDidMethodVersionEvidence::versioned(
                "did:webvh",
                Some(service_inception["versionId"].as_str().unwrap().into()),
                None,
            )
            .unwrap(),
        )
        .unwrap();
        package.stamp_registration_epoch(&evidence).unwrap();
        package.stamp_package_digest().unwrap();
        let station_did = Did::new("did:web:station.example").unwrap();
        let station_id = project_did_to_core_id(&station_did).unwrap();
        let station_method = DidUrl::new("did:web:station.example#notary-key").unwrap();
        let key = SigningKey::from_bytes(&[40; 32]);
        let signer = arkret_signatures::Ed25519PayloadSigner::new(
            key.clone(),
            station_did,
            station_method.clone(),
        );
        let realm = arkret_wire::RealmId::from_event_id(&arkret_wire::EventId::from_digest(
            canonical::DigestSuite::Sha256,
            [41; 32],
        ));
        let mut basis = json!({"schema":if ghost {arkret::AppletGhostAuthoringRequestBasis::SCHEMA}else{arkret::AppletBotAuthoringRequestBasis::SCHEMA},
            "purpose":if ghost {"provision_ghost"}else{"provision_bot"},"target_station_id":station_id,
            "applet_id":package.applet_id,"service_id":service,"effective_scope":{"kind":"realm","realm_id":realm},
            "registration_event_ref":arkret_wire::EventId::from_digest(canonical::DigestSuite::Sha256,[42;32]),
            "authorization_ref":arkret_wire::GrantId::from_event_id(&arkret_wire::EventId::from_digest(canonical::DigestSuite::Sha256,[43;32])),
            "registration_epoch_evidence":evidence,"package_digest":package.package_digest});
        let request_id = "01234567890123456789012345678901";
        if ghost {
            basis["external_ref"] =
                json!({"protocol":"bridge","instance_id":"fixture","external_id":"external-user"});
        } else {
            basis["request_id"] = json!(request_id);
        }
        let now = canonical::normalize_timestamp_canonical(Utc::now());
        let request = if ghost {
            arkret::AppletManagedActorAuthoringRequest::sign_ghost(
                serde_json::from_value(basis).unwrap(),
                station_id.clone(),
                now,
                now + chrono::Duration::minutes(5),
                &signer,
            )
        } else {
            arkret::AppletManagedActorAuthoringRequest::sign_bot(
                serde_json::from_value(basis).unwrap(),
                station_id.clone(),
                now,
                now + chrono::Duration::minutes(5),
                &signer,
            )
        }
        .unwrap();
        json!({"authoring_request":request,"applet_package":package,"inception":inception(31,33),
            "control_seed_b64url":canonical::base64url_encode([33;32]),"request_id":request_id,
            "service_signing_seed_b64url":canonical::base64url_encode([23;32]),"service_verification_method":service_method,
            "station_id":station_id,"station_verification_method":station_method,
            "station_public_jwk":{"kty":"OKP","crv":"Ed25519","x":canonical::base64url_encode(key.verifying_key().as_bytes())}})
    }

    #[test]
    fn current_bot_and_ghost_fixture_author_one_private_creation_original() {
        for ghost in [false, true] {
            let input = author_input(ghost);
            let outcome = applet_realm_actor_author(input).unwrap();
            assert_eq!(outcome.as_object().unwrap().len(), 1);
            let event: Event = serde_json::from_value(outcome["create_event"].clone()).unwrap();
            assert_eq!(event.kind, arkret_wire::EventKind::RealmActorCreate);
            assert!(matches!(
                event.scope_ref,
                arkret_wire::ScopeRef::RealmControl { .. }
            ));
            assert_eq!(
                outcome["create_event"]["payload"]["actor_id"]["kind"],
                "realm"
            );
            assert!(outcome.get("managed_actor_bundle").is_none());
        }
    }

    #[test]
    fn current_author_fixture_rejects_untrusted_station_and_retired_or_wrong_material() {
        let input = author_input(false);
        let mut stale = input.clone();
        stale["station_verification_method"] = json!("did:web:station.example#rotated-key");
        assert_eq!(
            applet_realm_actor_author(stale).unwrap()["error"],
            "authoring_request_proof_invalid"
        );
        let mut nested = input.clone();
        nested["authoring_request"]["basis"]["managed_actor_bundle"] = json!({});
        assert_eq!(
            applet_realm_actor_author(nested).unwrap()["error"],
            "authoring_request_coordinate_mismatch"
        );
        let mut wrong = input.clone();
        wrong["control_seed_b64url"] = json!(canonical::base64url_encode([34; 32]));
        assert!(applet_realm_actor_author(wrong).is_err());
        let mut retired = input;
        retired["managed_actor_bundle"] = json!({});
        assert!(applet_realm_actor_author(retired).is_err());
    }
}

#[derive(Debug, Deserialize)]
struct CanonicalInput {
    value: Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoricalHumanQueryInput {
    event: Event,
    commit: arkret_wire::RealmCommit,
    recipient_account_id: AccountId,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoricalHumanFactInput {
    event: Event,
    commit: arkret_wire::RealmCommit,
    query: arkret_models_identity::SignerKeysQueryRequestBody,
    outcome: arkret_models_identity::SignerKeyQueryResponseBody,
}

fn historical_human_selector(
    event: &Event,
    commit: &arkret_wire::RealmCommit,
) -> Result<arkret_models_identity::SignerKeyQuerySelector> {
    use arkret_models_identity::{HistoricalSignerKeyQuerySender, SignerKeyQuerySelector};
    arkret_wire::CommittedEventFullView {
        event: event.clone(),
        commit: commit.clone(),
    }
    .validate_shape()?;
    let producer = event
        .verify_producer_proof_self_consistency(event.realm_id.digest_suite_code().digest_suite())?
        .context("historical target has no Human device producer")?;
    let proof = event
        .producer_proof
        .as_ref()
        .context("historical target proof absent")?;
    Ok(SignerKeyQuerySelector::HistoricalEvent {
        sender: HistoricalSignerKeyQuerySender::AccountDevice {
            actor: arkret_wire::ActorId::account(producer.account_id),
            device_id: producer.device_id,
            verification_method: proof.verification_method.clone(),
            committed_event_ref: arkret_wire::CommittedEventRef {
                event_id: event.event_id.clone(),
                commit_id: commit.commit_id.clone(),
                stream_ref: commit.stream_ref.clone(),
                stream_position: commit.stream_position,
            },
        },
    })
}

/// The browser fixture uses the same closed historical selector as Rust live
/// scenarios. This does not grant the destination Station Realm history.
pub fn historical_human_signer_query(input: Value) -> Result<Value> {
    let input: HistoricalHumanQueryInput = serde_json::from_value(input)?;
    ensure!(
        input.commit.producer_signer_fact_digest.is_some(),
        "original Human Commit lacks signer fact digest"
    );
    let query = arkret_models_identity::SignerKeysQueryRequestBody {
        request_id: arkret_wire::RequestId::new_v7_at(Utc::now().timestamp_millis() as u64),
        realm_id: input.event.realm_id.clone(),
        recipient_account_id: Some(input.recipient_account_id),
        recipient_actor_id: None,
        queries: vec![historical_human_selector(&input.event, &input.commit)?],
    };
    query.validate()?;
    Ok(serde_json::to_value(query)?)
}

/// Reconstruct only the original immutable fact and independently check its
/// exact Commit binding and producer signature. Never use current admission.
pub fn historical_human_signer_fact(input: Value) -> Result<Value> {
    use arkret_models_collaboration::authority_commit::AccountDeviceHistoricalSignerFact;
    use arkret_models_identity::SignerKeyResolution;
    let input: HistoricalHumanFactInput = serde_json::from_value(input)?;
    let selector = historical_human_selector(&input.event, &input.commit)?;
    ensure!(
        input.query.realm_id == input.event.realm_id && input.query.queries == [selector],
        "historical query names another target"
    );
    input.outcome.validate_for_request(&input.query)?;
    let [
        SignerKeyResolution::HistoricalResolved {
            key, accepted_at, ..
        },
    ] = input.outcome.resolutions.as_slice()
    else {
        bail!("original Human historical signer source is unavailable");
    };
    let producer = input
        .event
        .account_device_producer()?
        .context("Human producer absent")?;
    let fact = AccountDeviceHistoricalSignerFact {
        event_id: input.event.event_id.clone(),
        actor: input.event.actual_signer().clone(),
        device_id: producer.device_id,
        verification_method: input
            .event
            .producer_proof
            .as_ref()
            .context("proof absent")?
            .verification_method
            .clone(),
        key: key.clone(),
        accepted_at: *accepted_at,
    };
    let suite = input.event.realm_id.digest_suite_code().digest_suite();
    fact.validate_commit_binding(
        &arkret_wire::CommittedEventFullView {
            event: input.event.clone(),
            commit: input.commit,
        },
        suite,
    )?;
    arkret_identity::account_device_signer_evidence::verify_historical_account_device_event_signature(
        &input.event,
        &fact,
        suite,
    )?;
    Ok(serde_json::to_value(fact)?)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SnapshotVerificationInput {
    snapshot: arkret_wire::RealmStateSnapshot,
    expected_snapshot_id: arkret_wire::RealmSnapshotId,
    authority_request: arkret_wire::RealmAuthorityBundleRequestBody,
    authority_bundle: arkret_wire::RealmAuthorityBundle,
    trusted_service_id: DidCoreId,
    service_resolution: arkret_models_identity::AuthenticatedServiceResolution,
}

/// Verify a live snapshot with the shared client verifier and retained
/// method-native service history. This CLI result is test tooling, not a wire
/// verdict or a substitute for the Station's authorization decision.
pub fn verify_realm_state_snapshot(input: Value) -> Result<Value> {
    let input: SnapshotVerificationInput = serde_json::from_value(input)?;
    let mut failure_stage = "service_history";
    let verified = (|| -> Result<()> {
        let now = Utc::now();
        ensure!(input.authority_bundle.current_service_id == input.trusted_service_id);
        arkret_identity::verify_authenticated_service_resolution_history(
            &input.service_resolution,
            &input.trusted_service_id,
            now,
        )?;
        failure_stage = "verification_methods";
        let mut methods = std::collections::BTreeSet::from([
            input
                .authority_bundle
                .genesis_commit
                .signature
                .verification_method
                .clone(),
            input
                .authority_bundle
                .current_assertion
                .signature
                .verification_method
                .clone(),
            input.snapshot.signature.verification_method.clone(),
        ]);
        for transition in &input.authority_bundle.authority_transitions {
            methods.insert(
                transition
                    .change_commit
                    .signature
                    .verification_method
                    .clone(),
            );
            methods.insert(
                transition
                    .handoff
                    .old_authority_signature
                    .verification_method
                    .clone(),
            );
            methods.insert(
                transition
                    .handoff
                    .new_authority_acceptance_signature
                    .verification_method
                    .clone(),
            );
        }
        let mut keys = arkret_identity::RealmAuthorityKeyMap::new();
        for method in methods {
            let key = arkret_identity::resolve_verification_method_key_from_document(
                &input.service_resolution.normalized_did_document,
                method.as_str(),
            )?;
            keys.insert(&method, key.public_key);
        }
        let freshness = arkret_identity::RealmAuthorityFreshness::new(
            now,
            input.authority_request.nonce.clone(),
        );
        let mut replica = garth::RealmReplica::new(input.authority_request.realm_id.clone());
        failure_stage = "authority";
        replica.install_verified_authority(
            &input.authority_request,
            input.authority_bundle.clone(),
            &freshness,
            &keys,
        )?;
        failure_stage = "snapshot";
        let mut current_replica = replica.clone();
        replica.install_verified_snapshot_heads(
            &input.snapshot,
            &input.expected_snapshot_id,
            &freshness,
            &keys,
        )?;
        current_replica.install_verified_current_snapshot_heads(
            &input.snapshot,
            &freshness,
            &keys,
        )?;
        Ok(())
    })()
    .is_ok();
    Ok(if verified {
        json!({"verified": true})
    } else {
        json!({"verified": false, "failure_stage": failure_stage})
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConsentCurrentVerificationInput {
    request: arkret_models_collaboration::call_invitation::ConsentCurrentReadRequestBody,
    outcome: arkret_models_collaboration::call_invitation::ConsentCurrentReadResponseBody,
    expected_realm_id: arkret_wire::RealmId,
    expected_generation: u64,
    expected_verification_method: DidUrl,
    authority: ConsentCurrentVerificationAuthority,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum ConsentCurrentVerificationAuthority {
    PublicKey {
        public_key_multibase: String,
    },
    ServiceResolution {
        trusted_service_id: DidCoreId,
        service_resolution: Box<arkret_models_identity::AuthenticatedServiceResolution>,
    },
}

/// Verify a complete editing read against independently obtained authority
/// material. None of these anchors are learned from the outcome being checked.
pub fn verify_consent_current_read_material(
    request: &arkret_models_collaboration::call_invitation::ConsentCurrentReadRequestBody,
    outcome: &arkret_models_collaboration::call_invitation::ConsentCurrentReadResponseBody,
    expected_realm_id: &arkret_wire::RealmId,
    expected_generation: u64,
    expected_verification_method: &DidUrl,
    key: &arkret_signatures::PublicKeyMaterial,
    now: chrono::DateTime<Utc>,
) -> Result<()> {
    ensure!(
        &outcome.realm_id == expected_realm_id,
        "Consent current names a different holder PCR"
    );
    ensure!(
        &outcome.proof.verification_method == expected_verification_method,
        "Consent current names a different authority method"
    );
    outcome.validate_for_request(request, expected_generation, now)?;
    arkret_signatures::call_invitation::verify_consent_current_read(
        outcome,
        request,
        expected_verification_method,
        key,
        expected_generation,
        now,
    )?;
    Ok(())
}

/// Read-only CLI oracle. A service-resolution carrier must include its
/// authenticated method history; a bare advertised DID document is insufficient.
pub fn verify_consent_current(input: Value) -> Result<Value> {
    let input: ConsentCurrentVerificationInput = serde_json::from_value(input)?;
    let now = Utc::now();
    let mut failure_stage = "authority";
    let checked = (|| -> Result<()> {
        let key = match &input.authority {
            ConsentCurrentVerificationAuthority::PublicKey {
                public_key_multibase,
            } => arkret_signatures::PublicKeyMaterial::Ed25519Multibase {
                value: public_key_multibase.clone(),
            },
            ConsentCurrentVerificationAuthority::ServiceResolution {
                trusted_service_id,
                service_resolution,
            } => {
                arkret_identity::verify_authenticated_service_resolution_history(
                    service_resolution,
                    trusted_service_id,
                    now,
                )?;
                let method_did = arkret_identity::verification_method_did(
                    input.expected_verification_method.as_str(),
                )?;
                ensure!(&project_did_to_core_id(&method_did)? == trusted_service_id);
                arkret_identity::validate_verification_method_relationship(
                    &service_resolution.normalized_did_document,
                    &input.expected_verification_method,
                    &method_did,
                    arkret_identity::DidVerificationRelationship::AssertionMethod,
                )?;
                arkret_identity::resolve_verification_method_key_from_document(
                    &service_resolution.normalized_did_document,
                    input.expected_verification_method.as_str(),
                )?
                .public_key
            }
        };
        failure_stage = "current";
        verify_consent_current_read_material(
            &input.request,
            &input.outcome,
            &input.expected_realm_id,
            input.expected_generation,
            &input.expected_verification_method,
            &key,
            now,
        )
    })();
    Ok(if checked.is_ok() {
        json!({"verified": true})
    } else {
        json!({"verified": false, "failure_stage": failure_stage})
    })
}

#[derive(Debug, Deserialize)]
struct EventProofInput {
    actor_did: String,
    verification_method: arkret_wire::DidUrl,
    created_at: String,
    event: Value,
    signing_seed_b64url: Option<String>,
}

#[derive(Debug, Deserialize)]
struct MimiConsentProofInput {
    request: Value,
    verification_method: arkret_wire::DidUrl,
    created_at: String,
    domain: String,
    audience: String,
    signing_seed_b64url: Option<String>,
}

#[derive(Debug, Deserialize)]
struct MlsKeyPackageUploadEntryInput {
    actor_id: arkret_wire::ActorId,
    device_id: DeviceId,
    signing_seed_b64url: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InviteSubjectProofInput {
    subject_account_id: AccountId,
    invite_id: String,
    realm_id: String,
    token_commitment: String,
    claim_nonce: String,
    verification_id: String,
    binding_proof: InviteClaimBindingProof,
    verification_method: DidUrl,
    subject_did: Did,
    root_public_key_multibase: String,
    recovery_key: String,
    #[serde(default)]
    negative_device_signing_seed_b64url: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PrincipalControlRealmInput {
    principal_id: DidCoreId,
}

#[derive(Debug, Deserialize)]
struct WebvhPlaceholderDidInput {
    base_url: String,
    local_id: String,
}

#[derive(Debug, Deserialize)]
struct WebvhGenesisInput {
    base_url: String,
    local_id: String,
    root_seed_b64url: String,
    next_root_public_key_multibase: String,
    version_created_at: Option<String>,
    /// The preliminary DID document, authored against the DID that
    /// `webvh-placeholder-did` returns.
    document: Value,
}

#[derive(Debug, Deserialize)]
struct PrincipalRegistrationFixtureInput {
    station_url: String,
    gate_account_base_url: String,
    handoff_request_id: String,
    identity_creation_lease: Value,
    device_id: String,
    trust_domain: String,
    initial_session: InitialSessionFixtureInput,
}

#[derive(Debug, Deserialize)]
struct InitialSessionFixtureInput {
    session_public_key: arkret::CanonicalSessionPublicJwk,
    audience_id: DidCoreId,
}

#[derive(Debug, Deserialize)]
struct AccountHandoffRequestFixtureInput {
    request_id: String,
    audience_id: DidCoreId,
    oidc_issuer_uri: String,
    client_id: String,
    redirect_uri: String,
    state: String,
    nonce: String,
    authorization_code: String,
    code_verifier: String,
    dpop_seed_b64url: String,
}

#[derive(Debug, Deserialize)]
struct IdentityCreationRegisterFixtureInput {
    challenge: Value,
    challenge_request: arkret::IdentityBindingChallengeRequestBody,
    account_subject: arkret::Hash,
    origin: arkret::WebOrigin,
    trust_domain: arkret::TrustDomainId,
    pcr_genesis_unit: Value,
    initial_session: arkret::InitialSessionGrantIntent,
    recovery_key: String,
    display_name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct WebvhVerifyLogInput {
    did: String,
    log_path: String,
    /// `service` selects the generic chain profile that admits service
    /// authority keys; anything else keeps the human-principal profile.
    profile: Option<String>,
}

pub fn invite_subject_proof(input: Value) -> Result<Value> {
    let input: InviteSubjectProofInput =
        serde_json::from_value(input).context("parse invite subject proof input")?;
    let binding_digest = input
        .binding_proof
        .canonical_digest()
        .context("digest invite binding proof")?;
    let transcript = InviteSubjectProofBody::from_wire_parts(
        input.subject_account_id,
        input.invite_id,
        input.realm_id,
        input.token_commitment,
        input.claim_nonce,
        input.verification_id,
        binding_digest.as_str(),
    )?;
    let transcript_digest = transcript.transcript_digest()?;
    ensure!(
        project_did_to_core_id(&input.subject_did)? == transcript.subject_account_id.principal_id,
        "native subject DID differs from the signed Account"
    );
    let material = arkret::identity_root::derive_identity_recovery_key_material_from_bip39(
        &input.recovery_key,
        "",
        0,
    )?;
    ensure!(
        material.root_public_key_multikey == input.root_public_key_multibase,
        "native control key differs from the accepted registration checkpoint"
    );
    let root_method = format!(
        "did:key:{}#{}",
        material.root_public_key_multikey, material.root_public_key_multikey
    );
    let signing_key = match input.negative_device_signing_seed_b64url {
        Some(seed) => {
            // Deliberately valid device signatures exercise the server's
            // native-control rejection; ordinary proofs use the root below.
            ensure!(
                input.verification_method.as_str() != root_method,
                "device rejection fixture must not name the native root method"
            );
            signing_key_from_seed(&seed)?
        }
        None => {
            ensure!(
                input.verification_method.as_str() == root_method,
                "subject proof requires the accepted native update-key method"
            );
            SigningKey::from_bytes(&material.root_seed)
        }
    };
    let signature = signing_key.sign(&transcript.canonical_bytes()?).to_bytes();
    let proof = InviteSubjectProof::new(
        input.verification_method,
        transcript_digest,
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature),
    );
    proof.validate()?;
    serde_json::to_value(proof).context("serialize invite subject proof")
}

pub fn validate_applet_authority_material(input: Value) -> Result<Value> {
    let material: arkret_models_collaboration::applet_installation_authority::AppletAuthorityMaterialResponseBody =
        serde_json::from_value(input).context("parse Applet authority material")?;
    material.validate_structural()?;
    for view in std::iter::once(&material.registration).chain(&material.grant_events) {
        view.validate_shape()?;
    }
    Ok(json!({"valid": true}))
}

pub fn mls_keypackage_upload_entry(input: Value) -> Result<Value> {
    let input: MlsKeyPackageUploadEntryInput =
        serde_json::from_value(input).context("parse MLS KeyPackage upload-entry input")?;
    let seed = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(input.signing_seed_b64url)
        .context("decode MLS signing seed")?;
    let seed: [u8; 32] = seed
        .try_into()
        .map_err(|_| anyhow::anyhow!("MLS signing seed must be 32 bytes"))?;
    let identity = arkret::ArkretMlsIdentity::new_human_device(
        input.actor_id,
        input.device_id,
        arkret::ArkretMlsSigner::from_ed25519_signing_key(ed25519_dalek::SigningKey::from_bytes(
            &seed,
        )),
    )?;
    let record = identity.key_package_record()?;
    let entry = arkret_models_crypto::mls_key_package_record_upload_entry(&record)
        .map_err(anyhow::Error::msg)?;
    serde_json::to_value(entry).context("serialize MLS KeyPackage upload entry")
}

/// Validate a self stream page with the SDK and return its disclosure coordinates.
/// The caller retains the originals; never reserialize or duplicate Event bytes.
/// Authentication and disclosure authority remain the caller's responsibility.
pub fn project_committed_stream_scan(input: Value) -> Result<Value> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Input {
        request: arkret_wire::StreamScanRequestBody,
        outcome: arkret_wire::StreamScanResponseBody,
    }
    let input: Input =
        serde_json::from_value(input).context("parse SDK stream projection input")?;
    input.outcome.validate_for_request(&input.request)?;
    let full_positions: Vec<usize> = input
        .outcome
        .committed_events
        .iter()
        .enumerate()
        .filter_map(|(position, view)| {
            matches!(view, arkret_wire::CommittedEventView::Full(_)).then_some(position)
        })
        .collect();
    Ok(json!({"full_positions": full_positions, "truncated": input.outcome.truncated}))
}

pub fn event_envelope_parse(input: Value) -> Result<Value> {
    let _: Event = serde_json::from_value(input).context("parse closed Event envelope")?;
    Ok(json!({ "valid": true }))
}

fn non_empty(value: impl Into<String>) -> Result<NonEmptyString> {
    NonEmptyString::new(value.into()).map_err(anyhow::Error::msg)
}

pub(crate) fn device_hpke_multibase(public_key: &[u8]) -> Result<NonEmptyString> {
    ensure!(
        public_key.len() == 32,
        "Device HPKE public key must be 32-byte X25519"
    );
    let mut multicodec = vec![0xec, 0x01];
    multicodec.extend_from_slice(public_key);
    non_empty(canonical::encode_multibase_base58btc(multicodec))
}

fn fresh_device_event_key() -> Result<SigningKey> {
    let mut seed = [0_u8; 32];
    getrandom::fill(&mut seed)
        .map_err(|error| anyhow::anyhow!("Device Event key CSPRNG unavailable: {error}"))?;
    Ok(SigningKey::from_bytes(&seed))
}

pub fn principal_registration_fixture(input: Value) -> Result<Value> {
    let input: PrincipalRegistrationFixtureInput =
        serde_json::from_value(input).context("parse principal-registration fixture input")?;
    let initial_session = arkret::InitialSessionGrantIntent {
        device_id: input
            .device_id
            .parse()
            .context("parse founding device id")?,
        session_public_key: input.initial_session.session_public_key,
        audience_id: input.initial_session.audience_id,
    };
    initial_session.validate()?;
    let endpoint = url::Url::parse(&input.station_url).context("parse Station URL")?;
    let created_at = Utc::now().with_nanosecond(0).unwrap_or_else(Utc::now);

    let mut entropy = [0u8; 32];
    getrandom::fill(&mut entropy).context("obtain native principal recovery entropy")?;
    let mnemonic = bip39::Mnemonic::from_entropy(&entropy)
        .context("build 24-word principal recovery mnemonic")?;
    let recovery_key = mnemonic.words().collect::<Vec<_>>().join(" ");
    let key_material = arkret::identity_root::derive_identity_recovery_key_material_from_bip39(
        &recovery_key,
        "",
        0,
    )
    .context("derive principal recovery key material")?;
    let draft =
        arkret::webvh::prepare_principal_inception(&arkret::webvh::PrincipalInceptionInput {
            provider_endpoint: &endpoint,
            principal_endpoint: &endpoint,
            local_id: &input
                .handoff_request_id
                .trim_start_matches("ak:request:")
                .to_ascii_lowercase(),
            also_known_as: &[],
            version_created_at: created_at,
            root_seed: &key_material.root_seed,
            next_root_public_key_multibase: &key_material.next_root_public_key_multikey,
            witness_policy: None,
        })
        .context("prepare principal inception")?;
    let principal = Did::new(draft.did.clone()).context("parse prepared principal DID")?;
    let genesis_salt = arkret::GenesisSalt::generate()?;
    let recovery_key_fingerprint = format!(
        "sha256:{}",
        hex::encode(Sha256::digest(recovery_key.as_bytes()))
    );
    let did_document = draft
        .log_entry
        .get("state")
        .cloned()
        .context("prepared principal inception omitted DID document state")?;
    let normalized_did_document: arkret_models_identity::DidDocument =
        serde_json::from_value(did_document.clone())
            .context("project prepared principal DID document")?;
    let principal_registration_anchor =
        arkret_models_identity::PrincipalRegistrationAnchor::WebvhRegistration {
            registration_did_operation: Box::new(draft.submit_body.clone()),
            log_entries: vec![
                serde_json::from_value(draft.log_entry.clone())
                    .context("prepared principal inception is not an object")?,
            ],
            witness_records: Vec::new(),
            normalized_did_document,
        };
    arkret_identity::validate_principal_registration_anchor(&principal_registration_anchor)
        .context("validate prepared principal registration anchor")?;
    let lease: arkret::IdentityCreationLease =
        serde_json::from_value(input.identity_creation_lease)
            .context("parse identity-creation lease")?;
    let device_hpke = arkret::crypto::hpke::generate_x25519_keypair()
        .context("generate client-owned founding Device HPKE custody")?;
    let (creation_events, device_signing_seed) = build_pcr_genesis_unit(
        &principal,
        initial_session.audience_id.clone(),
        genesis_salt.clone(),
        &input.trust_domain,
        &draft.version_id,
        &arkret_canonical::canonical_sha256(&draft.log_entry)?,
        &draft.root_public_key_multibase,
        &draft.root_verification_method,
        &key_material.root_seed,
        &input.device_id,
        device_hpke_multibase(device_hpke.public_key())?,
        created_at,
    )
    .context("build PCR genesis unit")?;
    let challenge_request = garth::identity_binding_challenge_request(
        arkret::RequestId::new(arkret_identifiers::new_prefixed_uuid7("ak:request:"))
            .context("build identity-binding challenge request id")?,
        &lease,
        principal_registration_anchor.clone(),
        &creation_events,
        &initial_session,
    )
    .context("build identity-binding challenge request")?;
    let checkpoint = json!({
        "station_url": input.station_url,
        "gate_account_base_url": input.gate_account_base_url,
        "handoff_request_id": input.handoff_request_id,
        "lease_id": lease.identity_creation_lease_id,
        "lease_fence": lease.fence,
        "device_id": input.device_id,
        "trust_domain": input.trust_domain,
        "did": draft.did,
        "version_id": draft.version_id,
        "root_public_key_multibase": draft.root_public_key_multibase,
        "root_verification_method": draft.root_verification_method,
        "next_root_public_key_multibase": draft.next_root_public_key_multibase,
        "next_root_key_hash": draft.next_root_key_hash,
        "recovery_proof_public_key_multibase": key_material.recovery_proof_public_key_multikey,
        "backup_hpke_public_key_multibase": key_material.backup_hpke_public_key_multikey,
        "recovery_key_fingerprint": recovery_key_fingerprint,
        "principal_registration_anchor": principal_registration_anchor,
        // The signed genesis Event itself, not a reserved id for it. `ak:event:`
        // is an event-derived kind, so its id is a function of this finished
        // envelope; the id-only field this fixture used to emit was both
        // unreadable by Inkson and a forbidden random mint.
        "pcr_genesis_unit": creation_events,
        "initial_session": initial_session,
        "device_signing_seed_b64url": device_signing_seed,
        "device_hpke_private_key_b64url": canonical::base64url_encode(device_hpke.private_key()),
        "genesis_created_at": arkret_canonical::format_timestamp_canonical(created_at),
        "genesis_salt": genesis_salt,
        "binding_receipt": null,
        "stage": "custody_confirmed",
    });
    Ok(json!({
        "principal_registration_anchor": checkpoint["principal_registration_anchor"],
        "recovery_key": recovery_key,
        "checkpoint": checkpoint,
        "challenge_request": challenge_request,
    }))
}

/// The founding Principal Control Realm genesis Event, signed by the identity
/// root the 24 words derive.
///
/// This mirrors Inkson's `build_bootstrap_create_event` exactly, and it has to:
/// Inkson rebuilds the Event from the checkpoint's own fields and refuses the
/// checkpoint unless the canonical bytes match byte-for-byte. Every input below
/// is therefore taken from a field the checkpoint also stores, and the digest
/// suite is the same `DigestSuite::Sha256` Inkson routes through.
#[allow(clippy::too_many_arguments)]
fn build_pcr_genesis_unit(
    principal: &Did,
    station_id: DidCoreId,
    genesis_salt: arkret::GenesisSalt,
    trust_domain: &str,
    version_id: &str,
    method_history_head: &str,
    root_public_key_multibase: &str,
    root_verification_method: &str,
    root_seed: &[u8; 32],
    device_id: &str,
    hpke_key: NonEmptyString,
    created_at: chrono::DateTime<Utc>,
) -> Result<(arkret_wire::PcrGenesisUnit, String)> {
    let principal_id = project_did_to_core_id(principal)?;
    let principal_device_id = DeviceId::new(device_id.to_owned()).context("parse device id")?;
    let device_key = fresh_device_event_key()?;
    let device_seed = device_key.to_bytes();
    let device_public_key_bytes = device_key.verifying_key().to_bytes();
    let device_multibase =
        arkret_canonical::ed25519_pubkey_to_did_key_multibase(&device_public_key_bytes);
    let device_public_key = non_empty(format!("did:key:{device_multibase}"))?;
    let algorithms = vec![non_empty("ak.hpke_x25519_aead_chacha20poly1305.v1")?];
    let mut authorize_payload =
        arkret_models_collaboration::events_payloads::DeviceAuthorizePayload {
            pairing_challenge_transcript_digest: None,
            device_id: principal_device_id.clone(),
            device_public_key_did: device_public_key.clone(),
            hpke_key: hpke_key.clone(),
            algorithms: algorithms.clone(),
            device_key_algorithm: non_empty("Ed25519")?,
            authorized_by:
                arkret_models_collaboration::events_payloads::DeviceOrPrincipalRef::Principal(
                    principal_id.clone(),
                ),
            // A registration-anchor authorization initializes and signs the
            // same PCR-local generation established by the genesis unit.
            authorized_generation_ref: 1,
            scopes: None,
            not_before: created_at,
            expires_at: None,
            authorization_binding_kind: arkret_models_collaboration::events_payloads::DeviceAuthorizationBindingKind::RegistrationAnchor,
            device_signature: arkret_models_collaboration::events_payloads::SignatureMaterial::NonEmptyString(
                non_empty("pending")?,
            ),
            recovery_session_id: None,
            // `registration_anchor` is one of the three branches that MUST NOT
            // carry an install fence (`device-lifecycle.md` section 5.2.3).
            applet_id: None,
        expected_control_revision:None,expected_device_revision:None,
        };
    authorize_payload.device_signature =
        arkret_models_collaboration::events_payloads::SignatureMaterial::NonEmptyString(non_empty(
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
                device_key
                    .sign(&authorize_payload.device_possession_signature_input(
                        &arkret::AccountId::new(principal_id.clone(), station_id.clone()),
                    )?)
                    .to_bytes(),
            ),
        )?);
    let authorize_payload_value = serde_json::to_value(&authorize_payload)?;
    let descriptor = arkret_models_collaboration::events_payloads::FoundingDeviceDescriptor {
        descriptor_version: 1,
        device_id: principal_device_id,
        device_public_key_did: device_public_key,
        device_key_algorithm:
            arkret_models_collaboration::events_payloads::FoundingDeviceKeyAlgorithm::Ed25519,
        device_key_purpose:
            arkret_models_collaboration::events_payloads::FoundingDeviceKeyPurpose::EventSigningAndMlsIdentity,
        hpke_key,
        hpke_key_algorithm:
            arkret_models_collaboration::events_payloads::FoundingDeviceHpkeKeyAlgorithm::X25519,
        algorithms,
        founding_authorize_payload_digest:
            arkret_models_collaboration::events_payloads::device_authorize_payload_digest(
                &authorize_payload_value,
                arkret_canonical::DigestSuite::Sha256,
            )?,
    };
    let mut create = arkret_bootstrap::build_self_principal_pcr_create(
        arkret_bootstrap::SelfPrincipalPcrCreateInput {
            principal_id: principal_id.clone(),
            governance_station_id: station_id,
            principal_did: principal.clone(),
            initial_resolution: arkret_models_identity::ResolutionCommitment {
                did: principal.clone(),
                method_history_head: method_history_head.to_owned(),
                version_id: version_id.to_owned(),
            },
            genesis_salt,
            trust_domain: arkret::TrustDomainId::new(trust_domain.to_owned())
                .context("parse trust domain")?,
            founding_device_descriptor: descriptor,
            initial_join_rule: arkret::JoinRule::Closed,
            initial_history_access: arkret::HistoryAccess::SinceJoin,
            initial_discoverability: arkret::Discoverability::Secret,
            created_at,
        },
    )
    .context("build self principal PCR create")?;

    let root_did = Did::new(format!("did:key:{root_public_key_multibase}"))
        .context("parse identity root did:key")?;
    let root_verification_method = arkret_wire::DidUrl::new(root_verification_method.to_owned())
        .map_err(anyhow::Error::msg)
        .context("parse identity root verification method")?;
    let root_signer = arkret::Ed25519PayloadSigner::from_did_key_seed(
        *root_seed,
        root_did,
        root_verification_method.clone(),
    );
    arkret::signatures::sign_event(
        &mut create,
        &root_signer,
        arkret::signatures::SignEventOptions::new().with_created_at(created_at),
    )
    .context("sign the PCR genesis Event with the identity root")?;
    let mut authorize =
        arkret_event_draft::TypedEventDraft::<arkret_wire::event_spec::DeviceAuthorize>::new(
            arkret::ScopeRef::Realm {
                realm_id: create.realm_id.clone(),
            },
            create.actor_id.clone(),
            authorize_payload,
        )?
        .author_with_digest_suite(created_at, arkret_canonical::DigestSuite::Sha256)?;
    let device_method =
        arkret_wire::DidUrl::new(format!("{principal}#{device_id}")).map_err(anyhow::Error::msg)?;
    let device_did = Did::new(format!("did:key:{device_multibase}"))?;
    let device_signer = arkret::Ed25519PayloadSigner::from_did_key_seed(
        device_seed,
        device_did,
        device_method.clone(),
    );
    arkret::signatures::sign_event(
        &mut authorize,
        &device_signer,
        arkret::signatures::SignEventOptions::new().with_created_at(created_at),
    )?;
    Ok((
        arkret_wire::PcrGenesisUnit::new(create.into_event(), authorize.into_event())
            .context("package the PCR genesis unit")?,
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(device_seed),
    ))
}

/// The webvh method authority (`host` or `host%3Aport`) of a hosting endpoint.
fn webvh_method_authority(base_url: &str) -> Result<String> {
    let endpoint = url::Url::parse(base_url).context("parse webvh hosting endpoint")?;
    let host = endpoint
        .host_str()
        .context("webvh hosting endpoint has no host")?;
    if !host.contains('.') {
        bail!("webvh hosting host must contain a dot: {host}");
    }
    Ok(arkret::webvh::skeleton::webvh_authority_pair(host, endpoint.port()).0)
}

/// The preliminary `did:webvh:{SCID}:…` a genesis DID document is authored
/// against. Callers build their document from this DID and hand it back to
/// `webvh-genesis`, which substitutes the derived SCID over the whole entry.
pub fn webvh_placeholder_did_command(input: Value) -> Result<Value> {
    let input: WebvhPlaceholderDidInput =
        serde_json::from_value(input).context("parse webvh placeholder DID input")?;
    let method_authority = webvh_method_authority(&input.base_url)?;
    Ok(json!({
        "method_authority": method_authority,
        "did": arkret::webvh::skeleton::webvh_placeholder_did(&method_authority, &input.local_id),
    }))
}

/// Verify one fetched `did:webvh` history (`did.jsonl`) against its DID.
///
/// The joint runner's TLS-topology preflight uses this as an independent
/// third-party check: the bytes come from an HTTPS fetch through the managed
/// reverse proxy, and the chain proof runs here rather than inside the service
/// that published the log. `profile = "service"` selects the generic chain
/// verifier (`verify_did_webvh_v1_chain_bytes`), which admits service
/// authority keys; the default keeps the human-principal profile
/// (`verify_did_webvh_v1_log_bytes`).
pub fn webvh_verify_log(input: Value) -> Result<Value> {
    let input: WebvhVerifyLogInput =
        serde_json::from_value(input).context("parse webvh verify-log input")?;
    let did = Did::new(input.did).context("parse webvh DID")?;
    let bytes = std::fs::read(&input.log_path)
        .with_context(|| format!("read webvh log {}", input.log_path))?;
    let verified = match input.profile.as_deref() {
        Some("service") => arkret_identity::verify_did_webvh_v1_chain_bytes(&did, &bytes)
            .context("verify did:webvh service chain")?,
        _ => arkret_identity::verify_did_webvh_v1_log_bytes(&did, &bytes)
            .context("verify did:webvh log")?,
    };
    Ok(json!({
        "verified": true,
        "head_version_id": verified.head_version_id,
        "entry_count": verified.entries.len(),
        "did_core_id": project_did_to_core_id(&did)?,
    }))
}

/// Build one signed `did:webvh` entry-0 through the SDK builders.
///
/// The conformance harness owns no webvh construction of its own: SCID
/// derivation, the whole-entry `{SCID}` substitution (identity-did.md §3.4.4),
/// the entry hash and the `eddsa-jcs-2022` proof all come from the SDK, so a
/// harness-minted genesis is byte-identical to a client-minted one.
pub fn webvh_genesis(input: Value) -> Result<Value> {
    use arkret::webvh::skeleton::{
        WebvhInceptionSkeletonInput, build_webvh_inception_skeleton, derive_webvh_scid,
        finalize_webvh_scid_substitution, format_webvh_did, webvh_entry_hash_multibase,
        webvh_next_key_hash_value,
    };

    let input: WebvhGenesisInput =
        serde_json::from_value(input).context("parse webvh genesis input")?;
    let method_authority = webvh_method_authority(&input.base_url)?;
    let root_signing = signing_key_from_seed(&input.root_seed_b64url)?;
    let root_public_key_multibase = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
        &root_signing.verifying_key().to_bytes(),
    );
    if root_public_key_multibase == input.next_root_public_key_multibase {
        bail!("active and next WebVH root keys must be distinct");
    }
    let version_created_at = match input.version_created_at {
        Some(version_created_at) => version_created_at,
        None => arkret_canonical::format_timestamp_canonical(Utc::now()),
    };
    let next_root_key_hash = webvh_next_key_hash_value(&input.next_root_public_key_multibase);
    let skeleton = build_webvh_inception_skeleton(&WebvhInceptionSkeletonInput {
        version_created_at: &version_created_at,
        update_keys: std::slice::from_ref(&root_public_key_multibase),
        next_key_hashes: std::slice::from_ref(&next_root_key_hash),
        portable: None,
        witness: None,
        state: &input.document,
    });
    let scid = derive_webvh_scid(&skeleton).context("derive webvh SCID")?;
    let mut entry = finalize_webvh_scid_substitution(&skeleton, &scid)
        .context("substitute the derived webvh SCID")?;
    let version_id = format!(
        "1-{}",
        webvh_entry_hash_multibase(&entry, &scid).context("hash the webvh genesis entry")?
    );
    let did = format_webvh_did(&method_authority, &scid, &input.local_id);
    let did_document = entry
        .get("state")
        .cloned()
        .context("webvh genesis entry has no DID document state")?;
    if let Value::Object(map) = &mut entry {
        map.insert("versionId".to_owned(), Value::String(version_id.clone()));
    }
    let proof = arkret_signatures::build_eddsa_jcs_2022_proof(
        &entry,
        &root_signing,
        &format!("did:key:{root_public_key_multibase}#{root_public_key_multibase}"),
        arkret_signatures::DataIntegrityProofPurpose::AssertionMethod,
    )
    .map_err(|error| anyhow::anyhow!("sign webvh genesis entry: {error}"))?;
    if let Value::Object(map) = &mut entry {
        map.insert("proof".to_owned(), Value::Array(vec![proof]));
    }
    Ok(json!({
        "did": did,
        "scid": scid,
        "versionId": version_id,
        "entry": entry,
        "didDocument": did_document,
    }))
}

pub fn account_handoff_request(input: Value) -> Result<Value> {
    let input: AccountHandoffRequestFixtureInput =
        serde_json::from_value(input).context("parse account-handoff request input")?;
    let signing_key = signing_key_from_seed(&input.dpop_seed_b64url)?;
    let request = garth::oidc_account_handoff_request(
        garth::OidcAccountHandoffInput {
            request_id: arkret::RequestId::new(input.request_id)
                .context("parse account-handoff request id")?,
            audience_id: input.audience_id,
            issuer_uri: input.oidc_issuer_uri,
            client_id: input.client_id,
            redirect_uri: input.redirect_uri,
            state: input.state,
            nonce: input.nonce,
            authorization_code: input.authorization_code,
            code_verifier: input.code_verifier,
        },
        |bytes| {
            Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(signing_key.sign(bytes).to_bytes()))
        },
    )
    .context("build account-handoff request")?;
    serde_json::to_value(request).context("serialize account-handoff request")
}

pub fn account_handoff_response_body(input: Value) -> Result<Value> {
    let outcome: arkret_models_identity::AccountHandoffResponseBody =
        serde_json::from_value(input).context("parse typed account-handoff outcome")?;
    outcome
        .validate()
        .context("validate account-handoff outcome")?;
    serde_json::to_value(outcome).context("serialize validated account-handoff outcome")
}

pub fn identity_creation_register_request(input: Value) -> Result<Value> {
    let input: IdentityCreationRegisterFixtureInput =
        serde_json::from_value(input).context("parse identity-creation register input")?;
    let challenge: arkret::IdentityBindingChallengeResponseBody =
        serde_json::from_value(input.challenge).context("parse identity-binding challenge")?;
    let key_material = arkret::identity_root::derive_identity_recovery_key_material_from_bip39(
        &input.recovery_key,
        "",
        0,
    )
    .context("derive identity root for control proof")?;
    let context = garth::IdentityCreationBindingContext {
        account_subject: input.account_subject,
        dpop_jkt: input
            .initial_session
            .session_public_key
            .thumbprint_sha256()?,
        audience_id: input.initial_session.audience_id.clone(),
        origin: input.origin,
        trust_domain: input.trust_domain,
    };
    let request = garth::identity_creation_register_request(
        &challenge,
        &input.challenge_request,
        &context,
        serde_json::from_value(input.pcr_genesis_unit).context("parse PCR genesis unit")?,
        input.initial_session,
        &key_material.root_seed,
        input.display_name,
    )
    .context("build identity-creation register request")?;
    serde_json::to_value(request).context("serialize identity-creation register request")
}

#[derive(Deserialize)]
struct KeyBackupAuthSignatureInput {
    envelope: Value,
    signing_seed_b64url: String,
}

/// Sign a key-backup envelope's `signature_proof` with its device key.
///
/// key-management.md section 7.4.1 anchors `signature_proof.signature` to the
/// accepted device authorization; the transcript is the SDK
/// `KeyBackup::signing_payload_bytes`, which is the canonical envelope without
/// the signature member. The caller sends the envelope without a signature and
/// receives the same envelope with the real signature attached.
pub fn key_backup_auth_signature(input: Value) -> Result<Value> {
    let input: KeyBackupAuthSignatureInput =
        serde_json::from_value(input).context("parse key-backup signature input")?;
    let unsigned = input.envelope;
    let mut envelope = unsigned.clone();
    let signature_proof = envelope
        .get_mut("signature_proof")
        .and_then(Value::as_object_mut)
        .context("key-backup envelope has no signature_proof object")?;
    ensure!(
        !signature_proof.contains_key("signature"),
        "key-backup envelope must arrive unsigned"
    );
    // The typed envelope requires the member, and the transcript removes it,
    // so a placeholder never reaches the signed bytes.
    signature_proof.insert(
        "signature".to_owned(),
        Value::String(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0_u8; 64])),
    );
    let backup: arkret_models_crypto::KeyBackup =
        serde_json::from_value(envelope).context("parse key-backup envelope")?;
    let transcript = backup
        .signing_payload_bytes()
        .context("key-backup signing transcript")?;
    let signing_key = signing_key_from_seed(&input.signing_seed_b64url)
        .context("parse key-backup device signing seed")?;
    let signature = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(signing_key.sign(&transcript).to_bytes());
    // The receiver re-derives the transcript from its own typed decode, so the
    // caller's wire members are returned unchanged with the signature added.
    let mut signed = unsigned;
    signed
        .get_mut("signature_proof")
        .and_then(Value::as_object_mut)
        .context("key-backup envelope has no signature_proof object")?
        .insert("signature".to_owned(), Value::String(signature));
    Ok(signed)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DevicePairingTargetProofInput {
    account_id: AccountId,
    stage_request: arkret_models_collaboration::device_pairing::DevicePairingStageRequestBody,
    stage_outcome: arkret_models_collaboration::device_pairing::DevicePairingStageResponseBody,
    device_signing_seed_b64url: String,
    hpke_public_key_b64url: String,
}

/// The candidate device's accepted-device target proof.
///
/// device-lifecycle.md section 2.1.1 item 2 and section 5.2.2: the candidate
/// rebuilds the challenge digest from its own stage request and the server
/// stage outcome, then signs the closed eight-member attestation that commits
/// the exact `AccountId` its pending handoff is bound to. The proof is checked
/// against the same reconstruction a gate performs before it is returned.
pub fn device_pairing_target_proof(input: Value) -> Result<Value> {
    use arkret_models_collaboration::device_pairing::UnsignedDevicePairingTargetProof;
    use arkret_signatures::device_pairing as pairing;

    let input: DevicePairingTargetProofInput =
        serde_json::from_value(input).context("parse device-pairing target proof input")?;
    let signing_key = signing_key_from_seed(&input.device_signing_seed_b64url)
        .context("parse candidate device signing seed")?;
    let public_key = signing_key.verifying_key().to_bytes();
    let staged_key = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(input.stage_request.new_device_public_key.key.as_str())
        .context("decode staged new_device_public_key")?;
    ensure!(
        staged_key.as_slice() == public_key.as_slice(),
        "staged new_device_public_key is not the candidate signing key"
    );
    let device_id = DeviceId::new(
        input
            .stage_request
            .new_device_public_key
            .kid
            .as_str()
            .to_owned(),
    )
    .context("staged new_device_public_key.kid is not a device id")?;
    let challenge = pairing::ServerDevicePairingChallenge::from_stage(
        &input.stage_request,
        &input.stage_outcome,
    );
    let (_, transcript_digest) = pairing::server_device_pairing_transcript(
        &input.stage_request.new_device_public_key,
        &challenge,
    )?;
    let hpke_public_key = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&input.hpke_public_key_b64url)
        .context("decode candidate HPKE public key")?;
    ensure!(
        hpke_public_key.len() == 32,
        "candidate HPKE public key must be a 32-byte X25519 key"
    );
    let unsigned = UnsignedDevicePairingTargetProof::new(
        input.account_id.clone(),
        device_id,
        arkret_wire::DidKey::new(format!(
            "did:key:{}",
            canonical::ed25519_pubkey_to_did_key_multibase(&public_key)
        ))
        .map_err(anyhow::Error::msg)?,
        device_hpke_multibase(&hpke_public_key)?,
        vec![non_empty(
            arkret_wire::HPKE_SUITE_X25519_CHACHA20POLY1305_V1,
        )?],
        transcript_digest,
    )?;
    let proof = pairing::sign_device_pairing_target_proof(unsigned, &signing_key)?;
    pairing::verify_server_device_pairing_target_proof(
        &input.stage_request.new_device_public_key,
        &challenge,
        &input.account_id,
        &proof,
        Utc::now(),
    )?;
    serde_json::to_value(proof).context("serialize device-pairing target proof")
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DevicePairingApprovalInput {
    bootstrap: arkret_models_collaboration::device_pairing::DevicePairingBootstrap,
    target_proof: arkret_models_collaboration::device_pairing::DevicePairingTargetProof,
    approving_account_id: AccountId,
    approving_did: Did,
    approving_device_id: DeviceId,
    approving_signing_seed_b64url: String,
    principal_control_realm_id: arkret_wire::RealmId,
    authorized_generation_ref: u64,
}

/// The approving device's `pair_device` request.
///
/// device-lifecycle.md sections 2.1.1 item 4, 2.1.4 and 5.4: the approving
/// accepted device verifies the out-of-band target proof against the resolved
/// bootstrap and its own `AccountId`, copies the attested material into a
/// complete `accepted_device` authorize payload, and signs the Event with its
/// own device key. The server receives the exact submission and never mints it.
pub fn device_pairing_approval(input: Value) -> Result<Value> {
    use arkret_models_collaboration::device_pairing::AccountDevicePairRequestBody;
    use arkret_models_collaboration::events_payloads::{
        DeviceAuthorizationBindingKind, DeviceAuthorizePayload, DeviceOrPrincipalRef,
        SignatureMaterial,
    };
    use arkret_signatures::device_pairing as pairing;

    let input: DevicePairingApprovalInput =
        serde_json::from_value(input).context("parse device-pairing approval input")?;
    pairing::verify_server_device_pairing_target_proof(
        &input.bootstrap.new_device_public_key,
        &pairing::ServerDevicePairingChallenge::from_bootstrap(&input.bootstrap),
        &input.approving_account_id,
        &input.target_proof,
        Utc::now(),
    )?;
    ensure!(
        project_did_to_core_id(&input.approving_did)? == input.approving_account_id.principal_id,
        "approving DID does not project to the approving account principal"
    );
    ensure!(
        input.authorized_generation_ref >= 1,
        "authorized_generation_ref must be the current positive PCR generation"
    );
    ensure!(
        matches!(
            input.target_proof.device_signature,
            SignatureMaterial::NonEmptyString(_)
        ),
        "accepted-device target proof must carry a base64url signature string"
    );
    let created_at = Utc::now().with_nanosecond(0).unwrap_or_else(Utc::now);
    let payload = DeviceAuthorizePayload {
        device_id: input.target_proof.device_id.clone(),
        device_public_key_did: non_empty(input.target_proof.device_public_key_did.as_str())?,
        hpke_key: input.target_proof.hpke_key.clone(),
        algorithms: input.target_proof.algorithms.clone(),
        device_key_algorithm: non_empty("Ed25519")?,
        authorized_by: DeviceOrPrincipalRef::DeviceId(input.approving_device_id.clone()),
        scopes: None,
        not_before: created_at,
        expires_at: None,
        authorization_binding_kind: DeviceAuthorizationBindingKind::AcceptedDevice,
        authorized_generation_ref: input.authorized_generation_ref,
        device_signature: input.target_proof.device_signature.clone(),
        recovery_session_id: None,
        pairing_challenge_transcript_digest: Some(
            input
                .target_proof
                .pairing_challenge_transcript_digest
                .clone(),
        ),
        // `accepted_device` is one of the three branches that MUST NOT carry an
        // install fence (`device-lifecycle.md` section 5.2.3).
        applet_id: None,
        expected_control_revision: None,
        expected_device_revision: None,
    };
    payload
        .validate_wire_constraints()
        .map_err(anyhow::Error::msg)?;
    let mut authorize =
        arkret_event_draft::TypedEventDraft::<arkret_wire::event_spec::DeviceAuthorize>::new(
            arkret::ScopeRef::Realm {
                realm_id: input.principal_control_realm_id.clone(),
            },
            arkret_wire::ActorId::account(input.approving_account_id.clone()),
            payload,
        )?
        .author_with_digest_suite(created_at, arkret_canonical::DigestSuite::Sha256)?;
    let signing_key = signing_key_from_seed(&input.approving_signing_seed_b64url)
        .context("parse approving device signing seed")?;
    let device_did = Did::new(format!(
        "did:key:{}",
        canonical::ed25519_pubkey_to_did_key_multibase(&signing_key.verifying_key().to_bytes())
    ))?;
    let method = DidUrl::new(format!(
        "{}#{}",
        input.approving_did, input.approving_device_id
    ))
    .map_err(anyhow::Error::msg)?;
    let signer =
        arkret::Ed25519PayloadSigner::from_did_key_seed(signing_key.to_bytes(), device_did, method);
    arkret::signatures::sign_event(
        &mut authorize,
        &signer,
        arkret::signatures::SignEventOptions::new().with_created_at(created_at),
    )
    .context("sign the accepted-device authorize Event")?;
    let request = AccountDevicePairRequestBody {
        pairing_code: input.bootstrap.pairing_code.clone(),
        new_device_public_key: input.bootstrap.new_device_public_key.clone(),
        authorize_event: EventAdmissionSubmission::new(authorize.into_event()),
        display_name: input
            .bootstrap
            .display_name
            .as_ref()
            .map(|value| value.as_str().to_owned()),
        device_metadata: input.bootstrap.device_metadata.clone(),
        device_pairing_request_id: input.bootstrap.device_pairing_request_id.clone(),
    };
    serde_json::to_value(request).context("serialize pair_device request")
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HumanSessionGrantRequestInput {
    principal_did: Did,
    account_id: AccountId,
    device_id: DeviceId,
    holder_jkt: String,
    account_subject: Hash,
    account_handoff_grant: String,
    handoff_expires_at: String,
    device_signing_seed_b64url: String,
}

/// A returning accepted device's Standard grant request.
///
/// device-lifecycle.md section 2.1.4 and section 3.3: a paired device obtains
/// its grant through `issue_session_grant` with its pending account handoff,
/// proving possession of its accepted device key over the SDK
/// `accepted_device` issue transcript. The grant binds the handoff holder key
/// (`cnf.jkt`), which is distinct from the device identity key.
pub fn human_session_grant_request(input: Value) -> Result<Value> {
    let input: HumanSessionGrantRequestInput =
        serde_json::from_value(input).context("parse human session-grant request input")?;
    ensure!(
        project_did_to_core_id(&input.principal_did)? == input.account_id.principal_id,
        "principal DID does not project to the account principal"
    );
    let now = Utc::now().with_nanosecond(0).unwrap_or_else(Utc::now);
    let handoff_expires_at = canonical::parse_timestamp_canonical(&input.handoff_expires_at)
        .context("parse account handoff expires_at")?;
    let expires_at = std::cmp::min(now + chrono::Duration::minutes(5), handoff_expires_at);
    ensure!(
        expires_at > now,
        "account handoff expired before the session grant request"
    );
    let unix_ms = u64::try_from(Utc::now().timestamp_millis()).context("clock before epoch")?;
    let request_id = arkret_wire::RequestId::new_v7_at(unix_ms);
    let audience = input.account_id.station_id.clone();
    let session_intent_digest = arkret::human_session_grant_intent_digest(
        &request_id,
        &input.account_id.principal_id,
        &input.device_id,
        &audience,
        &input.holder_jkt,
    )?;
    let unsigned = arkret_wire::UnsignedAcceptedDeviceIssuePossessionProof {
        context: arkret_wire::AcceptedDevicePossessionProofContext::V1,
        purpose: arkret_wire::AcceptedDeviceIssuePossessionPurpose::SessionGrantIssue,
        request_id: request_id.clone(),
        account_subject: input.account_subject,
        account_handoff_grant_digest: Hash::new(canonical::sha256_digest(
            input.account_handoff_grant.as_bytes(),
        ))?,
        account_id: input.account_id.clone(),
        device_id: input.device_id.clone(),
        audience_id: audience.clone(),
        holder_jkt: input.holder_jkt,
        session_intent_digest,
        issued_at: now,
        expires_at,
        verification_method: DidUrl::new(format!("{}#{}", input.principal_did, input.device_id))
            .map_err(anyhow::Error::msg)?,
    };
    let signing_key = signing_key_from_seed(&input.device_signing_seed_b64url)
        .context("parse accepted device signing seed")?;
    let signature = arkret_wire::Base64UrlString::new(
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
            signing_key
                .sign(&unsigned.canonical_signing_bytes()?)
                .to_bytes(),
        ),
    )
    .map_err(anyhow::Error::msg)?;
    let proof = unsigned.attach_signature(signature)?;
    let request = arkret::session_grant::human_session_grant_request(
        request_id,
        input.account_id.principal_id,
        input.device_id,
        audience,
        proof,
    )
    .context("build human session-grant request")?;
    serde_json::to_value(request).context("serialize human session-grant request")
}

fn signing_key_from_seed(seed_b64url: &str) -> Result<SigningKey> {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(seed_b64url)
        .context("decode Ed25519 seed")?;
    let seed: [u8; 32] = bytes.try_into().map_err(|bytes: Vec<u8>| {
        anyhow::anyhow!("Ed25519 seed must be 32 bytes, got {}", bytes.len())
    })?;
    Ok(SigningKey::from_bytes(&seed))
}

pub fn read_stdin_json() -> Result<Value> {
    let mut stdin = String::new();
    io::stdin()
        .read_to_string(&mut stdin)
        .context("read stdin")?;
    serde_json::from_str(&stdin).context("parse stdin JSON")
}

/// Project through an active SDK DID adapter; this does not verify a DID or history.
pub fn project_did_core_id(input: Value) -> Result<Value> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Input {
        did: Did,
    }
    let input: Input = serde_json::from_value(input).context("parse DID projection input")?;
    Ok(json!({"did_core_id":project_did_to_core_id(&input.did)?}))
}

/// Derive the document locator through the SDK adapter; no network verification is implied.
pub fn did_web_document_url(input: Value) -> Result<Value> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Input {
        did: Did,
    }
    let input: Input =
        serde_json::from_value(input).context("parse did:web document locator input")?;
    Ok(json!({"document_url":arkret_models_identity::did_web_document_url(&input.did)?}))
}

pub fn did_document_digest(input: Value) -> Result<Value> {
    let document: arkret_models_identity::DidDocument =
        serde_json::from_value(input).context("parse DID document for normalized digest")?;
    Ok(serde_json::to_value(
        arkret_models_identity::normalized_did_document_digest(&document)?,
    )?)
}

pub fn canonical_json(input: Value) -> Result<Value> {
    let input: CanonicalInput = serde_json::from_value(input).context("parse canonical input")?;
    let bytes = canonical::canonical_json_bytes(&input.value).context("canonical JSON encode")?;
    let canonical = String::from_utf8(bytes).context("canonical JSON was not UTF-8")?;
    Ok(json!({ "canonical": canonical }))
}

pub fn sha256_canonical_json(input: Value) -> Result<Value> {
    let input: CanonicalInput = serde_json::from_value(input).context("parse digest input")?;
    let digest = canonical::canonical_sha256(&input.value).context("canonical JSON digest")?;
    Ok(json!({
        "digest": digest,
        "digest_hex": digest.strip_prefix("sha256:").unwrap_or(digest.as_str()),
    }))
}

pub fn principal_control_realm(input: Value) -> Result<Value> {
    let input: PrincipalControlRealmInput =
        serde_json::from_value(input).context("parse principal-control realm input")?;
    let _principal_id = input.principal_id;
    bail!(
        "principal-control Realm is event-derived; this command requires an accepted create Event and cannot derive it from a DID"
    )
}

#[derive(Clone, Copy)]
pub enum EventDigestMode {
    RawCanonicalJson,
}

pub fn event_proof(input: Value, digest_mode: EventDigestMode) -> Result<Value> {
    let input: EventProofInput =
        serde_json::from_value(input).context("parse event proof input")?;
    let actor_did = Did::new(input.actor_did.clone()).context("parse actor DID")?;
    let actor_core =
        project_did_to_core_id(&actor_did).context("project actor DID to its core id")?;
    let actor: arkret_wire::ActorId = serde_json::from_value(
        input
            .event
            .get("actor_id")
            .cloned()
            .context("Event proof input requires actor_id")?,
    )
    .context("parse Event actor_id")?;
    let signer_actor: arkret_wire::ActorId = input
        .event
        .get("executed_by")
        .map(|value| serde_json::from_value(value.clone()))
        .transpose()
        .context("parse Event executed_by")?
        .unwrap_or_else(|| actor.clone());
    if signer_actor.signing_principal_id() != &actor_core {
        bail!("Event signer does not match actor_did");
    }
    let method_did = arkret_identity::verification_method_did(input.verification_method.as_str())
        .context("parse Event proof verification method")?;
    if project_did_to_core_id(&method_did)? != actor_core {
        bail!("Event verification method does not match actor_did");
    }
    let created_at = canonical::parse_timestamp_canonical(&input.created_at)
        .with_context(|| format!("parse proof created_at {:?}", input.created_at))?;
    let event_digest =
        Hash::new(event_digest(&input.event, digest_mode)?).context("parse event digest")?;
    let signing_key = match input.signing_seed_b64url.as_deref() {
        Some(seed) => signing_key_from_seed(seed).context("parse event signing seed")?,
        None => arkret_test_kit::development_signing_key(&input.verification_method),
    };

    let mut proof = ProducerEventProof {
        kind: proof_kind::DETACHED_JWS.to_owned(),
        verification_method: input.verification_method,
        event_digest,
        created_at,
        domain: None,
        audience: None,
        proof_purpose: None,
        jws: String::new(),
    };
    let binding_bytes = proof
        .canonical_binding_bytes(&actor)
        .context("encode event proof binding")?;
    proof.jws = arkret_signatures::proof::sign_ed25519_detached_jws(&signing_key, &binding_bytes)
        .map_err(|err| anyhow::anyhow!("sign event proof: {err}"))?;

    serde_json::to_value(proof).context("serialize event proof")
}

pub fn mimi_consent_proof(input: Value) -> Result<Value> {
    let input: MimiConsentProofInput =
        serde_json::from_value(input).context("parse MIMI consent proof input")?;
    let created_at = canonical::parse_timestamp_canonical(&input.created_at)
        .with_context(|| format!("parse proof created_at {:?}", input.created_at))?;
    let consent_id = input
        .request
        .get("consent_id")
        .and_then(Value::as_str)
        .context("MIMI consent request requires consent_id")?;
    let decision = input
        .request
        .get("decision")
        .cloned()
        .context("MIMI consent request requires decision")?;
    let actor_id: arkret_wire::ActorId = serde_json::from_value(
        input
            .request
            .get("actor_id")
            .cloned()
            .context("MIMI consent request requires actor_id")?,
    )
    .context("parse MIMI consent actor_id")?;
    let consent_event = input
        .request
        .get("consent_event")
        .cloned()
        .context("MIMI consent request requires consent_event")?;
    let reason = input
        .request
        .get("reason")
        .and_then(Value::as_str)
        .map(AuditReasonText::new)
        .transpose()
        .map_err(|error| anyhow::anyhow!("parse MIMI consent reason: {error}"))?;
    let expires_at = input
        .request
        .get("expires_at")
        .map(|value| serde_json::from_value(value.clone()))
        .transpose()
        .context("parse MIMI consent expires_at")?;
    let mut request = MimiUpdateConsentRequestBody {
        consent_id: ConsentId::new(consent_id.to_owned()).context("parse consent id")?,
        decision: serde_json::from_value::<MimiConsentDecision>(decision)
            .context("parse consent decision")?,
        actor_id,
        consent_event: serde_json::from_value::<EventAdmissionSubmission>(consent_event)
            .context("parse MIMI consent Event")?,
        signature: PayloadProof {
            kind: proof_kind::DETACHED_JWS.to_owned(),
            verification_method: input.verification_method.clone(),
            payload_digest: Hash::new(format!("sha256:{}", "0".repeat(64)))
                .context("build placeholder payload digest")?,
            created_at,
            domain: Some(input.domain),
            audience: Some(Audience::Single(input.audience)),
            proof_purpose: None,
            jws: String::new(),
        },
        reason,
        expires_at,
    };
    request.signature.payload_digest =
        request.payload_digest().context("digest consent request")?;
    let binding = request
        .unsigned_signature_binding_bytes(&request.signature.unsigned())
        .context("encode MIMI consent proof binding")?;
    let signing_key = match input.signing_seed_b64url.as_deref() {
        Some(seed) => signing_key_from_seed(seed).context("parse MIMI consent signing seed")?,
        None => arkret_test_kit::development_signing_key(&input.verification_method),
    };
    let jws = arkret_signatures::proof::sign_ed25519_detached_jws(&signing_key, &binding)
        .map_err(|error| anyhow::anyhow!("sign MIMI consent proof: {error}"))?;
    request.signature = request
        .signature
        .unsigned()
        .finalize(jws)
        .context("finalize MIMI consent signature")?;
    serde_json::to_value(request.signature).context("serialize MIMI consent proof")
}

/// The requester operation proof over `ak.mimi_request_consent_request_proof.v1`.
///
/// `mimi_request_consent_request_body` requires `proofs[]`: consent-model.md
/// section 5.1 mandates an actor proof for this operation, and the private
/// correlation the call freezes is only as strong as the signature that froze
/// it. The binding covers the requester's complete `ActorId`, the holder
/// account, the purpose and the unsigned-body digest, so the caller cannot
/// sign one correlation and submit another.
pub fn mimi_request_consent_proof(input: Value) -> Result<Value> {
    let input: MimiConsentProofInput =
        serde_json::from_value(input).context("parse MIMI request-consent proof input")?;
    let created_at = canonical::parse_timestamp_canonical(&input.created_at)
        .with_context(|| format!("parse proof created_at {:?}", input.created_at))?;
    let mut unsigned_request = input.request.clone();
    unsigned_request
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("MIMI request-consent body must be an object"))?
        .entry("proofs")
        .or_insert_with(|| json!([]));
    let mut request: MimiRequestConsentRequestBody =
        serde_json::from_value(unsigned_request).context("parse MIMI request-consent body")?;
    // The digest is over the body without `proofs`, so the proof being built
    // never enters its own preimage.
    request.proofs = Vec::new();
    let proof = arkret_wire::UnsignedPayloadProof {
        kind: proof_kind::DETACHED_JWS.to_owned(),
        verification_method: input.verification_method.clone(),
        payload_digest: request
            .payload_digest()
            .context("digest MIMI request-consent body")?,
        created_at,
        domain: Some(input.domain),
        audience: Some(Audience::Single(input.audience)),
        proof_purpose: None,
    };
    let binding = request
        .unsigned_proof_binding_bytes(&proof)
        .context("encode MIMI request-consent proof binding")?;
    let signing_key = match input.signing_seed_b64url.as_deref() {
        Some(seed) => {
            signing_key_from_seed(seed).context("parse MIMI request-consent signing seed")?
        }
        None => arkret_test_kit::development_signing_key(&input.verification_method),
    };
    let jws = arkret_signatures::proof::sign_ed25519_detached_jws(&signing_key, &binding)
        .map_err(|error| anyhow::anyhow!("sign MIMI request-consent proof: {error}"))?;
    let proof = proof
        .finalize(jws)
        .context("finalize MIMI request-consent proof")?;
    serde_json::to_value(proof).context("serialize MIMI request-consent proof")
}

/// Construct the message payload with the same local SDK intent as native clients.
pub fn local_message_payload(input: Value) -> Result<Value> {
    let intent: arkret_models_collaboration::message_authoring::MessageAuthoringIntent =
        serde_json::from_value(input)?;
    Ok(serde_json::to_value(intent.payload())?)
}

/// The content-bound `event_id` of an envelope, derived the SDK way.
///
/// `encoding.md` section 4.0 makes an Event id a function of the Event's own
/// digest, and section 6 keeps `event_id` out of that digest's preimage. A
/// producer therefore builds the complete digest preimage, derives the id and
/// only then signs. TypeScript callers send that digest-payload shape here and
/// get the real identity back.
pub fn event_derived_id(event: Value) -> Result<Value> {
    let mut event = event;
    if let Value::Object(object) = &mut event {
        for excluded in ["event_id", "producer_proof", "unsigned"] {
            object.remove(excluded);
        }
    }
    let digest_payload_bytes = arkret_canonical::canonical_json_bytes(&event)
        .context("canonicalize SDK Event digest payload")?;
    // This helper serves the existing fixed SHA-256 conformance fixtures.
    // Dynamic-suite protocol paths use the SDK authoring APIs with an explicit
    // replay-derived suite instead of this test-only command.
    let mut event = Event::from_digest_payload_bytes(
        &digest_payload_bytes,
        arkret_canonical::DigestSuite::Sha256,
    )
    .context("derive SDK Event identity from digest payload")?;
    // A Realm genesis names no Realm, so its `realm_id` is a function of the
    // Event that creates it and can only be computed once the Event has its
    // own id. Callers get both back because neither is theirs to choose.
    if event.scope_ref.realm_id_opt().is_none() {
        event.realm_id = arkret_wire::derive_genesis_realm_id(&event.event_id);
    }
    let object_id = arkret_schema::derived_object_id_for_kind(event.kind.as_str(), &event.event_id);
    let event_digest = event
        .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
        .context("derive SDK Event digest")?;
    Ok(serde_json::json!({
        "event_id": event.event_id.to_string(),
        "event_digest": event_digest,
        "realm_id": event.realm_id.to_string(),
        "object_id": object_id,
    }))
}

fn event_digest(event: &Value, _mode: EventDigestMode) -> Result<String> {
    // Use the SDK projection that every verifier uses. Deserializing before
    // hashing is significant: wire defaults such as SemanticRef.critical=true
    // are part of Event::digest_payload even when the producer omitted them.
    let event: Event =
        serde_json::from_value(event.clone()).context("parse SDK Event digest payload")?;
    let payload = event
        .digest_payload()
        .context("build SDK Event digest payload")?;
    canonical::canonical_sha256(&payload).context("hash event digest payload")
}

#[cfg(test)]
mod tests {
    use arkret_wire::EventId;

    use super::*;

    fn stream_projection_fixture(second_position: u64) -> Result<Value> {
        use arkret_wire::{CommitStreamRef, EventId, RealmId, ScopeRef};
        let at = chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")?.with_timezone(&Utc);
        let genesis = EventId::from_digest(canonical::DigestSuite::Sha256, [61; 32]);
        let realm = RealmId::from_event_id(&genesis);
        let scope = ScopeRef::Realm {
            realm_id: realm.clone(),
        };
        let actor = DidCoreId::new("ak:did_core:web:reader.example")?;
        let station = DidCoreId::new("ak:did_core:web:station.example")?;
        let first = arkret_test_kit::raw_event_at(
            "ak.realm.freeze",
            scope.clone(),
            actor.clone(),
            station.clone(),
            json!({}),
            at,
        )?;
        let second = arkret_test_kit::raw_event_at(
            "ak.realm.freeze",
            scope,
            actor,
            station,
            json!({}),
            at + chrono::Duration::seconds(1),
        )?;
        let key = SigningKey::from_bytes(&[62; 32]);
        let method =
            DidUrl::new("did:web:station.example#commit-key").map_err(anyhow::Error::msg)?;
        let first_commit = arkret_test_kit::authority_objects::signed_commit(
            &method,
            &key,
            &first,
            0,
            None,
            genesis.clone(),
            None,
        )?;
        let second_commit = arkret_test_kit::authority_objects::signed_commit(
            &method,
            &key,
            &second,
            second_position,
            Some(first_commit.commit_id.clone()),
            genesis,
            None,
        )?;
        // Shape/disclosure vectors only; this fixture does not prove live admission.
        Ok(json!({
            "request": {"realm_id":realm,"stream_ref":CommitStreamRef::Realm { realm_id: first.realm_id.clone() },"after_position":null,"limit":256},
            "outcome": {"committed_events":[
                {"commit":first_commit,"event":first},
                {"commit":second_commit,"event_disclosure":{"status":"withheld"}}
            ],"readable_floor":{"oldest_position":0,"floor_commit_id":first_commit.commit_id,"floor_reason":"stream_start"},"truncated":false}
        }))
    }

    #[test]
    fn committed_stream_projection_reports_disclosure_without_copying_originals() -> Result<()> {
        // ak.vector.sync.committed_event_view_integrity.v1
        let input = stream_projection_fixture(1)?;
        let output = project_committed_stream_scan(input)?;
        assert_eq!(output, json!({"full_positions": [0], "truncated": false}));
        assert!(serde_json::to_vec(&output)?.len() < 128);
        Ok(())
    }

    #[test]
    fn committed_stream_projection_rejects_malformed_views_and_gaps() -> Result<()> {
        let base = stream_projection_fixture(1)?;
        let mut mixed = base.clone();
        mixed["outcome"]["committed_events"][0]["event_disclosure"] = json!({"status":"withheld"});
        assert!(project_committed_stream_scan(mixed).is_err());
        let mut missing = base.clone();
        missing["outcome"]["committed_events"][0]
            .as_object_mut()
            .unwrap()
            .remove("event");
        assert!(project_committed_stream_scan(missing).is_err());
        let mut obsolete = base.clone();
        obsolete["outcome"]["committed_events"][1]["event_disclosure"]["status"] =
            json!("redacted");
        assert!(project_committed_stream_scan(obsolete).is_err());
        let mut mismatch = base.clone();
        mismatch["outcome"]["committed_events"][0]["event"]["event_id"] = json!(
            EventId::from_digest(canonical::DigestSuite::Sha256, [63; 32])
        );
        assert!(project_committed_stream_scan(mismatch).is_err());
        let mut no_truncation = base;
        no_truncation["outcome"]
            .as_object_mut()
            .unwrap()
            .remove("truncated");
        assert!(project_committed_stream_scan(no_truncation).is_err());
        assert!(project_committed_stream_scan(stream_projection_fixture(2)?).is_err());
        Ok(())
    }

    #[test]
    fn webvh_service_log_exposes_core_only_after_verified_history() -> Result<()> {
        use arkret_test_kit::service_identity::ServiceIdentityFixture;

        let now = Utc::now();
        let fixture = ServiceIdentityFixture::webvh(
            &url::Url::parse("https://flagon-wire.example/")?,
            781,
            [51; 32],
            "service-key",
            now,
            now,
        )?;
        let mut nonce = [0_u8; 16];
        getrandom::fill(&mut nonce).map_err(anyhow::Error::msg)?;
        struct LogFile(std::path::PathBuf);
        impl Drop for LogFile {
            fn drop(&mut self) {
                let _ = std::fs::remove_file(&self.0);
            }
        }
        let file = LogFile(std::env::temp_dir().join(format!(
            "cotest-verified-service-{}.jsonl",
            hex::encode(nonce)
        )));
        let write = |entry: &Value| -> Result<()> {
            let mut bytes = canonical::canonical_json_bytes(entry)?;
            bytes.push(b'\n');
            std::fs::write(&file.0, bytes)?;
            Ok(())
        };
        let entry = &fixture.history.entries[0];
        write(entry)?;
        let request = json!({
            "did":fixture.history.did, "log_path":file.0, "profile":"service"
        });
        let verified = webvh_verify_log(request.clone())?;
        assert_eq!(verified["verified"], true);
        assert_eq!(verified["did_core_id"], json!(fixture.service_id));
        assert_eq!(verified["head_version_id"], entry["versionId"]);
        assert_eq!(verified["entry_count"], 1);
        assert_ne!(verified["did_core_id"], json!(fixture.history.did));

        for field in ["state", "proof"] {
            let mut tampered = entry.clone();
            if field == "state" {
                tampered["state"]["service"][0]["serviceEndpoint"] =
                    json!("https://substituted.example/");
            } else {
                tampered["proof"][0]["proofValue"] = json!("zInvalidSignature");
            }
            write(&tampered)?;
            assert!(
                webvh_verify_log(request.clone()).is_err(),
                "accepted tampered {field}"
            );
        }
        write(entry)?;
        let other = ServiceIdentityFixture::webvh(
            &url::Url::parse("https://other-wire.example/")?,
            782,
            [52; 32],
            "service-key",
            now,
            now,
        )?;
        let mut wrong_did = request.clone();
        wrong_did["did"] = json!(other.history.did);
        assert!(webvh_verify_log(wrong_did).is_err());
        assert_eq!(
            webvh_verify_log(request)?["did_core_id"],
            json!(fixture.service_id)
        );
        Ok(())
    }

    #[test]
    fn consent_current_oracle_requires_independent_anchors_and_a_real_proof() {
        use arkret_models_collaboration::call_invitation::{
            ConsentCurrentReadRequestBody, ConsentCurrentReadResponseBody,
        };
        let account = AccountId::new(
            DidCoreId::new("ak:did_core:web:holder.example").unwrap(),
            DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        );
        let request: ConsentCurrentReadRequestBody = serde_json::from_value(json!({
            "holder_account_id":account,
            "peer":{"kind":"actor","actor_id":{"kind":"account","account_id":account}},
            "audience_actor_id":{"kind":"service","service_id":account.station_id},
            "nonce":canonical::base64url_encode([19;32]),
        }))
        .unwrap();
        let realm = arkret_wire::RealmId::from_event_id(&EventId::from_digest(
            canonical::DigestSuite::Sha256,
            [43; 32],
        ));
        let method = DidUrl::new("did:web:station.example#federation-fanout-key").unwrap();
        let now = Utc::now().with_nanosecond(0).unwrap();
        let signer = SigningKey::from_bytes(&[41; 32]);
        let mut outcome: ConsentCurrentReadResponseBody = serde_json::from_value(json!({
            "request_digest":arkret_models_collaboration::call_invitation::canonical_request_digest(&request).unwrap(),
            "realm_id":realm,
            "governance_generation":"0",
            "effective_stream_head":{"stream_ref":{"kind":"realm","realm_id":realm},
                "stream_position":2,"commit_id":arkret_wire::RealmCommitId::from_digest([47;32])},
            "current":{"state":"never_written"},
            "evaluated_at":canonical::format_timestamp_canonical(now),
            "expires_at":canonical::format_timestamp_canonical(now+chrono::Duration::seconds(30)),
            "proof":{"verification_method":method,"jws":"pending"},
        })).unwrap();
        arkret_signatures::call_invitation::sign_consent_current_read(&mut outcome, &signer)
            .unwrap();
        let input = json!({
            "request":request,
            "outcome":outcome,
            "expected_realm_id":realm,
            "expected_generation":0,
            "expected_verification_method":method,
            "authority":{"kind":"public_key","public_key_multibase":
                canonical::ed25519_pubkey_to_did_key_multibase(&signer.verifying_key().to_bytes())},
        });
        assert_eq!(
            verify_consent_current(input.clone()).unwrap()["verified"],
            true
        );
        for mutation in ["realm", "generation", "method", "proof", "nonce", "key"] {
            let mut changed = input.clone();
            match mutation {
                "realm" => {
                    changed["expected_realm_id"] = json!(arkret_wire::RealmId::from_event_id(
                        &EventId::from_digest(canonical::DigestSuite::Sha256, [53; 32],)
                    ))
                }
                "generation" => changed["expected_generation"] = json!(1),
                "method" => {
                    changed["expected_verification_method"] =
                        json!("did:web:another.example#federation-fanout-key")
                }
                "proof" => changed["outcome"]["proof"]["jws"] = json!("invalid"),
                "nonce" => {
                    changed["request"]["nonce"] = json!(canonical::base64url_encode([59; 32]))
                }
                "key" => {
                    changed["authority"]["public_key_multibase"] =
                        json!(canonical::ed25519_pubkey_to_did_key_multibase(
                            &SigningKey::from_bytes(&[61; 32]).verifying_key().to_bytes()
                        ))
                }
                _ => unreachable!(),
            }
            assert_eq!(
                verify_consent_current(changed).unwrap()["verified"],
                false,
                "accepted substituted {mutation}"
            );
        }
        let mut missing_anchor = input;
        missing_anchor
            .as_object_mut()
            .unwrap()
            .remove("expected_generation");
        assert!(verify_consent_current(missing_anchor).is_err());
    }

    #[test]
    fn founding_device_event_and_hpke_custody_are_fresh_independent_keys() {
        let first = fresh_device_event_key().unwrap();
        let second = fresh_device_event_key().unwrap();
        let hpke = arkret::crypto::hpke::generate_x25519_keypair().unwrap();
        assert_ne!(first.verifying_key(), second.verifying_key());
        assert_ne!(first.as_bytes().as_slice(), hpke.private_key());
        assert_eq!(
            arkret::crypto::hpke::x25519_public_key(hpke.private_key()).unwrap(),
            *hpke.public_key()
        );
    }

    #[test]
    fn invite_subject_oracle_signs_native_control_and_rejects_device_or_mismatched_custody() {
        let mnemonic = bip39::Mnemonic::from_entropy(&[37; 32]).unwrap();
        let recovery_key = mnemonic.words().collect::<Vec<_>>().join(" ");
        let material = arkret::identity_root::derive_identity_recovery_key_material_from_bip39(
            &recovery_key,
            "",
            0,
        )
        .unwrap();
        let (did, principal_id) = actor_ids(
            "did:webvh:zQmV5MGgUvFGbi15ajBaMzdXR5KQzL3TVDxM7VFQCv5nCwH5C:01kwxhre7cexz894j3nmsvmqh5",
        );
        let subject_account_id = AccountId::new(
            principal_id,
            DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        );
        let root_method = format!(
            "did:key:{}#{}",
            material.root_public_key_multikey, material.root_public_key_multikey
        );
        let input = json!({
            "subject_account_id": subject_account_id,
            "invite_id": "ak:invite:AY6DJbBwavsGTQuBZZiqqw9MVcqPZ8QX8invQ3i2kpi7",
            "realm_id": "ak:realm:AV0aa7N4-6SpEMTq2vRgjNbMjn0vCIqfM5PxnJ-qQpPP",
            "token_commitment": format!("sha256:{}", "ab".repeat(32)),
            "claim_nonce": "native-control-claim-nonce",
            "verification_id": "ak:did_core:web:verifier.example",
            "binding_proof": {
                "verification_id": "ak:did_core:web:verifier.example",
                "verification_method": "did:web:verifier.example#verification-1",
                "subject_account_id": subject_account_id,
                "realm_id": "ak:realm:AV0aa7N4-6SpEMTq2vRgjNbMjn0vCIqfM5PxnJ-qQpPP",
                "audience": "arkret.invite.claim",
                "claim_nonce": "native-control-claim-nonce",
                "expires_at": "2026-10-02T12:00:00.000Z",
                "signature": canonical::base64url_encode([19; 64])
            },
            "verification_method": root_method,
            "subject_did": did,
            "root_public_key_multibase": material.root_public_key_multikey,
            "recovery_key": recovery_key
        });
        let proof: InviteSubjectProof =
            serde_json::from_value(invite_subject_proof(input.clone()).unwrap()).unwrap();
        let parsed: InviteSubjectProofInput = serde_json::from_value(input.clone()).unwrap();
        let transcript = InviteSubjectProofBody::from_wire_parts(
            parsed.subject_account_id,
            parsed.invite_id,
            parsed.realm_id,
            parsed.token_commitment,
            parsed.claim_nonce,
            parsed.verification_id,
            parsed.binding_proof.canonical_digest().unwrap().as_str(),
        )
        .unwrap();
        assert_eq!(
            proof.transcript_digest,
            transcript.transcript_digest().unwrap()
        );
        let signature = ed25519_dalek::Signature::from_slice(
            &canonical::base64url_decode(&proof.signature).unwrap(),
        )
        .unwrap();
        SigningKey::from_bytes(&material.root_seed)
            .verifying_key()
            .verify_strict(&transcript.canonical_bytes().unwrap(), &signature)
            .unwrap();

        let mut device = input.clone();
        device["verification_method"] = json!(format!("{}#ak:device:fixture", did));
        assert!(invite_subject_proof(device).is_err());
        let mut wrong_subject = input.clone();
        wrong_subject["subject_did"] = json!("did:web:other.example");
        assert!(invite_subject_proof(wrong_subject).is_err());
        let mut wrong_key = input.clone();
        wrong_key["root_public_key_multibase"] = json!("unaccepted-key");
        assert!(invite_subject_proof(wrong_key).is_err());
        let mut retired_seed = input;
        retired_seed["signing_seed_b64url"] = json!(canonical::base64url_encode([37; 32]));
        assert!(invite_subject_proof(retired_seed).is_err());
    }

    #[test]
    fn event_identity_excludes_only_current_envelope_carriers() {
        let realm = "ak:realm:AV0aa7N4-6SpEMTq2vRgjNbMjn0vCIqfM5PxnJ-qQpPP";
        let draft = json!({
            "kind": "ak.message.create",
            "realm_id": realm,
            "scope_ref": {"kind": "realm", "realm_id": realm},
            "actor_id": {
                "kind": "account",
                "account_id": {
                    "principal_id": "ak:did_core:web:alice.example",
                    "station_id": "ak:did_core:web:station.example"
                }
            },
            "created_at": "2026-07-07T05:45:49.000Z",
            "payload": {"content": {"kind": "ak.content.text", "body": "first"}}
        });
        let identity = event_derived_id(draft.clone()).unwrap();
        let mut envelope = draft.clone();
        envelope["event_id"] = identity["event_id"].clone();
        envelope["producer_proof"] = json!({"fixture": "outside digest"});
        envelope["unsigned"] = json!({"fixture": "outside digest"});
        assert_eq!(event_derived_id(envelope.clone()).unwrap(), identity);
        envelope["payload"]["content"]["body"] = json!("second");
        assert_ne!(
            event_derived_id(envelope).unwrap()["event_id"],
            identity["event_id"]
        );
        let mut retired = draft;
        retired["proofs"] = json!([]);
        assert!(event_derived_id(retired).is_err());
    }

    #[test]
    fn mimi_consent_authoring_signs_unsigned_binding_and_rejects_tampering() {
        let body = json!({
            "requester_actor_id": {"kind":"account", "account_id": {
                "principal_id":"ak:did_core:web:bob.example", "station_id":"ak:did_core:web:station.example"
            }},
            "holder_account_id": {"principal_id":"ak:did_core:web:alice.example", "station_id":"ak:did_core:web:station.example"},
            "purpose":"voice_call",
            "proofs":[]
        });
        let input = json!({
            "request":body,
            "verification_method":"did:web:bob.example#device-1",
            "created_at":"2026-09-07T00:00:00.000Z",
            "domain":"ak:trust_domain:station.example",
            "audience":"ak:did_core:web:station.example",
            "signing_seed_b64url":canonical::base64url_encode([27;32])
        });
        let proof: PayloadProof =
            serde_json::from_value(mimi_request_consent_proof(input).unwrap()).unwrap();
        let mut request: MimiRequestConsentRequestBody = serde_json::from_value(body).unwrap();
        let bytes = request.proof_binding_bytes(&proof).unwrap();
        assert_eq!(
            bytes,
            request
                .unsigned_proof_binding_bytes(&proof.unsigned())
                .unwrap()
        );
        let key = SigningKey::from_bytes(&[27; 32]);
        arkret_signatures::Ed25519DetachedJwsVerifier::new()
            .verify_detached_jws(
                &proof.jws,
                &bytes,
                &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
                    bytes: key.verifying_key().to_bytes().to_vec(),
                },
            )
            .unwrap();
        request.holder_account_id.principal_id =
            DidCoreId::new("ak:did_core:web:mallory.example").unwrap();
        assert!(request.proof_binding_bytes(&proof).is_err());
        let mut malformed = proof;
        malformed.jws = "pending".to_owned();
        assert!(malformed.validate_production().is_err());
    }

    fn actor_ids(value: &str) -> (Did, DidCoreId) {
        let did = Did::new(value.to_owned()).unwrap();
        let core_id = project_did_to_core_id(&did).unwrap();
        (did, core_id)
    }

    #[test]
    fn event_digest_uses_producer_envelope_canonical_bytes() {
        let (_, actor_id) = actor_ids(
            "did:webvh:zQmV5MGgUvFGbi15ajBaMzdXR5KQzL3TVDxM7VFQCv5nCwH5C:01kwxhre7cexz894j3nmsvmqh5",
        );
        let actor_id = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            actor_id,
            DidCoreId::new("ak:did_core:web:principal.example").unwrap(),
        ));
        let event = json!({
            "event_id": "ak:event:AU_Y0iurnoT0IOtu1_ZyZP3V36hCxZmUCbEVS2jcWjxe",
            "kind": "ak.member.state",
            "realm_id": "ak:realm:AV0aa7N4-6SpEMTq2vRgjNbMjn0vCIqfM5PxnJ-qQpPP",
            "scope_ref": {"kind": "realm", "realm_id": "ak:realm:AV0aa7N4-6SpEMTq2vRgjNbMjn0vCIqfM5PxnJ-qQpPP"},
            "actor_id": actor_id,
            "created_at": "2026-07-07T05:45:49.000Z",
            "payload": {
                "realm_id": "ak:realm:AV0aa7N4-6SpEMTq2vRgjNbMjn0vCIqfM5PxnJ-qQpPP",
                "member_id": actor_id,
                "membership": "join",
                "reason": "invite_accept"
            }
        });

        let digest = event_digest(&event, EventDigestMode::RawCanonicalJson).unwrap();
        let producer_event: Event = serde_json::from_value(event).unwrap();
        let producer_event = producer_event.digest_payload().unwrap();

        assert_eq!(
            digest,
            canonical::canonical_sha256(&producer_event).unwrap()
        );
    }

    #[test]
    fn event_digest_materializes_sdk_ref_defaults() {
        let (_, actor_id) = actor_ids(
            "did:webvh:zQmV5MGgUvFGbi15ajBaMzdXR5KQzL3TVDxM7VFQCv5nCwH5C:01kwxhre7cexz894j3nmsvmqh5",
        );
        let actor_id = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            actor_id,
            DidCoreId::new("ak:did_core:web:principal.example").unwrap(),
        ));
        let event = json!({
            "event_id": "ak:event:AU_Y0iurnoT0IOtu1_ZyZP3V36hCxZmUCbEVS2jcWjxe",
            "kind": "ak.morph.update",
            "realm_id": "ak:realm:AV0aa7N4-6SpEMTq2vRgjNbMjn0vCIqfM5PxnJ-qQpPP",
            "scope_ref": {"kind": "realm", "realm_id": "ak:realm:AV0aa7N4-6SpEMTq2vRgjNbMjn0vCIqfM5PxnJ-qQpPP"},
            "actor_id": actor_id,
            "created_at": "2026-07-07T05:45:49.000Z",
            "semantic_refs": [{
                "role": "authorized_by",
                "id": "ak:grant:AVmnCiapkC3K0OFT032clTI00FaccV3R4XoEuGk4xygg"
            }],
            "payload": {
                "target_ref": "ak:morph:Aa8s5OtJTr4DL7dYQbiLrzNhuis8EyjprcGjTo_qPZDF",
                "patch": [{"op": "replace", "path": "fields.status", "value": "review"}]
            }
        });
        let raw_digest = canonical::canonical_sha256(&event).unwrap();
        let sdk_digest = event_digest(&event, EventDigestMode::RawCanonicalJson).unwrap();
        let sdk_event: Event = serde_json::from_value(event).unwrap();
        let sdk_payload = sdk_event.digest_payload().unwrap();

        assert_eq!(sdk_payload["semantic_refs"][0]["critical"], json!(true));
        assert_ne!(sdk_digest, raw_digest);
        assert_eq!(
            sdk_digest,
            canonical::canonical_sha256(&sdk_payload).unwrap()
        );
    }

    #[test]
    fn fallback_event_signer_uses_sdk_method_bound_development_key() {
        let method = "did:webvh:z6mkfixture:alice.example#device";

        assert_eq!(
            arkret_test_kit::development_signing_key(method).verifying_key(),
            arkret_test_kit::keys::development_verifying_key(method)
        );
        assert_ne!(
            arkret_test_kit::development_signing_key(method).verifying_key(),
            arkret_test_kit::keys::development_verifying_key(
                "did:webvh:z6mkfixture:alice.example#other-device"
            )
        );
    }

    #[test]
    fn event_proof_with_registered_seed_verifies_through_sdk() {
        let (actor_did, actor_id) = actor_ids("did:webvh:z6mkfixture:alice.example");
        let actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            actor_id.clone(),
            DidCoreId::new("ak:did_core:web:principal.example").unwrap(),
        ));
        let verification_method = format!("{actor_did}#device-signing-key");
        let seed = [42u8; 32];
        let signing_key = SigningKey::from_bytes(&seed);
        let event = json!({
            "event_id": "ak:event:AU_Y0iurnoT0IOtu1_ZyZP3V36hCxZmUCbEVS2jcWjxe",
            "kind": "ak.member.state",
            "realm_id": "ak:realm:AV0aa7N4-6SpEMTq2vRgjNbMjn0vCIqfM5PxnJ-qQpPP",
            "scope_ref": {"kind": "realm", "realm_id": "ak:realm:AV0aa7N4-6SpEMTq2vRgjNbMjn0vCIqfM5PxnJ-qQpPP"},
            "actor_id": actor,
            "created_at": "2026-07-07T05:45:49.000Z",
            "payload": {
                "realm_id": "ak:realm:AV0aa7N4-6SpEMTq2vRgjNbMjn0vCIqfM5PxnJ-qQpPP",
                "scope_ref": {"kind": "realm", "realm_id": "ak:realm:AV0aa7N4-6SpEMTq2vRgjNbMjn0vCIqfM5PxnJ-qQpPP"},
                "actor_id": actor,
                "membership": "join"
            }
        });
        let proof_value = event_proof(
            json!({
                "actor_did": actor_did,
                "verification_method": verification_method,
                "created_at": "2026-07-07T05:45:49.000Z",
                "event": event,
                "signing_seed_b64url": base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .encode(seed)
            }),
            EventDigestMode::RawCanonicalJson,
        )
        .unwrap();
        let proof: ProducerEventProof = serde_json::from_value(proof_value).unwrap();

        let sdk_event: Event = serde_json::from_value(event).unwrap();
        let canonical_bytes =
            canonical::canonical_json_bytes(&sdk_event.digest_payload().unwrap()).unwrap();
        let public_key = arkret_signatures::proof::PublicKeyMaterial::Ed25519Raw {
            bytes: signing_key.verifying_key().to_bytes().to_vec(),
        };

        assert_eq!(proof.verification_method, verification_method);
        arkret_signatures::proof::verify_ed25519_detached_jws_proof(
            &proof,
            &canonical_bytes,
            &actor,
            &public_key,
        )
        .unwrap();
    }

    #[test]
    fn sibling_pairing_proof_approval_and_session_request_compose() {
        let (did, principal_id) = actor_ids("did:web:alice.example");
        let account = AccountId::new(
            principal_id.clone(),
            DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        );
        let candidate_seed = [7_u8; 32];
        let candidate = SigningKey::from_bytes(&candidate_seed);
        let device_id = "ak:device:01904100-0000-7000-8000-000000000002";
        let stage_request = json!({
            "new_device_public_key": {
                "kty": "OKP",
                "kid": device_id,
                "algorithm": "Ed25519",
                "key": canonical::base64url_encode(candidate.verifying_key().to_bytes())
            },
            "client_nonce": "AAAAAAAAAAAAAAAAAAAAAA"
        });
        let stage_outcome = json!({
            "device_pairing_request_id": "device_pairing_request:01904100-0000-7000-8000-000000000003",
            "pairing_code": "ABCDEFGH",
            "gate_audience_uri": "https://account.example",
            "server_nonce": "BBBBBBBBBBBBBBBBBBBBBB",
            "expires_at": "2099-01-01T00:00:00.000Z"
        });
        let proof = device_pairing_target_proof(json!({
            "account_id": account,
            "stage_request": stage_request,
            "stage_outcome": stage_outcome,
            "device_signing_seed_b64url": canonical::base64url_encode(candidate_seed),
            "hpke_public_key_b64url": canonical::base64url_encode([5_u8; 32])
        }))
        .unwrap();
        assert_eq!(proof["account_id"], json!(account));
        assert_eq!(proof["device_id"], json!(device_id));

        let mut bootstrap = stage_outcome;
        bootstrap["arkret_base_url"] = json!("https://station.example");
        bootstrap["new_device_public_key"] = stage_request["new_device_public_key"].clone();
        bootstrap["client_nonce"] = stage_request["client_nonce"].clone();
        let approving_device = "ak:device:01904100-0000-7000-8000-000000000001";
        let approve = |approving_account: &AccountId| {
            device_pairing_approval(json!({
                "bootstrap": bootstrap,
                "target_proof": proof,
                "approving_account_id": approving_account,
                "approving_did": did,
                "approving_device_id": approving_device,
                "approving_signing_seed_b64url": canonical::base64url_encode([9_u8; 32]),
                "principal_control_realm_id": "ak:realm:AV0aa7N4-6SpEMTq2vRgjNbMjn0vCIqfM5PxnJ-qQpPP",
                "authorized_generation_ref": 1
            }))
        };
        let request = approve(&account).unwrap();
        let event = &request["authorize_event"]["event"];
        assert_eq!(event["kind"], json!("ak.device.authorize"));
        let payload = &event["payload"];
        for member in [
            "device_id",
            "device_public_key_did",
            "hpke_key",
            "algorithms",
            "device_signature",
            "pairing_challenge_transcript_digest",
        ] {
            assert_eq!(payload[member], proof[member], "{member}");
        }
        assert_eq!(payload["authorized_by"], json!(approving_device));
        assert_eq!(
            event["producer_proof"]["verification_method"],
            json!(format!("{did}#{approving_device}"))
        );
        // Same principal core under another Station is another account: the
        // approving side must refuse the attestation (section 5.2.2).
        let other_station = AccountId::new(
            principal_id,
            DidCoreId::new("ak:did_core:web:other-station.example").unwrap(),
        );
        assert!(approve(&other_station).is_err());

        let session_request = human_session_grant_request(json!({
            "principal_did": did,
            "account_id": account,
            "device_id": device_id,
            "holder_jkt": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "account_subject": format!("sha256:{}", "ab".repeat(32)),
            "account_handoff_grant": "handoff.jwt",
            "handoff_expires_at": "2099-01-01T00:00:00.000Z",
            "device_signing_seed_b64url": canonical::base64url_encode(candidate_seed)
        }))
        .unwrap();
        let body: arkret::SessionGrantRequestBody =
            serde_json::from_value(session_request).unwrap();
        body.validate().unwrap();
        assert!(matches!(body, arkret::SessionGrantRequestBody::Human(_)));
    }
    #[test]
    fn project_did_core_id_is_an_adapter_projection_without_verification_credit() -> Result<()> {
        let projected = project_did_core_id(json!({"did":"did:web:flagon.example"}))?;
        assert_eq!(
            projected,
            json!({"did_core_id":"ak:did_core:web:flagon.example"})
        );
        assert!(projected.get("verified").is_none());
        for invalid in [
            json!({"did":"not-a-did"}),
            json!({"did":"ak:did_core:web:flagon.example"}),
            json!({"did":"did:example:flagon"}),
            json!({"did":"did:web:flagon.example#key"}),
            json!({"did":null}),
            json!({"did":"did:web:flagon.example","verified":true}),
        ] {
            assert!(project_did_core_id(invalid).is_err());
        }
        Ok(())
    }
    #[test]
    fn did_web_document_url_uses_sdk_locator_and_rejects_non_document_subjects() -> Result<()> {
        for (did, document_url) in [
            (
                "did:web:flagon.example",
                "https://flagon.example/.well-known/did.json",
            ),
            (
                "did:web:flagon.example%3A9443:directory",
                "https://flagon.example:9443/directory/did.json",
            ),
        ] {
            assert_eq!(
                did_web_document_url(json!({"did":did}))?,
                json!({"document_url":document_url})
            );
        }
        for invalid in [
            json!({"did":"did:web:flagon.example#key"}),
            json!({"did":"ak:did_core:web:flagon.example"}),
            json!({"did":"did:example:flagon"}),
            json!({"did":"did:web:flagon.example::directory"}),
            json!({"did":"did:web:flagon.example:.."}),
            json!({"did":null}),
            json!({"did":"did:web:flagon.example","document_url":"https://substituted.example/"}),
        ] {
            assert!(did_web_document_url(invalid).is_err());
        }
        Ok(())
    }
}
