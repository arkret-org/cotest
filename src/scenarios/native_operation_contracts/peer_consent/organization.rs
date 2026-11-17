//! An independently published Org, admitted by the actual H operator process.
use anyhow::{Context as _, Result, ensure};
use arkret_event_draft::TypedEventDraft;
use arkret_models_collaboration::authority_commit::{
    AuthorityForwardBranch, PeerAuthorityForwardEventRequestBody,
};
use arkret_models_collaboration::events_payloads::realm::{
    RealmCreatePayload, RealmGenesis, RealmPurpose,
};
use arkret_models_identity::{
    AuthenticatedServiceResolution, DidOperationSubmitResponseBody, ResolutionCommitment,
};
use arkret_signatures::webvh::OrganizationInceptionInput;
use arkret_wire::*;
use ed25519_dalek::SigningKey;
use serde_json::Value;

use crate::harness::{ArkretServer, expect_json};
use crate::scenarios::agent_runtime_live::coauth_session_evidence::ActualAgentDeployment;
use crate::scenarios::mls_lifecycle_live::Member;

pub(super) struct Organization {
    pub request: PeerAuthorityForwardEventRequestBody,
    pub bundle: RealmAuthorityBundle,
    pub cli: Value,
    pub publication: DidOperationSubmitResponseBody,
}
impl Organization {
    pub fn account(&self) -> &AccountId {
        self.request
            .event_submission
            .event
            .actor_id
            .as_account_id()
            .expect("verified Org full Account")
    }
    pub fn realm(&self) -> &RealmId {
        &self.request.event_submission.event.realm_id
    }
}

pub(super) fn entropy() -> Result<[u8; 32]> {
    let mut bytes = [0; 32];
    getrandom::fill(&mut bytes).context("native Org key/nonce entropy")?;
    Ok(bytes)
}

pub(super) async fn service_resolution(
    station: &ArkretServer,
) -> Result<AuthenticatedServiceResolution> {
    let path = arkret_models_identity::canonical_service_resolution_path(station.service_id());
    let value = expect_json(
        station.http().get(station.url(&path)),
        reqwest::StatusCode::OK,
    )
    .await?;
    let source: AuthenticatedServiceResolution = serde_json::from_value(value)?;
    ensure!(
        source.service_id == *station.service_id(),
        "Service resolution names another real process"
    );
    arkret_identity::verify_authenticated_service_resolution_history(
        &source,
        station.service_id(),
        chrono::Utc::now(),
    )?;
    Ok(source)
}

fn assertion_method(
    source: &AuthenticatedServiceResolution,
    key: &SigningKey,
    at: chrono::DateTime<chrono::Utc>,
) -> Result<DidUrl> {
    let document =
        arkret_identity::authenticated_service_document_at(source, &source.service_id, at)?;
    let public = key.verifying_key().to_bytes();
    document
        .verification_methods
        .keys()
        .filter_map(|id| DidUrl::new(id).ok())
        .find(|method| {
            arkret_identity::validate_verification_method_relationship(
                &document,
                method,
                &document.id,
                arkret_identity::DidVerificationRelationship::AssertionMethod,
            )
            .is_ok()
                && arkret_identity::public_key_material_from_document(&document, method)
                    .ok()
                    .and_then(|material| material.ed25519_bytes().ok())
                    == Some(public)
        })
        .context("real held Service key has no published authorized assertion method")
}

pub(super) fn verify_bundle(
    bundle: &RealmAuthorityBundle,
    nonce: &Base64UrlString,
    governor: &AuthenticatedServiceResolution,
) -> Result<()> {
    let mut keys = arkret_identity::RealmAuthorityKeyMap::new();
    for signature in [
        &bundle.genesis_commit.signature,
        &bundle.current_assertion.signature,
    ] {
        let did = arkret_identity::verification_method_did(signature.verification_method.as_str())?;
        ensure!(
            project_did_to_core_id(&did)? == governor.service_id,
            "initial native G signer came from another Service"
        );
        let document = arkret_identity::authenticated_service_document_at(
            governor,
            &governor.service_id,
            signature.created_at,
        )?;
        arkret_identity::validate_verification_method_relationship(
            &document,
            &signature.verification_method,
            &did,
            arkret_identity::DidVerificationRelationship::AssertionMethod,
        )?;
        keys.insert_at(
            &signature.verification_method,
            signature.created_at,
            arkret_identity::public_key_material_from_document(
                &document,
                &signature.verification_method,
            )?,
        );
    }
    let verified = arkret_identity::verify_realm_authority_bundle(
        bundle,
        &arkret_identity::RealmAuthorityFreshness::new(chrono::Utc::now(), nonce.clone()),
        &keys,
    )?;
    ensure!(
        verified.current_generation() == 0
            && verified.current_service_id() == &governor.service_id
            && bundle.authority_transitions.is_empty(),
        "Org fixture changed tenure outside its one-create unit"
    );
    verified.verify_commit(&bundle.genesis_commit, &keys)?;
    Ok(())
}

pub(super) async fn create(
    hosting: &ActualAgentDeployment,
    governor: &ActualAgentDeployment,
    device: Option<&Member>,
) -> Result<Organization> {
    ensure!(
        hosting.station.service_id() != governor.station.service_id()
            && hosting.station.configured_database_url()
                != governor.station.configured_database_url(),
        "Organization split requires independent real H and G"
    );
    let root = entropy()?;
    let next = entropy()?;
    let control = entropy()?;
    let control_key = SigningKey::from_bytes(&control);
    let next_public = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
        SigningKey::from_bytes(&next).verifying_key().as_bytes(),
    );
    let local_id = format!("peer-consent-org-{}", uuid::Uuid::now_v7());
    let inception =
        arkret_signatures::webvh::prepare_organization_inception(&OrganizationInceptionInput {
            provider_endpoint: &hosting.station.base_url(),
            local_id: &local_id,
            version_created_at: chrono::Utc::now(),
            root_seed: &root,
            next_root_public_key_multibase: &next_public,
            control_public_key: &control_key.verifying_key().to_bytes(),
        })?;
    let publication: DidOperationSubmitResponseBody = serde_json::from_value(
        expect_json(
            hosting
                .station
                .http()
                .post(
                    hosting
                        .station
                        .url("/_arkret/root/identity/submit-did-operation"),
                )
                .bearer_auth(&hosting.webvh_registration_bearer)
                .json(&inception.submit_body),
            reqwest::StatusCode::OK,
        )
        .await?,
    )?;
    publication.validate_accepted_for_request(&inception.submit_body)?;
    let did = Did::new(&inception.did)?;
    let document: arkret_identity::DidDocument =
        serde_json::from_value(inception.log_entry["state"].clone())?;
    ensure!(
        document.id == did,
        "published native Org document names another DID"
    );
    let normalized = arkret_models_identity::normalized_did_document(&document)?;
    let control_method = document
        .verification_methods
        .keys()
        .filter_map(|id| DidUrl::new(id).ok())
        .find(|method| {
            normalized["capability_invocations"]
                .as_array()
                .into_iter()
                .flatten()
                .any(|row| row["verification_method"].as_str() == Some(method.as_str()))
                && normalized["verification_methods"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .any(|row| {
                        row["verification_method"].as_str() == Some(method.as_str())
                            && row["controller_did"].as_str() == Some(did.as_str())
                    })
                && arkret_identity::public_key_material_from_document(&document, method)
                    .ok()
                    .and_then(|key| key.ed25519_bytes().ok())
                    == Some(control_key.verifying_key().to_bytes())
        })
        .context("published native Org control method absent")?;
    let account = AccountId::new(
        project_did_to_core_id(&did)?,
        hosting.station.service_id().clone(),
    );
    let object = RealmGenesis::new(
        RealmPurpose::PrincipalControl,
        GenesisSalt::new(arkret_canonical::base64url_encode(entropy()?))?,
        hosting.station.trust_domain().clone(),
        SecurityClass::HighAssurance,
        governor.station.service_id().clone(),
        JoinRule::Closed,
        HistoryAccess::SinceJoin,
        Discoverability::Secret,
        None,
        Some(ResolutionCommitment {
            did: did.clone(),
            method_history_head: arkret_canonical::canonical_sha256(&inception.log_entry)?,
            version_id: inception.version_id.clone(),
        }),
    )?;
    let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let service = service_resolution(&governor.station).await?;
    let service_key = governor.station.federation_signing_key()?;
    let (executor, method, key) = if let Some(device) = device {
        ensure!(
            device.account.station_id == *hosting.station.service_id(),
            "finite executor C must have its real Account at H"
        );
        (
            device.actor.clone(),
            device.method.clone(),
            device.key.clone(),
        )
    } else {
        // S=G is explicit and legal, while source/hosting H stays independent.
        (
            ActorId::service(governor.station.service_id().clone()),
            assertion_method(&service, &service_key, at)?,
            service_key,
        )
    };
    let mut authored = TypedEventDraft::<event_spec::RealmCreate>::new(
        ScopeRef::RealmGenesis,
        ActorId::account(account),
        RealmCreatePayload { object },
    )?
    .with_executed_by(executor)
    .with_authorization_ref(
        AuthorizationRef::new(control_method.as_str()).map_err(anyhow::Error::msg)?,
    )
    .author_with_digest_suite(at, arkret_canonical::DigestSuite::Sha256)?;
    arkret_signatures::sign_event(
        &mut authored,
        &arkret_signatures::Ed25519DetachedJwsSigner::new(key, method.as_str().to_owned()),
        arkret_signatures::SignEventOptions::new().with_created_at(at),
    )?;
    let event = authored.into_event();
    let mut vote = ApprovalSignature {
        input: ApprovalSignatureInput {
            approval_context: ApprovalContext::RealmGovernance {},
            approval_target: ApprovalTarget::Event {
                event_id: event.event_id.clone(),
            },
            request_canonical_digest: Hash::new(arkret_canonical::canonical_sha256(&event)?)?,
            operation: ServiceOperationId::PEER_EVENTS_COMMAND_SUBMIT_V1.into(),
            action: CapabilityActionId::RealmCreate,
            realm_id: event.realm_id.clone(),
            initiating_actor_id: event.actor_id.clone(),
            approver_did: did,
            approved_at: arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now()),
            nonce: arkret_canonical::base64url_encode(entropy()?),
        },
        proof: ApprovalSignatureProof {
            kind: ApprovalSignatureProofKind::DetachedJws,
            verification_method: control_method.clone(),
            jws: String::new(),
        },
    };
    vote.proof.jws =
        arkret_signatures::Ed25519DetachedJwsSigner::new(control_key, control_method.to_string())
            .sign_detached_jws(
                &arkret_signatures::approval_signature::approval_signature_signing_bytes(&vote)?,
            );
    let original = EventAdmissionSubmission {
        event,
        approval_signatures: Some(vec![vote]),
    };
    arkret_identity::organization_pcr_genesis::verify_organization_pcr_genesis_authority(
        &original,
        &[inception.log_entry],
        &[],
        chrono::Utc::now(),
    )?;
    let request = PeerAuthorityForwardEventRequestBody {
        branch: AuthorityForwardBranch::AuthorityForward,
        event_submission: original,
        mls_group_state_material: None,
        content_backup_sources: None,
        producer_device_evidence: None,
        producer_agent_evidence: None,
        successor_device_evidence: None,
    };
    // The Device input is local preparation only. H itself must issue a real
    // current attestation before transmitting any standard peer body.
    if device.is_none() {
        request.validate()?;
    }
    let cli = hosting
        .station
        .accept_organization_hosting(&request)
        .await?;
    let outcome: AuthoritySubmitResponseBody =
        serde_json::from_value(cli["report"]["outcome"].clone())?;
    let AuthoritySubmitResponseBody::Accepted {
        status: AuthorityCommitStatus::Committed,
        commit,
    } = outcome
    else {
        anyhow::bail!("actual H CLI did not retain the genuine G original");
    };
    let nonce = Base64UrlString::new(arkret_canonical::base64url_encode(entropy()?))
        .map_err(anyhow::Error::msg)?;
    let bundle_request = RealmAuthorityBundleRequestBody {
        realm_id: request.event_submission.event.realm_id.clone(),
        nonce: nonce.clone(),
    };
    let bundle: RealmAuthorityBundle = serde_json::from_value(
        expect_json(
            governor
                .station
                .http()
                .post(governor.station.url("/_arkret/open/realm-authority/bundle"))
                .json(&bundle_request),
            reqwest::StatusCode::OK,
        )
        .await?,
    )?;
    verify_bundle(
        &bundle,
        &nonce,
        &service_resolution(&governor.station).await?,
    )?;
    ensure!(
        bundle.genesis_event == request.event_submission.event && bundle.genesis_commit == commit,
        "H CLI original differs from independently verified G public source"
    );
    let fact =
        arkret_models_collaboration::authority_commit::organization_genesis_signer_fact(&bundle)?
            .context("true Org public fact absent")?;
    ensure!(
        fact.approval_signatures == request.event_submission.approval_signatures,
        "G source changed the exact finite vote vector"
    );
    ensure!(
        fact.public_key_base64url.is_some() == device.is_some(),
        "G source changed the actual producer class"
    );
    Ok(Organization {
        request,
        bundle,
        cli,
        publication,
    })
}
