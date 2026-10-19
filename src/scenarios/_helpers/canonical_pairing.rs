//! A real accepted-device ceremony for API migration consumers.

use anyhow::{Context, Result, ensure};
use arkret_http_client::{Auth, Client, DpopAuth};
use arkret_models_collaboration::device_pairing::*;
use cotest_test_support::provisioning::{self, FoundingDeviceKey};
use serde_json::json;
use sha2::{Digest as _, Sha256};

use super::CanonicalApiFixture;
use crate::harness::{ClientSession, TestActorClient};

fn session_auth(session: &ClientSession) -> Result<Auth> {
    let ClientSession::Canonical { grant, signing_key } = session else {
        anyhow::bail!("sibling pairing requires a canonical session")
    };
    let key = signing_key.clone();
    Ok(Auth::Dpop(DpopAuth::with_dpop_token(
        grant.clone(),
        move |request| {
            garth::session::dpop::build_http_dpop_proof(request, &key)
                .map_err(|error| arkret_http_client::Error::Protocol(error.to_string()))
        },
    )))
}

pub(super) fn handoff_client(
    fixture: &CanonicalApiFixture,
    handoff: &provisioning::AccountHandoff,
) -> Result<Client> {
    let key = handoff.device_key.signing_key();
    Ok(Client::builder(fixture.endpoints.coauth_base_url.parse()?)
        .allow_insecure_localhost()
        .http_client(fixture.http.clone())
        .auth(Auth::Dpop(DpopAuth::with_dpop_token(
            handoff.account_handoff_grant.clone(),
            move |request| {
                garth::session::dpop::build_http_dpop_proof(request, &key)
                    .map_err(|error| arkret_http_client::Error::Protocol(error.to_string()))
            },
        )))
        .build()?)
}

pub(super) async fn handoff(
    fixture: &CanonicalApiFixture,
    key: FoundingDeviceKey,
) -> Result<provisioning::AccountHandoff> {
    let authorization = provisioning::authorize_with_current_account(
        &fixture.http,
        &fixture.endpoints.coauth_base_url,
        &fixture.oidc_client_id,
    )
    .await?;
    provisioning::create_returning_account_handoff(
        &fixture.http,
        &fixture.endpoints.coauth_base_url,
        fixture.client.service_id(),
        &authorization,
        key,
        &fixture
            .client
            .principal
            .as_ref()
            .context("canonical principal custody")?
            .core_id,
        &fixture.client.principal.as_ref().unwrap().did,
    )
    .await
}

struct PreparedPairing {
    public: Client,
    staged: DevicePairingStageOutcome,
    target: DevicePairingTargetProof,
    approval: AccountDevicePairRequestBody,
    account: arkret_wire::AccountId,
    device_id: arkret_wire::DeviceId,
    identity_key: FoundingDeviceKey,
    holder_key: FoundingDeviceKey,
}
async fn prepare_pairing(fixture: &CanonicalApiFixture) -> Result<PreparedPairing> {
    let original = fixture
        .client
        .principal
        .as_ref()
        .context("founding principal")?;
    let account = arkret_wire::AccountId::new(
        original.core_id.clone(),
        fixture.client.service_id().parse()?,
    );
    let device_id =
        arkret_wire::DeviceId::new(arkret_identifiers::new_prefixed_uuid7("ak:device:"))?;
    let identity_key = FoundingDeviceKey::derive(&format!("{device_id}-identity"));
    let holder_key = FoundingDeviceKey::derive(&format!("{device_id}-holder"));
    ensure!(
        identity_key.signing_key().verifying_key() != holder_key.signing_key().verifying_key(),
        "Device and Standard holder keys must be independent"
    );
    let hpke_entropy = FoundingDeviceKey::derive(&format!("{device_id}-hpke"));
    let hpke = arkret_crypto::identity_root::derive_identity_recovery_key_material(
        &hpke_entropy.signing_key().to_bytes(),
        0,
    )?;
    let public = Client::builder(fixture.endpoints.coland_base_url.parse()?)
        .http_client(fixture.http.clone())
        .build()?;
    let stage_request: DevicePairingStageRequestBody = serde_json::from_value(json!({
        "new_device_pubkey":{"kty":"OKP","kid":device_id,"algorithm":"Ed25519","key":arkret_canonical::base64url_encode(identity_key.signing_key().verifying_key().to_bytes())},
        "client_nonce":arkret_canonical::base64url_encode(&Sha256::digest(device_id.as_str().as_bytes())[..16])
    }))?;
    let staged = public.device_pairing_stage(&stage_request).await?;
    let pending = handoff(fixture, holder_key.clone()).await?;
    let target: DevicePairingTargetProof = serde_json::from_value(
        cotest_test_support::wire::device_pairing_target_proof(json!({
            "account_id":account,"stage_request":stage_request,"stage_outcome":staged,
            "device_signing_seed_b64url":identity_key.seed_b64url,
            "hpke_public_key_b64url":arkret_canonical::base64url_encode(hpke.backup_hpke_public_key)
        }))?,
    )?;
    let finalized = handoff_client(fixture, &pending)?
        .auth_finalize_device_pairing(&DevicePairingFinalizeRequestBody {
            device_pairing_request_id: staged.device_pairing_request_id.clone(),
            pairing_code: staged.pairing_code.clone(),
            target_proof: target.clone(),
        })
        .await?;
    ensure!(
        finalized.state == DevicePairingState::ReadyForClaim,
        "sibling proof did not become claimable"
    );
    let token = arkret_canonical::base64url_encode(arkret_canonical::canonical_json_bytes(
        &json!({"r":staged.device_pairing_request_id,"c":staged.pairing_code}),
    )?);
    let bootstrap = public
        .device_pairing_resolve(&serde_json::from_value(json!({"pairing_token":token}))?)
        .await?;
    let keys = fixture
        .client
        .sdk()
        .keys_query(&serde_json::from_value(
            json!({"device_keys":[{"account_id":account,"device_ids":[original.device_id]}]}),
        )?)
        .await?;
    let key_value = serde_json::to_value(keys)?;
    let generations = key_value["device_generations"]
        .as_array()
        .context("accepted PCR generation set")?;
    let generations = generations
        .iter()
        .filter(|row| row["account_id"] == json!(account))
        .collect::<Vec<_>>();
    ensure!(generations.len() == 1, "ambiguous PCR generation");
    let generation = generations[0]["generation_state"]["current_device_generation_ref"]
        .as_u64()
        .filter(|v| *v >= 1)
        .context("positive current PCR generation")?;
    let approval: AccountDevicePairRequestBody = serde_json::from_value(
        cotest_test_support::wire::device_pairing_approval(json!({
            "bootstrap":bootstrap,"target_proof":target,"approving_account_id":account,"approving_did":original.did,
            "approving_device_id":original.device_id,"approving_signing_seed_b64url":arkret_canonical::base64url_encode(original.device_signing_key.to_bytes()),
            "principal_control_realm_id":original.pcr_realm_id,"authorized_generation_ref":generation
        }))?,
    )?;
    Ok(PreparedPairing {
        public,
        staged,
        target,
        approval,
        account,
        device_id,
        identity_key,
        holder_key,
    })
}
pub(super) async fn prepare_pairing_request(
    fixture: &CanonicalApiFixture,
) -> Result<(
    Client,
    arkret_identity::VerifiedSubmission<AccountDevicePairRequestBody>,
)> {
    let prepared = prepare_pairing(fixture).await?;
    let gate = Client::builder(fixture.endpoints.coauth_base_url.parse()?)
        .allow_insecure_localhost()
        .http_client(fixture.http.clone())
        .auth(session_auth(fixture.client.session())?)
        .build()?;
    let approval = fixture.client.verify_publication(prepared.approval)?;
    Ok((gate, approval))
}
pub async fn pair(fixture: &CanonicalApiFixture) -> Result<TestActorClient> {
    let PreparedPairing {
        public,
        staged,
        target,
        approval,
        account,
        device_id,
        identity_key,
        holder_key,
    } = prepare_pairing(fixture).await?;
    let original = fixture
        .client
        .principal
        .as_ref()
        .context("founding principal")?;
    let event_id = approval.authorize_event.event.event_id.clone();
    let gate = Client::builder(fixture.endpoints.coauth_base_url.parse()?)
        .allow_insecure_localhost()
        .http_client(fixture.http.clone())
        .auth(session_auth(fixture.client.session())?)
        .build()?;
    let verified = fixture.client.verify_publication(approval.clone())?;
    let paired = gate.account_device_pair(&verified).await?;
    let retry = gate.account_device_pair(&verified).await?;
    ensure!(
        serde_json::to_value(&retry)? == serde_json::to_value(&paired)?,
        "exact pairing retry changed the original terminal outcome"
    );
    ensure!(
        paired.device_id == device_id && paired.authorized_event_ref.event_id == event_id,
        "pair outcome changed the candidate authorization"
    );
    let status = public
        .device_pairing_status(&DevicePairingStatusRequestBody {
            device_pairing_request_id: staged.device_pairing_request_id,
            pairing_code: staged.pairing_code,
        })
        .await?;
    ensure!(
        status.state == DevicePairingState::Authorized
            && status.device_id.as_ref() == Some(&device_id)
            && status.authorized_event_ref.as_ref() == Some(&paired.authorized_event_ref),
        "candidate status differs from accepted authorization"
    );
    let returning = handoff(fixture, holder_key.clone()).await?;
    let jkt = arkret_canonical::base64url_encode(Sha256::digest(
        holder_key.canonical_public_jwk()?.as_bytes(),
    ));
    let request: arkret_models_collaboration::session_grants::SessionGrantRequestBody =
        serde_json::from_value(cotest_test_support::wire::human_session_grant_request(
            json!({
                "principal_did":original.did,"account_id":account,"device_id":device_id,"holder_jkt":jkt,
                "account_subject":returning.account_subject,"account_handoff_grant":returning.account_handoff_grant,"handoff_expires_at":returning.expires_at,
                "device_signing_seed_b64url":identity_key.seed_b64url
            }),
        )?)?;
    let grant = handoff_client(fixture, &returning)?
        .auth_issue_session_grant(&request)
        .await?;
    ensure!(
        grant.account_id == account
            && grant.audience_id == account.station_id
            && grant.device_id.as_ref() == Some(&device_id),
        "sibling Standard grant changed the Account, Device or audience"
    );
    let session = ClientSession::Canonical {
        grant: grant.session_grant,
        signing_key: std::sync::Arc::new(holder_key.signing_key()),
    };
    let mut principal = original.clone();
    principal.device_id = device_id.clone();
    principal.device_signing_key = identity_key.signing_key();
    principal.founding_authorize_event_id = event_id.clone();
    crate::harness::register_event_signing_identity(
        original.did.as_str(),
        identity_key.signing_key().to_bytes(),
        format!("{}#{device_id}", original.did),
        account.station_id.clone(),
    );
    let client = fixture.server.actor_client(
        original.did.as_str(),
        device_id.as_str(),
        session,
        Some(principal),
    )?;
    let view =
        super::super::super::mls_lifecycle_live::accepted_full_view(&client, &event_id).await?;
    ensure!(
        view.event == approval.authorize_event.event
            && view.event.realm_id == original.pcr_realm_id,
        "paired device did not read the byte-identical accepted PCR Event"
    );
    let payload = &view.event.payload;
    let target_value = serde_json::to_value(target)?;
    for field in [
        "device_id",
        "device_public_key_did",
        "hpke_key",
        "algorithms",
        "device_signature",
        "pairing_challenge_transcript_digest",
    ] {
        ensure!(
            payload[field] == target_value[field],
            "accepted authorization changed candidate attestation {field}"
        );
    }
    ensure!(
        payload["authorization_binding_kind"] == "accepted_device",
        "pairing substituted another authorization class"
    );
    ensure!(
        client.dev_bearer().is_none(),
        "sibling client fell back to a development bearer"
    );
    Ok(client)
}

pub(super) async fn issue_for_device(
    fixture: &CanonicalApiFixture,
    client: &TestActorClient,
) -> Result<arkret_models_collaboration::session_grants::SessionGrantOutcome> {
    let original = client
        .principal
        .as_ref()
        .context("accepted Device custody")?;
    let holder_key = FoundingDeviceKey::derive(&arkret_identifiers::new_prefixed_uuid7("holder-"));
    let pending = handoff(fixture, holder_key.clone()).await?;
    let jkt = arkret_canonical::base64url_encode(Sha256::digest(
        holder_key.canonical_public_jwk()?.as_bytes(),
    ));
    let account =
        arkret_wire::AccountId::new(original.core_id.clone(), client.service_id().parse()?);
    let request = serde_json::from_value(cotest_test_support::wire::human_session_grant_request(
        json!({"principal_did":original.did,"account_id":account,"device_id":original.device_id,"holder_jkt":jkt,"account_subject":pending.account_subject,"account_handoff_grant":pending.account_handoff_grant,"handoff_expires_at":pending.expires_at,"device_signing_seed_b64url":arkret_canonical::base64url_encode(original.device_signing_key.to_bytes())}),
    )?)?;
    Ok(handoff_client(fixture, &pending)?
        .auth_issue_session_grant(&request)
        .await?)
}
pub(super) async fn refresh_for_device(
    fixture: &CanonicalApiFixture,
    client: &TestActorClient,
) -> Result<arkret_models_collaboration::session_grants::SessionGrantOutcome> {
    use ed25519_dalek::Signer as _;
    let original = client
        .principal
        .as_ref()
        .context("accepted Device custody")?;
    let jwt = client.session().credential();
    let encoded = jwt.split('.').nth(1).context("grant claims")?;
    let claims: arkret_models_identity::SignedSessionGrantClaims =
        serde_json::from_slice(&arkret_canonical::base64url_decode(encoded)?)?;
    let jkt = claims.session_public_key.thumbprint_sha256()?;
    let now = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let unsigned = arkret_wire::UnsignedAcceptedDeviceRefreshPossessionProof {
        context: arkret_wire::AcceptedDevicePossessionProofContext::V1,
        purpose: arkret_wire::AcceptedDeviceRefreshPossessionPurpose::SessionGrantRefresh,
        predecessor_session_grant_id: claims.grant_id.clone(),
        account_id: claims.account_id.clone(),
        device_id: original.device_id.clone(),
        audience_id: claims.audience_id.clone(),
        holder_jkt: jkt.clone(),
        session_intent_digest:
            arkret_models_collaboration::session_grant_bodies::session_grant_refresh_request_digest(
                jwt,
                &claims.grant_id,
                &claims.account_id.principal_id,
                &original.device_id,
                &claims.audience_id,
                &jkt,
            )?,
        issued_at: now,
        expires_at: now + chrono::Duration::minutes(1),
        verification_method: arkret_wire::DidUrl::new(format!(
            "{}#{}",
            original.did, original.device_id
        ))
        .map_err(anyhow::Error::msg)?,
    };
    let signature = arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(
        original
            .device_signing_key
            .sign(&unsigned.canonical_signing_bytes()?)
            .to_bytes(),
    ))
    .map_err(anyhow::Error::msg)?;
    let proof = unsigned.attach_signature(signature)?;
    let request = arkret::session_grant::human_session_grant_refresh_request(
        jwt,
        Some(claims.audience_id),
        original.device_id.clone(),
        proof,
    )?;
    let gate = Client::builder(fixture.endpoints.coauth_base_url.parse()?)
        .allow_insecure_localhost()
        .http_client(fixture.http.clone())
        .auth(session_auth(client.session())?)
        .build()?;
    Ok(gate.auth_refresh_session_grant(&request).await?)
}

/// Issue a real restricted grant; no accepted-device state is fabricated.
pub(super) async fn recovery_candidate(
    fixture: &CanonicalApiFixture,
) -> Result<(
    TestActorClient,
    Client,
    arkret_models_identity::InitialSessionGrantIntent,
)> {
    let device_id =
        arkret_wire::DeviceId::new(arkret_identifiers::new_prefixed_uuid7("ak:device:"))?;
    let identity_key = FoundingDeviceKey::derive(device_id.as_str());
    let holder_key = FoundingDeviceKey::derive(&format!("{device_id}-holder"));
    let pending = handoff(fixture, holder_key.clone()).await?;
    let gate = handoff_client(fixture, &pending)?;
    let original = fixture
        .client
        .principal
        .as_ref()
        .context("account custody")?;
    let request = arkret_models_collaboration::session_grants::SessionGrantRequestBody::Recovery(
        arkret_models_collaboration::session_grant_bodies::RecoverySessionGrantRequest {
            credential_class: arkret_models_identity::SessionGrantCredentialClass::RecoverySession,
            request_id: arkret_identifiers::new_prefixed_uuid7("ak:request:").parse()?,
            principal_id: original.core_id.clone(),
            device_id: device_id.clone(),
            audience_id: fixture.server.service_id().clone(),
        },
    );
    let grant = gate.auth_issue_session_grant(&request).await?;
    let mut principal = original.clone();
    principal.device_id = device_id.clone();
    principal.device_signing_key = identity_key.signing_key();
    crate::harness::register_event_signing_identity(
        original.did.as_str(),
        identity_key.signing_key().to_bytes(),
        format!("{}#{device_id}", original.did),
        fixture.server.service_id().clone(),
    );
    let candidate = fixture.server.actor_client(
        original.did.as_str(),
        device_id.as_str(),
        ClientSession::Canonical {
            grant: grant.session_grant,
            signing_key: std::sync::Arc::new(holder_key.signing_key()),
        },
        Some(principal),
    )?;
    let initial = arkret_models_identity::InitialSessionGrantIntent {
        device_id,
        session_public_key: grant.session_public_key,
        audience_id: grant.audience_id,
    };
    Ok((candidate, gate, initial))
}
