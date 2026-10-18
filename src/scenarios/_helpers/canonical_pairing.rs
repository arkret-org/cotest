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

fn handoff_client(
    fixture: &CanonicalApiFixture,
    handoff: &provisioning::AccountHandoff,
) -> Result<Client> {
    let key = handoff.device_key.signing_key();
    Ok(Client::builder(fixture.endpoints.coauth_base_url.parse()?)
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

async fn handoff(
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

pub async fn pair(fixture: &CanonicalApiFixture) -> Result<TestActorClient> {
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
    let identity_key = FoundingDeviceKey::derive("api-sibling-identity");
    let holder_key = FoundingDeviceKey::derive("api-sibling-holder");
    ensure!(
        identity_key.signing_key().verifying_key() != holder_key.signing_key().verifying_key(),
        "Device and Standard holder keys must be independent"
    );
    let hpke_entropy = FoundingDeviceKey::derive("api-sibling-hpke");
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
    let event_id = approval.authorize_event.event.event_id.clone();
    let gate = Client::builder(fixture.endpoints.coauth_base_url.parse()?)
        .http_client(fixture.http.clone())
        .auth(session_auth(fixture.client.session())?)
        .build()?;
    let paired = gate
        .account_device_pair(&fixture.client.verify_publication(approval.clone())?)
        .await?;
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
