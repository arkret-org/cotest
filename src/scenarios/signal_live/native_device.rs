//! A second Device admitted through the real Account Authority and Station.

use anyhow::{Context as _, Result, ensure};
use arkret_models_collaboration::device_pairing::*;
use arkret_models_collaboration::session_grants::{
    SessionGrantRequestBody, SessionGrantResponseBody,
};
use cotest_test_support::provisioning::{self, FoundingDeviceKey};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::json;

use crate::harness::ClientSession;
use crate::scenarios::agent_runtime_live::coauth_session_evidence::ActualAgentDeployment;
use crate::scenarios::mls_lifecycle_live::{Member, accepted_full_view};

async fn post<T: Serialize, U: DeserializeOwned>(
    deployment: &ActualAgentDeployment,
    path: &str,
    operation: &str,
    token: &str,
    holder: &ed25519_dalek::SigningKey,
    body: &T,
) -> Result<U> {
    let url = format!("{}{path}", deployment.coauth.base_url());
    let proof = arkret_signatures::dpop::build_dpop_proof(
        &arkret_signatures::dpop::DpopProofRequest::new("POST", &url).access_token(token),
        holder,
    )?
    .proof_jwt;
    let response = deployment
        .http
        .post(url)
        .header("Arkret-Operation", operation)
        .header("Authorization", format!("DPoP {token}"))
        .header("DPoP", proof)
        .json(body)
        .send()
        .await?;
    let status = response.status();
    let bytes = response.bytes().await?;
    ensure!(
        status.is_success(),
        "native Device gate {operation} refused {status}: {}",
        String::from_utf8_lossy(&bytes)
    );
    Ok(serde_json::from_slice(&bytes)?)
}

pub(crate) async fn pair(deployment: &ActualAgentDeployment) -> Result<Member> {
    let founder = deployment
        .controller
        .principal
        .as_ref()
        .context("native founding Device")?;
    let device_id =
        arkret_wire::DeviceId::new(arkret_identifiers::new_prefixed_uuid7("ak:device:"))?;
    let identity = FoundingDeviceKey::generate("Signal additional Device")?;
    let key = identity.signing_key();
    let hpke =
        arkret_crypto::identity_root::derive_identity_recovery_key_material(&key.to_bytes(), 0)?;
    let public = arkret_http_client::Client::builder(deployment.station.base_url().clone())
        .http_client(deployment.http.clone())
        .build()?;
    let mut nonce = [0u8; 32];
    getrandom::fill(&mut nonce).context("native Device stage nonce")?;
    let stage: DevicePairingStageRequestBody = serde_json::from_value(json!({
        "new_device_public_key": {"kty":"OKP","kid":device_id,"algorithm":"Ed25519","key":arkret_canonical::base64url_encode(key.verifying_key().to_bytes())},
        "client_nonce":arkret_canonical::base64url_encode(nonce),
    }))?;
    let staged = public.device_pairing_stage(&stage).await?;
    let authorization = provisioning::authorize_with_current_account(
        &deployment.http,
        deployment.coauth.base_url(),
        &deployment.oidc_client_id,
    )
    .await?;
    let handoff = provisioning::create_returning_account_handoff(
        &deployment.http,
        deployment.coauth.base_url(),
        deployment.station.service_id().as_str(),
        &authorization,
        identity.clone(),
        &founder.core_id,
        &founder.did,
    )
    .await?;
    let target: DevicePairingTargetProof = serde_json::from_value(
        cotest_test_support::wire::device_pairing_target_proof(json!({
            "account_id":deployment.account,"stage_request":stage,"stage_outcome":staged,
            "device_signing_seed_b64url":identity.seed_b64url,
            "hpke_public_key_b64url":arkret_canonical::base64url_encode(hpke.backup_hpke_public_key),
        }))?,
    )?;
    let finalized: DevicePairingFinalizeResponseBody = post(
        deployment,
        "/_arkret/gate/account/device-pairing/finalizations",
        "ak.gate.account.command.finalize_device_pairing.v1",
        &handoff.account_handoff_grant,
        &key,
        &DevicePairingFinalizeRequestBody {
            device_pairing_request_id: staged.device_pairing_request_id.clone(),
            pairing_code: staged.pairing_code.clone(),
            target_proof: target.clone(),
        },
    )
    .await?;
    ensure!(finalized.state == DevicePairingState::ReadyForClaim);
    let ClientSession::Canonical { grant, signing_key } = deployment.controller.session() else {
        anyhow::bail!("native Device approval requires the real issuer grant");
    };
    let claimed: DevicePairingCodeClaimResponseBody = post(
        deployment,
        "/_arkret/gate/account/device-pairing/code-claims",
        "ak.gate.account.read.claim_device_pairing_code.v1",
        grant,
        signing_key,
        &DevicePairingCodeClaimRequestBody {
            pairing_code: staged.pairing_code,
        },
    )
    .await?;
    ensure!(
        claimed.device_pairing_request_id == staged.device_pairing_request_id
            && serde_json::to_value(&claimed.target_proof)? == serde_json::to_value(&target)?
    );
    let keys = deployment
        .controller
        .sdk()
        .keys_query(&serde_json::from_value(json!({
            "device_keys":[{"account_id":deployment.account,"device_ids":[founder.device_id]}]
        }))?)
        .await?;
    let keys = serde_json::to_value(keys)?;
    let rows = keys["device_generations"]
        .as_array()
        .context("native Device generations")?
        .iter()
        .filter(|row| row["account_id"] == json!(deployment.account))
        .collect::<Vec<_>>();
    ensure!(rows.len() == 1);
    let generation = rows[0]["generation_state"]["current_device_generation_ref"]
        .as_u64()
        .filter(|value| *value >= 1)
        .context("accepted native generation")?;
    let approval: AccountDevicePairRequestBody = serde_json::from_value(
        cotest_test_support::wire::device_pairing_approval(json!({
            "bootstrap":claimed.bootstrap,"target_proof":target,"approving_account_id":deployment.account,
            "approving_did":founder.did,"approving_device_id":founder.device_id,
            "approving_signing_seed_b64url":arkret_canonical::base64url_encode(founder.device_signing_key.to_bytes()),
            "principal_control_realm_id":founder.pcr_realm_id,"authorized_generation_ref":generation,
        }))?,
    )?;
    let paired: AccountDevicePairResponseBody = post(
        deployment,
        "/_arkret/gate/account/device-pair",
        arkret_wire::ServiceOperationId::GATE_ACCOUNT_COMMAND_PAIR_DEVICE_V1,
        grant,
        signing_key,
        &deployment.controller.verify_publication(approval.clone())?,
    )
    .await?;
    ensure!(
        paired.device_id == device_id
            && paired.authorized_event_ref.event_id == approval.authorize_event.event.event_id
    );
    let accepted = accepted_full_view(
        &deployment.controller,
        &paired.authorized_event_ref.event_id,
    )
    .await?;
    ensure!(accepted.event == approval.authorize_event.event);

    let authorization = provisioning::authorize_with_current_account(
        &deployment.http,
        deployment.coauth.base_url(),
        &deployment.oidc_client_id,
    )
    .await?;
    let handoff = provisioning::create_returning_account_handoff(
        &deployment.http,
        deployment.coauth.base_url(),
        deployment.station.service_id().as_str(),
        &authorization,
        identity.clone(),
        &founder.core_id,
        &founder.did,
    )
    .await?;
    let jkt = arkret_canonical::base64url_encode(arkret_canonical::sha256_bytes(
        identity.canonical_public_jwk()?.as_bytes(),
    ));
    let request: SessionGrantRequestBody = serde_json::from_value(
        cotest_test_support::wire::human_session_grant_request(json!({
            "principal_did":founder.did,"account_id":deployment.account,"device_id":device_id,"holder_jkt":jkt,
            "account_subject":handoff.account_subject,"account_handoff_grant":handoff.account_handoff_grant,
            "handoff_expires_at":handoff.expires_at,"device_signing_seed_b64url":identity.seed_b64url,
        }))?,
    )?;
    let issued: SessionGrantResponseBody = post(
        deployment,
        "/_arkret/gate/account/session-grants",
        "ak.gate.account.command.issue_session_grant.v1",
        &handoff.account_handoff_grant,
        &key,
        &request,
    )
    .await?;
    let mut principal = founder.clone();
    principal.device_id = device_id;
    principal.device_signing_key = key;
    principal.device_hpke_private_key =
        Some(hpke.backup_hpke_serialized_private_key.to_vec().into());
    principal.founding_authorize_event_id = paired.authorized_event_ref.event_id;
    principal.root_key_seed = [0; 32];
    principal.native_root_rotation = None;
    let client = deployment
        .station
        .client_with_founding_device_grant(&principal, issued.session_grant)?;
    Member::from_client(client, deployment.account.clone())
}
