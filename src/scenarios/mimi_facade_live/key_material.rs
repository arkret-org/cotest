//! Native claims cross the facade without a second receipt or allocation ledger.
use arkret_models_crypto::PeerKeyPackageRequesterAuthorization;
use arkret_wire::{EventKind, MimiRoomUri, NonEmptyString, RealmId, ScopeRef, StrandId};
use ed25519_dalek::Signer as _;

use super::*;

#[allow(clippy::too_many_arguments)]
pub(super) async fn run(
    server: &ArkretServer,
    requester: &Member,
    coauth: &MockCoauthIntrospectionServer,
    database: &str,
    realm: &str,
    strand: &str,
    provider: &str,
) -> Result<()> {
    use crate::scenarios::mls_lifecycle_live as lifecycle;
    let target = Member::provision(
        server,
        coauth,
        "mimi-claim-target",
        "ak:device:01904100-0000-7000-8000-000000002884",
    )
    .await?;
    let join = target.client.author_event(realm, EventKind::MemberState.as_str(),
        crate::scenarios::human_device_producer_live::membership_payload(realm, target.account.clone(),
            arkret_models_collaboration::governance::membership_invite::MembershipPayloadState::Join,
            "MIMI native claim target")?).await?;
    submit_and_expect_commit(
        &target.client,
        &target.account,
        target.device.as_str(),
        &join,
    )
    .await?;
    let identity = target.mls_identity()?;
    let packages = [
        identity.key_package_record()?,
        identity.key_package_record()?,
        identity.key_package_record()?,
        identity.key_package_record()?,
    ];
    let upload = identity.signed_key_packages_upload_request(&packages, target.method.as_str())?;
    let uploaded: arkret_models_crypto::KeyPackagesUploadResponseBody = serde_json::from_value(
        expect_json(
            target
                .client
                .post("/_arkret/self/keys/keypackages/upload")
                .canonical_json(&upload)?,
            StatusCode::OK,
        )
        .await?,
    )?;
    ensure!(
        uploaded.accepted_count == 4,
        "MIMI packages were not published: {uploaded:?}"
    );
    let realm_id = RealmId::new(realm.to_owned())?;
    let group = ScopeRef::Realm {
        realm_id: realm_id.clone(),
    }
    .canonical_mls_group_id()?;
    let room =
        MimiRoomUri::new(format!("{provider}/rooms/{strand}")).map_err(anyhow::Error::msg)?;
    let sdk = provider_sdk(server, provider)?.with_mimi_room(room.clone())?;
    let mut native = lifecycle::claim_request_between(
        requester,
        server,
        server,
        &target,
        &realm_id,
        group.as_str(),
        [219; 16],
        chrono::Duration::minutes(5),
    )?;
    native.required_capabilities =
        vec![NonEmptyString::new("mimi.content.v1").map_err(anyhow::Error::msg)?];
    native.strand_id = Some(StrandId::new(strand.to_owned())?);
    lifecycle::resign_claim(requester, &mut native)?;
    let request = native.clone();
    let before = lifecycle::upload_durable_cut(database).await?;
    let wrong_room = provider_sdk(server, provider)?.with_mimi_room(
        MimiRoomUri::new(format!("{provider}/rooms/unknown")).map_err(anyhow::Error::msg)?,
    )?;
    let failure = wrong_room
        .mimi_request_key_material(&request, server.trust_domain(), server.trust_domain())
        .await
        .unwrap_err();
    ensure!(
        matches!(failure, arkret_http_client::Error::Api { ref error, .. } if error.code()=="claim_failed"),
        "unknown room: {failure:?}"
    );
    ensure!(
        lifecycle::upload_durable_cut(database).await? == before,
        "unknown room allocated or wrote a ledger"
    );
    for mutation in ["last_resort", "missing_content_capability"] {
        let mut invalid = native.clone();
        if mutation == "last_resort" {
            invalid.last_resort_allowed = Some(true);
        } else {
            invalid.required_capabilities =
                vec![NonEmptyString::new("ak.content.v1").map_err(anyhow::Error::msg)?];
        }
        lifecycle::resign_claim(requester, &mut invalid)?;
        let (status, problem) = super::signed_post_inner(
            server,
            "/_arkret/open/mimi/key-material",
            Some(room.as_str()),
            server.service_id().as_str(),
            &serde_json::to_value(invalid)?,
            None,
        )
        .await?;
        ensure!(
            !status.is_success()
                && problem["type"]
                    .as_str()
                    .is_some_and(|value| value.ends_with("/claim_failed")),
            "{mutation}: {status} {problem}"
        );
        ensure!(
            lifecycle::upload_durable_cut(database).await? == before,
            "{mutation} allocated or wrote a ledger"
        );
    }
    let mut provider_only = native.clone();
    provider_only.claim_request_id =
        arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode([221_u8; 16]))
            .map_err(anyhow::Error::msg)?;
    let input = arkret_models_crypto::keypackage_claim_authorization_signing_bytes(
        &provider_only.unsigned_request(),
        &provider_only.service_binding,
        &provider_only.requester_authorization,
    )?;
    if let PeerKeyPackageRequesterAuthorization::Device { signature, .. } =
        &mut provider_only.requester_authorization
    {
        let bytes = arkret_canonical::base64url_encode(
            server.federation_signing_key()?.sign(&input).to_bytes(),
        );
        signature.signature =
            arkret_wire::Base64UrlString::new(bytes).map_err(anyhow::Error::msg)?;
    }
    let failure = sdk
        .mimi_request_key_material(&provider_only, server.trust_domain(), server.trust_domain())
        .await
        .unwrap_err();
    ensure!(
        matches!(failure, arkret_http_client::Error::Api { ref error, .. } if error.code()=="claim_failed"),
        "provider-only authorization: {failure:?}"
    );
    ensure!(
        lifecycle::upload_durable_cut(database).await? == before,
        "provider signature replaced participant authority"
    );
    let first = sdk
        .mimi_request_key_material(&request, server.trust_domain(), server.trust_domain())
        .await?;
    ensure!(
        first
            .claim_outcome
            .as_ref()
            .is_some_and(|outcome| outcome.claims.len() == 1),
        "native MIMI claim: {first:?}"
    );
    let after = lifecycle::upload_durable_cut(database).await?;
    let retry = sdk
        .mimi_request_key_material(&request, server.trust_domain(), server.trust_domain())
        .await?;
    ensure!(
        serde_json::to_value(&retry)? == serde_json::to_value(&first)?,
        "facade lost-response recovery replaced original result"
    );
    let (status, body) = lifecycle::post_claim(&requester.client, &native).await?;
    ensure!(
        status == StatusCode::OK,
        "native replay: {status} {}",
        String::from_utf8_lossy(&body)
    );
    let replay: arkret_models_crypto::KeyPackagesClaimResponseBody = serde_json::from_slice(&body)?;
    ensure!(
        serde_json::to_value(replay)?
            == serde_json::to_value(
                first
                    .claim_outcome
                    .as_ref()
                    .context("MIMI original claim")?
            )?,
        "native and facade allocated distinct results"
    );
    ensure!(
        lifecycle::upload_durable_cut(database).await? == after,
        "cross-URL recovery allocated again"
    );
    native.claim_request_id =
        arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode([220_u8; 16]))
            .map_err(anyhow::Error::msg)?;
    lifecycle::resign_claim(requester, &mut native)?;
    let request = native.clone();
    let (status, body) = lifecycle::post_claim(&requester.client, &native).await?;
    ensure!(
        status == StatusCode::OK,
        "native first claim: {status} {}",
        String::from_utf8_lossy(&body)
    );
    let original: arkret_models_crypto::KeyPackagesClaimResponseBody =
        serde_json::from_slice(&body)?;
    ensure!(original.claims.len() == 1, "native second material missing");
    let after = lifecycle::upload_durable_cut(database).await?;
    let recovered = sdk
        .mimi_request_key_material(&request, server.trust_domain(), server.trust_domain())
        .await?;
    ensure!(
        serde_json::to_value(
            recovered
                .claim_outcome
                .as_ref()
                .context("recovered native claim")?
        )? == serde_json::to_value(&original)?,
        "facade did not recover native result"
    );
    ensure!(
        lifecycle::upload_durable_cut(database).await? == after,
        "native-to-facade recovery wrote durable state"
    );
    let mut expiring = lifecycle::claim_request_between(
        requester,
        server,
        server,
        &target,
        &realm_id,
        group.as_str(),
        [223; 16],
        chrono::Duration::seconds(2),
    )?;
    expiring.required_capabilities = native.required_capabilities.clone();
    expiring.strand_id = native.strand_id.clone();
    lifecycle::resign_claim(requester, &mut expiring)?;
    let expiring = expiring.clone();
    let allocated = sdk
        .mimi_request_key_material(&expiring, server.trust_domain(), server.trust_domain())
        .await?;
    ensure!(
        allocated.claim_outcome.is_some(),
        "expiring claim did not allocate"
    );
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    let expired = sdk
        .mimi_request_key_material(&expiring, server.trust_domain(), server.trust_domain())
        .await?;
    // Ordinary single-use claims become revoked/unusable on expiry (§9).
    // Recovery still retains the original outcome; it cannot republish it.
    ensure!(
        expired.state == arkret_models_crypto::PeerKeyPackagesClaimQueryState::Revoked
            && serde_json::to_value(&expired.claim_outcome)?
                == serde_json::to_value(&allocated.claim_outcome)?,
        "expired intent lost its original signed result: {expired:?}"
    );
    let expired_cut = lifecycle::upload_durable_cut(database).await?;
    let expired_retry = sdk
        .mimi_request_key_material(&expiring, server.trust_domain(), server.trust_domain())
        .await?;
    ensure!(
        serde_json::to_value(expired_retry)? == serde_json::to_value(expired)?
            && lifecycle::upload_durable_cut(database).await? == expired_cut,
        "expired recovery changed its terminal result or allocated again"
    );
    let revoke = requester.client.author_event(realm, EventKind::MimiRoomBinding.as_str(), json!({
        "profile":"ak.profile.mimi_interop.v1", "mimi_room_uri":room,
        "binding_scope":{"realm_id":realm,"strand_id":strand}, "hub_provider_id":server.service_id(),
        "local_provider_role":"hub", "status":"revoked", "mls_group_id":group
    })).await?;
    submit_and_expect_commit(
        &requester.client,
        &requester.account,
        requester.device.as_str(),
        &revoke,
    )
    .await?;
    let before = lifecycle::upload_durable_cut(database).await?;
    let replay = sdk
        .mimi_request_key_material(&request, server.trust_domain(), server.trust_domain())
        .await?;
    ensure!(
        serde_json::to_value(&replay.claim_outcome)? == serde_json::to_value(Some(&original))?,
        "revoked room hid the original claim result"
    );
    ensure!(
        lifecycle::upload_durable_cut(database).await? == before,
        "revoked binding replay changed original claim"
    );
    native.claim_request_id =
        arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode([222_u8; 16]))
            .map_err(anyhow::Error::msg)?;
    lifecycle::resign_claim(requester, &mut native)?;
    let failure = sdk
        .mimi_request_key_material(&native, server.trust_domain(), server.trust_domain())
        .await
        .unwrap_err();
    ensure!(
        matches!(failure, arkret_http_client::Error::Api { ref error, .. } if error.code()=="claim_failed"),
        "fresh claim in revoked room: {failure:?}"
    );
    ensure!(
        lifecycle::upload_durable_cut(database).await? == before,
        "fresh claim in revoked room wrote material or a claim ledger"
    );
    eprintln!(
        "MIMI native claim: participant authorization; unknown-room zero material/claim-ledger writes; cross-URL exact recovery in both directions; expired and revoked-room results recovered; revoked-room fresh allocation rejected"
    );
    Ok(())
}
