//! Verify actual issuer output using its accepted own-Station media binding.

use cotest::scenarios::mls_lifecycle_live::fresh_uuid_v7;

use super::*;

#[inline(never)]
pub(super) fn verify<'a>(
    holder: &'a Member,
    request: &'a arkret_models_collaboration::objects::media::CallMediaTokenExchangeRequestBody,
    outcome: &'a arkret_models_collaboration::objects::media::CallMediaTokenExchangeResponseBody,
    binding: &'a arkret_models_identity::MediaServiceBindingResponseBody,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> {
    Box::pin(verify_inner(holder, request, outcome, binding))
}

pub(super) async fn binding(
    holder: &Member,
    realm: &arkret_wire::RealmId,
) -> Result<arkret_models_identity::MediaServiceBindingResponseBody> {
    // This fixture's accepted ak.realm.media_service explicitly names the
    // holder Station as media service; never take this anchor from the token.
    let query = arkret_models_identity::MediaServiceBindingRequestBody {
        request_id: format!("ak:request:{}", fresh_uuid_v7()).parse()?,
        realm_id: realm.clone(),
    };
    let binding = holder
        .client
        .sdk()
        .media_service_binding(&query, &holder.account.station_id)
        .await?;
    ensure!(
        binding.route.service_kind == "station",
        "the real Station issuer was relabeled"
    );
    ensure!(
        binding.is_reusable_at(chrono::Utc::now()),
        "the real issuer binding is stale"
    );
    Ok(binding)
}

async fn verify_inner(
    holder: &Member,
    request: &arkret_models_collaboration::objects::media::CallMediaTokenExchangeRequestBody,
    outcome: &arkret_models_collaboration::objects::media::CallMediaTokenExchangeResponseBody,
    binding: &arkret_models_identity::MediaServiceBindingResponseBody,
) -> Result<()> {
    ensure!(
        binding.realm_id == request.realm_id && binding.is_reusable_at(chrono::Utc::now()),
        "media binding does not cover the token cut"
    );
    let mut anchors = arkret_signatures::media::MediaServiceAnchors::new([(
        binding.route.service_id.clone(),
        binding.route.did.clone(),
    )])?;
    for key in &binding.signing_keys {
        let bytes: [u8; 32] = arkret_canonical::base64url_decode(&key.public_key_base64url)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("accepted media signing key must be Ed25519"))?;
        anchors.insert_key(
            key.verification_method.as_str(),
            ed25519_dalek::VerifyingKey::from_bytes(&bytes)?,
        )?;
    }
    arkret_signatures::media::verify_call_media_token_outcome(
        request,
        outcome,
        &anchors,
        chrono::Utc::now(),
    )?;
    let mut public = outcome.clone();
    public.participant_binding.signature = arkret_canonical::base64url_encode([0u8; 64]);
    ensure!(
        arkret_signatures::media::verify_call_media_token_outcome(
            request,
            &public,
            &anchors,
            chrono::Utc::now()
        )
        .is_err(),
        "SDK accepted changed complete participant binding signature"
    );
    let backend = serde_json::to_value(&outcome.backend_token)?;
    fn contains(value: &serde_json::Value, wanted: &str) -> bool {
        match value {
            serde_json::Value::String(value) => value == wanted,
            serde_json::Value::Array(values) => values.iter().any(|value| contains(value, wanted)),
            serde_json::Value::Object(values) => {
                values.values().any(|value| contains(value, wanted))
            }
            _ => false,
        }
    }
    ensure!(
        !contains(&backend, holder.account.principal_id.as_str())
            && !contains(&backend, holder.device.as_str()),
        "backend token exposed real subject coordinates"
    );
    eprintln!(
        "[consent-call] actual_sdk_media_signatures=1 corrupt_public_private_rejected=2 backend_real_subject_fields=0"
    );
    Ok(())
}

#[inline(never)]
pub(super) fn reject_changed_admission_requests<'a>(
    sender: &'a Member,
    holder_host: &'a inkson::sync_engine::NativeAccountHost,
    received: &'a garth::signal::SignalReceiveOutcome,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + 'a>> {
    Box::pin(async move {
        for changed in ["audience", "subject", "device"] {
            let mut altered = received.clone();
            let garth::signal::SignalReceiveOutcome::Accepted {
                call_invitation: Some(delivery),
                ..
            } = &mut altered
            else {
                anyhow::bail!("real product admission material")
            };
            match changed {
                "audience" => delivery.request.audience_actor_id = sender.actor.clone(),
                "subject" => delivery.request.subject_actor_id = sender.actor.clone(),
                "device" => delivery.request.subject_device_id = sender.device.clone(),
                _ => unreachable!(),
            }
            ensure!(
                inkson::conformance::observe_native_call_projection(holder_host, altered).await?
                    == 0,
                "native ringing reused a real outcome for changed {changed}"
            );
        }
        Ok(())
    })
}

pub(super) async fn verify_actual_outcome(
    holder: &Member,
    request: &arkret_models_collaboration::objects::media::CallMediaTokenExchangeRequestBody,
    outcome: &arkret_models_collaboration::objects::media::CallMediaTokenExchangeResponseBody,
) -> Result<()> {
    let accepted = binding(holder, &request.realm_id).await?;
    verify(holder, request, outcome, &accepted).await
}
