//! Apply a real Push Gateway onboarding snapshot to an owned Station deployment.
use super::*;

impl ArkretServer {
    pub(crate) async fn restart_with_native_push_gateway(
        &mut self,
        resolution: &arkret_models_identity::AuthenticatedServiceResolution,
        receipt_method: &arkret_wire::DidUrl,
    ) -> Result<()> {
        let at = arkret_canonical::normalize_timestamp_canonical(Utc::now());
        anyhow::ensure!(
            resolution.service_kind == arkret_wire::ServiceKind::PushGateway.as_str(),
            "Push Gateway onboarding has another role"
        );
        arkret_identity::verify_authenticated_service_resolution_history(
            resolution,
            &resolution.service_id,
            at,
        )?;
        let document = &resolution.normalized_did_document;
        arkret_identity::validate_verification_method_relationship(
            document,
            receipt_method,
            &document.id,
            arkret_identity::DidVerificationRelationship::AssertionMethod,
        )?;
        let key = arkret_identity::public_key_material_from_document(document, receipt_method)?
            .ed25519_bytes()?;
        let endpoint = Url::parse(&resolution.projection()?.base_url)?;
        anyhow::ensure!(
            endpoint.scheme() == "https",
            "native Gateway onboarding requires actual HTTPS"
        );
        let registry = serde_json::json!([{"canonical_origin":endpoint.origin().ascii_serialization(),"service_did":document.id,"receipt_verification_method":receipt_method,"receipt_public_key_multibase":arkret_canonical::encode_ed25519_pubkey_multibase(&key)}]);
        let config = self
            .external_restart
            .as_mut()
            .context("native Push Gateway onboarding requires an owned Station")?;
        config
            .extra_env
            .retain(|(name, _)| name != "COLAND_TRUSTED_PUSH_GATEWAYS");
        config.extra_env.push((
            "COLAND_TRUSTED_PUSH_GATEWAYS".into(),
            serde_json::to_string(&registry)?,
        ));
        self.restart_external_process().await
    }
}
