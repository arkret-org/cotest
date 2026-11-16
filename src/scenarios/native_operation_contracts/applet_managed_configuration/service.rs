//! Independent Applet custody and the real owned production-host process.
use std::path::PathBuf;

use anyhow::{Context as _, Result, ensure};
use arkret_models_integration::*;
use arkret_test_kit::service_identity::ServiceIdentityFixture;
use arkret_wire::{AppletId, Did, DidUrl, RealmId, ServiceOperationId};
use ed25519_dalek::SigningKey;
use serde_json::json;

use crate::harness::{ArkretServer, reserve_port};
use crate::scenarios::_helpers::managed_applet_host::{Launch, ManagedAppletHost};
use crate::scenarios::mls_lifecycle_live::Member;

/// The worker exits and releases both stores before its directory is reclaimed.
pub(super) struct ManagedService {
    pub host: ManagedAppletHost,
    _directory: tempfile::TempDir,
    pub package: AppletPackage,
    pub epoch: AppletRegistrationEpochEvidence,
    pub identity: ServiceIdentityFixture,
    pub journal: PathBuf,
    pub governor_resolution: arkret_models_identity::AuthenticatedServiceResolution,
    governor_method: DidUrl,
    launch: Launch,
    product: PathBuf,
}

fn random_key() -> Result<[u8; 32]> {
    let mut key = [0; 32];
    getrandom::fill(&mut key)?;
    Ok(key)
}

impl ManagedService {
    pub async fn start(governor: &ArkretServer) -> Result<Self> {
        let directory = tempfile::tempdir()?;
        let root = directory.path().canonicalize()?;
        let mut port = reserve_port()?;
        let origin: url::Url = format!("https://127.0.0.1:{}/", port.port()).parse()?;
        let signing_seed = random_key()?;
        let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
        let entropy = random_key()?;
        let identity = ServiceIdentityFixture::webvh_applet_service(
            &origin,
            u64::from_le_bytes(entropy[..8].try_into()?),
            signing_seed,
            "applet-service-key",
            at,
            at,
        )?;
        ensure!(
            &identity.service_id != governor.service_id(),
            "Applet Service cannot borrow the governor identity"
        );
        let epoch = AppletRegistrationEpochEvidence::from_did_document(
            &identity.resolution.normalized_did_document,
            AppletDidMethodVersionEvidence::versioned(
                "did:webvh",
                Some(
                    identity
                        .resolution
                        .method_history_evidence
                        .boundary()
                        .to_version_id
                        .clone(),
                ),
                None,
            )?,
        )?;
        let controller_seed = random_key()?;
        let controller_key = SigningKey::from_bytes(&controller_seed);
        let multibase = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
            controller_key.verifying_key().as_bytes(),
        );
        let controller = Did::new(format!("did:key:{multibase}"))?;
        let controller_method =
            DidUrl::new(format!("{controller}#{multibase}")).map_err(anyhow::Error::msg)?;
        let mut package = AppletPackage::new(
            "native-managed-configuration",
            AppletId::new(arkret_identifiers::new_prefixed_uuid7("ak:applet:"))?,
            identity.service_id.clone(),
            identity.history.did.clone(),
            arkret_wire::project_did_to_core_id(&controller)?,
            origin.as_str().trim_end_matches('/'),
            vec!["fixture".into()],
            AppletWireNamespaces {
                handles: vec![AppletNamespaceEntry::exclusive(format!(
                    "nativecfg.{}",
                    uuid::Uuid::now_v7().simple()
                ))],
                ..Default::default()
            },
        );
        package.requested_scopes = vec![
            arkret_wire::CapabilityActionId::APPLET_BOT_PROVISION.into(),
            arkret_wire::CapabilityActionId::APPLET_GHOST_PROVISION.into(),
        ];
        package.ghost_policy.enabled = true;
        package.webhook_signature_policy = WebhookSignaturePolicy::http_message_signature(
            identity.verification_method.clone(),
            vec![HttpMessageSignatureAlgorithm::Ed25519],
        );
        package.endpoint_policy = AppletEndpointPolicy {
            endpoints: [
                "/_arkret/edge/applet/transactions",
                "/_arkret/edge/applet/managed-actors/author",
                "/_arkret/edge/applet/configuration",
            ]
            .into_iter()
            .map(|path| AppletEndpointEntry {
                method: AppletEndpointMethod::Post,
                path: path.into(),
                authentication_kind: Some(AppletEndpointAuth::WebhookSignature),
                description: None,
                extra: Default::default(),
            })
            .collect(),
            extra: Default::default(),
        };
        package.stamp_registration_epoch(&epoch)?;
        package.stamp_package_digest()?;
        package.sign(
            &arkret_signatures::Ed25519PayloadSigner::from_did_key_seed(
                controller_seed,
                controller,
                controller_method.clone(),
            ),
            &controller_method,
        )?;

        // Onboard only actual public assertion methods for the governor's
        // durable runtime key. No Station private key enters the Applet config.
        let encoded =
            url::form_urlencoded::byte_serialize(governor.service_id().as_str().as_bytes())
                .collect::<String>();
        let resolution: arkret_models_identity::AuthenticatedServiceResolution = governor
            .http()
            .get(governor.url(&format!("/_arkret/open/services/{encoded}/resolution")))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        arkret_identity::verify_authenticated_service_resolution_history(
            &resolution,
            governor.service_id(),
            chrono::Utc::now(),
        )?;
        let arkret_models_identity::ResolutionMethodHistoryEvidence::WebvhLog {
            log_entries, ..
        } = &resolution.method_history_evidence
        else {
            anyhow::bail!("native Applet governor requires actual WebVH originals");
        };
        let document = &log_entries
            .last()
            .context("current governor WebVH original absent")?["state"];
        let assertions = document["assertionMethod"]
            .as_array()
            .context("governor assertions absent")?;
        let expected = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
            governor
                .federation_signing_key()?
                .verifying_key()
                .as_bytes(),
        );
        let trusted = document["verificationMethod"]
            .as_array()
            .context("governor methods absent")?
            .iter()
            .filter(|entry| {
                entry["publicKeyMultibase"] == expected && assertions.contains(&entry["id"])
            })
            .map(|entry| -> Result<_> {
                let vm = DidUrl::new(entry["id"].as_str().context("governor method id absent")?)
                    .map_err(anyhow::Error::msg)?;
                arkret_identity::validate_verification_method_relationship(
                    &resolution.normalized_did_document,
                    &vm,
                    &resolution.normalized_did_document.id,
                    arkret_identity::DidVerificationRelationship::AssertionMethod,
                )?;
                let public_key = arkret_identity::public_key_material_from_document(
                    &resolution.normalized_did_document,
                    &vm,
                )?;
                Ok(json!({"verification_method":vm,"public_key":public_key}))
            })
            .collect::<Result<Vec<_>>>()?;
        ensure!(
            !trusted.is_empty(),
            "governor runtime key has no current assertion method"
        );
        let governor_method = serde_json::from_value(trusted[0]["verification_method"].clone())?;
        let daily = random_key()?;
        let manager = random_key()?;
        ensure!(
            daily != signing_seed && manager != daily && manager != signing_seed,
            "independent Applet key generation collided"
        );
        let config = root.join("applet.yaml");
        std::fs::write(
            &config,
            serde_json::to_vec_pretty(&json!({
                "bridge":{"bridge_id":"native-managed-configuration"},
                "arkret":{"server_url":governor.base_url(),"applet_base_url":origin,
                    "service_did":identity.history.did,"service_resolution":identity.resolution,
                    "trust_domain":governor.trust_domain(),"applet_id":package.applet_id,
                    "signing_key_seed_hex":hex::encode(signing_seed),
                    "verification_method_fragment":"#applet-service-key",
                    "trusted_server_did":governor.service_did(),"trusted_verification_methods":trusted,
                    "applet_namespaces":package.namespaces,
                    "managed_actor_authoring":{"principal_endpoint":origin,"key_encryption_key_hex":hex::encode(daily)}}
            }))?,
        )?;
        let manager_key = root.join("manager.key");
        std::fs::write(&manager_key, manager)?;
        let ca_certificate = root.join("ca.pem");
        std::fs::copy(
            governor
                .tls_ca_path()
                .context("governor run TLS CA absent")?,
            &ca_certificate,
        )?;
        let (cert, key) = governor.native_test_tls_identity_paths()?;
        let tls_certificate = root.join("server.pem");
        let tls_key = root.join("server.key");
        std::fs::copy(cert, &tls_certificate)?;
        std::fs::copy(key, &tls_key)?;
        let journal = root.join("daily.redb");
        let launch = Launch {
            root: root.clone(),
            config,
            journal: journal.clone(),
            manager_archive: root.join("manager.redb"),
            manager_key,
            ca_certificate,
            tls_certificate,
            tls_key,
            observations: root.join("observations.ndjson"),
            ready: root.join("ready.json"),
            stdout: root.join("stdout.log"),
            stderr: root.join("stderr.log"),
            origin,
        };
        let product = PathBuf::from(
            std::env::var_os("COTEST_NATIVE_APPLET_HOST_PRODUCT").context(
                "native Applet management requires its actual prepared owned-host product",
            )?,
        );
        ensure!(
            product.is_absolute(),
            "prepared Applet host product must be absolute"
        );
        port.release();
        let http = governor.http();
        let host = ManagedAppletHost::spawn(&product, launch.clone(), &http).await?;
        Ok(Self {
            host,
            _directory: directory,
            package,
            epoch,
            identity,
            journal,
            governor_resolution: resolution,
            governor_method,
            launch,
            product,
        })
    }

    pub async fn install(
        &self,
        governor: &ArkretServer,
        owner: &Member,
        realm: &RealmId,
    ) -> Result<(
        AppletInstallResponseBody,
        arkret_wire::Event,
        arkret_wire::Event,
    )> {
        let (body, registration, grant) =
            crate::scenarios::call_recording_live::service::installation_request_for_package(
                &self.package,
                &self.epoch,
                governor,
                owner,
                realm,
                &[serde_json::from_value(serde_json::json!({
                    "constraint_kind":"quota","constraint_subkind":"rate","effect":"allow",
                    "max_operation_count":3,"period":"P1D","constraint_scope":"per_realm"
                }))?],
            )
            .await?;
        let response: AppletInstallResponseBody = serde_json::from_value(
            crate::harness::expect_json(
                owner
                    .client
                    .post("/_arkret/self/applets/install")
                    .header(
                        "idempotency-key",
                        arkret_identifiers::new_prefixed_uuid7("ak:request:"),
                    )
                    .json(&body),
                reqwest::StatusCode::CREATED,
            )
            .await?,
        )?;
        response.validate()?;
        ensure!(
            response.rejections.is_empty() && response.service_id == self.package.service_id,
            "native management installation was partially admitted or retargeted"
        );
        Ok((response, registration, grant))
    }

    pub fn service_request<T: serde::Serialize>(
        &self,
        governor: &ArkretServer,
        path: &str,
        operation: ServiceOperationId,
        body: &T,
        idempotency_key: Option<&str>,
    ) -> Result<reqwest::RequestBuilder> {
        use arkret_signatures::http_signature::{
            ContentDigest, ContentDigestAlgorithm, HttpSignatureScenario, SignedRequestParts,
            sign_http_message_for_scenario,
        };
        let bytes = arkret_canonical::canonical_json_bytes(body)?;
        let target = governor.url(path);
        let url: url::Url = target.parse()?;
        let digest = ContentDigest::compute(&bytes, ContentDigestAlgorithm::Sha256).wire_value;
        let mut headers = vec![
            ("content-type".into(), "application/json".into()),
            ("content-digest".into(), digest.clone()),
            (
                "source-service-id".into(),
                self.package.service_id.to_string(),
            ),
            (
                "destination-service-id".into(),
                governor.service_id().to_string(),
            ),
            (
                "source-trust-domain".into(),
                governor.trust_domain().to_string(),
            ),
            (
                "destination-trust-domain".into(),
                governor.trust_domain().to_string(),
            ),
            ("arkret-operation".into(), operation.as_str().into()),
        ];
        let mut required = vec!["content-digest"];
        if let Some(key) = idempotency_key {
            headers.push(("idempotency-key".into(), key.to_owned()));
            required.push("idempotency-key");
        }
        let signed = sign_http_message_for_scenario(
            &SignedRequestParts {
                method: "POST".into(),
                target_uri: target.clone(),
                authority: url[url::Position::BeforeHost..url::Position::AfterPort].to_owned(),
                path: url.path().into(),
                headers: headers.clone(),
                body_digest: Some(digest),
            },
            HttpSignatureScenario::ServiceToServiceV1,
            &required,
            "sig1",
            self.identity.verification_method.as_str(),
            chrono::Utc::now().timestamp(),
            &self.identity.signing_key,
        )?;
        let mut request = governor.http().post(target).body(bytes);
        for (name, value) in headers {
            request = request.header(name, value);
        }
        Ok(request
            .header("signature-input", signed.signature_input_header)
            .header("signature", signed.signature_header))
    }

    pub fn governor_request<T: serde::Serialize>(
        &self,
        governor: &ArkretServer,
        path: &str,
        operation: ServiceOperationId,
        body: &T,
        idempotency_key: Option<&str>,
    ) -> Result<reqwest::RequestBuilder> {
        use arkret_signatures::http_signature::{
            ContentDigest, ContentDigestAlgorithm, HttpSignatureScenario, SignedRequestParts,
            sign_http_message_for_scenario,
        };
        let bytes = arkret_canonical::canonical_json_bytes(body)?;
        let url = self.launch.origin.join(path)?;
        let digest = ContentDigest::compute(&bytes, ContentDigestAlgorithm::Sha256).wire_value;
        let mut headers = vec![
            ("content-type".into(), "application/json".into()),
            ("content-digest".into(), digest.clone()),
            (
                "source-service-id".into(),
                governor.service_id().to_string(),
            ),
            (
                "destination-service-id".into(),
                self.package.service_id.to_string(),
            ),
            (
                "source-trust-domain".into(),
                governor.trust_domain().to_string(),
            ),
            (
                "destination-trust-domain".into(),
                governor.trust_domain().to_string(),
            ),
            ("arkret-operation".into(), operation.as_str().into()),
        ];
        let mut required = vec!["content-digest"];
        if let Some(key) = idempotency_key {
            headers.push(("idempotency-key".into(), key.to_owned()));
            required.push("idempotency-key");
        }
        let signed = sign_http_message_for_scenario(
            &SignedRequestParts {
                method: "POST".into(),
                target_uri: url.to_string(),
                authority: url[url::Position::BeforeHost..url::Position::AfterPort].to_owned(),
                path: url.path().into(),
                headers: headers.clone(),
                body_digest: Some(digest),
            },
            HttpSignatureScenario::ServiceToServiceV1,
            &required,
            "sig1",
            self.governor_method.as_str(),
            chrono::Utc::now().timestamp(),
            &governor.federation_signing_key()?,
        )?;
        let mut request = governor.http().post(url).body(bytes);
        for (name, value) in headers {
            request = request.header(name, value);
        }
        Ok(request
            .header("signature-input", signed.signature_input_header)
            .header("signature", signed.signature_header))
    }

    /// Read only public creation/configuration records after the owning process
    /// has exited. Custody ciphertext and manager keys never enter the artifact.
    pub async fn cold_restart(&mut self, governor: &ArkretServer) -> Result<serde_json::Value> {
        use arkret_bridge_runtime::{AuthoringStore as _, FileAuthoringStore};
        let stopped = self.host.kill_and_wait()?;
        let records = {
            let store = FileAuthoringStore::new(self.journal.clone())?;
            let originals = store.entries_with_prefix("managed-authoring/original/")?;
            let configurations = store
                .entries_with_prefix("applet-configuration/v1/")?
                .into_iter()
                .map(|(key, value)| (key, arkret_canonical::sha256_hex(value.as_bytes())))
                .collect::<Vec<_>>();
            json!({"originals":originals,"configurations":configurations})
        };
        let generation = uuid::Uuid::now_v7().simple().to_string();
        let mut launch = self.launch.clone();
        launch.observations = launch
            .root
            .join(format!("observations-{generation}.ndjson"));
        launch.ready = launch.root.join(format!("ready-{generation}.json"));
        launch.stdout = launch.root.join(format!("stdout-{generation}.log"));
        launch.stderr = launch.root.join(format!("stderr-{generation}.log"));
        self.host =
            ManagedAppletHost::spawn(&self.product, launch.clone(), &governor.http()).await?;
        self.launch = launch;
        let restarted = self.host.identity()?;
        Ok(json!({"stopped":stopped,"restarted":restarted,"records":records}))
    }

    pub async fn replay_source(
        &self,
        governor: &ArkretServer,
        prior: &AppletConfigurationExecutionRequestBody,
    ) -> Result<(
        AppletConfigurationExecutionRequestBody,
        AppletConfigurationExecutionResponseBody,
    )> {
        let request = prior.clone();
        request.validate_at(chrono::Utc::now())?;
        let response = serde_json::from_value(
            crate::harness::expect_json(
                self.governor_request(
                    governor,
                    "/_arkret/edge/applet/configuration",
                    ServiceOperationId::EdgeAppletConfigurationCommandExecuteV1,
                    &request,
                    Some(request.intent.request_id.as_str()),
                )?,
                reqwest::StatusCode::OK,
            )
            .await?,
        )?;
        Ok((request, response))
    }
}
