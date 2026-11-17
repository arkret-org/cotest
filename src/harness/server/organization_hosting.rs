//! Invoke the production H operator owner with its actual retained custody.
use anyhow::ensure;
use arkret_models_collaboration::authority_commit::PeerAuthorityForwardEventRequestBody;

use super::*;

struct HostingCommand(Option<Child>);
impl Drop for HostingCommand {
    fn drop(&mut self) {
        if let Some(child) = self.0.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

impl ArkretServer {
    /// Invoke the true production owner, not a direct peer-signature fixture.
    pub async fn accept_organization_hosting(
        &self,
        request: &PeerAuthorityForwardEventRequestBody,
    ) -> Result<Value> {
        request.event_submission.validate()?;
        ensure!(
            request
                .event_submission
                .event
                .actor_id
                .as_account_id()
                .is_some_and(|account| account.station_id == self.service_id),
            "Organization CLI belongs to another H"
        );
        let evidence = self
            .run_organization_operator(
                "accept-hosting",
                arkret_canonical::canonical_json_bytes(request)?,
            )
            .await?;
        let report = &evidence["report"];
        let outcome: arkret_wire::AuthoritySubmitResponseBody =
            serde_json::from_value(report["outcome"].clone())?;
        outcome.validate_shape()?;
        ensure!(
            report["holder_account_id"]
                == serde_json::to_value(request.event_submission.event.actor_id.as_account_id())?
                && report["realm_id"] == request.event_submission.event.realm_id.as_str(),
            "H operator changed the original Org subject or Realm"
        );
        Ok(evidence)
    }

    /// A real local H inspection with the unchanged standard peer current body.
    pub async fn inspect_organization_consent(
        &self,
        request: &arkret_models_collaboration::call_invitation::ConsentCurrentReadRequestBody,
    ) -> Result<Value> {
        request.validate()?;
        ensure!(
            request.holder_account_id.station_id == self.service_id
                && request.audience_actor_id
                    == arkret_wire::ActorId::service(self.service_id.clone()),
            "inspect CLI belongs to another H or audience"
        );
        let evidence = self
            .run_organization_operator(
                "inspect-consent",
                arkret_canonical::canonical_json_bytes(request)?,
            )
            .await?;
        let response: arkret_models_collaboration::call_invitation::ConsentCurrentReadResponseBody =
            serde_json::from_value(evidence["report"].clone())?;
        response.validate_for_request(
            request,
            response.governance_generation,
            chrono::Utc::now(),
        )?;
        Ok(evidence)
    }

    async fn run_organization_operator(&self, operation: &str, bytes: Vec<u8>) -> Result<Value> {
        ensure!(
            matches!(operation, "accept-hosting" | "inspect-consent"),
            "unsupported local Organization operator operation"
        );
        let actual_h = self.native_process_identity()?;
        let config = self
            .external_restart
            .as_ref()
            .context("owned H operator configuration")?;
        let executable_sha256 = arkret_canonical::sha256_digest(fs::read(&config.bin_path)?);
        ensure!(
            actual_h["sha256"] == executable_sha256,
            "CLI binary differs from the running H source product"
        );
        let directory = tempfile::tempdir().context("private H CLI input/output")?;
        let input = directory.path().join("organization-request.json");
        let stdout = directory.path().join("stdout.json");
        let stderr = directory.path().join("stderr.log");
        fs::write(&input, &bytes)?;
        let mut command = self.retained_operator_command()?;
        // Use only the original run PKI when it was not already selected by
        // the retained deployment. No OS roots, name mapping or TLS bypass.
        if !config
            .extra_env
            .iter()
            .any(|(name, _)| name == "SSL_CERT_FILE")
            && let Some(tls) = &self._tls
        {
            command.env("SSL_CERT_FILE", &tls.ca_path);
        }
        command
            .args(["organization-pcr", operation])
            .arg(&input)
            .stdout(std::process::Stdio::from(fs::File::create(&stdout)?))
            .stderr(std::process::Stdio::from(fs::File::create(&stderr)?));
        let child = command
            .spawn()
            .context("execute the production Organization H CLI")?;
        let pid = child.id();
        let mut owned = HostingCommand(Some(child));
        // This bounds only the owned subprocess lifetime, never a protocol
        // authorization/evidence window or a production retry policy.
        let completion = tokio::time::timeout(Duration::from_secs(180), async {
            loop {
                if let Some(status) = owned.0.as_mut().context("owned H CLI child")?.try_wait()? {
                    return Ok::<_, anyhow::Error>(status);
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await;
        let status = match completion {
            Ok(Ok(status)) => status,
            failed => {
                if let Some(child) = owned.0.as_mut() {
                    let _ = child.kill();
                    let _ = child.wait();
                }
                let diagnostics = directory.keep();
                anyhow::bail!(
                    "owned H CLI did not finish: {failed:?}; private diagnostics at {}",
                    diagnostics.display()
                );
            }
        };
        owned.0.as_mut().context("owned H CLI child")?.wait()?;
        let raw = fs::read(&stdout)?;
        let errors = fs::read(&stderr)?;
        if !status.success() {
            let diagnostics = directory.keep();
            anyhow::bail!(
                "production H CLI failed with {status}; stdout_sha256={} stderr_sha256={}; private diagnostics at {}",
                arkret_canonical::sha256_digest(&raw),
                arkret_canonical::sha256_digest(&errors),
                diagnostics.display()
            );
        }
        ensure!(
            arkret_canonical::sha256_digest(fs::read(&config.bin_path)?) == executable_sha256,
            "H CLI executable changed while running"
        );
        let report: Value =
            serde_json::from_slice(&raw).context("decode the actual H operator report")?;
        Ok(serde_json::json!({
            "report":report,"request_sha256":arkret_canonical::sha256_digest(bytes),
            "cli":{"pid":pid,"executable":config.bin_path,"sha256":executable_sha256,"exit_code":status.code(),"operation":operation,
                "stdout_sha256":arkret_canonical::sha256_digest(raw),"stderr_sha256":arkret_canonical::sha256_digest(errors)},
            "hosting_process":actual_h,
        }))
    }
}
