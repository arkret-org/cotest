//! Exercise the production migration command with retained process custody.
use anyhow::ensure;

use super::*;

impl ArkretServer {
    pub fn reserve_public_base_target(&mut self) -> Result<Url> {
        let mut port = reserve_port()?;
        let url = Url::parse(&format!("https://127.0.0.1:{}/", port.port()))?;
        port.release();
        self._port_reservations.push(port);
        Ok(url)
    }

    fn retained_migration_command(&self) -> Result<Command> {
        let config = self
            .external_restart
            .as_ref()
            .context("owned external Station")?;
        let blob = self.blob_root.as_ref().context("retained blob custody")?;
        let mut command = Command::new(&config.bin_path);
        command
            .env_remove("DATABASE_URL")
            .env("COLAND_PUBLIC_BASE_URL", self.base_url.as_str())
            .env("COLAND_NOTARY_SIGNING_KEY", &config.notary_signing_key)
            .env("COLAND_TRUST_DOMAIN", self.trust_domain.as_str())
            .env("COLAND_DEVELOPMENT_MODE", "1")
            .env("COLAND_BLOB_ROOT", blob)
            .env(
                "COLAND_EMBEDDED_WEBVH_REGISTRATION_BEARER",
                EMBEDDED_WEBVH_REGISTRATION_BEARER,
            );
        if !config
            .extra_env
            .iter()
            .any(|(key, _)| key == "COLAND_KEYSTORE_BACKEND")
        {
            command
                .env("COLAND_KEYSTORE_BACKEND", "encrypted_file")
                .env("COLAND_KEYSTORE_PATH", blob.join("keystore.v1"))
                .env(
                    "COLAND_KEYSTORE_MASTER_KEY",
                    DURABLE_TEST_KEYSTORE_MASTER_KEY,
                );
        }
        for (key, value) in
            harness_account_authority_env(|key| config.extra_env.iter().any(|(k, _)| k == key))
        {
            command.env(key, value);
        }
        for (key, value) in &config.extra_env {
            command.env(key, value);
        }
        Ok(command)
    }

    pub async fn migrate_public_base(&mut self, target: &Url, preflight: bool) -> Result<Value> {
        self.migrate_public_base_with_hosting(target, preflight, false)
            .await
    }

    pub(crate) async fn migrate_public_base_with_hosting(
        &mut self,
        target: &Url,
        preflight: bool,
        preserve_did_host: bool,
    ) -> Result<Value> {
        ensure!(
            matches!(self.handle, SutHandle::Terminated),
            "migration requires the business process stopped"
        );
        let mut command = self.retained_migration_command()?;
        command.args([
            "service-identity",
            "migrate-base",
            "--from",
            self.base_url.as_str(),
            "--to",
            target.as_str(),
        ]);
        if preflight {
            command.arg("--preflight");
        }
        if preserve_did_host {
            command.arg("--preserve-did-host");
        }
        let output = tokio::task::spawn_blocking(move || command.output()).await??;
        ensure!(
            output.status.success(),
            "migration CLI failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report: Value =
            serde_json::from_slice(&output.stdout).context("migration CLI public report")?;
        append_service_log(
            self.log_path.as_deref(),
            &format!(
                "[cotest] migration public report: {}",
                String::from_utf8_lossy(&output.stdout)
            ),
        )?;
        ensure!(
            report["service_id"].as_str() == Some(self.service_id.as_str()),
            "migration changed core"
        );
        if !preflight {
            self.service_did = report["did"].as_str().context("target DID")?.parse()?;
            self.base_url = target.clone();
            self.external_restart.as_mut().context("restart")?.bind =
                format!("127.0.0.1:{}", target.port().context("explicit port")?);
        }
        Ok(report)
    }

    pub async fn reconnect_after_public_base_migration(
        &self,
        client: &TestActorClient,
        issuer: &MockCoauthIntrospectionServer,
    ) -> Result<TestActorClient> {
        ensure!(
            client.service_id == self.service_id.as_str(),
            "Account Station changed"
        );
        let fresh = self.client_with_founding_device_grant(
            client.principal.as_ref().context("accepted principal")?,
            client.session().credential().to_owned(),
        )?;
        let fresh = super::super::native_session::bind_standard_host(
            fresh,
            issuer,
            &self.service_id,
            &self.trust_domain,
            self._tls.as_ref().map(|tls| tls.ca_pem.as_slice()),
        )
        .await?;
        let mut retained = client.clone();
        retained.base_url = self.base_url.clone();
        retained.http = OperationSelectingHttpClient {
            inner: self.http_client.clone(),
        };
        retained.sdk = fresh.sdk;
        retained.session = fresh.session;
        Ok(retained)
    }
}

/// Keeps only this harness-owned historical host process alive.
pub struct HistoricalOriginHost(Child);
impl Drop for HistoricalOriginHost {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
impl ArkretServer {
    pub async fn serve_historical_public_base(
        &mut self,
        origin: &Url,
        historical_did: &Did,
    ) -> Result<HistoricalOriginHost> {
        let mut metrics = reserve_port()?;
        let mut command = self.retained_migration_command()?;
        command
            .arg("--bind")
            .arg(format!(
                "127.0.0.1:{}",
                origin.port().context("historical origin port")?
            ))
            .env("COLAND_PUBLIC_BASE_URL", origin.as_str())
            .env(
                "COLAND_METRICS_BIND",
                format!("127.0.0.1:{}", metrics.port()),
            );
        if let Some(tls) = &self._tls {
            tls.apply_to_command(&mut command);
        }
        let (stdout, stderr) = service_log_stdio(self.log_path.as_deref())?;
        command.stdout(stdout).stderr(stderr);
        metrics.release();
        let mut child = command.spawn()?;
        let raw_url = arkret_identity::DidWebvhResolver::log_url(historical_did)?;
        let mut ready = false;
        for _ in 0..300 {
            if child.try_wait()?.is_some() {
                break;
            }
            if self
                .http_client
                .get(&raw_url)
                .send()
                .await
                .is_ok_and(|r| r.status().is_success())
            {
                ready = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        if !ready {
            let _ = child.kill();
            let _ = child.wait();
            anyhow::bail!("historical origin failed to serve retained history");
        }
        self._port_reservations.push(metrics);
        Ok(HistoricalOriginHost(child))
    }
}
