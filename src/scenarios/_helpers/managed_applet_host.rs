//! Owned test transport for the production managed Applet HTTP host.
//! This utility is not a native operation case and contributes no test result.
use std::collections::BTreeSet;
use std::io::{BufRead as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use anyhow::{Context as _, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

pub const WORKER_TARGET: &str = "native_applet_host_worker";
pub const WORKER_ARGUMENT: &str = "--cotest-managed-applet-host-worker";
pub const WORKER_ROLE: &str = "cotest_managed_applet_host_worker";

/// Private process paths only. Config and key material stay in owned files;
/// no protocol authority DTO, bearer token or key is encoded on the command line.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Launch {
    pub root: PathBuf,
    pub config: PathBuf,
    pub journal: PathBuf,
    pub manager_archive: PathBuf,
    pub manager_key: PathBuf,
    pub ca_certificate: PathBuf,
    pub tls_certificate: PathBuf,
    pub tls_key: PathBuf,
    pub observations: PathBuf,
    pub ready: PathBuf,
    pub stdout: PathBuf,
    pub stderr: PathBuf,
    pub origin: url::Url,
}

impl Launch {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.root.is_absolute() && self.root.is_dir(),
            "host root is not owned"
        );
        ensure!(
            self.origin.scheme() == "https"
                && self.origin.host_str() == Some("127.0.0.1")
                && self.origin.port().is_some()
                && self.origin.path() == "/"
                && self.origin.username().is_empty()
                && self.origin.password().is_none()
                && self.origin.query().is_none()
                && self.origin.fragment().is_none(),
            "host needs one exact loopback TLS origin"
        );
        let root = self.root.canonicalize()?;
        let mut paths = BTreeSet::new();
        for (path, must_exist) in [
            (&self.config, true),
            (&self.manager_key, true),
            (&self.ca_certificate, true),
            (&self.tls_certificate, true),
            (&self.tls_key, true),
            (&self.journal, false),
            (&self.manager_archive, false),
            (&self.observations, false),
            (&self.ready, false),
            (&self.stdout, false),
            (&self.stderr, false),
        ] {
            ensure!(path.is_absolute(), "host path must be absolute");
            let canonical = if path.exists() {
                path.canonicalize()?
            } else {
                path.parent()
                    .context("host path has no parent")?
                    .canonicalize()?
                    .join(path.file_name().context("host path has no name")?)
            };
            ensure!(
                canonical.starts_with(&root) && canonical != root && paths.insert(canonical),
                "host files escape or alias the owned root"
            );
            if must_exist {
                ensure!(path.is_file(), "host input is not a regular file");
            }
        }
        for path in [&self.observations, &self.ready] {
            ensure!(!path.exists(), "host observation generation must be fresh");
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ready {
    pub pid: u32,
    pub origin: url::Url,
    pub executable: PathBuf,
    pub sha256: String,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerProduct {
    pub role: String,
    pub executable: PathBuf,
    pub sha256: String,
    pub producer_result: PathBuf,
}

impl WorkerProduct {
    /// Full source/compiler provenance is checked by the official Python
    /// producer gate. This second local check prevents spawning different bytes.
    pub fn load(path: &Path) -> Result<Self> {
        let product: Self = serde_json::from_slice(&std::fs::read(path)?)?;
        ensure!(
            product.role == WORKER_ROLE
                && product.executable.is_absolute()
                && product.executable.is_file(),
            "not the prepared managed host product"
        );
        let name = product
            .executable
            .file_name()
            .context("host executable has no name")?
            .to_string_lossy();
        let pattern = regex::Regex::new(r"^native_applet_host_worker(?:\.exe)?$")?;
        ensure!(
            pattern.is_match(&name)
                && product.sha256.len() == 64
                && product
                    .sha256
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "host executable is not the exact worker artifact"
        );
        ensure!(
            arkret_canonical::sha256_hex(std::fs::read(&product.executable)?) == product.sha256,
            "prepared host executable changed"
        );
        ensure!(
            product.producer_result.components().count() == 1
                && product.producer_result.file_name().is_some(),
            "host producer escaped its evidence directory"
        );
        let producer_path = path
            .parent()
            .context("host product has no parent")?
            .join(&product.producer_result);
        let producer: Value = serde_json::from_slice(&std::fs::read(producer_path)?)?;
        ensure!(
            producer["exit_code"] == 0
                && producer["sources_unchanged"] == true
                && producer["role"] == WORKER_ROLE
                && producer["compiler_target"]["name"] == WORKER_TARGET
                && producer["sha256"] == product.sha256
                && Path::new(
                    producer["executable"]
                        .as_str()
                        .context("producer executable absent")?
                )
                .canonicalize()?
                    == product.executable.canonicalize()?,
            "host product has no matching successful producer"
        );
        Ok(product)
    }
}

/// Owns the real child only. The caller owns root/journal/vault lifetime, so
/// dropping/reopening this process never deletes durable custody or another DB.
pub struct ManagedAppletHost {
    child: Child,
    product: WorkerProduct,
    launch: Launch,
}

impl Drop for ManagedAppletHost {
    fn drop(&mut self) {
        if !matches!(self.child.try_wait(), Ok(Some(_))) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

impl ManagedAppletHost {
    pub async fn spawn(
        product_path: &Path,
        launch: Launch,
        http: &reqwest::Client,
    ) -> Result<Self> {
        launch.validate()?;
        let product = WorkerProduct::load(product_path)?;
        let stdout = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&launch.stdout)?;
        let stderr = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&launch.stderr)?;
        let mut command = Command::new(&product.executable);
        command
            .arg(WORKER_ARGUMENT)
            .current_dir(&launch.root)
            .env_clear();
        // The worker does not inherit Station/AA DB URLs, issuer secrets,
        // global manager credentials or parent libtest reporting variables.
        for name in ["SystemRoot", "WINDIR", "TEMP", "TMP"] {
            if let Some(value) = std::env::var_os(name) {
                command.env(name, value);
            }
        }
        let child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr))
            .spawn()?;
        let mut owned = Self {
            child,
            product,
            launch,
        };
        let bytes = zeroize::Zeroizing::new(serde_json::to_vec(&owned.launch)?);
        ensure!(bytes.len() <= 64 * 1024, "private host launch is oversized");
        {
            let mut input = owned.child.stdin.take().context("host stdin not owned")?;
            input.write_all(&bytes)?;
            input.write_all(b"\n")?;
            input.flush()?;
        }
        tokio::time::timeout(Duration::from_secs(60), async {
            loop {
                ensure!(
                    owned.child.try_wait()?.is_none(),
                    "managed host exited before readiness"
                );
                if owned.launch.ready.is_file() {
                    let ready: Ready =
                        serde_json::from_slice(&std::fs::read(&owned.launch.ready)?)?;
                    ensure!(
                        ready.pid == owned.child.id()
                            && ready.origin == owned.launch.origin
                            && ready.executable.canonicalize()?
                                == owned.product.executable.canonicalize()?
                            && ready.sha256 == owned.product.sha256,
                        "readiness came from another child"
                    );
                    let response = http
                        .get(owned.launch.origin.join("_arkret/describe")?)
                        .header(
                            "arkret-operation",
                            arkret_wire::ServiceOperationId::SERVER_READ_DESCRIBE_V1,
                        )
                        .send()
                        .await?;
                    ensure!(
                        response.status().is_success(),
                        "production host describe refused readiness"
                    );
                    let describe: arkret_models_discovery::ServiceDescribe =
                        response.json().await?;
                    describe.validate()?;
                    ensure!(
                        describe.service_kind == arkret_wire::ServiceKind::AppletService,
                        "production host is not an Applet Service"
                    );
                    break Ok::<_, anyhow::Error>(());
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .context("production managed host readiness timed out")??;
        Ok(owned)
    }

    /// Actual successful inbound bytes from the production adapter. This does
    /// not certify authority: later domain proofs and the native product gate do.
    pub fn observations(
        &self,
    ) -> Result<Vec<cotest_test_support::operation_observation::NativeOperationObservations>> {
        let file = std::fs::File::open(&self.launch.observations)?;
        let mut result = Vec::new();
        for line in std::io::BufReader::new(file).lines() {
            let observations: cotest_test_support::operation_observation::NativeOperationObservations = serde_json::from_str(&line?)?;
            ensure!(
                observations.accepted_identity_material.is_empty()
                    && observations.issuer_bindings.is_empty(),
                "host observer cannot certify native issuer authority"
            );
            for exchange in &observations.exchanges {
                let url: url::Url = exchange.url.parse()?;
                ensure!(url.origin() == self.launch.origin.origin()
                    && [arkret_wire::ServiceOperationId::EDGE_APPLET_MANAGED_ACTOR_COMMAND_AUTHOR_V1,
                        arkret_wire::ServiceOperationId::EDGE_APPLET_CONFIGURATION_COMMAND_EXECUTE_V1,
                        arkret_wire::ServiceOperationId::EDGE_APPLET_COMMAND_TRANSACTION_V1].contains(&exchange.operation_id.as_str())
                    && exchange.operation_id.matches_http_request(&exchange.method, url.path())
                    && (200..300).contains(&exchange.response_status), "unexpected managed host exchange");
            }
            result.push(observations);
        }
        Ok(result)
    }

    pub fn identity(&mut self) -> Result<Value> {
        ensure!(
            self.child.try_wait()?.is_none(),
            "owned host is no longer running"
        );
        let pid = self.child.id();
        #[cfg(windows)]
        let process = {
            let output = Command::new("powershell.exe").args(["-NoProfile", "-NonInteractive", "-Command", &format!("Get-CimInstance Win32_Process -Filter 'ProcessId = {pid}' | Select-Object ProcessId,CreationDate,CommandLine | ConvertTo-Json -Compress")]).output()?;
            ensure!(
                output.status.success(),
                "owned host OS identity unavailable"
            );
            let value: Value = serde_json::from_slice(&output.stdout)?;
            ensure!(
                value["ProcessId"].as_u64() == Some(u64::from(pid))
                    && !value["CreationDate"].is_null()
                    && value["CommandLine"]
                        .as_str()
                        .is_some_and(|s| s.contains(WORKER_ARGUMENT)),
                "owned host OS identity incomplete"
            );
            value
        };
        #[cfg(not(windows))]
        let process = {
            let output = Command::new("ps")
                .args([
                    "-p",
                    &pid.to_string(),
                    "-o",
                    "pid=",
                    "-o",
                    "lstart=",
                    "-o",
                    "args=",
                ])
                .output()?;
            ensure!(
                output.status.success(),
                "owned host OS identity unavailable"
            );
            let value = String::from_utf8(output.stdout)?;
            ensure!(
                value.trim_start().starts_with(&pid.to_string()) && value.contains(WORKER_ARGUMENT),
                "owned host OS identity incomplete"
            );
            json!({"pid_start_time_command":value})
        };
        Ok(
            json!({"role":WORKER_ROLE,"pid":pid,"origin":self.launch.origin,"executable":self.product.executable,
            "sha256":format!("sha256:{}",self.product.sha256),"os_process":process}),
        )
    }

    pub fn kill_and_wait(&mut self) -> Result<Value> {
        let before = self.identity()?;
        self.child.kill()?;
        let status = self.child.wait()?;
        ensure!(
            !status.success(),
            "worker kill became a successful no-op exit"
        );
        Ok(json!({"before":before,"waited":true,"exit_status":status.to_string()}))
    }
}
