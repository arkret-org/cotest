//! Owned production-host process utility. Its normal binary main starts the host.
use std::io::{BufRead as _, Read as _, Write as _};
use std::sync::{Arc, Mutex};

use anyhow::{Context as _, Result, ensure};
use arkret_bridge_runtime::salvo::conn::rustls::{Keycert, RustlsConfig};
use arkret_bridge_runtime::salvo::conn::{Listener, TcpListener};
use arkret_bridge_runtime::salvo::http::HeaderMap;
use arkret_bridge_runtime::salvo::prelude::*;
use cotest::scenarios::_helpers::managed_applet_host::{Launch, Ready, WORKER_ARGUMENT};
use cotest_test_support::operation_observation::{observe, record_response};

#[derive(Clone)]
struct ProductionAdapter {
    host: Arc<arkret_bridge_runtime::web::ManagedAppletHttpHost>,
    origin: url::Url,
    observations: Arc<Mutex<std::fs::File>>,
}

impl ProductionAdapter {
    async fn forward(&self, req: &mut Request) -> Result<(StatusCode, HeaderMap, Vec<u8>)> {
        let method = req.method().clone();
        let uri = req.uri().clone();
        let authority = uri
            .authority()
            .map(|a| a.as_str())
            .or_else(|| req.headers().get("host").and_then(|h| h.to_str().ok()))
            .context("owned host ingress authority absent")?;
        ensure!(
            authority == &self.origin[url::Position::BeforeHost..url::Position::AfterPort]
                && uri.scheme_str().is_none_or(|scheme| scheme == "https"),
            "foreign request URI reached owned host"
        );
        let url = self.origin.join(
            uri.path_and_query()
                .context("owned host request target absent")?
                .as_str(),
        )?;
        ensure!(
            url.origin() == self.origin.origin(),
            "owned host request target changed origin"
        );
        let headers = req.headers().clone();
        let body = req
            .payload_with_max_size(arkret_bridge_runtime::web::MAX_APPLET_TRANSACTION_BODY_BYTES)
            .await?
            .to_vec();
        let selected =
            headers
                .get("arkret-operation")
                .and_then(|h| h.to_str().ok())
                .is_some_and(|op| {
                    [arkret_wire::ServiceOperationId::EDGE_APPLET_MANAGED_ACTOR_COMMAND_AUTHOR_V1,
                arkret_wire::ServiceOperationId::EDGE_APPLET_CONFIGURATION_COMMAND_EXECUTE_V1,
                arkret_wire::ServiceOperationId::EDGE_APPLET_COMMAND_TRANSACTION_V1].contains(&op)
                });
        let mut frozen = reqwest::Request::new(method.clone(), url);
        *frozen.headers_mut() = headers.clone();
        *frozen.body_mut() = Some(body.clone().into());
        let (outcome, observations) = observe(async {
            // The unique production adapter owns every route, signature,
            // current/approval cut and journal operation. Preserve raw inputs.
            let actual = self.host.receive(method, uri, headers, body).await?;
            if selected {
                record_response(Some(&frozen), actual.0.as_u16(), &actual.2)?;
            }
            Ok::<_, anyhow::Error>(actual)
        })
        .await;
        let actual = outcome?;
        if !observations.exchanges.is_empty() {
            let mut file = self
                .observations
                .lock()
                .map_err(|_| anyhow::anyhow!("host observation lock unavailable"))?;
            serde_json::to_writer(&mut *file, &observations)?;
            file.write_all(b"\n")?;
            file.flush()?;
            file.sync_data()?;
        }
        Ok(actual)
    }
}

#[handler]
impl ProductionAdapter {
    async fn handle(&self, req: &mut Request, res: &mut Response) {
        match self.forward(req).await {
            Ok((status, headers, bytes)) => {
                res.status_code(status);
                *res.headers_mut() = headers;
                if res.write_body(bytes).is_err() {
                    res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
                }
            }
            Err(_) => {
                // A transport/recorder failure earns no success observation.
                // Never dump request/config/manager material into worker logs.
                res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
            }
        }
    }
}

async fn run() -> Result<()> {
    ensure!(
        std::env::args().skip(1).collect::<Vec<_>>() == [WORKER_ARGUMENT],
        "worker needs its exact private launch selector"
    );
    let mut bytes = zeroize::Zeroizing::new(Vec::new());
    std::io::stdin()
        .lock()
        .take(64 * 1024 + 1)
        .read_until(b'\n', &mut bytes)?;
    ensure!(
        bytes.len() <= 64 * 1024 && bytes.last() == Some(&b'\n'),
        "bounded private worker launch absent"
    );
    let launch: Launch = serde_json::from_slice(&bytes)?;
    launch.validate()?;
    arkret_bridge_runtime::install_default_crypto_provider();
    let config = Arc::new(arkret_bridge_runtime::Config::load(&launch.config)?);
    ensure!(
        config.arkret.applet_base_url.parse::<url::Url>()? == launch.origin
            && config.database.url == arkret_bridge_runtime::DatabaseConfig::default().url,
        "worker uses only its own FileJournal/vault and exact public origin"
    );
    let http = reqwest::Client::builder()
        .tls_backend_rustls()
        .tls_certs_only(reqwest::Certificate::from_pem_bundle(&std::fs::read(
            &launch.ca_certificate,
        )?)?)
        .timeout(std::time::Duration::from_secs(30))
        .build()?;
    let station: url::Url = config.arkret.server_url.parse()?;
    ensure!(
        station.scheme() == "https" && station.host_str() == Some("127.0.0.1"),
        "worker needs the real loopback TLS Station"
    );
    let client = arkret::ClientBuilder::new(station.clone())
        .loopback_service_discovery(
            station.host_str().context("Station host absent")?,
            station.port().context("Station port absent")?,
        )?
        .http_client(http)
        .build()?;
    let signer = arkret_signatures::Ed25519PayloadSigner::from_did_key_seed(
        config.signing_seed()?,
        config.arkret.service_did.clone(),
        config
            .arkret
            .verification_method_for(&config.arkret.service_did)?,
    );
    let journal = arkret_bridge_runtime::AuthoringJournal::new(
        arkret_bridge_runtime::FileAuthoringStore::shared(launch.journal.clone())?,
    );
    let edge = Arc::new(arkret_bridge_runtime::ArkretEdge::new_outbound(
        config, client, signer, journal,
    )?);
    let wrapping_key = arkret::KeyBytes::new(std::fs::read(&launch.manager_key)?);
    arkret_bridge_runtime::managed_actor_authoring::ManagedActorManagerService::validate_archive_wrapping_key(&edge,&wrapping_key)?;
    let vault = Arc::new(
        arkret_bridge_runtime::manager_archive::ManagerArchiveVault::open(
            &launch.manager_archive,
            wrapping_key,
        )?,
    );
    let manager = Arc::new(
        arkret_bridge_runtime::managed_actor_authoring::ManagedActorManagerService::new(
            edge.clone(),
            vault,
        )?,
    );
    let host =
        Arc::new(arkret_bridge_runtime::web::ManagedAppletHttpHost::with_manager(edge, manager)?);
    let observations = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&launch.observations)?;
    let adapter = ProductionAdapter {
        host,
        origin: launch.origin.clone(),
        observations: Arc::new(Mutex::new(observations)),
    };
    let acceptor = TcpListener::new(format!(
        "127.0.0.1:{}",
        launch.origin.port().context("host port absent")?
    ))
    .rustls(RustlsConfig::new(
        Keycert::new()
            .cert_from_path(&launch.tls_certificate)?
            .key_from_path(&launch.tls_key)?,
    ))
    .try_bind()
    .await?;
    let ready = Ready {
        pid: std::process::id(),
        origin: launch.origin.clone(),
        executable: std::fs::canonicalize(std::env::current_exe()?)?,
        sha256: arkret_canonical::sha256_hex(std::fs::read(std::env::current_exe()?)?),
    };
    // Publish the bounded readiness record atomically; the parent must never
    // mistake a partially written JSON file for a ready process.
    let mut file =
        tempfile::NamedTempFile::new_in(launch.ready.parent().context("ready parent absent")?)?;
    serde_json::to_writer(file.as_file_mut(), &ready)?;
    file.as_file_mut().flush()?;
    file.as_file().sync_all()?;
    file.persist_noclobber(&launch.ready)?;
    let router = Router::new()
        .goal(adapter.clone())
        .push(Router::with_path("{**rest}").goal(adapter));
    Server::new(acceptor).serve(router).await;
    Ok(())
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    match run().await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(_) => {
            eprintln!("owned managed Applet host failed");
            std::process::ExitCode::FAILURE
        }
    }
}
