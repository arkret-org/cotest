//! HTTP-only Service method faults around a retained, independently running SUT.
use std::collections::BTreeMap;

use anyhow::ensure;
use arkret_keystore::{EncryptedFileKeyStore, KeyBytes, KeyStore};
use arkret_models_identity::{AuthenticatedServiceResolution, ResolutionMethodHistoryEvidence};
use salvo::conn::rustls::{Keycert, RustlsConfig};
use salvo::conn::{Listener, TcpListener as HttpListener};
use salvo::prelude::*;

use super::*;

#[derive(Clone, Default)]
pub struct ServiceRouteControl(Arc<Mutex<FaultState>>);

#[derive(Default)]
struct FaultState {
    method_only: bool,
    replies: BTreeMap<String, (u16, Vec<u8>)>,
    requests: BTreeMap<String, usize>,
}

impl ServiceRouteControl {
    pub fn reply(&self, path: &str, status: u16, bytes: Vec<u8>) {
        self.0
            .lock()
            .unwrap()
            .replies
            .insert(path.into(), (status, bytes));
    }
    pub fn clear(&self) {
        self.0.lock().unwrap().replies.clear();
    }
    pub fn requests(&self, path: &str) -> usize {
        self.0
            .lock()
            .unwrap()
            .requests
            .get(path)
            .copied()
            .unwrap_or(0)
    }
}

pub struct ServiceRouteRelay {
    control: ServiceRouteControl,
    task: tokio::task::JoinHandle<()>,
}
impl ServiceRouteRelay {
    pub fn control(&self) -> ServiceRouteControl {
        self.control.clone()
    }
}
impl Drop for ServiceRouteRelay {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[derive(Clone)]
struct Relay {
    upstream: Url,
    http: HttpClient,
    control: ServiceRouteControl,
}
impl Relay {
    async fn forward(&self, req: &mut Request, res: &mut Response) -> Result<()> {
        let path = req.uri().path().to_owned();
        let replacement = {
            let mut state = self.control.0.lock().unwrap();
            *state.requests.entry(path.clone()).or_default() += 1;
            state.replies.get(&path).cloned().or_else(|| {
                (state.method_only && !path.starts_with("/webvh/")).then(|| {
                    (
                        503,
                        b"retired service endpoint; method hosting only".to_vec(),
                    )
                })
            })
        };
        if let Some((status, bytes)) = replacement {
            res.status_code(salvo::http::StatusCode::from_u16(status)?);
            res.headers_mut().insert(
                "content-type",
                if path.ends_with(".jsonl") {
                    "application/jsonl; charset=utf-8"
                } else if path.ends_with("/did.json") {
                    "application/did+json; charset=utf-8"
                } else {
                    "application/json"
                }
                .parse()?,
            );
            res.write_body(bytes)?;
            return Ok(());
        }
        let target = self.upstream.join(
            req.uri()
                .path_and_query()
                .context("route relay path")?
                .as_str(),
        )?;
        let body = req.payload_with_max_size(16 * 1024 * 1024).await?.to_vec();
        let mut headers = req.headers().clone();
        let authority = req
            .uri()
            .authority()
            .map(|a| a.as_str())
            .or_else(|| req.headers().get("host").and_then(|v| v.to_str().ok()))
            .context("route relay ingress authority")?;
        headers.insert("host", authority.parse()?);
        headers.insert("x-forwarded-host", authority.parse()?);
        headers.remove("connection");
        headers.remove("transfer-encoding");
        let response = self
            .http
            .request(req.method().clone(), target)
            .headers(headers)
            .body(body)
            .send()
            .await?;
        res.status_code(response.status());
        let mut headers = response.headers().clone();
        headers.remove("content-length");
        headers.remove("transfer-encoding");
        headers.remove("connection");
        *res.headers_mut() = headers;
        res.write_body(response.bytes().await?)?;
        Ok(())
    }
}
#[handler]
impl Relay {
    async fn handle(&self, req: &mut Request, res: &mut Response) {
        if let Err(error) = self.forward(req, res).await {
            res.status_code(salvo::http::StatusCode::BAD_GATEWAY);
            res.render(error.to_string());
        }
    }
}

async fn listen(tls: &HarnessTls, public: &Url, upstream: Url) -> Result<ServiceRouteRelay> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let acceptor = HttpListener::new(format!(
        "127.0.0.1:{}",
        public.port().context("route relay port")?
    ))
    .rustls(RustlsConfig::new(
        Keycert::new()
            .cert_from_path(&tls.cert_path)?
            .key_from_path(&tls.key_path)?,
    ))
    .try_bind()
    .await?;
    let control = ServiceRouteControl::default();
    let relay = Relay {
        upstream,
        http: tls.http_client()?,
        control: control.clone(),
    };
    let router = Router::new()
        .goal(relay.clone())
        .push(Router::with_path("{**rest}").goal(relay));
    Ok(ServiceRouteRelay {
        control,
        task: tokio::spawn(async move {
            Server::new(acceptor).serve(router).await;
        }),
    })
}

impl ArkretServer {
    pub async fn install_service_route_relay(&mut self) -> Result<ServiceRouteRelay> {
        ensure!(
            self.external_restart.is_some(),
            "route relay requires an owned process"
        );
        let tls = self._tls.clone().context("route relay requires run TLS")?;
        let mut private = reserve_port()?;
        let bind = format!("127.0.0.1:{}", private.port());
        self.stop_external_process().await?;
        let relay = listen(
            &tls,
            &self.base_url,
            Url::parse(&format!("https://{bind}/"))?,
        )
        .await?;
        self.external_restart.as_mut().unwrap().bind = bind;
        private.release();
        self._port_reservations.push(private);
        self.start_external_process().await?;
        Ok(relay)
    }

    /// Keep the original method host and explicitly sign an endpoint successor
    /// through the real CLI before retiring the old service API.
    pub async fn move_service_endpoint(
        &mut self,
        old: &ServiceRouteControl,
    ) -> Result<ServiceRouteRelay> {
        let tls = self
            ._tls
            .clone()
            .context("endpoint move requires run TLS")?;
        let bind = self
            .external_restart
            .as_ref()
            .context("endpoint move requires an owned process")?
            .bind
            .clone();
        let mut port = reserve_port()?;
        let public = Url::parse(&format!("https://127.0.0.1:{}/", port.port()))?;
        self.stop_external_process().await?;
        self.migrate_public_base_with_hosting(&public, true, true)
            .await?;
        self.migrate_public_base_with_hosting(&public, false, true)
            .await?;
        self.external_restart.as_mut().unwrap().bind = bind.clone();
        port.release();
        let relay = listen(&tls, &public, Url::parse(&format!("https://{bind}/"))?).await?;
        self._port_reservations.push(port);
        old.0.lock().unwrap().method_only = true;
        self.base_url = public;
        self.start_external_process().await?;
        let metadata = arkret_identity::DidWebvhResolver::log_url(&self.service_did)?;
        let response = self.http_client.get(&metadata).send().await?;
        ensure!(
            response.status().is_success(),
            "retained method host {metadata} returned {}",
            response.status()
        );
        Ok(relay)
    }

    pub fn rebind_actor_client(&self, previous: &TestActorClient) -> Result<TestActorClient> {
        ensure!(
            previous.service_id == self.service_id.as_str(),
            "endpoint move changed Account Station"
        );
        let mut client = self.actor_client(
            &previous.actor,
            &previous.device_id,
            previous.session.clone(),
            previous.principal.clone(),
        )?;
        client.controlled_realms = previous.controlled_realms.clone();
        client.default_strands = previous.default_strands.clone();
        client.held_grants = previous.held_grants.clone();
        Ok(client)
    }

    /// Read only this owned fixture's next precommitted control key. Never log
    /// or return its bytes; all faults are published solely through HTTP.
    pub async fn service_route_signer(
        &self,
        database_url: &str,
        resolution: &AuthenticatedServiceResolution,
    ) -> Result<ServiceRouteSigner> {
        ensure!(
            self.external_restart.is_some(),
            "route signer requires an owned fixture"
        );
        let database_url = database_url.to_owned();
        let identity = tokio::task::spawn_blocking(
            move || -> Result<arkret_identity::service_identity::StoredDidCoreIdentity> {
                let mut db = postgres::Client::connect(&database_url, postgres::NoTls)?;
                Ok(serde_json::from_value(
                    db.query_one("SELECT identity FROM service_identity", &[])?
                        .get(0),
                )?)
            },
        )
        .await??;
        ensure!(
            identity.identity.service_id == self.service_id
                && identity.identity.did == resolution.normalized_did_document.id
        );
        let ResolutionMethodHistoryEvidence::WebvhLog { log_entries, .. } =
            &resolution.method_history_evidence
        else {
            anyhow::bail!("fixture is not WebVH")
        };
        ensure!(
            log_entries.last().context("native head")?["versionId"] == identity.identity.version_id
        );
        let (prefix, generation) = identity
            .identity
            .control_key_ref
            .as_str()
            .rsplit_once(':')
            .context("fixture control key generation")?;
        let next = format!(
            "{prefix}:{}",
            generation
                .parse::<u64>()?
                .checked_add(1)
                .context("control generation overflow")?
        );
        let master: [u8; 32] = BASE64_STANDARD
            .decode(DURABLE_TEST_KEYSTORE_MASTER_KEY)?
            .try_into()
            .map_err(|_| anyhow!("fixture master key length"))?;
        // The actual SUT uses this namespace for its durable identity vault.
        let store = EncryptedFileKeyStore::new(
            self.blob_root
                .as_ref()
                .context("fixture blob root")?
                .join("keystore.v1"),
            "coland.service-identity",
            master,
        )?;
        Ok(ServiceRouteSigner {
            did: self.service_did.clone(),
            service_id: self.service_id.clone(),
            entries: log_entries.clone(),
            seed: store.load(&next)?,
        })
    }
}

pub struct ServiceRouteSigner {
    did: Did,
    service_id: DidCoreId,
    entries: Vec<Value>,
    seed: KeyBytes,
}
impl ServiceRouteSigner {
    pub async fn successor(&self, state: Value) -> Result<Vec<Value>> {
        let head = self.entries.last().context("native predecessor")?;
        let earliest = chrono::DateTime::parse_from_rfc3339(
            head["versionTime"].as_str().context("native time")?,
        )?
        .with_timezone(&Utc)
            + chrono::Duration::seconds(1);
        let now =
            chrono::DateTime::from_timestamp(Utc::now().timestamp(), 0).context("wall time")?;
        let at = earliest.max(now);
        while Utc::now() < at {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let following = arkret_canonical::multibase::ed25519_pubkey_to_did_key_multibase(
            &ed25519_dalek::SigningKey::from_bytes(&[0xb7; 32])
                .verifying_key()
                .to_bytes(),
        );
        let entry = arkret_signatures::webvh::prepare_service_rotation(
            &arkret_signatures::webvh::ServiceRotationInput {
                did: self.did.as_str(),
                previous_entries: &self.entries,
                state: &state,
                current_update_seed: self
                    .seed
                    .as_slice()
                    .try_into()
                    .context("fixture update seed length")?,
                next_update_public_key_multibase: &following,
                version_time: at,
            },
        )?;
        Ok(self
            .entries
            .iter()
            .cloned()
            .chain(std::iter::once(entry.log_entry))
            .collect())
    }

    pub fn resolution(&self, entries: Vec<Value>) -> Result<AuthenticatedServiceResolution> {
        let document =
            serde_json::from_value(entries.last().context("native terminal")?["state"].clone())?;
        Ok(
            arkret_identity::build_authenticated_webvh_service_resolution(
                self.service_id.clone(),
                "station".into(),
                document,
                entries,
                vec![],
                Utc::now(),
            )?,
        )
    }
}
