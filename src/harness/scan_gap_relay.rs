//! Run-PKI HTTP fault boundary; accepted originals and the database stay intact.

use anyhow::ensure;
use arkret_wire::{CommitStreamRef, StreamScanOutcome, StreamScanRequest};
use salvo::conn::rustls::{Keycert, RustlsConfig};
use salvo::conn::{Listener, TcpListener as HttpListener};
use salvo::prelude::*;

use super::*;

#[derive(Clone, Default)]
pub struct ScanGapControl(Arc<Mutex<GapState>>);

#[derive(Default)]
struct GapState {
    stream: Option<CommitStreamRef>,
    observations: Vec<StreamScanOutcome>,
}

impl ScanGapControl {
    pub fn omit_position_one(&self, stream: CommitStreamRef) {
        let mut state = self.0.lock().unwrap();
        state.stream = Some(stream);
        state.observations.clear();
    }

    pub fn clear(&self) {
        self.0.lock().unwrap().stream = None;
    }

    pub fn observations(&self) -> Vec<StreamScanOutcome> {
        self.0.lock().unwrap().observations.clone()
    }
}

pub struct ScanGapRelay {
    control: ScanGapControl,
    task: tokio::task::JoinHandle<()>,
}

impl ScanGapRelay {
    pub fn control(&self) -> ScanGapControl {
        self.control.clone()
    }
}

impl Drop for ScanGapRelay {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[derive(Clone)]
struct Relay {
    upstream: Url,
    http: HttpClient,
    control: ScanGapControl,
}

impl Relay {
    async fn forward(&self, req: &mut Request, res: &mut Response) -> Result<()> {
        let path = req
            .uri()
            .path_and_query()
            .context("relay request path")?
            .as_str();
        let target = self.upstream.join(path)?;
        let body = req.payload().await?.to_vec();
        let mut headers = req.headers().clone();
        headers.remove("connection");
        headers.remove("transfer-encoding");
        let response = self
            .http
            .request(req.method().clone(), target)
            .headers(headers)
            .body(body.clone())
            .send()
            .await?;
        res.status_code(response.status());
        let mut headers = response.headers().clone();
        headers.remove("content-length");
        headers.remove("transfer-encoding");
        headers.remove("connection");
        let mut bytes = response.bytes().await?.to_vec();
        if req.uri().path() == "/_arkret/self/streams/scan"
            && res.status_code == Some(StatusCode::OK)
        {
            let request: StreamScanRequest = serde_json::from_slice(&body)?;
            let mut state = self.control.0.lock().unwrap();
            if state.stream.as_ref() == Some(&request.stream_ref) {
                let mut outcome: StreamScanOutcome = serde_json::from_slice(&bytes)?;
                outcome.validate_for_request(&request)?;
                let old_len = outcome.committed_events.len();
                outcome
                    .committed_events
                    .retain(|row| row.commit().stream_position != 1);
                if outcome.committed_events.len() != old_len {
                    state.observations.push(outcome.clone());
                    bytes = serde_json::to_vec(&outcome)?;
                }
            }
        }
        *res.headers_mut() = headers;
        res.write_body(bytes)?;
        Ok(())
    }
}

#[handler]
impl Relay {
    async fn handle(&self, req: &mut Request, res: &mut Response) {
        if let Err(error) = self.forward(req, res).await {
            res.status_code(StatusCode::BAD_GATEWAY);
            res.render(error.to_string());
        }
    }
}

impl ArkretServer {
    /// Move the same retained SUT behind a TLS relay without changing its
    /// advertised origin, DPoP target, service identity or account session.
    pub async fn install_scan_gap_relay(&mut self) -> Result<ScanGapRelay> {
        ensure!(
            self.external_restart.is_some(),
            "scan relay requires an owned process"
        );
        let tls = self._tls.clone().context("scan relay requires run TLS")?;
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let public_port = self.base_url.port().context("scan relay public port")?;
        let mut private_port = reserve_port()?;
        let private_bind = format!("127.0.0.1:{}", private_port.port());
        let upstream = Url::parse(&format!("https://{private_bind}/"))?;
        self.stop_external_process().await?;
        let control = ScanGapControl::default();
        let acceptor = HttpListener::new(format!("127.0.0.1:{public_port}"))
            .rustls(RustlsConfig::new(
                Keycert::new()
                    .cert_from_path(&tls.cert_path)?
                    .key_from_path(&tls.key_path)?,
            ))
            .try_bind()
            .await?;
        let relay = Relay {
            upstream,
            http: tls.http_client()?,
            control: control.clone(),
        };
        let router = Router::new()
            .goal(relay.clone())
            .push(Router::with_path("{**rest}").goal(relay));
        let guard = ScanGapRelay {
            control,
            task: tokio::spawn(async move {
                Server::new(acceptor).serve(router).await;
            }),
        };
        self.external_restart.as_mut().unwrap().bind = private_bind;
        private_port.release();
        self._port_reservations.push(private_port);
        self.start_external_process().await?;
        Ok(guard)
    }
}
