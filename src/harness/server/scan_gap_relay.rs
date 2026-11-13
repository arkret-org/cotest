//! Run-PKI HTTP fault boundary; accepted originals and the database stay intact.

use anyhow::ensure;
use arkret_wire::{CommitStreamRef, StreamScanRequestBody, StreamScanResponseBody};
use salvo::conn::rustls::{Keycert, RustlsConfig};
use salvo::conn::{Listener, TcpListener as HttpListener};
use salvo::prelude::*;

use super::*;

#[derive(Clone, Default)]
pub struct ScanGapControl(Arc<Mutex<GapState>>);

#[derive(Default)]
struct GapState {
    withheld_event_gets: std::collections::BTreeSet<arkret_wire::EventId>,
    withheld_event_get_counts: std::collections::BTreeMap<arkret_wire::EventId, usize>,
    unavailable_paths: std::collections::BTreeSet<String>,
    unavailable_requests: std::collections::BTreeMap<String, usize>,
    stream: Option<CommitStreamRef>,
    position: u64,
    observations: Vec<StreamScanResponseBody>,
    scan_requests: Vec<StreamScanRequestBody>,
    planned_events: Vec<arkret_wire::EventId>,
    block_audit_replication: bool,
    blocked_audit_replications: usize,
    split_audit_scan: bool,
    split_audit_pages: usize,
    drop_audit_ack: bool,
    dropped_audit_acks: usize,
    hold_watch_reply: bool,
    watch_reply_started: Arc<tokio::sync::Notify>,
    watch_reply_release: Arc<tokio::sync::Notify>,
}

impl ScanGapControl {
    pub fn set_event_get_withheld(&self, event: &arkret_wire::EventId, withheld: bool) {
        let mut state = self.0.lock().unwrap();
        if withheld {
            state.withheld_event_gets.insert(event.clone());
        } else {
            state.withheld_event_gets.remove(event);
        }
    }

    pub fn withheld_event_get_count(&self, event: &arkret_wire::EventId) -> usize {
        self.0
            .lock()
            .unwrap()
            .withheld_event_get_counts
            .get(event)
            .copied()
            .unwrap_or(0)
    }

    pub fn hold_next_watch_reply(&self) {
        let mut state = self.0.lock().unwrap();
        state.hold_watch_reply = true;
        state.watch_reply_started = Arc::new(tokio::sync::Notify::new());
        state.watch_reply_release = Arc::new(tokio::sync::Notify::new());
    }

    pub async fn wait_for_held_watch_reply(&self) -> Result<()> {
        let started = self.0.lock().unwrap().watch_reply_started.clone();
        tokio::time::timeout(std::time::Duration::from_secs(30), started.notified())
            .await
            .context("native governor did not produce a held Watch reply")?;
        Ok(())
    }

    pub fn release_watch_reply(&self) {
        self.0.lock().unwrap().watch_reply_release.notify_one();
    }
    pub fn block_audit_replication(&self) {
        self.0.lock().unwrap().block_audit_replication = true;
    }
    pub fn split_audit_scan_and_drop_ack(&self) {
        let mut state = self.0.lock().unwrap();
        state.split_audit_scan = true;
        state.drop_audit_ack = true;
    }
    pub fn audit_fault_counts(&self) -> (usize, usize, usize) {
        let state = self.0.lock().unwrap();
        (
            state.blocked_audit_replications,
            state.split_audit_pages,
            state.dropped_audit_acks,
        )
    }

    pub fn set_path_unavailable(&self, path: &str, unavailable: bool) {
        let mut state = self.0.lock().unwrap();
        if unavailable {
            state.unavailable_paths.insert(path.to_owned());
        } else {
            state.unavailable_paths.remove(path);
        }
    }

    pub fn unavailable_request_count(&self, path: &str) -> usize {
        self.0
            .lock()
            .unwrap()
            .unavailable_requests
            .get(path)
            .copied()
            .unwrap_or(0)
    }
    pub fn omit_position_one(&self, stream: CommitStreamRef) {
        self.omit_position(stream, 1);
    }

    pub fn omit_position(&self, stream: CommitStreamRef, position: u64) {
        let mut state = self.0.lock().unwrap();
        state.stream = Some(stream);
        state.position = position;
        state.observations.clear();
    }

    pub fn event_submission_count(&self, event: &arkret_wire::EventId) -> usize {
        self.0
            .lock()
            .unwrap()
            .planned_events
            .iter()
            .filter(|id| *id == event)
            .count()
    }

    pub fn clear(&self) {
        self.0.lock().unwrap().stream = None;
    }

    pub fn observations(&self) -> Vec<StreamScanResponseBody> {
        self.0.lock().unwrap().observations.clone()
    }

    pub fn clear_scan_requests(&self) {
        self.0.lock().unwrap().scan_requests.clear();
    }

    pub fn scan_requests(&self) -> Vec<StreamScanRequestBody> {
        self.0.lock().unwrap().scan_requests.clone()
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
        let unavailable = {
            let mut state = self.control.0.lock().unwrap();
            let path = req.uri().path();
            if state.unavailable_paths.contains(path) {
                *state
                    .unavailable_requests
                    .entry(path.to_owned())
                    .or_default() += 1;
                true
            } else {
                false
            }
        };
        if unavailable {
            res.status_code(salvo::http::StatusCode::SERVICE_UNAVAILABLE);
            res.render(Text::Plain("fixture upstream unavailable"));
            return Ok(());
        }
        let path = req
            .uri()
            .path_and_query()
            .context("relay request path")?
            .as_str();
        let target = self.upstream.join(path)?;
        // Match the production ingress budget for complete handoff material.
        let body = req.payload_with_max_size(16 * 1024 * 1024).await?.to_vec();
        use arkret_models_collaboration::authority_commit::{
            PeerAuthoritySubmitRequestBody, PeerRegisteredAtomicUnit,
        };
        let peer_unit = (req.uri().path() == "/_arkret/peer/events")
            .then(|| serde_json::from_slice::<PeerAuthoritySubmitRequestBody>(&body).ok())
            .flatten();
        if matches!(&peer_unit, Some(PeerAuthoritySubmitRequestBody::RegisteredAtomicUnit(value)) if matches!(&value.unit, PeerRegisteredAtomicUnit::AuditPairedEvent(_)))
        {
            let blocked = {
                let mut state = self.control.0.lock().unwrap();
                if state.block_audit_replication {
                    state.blocked_audit_replications += 1;
                    true
                } else {
                    false
                }
            };
            if blocked {
                res.status_code(StatusCode::SERVICE_UNAVAILABLE);
                res.render("injected whole audit delivery outage");
                return Ok(());
            }
        }
        if req.uri().path() == "/_arkret/self/events"
            && req.method() == salvo::http::Method::POST
            && let Ok(
                arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequestBody::Event(
                    submission,
                ),
            ) = serde_json::from_slice::<
                arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequestBody,
            >(&body)
        {
            self.control
                .0
                .lock()
                .unwrap()
                .planned_events
                .push(submission.event.event_id);
        }
        let mut headers = req.headers().clone();
        // Record the actual ingress authority for the production gateway
        // reconstruction path. The private HTTP/2 hop has another URI
        // authority, and a caller-supplied forwarded host is not that ingress.
        let authority = req
            .uri()
            .authority()
            .map(|authority| authority.as_str())
            .or_else(|| {
                req.headers()
                    .get("host")
                    .and_then(|value| value.to_str().ok())
            })
            .context("relay request authority")?;
        headers.insert("host", authority.parse()?);
        headers.insert("x-forwarded-host", authority.parse()?);
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
        if req.uri().path() == "/_arkret/self/signal/subscribe" {
            *res.headers_mut() = headers;
            res.stream(response.bytes_stream());
            return Ok(());
        }
        let mut bytes = response.bytes().await?.to_vec();
        if req.method() == salvo::http::Method::GET
            && req
                .uri()
                .path()
                .starts_with("/_arkret/self/committed-events/")
            && res.status_code == Some(StatusCode::OK)
            && let Ok(original) = serde_json::from_slice::<arkret_wire::CommittedEventView>(&bytes)
        {
            let mut state = self.control.0.lock().unwrap();
            let event = original.commit().event_ref.clone();
            if state.withheld_event_gets.contains(&event) {
                *state.withheld_event_get_counts.entry(event).or_default() += 1;
                bytes = serde_json::to_vec(&arkret_wire::CommittedEventView::Withheld(
                    arkret_wire::CommittedEventWithheldView {
                        commit: original.commit().clone(),
                        event_disclosure: arkret_wire::EventDisclosure {
                            status: arkret_wire::EventDisclosureStatus::Withheld,
                        },
                    },
                ))?;
            }
        }
        if req.uri().path() == "/_arkret/peer/strands/watch/current"
            && res.status_code == Some(StatusCode::OK)
        {
            let gate = {
                let mut state = self.control.0.lock().unwrap();
                if state.hold_watch_reply {
                    state.hold_watch_reply = false;
                    state.watch_reply_started.notify_one();
                    Some(state.watch_reply_release.clone())
                } else {
                    None
                }
            };
            if let Some(gate) = gate {
                gate.notified().await;
            }
        }
        if res.status_code == Some(StatusCode::OK)
            && matches!(
                &peer_unit,
                Some(PeerAuthoritySubmitRequestBody::AuthorityForwardAtomic(_))
            )
        {
            let drop_ack = {
                let mut state = self.control.0.lock().unwrap();
                if state.drop_audit_ack {
                    state.drop_audit_ack = false;
                    state.dropped_audit_acks += 1;
                    true
                } else {
                    false
                }
            };
            if drop_ack {
                res.status_code(StatusCode::SERVICE_UNAVAILABLE);
                headers.remove("content-type");
                bytes = b"injected lost accepted audit acknowledgement".to_vec();
            }
        }
        if req.uri().path() == "/_arkret/peer/streams/scan"
            && res.status_code == Some(StatusCode::OK)
        {
            let request: StreamScanRequestBody = serde_json::from_slice(&body)?;
            let mut state = self.control.0.lock().unwrap();
            state.scan_requests.push(request.clone());
            if state.split_audit_scan && request.limit > 2 {
                let mut page: arkret_models_collaboration::authority_commit::PeerStreamScanResponseBody =
                    serde_json::from_slice(&bytes)?;
                page.validate_for_request(&request)?;
                if let Some(index) = page.committed_events.iter().position(|item| matches!(item,
                    arkret_wire::CommittedEventView::Full(full) if full.event.kind != arkret_wire::EventKind::AuditAccessed
                    && arkret_models_collaboration::authority_commit::is_audit_paired_event_slot(&full.event).unwrap_or(false)))
                    && index + 1 < page.committed_events.len() {
                    page.committed_events.truncate(index + 1); page.truncated = true;
                    page.producer_signer_facts.retain(|fact| page.committed_events.iter().any(|item| item.commit().commit_id == fact.target.commit_id));
                    page.validate_for_request(&request)?;
                    state.split_audit_pages += 1; bytes = serde_json::to_vec(&page)?;
                }
            }
        }
        if req.uri().path() == "/_arkret/self/streams/scan"
            && res.status_code == Some(StatusCode::OK)
        {
            let request: StreamScanRequestBody = serde_json::from_slice(&body)?;
            let mut state = self.control.0.lock().unwrap();
            state.scan_requests.push(request.clone());
            if state.stream.as_ref() == Some(&request.stream_ref) {
                let mut outcome: StreamScanResponseBody = serde_json::from_slice(&bytes)?;
                outcome.validate_for_request(&request)?;
                let old_len = outcome.committed_events.len();
                outcome
                    .committed_events
                    .retain(|row| row.commit().stream_position != state.position);
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
