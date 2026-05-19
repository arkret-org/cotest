//! CT-7 — Soland + Floria push gateway end-to-end.
//!
//! Spec: `contrix-spec/spec/v1/zh/discovery/push-notifications.md` §3 (push
//! device registration) and §4 (push rule engine + blind wakeup invariants).
//!
//! Goal:
//!   1. Alice's chime-like client registers a push device with soland (the
//!      principal server) using the standard `cx.push.register_device`
//!      operation. soland forwards the registration to floria (the push
//!      gateway) per the principal/push bridge contract.
//!   2. A message-creation event in a Space alice is in triggers soland's
//!      notify rule.
//!   3. Soland calls floria's `POST /api/v1/push/notify` with a blind-wakeup
//!      envelope (no sender DID, no message body, no Space id — only
//!      `push_target_id`, `wakeup_kind`, and `devices[]`).
//!   4. Floria's `custom` pushkin dispatches to a mock HTTPS receiver we
//!      stand up in-process; the receiver MUST observe exactly one POST
//!      whose body satisfies §4.5 blind-wakeup invariants.
//!
//! Why `#[ignore]`-only:
//!
//! Wiring this end-to-end requires a real `floria` binary (built sibling
//! checkout or `FLORIA_BIN` env override), a real `soland` binary configured
//! with `SOLAND_PUSH_GATEWAY_URL` pointing at the spawned floria, a templated
//! floria config whose `custom` pushkin URL points at the in-process mock
//! receiver, and matching service-DID + signing-key plumbing between the two.
//! That dependency surface is intentionally opt-in: CI runners without the
//! binaries get a clean ignore; local developers exercising the bridge run
//! `cargo test --test soland_floria_push_e2e -- --ignored`.
//!
//! The scenario below is fully scaffolded so the wiring is auditable even
//! when ignored; the prerequisite gating uses
//! [`crate::scenarios::_helpers::external_binary::skip_reason`] so a missing
//! binary surfaces as a descriptive `bail!` rather than a hang.

use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use serde_json::{Value, json};

use crate::scenarios::_helpers::external_binary::{
    SOLAND_SPEC, skip_reason, try_spawn_with_extra_env,
};
use crate::scenarios::_helpers::floria_bootstrap::spawn_floria_with_custom_pushkin_url;

/// Top-level run. Wired so the entire pipeline (alice register → bob send →
/// soland forward → floria fan-out → mock receiver observes blind wakeup) is
/// represented in code, even though we currently gate the full live spawn
/// behind binary availability.
pub async fn soland_floria_push_blind_wakeup_e2e_run() -> Result<()> {
    if let Some(reason) = skip_reason(&SOLAND_SPEC) {
        bail!(reason.describe("soland"));
    }

    // 1. Mock HTTPS receiver — floria's `custom` pushkin will POST blind
    //    wakeups to this URL. We run it on plain HTTP (127.0.0.1:<port>) and
    //    rely on `custom` pushkin's allow-http branch (configured via the
    //    rendered floria config below) so we don't need a TLS cert just to
    //    exercise the wire shape.
    let receiver = MockPushReceiver::spawn().context("spawn mock push receiver")?;
    let receiver_url = receiver.url().to_owned();

    // 2. Spawn floria with a config whose `custom` pushkin points at
    //    `receiver_url`, so a live floria process will fan out into our
    //    in-process sink instead of the placeholder health-only URL.
    let floria = match spawn_floria_with_custom_pushkin_url(Some(&receiver_url)).await? {
        Some(handle) => handle,
        None => bail!(
            "floria bootstrap returned None — binary missing or config render failed \
             (CT-7 prereq)"
        ),
    };
    let floria_gateway_url = floria.base_url().to_owned();

    // 3. Spawn soland configured with floria as its outbound push gateway.
    //    Soland reads `SOLAND_PUSH_GATEWAY_URL` to learn where to forward
    //    `cx.push.notify` calls. The helper keeps SOLAND_SPEC.extra_env and
    //    layers this per-run URL on top.
    let _soland = match try_spawn_with_extra_env(
        &SOLAND_SPEC,
        &[("SOLAND_PUSH_GATEWAY_URL", floria_gateway_url.as_str())],
    )
    .await?
    {
        Some(handle) => handle,
        None => bail!(
            "soland bootstrap returned None — binary missing or failed health check \
             (CT-7 prereq)"
        ),
    };

    // 4. The process-level wiring is now live: mock receiver URL is injected
    //    into floria config, and soland receives SOLAND_PUSH_GATEWAY_URL.
    //    The remaining unblock requires soland's public test API for device
    //    registration/message creation to be finalized.
    //
    bail!(
        "TODO(CT-7): helper-level wiring is unblocked and live services were spawned \
         (floria={floria_gateway_url}, receiver={receiver_url}); finish the service API \
         steps by (a) POSTing `cx.push.register_device` for alice, \
         (b) writing a bob→alice message event, (c) waiting on \
         `receiver.next_notification()` and asserting blind-wakeup invariants per §4.5: \
         - `notification.push_target_id` is a per-(principal,device,push_route) pseudonym \
         - `notification.wakeup_kind in [\"message\",\"mention\",\"reaction\",\"call_invite\"]` \
         - the body contains NO `sender`, `sender_did`, `event_id`, `space_id`, `space_name`, \
           `message_body`, `body`, `payload`, or any cross-Space stable identifier."
    );
}

/// In-process HTTP receiver impersonating the operator's custom push endpoint
/// that floria's `custom` pushkin POSTs blind wakeups to. We capture every
/// request body so the scenario can assert §4.5 invariants on the wire.
struct MockPushReceiver {
    url: String,
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    notifications: Arc<Mutex<Vec<Value>>>,
    handle: Option<thread::JoinHandle<()>>,
}

impl MockPushReceiver {
    fn spawn() -> Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let addr = listener.local_addr()?;
        let url = format!("http://{addr}/cotest-push-sink");
        let stop = Arc::new(AtomicBool::new(false));
        let notifications: Arc<Mutex<Vec<Value>>> = Arc::new(Mutex::new(Vec::new()));
        let thread_stop = Arc::clone(&stop);
        let thread_notifications = Arc::clone(&notifications);
        let handle = thread::spawn(move || {
            while !thread_stop.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let log = Arc::clone(&thread_notifications);
                        thread::spawn(move || handle_request(stream, log));
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }
        });
        Ok(Self {
            url,
            addr,
            stop,
            notifications,
            handle: Some(handle),
        })
    }

    fn url(&self) -> &str {
        &self.url
    }

    /// Block until at least one notification arrives or `timeout` elapses.
    /// Used by the live wiring (once unblocked) to assert exactly-one
    /// delivery for the bob→alice message scenario.
    #[allow(dead_code)]
    async fn next_notification(&self, timeout: Duration) -> Result<Value> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(notification) = self.notifications.lock().unwrap().first().cloned() {
                return Ok(notification);
            }
            if Instant::now() >= deadline {
                bail!("mock push receiver got no notification within {timeout:?}");
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// Snapshot the captured notifications — useful for the count assertion
    /// (`exactly 1 within timeout`) and for blind-wakeup invariant checks.
    #[allow(dead_code)]
    fn captured(&self) -> Vec<Value> {
        self.notifications.lock().unwrap().clone()
    }
}

impl Drop for MockPushReceiver {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        let _ = TcpStream::connect(self.addr);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn handle_request(mut stream: TcpStream, notifications: Arc<Mutex<Vec<Value>>>) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                buffer.extend_from_slice(&chunk[..n]);
                if request_complete(&buffer) {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    if let Some(body) = parse_json_body(&buffer) {
        notifications.lock().unwrap().push(body);
    }
    // Floria's custom pushkin expects a 200 with `{"rejected": []}` to mark
    // the delivery as successful (no push token retraction).
    let response_body = json!({"rejected": []}).to_string();
    let response = format!(
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        response_body.as_bytes().len(),
        response_body
    );
    let _ = stream.write_all(response.as_bytes());
}

fn request_complete(buffer: &[u8]) -> bool {
    let Some(header_end) = buffer.windows(4).position(|w| w == b"\r\n\r\n") else {
        return false;
    };
    let body_start = header_end + 4;
    let headers = String::from_utf8_lossy(&buffer[..header_end]);
    let content_length = headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())
                .flatten()
        })
        .unwrap_or(0);
    buffer.len() >= body_start + content_length
}

fn parse_json_body(buffer: &[u8]) -> Option<Value> {
    let header_end = buffer.windows(4).position(|w| w == b"\r\n\r\n")?;
    let body = &buffer[header_end + 4..];
    serde_json::from_slice(body).ok()
}

/// §4.5 blind-wakeup invariant checks — exported for use by the live wiring
/// once the spawn-time env injection lands.
#[allow(dead_code)]
pub fn assert_blind_wakeup_invariants(notification: &Value) -> Result<()> {
    let inner = notification
        .get("notification")
        .ok_or_else(|| anyhow::anyhow!("push body missing top-level `notification`"))?;
    if !inner
        .get("push_target_id")
        .and_then(Value::as_str)
        .is_some_and(|value| !value.is_empty())
    {
        bail!("blind wakeup MUST carry a non-empty `notification.push_target_id`");
    }
    let wakeup_kind = inner
        .get("wakeup_kind")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("blind wakeup MUST carry `notification.wakeup_kind`"))?;
    let allowed = [
        "message",
        "mention",
        "reaction",
        "call_invite",
        "incoming_call",
    ];
    if !allowed.contains(&wakeup_kind) {
        bail!(
            "wakeup_kind `{wakeup_kind}` is outside the §2.2 closed enum {:?}",
            allowed
        );
    }
    // §4.5 + §2.2 — these fields MUST NOT appear on a blind wakeup. Calling
    // them out individually so a regression report names the leaked field.
    let banned_fields = [
        "sender",
        "sender_did",
        "sender_display_name",
        "event_id",
        "realm_id",
        "space_name",
        "kind",
        "message_body",
        "body",
        "payload",
        "matched_keyword",
        "principal_id",
        "device_did",
    ];
    if let Some(map) = inner.as_object() {
        for field in banned_fields {
            if map.contains_key(field) {
                bail!(
                    "blind wakeup leaked banned identifier `notification.{field}` — \
                     violates push-notifications §2.2 / §4.5"
                );
            }
        }
    }
    Ok(())
}
