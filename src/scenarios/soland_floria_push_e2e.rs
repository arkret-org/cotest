//! CT-7 — Soland + Floria push gateway end-to-end.
//!
//! Spec: `arkret-spec/spec/v1/zh/discovery/push-notifications.md` §3 (push
//! device registration) and §4 (push rule engine + blind wakeup invariants).
//!
//! Goal:
//!   1. Alice's chime-like client registers a push device with soland (the principal server) using
//!      the standard `ak.edge.push.command.register_device` operation. soland forwards the
//!      registration to floria (the push gateway) per the principal/push bridge contract.
//!   2. A message-creation event in a Space alice is in triggers soland's notify rule.
//!   3. Soland calls floria's `POST /_arkret/edge/push/notify` with a blind-wakeup envelope (no
//!      sender DID, no message body, no Space id — only `push_target_id`, `wakeup_kind`, and
//!      `devices[]`).
//!   4. Floria's `custom` pushkin dispatches to a mock HTTPS receiver we stand up in-process; the
//!      receiver MUST observe exactly one POST whose body satisfies §4.5 blind-wakeup invariants.
//!
//! Why `#[ignore]`-only:
//!
//! Wiring this end-to-end requires a real `floria` binary (built sibling
//! checkout or `FLORIA_BIN` env override), a real `soland` binary configured
//! with `SOLAND_PUSH_GATEWAY_URL` pointing at the spawned floria, a templated
//! floria config whose `custom` pushkin URL points at the in-process mock
//! receiver, and matching service ID + signing-key plumbing between the two.
//! That dependency surface is intentionally opt-in: CI runners without the
//! binaries get a clean ignore; local developers exercising the bridge run
//! `cargo test --test soland_floria_push_e2e -- --ignored`.
//!
//! The scenario below is fully scaffolded so the wiring is auditable even
//! when ignored; the prerequisite gating uses
//! [`crate::scenarios::_helpers::external_binary::skip_reason`] so a missing
//! binary surfaces as a descriptive `bail!` rather than a hang.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use salvo::affix_state;
use salvo::prelude::{Depot, Json, Request, Response, Router, handler};
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

    // 1. Mock HTTPS receiver — floria's `custom` pushkin will POST blind wakeups to this URL. We
    //    run it on plain HTTP (127.0.0.1:<port>) and rely on `custom` pushkin's allow-http branch
    //    (configured via the rendered floria config below) so we don't need a TLS cert just to
    //    exercise the wire shape.
    let receiver = MockPushReceiver::spawn()
        .await
        .context("spawn mock push receiver")?;
    let receiver_url = receiver.url().to_owned();

    // 2. Spawn floria with a config whose `custom` pushkin points at `receiver_url`, so a live
    //    floria process will fan out into our in-process sink instead of the placeholder
    //    health-only URL.
    let floria = match spawn_floria_with_custom_pushkin_url(Some(&receiver_url)).await? {
        Some(handle) => handle,
        None => bail!(
            "floria bootstrap returned None — binary missing or config render failed \
             (CT-7 prereq)"
        ),
    };
    let floria_gateway_url = floria.base_url().to_owned();

    // 3. Spawn soland configured with floria as its outbound push gateway. Soland reads
    //    `SOLAND_PUSH_GATEWAY_URL` to learn where to forward `ak.edge.push.command.notify` calls.
    //    The helper keeps SOLAND_SPEC.extra_env and layers this per-run URL on top.
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

    // 4. The process-level wiring is now live: mock receiver URL is injected into floria config,
    //    and soland receives SOLAND_PUSH_GATEWAY_URL. The remaining unblock requires soland's
    //    public test API for device registration/message creation to be finalized.
    //
    bail!(
        "TODO(CT-7): helper-level wiring is unblocked and live services were spawned \
         (floria={floria_gateway_url}, receiver={receiver_url}); finish the service API \
         steps by (a) POSTing `ak.edge.push.command.register_device` for alice, \
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
#[derive(Clone)]
struct PushReceiverState {
    notifications: Arc<Mutex<Vec<Value>>>,
}

struct MockPushReceiver {
    url: String,
    notifications: Arc<Mutex<Vec<Value>>>,
    _server: crate::scenarios::_helpers::mock_http::MockServer,
}

impl MockPushReceiver {
    async fn spawn() -> Result<Self> {
        let notifications: Arc<Mutex<Vec<Value>>> = Arc::new(Mutex::new(Vec::new()));
        let state = PushReceiverState {
            notifications: Arc::clone(&notifications),
        };
        let router = Router::with_path("cotest-push-sink")
            .hoop(affix_state::inject(state))
            .post(push_sink);
        let server = crate::scenarios::_helpers::mock_http::spawn_mock(router).await?;
        let url = format!("http://{}/cotest-push-sink", server.addr());
        Ok(Self {
            url,
            notifications,
            _server: server,
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

#[handler]
async fn push_sink(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let notifications = depot
        .get_typed::<PushReceiverState>()
        .expect("push mock state injected")
        .notifications
        .clone();
    if let Ok(body) = req.parse_json::<arkret_core::PushNotifyRequestBody>().await {
        let body = serde_json::to_value(body).unwrap_or(Value::Null);
        notifications.lock().unwrap().push(body);
    }
    // Floria's custom pushkin expects a 200 with `{"rejected": []}` to mark
    // the delivery as successful (no push token retraction).
    res.render(Json(json!({ "rejected": [] })));
}

/// §4.5 blind-wakeup invariant checks — exported for use by the live wiring
/// once the spawn-time env injection lands.
#[allow(dead_code)]
pub fn assert_blind_wakeup_invariants(notification: &Value) -> Result<()> {
    let inner = notification
        .get("notification")
        .ok_or_else(|| anyhow::anyhow!("push body missing top-level `notification`"))?;
    if inner
        .get("push_target_id")
        .and_then(Value::as_str)
        .is_none_or(|value| value.is_empty())
    {
        bail!("blind wakeup MUST carry a non-empty `notification.push_target_id`");
    }
    let wakeup_kind = inner
        .get("wakeup_kind")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("blind wakeup MUST carry `notification.wakeup_kind`"))?;
    let allowed = ["message", "mention", "reaction", "call_invite"];
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
