//! Active public Gateway revocation is performed only by the erasure worker.

use arkret_models_integration::{
    PushNotifyRequestBody, PushNotifyResponseBody, PushRegisterDeviceRequestBody,
    PushRegisterDeviceResponseBody, PushRegistrationHandoffRequestBody,
    PushRegistrationHandoffResponseBody, PushRegistrationHandoffState,
};
use base64::Engine as _;

use super::super::push_gateway as push;
use super::*;
use crate::scenarios::_helpers::floria_bootstrap::{NativeFloria, NativePushProvider};

const SCOPE: [&str; 2] = [
    "ak.edge.push.command.apply_registration.v1",
    "ak.edge.push.command.notify.v1",
];

/// A real row lock, never an injected HTTP response or a synthesized receipt.
/// Dropping this handle releases the transaction even when an assertion fails.
struct GatewayRevokeHold {
    holder_pid: i32,
    release: Option<std::sync::mpsc::Sender<()>>,
    task: Option<tokio::task::JoinHandle<Result<()>>>,
}

impl GatewayRevokeHold {
    async fn acquire(gateway: &NativeFloria, source: &Deployment, id: &str) -> Result<Self> {
        let url = gateway.database.connect_url.clone();
        let station = source.station.service_id().to_string();
        let id = id.to_owned();
        let (ready, acquired) = tokio::sync::oneshot::channel();
        let (release, released) = std::sync::mpsc::channel();
        let task = tokio::task::spawn_blocking(move || -> Result<()> {
            let mut db = postgres::Client::connect(&url, postgres::NoTls)?;
            let mut tx = db.transaction()?;
            let row = tx.query_one(
                "SELECT pg_backend_pid(), state FROM floria_push_registration_handoffs \
                 WHERE source_station_id=$1 AND registration_id=$2 FOR UPDATE",
                &[&station, &id],
            )?;
            ensure!(
                row.get::<_, String>(1) == "active",
                "held Gateway row is not active"
            );
            ready
                .send(row.get::<_, i32>(0))
                .map_err(|_| anyhow::anyhow!("Gateway holder observer dropped"))?;
            let released = released.recv_timeout(std::time::Duration::from_secs(60));
            tx.rollback()?;
            released
                .context("Gateway row-lock release was not requested within its finite lifetime")?;
            Ok(())
        });
        let holder_pid = match acquired.await {
            Ok(pid) => pid,
            Err(error) => {
                task.await??;
                anyhow::bail!("Gateway row lock did not initialize: {error}");
            }
        };
        Ok(Self {
            holder_pid,
            release: Some(release),
            task: Some(task),
        })
    }

    async fn release(mut self) -> Result<()> {
        self.release
            .take()
            .context("Gateway hold already released")?
            .send(())
            .map_err(|_| anyhow::anyhow!("Gateway holder ended before release"))?;
        self.task
            .take()
            .context("Gateway holder task missing")?
            .await??;
        Ok(())
    }
}

impl Drop for GatewayRevokeHold {
    fn drop(&mut self) {
        if let Some(release) = self.release.take() {
            let _ = release.send(());
        }
    }
}

pub(super) struct NativeErasurePushFixture {
    gateway: NativeFloria,
    registered: PushRegisterDeviceResponseBody,
    active: PushRegistrationHandoffRequestBody,
    notify: PushNotifyRequestBody,
    cursor: usize,
    hold: Option<GatewayRevokeHold>,
    evidence: Value,
}

async fn cut(source: &Deployment, gateway: &NativeFloria, registration: &str) -> Result<Value> {
    let source_url = source
        .station
        .owned_database_url()
        .context("owned erasure source PG")?
        .to_owned();
    let gateway_url = gateway.database.connect_url.clone();
    let station = source.station.service_id().to_string();
    let account = json!(source.account);
    let registration = registration.to_owned();
    tokio::task::spawn_blocking(move || -> Result<Value> {
        let mut source = postgres::Client::connect(&source_url, postgres::NoTls)?;
        let mut tx = source.build_transaction().isolation_level(postgres::IsolationLevel::RepeatableRead).read_only(true).start()?;
        let intents: Vec<Value> = tx.query(
            "SELECT to_jsonb(r)-'canonical_request' || jsonb_build_object('canonical_request_base64',encode(canonical_request,'base64')) \
             FROM push_registration_handoff_intents r WHERE source_station_id=$1 AND local_account_id=$2 ORDER BY registration_id",
            &[&station, &account],
        )?.into_iter().map(|row| row.get(0)).collect();
        let devices: Vec<Value> = tx.query(
            "SELECT to_jsonb(r) FROM push_devices r WHERE payload->'account_id'=$1 ORDER BY id", &[&account],
        )?.into_iter().map(|row| row.get(0)).collect();
        let completions: Vec<Value> = tx.query(
            "SELECT response_body FROM idempotency_keys WHERE response_body->'account_id'=$1 AND response_body->>'state'='completed' ORDER BY idempotency_key", &[&account],
        )?.into_iter().map(|row| row.get(0)).collect();
        tx.commit()?;
        let mut gateway = postgres::Client::connect(&gateway_url, postgres::NoTls)?;
        let registrations: Vec<Value> = gateway.query(
            "SELECT to_jsonb(r)-'route_ciphertext' || jsonb_build_object('has_route_ciphertext',route_ciphertext IS NOT NULL) \
             FROM floria_push_registration_handoffs r WHERE source_station_id=$1 AND registration_id=$2",
            &[&station, &registration],
        )?.into_iter().map(|row| row.get(0)).collect();
        Ok(json!({"intents":intents,"push_devices":devices,"completions":completions,"gateway_registrations":registrations}))
    }).await?
}

fn original_request(row: &Value) -> Result<PushRegistrationHandoffRequestBody> {
    // PostgreSQL's base64 encoder wraps long bytea values at 76 columns.
    let encoded = row["canonical_request_base64"]
        .as_str()
        .context("original handoff bytes")?;
    let encoded: String = encoded
        .chars()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect();
    let raw = base64::engine::general_purpose::STANDARD.decode(encoded)?;
    let request: PushRegistrationHandoffRequestBody = serde_json::from_slice(&raw)?;
    ensure!(
        raw == arkret_canonical::canonical_json_bytes(&request)?,
        "handoff original is not canonical"
    );
    ensure!(
        row["request_digest"] == json!(request.request_digest()?),
        "handoff digest does not bind its original bytes"
    );
    Ok(request)
}

pub(super) async fn register(source: &mut Deployment) -> Result<NativeErasurePushFixture> {
    let provider = NativePushProvider::spawn().await?;
    let gateway = NativeFloria::spawn_required(&source.station, provider).await?;
    source
        .station
        .restart_with_native_push_gateway(
            &gateway.identity.resolution,
            &gateway.identity.verification_method,
        )
        .await?;
    let mut cursor = gateway.observations()?["forwarded"]
        .as_array()
        .context("Gateway ingress")?
        .len();
    let push_key = format!("native-erasure-{}", uuid::Uuid::new_v4().simple());
    let request = PushRegisterDeviceRequestBody {
        device_id: arkret_wire::DeviceId::new(source.controller.device_id.clone())?,
        push_gateway_url: format!("{}/_arkret/edge/push/notify", gateway.server.base_url),
        push_key: arkret_models_integration::PushKey::new(push_key.clone())
            .map_err(anyhow::Error::msg)?,
        platform: None,
        app_id: Some("org.arkret.native-push".to_owned()),
        display_name: None,
        visible_notification_opt_in: false,
    };
    let registered = source
        .controller
        .sdk()
        .push_register_device(&request)
        .await?;
    let applied = push::record_forwarded(&gateway, &mut cursor)?;
    ensure!(
        applied.len() == 1 && applied[0]["status"] == 200,
        "active registration has no real Gateway acceptance: {applied:?}"
    );
    let active: PushRegistrationHandoffRequestBody =
        serde_json::from_value(applied[0]["request"].clone())?;
    let accepted: PushRegistrationHandoffResponseBody =
        serde_json::from_value(applied[0]["response"].clone())?;
    push::receipt(&gateway, &source.station, &active, &accepted)?;
    ensure!(
        active.state() == PushRegistrationHandoffState::Active
            && active.registration_id() == &registered.registration_id
            && active.push_target_id() == &registered.push_target_id
            && active.device_id() == &request.device_id,
        "active Gateway tuple differs from actual Station registration"
    );
    let notify: PushNotifyRequestBody = serde_json::from_value(
        json!({"notification":{"push_target_id":registered.push_target_id,"wakeup_kind":"message","devices":[{"device_id":request.device_id}]}}),
    )?;
    let delivered: PushNotifyResponseBody = push::client(&source.station, &gateway)?
        .push_notify(
            &notify,
            &format!("native-erasure-active-{}", uuid::Uuid::new_v4()),
            source.station.service_id(),
            &gateway.identity.service_id,
        )
        .await?;
    let notify_exchange = push::record_forwarded(&gateway, &mut cursor)?;
    ensure!(
        delivered.outcomes
            == vec![
                arkret_models_integration::PushGatewaySubmissionOutcome::accepted(
                    request.device_id.clone()
                )
            ],
        "real active route did not accept the Device"
    );
    let received = gateway.observations()?["provider"]["provider_received"].clone();
    ensure!(
        received.as_array().is_some_and(|rows| rows.len() == 1)
            && received[0]["uri"]
                .as_str()
                .is_some_and(|uri| uri.ends_with(&push_key)),
        "active route did not actually reach the owned provider"
    );
    let before = cut(source, &gateway, registered.registration_id.as_str()).await?;
    ensure!(
        before["completions"] == json!([])
            && before["push_devices"]
                .as_array()
                .is_some_and(|rows| rows.len() == 1 && rows[0]["public_handoff"] == true)
            && before["intents"]
                .as_array()
                .is_some_and(|rows| rows.len() == 1)
            && before["intents"][0]["desired_state"] == "active"
            && before["intents"][0]["status"] == "receipt_verified"
            && before["intents"][0]["receipt"] == json!(accepted.receipt)
            && before["gateway_registrations"][0]["state"] == "active"
            && before["gateway_registrations"][0]["has_route_ciphertext"] == true,
        "fixture was not durably active in both real stores"
    );
    ensure!(
        original_request(&before["intents"][0])? == active,
        "source active original differs from Gateway request"
    );
    Ok(NativeErasurePushFixture {
        gateway,
        registered: registered.clone(),
        active,
        notify,
        cursor,
        hold: None,
        evidence: json!({"registration_request":request,"registered":registered,"apply":applied,"active_acceptance":accepted,"initial_notify":delivered,"initial_notify_exchange":notify_exchange,"provider_before":received,"before":before}),
    })
}

impl NativeErasurePushFixture {
    /// Call immediately before sending the original AA erasure request.
    pub(super) async fn hold_revoke(&mut self, source: &Deployment) -> Result<()> {
        ensure!(self.hold.is_none(), "Gateway barrier was already armed");
        self.hold = Some(
            GatewayRevokeHold::acquire(
                &self.gateway,
                source,
                self.registered.registration_id.as_str(),
            )
            .await?,
        );
        Ok(())
    }

    /// Observe the actual worker's PG lock wait and real typed DB refusal.
    /// Releasing the lock permits that same durable erasure job to retry.
    pub(super) async fn await_failed_revoke_and_release(
        &mut self,
        source: &Deployment,
    ) -> Result<()> {
        let pid = self
            .hold
            .as_ref()
            .context("Gateway barrier not armed")?
            .holder_pid;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(40);
        let mut blocked = None;
        let mut exchanges = Vec::new();
        loop {
            let url = self.gateway.database.connect_url.clone();
            let waiting=tokio::task::spawn_blocking(move || -> Result<Value> {
                let mut db=postgres::Client::connect(&url,postgres::NoTls)?;
                let rows:Vec<Value>=db.query("SELECT jsonb_build_object('holder_pid',$1::int,'blocked_pid',a.pid,'wait_event_type',a.wait_event_type,'query',a.query) FROM pg_stat_activity a WHERE a.datname=current_database() AND $1=ANY(pg_blocking_pids(a.pid)) AND a.wait_event_type='Lock' AND a.query ILIKE '%floria_push_registration_handoffs%'",&[&pid])?.into_iter().map(|row|row.get(0)).collect();
                Ok(json!(rows))
            }).await??;
            if blocked.is_none() && waiting.as_array().is_some_and(|rows| !rows.is_empty()) {
                let state = cut(
                    source,
                    &self.gateway,
                    self.registered.registration_id.as_str(),
                )
                .await?;
                ensure!(
                    state["completions"] == json!([]),
                    "Completed was signed while the active Gateway revoke was blocked"
                );
                blocked = Some(json!({"pg_blocking_pids":waiting,"cut":state}));
            }
            exchanges.extend(push::record_forwarded(&self.gateway, &mut self.cursor)?);
            let failure = exchanges
                .iter()
                .find(|row| row["status"] == 503 && row["request"]["state"] == "revoked")
                .cloned();
            if let Some(failure) = failure {
                let request: PushRegistrationHandoffRequestBody =
                    serde_json::from_value(failure["request"].clone())?;
                ensure!(
                    request.registration_id() == self.active.registration_id()
                        && request.push_target_id() == self.active.push_target_id()
                        && request.device_id() == self.active.device_id(),
                    "erasure worker substituted its revoke tuple"
                );
                let problem: arkret_wire::Problem =
                    serde_json::from_value(failure["response"].clone())?;
                ensure!(
                    problem.code() == "service_unavailable",
                    "actual Gateway DB failure lost its typed error"
                );
                let state = cut(
                    source,
                    &self.gateway,
                    self.registered.registration_id.as_str(),
                )
                .await?;
                ensure!(
                    blocked.is_some()
                        && state["completions"] == json!([])
                        && state["intents"][0]["desired_state"] == "revoked"
                        && state["intents"][0]["status"] == "awaiting_receipt"
                        && state["intents"][0]["receipt"].is_null()
                        && state["gateway_registrations"][0]["state"] == "active",
                    "failed real revoke produced a completion, receipt or unobserved barrier"
                );
                self.evidence["blocked_revoke"] =
                    blocked.context("real Gateway row-lock wait not observed")?;
                self.evidence["unavailable_revoke"] = json!({"exchange":failure,"cut":state});
                self.evidence["failed_revoke_exchanges"] = json!(exchanges);
                self.hold
                    .take()
                    .context("Gateway hold disappeared")?
                    .release()
                    .await?;
                return Ok(());
            }
            ensure!(
                std::time::Instant::now() < deadline,
                "real Gateway revoke did not yield its row-lock wait and typed storage refusal: {exchanges:?}"
            );
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    }

    /// Call only after the normal Account worker has persisted its signed Completed.
    pub(super) async fn completed(
        mut self,
        source: &Deployment,
        package: &arkret_models_collaboration::governance::erasure::ErasureReceiptPackage,
    ) -> Result<Value> {
        ensure!(
            self.hold.is_none(),
            "completion was read before the Gateway barrier was released"
        );
        super::transport::verify_package(package, &self.gateway.source_resolution)?;
        let exchanges = push::record_forwarded(&self.gateway, &mut self.cursor)?;
        let after = cut(
            source,
            &self.gateway,
            self.registered.registration_id.as_str(),
        )
        .await?;
        let intent = after["intents"]
            .as_array()
            .context("retained source revoke intents")?
            .iter()
            .find(|row| row["registration_id"] == json!(self.registered.registration_id))
            .context("original revoke intent missing after Completed")?;
        let request = original_request(intent)?;
        ensure!(
            request.state() == PushRegistrationHandoffState::Revoked
                && request.registration_id() == self.active.registration_id()
                && request.push_target_id() == self.active.push_target_id()
                && request.device_id() == self.active.device_id(),
            "completed erasure has no exact original revoke request"
        );
        let receipt: PushRegistrationHandoffResponseBody =
            serde_json::from_value(json!({"receipt":intent["receipt"]}))?;
        push::receipt(&self.gateway, &source.station, &request, &receipt)?;
        ensure!(
            intent["desired_state"] == "revoked"
                && intent["status"] == "receipt_verified"
                && intent["destination_gateway_id"] == json!(self.gateway.identity.service_id),
            "Completed did not retain the Station's verified Gateway receipt"
        );
        ensure!(
            exchanges.iter().any(|row| row["status"] == 200
                && row["request"] == json!(request)
                && row["response"] == json!(receipt)),
            "no real worker exchange returned the durable original revoke receipt"
        );
        let gateway = &after["gateway_registrations"][0];
        let stored: arkret_models_integration::PushRegistrationInstallationReceipt =
            serde_json::from_str(
                gateway["receipt_json"]
                    .as_str()
                    .context("Gateway original receipt")?,
            )?;
        ensure!(
            stored == receipt.receipt
                && gateway["state"] == "revoked"
                && gateway["has_route_ciphertext"] == false
                && after["push_devices"] == json!([])
                && after["intents"]
                    .as_array()
                    .context("source intents")?
                    .iter()
                    .all(|row| row["desired_state"] == "revoked"
                        && row["status"] == "receipt_verified"),
            "Gateway route or active/unverified handoff survived Completed"
        );
        ensure!(
            after["completions"]
                .as_array()
                .is_some_and(|rows| rows.len() == 1)
                && after["completions"][0]["package"] == json!(package),
            "signed package differs from the exact durable completion"
        );
        // This is supplementary timestamp evidence. The real blocked/failing
        // revoke and source transaction barrier above establish the causal cut.
        ensure!(
            receipt.receipt.stored_at <= package.receipt.completed_at,
            "completion timestamp predates the actual Gateway revoke receipt"
        );
        let stopped = push::client(&source.station, &self.gateway)?
            .push_notify(
                &self.notify,
                &format!("native-erasure-stopped-{}", uuid::Uuid::new_v4()),
                source.station.service_id(),
                &self.gateway.identity.service_id,
            )
            .await?;
        let stopped_exchange = push::record_forwarded(&self.gateway, &mut self.cursor)?;
        ensure!(
            stopped.outcomes
                == vec![
                    arkret_models_integration::PushGatewaySubmissionOutcome::rejected(
                        self.active.device_id().clone(),
                        arkret_models_integration::PushNotifyReasonCode::PushTargetUnknown,
                        None
                    )
                ]
                && self.gateway.observations()?["provider"]["provider_received"]
                    == self.evidence["provider_before"],
            "erased target was dispatched to the real provider"
        );
        self.evidence["revoke_exchanges"] = json!(exchanges);
        self.evidence["revoke_request"] = json!(request);
        self.evidence["revoke_receipt"] = json!(receipt);
        self.evidence["after"] = after;
        self.evidence["stopped_notify"] = json!(stopped);
        self.evidence["stopped_notify_exchange"] = json!(stopped_exchange);
        self.evidence["source_station"] = json!(source.station.service_id());
        self.evidence["gateway"] = self.gateway.observations()?;
        Ok(self.evidence.take())
    }
}

pub(super) fn verify_transports(
    evidence: &Value,
    observations: &NativeOperationObservations,
) -> Result<()> {
    validate_exchange_schemas(observations, &SCOPE)?;
    push::verify_gateway_transports(evidence, observations)
}
