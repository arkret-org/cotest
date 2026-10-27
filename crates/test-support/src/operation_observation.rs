//! Native HTTP observations are inputs to domain proofs, never coverage alone.
//!
//! No mock response generator or authority constructor lives here. A caller
//! must additionally prove the owning process, accepted originals and effects.
use std::collections::BTreeMap;
use std::future::Future;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedOperationExchange {
    pub operation_id: arkret_wire::ServiceOperationId,
    pub method: String,
    pub url: String,
    pub explicit_request_headers: BTreeMap<String, String>,
    pub request_body: Value,
    pub request_json_base64url: String,
    pub response_status: u16,
    pub response_body: Value,
    pub decoded_response_bytes_base64url: String,
    pub observed_at: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeOperationObservations {
    pub exchanges: Vec<ObservedOperationExchange>,
    pub accepted_identity_material: Vec<Value>,
    pub issuer_bindings: Vec<Value>,
}

tokio::task_local! {
    static OBSERVATIONS: Arc<Mutex<NativeOperationObservations>>;
}

pub async fn observe<F: Future>(future: F) -> (F::Output, NativeOperationObservations) {
    let records = Arc::new(Mutex::new(NativeOperationObservations::default()));
    let result = OBSERVATIONS.scope(records.clone(), future).await;
    let observations = records.lock().expect("observation lock").clone();
    (result, observations)
}

pub fn freeze_request(builder: &reqwest::RequestBuilder) -> Result<Option<reqwest::Request>> {
    if OBSERVATIONS.try_with(|_| ()).is_err() {
        return Ok(None);
    }
    // Multipart and streaming prerequisites are outside this buffered JSON
    // recorder. Missing originals never earn JSON contract coverage.
    builder
        .try_clone()
        .map(|request| request.build().map_err(Into::into))
        .transpose()
}

/// Record actual successful bytes; registered empty responses retain no entity body.
pub fn record_response(request: Option<&reqwest::Request>, status: u16, body: &[u8]) -> Result<()> {
    if !(200..300).contains(&status) {
        return Ok(());
    }
    let Some(request) = request else {
        return Ok(());
    };
    let Some(operation) = request.headers().get("arkret-operation") else {
        return Ok(());
    };
    record_json_exchange(
        operation.to_str()?,
        Some(request),
        status,
        std::str::from_utf8(body)?,
    )
}

/// Send a real request; the observation itself supplies no authority credit.
pub async fn send_json_exchange(
    operation_id: &str,
    request: reqwest::RequestBuilder,
) -> Result<Value> {
    let frozen = freeze_request(&request)?;
    let response = request
        .send()
        .await
        .context("send observed native request")?;
    let status = response.status();
    let text = response
        .text()
        .await
        .context("read observed native response")?;
    ensure!(
        status.is_success(),
        "native {operation_id} refused: {status}: {text}"
    );
    record_json_exchange(operation_id, frozen.as_ref(), status.as_u16(), &text)?;
    serde_json::from_str(&text).context("decode observed native JSON")
}

pub(crate) fn record_json_exchange(
    operation_id: &str,
    request: Option<&reqwest::Request>,
    response_status: u16,
    decoded_response_text: &str,
) -> Result<()> {
    let Ok(records) = OBSERVATIONS.try_with(Arc::clone) else {
        return Ok(());
    };
    let operation_id = arkret_wire::ServiceOperationId::from_wire(operation_id)
        .context("observed operation is not registered")?;
    let request = request.context("active observation requires the actual frozen request")?;
    let method = request.method().as_str();
    let url = request.url().as_str();
    ensure!(
        request.headers().get_all("arkret-operation").iter().count() == 1
            && request
                .headers()
                .get("arkret-operation")
                .context("request selector absent")?
                .to_str()?
                == operation_id.as_str(),
        "actual request did not select the exact operation once"
    );
    ensure!(
        (200..300).contains(&response_status),
        "a refusal is not a successful exchange"
    );
    let parsed_url = url::Url::parse(url)?;
    ensure!(
        operation_id.matches_http_request(method, parsed_url.path()),
        "observed request differs from its operation binding"
    );
    let response_body: Value = if operation_id.descriptor().success_shape_kind == "empty_response" {
        ensure!(
            decoded_response_text.is_empty(),
            "registered empty response carried an entity body"
        );
        Value::Null
    } else {
        let value: Value = serde_json::from_str(decoded_response_text)?;
        ensure!(value.is_object(), "JSON operation did not return an object");
        value
    };
    let request_bytes = match request.body() {
        Some(body) => body
            .as_bytes()
            .context("native request body is not buffered")?,
        None => &[],
    };
    let request_body: Value = if request_bytes.is_empty() {
        ensure!(method == "GET", "native JSON request bytes absent");
        Value::Null
    } else {
        serde_json::from_slice(request_bytes)?
    };
    let row = ObservedOperationExchange {
        operation_id,
        method: method.to_owned(),
        url: url.to_owned(),
        explicit_request_headers: request
            .headers()
            .iter()
            .map(|(name, value)| Ok((name.to_string(), value.to_str()?.to_owned())))
            .collect::<Result<_>>()?,
        request_body,
        request_json_base64url: arkret_canonical::base64url_encode(request_bytes),
        response_status,
        response_body,
        decoded_response_bytes_base64url: arkret_canonical::base64url_encode(
            decoded_response_text.as_bytes(),
        ),
        observed_at: arkret_canonical::format_timestamp_canonical(chrono::Utc::now()),
    };
    records
        .lock()
        .expect("observation lock")
        .exchanges
        .push(row);
    Ok(())
}

pub(crate) fn record_verified_identity_material(material: impl FnOnce() -> Value) {
    let _ = OBSERVATIONS.try_with(|records| {
        records
            .lock()
            .expect("observation lock")
            .accepted_identity_material
            .push(material());
    });
}

/// Retain a read-only issuer observation; this alone certifies no authority.
pub fn record_issuer_binding_observation(material: Value) {
    let _ = OBSERVATIONS.try_with(|records| {
        records
            .lock()
            .expect("observation lock")
            .issuer_bindings
            .push(material);
    });
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[tokio::test]
    async fn empty_response_is_closed_by_the_registered_shape_and_grants_no_authority() {
        let (_, observed) = observe(async {
            let request = reqwest::Client::new()
                .delete("https://station.example/_arkret/self/keys/backups/ak:backup:test")
                .header(
                    "arkret-operation",
                    "ak.self.keys.backups.resource.delete.v1",
                )
                .json(&json!({"transport_test":true}))
                .build()
                .unwrap();
            for invented in ["{}", "null", "{\"deleted\":true}"] {
                assert!(
                    record_json_exchange(
                        "ak.self.keys.backups.resource.delete.v1",
                        Some(&request),
                        200,
                        invented
                    )
                    .is_err()
                );
            }
            record_json_exchange(
                "ak.self.keys.backups.resource.delete.v1",
                Some(&request),
                200,
                "",
            )
            .unwrap();
            let typed = reqwest::Client::new()
                .get("https://issuer.example/_arkret/gate/account/onboarding")
                .header("arkret-operation", "ak.gate.account.read.onboarding.v1")
                .build()
                .unwrap();
            assert!(
                record_json_exchange("ak.gate.account.read.onboarding.v1", Some(&typed), 200, "")
                    .is_err()
            );
        })
        .await;
        assert_eq!(observed.exchanges.len(), 1);
        assert!(
            observed.exchanges[0].response_body.is_null()
                && observed.exchanges[0]
                    .decoded_response_bytes_base64url
                    .is_empty()
        );
        assert!(observed.accepted_identity_material.is_empty());
    }

    #[tokio::test]
    async fn streaming_prerequisites_are_not_blocked_or_credited_as_json() {
        let (_, rows) = observe(async {
            let request = reqwest::Client::new()
                .post("https://station.example/_arkret/self/blobs/upload")
                .body(reqwest::Body::wrap(reqwest::Body::from(
                    "actual streaming prerequisite",
                )));
            let frozen = freeze_request(&request).unwrap();
            assert!(frozen.is_none());
            record_response(frozen.as_ref(), 200, br#"{"stored":true}"#).unwrap();
            assert!(
                record_json_exchange("ak.self.keys.keypackages.command.claim.v1", None, 200, "{}")
                    .is_err()
            );
        })
        .await;
        assert!(rows.exchanges.is_empty());
    }

    #[tokio::test]
    async fn a_rejection_or_wrong_route_cannot_enter_success_observations() {
        let (_, rows) = observe(async {
            for (status, path) in [(401, "authentication-handoffs"), (200, "register")] {
                let request = reqwest::Client::new()
                    .post(format!(
                        "https://issuer.example/_arkret/gate/account/{path}"
                    ))
                    .header(
                        "arkret-operation",
                        "ak.gate.account.exchange.create_handoff.v1",
                    )
                    .json(&json!({}))
                    .build()
                    .unwrap();
                assert!(
                    record_json_exchange(
                        "ak.gate.account.exchange.create_handoff.v1",
                        Some(&request),
                        status,
                        "{}",
                    )
                    .is_err()
                );
            }
        })
        .await;
        assert!(rows.exchanges.is_empty());
        assert!(rows.accepted_identity_material.is_empty());
    }

    #[tokio::test]
    async fn a_bodyless_read_preserves_absence_without_fabricating_request_json() {
        let (_, observed) = observe(async {
            let request = reqwest::Client::new()
                .get("https://issuer.example/_arkret/gate/account/onboarding")
                .header("arkret-operation", "ak.gate.account.read.onboarding.v1")
                .build()
                .unwrap();
            record_json_exchange(
                "ak.gate.account.read.onboarding.v1",
                Some(&request),
                200,
                "{\"transport_observation_only\":true}",
            )
            .unwrap();
        })
        .await;
        assert_eq!(observed.exchanges.len(), 1);
        assert!(observed.exchanges[0].request_body.is_null());
        assert!(observed.exchanges[0].request_json_base64url.is_empty());
        assert!(observed.accepted_identity_material.is_empty());
    }

    #[tokio::test]
    async fn transport_observation_does_not_create_authority_evidence_or_leak_to_another_scope() {
        let (_, first) = observe(async {
            let request = reqwest::Client::new()
                .post("https://issuer.example/_arkret/gate/account/authentication-handoffs")
                .header(
                    "arkret-operation",
                    "ak.gate.account.exchange.create_handoff.v1",
                )
                .json(&json!({"test_input":true}))
                .build()
                .unwrap();
            record_json_exchange(
                "ak.gate.account.exchange.create_handoff.v1",
                Some(&request),
                200,
                "{\"test_response\":true}",
            )
            .unwrap();
        })
        .await;
        assert_eq!(first.exchanges.len(), 1);
        assert!(first.accepted_identity_material.is_empty());
        let (_, second) = observe(async {}).await;
        assert!(second.exchanges.is_empty() && second.accepted_identity_material.is_empty());
    }
}
