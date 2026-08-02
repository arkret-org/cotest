use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::future::Future;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::Utc;
use reqwest::header::{HeaderMap, HeaderValue};
use reqwest::{Request, RequestBuilder, StatusCode};
use serde_json::{Value, json};
use url::Url;

const ACCOUNT_SUBSCRIBE_FRAME_DEADLINE: Duration = Duration::from_secs(40);
const HTTP_REQUEST_DEADLINE: Duration = Duration::from_secs(45);

pub struct RecordedResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
    context: String,
}

impl RecordedResponse {
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    pub fn json(&self) -> Result<Value> {
        serde_json::from_slice(&self.body)
            .with_context(|| format!("invalid JSON body:\n{}", self.context))
    }

    pub fn context(&self) -> &str {
        &self.context
    }
}

pub async fn expect_account_subscribe_delta(
    builder: reqwest::RequestBuilder,
    status: StatusCode,
) -> Result<Value> {
    expect_account_subscribe_delta_matching(builder, status, |_| true).await
}

pub async fn expect_account_subscribe_realm_delta(
    builder: reqwest::RequestBuilder,
    status: StatusCode,
) -> Result<Value> {
    expect_account_subscribe_delta_matching(builder, status, |delta| {
        delta
            .get("realms")
            .and_then(Value::as_object)
            .is_some_and(|realms| !realms.is_empty())
    })
    .await
}

async fn expect_account_subscribe_delta_matching(
    builder: reqwest::RequestBuilder,
    status: StatusCode,
    matches: impl Fn(&Value) -> bool,
) -> Result<Value> {
    let mut response = builder
        .header("accept", "application/x-ndjson")
        .send()
        .await
        .context("send account subscribe request")?;
    if response.status() != status {
        let actual = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(anyhow!("expected HTTP {status}, got {actual}:\n{body}"));
    }

    tokio::time::timeout(ACCOUNT_SUBSCRIBE_FRAME_DEADLINE, async move {
        let mut pending = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .context("read account subscribe frame")?
        {
            pending.extend_from_slice(&chunk);
            while let Some(newline) = pending.iter().position(|byte| *byte == b'\n') {
                let line = pending.drain(..=newline).collect::<Vec<_>>();
                let line = std::str::from_utf8(&line)
                    .context("account subscribe frame is not UTF-8")?
                    .trim();
                if line.is_empty() {
                    continue;
                }
                let frame: Value = serde_json::from_str(line)
                    .with_context(|| format!("invalid subscribe frame: {line}"))?;
                if frame.get("kind").and_then(Value::as_str) == Some("delta") {
                    let delta = frame.get("payload").cloned().unwrap_or(frame);
                    if matches(&delta) {
                        return Ok(delta);
                    }
                }
            }
        }
        Err(anyhow!(
            "account subscribe response ended without a delta frame"
        ))
    })
    .await
    .context("timed out waiting for account subscribe delta")?
}

pub fn account_subscribe_delta_from_text(ndjson: &str) -> Result<Value> {
    for line in ndjson
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
    {
        let frame: Value = serde_json::from_str(line)
            .with_context(|| format!("invalid subscribe frame: {line}"))?;
        if frame.get("kind").and_then(Value::as_str) == Some("delta") {
            return Ok(frame.get("payload").cloned().unwrap_or(frame));
        }
    }
    Err(anyhow!(
        "account subscribe response did not include a delta frame"
    ))
}

pub async fn expect_json(builder: reqwest::RequestBuilder, status: StatusCode) -> Result<Value> {
    expect_response(builder, status).await?.json()
}

pub async fn expect_status(builder: reqwest::RequestBuilder, status: StatusCode) -> Result<()> {
    let _ = expect_response(builder, status).await?;
    Ok(())
}

pub async fn expect_api_error(
    builder: reqwest::RequestBuilder,
    status: StatusCode,
    errcode: &str,
) -> Result<Value> {
    let response = expect_response(builder, status).await?;
    let body = response.json()?;
    let actual_errcode = body["error"]["errcode"]
        .as_str()
        .or_else(|| body["error"]["code"].as_str());
    if body["ok"] != false || actual_errcode != Some(errcode) {
        return Err(anyhow!(
            "expected error {errcode} at HTTP {status}, got body {body}:\n{}",
            response.context()
        ));
    }
    Ok(body)
}

pub async fn expect_response(
    builder: reqwest::RequestBuilder,
    status: StatusCode,
) -> Result<RecordedResponse> {
    let response = send_recorded(builder).await?;
    if response.status != status {
        return Err(anyhow!(
            "expected HTTP {status}, got {}:\n{}",
            response.status,
            response.context()
        ));
    }
    Ok(response)
}

pub async fn expect_text(builder: reqwest::RequestBuilder, status: StatusCode) -> Result<String> {
    Ok(expect_response(builder, status).await?.text())
}

pub async fn expect_indistinguishable_api_errors(
    hidden: reqwest::RequestBuilder,
    missing: reqwest::RequestBuilder,
    status: StatusCode,
    errcode: &str,
) -> Result<Value> {
    let hidden_body = normalize_transient_fields(expect_api_error(hidden, status, errcode).await?);
    let missing_body =
        normalize_transient_fields(expect_api_error(missing, status, errcode).await?);
    if hidden_body != missing_body {
        return Err(anyhow!(
            "expected indistinguishable {errcode} errors, got hidden={hidden_body} missing={missing_body}"
        ));
    }
    Ok(hidden_body)
}

pub fn expect_audit_action<'a>(audit: &'a Value, action: &str) -> Result<&'a Value> {
    audit["events"]
        .as_array()
        .and_then(|events| events.iter().find(|event| event["action"] == action))
        .ok_or_else(|| anyhow!("missing audit action {action} in body {audit}"))
}

pub async fn eventually<F, Fut, T>(
    label: &str,
    timeout: Duration,
    interval: Duration,
    mut operation: F,
) -> Result<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T>>,
{
    let started = Instant::now();
    let mut last_error = None;
    loop {
        match operation().await {
            Ok(value) => return Ok(value),
            Err(error) => {
                if started.elapsed() >= timeout {
                    let message = last_error.unwrap_or_else(|| error.to_string());
                    return Err(anyhow!("timed out waiting for {label}: {message}"));
                }
                last_error = Some(error.to_string());
                tokio::time::sleep(interval).await;
            }
        }
    }
}

fn transcript_path() -> Option<PathBuf> {
    std::env::var_os("COTEST_TRANSCRIPT_PATH")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("COTEST_ARTIFACT_DIR")
                .map(PathBuf::from)
                .map(|path| path.join("transcript.ndjson"))
        })
}

fn append_transcript_entry(entry: &Value) -> Result<()> {
    let Some(path) = transcript_path() else {
        return Ok(());
    };
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    use std::io::Write as _;
    writeln!(file, "{}", serde_json::to_string(entry)?)?;
    Ok(())
}

async fn send_recorded(builder: RequestBuilder) -> Result<RecordedResponse> {
    let request = snapshot_request_builder(&builder);
    let started = Instant::now();
    let response = match builder.timeout(HTTP_REQUEST_DEADLINE).send().await {
        Ok(response) => response,
        Err(error) => {
            let error_snapshot = json!({
                "transport_error": truncate_string(&error.to_string(), 512),
            });
            let _ = append_transcript_entry(&json!({
                "timestamp": arkret_canonical::format_timestamp_canonical(Utc::now()),
                "duration_ms": started.elapsed().as_millis(),
                "request": request,
                "error": error_snapshot,
            }));
            return Err(anyhow!(
                "HTTP request failed:\n{}",
                format_exchange_context(&request, &error_snapshot)
            ));
        }
    };

    let status = response.status();
    let headers = response.headers().clone();
    let body = response.bytes().await?.to_vec();
    let response_snapshot = snapshot_response(status, &headers, &body);
    let context = format_exchange_context(&request, &response_snapshot);
    let _ = append_transcript_entry(&json!({
        "timestamp": arkret_canonical::format_timestamp_canonical(Utc::now()),
        "duration_ms": started.elapsed().as_millis(),
        "request": request,
        "response": response_snapshot,
    }));
    Ok(RecordedResponse {
        status,
        headers,
        body,
        context,
    })
}

fn snapshot_request_builder(builder: &RequestBuilder) -> Value {
    let Some(clone) = builder.try_clone() else {
        return json!({
            "unavailable": "request builder could not be cloned for transcript capture"
        });
    };
    match clone.build() {
        Ok(request) => snapshot_request(&request),
        Err(error) => json!({
            "error": truncate_string(&error.to_string(), 256),
        }),
    }
}

fn snapshot_request(request: &Request) -> Value {
    json!({
        "method": request.method().as_str(),
        "url": sanitize_url(request.url()),
        "headers": sanitize_headers(request.headers()),
        "body": request
            .body()
            .and_then(|body| body.as_bytes())
            .map(sanitize_body_bytes)
            .unwrap_or_else(|| json!("[unavailable]")),
    })
}

fn snapshot_response(status: StatusCode, headers: &HeaderMap, body: &[u8]) -> Value {
    json!({
        "status": status.as_u16(),
        "headers": sanitize_headers(headers),
        "body": sanitize_body_bytes(body),
    })
}

fn sanitize_url(url: &Url) -> String {
    let mut sanitized = url.clone();
    let query_pairs: Vec<_> = sanitized
        .query_pairs()
        .map(|(key, value)| {
            let value = if is_secret_field(key.as_ref()) {
                "[redacted]".to_owned()
            } else {
                truncate_string(value.as_ref(), 128)
            };
            (key.into_owned(), value)
        })
        .collect();
    sanitized
        .query_pairs_mut()
        .clear()
        .extend_pairs(query_pairs);
    sanitized.to_string()
}

fn sanitize_headers(headers: &HeaderMap) -> Value {
    let mut sanitized = BTreeMap::new();
    for (name, value) in headers {
        let key = name.as_str().to_owned();
        let rendered = if is_secret_field(name.as_str()) {
            "[redacted]".to_owned()
        } else {
            truncate_string(&header_value_to_string(value), 256)
        };
        sanitized.insert(key, rendered);
    }
    serde_json::to_value(sanitized).unwrap_or_else(|_| json!({}))
}

fn header_value_to_string(value: &HeaderValue) -> String {
    value
        .to_str()
        .map(ToOwned::to_owned)
        .unwrap_or_else(|_| format!("base64url:{}", URL_SAFE_NO_PAD.encode(value.as_bytes())))
}

fn sanitize_body_bytes(bytes: &[u8]) -> Value {
    if bytes.is_empty() {
        return Value::Null;
    }
    if let Ok(text) = std::str::from_utf8(bytes) {
        if let Ok(value) = serde_json::from_str::<Value>(text) {
            return sanitize_json_value(value);
        }
        return Value::String(truncate_string(text, 512));
    }
    json!({
        "encoding": "base64url",
        "size": bytes.len(),
        "preview": truncate_string(&URL_SAFE_NO_PAD.encode(bytes), 512),
    })
}

fn sanitize_json_value(value: Value) -> Value {
    match value {
        Value::Object(object) => Value::Object(
            object
                .into_iter()
                .map(|(key, value)| {
                    let value = if is_secret_field(&key) {
                        Value::String("[redacted]".to_owned())
                    } else {
                        sanitize_json_value(value)
                    };
                    (key, value)
                })
                .collect(),
        ),
        Value::Array(values) => Value::Array(values.into_iter().map(sanitize_json_value).collect()),
        Value::String(text) => Value::String(truncate_string(&text, 256)),
        other => other,
    }
}

fn is_secret_field(name: &str) -> bool {
    let normalized = name.trim().to_ascii_lowercase();
    matches!(
        normalized.as_str(),
        "authorization"
            | "cookie"
            | "set-cookie"
            | "access_token"
            | "token"
            | "auth"
            | "password"
            | "secret"
            | "secret_b64u"
            | "session_credential"
            | "credential"
            | "push_key"
            | "invite_token"
            | "signed_link"
            | "jws"
            | "sig"
            | "private_key"
            | "seed"
            | "mnemonic"
            | "recovery_key"
            | "recovery_phrase"
            | "recovery_secret"
            | "root_seed"
            | "root_private_key"
            | "hkdf_prk"
            | "prk"
    )
}

fn truncate_string(value: &str, max_chars: usize) -> String {
    let mut chars = value.chars();
    let truncated: String = chars.by_ref().take(max_chars).collect();
    if chars.next().is_some() {
        format!("{truncated}...[truncated]")
    } else {
        truncated
    }
}

fn format_exchange_context(request: &Value, response: &Value) -> String {
    format!(
        "request:\n{}\nresponse:\n{}",
        serde_json::to_string_pretty(request).unwrap_or_else(|_| request.to_string()),
        serde_json::to_string_pretty(response).unwrap_or_else(|_| response.to_string())
    )
}

fn normalize_transient_fields(value: Value) -> Value {
    match value {
        Value::Object(object) => Value::Object(
            object
                .into_iter()
                .filter(|(key, _)| key != "request_id")
                .map(|(key, value)| (key, normalize_transient_fields(value)))
                .collect(),
        ),
        Value::Array(values) => {
            Value::Array(values.into_iter().map(normalize_transient_fields).collect())
        }
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{is_secret_field, sanitize_json_value};

    #[test]
    fn transcript_sanitizer_redacts_credential_material() {
        for field in [
            "credential",
            "secret_b64u",
            "private_key",
            "recovery_key",
            "root_seed",
            "hkdf_prk",
        ] {
            assert!(is_secret_field(field), "{field} must be treated as secret");
        }

        let sanitized = sanitize_json_value(json!({
            "ice": {
                "credential": "turn-password",
                "username": "public-routing-user"
            },
            "recovery_key": "word list"
        }));
        assert_eq!(sanitized["ice"]["credential"], "[redacted]");
        assert_eq!(sanitized["ice"]["username"], "public-routing-user");
        assert_eq!(sanitized["recovery_key"], "[redacted]");
    }
}
