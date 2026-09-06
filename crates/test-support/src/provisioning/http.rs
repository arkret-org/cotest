//! Small JSON helpers shared by the provisioning steps.
//!
//! These exist so a failing step names the service and the operation rather
//! than surfacing a bare serde error. Anything richer — retries, DPoP, request
//! ids — belongs in the SDK client, not here; this module only covers Coauth's
//! private product API, which the SDK deliberately does not model.

use anyhow::{Context, Result, bail};
use serde_json::{Map, Value};

pub async fn post_json(http: &reqwest::Client, url: &str, body: &Value) -> Result<Value> {
    let response = http
        .post(url)
        .json(body)
        .send()
        .await
        .with_context(|| format!("POST {url}"))?;
    read_json(response, url).await
}

/// GET a canonical Arkret endpoint.
///
/// `Arkret-Operation` is required, not decorative: a canonical request without
/// it is refused with `operation_selector_required`, which is how the first
/// live run of this module failed. The caller passes the registered operation
/// id rather than this module guessing one from the path.
pub async fn get_arkret_json(
    http: &reqwest::Client,
    url: &str,
    operation_id: &str,
) -> Result<Value> {
    let response = http
        .get(url)
        .header("Arkret-Operation", operation_id)
        .send()
        .await
        .with_context(|| format!("GET {url}"))?;
    read_json(response, url).await
}

async fn read_json(response: reqwest::Response, url: &str) -> Result<Value> {
    let status = response.status();
    let body = response
        .text()
        .await
        .with_context(|| format!("read body of {url}"))?;
    if !status.is_success() {
        bail!("{url} returned {status}: {body}");
    }
    serde_json::from_str(&body).with_context(|| format!("parse JSON body of {url}: {body}"))
}

pub fn json_object<'a>(value: &'a Value, what: &str) -> Result<&'a Map<String, Value>> {
    value
        .as_object()
        .with_context(|| format!("{what} did not return a JSON object: {value}"))
}
