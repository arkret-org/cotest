//! The named wire-negative body itself lives in `arkret_test_kit::negative`:
//! it is protocol-generic and every implementation needs it, whereas the
//! canonical-JSON request extension below is bound to `reqwest`.

use anyhow::{Result, anyhow};
use serde::{Serialize, Serializer};
use serde_json::Value;

/// Sends a request body the way a real Arkret client does: as RFC 8785
/// canonical JSON bytes.
///
/// `reqwest`'s own `.json()` serialises struct fields in declaration order,
/// which is almost never lexicographic, so a server that admits non-streaming
/// JSON operation bodies through the SDK ingress budget rejects it with
/// `schema_violation`. The SDK's HTTP client canonicalises for exactly this
/// reason (`arkret-http-client` `canonical_json_body`); the harness has to do
/// the same wherever it hand-builds a request instead of going through the SDK.
///
/// Deliberately non-canonical bytes are a different intent — a wire-negative
/// case — and those call sites must keep using `.json()` or `.body()` so the
/// mutation survives to the server.
pub trait CanonicalJsonBody: Sized {
    fn canonical_json<T: Serialize + ?Sized>(self, body: &T) -> Result<Self>;
}

impl CanonicalJsonBody for reqwest::RequestBuilder {
    fn canonical_json<T: Serialize + ?Sized>(self, body: &T) -> Result<Self> {
        let bytes = arkret_canonical::canonical::canonical_json_bytes(body)
            .map_err(|error| anyhow!("request body is not canonicalisable: {error}"))?;
        Ok(self
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(bytes))
    }
}

/// Explicit isolation for non-protocol test infrastructure and probes of
/// removed endpoints. This type must not be used for an active Arkret surface.
pub struct NonProtocolTestBody(Value);

impl NonProtocolTestBody {
    pub fn new(value: Value) -> Self {
        Self(value)
    }
}

impl Serialize for NonProtocolTestBody {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

/// Forward all signed headers and exact body bytes using the real Station's TLS client.
/// Once the Station accepts the request, close the caller's socket before sending a receipt.
pub(crate) async fn withhold_station_receipt(builder: reqwest::RequestBuilder) -> Result<Vec<u8>> {
    use std::time::Duration;

    use anyhow::{Context as _, bail, ensure};
    use reqwest::StatusCode;
    use reqwest::header::{CONTENT_LENGTH, HOST, HeaderMap, HeaderName, HeaderValue};
    use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, BufReader};
    let (upstream, request) = builder.build_split();
    let request = request?;
    let target = request.url().clone();
    ensure!(
        matches!(target.host_str(), Some("127.0.0.1" | "localhost" | "[::1]"))
            && target.query().is_none()
    );
    let method = request.method().clone();
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?;
    let local = format!("http://{}{}", listener.local_addr()?, target.path());
    let downstream = reqwest::Client::builder()
        .no_proxy()
        .build()?
        .request(method.clone(), local)
        .headers(request.headers().clone())
        .body(
            request
                .body()
                .and_then(reqwest::Body::as_bytes)
                .context("signed JSON")?
                .to_vec(),
        );
    let relay = async move {
        let (stream, _) = listener.accept().await?;
        let mut incoming = BufReader::new(stream);
        let mut line = String::new();
        incoming.read_line(&mut line).await?;
        ensure!(line.trim_end() == format!("{method} {} HTTP/1.1", target.path()));
        let mut headers = HeaderMap::new();
        loop {
            line.clear();
            ensure!(incoming.read_line(&mut line).await? > 0 && line.len() <= 65536);
            if line == "\r\n" {
                break;
            }
            let (name, value) = line.split_once(':').context("HTTP field")?;
            headers.append(
                HeaderName::from_bytes(name.as_bytes())?,
                HeaderValue::from_str(value.trim())?,
            );
        }
        let length = headers
            .get(CONTENT_LENGTH)
            .context("signed content length")?
            .to_str()?
            .parse::<usize>()?;
        ensure!((1..2 * 1024 * 1024).contains(&length));
        headers.remove(HOST);
        let mut bytes = vec![0; length];
        incoming.read_exact(&mut bytes).await?;
        let response = upstream
            .request(method, target)
            .headers(headers)
            .body(bytes)
            .send()
            .await?;
        let status = response.status();
        if status != StatusCode::OK {
            let problem: arkret_wire::Problem = response.json().await?;
            bail!("Station declined fault-injection request: {status} {problem:?}");
        }
        // No response bytes are written to the downstream socket.
        let receipt = response.bytes().await?.to_vec();
        drop(incoming);
        anyhow::Ok(receipt)
    };
    let (forwarded, received) = tokio::time::timeout(Duration::from_secs(40), async {
        tokio::join!(relay, downstream.send())
    })
    .await?;
    let receipt = forwarded?;
    ensure!(received.is_err(), "caller received an acknowledgement");
    Ok(receipt)
}
