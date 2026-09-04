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
