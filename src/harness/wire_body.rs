use anyhow::{Result, anyhow};
use serde::{Serialize, Serializer};
use serde_json::Value;

/// Raw body for a named wire-negative case. Construction starts from a
/// serializable SDK value and applies one deliberate mutation.
pub struct WireNegativeBody(Value);

impl Serialize for WireNegativeBody {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

pub fn wire_negative_from_sdk<T: Serialize>(
    baseline: &T,
    mutate: impl FnOnce(&mut Value),
) -> Result<WireNegativeBody> {
    let mut value = serde_json::to_value(baseline)
        .map_err(|error| anyhow!("wire-negative baseline encode failed: {error}"))?;
    mutate(&mut value);
    Ok(WireNegativeBody(value))
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
