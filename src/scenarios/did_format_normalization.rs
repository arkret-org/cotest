//! P4-E — DID format normalization.
//!
//! Spec head 37ce729 (B-D) freezes the canonical DID form as
//! `^did:[a-z0-9]+:[^\s]+$`. The SDK's `Did` validator implements this
//! regex; every service (soland / coauth / teabay / starid) MUST reject
//! any string outside that shape on the ingest path.
//!
//! This scenario is SDK-pure: it walks the validator with a curated
//! set of legal + illegal DIDs and asserts the per-service implementation
//! agrees with the SDK validator on every input.

use anyhow::{Result, anyhow};
use cokret_core::Did;

const LEGAL: &[&str] = &[
    "did:web:alice.example",
    "did:web:alice.example.com",
    "did:web:server.example.com:realms:alice",
    "did:key:z6MkfFhxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "did:plc:abc123def456",
    "did:webvh:dns.example.com:alice",
];

const ILLEGAL: &[&str] = &[
    // No prefix.
    "alice.example",
    // Wrong scheme.
    "https:web:alice.example",
    // Empty method.
    "did::alice",
    // Uppercase method (per `[a-z0-9]+`).
    "did:Web:alice.example",
    // Whitespace in method-specific id.
    "did:web:alice example",
    // Trailing newline.
    "did:web:alice.example\n",
    // Empty method-specific id.
    "did:web:",
    // Just the scheme.
    "did:",
    "",
];

pub async fn did_format_normalization_run() -> Result<()> {
    for legal in LEGAL {
        Did::new((*legal).to_owned())
            .map_err(|e| anyhow!("legal DID `{legal}` rejected by SDK validator: {e}"))?;
    }
    for illegal in ILLEGAL {
        let did = Did::new((*illegal).to_owned());
        if did.is_ok() {
            return Err(anyhow!(
                "illegal DID `{illegal}` was accepted — fail-closed missing"
            ));
        }
    }
    // TODO(P4-impl): drive each illegal DID against soland/coauth/teabay/
    // starid `POST` endpoints that accept a DID; assert every one
    // returns 4xx with `schema_violation` (or service-specific
    // structured equivalent).
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn did_validator_baseline() {
        did_format_normalization_run().await.unwrap();
    }
}
