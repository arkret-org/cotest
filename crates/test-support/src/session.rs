//! How a test client holds its credentials.
//!
//! The harness has two ways to be a principal and they are not interchangeable
//! at the wire. A development session is a bearer the Station accepts because
//! test builds are configured to; a canonical session is an `ak.session.grant`
//! that is only valid together with a DPoP proof over the exact method and URL
//! of each request, signed by the device key the grant was issued to.
//!
//! Modelling that as one `String` is what made `bearer_auth(&client.token)`
//! spread through the scenarios. It works for every client the harness could
//! build until now, and would fail with a bare 401 the moment one of them came
//! from the canonical chain. [`ClientSession`] makes the difference something
//! the request path handles rather than something each caller has to remember.
//!
//! It lives on the light build edge rather than beside
//! `cotest::harness::TestActorClient`, which re-exports it. Presenting a
//! credential needs Garth and the SDK and nothing else, so keeping it here
//! means it can be exercised against a live Station without building the
//! server harness — and a proof minted over the wrong method or URL, its one
//! real risk, only shows against a live Station.

use std::sync::Arc;

use anyhow::{Context, Result};
use arkret_http_client::DpopProofRequest;
use ed25519_dalek::SigningKey;
use reqwest::RequestBuilder;

/// The credential a client presents, and what presenting it requires.
#[derive(Clone)]
pub enum ClientSession {
    /// A bearer from `/_coland/gate/auth/dev-login`.
    ///
    /// Development seam: no account authorization, no grant issuance, no key
    /// binding. See `harness::dev_login`.
    DevBearer(String),
    /// An `ak.session.grant` and the device key it is bound to.
    ///
    /// Every request carries `Authorization: DPoP <grant>` plus a proof over
    /// that request's own method and URL, bound to the grant through `ath`.
    /// Both halves are required; the Station refuses either alone.
    Canonical {
        grant: String,
        signing_key: Arc<SigningKey>,
    },
}

impl std::fmt::Debug for ClientSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DevBearer(_) => f.debug_tuple("DevBearer").field(&"<redacted>").finish(),
            Self::Canonical { .. } => f
                .debug_struct("Canonical")
                .field("grant", &"<redacted>")
                .finish_non_exhaustive(),
        }
    }
}

impl ClientSession {
    /// The bearer, when this session has one.
    ///
    /// `None` for a canonical session: its grant is not a bearer, and handing
    /// it to `bearer_auth` produces a request the Station will refuse. Callers
    /// that build their own requests should use [`Self::authorize`] instead of
    /// reaching for this.
    pub fn dev_bearer(&self) -> Option<&str> {
        match self {
            Self::DevBearer(token) => Some(token),
            Self::Canonical { .. } => None,
        }
    }

    /// The credential string, whichever kind it is.
    ///
    /// For a canonical session this is the grant — useful for introspection
    /// assertions, never as a bearer.
    pub fn credential(&self) -> &str {
        match self {
            Self::DevBearer(token) => token,
            Self::Canonical { grant, .. } => grant,
        }
    }

    /// Attach this session's credentials to a request.
    ///
    /// The method and URL come from the builder itself rather than from
    /// parameters, because a DPoP proof is bound to them and a proof minted
    /// over a different URL than the one sent is the failure this is meant to
    /// make impossible.
    pub fn authorize(&self, builder: RequestBuilder) -> Result<RequestBuilder> {
        match self {
            Self::DevBearer(token) => Ok(builder.bearer_auth(token)),
            Self::Canonical { grant, signing_key } => {
                let probe = builder
                    .try_clone()
                    .context(
                        "a streaming request body cannot be authorized with DPoP: the proof binds \
                         to the request's method and URL, which requires reading them back",
                    )?
                    .build()
                    .context("build the request to read back its method and URL")?;
                let proof = arkret_garth_dpop(
                    DpopProofRequest::new(probe.method().as_str(), probe.url().as_str())
                        .access_token(grant.clone()),
                    signing_key,
                )?;
                Ok(builder
                    .header("Authorization", format!("DPoP {grant}"))
                    .header("DPoP", proof))
            }
        }
    }
}

/// Mint a DPoP proof through Garth, the same builder the product client uses.
///
/// Named rather than inlined so the one place the harness signs a DPoP proof is
/// greppable: a second implementation here is how the harness would start
/// asserting against itself instead of against the client under test.
fn arkret_garth_dpop(request: DpopProofRequest, signing_key: &SigningKey) -> Result<String> {
    garth::session::dpop::build_http_dpop_proof(request, signing_key)
        .map_err(|error| anyhow::anyhow!("build DPoP proof: {error}"))
}
