//! Canonical principal provisioning, in Rust.
//!
//! One implementation of the chain written down in
//! `cotest/docs/canonical-provisioning-operations.md`, so that a Rust scenario
//! and the TypeScript suite prepare identities the same way instead of two ways
//! that drift. Today only the pieces below are here; the remaining gate steps
//! land on top of them (see 1725's P2).
//!
//! Three boundaries this module holds:
//!
//! * **It starts nothing.** Postgres, Coauth, Soland and the TLS proxy are the runner's job. This
//!   module is handed endpoints, identities and trust material and connects to them. A provisioning
//!   library that could also boot a deployment would end up owning the deployment.
//! * **Coauth's private account API is separated** into `coauth_account`, not mixed with the
//!   standard gate operations. It is a product surface, not a protocol one.
//! * **Protocol material comes from [`crate::wire`]**, the same functions the TypeScript side
//!   reaches through `cotest-wire`. Nothing here rebuilds a DID operation, a PCR genesis unit or a
//!   register body.
//!
//! It also fails closed rather than degrading: a missing mock inbox, an absent
//! Station description, a handoff that comes back in the wrong state are all
//! errors. A provisioning helper that quietly produces a weaker identity is how
//! a test suite ends up asserting against a principal it did not really create.

pub mod coauth_account;
mod http;

use anyhow::{Context, Result};
pub use coauth_account::{MockEmailInbox, UnboundAccount};
use serde_json::Value;

/// Where the services under test are, and what the caller is allowed to assume
/// about them.
///
/// Constructed by the caller from the runner's topology; this module never
/// discovers or defaults an endpoint, because a defaulted endpoint is how a
/// test ends up silently provisioning against the wrong deployment.
#[derive(Clone, Debug)]
pub struct DeploymentEndpoints {
    pub coauth_base_url: String,
    pub soland_base_url: String,
    /// Present only when the deployment verifies registration email. Absent is
    /// legitimate; absent *while the deployment asks for verification* is an
    /// error, not a skip.
    pub mock_email: Option<MockEmailInbox>,
}

/// The Station facts a registration needs, read from the Station itself.
///
/// Step 2 of the chain. Read rather than configured on purpose: the audience a
/// grant binds to has to be the service id the Station actually publishes, and
/// a copy in a config file is a copy that can be wrong.
#[derive(Clone, Debug)]
pub struct StationFacts {
    pub trust_domain: String,
    pub service_id: String,
}

/// The registered operation id for `GET /_arkret/describe`.
///
/// Spelled out rather than derived from the spec registry the way the
/// TypeScript helper does. One constant for one call is not worth a registry
/// walk; if this module ever needs a second, it should read the registry
/// instead of growing a second constant.
const DESCRIBE_OPERATION_ID: &str = "ak.server.read.describe.v1";

pub async fn describe_station(
    http: &reqwest::Client,
    endpoints: &DeploymentEndpoints,
) -> Result<StationFacts> {
    let url = format!(
        "{}/_arkret/describe",
        endpoints.soland_base_url.trim_end_matches('/')
    );
    let described = http::get_arkret_json(http, &url, DESCRIBE_OPERATION_ID)
        .await
        .context("describe Station")?;
    let described = http::json_object(&described, "Station description")?;
    let trust_domain = described
        .get("trust_domain")
        .and_then(Value::as_str)
        .context("Station description omitted trust_domain")?
        .to_owned();
    let service_id = described
        .get("service_id")
        .and_then(Value::as_str)
        .context("Station description omitted service_id")?
        .to_owned();
    Ok(StationFacts {
        trust_domain,
        service_id,
    })
}

/// Register an account through Coauth's product API and authenticate it.
///
/// Steps 1, 1a, 1b and the login that step 3 needs. Stops there: the account
/// exists and can authenticate, but no principal has been authored. That
/// boundary is the point — the account product and the identity protocol are
/// different surfaces, and the caller should be able to see where one ends.
pub async fn provision_unbound_account(
    http: &reqwest::Client,
    endpoints: &DeploymentEndpoints,
    account: &UnboundAccount,
) -> Result<()> {
    coauth_account::register_unbound_account(
        http,
        &endpoints.coauth_base_url,
        account,
        endpoints.mock_email.as_ref(),
    )
    .await?;
    coauth_account::login(
        http,
        &endpoints.coauth_base_url,
        &account.handle,
        &account.password,
    )
    .await
}
