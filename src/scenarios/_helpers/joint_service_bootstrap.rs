//! CT-6 — joint service bootstrap (coland + coauth + flagon).
//!
//! Provides a single [`JointServiceStack`] entry point that:
//!   1. Spawns `coland` (via the existing [`ArkretServer::spawn_with_env`] machinery, which honours
//!      the pre-built sibling binary fast path).
//!   2. Optionally spawns `coauth` via [`coauth_bootstrap::spawn_coauth_with_db`] (docker-postgres
//!      + generated config). Wires coland -> coauth session-grant introspection via
//!      `COLAND_SESSION_GRANT_INTROSPECTION_URL`.
//!   3. Optionally spawns `flagon` via [`external_binary::FLAGON_SPEC`] — requires `DATABASE_URL`
//!      in the caller's env (see `FLAGON_SPEC.required_env_vars`).
//!
//! `try_bootstrap` is fail-soft: services that can't start (missing binary,
//! missing DATABASE_URL, docker unreachable) are returned as `None` slots so
//! callers can decide to skip vs. fail. `bootstrap_required` folds the same
//! checks into a hard error so `#[ignore]` tests opted in via `--ignored`
//! get a descriptive bail.
//!
//! Drop order is LIFO (flagon → coauth → coland), so each service gets a
//! chance to flush before its upstream goes away. Postgres for coauth is
//! reaped by `EphemeralPg::Drop` after the coauth handle drops.

use std::time::Duration;

use anyhow::{Context, Result, anyhow};

use crate::harness::{ArkretServer, reserve_port};
use crate::scenarios::_helpers::coauth_bootstrap::{
    JOINT_TRUST_DOMAIN, SpawnedCoauth, coauth_with_db_available, prepare_coauth_with_db_required,
};
use crate::scenarios::_helpers::external_binary::{
    COLAND_SPEC, FLAGON_SPEC, SpawnedExternalProcess, locate_external_binary, skip_reason,
    try_spawn,
};

/// Per-service env wiring used when spinning up the joint service stack.
/// All fields default to development-friendly values; callers can override
/// any of them before `try_bootstrap`.
#[derive(Clone)]
pub struct JointServiceConfig {
    /// Logical name passed to coland (used for the test DID + log directory).
    pub name: String,
    /// Bearer token expected by coland when calling coauth's
    /// `session-grants/introspect` endpoint. Must match the value coauth's
    /// generated config patched in.
    pub internal_authority_shared_secret: String,
    /// Bearer token coland presents when registering a did:webvh document
    /// against the embedded provider. Mirrors run-joint-e2e.ps1.
    pub embedded_webvh_registration_bearer: String,
    /// Optional durable Coland PostgreSQL store. Recovery restart tests set
    /// this so the coordinator process can be replaced without losing its
    /// transaction/session/receipt ledger.
    pub coland_database_url: Option<String>,
}

impl JointServiceConfig {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            internal_authority_shared_secret: "cotest-session-grant-introspection".to_owned(),
            embedded_webvh_registration_bearer: "cotest-webvh-registration".to_owned(),
            coland_database_url: std::env::var("COTEST_COLAND_DATABASE_URL").ok(),
        }
    }
}

/// Aggregated handle for the joint service stack. Each optional field is
/// `Some` only when the corresponding service was successfully spawned.
///
/// Drop order is enforced via field ordering. Rust drops fields from top to
/// bottom, so upstream dependants are declared before `coland`; coland is the
/// final process to be torn down.
pub struct JointServiceStack {
    /// flagon (directory) — `Some` if sibling binary + `DATABASE_URL` were
    /// available.
    pub flagon: Option<SpawnedExternalProcess>,
    /// coauth (auth/account) — `Some` if docker + sibling binary were
    /// available; `None` if the bootstrap couldn't bring it up.
    pub coauth: Option<SpawnedCoauth>,
    /// coland (Station) — always present (or the bootstrap returns
    /// `Err`). This is the "main" service the rest of the stack talks to.
    pub coland: ArkretServer,
}

impl JointServiceStack {
    /// Public REST base URL for coland (always present).
    pub fn coland_base_url(&self) -> String {
        self.coland.base_url().to_string()
    }

    /// Public REST base URL for coauth (when spawned).
    pub fn coauth_base_url(&self) -> Option<&str> {
        self.coauth.as_ref().map(SpawnedCoauth::base_url)
    }

    /// Public REST base URL for flagon (when spawned).
    pub fn flagon_base_url(&self) -> Option<&str> {
        self.flagon.as_ref().map(|p| p.base_url.as_str())
    }

    /// Run `/health` against every spawned service. Returns `Err` if any
    /// service is unreachable within the per-service timeout. Each service's
    /// own bootstrap already waited for `/health` once; this is the
    /// "post-stack" sanity check exercised by the smoke scenario.
    pub async fn assert_healthy(&self) -> Result<()> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(3))
            .build()
            .context("constructing reqwest client for joint service health check")?;

        // coland's base_url already ends in `/`; trim before re-joining.
        let coland_health = format!("{}/health", self.coland_base_url().trim_end_matches('/'));
        probe(&self.coland.http(), "coland", &coland_health).await?;

        if let Some(url) = self.coauth_base_url() {
            // coauth's `/health` lives on its internal listener, NOT the
            // public REST base. Use the dedicated `health_url()` accessor.
            let internal = self
                .coauth
                .as_ref()
                .expect("coauth handle present when base url is")
                .health_url();
            probe(&client, "coauth", &internal).await?;
            let _ = url; // public REST URL is exported via the accessor; nothing to probe here.
        }
        if let Some(url) = self.flagon_base_url() {
            probe(
                &client,
                "flagon",
                &format!("{}/health", url.trim_end_matches('/')),
            )
            .await?;
        }
        Ok(())
    }
}

async fn probe(client: &reqwest::Client, name: &str, url: &str) -> Result<()> {
    let resp = client
        .get(url)
        .send()
        .await
        .with_context(|| format!("{name} health probe at {url} failed"))?;
    if !resp.status().is_success() {
        return Err(anyhow!(
            "{name} health probe at {url} returned {}",
            resp.status()
        ));
    }
    Ok(())
}

/// Try to bring up every service; return whichever subset spawned
/// successfully. Coland is the only required participant — if coland fails to
/// spawn, the whole bootstrap returns `Err` (every other test in cotest
/// assumes a working coland).
pub async fn try_bootstrap(config: JointServiceConfig) -> Result<JointServiceStack> {
    let prepared_coauth =
        if coauth_with_db_available() && locate_external_binary(&COLAND_SPEC).is_some() {
            Some(prepare_coauth_with_db_required()?)
        } else {
            None
        };

    // 2. flagon — requires DATABASE_URL. Soft-skip otherwise.
    let flagon = match skip_reason(&FLAGON_SPEC) {
        Some(_) => None,
        None => try_spawn(&FLAGON_SPEC).await?,
    };

    // 3. Build the coland env from the resolved upstream URLs. Empty/absent keys are simply not
    //    exported (coland's config keeps the production-safe default when the env var is unset).
    let mut coland_env: Vec<(String, String)> = Vec::new();
    coland_env.push((
        "COLAND_TRUST_DOMAIN".to_owned(),
        JOINT_TRUST_DOMAIN.to_owned(),
    ));
    if let Some(database_url) = &config.coland_database_url {
        coland_env.push(("DATABASE_URL".to_owned(), database_url.clone()));
    }

    if let Some(coauth) = &prepared_coauth {
        let base = coauth.base_url();
        let base = base.trim_end_matches('/');
        coland_env.push((
            "COLAND_SESSION_GRANT_INTROSPECTION_URL".to_owned(),
            format!("{base}/_coauth/internal/session-grants/introspect"),
        ));
        coland_env.push((
            "COLAND_AUTH_SESSION_LOGOUT_URL".to_owned(),
            format!("{base}/_coauth/internal/auth-sessions/logout"),
        ));
        coland_env.push((
            "COLAND_INTERNAL_AUTHORITY_SHARED_SECRET".to_owned(),
            config.internal_authority_shared_secret.clone(),
        ));
        coland_env.push((
            "COLAND_ACCOUNT_AUTHORITY_TRUST_DOMAIN".to_owned(),
            crate::scenarios::_helpers::coauth_bootstrap::JOINT_TRUST_DOMAIN.to_owned(),
        ));
        coland_env.push((
            "COLAND_EMBEDDED_WEBVH_REGISTRATION_BEARER".to_owned(),
            config.embedded_webvh_registration_bearer.clone(),
        ));
        coland_env.push(("COLAND_ACCOUNT_AUTHORITY_URL".to_owned(), base.to_owned()));
    }
    // ArkretServer::spawn_with_env takes &[(&str, &str)] — borrow the owned
    // strings before passing.
    let env_borrowed: Vec<(&str, &str)> = coland_env
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    let coland = if let (Some(_), Some(coland_bin)) = (
        prepared_coauth.as_ref(),
        locate_external_binary(&COLAND_SPEC),
    ) {
        let port = reserve_port().context("reserve joint service coland port")?;
        let metrics_port = reserve_port().context("reserve joint service coland metrics port")?;
        ArkretServer::spawn_external_binary_with_ports_and_env(
            &config.name,
            &coland_bin,
            port,
            metrics_port,
            &env_borrowed,
        )
        .await
    } else {
        ArkretServer::spawn_with_env(&config.name, &env_borrowed).await
    }
    .context("joint service bootstrap: failed to spawn coland with wired env")?;

    let coauth = match prepared_coauth {
        Some(prepared) => Some(
            prepared
                .spawn_for_station(
                    coland.base_url().as_str(),
                    &config.internal_authority_shared_secret,
                    &config.embedded_webvh_registration_bearer,
                    coland.tls_ca_path(),
                )
                .await
                .context("joint service bootstrap: failed to spawn prepared coauth")?,
        ),
        None => None,
    };

    Ok(JointServiceStack {
        flagon,
        coauth,
        coland,
    })
}

/// Strict wrapper around [`try_bootstrap`] that fails if any of the optional
/// services is missing. Use this in `#[ignore]` tests that the operator
/// opted into via `--ignored`; the descriptive error explains exactly which
/// piece of the stack didn't come up.
pub async fn bootstrap_required(config: JointServiceConfig) -> Result<JointServiceStack> {
    let stack = try_bootstrap(config).await?;
    let mut missing: Vec<&str> = Vec::new();
    if stack.coauth.is_none() {
        missing.push("coauth (need docker + COAUTH_BIN or sibling checkout)");
    }
    if stack.flagon.is_none() {
        missing.push("flagon (need FLAGON_BIN or sibling checkout + DATABASE_URL)");
    }
    if !missing.is_empty() {
        return Err(anyhow!(
            "joint service bootstrap incomplete: {}",
            missing.join("; ")
        ));
    }
    Ok(stack)
}
