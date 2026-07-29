//! CT-6 — 4-service joint bootstrap (soland + coauth + starid + teabay).
//!
//! Provides a single [`FourServiceStack`] entry point that:
//!   1. Spawns `soland` (via the existing [`ArkretServer::spawn_with_env`] machinery, which honours
//!      the pre-built sibling binary fast path).
//!   2. Optionally spawns `coauth` via [`coauth_bootstrap::spawn_coauth_with_db`] (docker-postgres
//!      + generated config). Wires soland -> coauth session-grant introspection via
//!      `SOLAND_SESSION_GRANT_INTROSPECTION_URL`.
//!   3. Optionally spawns `starid` via the [`external_binary::STARID_SPEC`] (no external deps in
//!      development mode). Wires soland → starid via `SOLAND_STARID_WEBVH_RESOLVER_URL` +
//!      `SOLAND_DID_RESOLVER_ALLOW_METHODS`.
//!   4. Optionally spawns `teabay` via [`external_binary::TEABAY_SPEC`] — requires `DATABASE_URL`
//!      in the caller's env (see `TEABAY_SPEC.required_env_vars`).
//!
//! `try_bootstrap` is fail-soft: services that can't start (missing binary,
//! missing DATABASE_URL, docker unreachable) are returned as `None` slots so
//! callers can decide to skip vs. fail. `bootstrap_required` folds the same
//! checks into a hard error so `#[ignore]` tests opted in via `--ignored`
//! get a descriptive bail.
//!
//! Drop order is LIFO (teabay → starid → coauth → soland), so each service
//! gets a chance to flush before its upstream goes away. Postgres for coauth
//! is reaped by `EphemeralPg::Drop` after the coauth handle drops.

use std::time::Duration;

use anyhow::{Context, Result, anyhow};

use crate::harness::{ArkretServer, reserve_port};
use crate::scenarios::_helpers::coauth_bootstrap::{
    SpawnedCoauth, coauth_with_db_available, prepare_coauth_with_db_required,
};
use crate::scenarios::_helpers::external_binary::{
    SOLAND_SPEC, STARID_SPEC, SpawnedExternalProcess, TEABAY_SPEC, locate_external_binary,
    skip_reason, try_spawn,
};

/// Per-service env wiring used when spinning up the four-service stack.
/// All fields default to development-friendly values; callers can override
/// any of them before `try_bootstrap`.
#[derive(Clone)]
pub struct FourServiceConfig {
    /// Logical name passed to soland (used for the test DID + log directory).
    pub name: String,
    /// Bearer token expected by soland when calling coauth's
    /// `session-grants/introspect` endpoint. Must match the value coauth's
    /// generated config patched in.
    pub session_grant_introspection_bearer: String,
    /// Bearer token soland presents when registering a did:webvh document
    /// against the embedded provider. Mirrors run-joint-e2e.ps1.
    pub embedded_webvh_registration_bearer: String,
    /// When `true`, attempt to wire teabay's discovery ingest at the soland
    /// announce stream. Implemented by exporting the soland public base URL
    /// to teabay via `TEABAY_SOLAND_ANNOUNCE_URL` — teabay's optional
    /// announce-ingest worker reads this when it boots.
    pub wire_directory_ingest: bool,
}

impl FourServiceConfig {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            session_grant_introspection_bearer: "cotest-session-grant-introspection".to_owned(),
            embedded_webvh_registration_bearer: "cotest-webvh-registration".to_owned(),
            wire_directory_ingest: true,
        }
    }
}

/// Aggregated handle for the four-service stack. Each optional field is
/// `Some` only when the corresponding service was successfully spawned.
///
/// Drop order is enforced via field ordering. Rust drops fields from top to
/// bottom, so upstream dependants are declared before `soland`; soland is the
/// final process to be torn down.
pub struct FourServiceStack {
    /// teabay (directory) — `Some` if sibling binary + `DATABASE_URL` were
    /// available.
    pub teabay: Option<SpawnedExternalProcess>,
    /// starid (DID resolver) — `Some` if sibling binary was available.
    pub starid: Option<SpawnedExternalProcess>,
    /// coauth (auth/account) — `Some` if docker + sibling binary were
    /// available; `None` if the bootstrap couldn't bring it up.
    pub coauth: Option<SpawnedCoauth>,
    /// soland (principal server) — always present (or the bootstrap returns
    /// `Err`). This is the "main" service the rest of the stack talks to.
    pub soland: ArkretServer,
}

impl FourServiceStack {
    /// Public REST base URL for soland (always present).
    pub fn soland_base_url(&self) -> String {
        self.soland.base_url().to_string()
    }

    /// Public REST base URL for coauth (when spawned).
    pub fn coauth_base_url(&self) -> Option<&str> {
        self.coauth.as_ref().map(SpawnedCoauth::base_url)
    }

    /// Public REST base URL for starid (when spawned).
    pub fn starid_base_url(&self) -> Option<&str> {
        self.starid.as_ref().map(|p| p.base_url.as_str())
    }

    /// Public REST base URL for teabay (when spawned).
    pub fn teabay_base_url(&self) -> Option<&str> {
        self.teabay.as_ref().map(|p| p.base_url.as_str())
    }

    /// Run `/health` against every spawned service. Returns `Err` if any
    /// service is unreachable within the per-service timeout. Each service's
    /// own bootstrap already waited for `/health` once; this is the
    /// "post-stack" sanity check exercised by the smoke scenario.
    pub async fn assert_healthy(&self) -> Result<()> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(3))
            .build()
            .context("constructing reqwest client for four-service health check")?;

        // soland's base_url already ends in `/`; trim before re-joining.
        let soland_health = format!("{}/health", self.soland_base_url().trim_end_matches('/'));
        probe(&client, "soland", &soland_health).await?;

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
        if let Some(url) = self.starid_base_url() {
            probe(
                &client,
                "starid",
                &format!("{}/health", url.trim_end_matches('/')),
            )
            .await?;
        }
        if let Some(url) = self.teabay_base_url() {
            probe(
                &client,
                "teabay",
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

/// Try to bring up all four services; return whichever subset spawned
/// successfully. Soland is the only required participant — if soland fails to
/// spawn, the whole bootstrap returns `Err` (every other test in cotest
/// assumes a working soland).
pub async fn try_bootstrap(config: FourServiceConfig) -> Result<FourServiceStack> {
    let prepared_coauth =
        if coauth_with_db_available() && locate_external_binary(&SOLAND_SPEC).is_some() {
            Some(prepare_coauth_with_db_required()?)
        } else {
            None
        };

    // 2. starid — env-driven, no external deps. Soft-skip if the binary can't be located.
    let starid = match skip_reason(&STARID_SPEC) {
        Some(_) => None,
        None => try_spawn(&STARID_SPEC).await?,
    };

    // 3. teabay — requires DATABASE_URL. Soft-skip otherwise.
    let teabay = match skip_reason(&TEABAY_SPEC) {
        Some(_) => None,
        None => try_spawn(&TEABAY_SPEC).await?,
    };

    // 4. Build the soland env from the resolved upstream URLs. Empty/absent keys are simply not
    //    exported (soland's config keeps the production-safe default when the env var is unset).
    let mut soland_env: Vec<(String, String)> = Vec::new();

    if let Some(coauth) = &prepared_coauth {
        let base = coauth.base_url();
        let base = base.trim_end_matches('/');
        soland_env.push((
            "SOLAND_SESSION_GRANT_INTROSPECTION_URL".to_owned(),
            format!("{base}/_arkret/gate/account/session-grants/introspect"),
        ));
        soland_env.push((
            "SOLAND_SESSION_GRANT_INTROSPECTION_BEARER".to_owned(),
            config.session_grant_introspection_bearer.clone(),
        ));
        soland_env.push((
            "SOLAND_EMBEDDED_WEBVH_REGISTRATION_BEARER".to_owned(),
            config.embedded_webvh_registration_bearer.clone(),
        ));
        soland_env.push(("SOLAND_ACCOUNT_AUTHORITY_URL".to_owned(), base.to_owned()));
    }
    if let Some(starid) = &starid {
        // did:webvh is the v1 core default method; did:web is intentionally
        // absent (no-history method, negative-fixture only — soland's default
        // allow-methods no longer includes it either).
        soland_env.push((
            "SOLAND_DID_RESOLVER_ALLOW_METHODS".to_owned(),
            "did:webvh,did:key".to_owned(),
        ));
        soland_env.push((
            "SOLAND_STARID_WEBVH_RESOLVER_URL".to_owned(),
            starid.base_url.clone(),
        ));
    }
    if let Some(teabay) = &teabay
        && config.wire_directory_ingest
    {
        // Teabay-side wiring (announce ingest target) is handled via
        // TEABAY_SPEC's env at spawn time; this just gives soland a hint
        // about which directory to announce to. Soland's announce config
        // key is optional (default: no announce), so unset is harmless.
        soland_env.push((
            "SOLAND_DIRECTORY_ANNOUNCE_URL".to_owned(),
            format!("{}/_arkret/find/directory/announce", teabay.base_url),
        ));
    }

    // ArkretServer::spawn_with_env takes &[(&str, &str)] — borrow the owned
    // strings before passing.
    let env_borrowed: Vec<(&str, &str)> = soland_env
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    let soland = if let (Some(_), Some(soland_bin)) = (
        prepared_coauth.as_ref(),
        locate_external_binary(&SOLAND_SPEC),
    ) {
        let port = reserve_port().context("reserve four-service soland port")?;
        let metrics_port = reserve_port().context("reserve four-service soland metrics port")?;
        ArkretServer::spawn_external_binary_with_ports_and_env(
            &config.name,
            &soland_bin,
            port,
            metrics_port,
            &env_borrowed,
        )
        .await
    } else {
        ArkretServer::spawn_with_env(&config.name, &env_borrowed).await
    }
    .context("four-service bootstrap: failed to spawn soland with wired env")?;

    let coauth = match prepared_coauth {
        Some(prepared) => Some(
            prepared
                .spawn_for_principal_server(
                    soland.base_url().as_str(),
                    &config.session_grant_introspection_bearer,
                    &config.embedded_webvh_registration_bearer,
                )
                .await
                .context("four-service bootstrap: failed to spawn prepared coauth")?,
        ),
        None => None,
    };

    Ok(FourServiceStack {
        teabay,
        starid,
        coauth,
        soland,
    })
}

/// Strict wrapper around [`try_bootstrap`] that fails if any of the optional
/// services is missing. Use this in `#[ignore]` tests that the operator
/// opted into via `--ignored`; the descriptive error explains exactly which
/// piece of the stack didn't come up.
pub async fn bootstrap_required(config: FourServiceConfig) -> Result<FourServiceStack> {
    let stack = try_bootstrap(config).await?;
    let mut missing: Vec<&str> = Vec::new();
    if stack.coauth.is_none() {
        missing.push("coauth (need docker + COAUTH_BIN or sibling checkout)");
    }
    if stack.starid.is_none() {
        missing.push("starid (need STARID_BIN or sibling checkout)");
    }
    if stack.teabay.is_none() {
        missing.push("teabay (need TEABAY_BIN or sibling checkout + DATABASE_URL)");
    }
    if !missing.is_empty() {
        return Err(anyhow!(
            "four-service bootstrap incomplete: {}",
            missing.join("; ")
        ));
    }
    Ok(stack)
}
