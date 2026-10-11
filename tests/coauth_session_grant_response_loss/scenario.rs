//! Live Coauth issuer-ledger recovery after a committed response is lost.
//!
//! The scenario owns real Coauth/HTTPS Station children and isolated PostgreSQL.
//! Coauth verifies the Station through its normal trust preflight, then pauses
//! only after its issuer-ledger transaction commits; Cotest kills the process,
//! restarts it from the same config/key material, and sends the exact same
//! canonical request twice. The two replay responses must be byte-identical.

use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, bail, ensure};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use cotest::scenarios::_helpers::coauth_bootstrap::{
    CoauthChaosConfig, spawn_coauth_with_station_and_chaos,
};
use ed25519_dalek::SigningKey;
use serde_json::{Value, json};

const BREAKPOINT: &str = "session_grant_issue_post_commit_pre_response";

/// Run the destructive, opt-in live fault scenario.
pub async fn coauth_session_grant_response_loss_run() -> Result<()> {
    let marker_dir = tempfile::tempdir().context("create Coauth chaos marker directory")?;
    let marker = marker_dir.path().join("post-commit.reached");
    let (mut coauth, station) = spawn_coauth_with_station_and_chaos(CoauthChaosConfig {
        breakpoint: BREAKPOINT.to_owned(),
        request_identity: None,
        delay_ms: 30_000,
        reached_file: Some(marker.clone()),
    })
    .await?;

    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(40))
        .build()
        .context("build Coauth fault-test client")?;
    // This case exercises issuer durability, not product onboarding. Seed its
    // isolated private account through the actual repository using the owning
    // storage crate's signed SDK fixture; no retired HTTP provisioning seam.
    wait_for_station_trust(&http, coauth.base_url()).await?;
    let audience = station.service_id().as_str();
    let actor_id = seed_bound_account(&coauth.pg.connect_url, audience).await?;

    let holder = SigningKey::from_bytes(&[0x5a; 32]);
    let issue_body = json!({
        "actor_id": actor_id,
        "device_id": "ak:device:019b0000-0000-7000-8000-00000000f001",
        "dpop_jwk": {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": URL_SAFE_NO_PAD.encode(holder.verifying_key().as_bytes()),
            "use": "sig",
            "key_ops": ["verify"],
            "alg": "Ed25519"
        },
        "audience_id": audience,
    });
    let canonical_request = arkret_canonical::canonical_json_bytes(&issue_body)?;
    let issue_url = format!(
        "{}/_coauth/account/test/debug/issue-dpop-grant",
        coauth.base_url()
    );
    let first_attempt = tokio::spawn({
        let http = http.clone();
        let issue_url = issue_url.clone();
        let canonical_request = canonical_request.clone();
        async move {
            http.post(issue_url)
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(canonical_request)
                .send()
                .await
        }
    });

    wait_for_marker(&marker, Duration::from_secs(20)).await?;
    coauth.kill_immediately()?;
    let first_result = first_attempt
        .await
        .context("join interrupted Coauth issue request")?;
    if let Ok(response) = first_result {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        bail!("post-commit response unexpectedly escaped process kill: {status} {body}");
    }

    coauth.restart_same_config().await?;
    wait_for_station_trust(&http, coauth.base_url()).await?;
    let replay_one = post_exact(&http, &issue_url, &canonical_request).await?;
    let replay_two = post_exact(&http, &issue_url, &canonical_request).await?;
    ensure!(
        replay_one == replay_two,
        "issuer-ledger replay changed canonical response bytes after restart"
    );
    let outcome: Value =
        serde_json::from_slice(&replay_one).context("decode replayed debug grant outcome")?;
    ensure!(
        outcome
            .get("grant_id")
            .and_then(Value::as_str)
            .is_some_and(|value| value.starts_with("ak:session_grant:")),
        "replayed outcome omitted a canonical SessionGrantId"
    );
    ensure!(
        outcome
            .get("grant_jwt")
            .and_then(Value::as_str)
            .is_some_and(|value| value.split('.').count() == 3),
        "replayed outcome omitted the committed signed credential"
    );
    Ok(())
}

async fn wait_for_station_trust(http: &reqwest::Client, base_url: &str) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(60);
    while Instant::now() < deadline {
        let response = http
            .get(format!("{base_url}/_coauth/self/viewer"))
            .send()
            .await?;
        if response.status() == reqwest::StatusCode::UNAUTHORIZED || response.status().is_success()
        {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    bail!("Coauth owning Station trust never enabled business routes")
}

async fn wait_for_marker(path: &std::path::Path, timeout: Duration) -> Result<()> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Ok(marker) = std::fs::read_to_string(path)
            && marker.contains(&format!("breakpoint={BREAKPOINT}"))
            && marker.contains("request_identity=")
        {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    bail!(
        "Coauth never reached the durable post-commit breakpoint at {}",
        path.display()
    )
}

async fn post_exact(
    http: &reqwest::Client,
    url: &str,
    canonical_request: &[u8],
) -> Result<Vec<u8>> {
    let response = http
        .post(url)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(canonical_request.to_vec())
        .send()
        .await
        .context("replay exact Coauth request")?;
    let status = response.status();
    let body = response.bytes().await?.to_vec();
    ensure!(
        status.is_success(),
        "Coauth exact replay returned {status}: {}",
        String::from_utf8_lossy(&body)
    );
    Ok(body)
}

async fn seed_bound_account(database_url: &str, audience: &str) -> Result<String> {
    use coauth_data::user::{PrincipalDidRepository as _, UserRepository as _};
    use coauth_data::{RepositoryAccess as _, RepositoryFactory as _, SystemClock};
    use coauth_storage_postgres::{PgRepositoryFactory, test_utils};
    use rand_core_06::SeedableRng as _;

    let config = serde_json::from_value(json!({ "uri": database_url }))?;
    let pool = coauth_backend::util::diesel_pool_from_config(&config).await?;
    let factory = PgRepositoryFactory::new(pool);
    let mut repo = factory.create().await?;
    let mut rng = rand_chacha_03::ChaChaRng::seed_from_u64(906);
    let clock = SystemClock::default();
    let user = repo
        .user()
        .add(&mut rng, &clock, "coauth-ledger-chaos".to_owned())
        .await?;
    let (actor_id, head) = test_utils::principal_binding_test_material("coauthledgerchaos");
    let mut input = test_utils::verified_principal_binding_input(
        "did:web:fixture.example",
        audience,
        actor_id.clone(),
        head,
    );
    input.binding_receipt_digest =
        arkret_identifiers::Hash::new(arkret_canonical::canonical_sha256(&input.binding_receipt)?)?;
    // Pin the fixture's provenance before trusting it as this case's input.
    arkret_signatures::Ed25519DetachedJwsVerifier::new()
        .verify_detached_jws(
            &input.binding_receipt.proof.jws,
            &input.binding_receipt.canonical_proof_binding_bytes()?,
            &arkret_signatures::proof::PublicKeyMaterial::Ed25519Raw {
                bytes: test_utils::fixture_account_authority_verifying_key().to_vec(),
            },
        )
        .map_err(|error| anyhow::anyhow!("invalid issuer-ledger binding fixture: {error}"))?;
    repo.principal_did()
        .add_verified(&mut rng, &clock, &user, input)
        .await?;
    repo.save().await?;
    Ok(actor_id)
}
