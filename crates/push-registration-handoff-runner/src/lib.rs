//! Real Floria/PostgreSQL execution for the public registration-handoff vector.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail, ensure};
use arkret_models_integration::{
    PushRegistrationHandoffOutcome, PushRegistrationHandoffRequestBody,
};
use arkret_signatures::generated::http_signature_contract::HttpSignatureScenario;
use arkret_signatures::http_signature::{
    ContentDigest, ContentDigestAlgorithm, SignedRequestParts, sign_http_message_for_scenario,
};
use arkret_signatures::{PublicKeyMaterial, verify_ed25519_detached_jws_payload_proof};
use arkret_wire::{Did, DidCoreId, ServiceOperationId};
use ed25519_dalek::SigningKey;
use floria::AppState;
use floria::auth::{DESTINATION_SERVICE_ID_HEADER, SOURCE_SERVICE_ID_HEADER};
use floria::config::{NotifyAuthConfig, NotifyServicePrincipalConfig, RegistrationHandoffConfig};
use floria::nonce_store::NonceStore;
use floria::pushkin::PushkinRegistry;
use floria::registration_handoff::{ApplyRegistrationError, RegistrationHandoffStore};
use floria::service::build_router;
use postgres::{Client, NoTls};
use salvo::http::StatusCode;
use salvo::test::TestClient;
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

pub const PUSH_REGISTRATION_HANDOFF_VECTOR_ID: &str =
    "ak.vector.push.registration_handoff_lifecycle.v1";
pub const FIXTURE: &str = "push-notify-outcome-fixture.json";
pub const DATABASE_URL_ENV: &str = "COTEST_FLORIA_HANDOFF_DATABASE_URL";
const GATEWAY_DID: &str = "did:web:gateway.example";
const METHOD: &str = "did:web:gateway.example#receipt";
const TARGET_A: &str = "ak:pseudonym:push:kosc9iQ4gVct1OB-b6X364WIFIsJFVbVzn7BMBs1sm8";
const TARGET_B: &str = "ak:pseudonym:push:lg8aqJ2eJjms1GQpkzloxGn8F802f8RfmfmfsC85eRo";
const DEVICE_A: &str = "ak:device:01904100-0000-7000-8000-000000000001";
const DEVICE_B: &str = "ak:device:01904100-0000-7000-8000-000000000002";
const RECEIPT_SEED: [u8; 32] = [7; 32];
const SOURCE_SEED: [u8; 32] = [19; 32];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaseExecutionResult {
    pub case_id: String,
    pub assertions: usize,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PushRegistrationHandoffExecution {
    pub vector_id: &'static str,
    pub fixture: &'static str,
    pub cases: Vec<CaseExecutionResult>,
}
#[derive(Debug, Deserialize)]
struct Fixture {
    registration_handoff_lifecycle_cases: Vec<Case>,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct Case {
    name: String,
    #[serde(default)]
    steps: Vec<String>,
    #[serde(default)]
    variants: Vec<String>,
    expected: String,
}
struct Cleanup {
    url: String,
    table: String,
}
impl Drop for Cleanup {
    fn drop(&mut self) {
        if let Ok(mut client) = Client::connect(&self.url, NoTls) {
            let _ = client.batch_execute(&format!("DROP TABLE IF EXISTS {}", self.table));
        }
    }
}
struct Harness {
    url: String,
    table: String,
    gateway: DidCoreId,
    store: Arc<RegistrationHandoffStore>,
}

pub fn validate_push_registration_handoff_fixture() -> Result<()> {
    fixture().map(|_| ())
}

pub fn run_push_registration_handoff_lifecycle_vector() -> Result<PushRegistrationHandoffExecution>
{
    let url = std::env::var(DATABASE_URL_ENV).with_context(|| {
        format!("{DATABASE_URL_ENV} is required; this vector must use real PostgreSQL")
    })?;
    run_push_registration_handoff_lifecycle_with_database_url(&url)
}

pub fn run_push_registration_handoff_lifecycle_with_database_url(
    url: &str,
) -> Result<PushRegistrationHandoffExecution> {
    let cases = fixture()?;
    let table = format!("cotest_push_handoff_{}", Uuid::new_v4().simple());
    let _cleanup = Cleanup {
        url: url.to_owned(),
        table: table.clone(),
    };
    let gateway = core(GATEWAY_DID)?;
    let mut config = RegistrationHandoffConfig::default();
    config.postgres_url = Some(url.to_owned());
    config.table = table.clone();
    config.encryption_key_hex = Some(hex::encode([11_u8; 32]));
    config.receipt_signing_key_seed_hex = Some(hex::encode(RECEIPT_SEED));
    config.receipt_verification_method = Some(METHOD.to_owned());
    let store = RegistrationHandoffStore::from_config(&config, gateway.clone())?
        .context("Floria handoff store was not enabled")?;
    let harness = Harness {
        url: url.to_owned(),
        table,
        gateway,
        store: Arc::new(store),
    };
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(execute(&harness, cases))
}

async fn execute(h: &Harness, cases: Vec<Case>) -> Result<PushRegistrationHandoffExecution> {
    let mut results = Vec::new();
    for case in cases {
        let assertions = match case.name.as_str() {
            "exact_replay_after_lost_response" => replay(h).await?,
            "same_registration_id_different_body_conflicts" => conflict(h).await?,
            "successor_tombstones_predecessor_atomically" => supersede(h).await?,
            "revoke_wins_over_delayed_install" => revoke(h).await?,
            "source_destination_and_device_are_exact" => identities(h).await?,
            "tenant_isolation" => tenants(h).await?,
            other => bail!("unexecuted handoff case {other}"),
        };
        ensure!(assertions > 0, "{} executed no assertions", case.name);
        results.push(CaseExecutionResult {
            case_id: case.name,
            assertions,
        });
    }
    Ok(PushRegistrationHandoffExecution {
        vector_id: PUSH_REGISTRATION_HANDOFF_VECTOR_ID,
        fixture: FIXTURE,
        cases: results,
    })
}

async fn replay(h: &Harness) -> Result<usize> {
    let source = core("did:web:station-replay.example")?;
    let req = active("registration_replay_000000000001", "provider-replay", None)?;
    let a = apply(h, &source, &req).await?;
    let b = apply(h, &source, &req).await?;
    receipt(&a, &req, &source, &h.gateway, "provider-replay")?;
    ensure!(
        serde_json::to_vec(&a)? == serde_json::to_vec(&b)?,
        "replay receipt bytes changed"
    );
    ensure!(
        resolve(h, &source, &req)
            .await?
            .is_some_and(|r| r.push_key.as_str() == "provider-replay")
    );
    ensure!(count(h, &source, req.registration_id().as_str()).await? == 1);
    Ok(4)
}

async fn conflict(h: &Harness) -> Result<usize> {
    let source = core("did:web:station-conflict.example")?;
    let a = active("registration_conflict_000000001", "provider-original", None)?;
    let b = active("registration_conflict_000000001", "provider-mutated", None)?;
    let first = apply(h, &source, &a).await?;
    must_conflict(
        h.store.apply(source.clone(), h.gateway.clone(), b).await,
        "different-body replay",
    )?;
    ensure!(
        serde_json::to_vec(&first)? == serde_json::to_vec(&apply(h, &source, &a).await?)?,
        "conflict mutated receipt bytes"
    );
    ensure!(
        resolve(h, &source, &a)
            .await?
            .is_some_and(|r| r.push_key.as_str() == "provider-original")
    );
    ensure!(count(h, &source, a.registration_id().as_str()).await? == 1);
    Ok(4)
}

async fn supersede(h: &Harness) -> Result<usize> {
    let source = core("did:web:station-supersede.example")?;
    let old = active("registration_predecessor_0000001", "provider-old", None)?;
    let new = active(
        "registration_successor_00000001",
        "provider-new",
        Some(old.registration_id().as_str()),
    )?;
    apply(h, &source, &old).await?;
    let installed = apply(h, &source, &new).await?;
    receipt(&installed, &new, &source, &h.gateway, "provider-new")?;
    must_conflict(
        h.store.apply(source.clone(), h.gateway.clone(), old).await,
        "delayed predecessor",
    )?;
    ensure!(
        resolve(h, &source, &new)
            .await?
            .is_some_and(
                |r| r.registration_id.as_str() == new.registration_id().as_str()
                    && r.push_key.as_str() == "provider-new"
            )
    );
    ensure!(active_count(h, &source, &new).await? == 1);
    Ok(4)
}

async fn revoke(h: &Harness) -> Result<usize> {
    let source = core("did:web:station-revoke.example")?;
    let active = active("registration_revoked_0000000001", "provider-delayed", None)?;
    let revoked = revoked(&active)?;
    let tombstone = apply(h, &source, &revoked).await?;
    receipt(&tombstone, &revoked, &source, &h.gateway, "")?;
    must_conflict(
        h.store
            .apply(source.clone(), h.gateway.clone(), active.clone())
            .await,
        "active after tombstone",
    )?;
    ensure!(resolve(h, &source, &active).await?.is_none());
    ensure!(
        serde_json::to_vec(&tombstone)? == serde_json::to_vec(&apply(h, &source, &revoked).await?)?
    );
    Ok(4)
}

async fn identities(h: &Harness) -> Result<usize> {
    let source = core("did:web:station-exact.example")?;
    let other = core("did:web:station-other.example")?;
    let wrong_gateway = core("did:web:wrong-gateway.example")?;
    let req = active("registration_exact_000000000001", "provider-exact", None)?;
    ensure!(
        http_status(
            h,
            &source,
            &h.gateway,
            &req,
            &SigningKey::from_bytes(&[23; 32]),
            "wrong-source"
        )
        .await?
            == StatusCode::UNAUTHORIZED
    );
    ensure!(
        http_status(
            h,
            &source,
            &wrong_gateway,
            &req,
            &SigningKey::from_bytes(&SOURCE_SEED),
            "wrong-destination"
        )
        .await?
            == StatusCode::FORBIDDEN
    );
    ensure!(
        resolve(h, &source, &req).await?.is_none(),
        "rejected HTTP requests mutated state"
    );
    apply(h, &source, &req).await?;
    ensure!(
        resolve(h, &source, &variant(&req, TARGET_B, DEVICE_A)?)
            .await?
            .is_none()
    );
    ensure!(
        resolve(h, &source, &variant(&req, TARGET_A, DEVICE_B)?)
            .await?
            .is_none()
    );
    ensure!(resolve(h, &other, &req).await?.is_none());
    let cross = active(
        "registration_cross_station_00001",
        "provider-cross",
        Some(req.registration_id().as_str()),
    )?;
    must_conflict(
        h.store.apply(other, h.gateway.clone(), cross).await,
        "cross-station supersede",
    )?;
    ensure!(
        resolve(h, &source, &req)
            .await?
            .is_some_and(|r| r.push_key.as_str() == "provider-exact")
    );
    Ok(8)
}

async fn tenants(h: &Harness) -> Result<usize> {
    let a = core("did:web:station-tenant-a.example")?;
    let b = core("did:web:station-tenant-b.example")?;
    let c = core("did:web:station-tenant-c.example")?;
    let req = active("registration_tenant_shared_00001", "provider-shared", None)?;
    let out_a = apply(h, &a, &req).await?;
    let out_b = apply(h, &b, &req).await?;
    receipt(&out_a, &req, &a, &h.gateway, "provider-shared")?;
    receipt(&out_b, &req, &b, &h.gateway, "provider-shared")?;
    ensure!(out_a != out_b, "tenants were deduplicated together");
    ensure!(resolve(h, &a, &req).await?.is_some());
    ensure!(resolve(h, &b, &req).await?.is_some());
    ensure!(resolve(h, &c, &req).await?.is_none());
    ensure!(total_count(h, req.registration_id().as_str()).await? == 2);
    Ok(7)
}

async fn apply(
    h: &Harness,
    source: &DidCoreId,
    request: &PushRegistrationHandoffRequestBody,
) -> Result<PushRegistrationHandoffOutcome> {
    h.store
        .apply(source.clone(), h.gateway.clone(), request.clone())
        .await
        .map_err(Into::into)
}
async fn resolve(
    h: &Harness,
    source: &DidCoreId,
    request: &PushRegistrationHandoffRequestBody,
) -> Result<Option<arkret_models_integration::PushRegistrationRecord>> {
    h.store
        .resolve(
            source,
            request.push_target_id(),
            request.device_id(),
            "https://gateway.example/",
        )
        .await
}
fn must_conflict(
    value: Result<PushRegistrationHandoffOutcome, ApplyRegistrationError>,
    label: &str,
) -> Result<()> {
    match value {
        Err(ApplyRegistrationError::Conflict) => Ok(()),
        Err(e) => Err(anyhow!("{label}: {e}")),
        Ok(_) => bail!("{label} unexpectedly succeeded"),
    }
}
fn receipt(
    out: &PushRegistrationHandoffOutcome,
    req: &PushRegistrationHandoffRequestBody,
    source: &DidCoreId,
    gateway: &DidCoreId,
    secret: &str,
) -> Result<()> {
    out.receipt.validate_for_handoff(req, source, gateway)?;
    verify_ed25519_detached_jws_payload_proof(
        &out.receipt.proof,
        &out.receipt.proof_binding_bytes()?,
        &PublicKeyMaterial::Ed25519Raw {
            bytes: SigningKey::from_bytes(&RECEIPT_SEED)
                .verifying_key()
                .to_bytes()
                .to_vec(),
        },
    )?;
    ensure!(
        secret.is_empty() || !serde_json::to_string(out)?.contains(secret),
        "receipt disclosed provider secret"
    );
    Ok(())
}

async fn http_status(
    h: &Harness,
    source: &DidCoreId,
    destination: &DidCoreId,
    req: &PushRegistrationHandoffRequestBody,
    signing: &SigningKey,
    idempotency: &str,
) -> Result<StatusCode> {
    let expected = SigningKey::from_bytes(&SOURCE_SEED);
    let mut principal = NotifyServicePrincipalConfig::default();
    principal.signature_verification_method = Some(format!("{}#push", source.as_str()));
    principal.signature_public_key_hex = Some(hex::encode(expected.verifying_key().to_bytes()));
    let mut auth = NotifyAuthConfig::default();
    auth.gateway_service_did = Some(GATEWAY_DID.to_owned());
    auth.require_message_signatures = true;
    auth.replay_window_seconds = 300;
    auth.service_principals = HashMap::from([(source.as_str().to_owned(), principal)]);
    let mut state = AppState::new(Arc::new(PushkinRegistry::new(HashMap::new())));
    state.notify_auth = auth;
    state.notify_nonce_store = Some(Arc::new(NonceStore::memory(Duration::from_secs(300))));
    state.registration_handoff = Some(h.store.clone());
    let service = salvo::Service::new(build_router(Arc::new(state)));
    let body = arkret_canonical::canonical::canonical_json_bytes(req)?;
    let digest = ContentDigest::compute(&body, ContentDigestAlgorithm::Sha256).wire_value;
    let url = "http://127.0.0.1/_arkret/edge/push/registrations:apply";
    let operation = ServiceOperationId::EDGE_PUSH_COMMAND_APPLY_REGISTRATION_V1;
    let parts = SignedRequestParts {
        method: "POST".to_owned(),
        target_uri: url.to_owned(),
        authority: "127.0.0.1".to_owned(),
        path: "/_arkret/edge/push/registrations:apply".to_owned(),
        headers: vec![
            ("arkret-operation".into(), operation.into()),
            ("source-service-id".into(), source.as_str().into()),
            ("destination-service-id".into(), destination.as_str().into()),
            ("idempotency-key".into(), idempotency.into()),
            ("content-digest".into(), digest.clone()),
        ],
        body_digest: Some(digest.clone()),
    };
    let signed = sign_http_message_for_scenario(
        &parts,
        HttpSignatureScenario::ServiceToServiceV1,
        &["content-digest", "idempotency-key"],
        "sig1",
        &format!("{}#push", source.as_str()),
        now()?,
        signing,
    )?;
    TestClient::post(url)
        .add_header("Arkret-Operation", operation, true)
        .add_header(SOURCE_SERVICE_ID_HEADER, source.as_str(), true)
        .add_header(DESTINATION_SERVICE_ID_HEADER, destination.as_str(), true)
        .add_header("Idempotency-Key", idempotency, true)
        .add_header("Content-Digest", digest, true)
        .add_header("Signature-Input", signed.signature_input_header, true)
        .add_header("Signature", signed.signature_header, true)
        .add_header("Content-Type", "application/json", true)
        .body(body)
        .send(&service)
        .await
        .status_code
        .ok_or_else(|| anyhow!("HTTP status missing"))
}

fn active(
    id: &str,
    key: &str,
    supersedes: Option<&str>,
) -> Result<PushRegistrationHandoffRequestBody> {
    let mut v = json!({"registration_id":id,"push_target_id":TARGET_A,"device_id":DEVICE_A,"state":"active","push_key":key,"platform":"apns","app_id":"org.arkret.cotest","visible_notification_opt_in":false});
    if let Some(old) = supersedes {
        v["supersedes_registration_id"] = json!(old);
    }
    Ok(serde_json::from_value(v)?)
}
fn revoked(req: &PushRegistrationHandoffRequestBody) -> Result<PushRegistrationHandoffRequestBody> {
    Ok(serde_json::from_value(
        json!({"registration_id":req.registration_id(),"push_target_id":req.push_target_id(),"device_id":req.device_id(),"state":"revoked"}),
    )?)
}
fn variant(
    req: &PushRegistrationHandoffRequestBody,
    target: &str,
    device: &str,
) -> Result<PushRegistrationHandoffRequestBody> {
    Ok(serde_json::from_value(
        json!({"registration_id":req.registration_id(),"push_target_id":target,"device_id":device,"state":"active","push_key":"unused","visible_notification_opt_in":false}),
    )?)
}
fn core(value: &str) -> Result<DidCoreId> {
    arkret_wire::project_did_to_core_id(&Did::new(value.to_owned()).map_err(anyhow::Error::msg)?)
        .map_err(anyhow::Error::msg)
}
fn now() -> Result<i64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_secs()
        .try_into()?)
}

async fn query_count(h: &Harness, where_sql: String, values: Vec<String>) -> Result<i64> {
    let url = h.url.clone();
    let table = h.table.clone();
    tokio::task::spawn_blocking(move || {
        let mut client = Client::connect(&url, NoTls)?;
        let refs: Vec<&(dyn postgres::types::ToSql + Sync)> = values
            .iter()
            .map(|v| v as &(dyn postgres::types::ToSql + Sync))
            .collect();
        let row = client.query_one(
            &format!("SELECT COUNT(*) FROM {table} WHERE {where_sql}"),
            &refs,
        )?;
        Ok::<i64, anyhow::Error>(row.get(0))
    })
    .await
    .context("count task failed")?
}
async fn count(h: &Harness, source: &DidCoreId, id: &str) -> Result<i64> {
    query_count(
        h,
        "source_station_id=$1 AND registration_id=$2".into(),
        vec![source.as_str().into(), id.into()],
    )
    .await
}
async fn total_count(h: &Harness, id: &str) -> Result<i64> {
    query_count(h, "registration_id=$1".into(), vec![id.into()]).await
}
async fn active_count(
    h: &Harness,
    source: &DidCoreId,
    req: &PushRegistrationHandoffRequestBody,
) -> Result<i64> {
    query_count(h, "source_station_id=$1 AND push_target_id=$2 AND device_id=$3 AND state='active' AND successor_registration_id IS NULL".into(), vec![source.as_str().into(), req.push_target_id().as_str().into(), req.device_id().as_str().into()]).await
}

fn fixture() -> Result<Vec<Case>> {
    let path = fixture_path();
    let parsed: Fixture = serde_json::from_slice(
        &std::fs::read(&path).with_context(|| format!("read {}", path.display()))?,
    )?;
    ensure!(
        parsed.registration_handoff_lifecycle_cases == expected(),
        "handoff fixture drifted from closed executable mapping"
    );
    Ok(parsed.registration_handoff_lifecycle_cases)
}
fn fixture_path() -> PathBuf {
    if let Some(root) = std::env::var_os("COTEST_SPEC_ARTIFACTS_ROOT") {
        return PathBuf::from(root).join("fixtures").join(FIXTURE);
    }
    if let Some(root) = std::env::var_os("COTEST_SPEC_ROOT") {
        return PathBuf::from(root)
            .join("spec/v1/artifacts/fixtures")
            .join(FIXTURE);
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../arkret-spec/spec/v1/artifacts/fixtures")
        .join(FIXTURE)
}
fn c(name: &str, steps: &[&str], variants: &[&str], expected: &str) -> Case {
    Case {
        name: name.into(),
        steps: steps.iter().map(|v| (*v).into()).collect(),
        variants: variants.iter().map(|v| (*v).into()).collect(),
        expected: expected.into(),
    }
}
fn expected() -> Vec<Case> {
    vec![
        c(
            "exact_replay_after_lost_response",
            &[
                "gateway_durable_commit_active",
                "response_lost",
                "station_replays_identical_body",
            ],
            &[],
            "byte_identical_signed_receipt_and_one_active_installation",
        ),
        c(
            "same_registration_id_different_body_conflicts",
            &[
                "install_active",
                "replay_same_source_and_registration_id_with_different_push_key",
            ],
            &[],
            "duplicate_conflict_and_zero_mutation",
        ),
        c(
            "successor_tombstones_predecessor_atomically",
            &[
                "install_registration_0001",
                "install_registration_0002_superseding_0001",
                "deliver_delayed_install_for_0001",
            ],
            &[],
            "registration_0002_active_and_0001_terminal_without_old_route_revival",
        ),
        c(
            "revoke_wins_over_delayed_install",
            &[
                "commit_revoked_tombstone_for_registration_0001",
                "deliver_delayed_active_body_for_registration_0001",
            ],
            &[],
            "terminal_revoked_and_provider_route_absent",
        ),
        c(
            "source_destination_and_device_are_exact",
            &[],
            &[
                "wrong_source_station",
                "wrong_destination_gateway",
                "wrong_device",
                "wrong_push_target",
                "cross_station_supersedes",
            ],
            "reject_before_route_mutation_or_disclosure",
        ),
        c(
            "tenant_isolation",
            &[],
            &[
                "same_registration_id_from_two_source_stations",
                "same_provider_token_from_two_source_stations",
                "cross_station_admin_or_worker_lookup",
            ],
            "separate_tenant_objects_no_cross_station_index_log_access_or_dedup",
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fixture_mapping_is_closed() {
        validate_push_registration_handoff_fixture().unwrap();
    }
    #[test]
    #[ignore = "requires real PostgreSQL via COTEST_FLORIA_HANDOFF_DATABASE_URL"]
    fn executes_real_lifecycle() {
        let r = run_push_registration_handoff_lifecycle_vector().unwrap();
        assert_eq!(r.cases.len(), 6);
        assert!(r.cases.iter().all(|c| c.assertions > 0));
    }
}
