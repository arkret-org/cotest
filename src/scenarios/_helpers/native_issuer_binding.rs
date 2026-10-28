//! Actual issuer enrollment originals, read without creating authority material.

use anyhow::{Context as _, Result, ensure};
use arkret_models_identity::{AuthenticatedServiceResolution, ServiceMethodState};
use serde_json::{Value, json};

use super::coauth_bootstrap::SpawnedCoauth;
use crate::harness::{ArkretServer, expect_json};

pub(crate) async fn capture(coauth: &SpawnedCoauth, station: &ArkretServer) -> Result<Value> {
    let resolution: AuthenticatedServiceResolution = serde_json::from_value(
        expect_json(
            station.http().get(station.url(&format!(
                "/_arkret/open/services/{}/resolution",
                station.service_id()
            ))),
            reqwest::StatusCode::OK,
        )
        .await?,
    )?;
    arkret_identity::verify_authenticated_service_resolution_history(
        &resolution,
        station.service_id(),
        chrono::Utc::now(),
    )?;
    let configuration: Value =
        serde_saphyr::from_reader(std::fs::File::open(coauth.config.path())?)?;
    let configured = configuration["arkret"]["stations"]
        .as_array()
        .context("native configured Stations")?
        .iter()
        .filter(|entry| {
            entry["endpoint"].as_str().is_some_and(|endpoint| {
                endpoint.trim_end_matches('/') == station.base_url().as_str().trim_end_matches('/')
            })
        })
        .collect::<Vec<_>>();
    let [configured] = configured.as_slice() else {
        anyhow::bail!("native issuer has no unique configured owning endpoint");
    };
    let name = configured["name"]
        .as_str()
        .context("native enrollment name")?
        .to_owned();
    let endpoint = station.base_url().to_string();
    let database = coauth.pg.connect_url.clone();
    let originals = tokio::task::spawn_blocking(move || -> Result<Value> {
        let mut database = postgres::Client::connect(&database, postgres::NoTls)?;
        let mut transaction = database.build_transaction()
            .isolation_level(postgres::IsolationLevel::RepeatableRead).read_only(true).start()?;
        let enrollments = transaction.query(
            "SELECT to_jsonb(e) FROM station_trust_enrollments e WHERE name=$1 OR canonical_endpoint=$2 ORDER BY name",
            &[&name, &endpoint],
        )?.into_iter().map(|row| row.get::<_, Value>(0)).collect::<Vec<_>>();
        let audits = transaction.query(
            "SELECT to_jsonb(a) FROM station_trust_audits a WHERE enrollment_name=$1 ORDER BY created_at,id",
            &[&name],
        )?.into_iter().map(|row| row.get::<_, Value>(0)).collect::<Vec<_>>();
        transaction.commit()?;
        Ok(json!({"configured_name":name,"configured_endpoint":endpoint,
            "enrollments":enrollments,"audits":audits}))
    }).await??;
    let captured = json!({"resolution":resolution,"originals":originals});
    verify(&captured)?;
    Ok(captured)
}

pub(crate) fn verify(captured: &Value) -> Result<ServiceMethodState> {
    let resolution: AuthenticatedServiceResolution =
        serde_json::from_value(captured["resolution"].clone())?;
    arkret_identity::verify_authenticated_service_resolution_history(
        &resolution,
        &resolution.service_id,
        chrono::Utc::now(),
    )?;
    let projection = resolution.projection()?;
    let originals = &captured["originals"];
    let pins = originals["enrollments"]
        .as_array()
        .context("native enrollment originals")?;
    let [pin] = pins.as_slice() else {
        anyhow::bail!("native issuer original pin is not unique");
    };
    ensure!(
        pin["name"] == originals["configured_name"]
            && pin["canonical_endpoint"] == originals["configured_endpoint"]
            && pin["canonical_endpoint"] == json!(projection.base_url)
            && pin["service_id"] == json!(projection.service_id)
            && pin["service_kind"] == "station"
            && pin["did"] == json!(projection.did)
            && pin["method_history_head"] == json!(projection.method_history_head)
            && pin["version_id"] == json!(projection.version_id)
            && pin["source"] == "automatic_verified",
        "actual issuer enrollment disagrees with the complete native Station proof"
    );
    let verified_at = chrono::DateTime::parse_from_rfc3339(
        pin["last_verified_at"]
            .as_str()
            .context("actual pin verification time")?,
    )?
    .with_timezone(&chrono::Utc);
    let enrolled_at = chrono::DateTime::parse_from_rfc3339(
        pin["enrolled_at"]
            .as_str()
            .context("actual pin enrollment time")?,
    )?
    .with_timezone(&chrono::Utc);
    ensure!(
        enrolled_at <= verified_at && verified_at <= chrono::Utc::now(),
        "native issuer pin timestamps are invalid"
    );
    let audits = originals["audits"]
        .as_array()
        .context("actual native enrollment audit")?;
    ensure!(
        audits.iter().any(|audit| audit["action"] == "enrolled"
            && audit["enrollment_name"] == pin["name"]
            && audit["service_id"] == pin["service_id"]),
        "native issuer pin has no actual enrollment audit"
    );
    ensure!(
        audits
            .iter()
            .all(|audit| audit["action"] != "replaced" && audit["action"] != "revoked"),
        "native issuer accepted a replaced or revoked enrollment"
    );
    Ok(ServiceMethodState {
        service_id: projection.service_id,
        service_kind: projection.service_kind,
        did: projection.did,
        method_history_head: projection.method_history_head,
        version_id: projection.version_id,
        verified_at,
    })
}
