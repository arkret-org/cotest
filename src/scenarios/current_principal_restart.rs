//! Live current-principal continuity across index eviction and process restart.

use anyhow::{Context, Result};
use arkret_models_identity::{CurrentPrincipalOutcome, CurrentPrincipalRequestBody};
use arkret_wire::{AccountId, RequestId};
use reqwest::StatusCode;

use crate::harness::{ArkretServer, expect_json};
use crate::scenarios::identity_test_support::actor_did_for_service_did;

async fn read_current(
    client: &crate::harness::TestActorClient,
    request: &CurrentPrincipalRequestBody,
) -> Result<(serde_json::Value, CurrentPrincipalOutcome)> {
    let value = expect_json(
        client
            .post("/_arkret/self/account/current-principal")
            .json(request),
        StatusCode::OK,
    )
    .await?;
    let keys = value
        .as_object()
        .context("current-principal outcome is not an object")?
        .keys()
        .map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>();
    anyhow::ensure!(
        keys == std::collections::BTreeSet::from([
            "account_id",
            "principal_control_realm_id",
            "request_id",
            "resolution_projection",
        ]),
        "current-principal outcome is not the closed four-field carrier: {value}"
    );
    let outcome: CurrentPrincipalOutcome = serde_json::from_value(value.clone())?;
    outcome.validate_for_request(request)?;
    Ok((value, outcome))
}

pub async fn current_principal_survives_index_eviction_and_restart() -> Result<()> {
    let ephemeral = crate::scenarios::_helpers::coauth_bootstrap::spawn_ephemeral_postgres_for(
        "COTEST_SOLAND_DATABASE_URL",
    )?
    .context("current-principal live row requires isolated PostgreSQL")?;
    let database_url = ephemeral.connect_url.clone();
    let keystore_dir = tempfile::tempdir()?;
    let keystore_path = keystore_dir
        .path()
        .join("soland.v1")
        .to_string_lossy()
        .into_owned();
    let keystore_env = [
        ("SOLAND_KEYSTORE_BACKEND", "encrypted_file"),
        ("SOLAND_KEYSTORE_PATH", keystore_path.as_str()),
        (
            "SOLAND_KEYSTORE_MASTER_KEY",
            "UlJSUlJSUlJSUlJSUlJSUlJSUlJSUlJSUlJSUlJSUlI=",
        ),
    ];
    let mut server = ArkretServer::spawn_with_database_url(
        "current-principal-restart",
        &database_url,
        &keystore_env,
    )
    .await?;
    let actor = actor_did_for_service_did(server.service_did(), "current-principal-alice")?;
    let client = server
        .register_client(
            &actor,
            "current-principal-alice",
            "ak:device:01904100-0000-7000-8000-0000000000c1",
        )
        .await?;
    let principal = client
        .principal
        .as_ref()
        .context("registered live client omitted its PCR")?;
    let account_id = AccountId::new(principal.core_id.clone(), server.service_id().clone());
    let request = CurrentPrincipalRequestBody {
        request_id: RequestId::new("ak:request:01904100-0000-7000-8000-0000000000c1")?,
        account_id: account_id.clone(),
    };
    let (initial_value, initial) = read_current(&client, &request)
        .await
        .context("read current-principal after registration")?;
    anyhow::ensure!(
        initial.principal_control_realm_id == principal.pcr_realm_id,
        "registration and current-principal selected different PCRs"
    );

    let principal_id = account_id.principal_id.to_string();
    let station_id = account_id.station_id.to_string();
    let database_url_for_delete = database_url.clone();
    let (before, deleted, after) = tokio::task::spawn_blocking(move || -> Result<(i64, u64, i64)> {
        let mut database = postgres::Client::connect(&database_url_for_delete, postgres::NoTls)?;
        let before: i64 = database
            .query_one(
                "SELECT COUNT(*) FROM principal_resolutions WHERE principal_id=$1 AND station_id=$2",
                &[&principal_id, &station_id],
            )?
            .get(0);
        let deleted = database.execute(
            "DELETE FROM principal_resolutions WHERE principal_id=$1 AND station_id=$2",
            &[&principal_id, &station_id],
        )?;
        let after: i64 = database
            .query_one(
                "SELECT COUNT(*) FROM principal_resolutions WHERE principal_id=$1 AND station_id=$2",
                &[&principal_id, &station_id],
            )?
            .get(0);
        Ok((before, deleted, after))
    })
    .await??;
    anyhow::ensure!(
        before == 1 && deleted == 1 && after == 0,
        "live index eviction did not remove exactly one principal_resolutions row"
    );
    let (after_eviction_value, after_eviction) = read_current(&client, &request)
        .await
        .context("read current-principal after evicting its index")?;
    anyhow::ensure!(
        after_eviction == initial && after_eviction_value == initial_value,
        "current-principal changed after evicting its replaceable index"
    );

    server.restart_external_process().await?;
    let (after_restart_value, after_restart) = read_current(&client, &request)
        .await
        .context("read current-principal after restart")?;
    anyhow::ensure!(
        after_restart == initial && after_restart_value == initial_value,
        "current-principal changed after process restart with the index absent"
    );
    Ok(())
}
