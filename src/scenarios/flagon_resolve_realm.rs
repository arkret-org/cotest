//! Live current-v1 `resolve_realm` probe against a fresh read-only Directory.

use std::time::Duration;

use anyhow::{Context, Result, bail};
use arkret_models_discovery::DirectoryResolveRealmRequestBody;
use arkret_wire::{Problem, RealmId, ServiceOperationId};

use crate::scenarios::_helpers::external_binary::{FLAGON_SPEC, spawn_required};

pub async fn flagon_resolve_realm_unknown_is_blinded_run() -> Result<()> {
    let proc = spawn_required(&FLAGON_SPEC)
        .await
        .context("spawn flagon binary for resolve-realm test")?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?;
    let url = proc.url("/_arkret/find/directory/resolve-realm");
    let request = DirectoryResolveRealmRequestBody {
        realm_id: RealmId::new("ak:realm:AZAySZA7XRDeJ9cO4MqaDWrJD-rqPk6Cudk7CCzsDQz1")?,
    };

    let response = client
        .post(&url)
        .header(
            "Arkret-Operation",
            ServiceOperationId::FIND_DIRECTORY_READ_RESOLVE_REALM_V1,
        )
        .json(&request)
        .send()
        .await?;
    let status = response.status();
    let text = response.text().await.unwrap_or_default();
    if status.as_u16() != 404 {
        bail!("unknown Realm must return blinded 404, got {status}: {text}");
    }
    let problem: Problem = serde_json::from_str(&text)
        .with_context(|| format!("resolve-realm 404 response is not JSON: {text}"))?;
    if !problem.code().contains("not_found") {
        bail!(
            "unknown Realm returned unexpected error code: {}",
            problem.code()
        );
    }

    let missing_realm_id = arkret_test_kit::wire_negative_from_sdk(&request, |body| {
        body.as_object_mut()
            .expect("SDK resolve-realm body is an object")
            .remove("realm_id");
    })?;
    let missing = client
        .post(&url)
        .header(
            "Arkret-Operation",
            ServiceOperationId::FIND_DIRECTORY_READ_RESOLVE_REALM_V1,
        )
        .json(&missing_realm_id)
        .send()
        .await?;
    if missing.status().as_u16() != 400 {
        bail!(
            "resolve-realm without realm_id must fail validation, got {}",
            missing.status()
        );
    }
    Ok(())
}
