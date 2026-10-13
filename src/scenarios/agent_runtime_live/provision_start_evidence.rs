//! Real provision prerequisites before any Agent inception or private key.

use super::*;
use crate::scenarios::_helpers::acceptance_footprint::acceptance_rows_with_agent_stores;

pub async fn run_agent_provision_prerequisites_boundary() -> Result<()> {
    let name = "agent-provision-prerequisites-production";
    let database = database(name)?.context("real PostgreSQL required")?;
    let coauth = MockCoauthIntrospectionServer::spawn_with_internal_secret(
        HARNESS_INTERNAL_AUTHORITY_SECRET,
    )
    .await?;
    let group = TestServerGroup::try_multi_external_with_node_envs(
        name,
        &[station_env(&database.connect_url, &coauth)],
    )
    .await?
    .context("current real Station process required")?;
    let station = group.server(0);
    let (controller, account) = standard_client(
        station,
        &coauth,
        "provision-prerequisite-controller",
        CONTROLLER_DEVICE,
    )
    .await?;
    // This is a parse-only identifier. No Agent key or DID operation exists.
    let unpublished = Did::new("did:web:agent-not-created.example")?;
    let request = AgentProvisionRequestBody::Prepare(AgentProvisionPrepareRequestBody {
        phase: AgentProvisionPreparePhase::Prepare,
        operation_id: ProtocolOperationId::new(format!("ak:operation:{}", unique_uuid7()))
            .map_err(anyhow::Error::msg)?,
        idempotency_key: IdempotencyKey::new(unique_uuid7()).map_err(anyhow::Error::msg)?,
        did: unpublished.clone(),
        slug: "prerequisite-agent".to_owned(),
        requested_scope: requested_scope(&runtime_operations())?,
        pairing_ttl_ms: None,
        controller_station_id: account.station_id.clone(),
    });
    let before = acceptance_rows_with_agent_stores(&database.connect_url, true).await?;
    let problem = crate::harness::expect_api_error(
        controller.post("/_arkret/self/agents").json(&request),
        StatusCode::CONFLICT,
        arkret_wire::ErrorCode::FAILED_PRECONDITION,
    )
    .await?;
    ensure!(
        problem.detail.contains("recovery policy"),
        "provision did not reject recovery before DID resolution: {problem:?}"
    );
    ensure!(
        acceptance_rows_with_agent_stores(&database.connect_url, true).await? == before,
        "missing recovery policy wrote accepted Agent/PCR/accountability/selector/pairing/grant state"
    );
    let url = database.connect_url.clone();
    let controller_actor = serde_json::to_value(ActorId::account(account.clone()))?;
    let reservations: i64 = tokio::task::spawn_blocking(move || -> Result<i64> {
        let mut db = postgres::Client::connect(&url, postgres::NoTls)?;
        Ok(db.query_one("SELECT count(*) FROM idempotency_keys WHERE operation_id='ak.self.agent.command.provision' AND authenticated_actor=$1", &[&controller_actor])?.get(0))
    }).await??;
    ensure!(
        reservations == 0,
        "missing recovery policy allocated a provision reservation"
    );
    Ok(())
}
