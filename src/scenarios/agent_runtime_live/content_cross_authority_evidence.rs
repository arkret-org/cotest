//! A real accepted Realm handoff cannot supply an unregistered issuer source.
use super::*;
use crate::scenarios::_helpers::acceptance_footprint::acceptance_rows_with_agent_stores;

pub const REVIEWED_CROSS_AUTHORITY_CONTENT_CASES: [&str; 1] =
    ["cross_authority_source_unregistered"];

pub async fn run_agent_content_cross_authority_production()
-> Result<crate::conformance::SuiteExecutionResult> {
    let fixture = crate::conformance::load_fixture_value("agent-vectors-fixture.json")?;
    let rows = fixture["session_content_authority_contract"]["cases"]
        .as_array()
        .context("canonical content cases")?;
    let matches = rows
        .iter()
        .filter(|row| row["name"] == REVIEWED_CROSS_AUTHORITY_CONTENT_CASES[0])
        .collect::<Vec<_>>();
    ensure!(
        matches.len() == 1
            && matches[0]["input"] == json!({"source_supply_verified":false})
            && matches[0]["expected"] == "deny",
        "review changed cross-authority contract"
    );
    let mut scene = content_grant_evidence::GrantFixture::establish().await?;
    let mut successor = ArkretServer::spawn_with_env(
        "agent-content-successor",
        &[
            ("COLAND_SEED_DEMO_DATA", "0"),
            (
                "COLAND_TRUST_DOMAIN",
                scene.deployment.station.trust_domain().as_str(),
            ),
            ("COLAND_FEDERATION_OUTBOUND", "0"),
        ],
    )
    .await?;
    ensure!(scene.deployment.station.service_id() != successor.service_id());
    let original_url = scene
        .deployment
        .station
        .owned_database_url()
        .context("owning database")?
        .to_owned();
    let successor_url = successor
        .owned_database_url()
        .context("successor database")?
        .to_owned();
    ensure!(original_url != successor_url);
    successor
        .restart_with_federation_peers(&[scene.deployment.station.base_url().to_string()])
        .await?;
    scene
        .deployment
        .station
        .restart_with_federation_peers(&[successor.base_url().to_string()])
        .await?;
    let operations = scene
        .operations
        .iter()
        .map(String::as_str)
        .filter(|action| *action != "ak.message.create")
        .collect::<Vec<_>>();
    let (runtime, claims) = scene.issue_for(&operations, scene.selectors()).await?;
    ensure!(claims.scopes.iter().any(|action| action == "ak.event.read"));
    scene.read_exact(&runtime).await?;
    let (change, changed) =
        crate::scenarios::fanout_route_miss_live::origin_binding_live::activate_realm_successor(
            &scene.deployment.station,
            &mut successor,
            &scene.deployment.controller,
            &scene.deployment.account,
            scene.realm.as_str(),
            &original_url,
            &successor_url,
        )
        .await?;
    ensure!(changed.event_ref == change.event_id);
    for url in [&original_url, &successor_url] {
        let url = url.clone();
        let realm = scene.realm.to_string();
        let governor = successor.service_id().to_string();
        let original = scene.message.clone();
        tokio::task::spawn_blocking(move || -> Result<()> {
            let mut connection = postgres::Client::connect(&url, postgres::NoTls)?;
            let row = connection.query_one("SELECT service_id,generation FROM realm_authorities WHERE realm_id=$1", &[&realm])?;
            ensure!(row.get::<_,String>(0) == governor && row.get::<_,i64>(1) == 1,
                "normal handoff did not install exact successor authority");
            let retained: serde_json::Value = connection.query_one(
                "SELECT e.envelope FROM canonical_events e JOIN realm_commits c ON c.event_pk=e.pk WHERE e.envelope->>'event_id'=$1 AND e.state='committed'",
                &[&original.event_id.as_str()],
            )?.get(0);
            ensure!(retained == serde_json::to_value(original)?, "handoff changed accepted original");
            Ok(())
        }).await??;
    }
    let before = acceptance_rows_with_agent_stores(&original_url, true).await?;
    let incoming_before = acceptance_rows_with_agent_stores(&successor_url, true).await?;
    let request = coauth_session_evidence::build_runtime_session_request(
        &scene.deployment.station,
        scene.deployment.coauth.base_url(),
        &scene.agent.agent_account.principal_id,
        &scene.agent.key_authorization,
        &scene.agent.verification_method,
        &scene.agent.runtime_key,
        &operations,
        scene.selectors(),
    )?;
    coauth_session_evidence::expect_issue_refusal(
        &scene.deployment.station,
        &scene.deployment.coauth.pg.connect_url,
        &format!(
            "{}/_arkret/gate/account/session-grants",
            scene.deployment.coauth.base_url()
        ),
        &request,
        &scene.agent.runtime_key,
        None,
        arkret_wire::ErrorCode::SERVICE_UNAVAILABLE,
        None,
    )
    .await?;
    ensure!(acceptance_rows_with_agent_stores(&original_url, true).await? == before);
    ensure!(acceptance_rows_with_agent_stores(&successor_url, true).await? == incoming_before);
    expect_json(
        scene.agent.runtime.get("/_arkret/self/device_messages"),
        StatusCode::OK,
    )
    .await?;
    println!(
        "[agent-cross-authority] real_coauth=1 prior_same_agent_read_full=1 two_distinct_native_stations=1 complete_private_handoff=1 accepted_governance_change=1 both_authorities_verified_successor=1 original_exact_facts_retained=1 unregistered_source_issue_503=1 complete_issuer_and_both_business_snapshots_unchanged=1 original_runtime_service_session_valid=1"
    );
    Ok(crate::conformance::SuiteExecutionResult {
        entrypoint: "ak.suite.agent.vectors.v1",
        fixture: "agent-vectors-fixture.json",
        cases: vec![crate::conformance::CaseExecutionResult {
            case_id: REVIEWED_CROSS_AUTHORITY_CONTENT_CASES[0].to_owned(),
            assertions: 1,
        }],
    })
}
