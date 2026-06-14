use anyhow::Result;
use reqwest::StatusCode;
use serde_json::json;

use crate::fixtures::TestScaffold;
use crate::harness::expect_json;

pub async fn two_sut_instances_are_isolated_and_federation_ready() -> Result<()> {
    // CT-12: fresh_multi spawns two isolated soland processes with
    // distinct service DIDs, ports, and blob roots — see
    // fixtures::scaffold module docs for the full isolation audit.
    let scaffold = TestScaffold::fresh_multi("federation-ready", 2).await?;
    assert_eq!(scaffold.len(), 2);

    let server_a = scaffold.server(0);
    let server_b = scaffold.server(1);

    let describe_a = expect_json(
        server_a.http().get(server_a.url("/_cokret/describe")),
        StatusCode::OK,
    )
    .await?;
    let describe_b = expect_json(
        server_b.http().get(server_b.url("/_cokret/describe")),
        StatusCode::OK,
    )
    .await?;
    assert_ne!(server_a.service_did(), server_b.service_did());
    assert_eq!(describe_a["service_type"], "principal_server");
    assert_eq!(describe_b["service_type"], "principal_server");

    let resolve = expect_json(
        server_a
            .http()
            .post(server_a.url("/_cokret/root/identity/resolve"))
            .json(&json!({"did": "did:web:alice.example"})),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        resolve["did_document"]["document"]["id"],
        "did:web:alice.example"
    );

    Ok(())
}
