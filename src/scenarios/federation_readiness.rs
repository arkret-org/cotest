use anyhow::Result;
use reqwest::StatusCode;

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
        server_a.http().get(server_a.url("/_arkret/describe")),
        StatusCode::OK,
    )
    .await?;
    let describe_b = expect_json(
        server_b.http().get(server_b.url("/_arkret/describe")),
        StatusCode::OK,
    )
    .await?;
    assert_ne!(server_a.service_id(), server_b.service_id());
    assert_eq!(describe_a["service_kind"], "station");
    assert_eq!(describe_b["service_kind"], "station");

    // Federation readiness is resolving the other Station's own service DID
    // over its published DID method; a fixed `did:web` of a reserved example
    // domain has nothing to fetch and correctly fails closed.
    let peer_did = server_b.service_did().as_str().to_owned();
    let resolve = expect_json(
        server_a
            .http()
            .post(server_a.url("/_arkret/root/identity/resolve"))
            .json(
                &arkret_models_identity::identity::IdentityResolveRequestBody {
                    did: arkret_wire::Did::new(peer_did.clone())?,
                    requested_evidence_kinds: Vec::new(),
                },
            ),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(resolve["did_document"]["id"], peer_did.as_str());

    Ok(())
}
