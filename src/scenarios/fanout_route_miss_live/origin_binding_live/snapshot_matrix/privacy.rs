//! Unknown and hidden private streams have the same public refusal per role.

use super::*;

pub(super) async fn assert_hidden_scans(
    fixture: &CurrentOriginFixture,
    streams: &[CommitStreamRef],
    governor: usize,
) -> Result<()> {
    let unknown =
        arkret_wire::EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [0xe7; 32]);
    for stream in streams {
        let missing = match stream {
            CommitStreamRef::Circle { realm_id, .. } => CommitStreamRef::Circle {
                realm_id: realm_id.clone(),
                circle_id: arkret_wire::CircleId::from_event_id(&unknown),
            },
            CommitStreamRef::Sidecar { realm_id, .. } => CommitStreamRef::Sidecar {
                realm_id: realm_id.clone(),
                sidecar_id: arkret_wire::SidecarId::from_event_id(&unknown),
            },
            _ => bail!("private scan requires a Circle or Sidecar"),
        };
        for peer in [false, true] {
            let mut failures = Vec::new();
            for requested in [stream.clone(), missing.clone()] {
                let request = StreamScanRequest {
                    realm_id: requested.realm_id().clone(),
                    stream_ref: requested,
                    direction: StreamScanDirection::After(None),
                    limit: 2,
                };
                let mut problem = if peer {
                    let serving = fixture.group.server(governor);
                    let (status, body) = serving
                        .signed_peer_post(
                            fixture.group.server(1),
                            "/_arkret/peer/streams/scan",
                            &arkret_canonical::canonical_json_bytes(&request)?,
                            serving.service_id(),
                        )
                        .await?;
                    let value: serde_json::Value = serde_json::from_slice(&body)?;
                    ensure!(
                        status == StatusCode::FORBIDDEN,
                        "private peer scan {status}: {value}"
                    );
                    ensure!(value["type"] == "https://arkret.org/problems/capability_denied");
                    value
                } else {
                    // Circle replicas require a held opening proof. Native
                    // Sidecars first require independent controller/recipient
                    // authority; the parent Realm cannot grant that authority.
                    let (status, code) = match stream {
                        CommitStreamRef::Circle { .. } => {
                            (StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable")
                        }
                        CommitStreamRef::Sidecar { .. } => {
                            (StatusCode::FORBIDDEN, "capability_denied")
                        }
                        _ => unreachable!(),
                    };
                    let value = expect_json(
                        fixture
                            .bob
                            .post("/_arkret/self/streams/scan")
                            .canonical_json(&request)?,
                        status,
                    )
                    .await?;
                    ensure!(value["type"] == format!("https://arkret.org/problems/{code}"));
                    value
                };
                ensure!(
                    problem.get("committed_events").is_none()
                        && problem.get("readable_floor").is_none()
                        && problem.get("producer_signer_facts").is_none()
                );
                ensure!(problem["instance"].as_str().is_some());
                problem
                    .as_object_mut()
                    .context("closed Problem")?
                    .remove("instance");
                failures.push(problem);
            }
            ensure!(
                failures[0] == failures[1],
                "unknown and hidden private scan leaked existence: {failures:?}"
            );
        }
    }
    println!(
        "[2133-private-scan] governor_index={governor} circle_and_sidecar=1 member_circle_unproved_503=1 member_sidecar_denied_403=1 peer_denied_403=1 unknown_matches_hidden=1 zero_physical_pages=1"
    );
    Ok(())
}
