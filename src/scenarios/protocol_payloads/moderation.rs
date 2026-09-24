//! Phase 10 — `/_arkret/self/moderation/report` submission.

use anyhow::Result;
use arkret_wire::ScopeRef;
use reqwest::StatusCode;

use crate::harness::{
    ArkretServer, TestActorClient, expect_api_error, expect_json, moderation_report_request,
};

pub async fn run(
    server: &ArkretServer,
    actor: &TestActorClient,
    target_realm_id: &str,
    target_event_id: &str,
) -> Result<()> {
    let realm_id = arkret_identifiers::RealmId::new(target_realm_id.to_owned())?;
    let request = moderation_report_request(
        actor,
        target_realm_id,
        target_event_id,
        ScopeRef::Realm { realm_id },
    )
    .await?;
    let report = expect_json(
        actor
            .authorize(
                server
                    .http()
                    .post(server.url("/_arkret/self/moderation/report")),
            )
            .json(&request),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(report["status"], "submitted");

    // Exact replay of the accepted report Event returns the stored outcome.
    let replay = expect_json(
        actor
            .authorize(
                server
                    .http()
                    .post(server.url("/_arkret/self/moderation/report")),
            )
            .json(&request),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(replay, report);

    // An absent target is the single anti-oracle not_found with zero writes.
    let absent = arkret_wire::EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        arkret_canonical::sha256_bytes(b"protocol-payloads-absent-report-target"),
    );
    let absent_request = moderation_report_request(
        actor,
        target_realm_id,
        absent.as_str(),
        ScopeRef::Realm {
            realm_id: arkret_identifiers::RealmId::new(target_realm_id.to_owned())?,
        },
    )
    .await?;
    expect_api_error(
        actor
            .authorize(
                server
                    .http()
                    .post(server.url("/_arkret/self/moderation/report")),
            )
            .json(&absent_request),
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await?;
    Ok(())
}
