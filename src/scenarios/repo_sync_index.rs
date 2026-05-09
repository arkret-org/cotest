use anyhow::Result;
use contrix_core::{Commit, CommitId, Did, Operation, OperationId, SpaceId};
use reqwest::StatusCode;
use serde_json::json;

use crate::harness::{
    ContrixServer, expect_api_error, expect_json, repo_message_operation, signed_commit,
};

pub async fn repo_submit_read_expand_idempotency_and_cas_edges() -> Result<()> {
    let server = ContrixServer::spawn("repo-workflow").await?;
    let op1 = repo_message_operation(
        "cx:operation:adapter-01",
        "cx:event:adapter-01",
        "cx:space:adapter",
        "did:web:alice.example",
        "cx:thread:adapter",
        "hello",
    )?;
    let commit1 = signed_commit(
        "cx:commit:adapter-01",
        "did:web:alice.example",
        1,
        std::slice::from_ref(&op1),
        None,
    )?;
    let head_commit = commit1.commit_digest()?;

    let submitted = expect_json(
        server
            .http()
            .post(server.url("/api/v1/repo/submit-commit"))
            .json(&json!({
                "repo_id": "did:web:alice.example",
                "expected_head": null,
                "operations": [op1.clone()],
                "commit": commit1.clone()
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(submitted["status"], "accepted");
    assert_eq!(submitted["head_commit"], head_commit);

    let duplicate = expect_json(
        server
            .http()
            .post(server.url("/api/v1/repo/submit-commit"))
            .json(&json!({
                "repo_id": "did:web:alice.example",
                "expected_head": null,
                "operations": [op1],
                "commit": commit1
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(duplicate["head_commit"], head_commit);

    let describe = expect_json(
        server
            .http()
            .get(server.url("/api/v1/repo/describe?repo_id=did:web:alice.example")),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(describe["repo_did"], "did:web:alice.example");
    assert_eq!(describe["head_commit"], head_commit);

    let commits = expect_json(
        server
            .http()
            .get(server.url("/api/v1/repo/commits?repo_id=did:web:alice.example&limit=1")),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(commits["commits"].as_array().unwrap().len(), 1);

    let commit = expect_json(
        server
            .http()
            .get(server.url("/api/v1/repo/commit?commit_id=cx:commit:adapter-01")),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(commit["commit"]["commit_id"], "cx:commit:adapter-01");
    assert!(commit["operations"].as_array().unwrap().is_empty());

    let expanded = expect_json(
        server.http().get(
            server
                .url("/api/v1/repo/commit?commit_id=cx:commit:adapter-01&include_operations=true"),
        ),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        expanded["operations"][0]["operation_id"],
        "cx:operation:adapter-01"
    );

    let operations = expect_json(
        server
            .http()
            .post(server.url("/api/v1/repo/operations"))
            .json(&json!({"operation_ids": ["cx:operation:adapter-01"]})),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(operations["operations"].as_array().unwrap().len(), 1);

    let sync = expect_json(
        server
            .http()
            .post(server.url("/api/v1/repo/sync"))
            .json(&json!({
                "repo_id": "did:web:alice.example",
                "since": null,
                "limit": 1,
                "filters": null
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(sync["operations"].as_array().unwrap().len(), 1);

    let mut stale_commit = Commit::new(
        CommitId::new("cx:commit:adapter-02".to_owned())?,
        "did:web:alice.example",
        Did::new("did:web:alice.example".to_owned())?,
        2,
    );
    stale_commit
        .proofs
        .push(crate::harness::dummy_proof("did:web:alice.example"));
    expect_api_error(
        server
            .http()
            .post(server.url("/api/v1/repo/submit-commit"))
            .json(&json!({
                "repo_id": "did:web:alice.example",
                "expected_head": null,
                "commit": stale_commit
            })),
        StatusCode::CONFLICT,
        "cas_conflict",
    )
    .await?;

    expect_api_error(
        server.http().get(server.url("/api/v1/repo/commit")),
        StatusCode::BAD_REQUEST,
        "missing_param",
    )
    .await?;
    expect_api_error(
        server
            .http()
            .get(server.url("/api/v1/repo/commit?commit_id=not-a-commit")),
        StatusCode::BAD_REQUEST,
        "invalid_param",
    )
    .await?;
    expect_api_error(
        server
            .http()
            .get(server.url("/api/v1/repo/commit?commit_id=cx:commit:missing")),
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await?;

    Ok(())
}

pub async fn repo_rejects_unsigned_unknown_family_and_repo_mismatch() -> Result<()> {
    let server = ContrixServer::spawn("repo-rejection").await?;

    let unsigned = Commit::new(
        CommitId::new("cx:commit:repo-unsigned".to_owned())?,
        "did:web:alice.example",
        Did::new("did:web:alice.example".to_owned())?,
        1,
    );
    expect_api_error(
        server
            .http()
            .post(server.url("/api/v1/repo/submit-commit"))
            .json(&json!({
                "repo_id": "did:web:alice.example",
                "expected_head": null,
                "operations": [],
                "commit": unsigned
            })),
        StatusCode::CONFLICT,
        "duplicate_conflict",
    )
    .await?;

    let bad_operation = Operation::create(
        OperationId::new("cx:operation:repo-bad-family".to_owned())?,
        SpaceId::new("cx:space:repo-rejection".to_owned())?,
        "unknown.family",
        json!({"body": "bad"}),
    );
    let bad_commit = signed_commit(
        "cx:commit:repo-bad-family",
        "did:web:alice.example",
        1,
        std::slice::from_ref(&bad_operation),
        None,
    )?;
    expect_api_error(
        server
            .http()
            .post(server.url("/api/v1/repo/submit-commit"))
            .json(&json!({
                "repo_id": "did:web:alice.example",
                "expected_head": null,
                "operations": [bad_operation],
                "commit": bad_commit
            })),
        StatusCode::BAD_REQUEST,
        "invalid_param",
    )
    .await?;

    let mismatch_op = repo_message_operation(
        "cx:operation:repo-mismatch",
        "cx:event:repo-mismatch",
        "cx:space:repo-rejection",
        "did:web:alice.example",
        "cx:thread:repo-rejection",
        "mismatch",
    )?;
    let mismatch_commit = signed_commit(
        "cx:commit:repo-mismatch",
        "did:web:alice.example",
        1,
        std::slice::from_ref(&mismatch_op),
        None,
    )?;
    expect_api_error(
        server
            .http()
            .post(server.url("/api/v1/repo/submit-commit"))
            .json(&json!({
                "repo_id": "did:web:bob.example",
                "expected_head": null,
                "operations": [mismatch_op],
                "commit": mismatch_commit
            })),
        StatusCode::CONFLICT,
        "duplicate_conflict",
    )
    .await?;

    Ok(())
}

pub async fn sync_directory_and_index_parameter_edges_are_enforced() -> Result<()> {
    let server = ContrixServer::spawn("sync-index-edges").await?;

    // C17 (spec 2026-05-08): cx.sync.subscribe → cx.events.subscribe at
    // /api/v1/events/subscribe; cx.sync.backfill folded into cx.events.query
    // at /api/v1/events.
    expect_api_error(
        server.http().get(server.url("/api/v1/events/subscribe")),
        StatusCode::BAD_REQUEST,
        "missing_param",
    )
    .await?;
    expect_api_error(
        server
            .http()
            .get(server.url("/api/v1/events/subscribe?spaces=bad")),
        StatusCode::BAD_REQUEST,
        "invalid_param",
    )
    .await?;
    expect_api_error(
        server.http().get(server.url("/api/v1/events")),
        StatusCode::BAD_REQUEST,
        "missing_param",
    )
    .await?;
    expect_api_error(
        server
            .http()
            .get(server.url("/api/v1/sync/snapshot-head?space_id=cx:space:missing")),
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await?;
    expect_api_error(
        server
            .http()
            .post(server.url("/api/v1/directory/resolve-space"))
            .json(&json!({})),
        StatusCode::BAD_REQUEST,
        "missing_param",
    )
    .await?;
    expect_api_error(
        server.http().get(server.url("/api/v1/index/entity")),
        StatusCode::BAD_REQUEST,
        "missing_param",
    )
    .await?;
    expect_api_error(
        server
            .http()
            .get(server.url("/api/v1/index/thread?thread_id=")),
        StatusCode::BAD_REQUEST,
        "invalid_param",
    )
    .await?;
    expect_api_error(
        server
            .http()
            .post(server.url("/api/v1/index/search"))
            .json(&json!({"query": ""})),
        StatusCode::BAD_REQUEST,
        "missing_param",
    )
    .await?;
    expect_api_error(
        server
            .http()
            .get(server.url("/api/v1/index/notifications?actor=bad")),
        StatusCode::BAD_REQUEST,
        "invalid_param",
    )
    .await?;

    Ok(())
}
