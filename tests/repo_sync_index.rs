mod support;

use anyhow::Result;
use contrix_sdk::{Commit, CommitId, Did, Operation, OperationId, SpaceId};
use reqwest::StatusCode;
use serde_json::json;
use serial_test::serial;

use support::{ServerxInstance, expect_api_error, expect_json, message_operation, signed_commit};

#[tokio::test]
#[serial]
async fn repo_submit_read_expand_idempotency_and_cas_edges() -> Result<()> {
    let server = ServerxInstance::spawn("repo-workflow").await?;
    let op1 = message_operation(
        "cx:operation:repo-workflow-01",
        "cx:space:repo-workflow",
        "did:web:alice.example",
        "repo workflow one",
    )?;
    let commit1 = signed_commit(
        "cx:commit:repo-workflow-01",
        "did:web:alice.example",
        1,
        std::slice::from_ref(&op1),
        None,
    )?;

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
    let head = submitted["head_commit"].as_str().unwrap().to_owned();
    assert_eq!(submitted["status"], "accepted");

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
    assert_eq!(duplicate["head_commit"], head);

    let expanded = expect_json(
        server.http().get(server.url(
            "/api/v1/repo/commit?commit_id=cx:commit:repo-workflow-01&include_operations=true",
        )),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        expanded["operations"][0]["operation_id"],
        "cx:operation:repo-workflow-01"
    );

    let op2 = message_operation(
        "cx:operation:repo-workflow-02",
        "cx:space:repo-workflow",
        "did:web:alice.example",
        "repo workflow two",
    )?;
    let commit2 = signed_commit(
        "cx:commit:repo-workflow-02",
        "did:web:alice.example",
        2,
        std::slice::from_ref(&op2),
        Some(&head),
    )?;
    expect_api_error(
        server
            .http()
            .post(server.url("/api/v1/repo/submit-commit"))
            .json(&json!({
                "repo_id": "did:web:alice.example",
                "expected_head": null,
                "operations": [op2],
                "commit": commit2
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

#[tokio::test]
#[serial]
async fn repo_rejects_unsigned_unknown_family_and_repo_mismatch() -> Result<()> {
    let server = ServerxInstance::spawn("repo-rejection").await?;

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

    let mismatch_op = message_operation(
        "cx:operation:repo-mismatch",
        "cx:space:repo-rejection",
        "did:web:alice.example",
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

#[tokio::test]
#[serial]
async fn sync_directory_and_index_parameter_edges_are_enforced() -> Result<()> {
    let server = ServerxInstance::spawn("sync-index-edges").await?;

    expect_api_error(
        server.http().get(server.url("/api/v1/sync/subscribe")),
        StatusCode::BAD_REQUEST,
        "missing_param",
    )
    .await?;
    expect_api_error(
        server
            .http()
            .get(server.url("/api/v1/sync/subscribe?space_id=bad")),
        StatusCode::BAD_REQUEST,
        "invalid_param",
    )
    .await?;
    expect_api_error(
        server.http().get(server.url("/api/v1/sync/backfill")),
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
