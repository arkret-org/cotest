use anyhow::{Context, Result, ensure};
use chrono::{Duration, Utc};
use cotest::harness::expect_response;
use cotest::scenarios::identity_test_support::{
    actor_did_for_service_did, spawn_with_harness_account_authority,
};
use reqwest::StatusCode;
use serde_json::json;

const VERIFIER: &str = "ak:did_core:web:verifier.example";

fn create_payload(token_byte: char) -> serde_json::Value {
    json!({
        "third_party_invite": {
            "oob_code_kind": "offline_token",
            "token_commitment": format!("sha256:{}", token_byte.to_string().repeat(64)),
            "token_salt_id": "salt-cotest-2162",
            "token_entropy_bits": 128,
            "max_claims": 1,
            "verification_id": VERIFIER,
            "verification_public_key": "did:web:verifier.example#invite-1"
        },
        "expires_at": arkret_canonical::format_timestamp_canonical(Utc::now() + Duration::hours(12))
    })
}

#[tokio::test]
async fn third_party_invite_create_requires_current_allowlist() -> Result<()> {
    let server = spawn_with_harness_account_authority("third-party-invite-create", &[]).await?;
    let alice_did = actor_did_for_service_did(server.service_did(), "third-party-create-alice")?;
    let alice = server
        .standard_client(&alice_did, "ak:device:01904100-0000-7000-8000-00000000c621")
        .await?;

    let denied_realm = alice.create_realm("3PID deny-all").await?;
    let denied_event = alice
        .author_event(&denied_realm, "ak.invite.third_party", create_payload('a'))
        .await?;
    let denied = expect_response(
        alice
            .post("/_arkret/self/events")
            .json(&cotest::publication::initial_submission(
                denied_event.clone(),
                "",
            )?),
        StatusCode::FORBIDDEN,
    )
    .await?;
    let problem: arkret_wire::Problem = serde_json::from_value(denied.json()?)?;
    ensure!(
        problem.code() == "capability_denied",
        "unexpected refusal: {problem:?}"
    );

    let created_realm = alice
        .create_realm_with(json!({
            "title": "3PID allowlisted",
            "summary": "3PID allowlisted",
            "public": false,
            "plaintext_visible_services": [server.service_id()],
            "allowed_third_party_invite_verification_ids": [VERIFIER]
        }))
        .await?;
    let realm_id = created_realm["realm_id"]
        .as_str()
        .context("created Realm lacks realm_id")?;
    let event = alice
        .author_event(realm_id, "ak.invite.third_party", create_payload('b'))
        .await?;
    let submission = cotest::publication::initial_submission(event.clone(), "")?;
    let accepted = cotest::harness::expect_json(
        alice.post("/_arkret/self/events").json(&submission),
        StatusCode::OK,
    )
    .await?;
    ensure!(
        accepted["status"] == "committed",
        "create did not commit: {accepted}"
    );
    ensure!(accepted["commit"]["event_ref"] == event.event_id.as_str());
    let replay = cotest::harness::expect_json(
        alice.post("/_arkret/self/events").json(&submission),
        StatusCode::OK,
    )
    .await?;
    ensure!(
        replay["status"] == "duplicate",
        "exact replay did not dedupe: {replay}"
    );
    ensure!(replay["commit"] == accepted["commit"]);
    Ok(())
}
