//! Actual Account Authority hard logout and immutable principal authority.
use ed25519_dalek::SigningKey;

use super::*;

type Deployment =
    crate::scenarios::agent_runtime_live::coauth_session_evidence::ActualAgentDeployment;

async fn authority_state(deployment: &Deployment, realm: &arkret_wire::RealmId) -> Result<Value> {
    let database = deployment
        .station
        .owned_database_url()
        .context("native Station database")?
        .to_owned();
    let actor = deployment.account.principal_id.to_string();
    let realm = realm.to_string();
    tokio::task::spawn_blocking(move || -> Result<Value> {
        let mut db = postgres::Client::connect(&database, postgres::NoTls)?;
        let row = db.query_one("SELECT (SELECT COALESCE(jsonb_agg(to_jsonb(e) ORDER BY pk),'[]'::jsonb) FROM canonical_events e WHERE realm_id=$1),(SELECT COALESCE(jsonb_agg(to_jsonb(c) ORDER BY commit_id),'[]'::jsonb) FROM realm_commits c WHERE realm_id=$1),(SELECT COALESCE(jsonb_agg(to_jsonb(d) ORDER BY device_id),'[]'::jsonb) FROM devices d WHERE actor_id=$2),(SELECT COALESCE(jsonb_agg(to_jsonb(s) ORDER BY record_id),'[]'::jsonb) FROM account_status_replica_records s)", &[&realm,&actor])?;
        Ok(json!({"events":row.get::<_,Value>(0),"commits":row.get::<_,Value>(1),"devices":row.get::<_,Value>(2),"account_status_records":row.get::<_,Value>(3)}))
    }).await?
}

pub(super) async fn exercise(
    deployment: &Deployment,
    issued: &str,
    refreshed: &str,
    holder: &SigningKey,
    audit: &arkret_models_identity::PrincipalResolutionAuditEvidence,
) -> Result<Value> {
    let before = authority_state(deployment, &audit.principal_control_realm_id).await?;
    ensure!(
        !before["devices"]
            .as_array()
            .context("device inventory")?
            .is_empty(),
        "no actual authorized Device before logout"
    );
    let path = "/_arkret/gate/account/logout";
    let operation = "ak.gate.account.command.logout.v1";
    let request = arkret_models_identity::AccountLogoutRequestBody::default();
    let accepted =
        super::session_grants::post(deployment, path, operation, refreshed, holder, &request)
            .await?;
    let accepted_typed: arkret_models_identity::AccountLogoutResponseBody =
        serde_json::from_value(accepted.clone())?;
    ensure!(
        accepted_typed.revoked,
        "first native hard logout did not terminate its lineage"
    );
    let replay =
        super::session_grants::post(deployment, path, operation, refreshed, holder, &request)
            .await?;
    let replay_typed: arkret_models_identity::AccountLogoutResponseBody =
        serde_json::from_value(replay.clone())?;
    ensure!(
        !replay_typed.revoked,
        "completed native logout replay repeated its invocation effect"
    );
    let after = authority_state(deployment, &audit.principal_control_realm_id).await?;
    ensure!(
        before == after,
        "hard logout changed immutable principal authority or durable Device authorization"
    );
    let issuer_database = deployment.coauth.pg.connect_url.clone();
    let tokens = [issued.to_owned(), refreshed.to_owned()];
    let issuer = tokio::task::spawn_blocking(move || -> Result<Value> {
        let mut db=postgres::Client::connect(&issuer_database,postgres::NoTls)?;
        let mut originals=Vec::new();
        for token in tokens {
            let row=db.query_one("SELECT to_jsonb(g),to_jsonb(s),o.canonical_outcome FROM oauth_session_grants g JOIN user_sessions s ON s.id=g.user_session_id JOIN oauth_session_grant_operations o ON o.id=g.issuance_operation_id WHERE g.grant_jwt=$1",&[&token])?;
            let bytes:Vec<u8>=row.get(2);
            originals.push(json!({"grant":row.get::<_,Value>(0),"browser_session":row.get::<_,Value>(1),"canonical_outcome_base64url":arkret_canonical::base64url_encode(&bytes),"canonical_outcome":serde_json::from_slice::<Value>(&bytes)?}));
        }
        ensure!(originals[1]["grant"]["lifecycle_state"]=="revoked" && originals[1]["grant"]["revoked_at"].is_string(),"issuer did not durably revoke the actual successor");
        ensure!(originals.iter().all(|row|row["browser_session"]["finished_at"].is_string()),"logout retained a live underlying browser session");
        Ok(json!(originals))
    }).await??;
    let station_database = deployment
        .station
        .owned_database_url()
        .context("native Station database")?
        .to_owned();
    let account = json!(deployment.account);
    let device = deployment
        .controller
        .principal
        .as_ref()
        .context("actual Device")?
        .device_id
        .to_string();
    let journal=tokio::task::spawn_blocking(move || -> Result<Value> {
        let mut db=postgres::Client::connect(&station_database,postgres::NoTls)?;
        let row=db.query_one("SELECT to_jsonb(j) FROM push_hard_logout_journal j WHERE account_id=$1 AND device_id=$2",&[&account,&device])?;
        Ok(row.get(0))
    }).await??;
    ensure!(
        journal["auth_side_confirmed"] == true && journal["completed_at"].is_string(),
        "logout response preceded durable two-authority completion"
    );
    Ok(
        json!({"accepted":accepted,"replay":replay,"issuer_originals":issuer,"journal":journal,"principal_authority_before":before,"principal_authority_after":after}),
    )
}

pub(super) fn verify(
    observations: &NativeOperationObservations,
    evidence: &Value,
    claims: &Value,
) -> Result<()> {
    let claims: arkret_models_identity::SignedSessionGrantClaims =
        serde_json::from_value(claims.clone())?;
    let token = evidence["issuer_originals"][1]["grant"]["grant_jwt"]
        .as_str()
        .context("actual issuer credential original")?;
    let expected = claims.session_public_key.thumbprint_sha256()?;
    let issuer: reqwest::Url = original_exchange(
        observations,
        "ak.gate.account.command.issue_session_grant.v1",
    )?
    .url
    .parse()?;
    let mut seen = std::collections::BTreeSet::new();
    for exchange in observations
        .exchanges
        .iter()
        .filter(|row| row.operation_id.as_str() == "ak.gate.account.command.logout.v1")
    {
        let target: reqwest::Url = exchange.url.parse()?;
        ensure!(
            target.origin() == issuer.origin() && target.path() == "/_arkret/gate/account/logout",
            "client-visible logout bypassed its actual Account Authority origin"
        );
        ensure!(
            exchange.explicit_request_headers.get("authorization")
                == Some(&format!("DPoP {token}")),
            "logout substituted its actual issuer credential"
        );
        let verified = arkret_signatures::dpop::verify_dpop_proof(
            &arkret_signatures::dpop::DpopVerificationRequest {
                proof_jwt: exchange
                    .explicit_request_headers
                    .get("dpop")
                    .context("native holder proof")?,
                method: &exchange.method,
                htu: &exchange.url,
                access_token: Some(token),
                expected_nonce: None,
                now: chrono::DateTime::parse_from_rfc3339(&exchange.observed_at)?
                    .with_timezone(&chrono::Utc),
                max_age: chrono::Duration::seconds(60),
                max_future_skew: chrono::Duration::seconds(5),
            },
        )?;
        ensure!(
            verified.jkt == expected
                && evidence["journal"]["cnf_jkt"] == expected
                && seen.insert(verified.claims.jti),
            "logout holder, durable journal or fresh retry proof is not bound to its issued original"
        );
    }
    ensure!(
        seen.len() == 2,
        "native logout must complete and replay with distinct holder proofs"
    );
    Ok(())
}
