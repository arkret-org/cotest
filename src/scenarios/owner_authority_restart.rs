//! Current-v1 owner authority survives process restart without legacy
//! registry snapshots, compatibility grants, or database migration rows.

use anyhow::{Context, Result, anyhow};
use arkret_canonical::canonical_sha256;
use arkret_models_collaboration::governance::authorization::AuthzCheckRequestBody;
use arkret_models_collaboration::governance::invite_addressing::IntroductionEvidence;
use reqwest::StatusCode;
use serde_json::json;

use crate::harness::{
    ArkretServer, actor_core_id, expect_json, invite_create_payload, submitted_event_id,
};
use crate::scenarios::identity_test_support::actor_did_for_service_did;

pub async fn owner_invite_remove_grant_revoke_survive_restart() -> Result<()> {
    let configured_database = std::env::var("COTEST_SOLAND_DATABASE_URL")
        .ok()
        .filter(|url| !url.trim().is_empty());
    let mut ephemeral = None;
    let database_url = if let Some(url) = configured_database {
        url
    } else {
        ephemeral = crate::scenarios::_helpers::coauth_bootstrap::spawn_ephemeral_postgres()?;
        let Some(database) = ephemeral.as_ref() else {
            eprintln!(
                "owner restart row skipped: no COTEST_SOLAND_DATABASE_URL and Docker/Postgres unavailable"
            );
            return Ok(());
        };
        database.connect_url.clone()
    };

    let test_name = "owner-authority-restart";
    let keystore_dir = tempfile::tempdir()?;
    let keystore_path = keystore_dir
        .path()
        .join("soland.v1")
        .to_string_lossy()
        .into_owned();
    let keystore_env = [
        ("SOLAND_KEYSTORE_BACKEND", "encrypted_file"),
        ("SOLAND_KEYSTORE_PATH", keystore_path.as_str()),
        (
            "SOLAND_KEYSTORE_MASTER_KEY",
            "UlJSUlJSUlJSUlJSUlJSUlJSUlJSUlJSUlJSUlJSUlI=",
        ),
    ];
    let mut server =
        ArkretServer::spawn_with_database_url(test_name, &database_url, &keystore_env).await?;
    let alice_did = actor_did_for_service_did(server.service_did(), "owner-restart-alice")?;
    let bob_did = actor_did_for_service_did(server.service_did(), "owner-restart-bob")?;
    let alice_device = "ak:device:01904100-0000-7000-8000-0000000000e1";
    let bob_device = "ak:device:01904100-0000-7000-8000-0000000000e2";
    let alice = server.demo_client(&alice_did, alice_device).await?;
    let _bob = server
        .register_client(&bob_did, "owner-restart-bob", bob_device)
        .await?;
    let created = alice.create_realm("Owner Restart Authority").await?;
    let realm_id = created;

    server.kill_immediately().await?;
    drop(server);
    let mut server =
        ArkretServer::spawn_with_database_url(test_name, &database_url, &keystore_env).await?;
    let alice = server.demo_client(&alice_did, alice_device).await?;
    let bob = server.demo_client(&bob_did, bob_device).await?;
    alice.track_controlled_realm(&arkret_identifiers::RealmId::new(realm_id.clone())?);

    let invite = alice
        .submit_event(
            &realm_id,
            "ak.invite.create",
            invite_create_payload(
                bob.actor.as_str(),
                alice.service_id(),
                canonical_sha256(&IntroductionEvidence::SamePrincipalServer)?,
                chrono::Utc::now() + chrono::Duration::days(7),
            )?,
        )
        .await?;
    if invite["status"] != "accepted" {
        return Err(anyhow!("restarted owner could not create invite: {invite}"));
    }
    alice
        .await_event_seal_coverage(&realm_id, &submitted_event_id(&invite)?)
        .await?;

    let added = alice.add_member(&realm_id, &bob).await?;
    if added["status"] != "accepted" {
        return Err(anyhow!("restarted owner could not add member: {added}"));
    }
    alice
        .await_event_seal_coverage(&realm_id, &submitted_event_id(&added)?)
        .await?;
    let grant_id = alice
        .grant_realm_actions_to_client(&realm_id, &bob, &["ak.message.create"])
        .await?;
    let bob_core = actor_core_id(&bob.actor)?;
    let allowed = expect_json(
        bob.post("/_arkret/self/authz/check").json(
            &serde_json::from_value::<AuthzCheckRequestBody>(json!({
                "actor_id": bob_core,
                "action": "ak.message.create",
                "resource": {"kind": "realm", "realm_id": realm_id}
            }))?,
        ),
        StatusCode::OK,
    )
    .await?;
    if allowed["decision"] != "allow" {
        return Err(anyhow!(
            "restarted owner grant did not become effective: {allowed}"
        ));
    }

    let revoked = alice.revoke_realm_grant(&realm_id, &grant_id).await?;
    if revoked["status"] != "accepted" {
        return Err(anyhow!("restarted owner could not revoke grant: {revoked}"));
    }
    alice
        .await_event_seal_coverage(&realm_id, &submitted_event_id(&revoked)?)
        .await?;
    let denied = expect_json(
        bob.post("/_arkret/self/authz/check").json(
            &serde_json::from_value::<AuthzCheckRequestBody>(json!({
                "actor_id": actor_core_id(&bob.actor)?,
                "action": "ak.message.create",
                "resource": {"kind": "realm", "realm_id": realm_id}
            }))?,
        ),
        StatusCode::OK,
    )
    .await?;
    if denied["decision"] != "hard_deny" {
        return Err(anyhow!("revoked grant remained effective: {denied}"));
    }

    let removed = alice.remove_member(&realm_id, &bob).await?;
    if removed["status"] != "accepted" {
        return Err(anyhow!(
            "restarted owner could not remove member: {removed}"
        ));
    }
    alice
        .await_event_seal_coverage(&realm_id, &submitted_event_id(&removed)?)
        .await?;

    server
        .kill_immediately()
        .await
        .context("stop restarted Soland")?;
    drop(ephemeral);
    Ok(())
}
