//! S2 — a directed `ak.invite.create` is admitted by the Realm's governing
//! Station through the single Event/RealmCommit carrier and then privately
//! delivered to a same-Station invitee through `ak.self.invites.command.dispatch.v1`
//! (`zh/sync/invite-addressing.md` §7).
//!
//! The scenario proves, against a live Soland:
//!
//! 1. the create is accepted with a RealmCommit on the Realm stream;
//! 2. dispatching that committed Event lands one delivery entry for the Invite in the invitee's
//!    holder-private `ak.account.invite_delivery` cell;
//! 3. an exact replay of the same dispatch succeeds and leaves the delivery cell at the same
//!    revision and bytes, so the invitee is never delivered twice;
//! 4. an exact replay of the create itself is the stored `duplicate` outcome naming the same
//!    RealmCommit.

use anyhow::{Context, Result, ensure};
use arkret_models_collaboration::governance::invite_addressing::InviteDelivery;
use arkret_wire::{AccountDataKey, InviteReceiveAction};
use reqwest::StatusCode;
use serde_json::Value;

use crate::harness::{ArkretServer, CanonicalJsonBody, TestActorClient, expect_json};
use crate::scenarios::_helpers::bridge::MockCoauthIntrospectionServer;
use crate::scenarios::_helpers::coauth_bootstrap::{EphemeralPg, spawn_ephemeral_postgres_for};
use crate::scenarios::bridge_contracts::session_grant::mock_session_grant_jwt;
use crate::scenarios::identity_test_support::{
    HARNESS_INTERNAL_AUTHORITY_SECRET, actor_did_for_service_did,
    spawn_with_harness_account_authority_at,
};
use crate::scenarios::invite_service_fanout_live::{
    account_data_row, prepare_explicit_invite, set_explicit_address_behavior,
};
use crate::scenarios::security_rotation_live::rotation_station_env;

/// One Station whose Account Authority and session-grant introspection is a
/// mock Coauth, so an Account can hold the standard session grant that
/// `ak.self.events.command.submit.v1` requires of every producer.
pub struct InviteStation {
    pub server: ArkretServer,
    coauth: MockCoauthIntrospectionServer,
    _database: EphemeralPg,
}

impl InviteStation {
    pub async fn spawn(name: &str) -> Result<Self> {
        let database = spawn_ephemeral_postgres_for("COTEST_SOLAND_DATABASE_URL")?.context(
            "the invite scenarios need PostgreSQL; set COTEST_SOLAND_DATABASE_URL or make Docker available",
        )?;
        let coauth = MockCoauthIntrospectionServer::spawn_with_internal_secret(
            HARNESS_INTERNAL_AUTHORITY_SECRET,
        )
        .await?;
        let env = rotation_station_env(&coauth);
        let env = env
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str()))
            .collect::<Vec<_>>();
        let server =
            spawn_with_harness_account_authority_at(name, &database.connect_url, &env).await?;
        Ok(Self {
            server,
            coauth,
            _database: database,
        })
    }

    /// Provision `label`'s principal with `device` as its founding device and
    /// return a client presenting that device's standard session grant.
    pub async fn grant_bearing_client(&self, label: &str, device: &str) -> Result<TestActorClient> {
        let actor = actor_did_for_service_did(self.server.service_did(), label)?;
        let provisioned = self.server.demo_client(&actor, device).await?;
        let principal = provisioned
            .principal
            .as_ref()
            .context("the provisioned client carries its principal")?
            .clone();
        let grant = mock_session_grant_jwt(
            principal.core_id.as_str(),
            principal.device_id.as_str(),
            self.server.service_id().as_str(),
        );
        self.coauth.bind_founding_device_grant(
            &grant,
            principal.core_id.as_str(),
            principal.device_id.as_str(),
            principal.founding_authorize_event_id.as_str(),
            &principal.device_signing_key.verifying_key(),
        )?;
        self.server
            .client_with_founding_device_grant(&principal, grant)
    }
}

fn delivery_entries_for(content: &Value, invite_id: &str) -> Result<usize> {
    let delivery: InviteDelivery = serde_json::from_value(content.clone())
        .context("invite_delivery account-data cell is not an InviteDelivery")?;
    Ok(delivery
        .delivery_entries
        .iter()
        .filter(|entry| entry.invite_id.as_str() == invite_id)
        .count())
}

pub async fn invite_create_and_dispatch_run() -> Result<()> {
    let station = InviteStation::spawn("invite-create-and-dispatch").await?;
    let server = &station.server;
    let inviter = station
        .grant_bearing_client(
            "alice-invite-create-dispatch",
            "ak:device:01904100-0000-7000-8000-0000000000a3",
        )
        .await
        .context("bootstrap inviter client")?;
    let holder = server
        .register_client(
            &actor_did_for_service_did(server.service_did(), "bob-invite-create-dispatch")?,
            "bob-invite-create-dispatch",
            "ak:device:01904100-0000-7000-8000-0000000000b3",
        )
        .await
        .context("bootstrap invitee client")?;
    set_explicit_address_behavior(&holder, InviteReceiveAction::Notify)
        .await
        .context("allow explicit-address invites to notify")?;

    let prepared = prepare_explicit_invite(&inviter, &holder, "Invite Create And Dispatch")
        .await
        .context("commit the directed invite create")?;
    let invite_event_id = prepared.request.invite_event_id.clone();
    let invite_id = prepared.invite_id.to_string();

    // (1) the create is on the Realm stream behind a RealmCommit.
    let committed = inviter
        .get_committed_event(&invite_event_id)
        .await
        .context("read the committed invite create")?;
    ensure!(
        committed["commit"]["event_ref"] == invite_event_id.as_str()
            && committed["commit"]["stream_ref"]["kind"] == "realm",
        "the invite create must be committed on its Realm stream: {committed}"
    );

    // (2) dispatch delivers exactly one entry to the invitee.
    let dispatched = expect_json(
        inviter
            .post("/_arkret/self/invites/dispatch")
            .json(&prepared.request),
        StatusCode::OK,
    )
    .await
    .context("dispatch the committed invite")?;
    ensure!(
        dispatched["status"] == "accepted",
        "a notify dispatch must be accepted: {dispatched}"
    );
    let delivered = account_data_row(&holder, AccountDataKey::ACCOUNT_INVITE_DELIVERY)
        .await
        .context("read the invitee delivery cell")?;
    ensure!(
        delivery_entries_for(&delivered.content, &invite_id)? == 1,
        "the invitee must hold exactly one delivery entry for {invite_id}: {}",
        delivered.content
    );

    // (3) an exact dispatch replay delivers nothing new.
    let replayed = expect_json(
        inviter
            .post("/_arkret/self/invites/dispatch")
            .json(&prepared.request),
        StatusCode::OK,
    )
    .await
    .context("replay the dispatch")?;
    ensure!(
        replayed["status"] == "accepted" || replayed["status"] == "duplicate",
        "an exact dispatch replay must succeed idempotently: {replayed}"
    );
    let after_replay = account_data_row(&holder, AccountDataKey::ACCOUNT_INVITE_DELIVERY)
        .await
        .context("re-read the invitee delivery cell")?;
    ensure!(
        after_replay.revision == delivered.revision && after_replay.content == delivered.content,
        "an exact dispatch replay must not touch the delivery cell"
    );

    // (4) an exact replay of the create returns its stored Commit.
    let create_event = serde_json::from_value::<arkret_wire::Event>(committed["event"].clone())
        .context("committed invite create is not a typed Event")?;
    let replay = expect_json(
        inviter
            .post("/_arkret/self/events")
            .canonical_json(&crate::publication::initial_submission(create_event, "")?)?,
        StatusCode::OK,
    )
    .await
    .context("replay the invite create")?;
    ensure!(
        replay["status"] == "duplicate" && replay["commit"] == committed["commit"],
        "an exact create replay must return the stored Commit: {replay}"
    );
    Ok(())
}
