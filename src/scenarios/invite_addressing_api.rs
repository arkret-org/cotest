//! Typed invite addressing against two isolated real Stations.

use anyhow::{Context, Result, ensure};
use arkret_models_collaboration::governance::invite_addressing::*;
use arkret_models_collaboration::governance::realm_join_intake::{
    AuthorityLocatorSource, RealmJoinCandidate, RealmJoinCandidateServiceKind,
};
use reqwest::StatusCode;
use serde_json::{Value, json};

use super::_helpers::native_account::NativeAccountProvisioner;
use super::agent_runtime_live::coauth_session_evidence::actual_agent_deployment;
use super::human_device_producer_live::original_human_signer_fact;
use super::invite_service_fanout_live::prepare_explicit_invite;
use crate::harness::{ArkretServer, CanonicalJsonBody, TestActorClient, expect_json};

mod locators;

async fn untouched(holder: &TestActorClient, realm: &str) -> Result<()> {
    let invites = expect_json(holder.get("/_arkret/self/authz/invites"), StatusCode::OK).await?;
    ensure!(
        !serde_json::to_string(&invites)?.contains(realm),
        "low-trust delivery exposed a holder-private invite"
    );
    let data = expect_json(holder.get("/_arkret/self/account_data"), StatusCode::OK).await?;
    ensure!(
        !data["account_data_entries"]
            .as_array()
            .context("account-data entries")?
            .iter()
            .any(|row| row["account_data_key"] == "ak.account.invite_delivery"),
        "low-trust delivery wrote holder invite-delivery state"
    );
    Ok(())
}

async fn peer(
    receiver: &ArkretServer,
    source: &ArkretServer,
    body: &InviteDeliveryRequestBody,
) -> Result<(StatusCode, Value)> {
    let (status, bytes) = receiver
        .signed_peer_post_with_idempotency_key(
            source,
            "/_arkret/peer/invites",
            &arkret_canonical::canonical_json_bytes(body)?,
            receiver.service_id(),
            Some(&body.idempotency_key),
        )
        .await?;
    Ok((status, serde_json::from_slice(&bytes)?))
}

async fn exercise(
    source: &ArkretServer,
    receiver: &ArkretServer,
    alice: &TestActorClient,
    holder: &TestActorClient,
    foreign: bool,
) -> Result<()> {
    let prepared = prepare_explicit_invite(
        alice,
        holder,
        if foreign {
            "foreign invite"
        } else {
            "local invite"
        },
    )
    .await?;
    let mut request = prepared.request;
    request.invite_address.account_id.station_id = receiver.service_id().clone();
    request.invite_address.service_resolution =
        arkret_models_identity::ServiceResolutionCarrier::ResolutionUrl {
            resolution_url: receiver.url(
                &arkret_models_identity::canonical_service_resolution_path(receiver.service_id()),
            ),
        };
    let accepted =
        super::mls_lifecycle_live::accepted_full_view(alice, &request.invite_event_id).await?;
    let event = accepted.event.clone();
    let commit = accepted.commit.clone();
    let realm = event.realm_id.to_string();
    let fact = original_human_signer_fact(alice, &event, &commit).await?;
    let body = InviteDeliveryRequestBody::new(
        event.clone(),
        commit.clone(),
        Some(fact),
        vec![RealmJoinCandidate {
            service_kind: RealmJoinCandidateServiceKind::Station,
            service_id: source.service_id().clone(),
            endpoint_url: None,
            source: AuthorityLocatorSource::Invite,
        }],
        request.invite_address.clone(),
        request.introduction_evidence.clone(),
        format!("invite-addressing-{}", event.event_id),
    )?;
    untouched(holder, &realm).await?;
    let (status, outcome) = peer(receiver, source, &body).await?;
    ensure!(
        status == StatusCode::OK
            && outcome["status"] == "deferred"
            && outcome.get("disclosed_outcome").is_none(),
        "low-trust peer delivery was not opaque: {status} {outcome}"
    );
    let received = outcome["received_at"]
        .as_str()
        .context("delivery receipt time")?;
    arkret_canonical::parse_timestamp_canonical(received)?;
    untouched(holder, &realm).await?;
    if foreign {
        let response = holder
            .get(&format!("/_arkret/self/realms/{realm}"))
            .send()
            .await?;
        ensure!(
            response.status() == StatusCode::NOT_FOUND,
            "first contact disclosed foreign Realm history"
        );
        for mutation in 0..3 {
            let mut invalid = body.clone();
            invalid.idempotency_key = format!("{}-invalid-{mutation}", body.idempotency_key);
            // Keep the outer transport signature genuine; corrupt only the
            // original producer or governing authority material under test.
            let mut wire = serde_json::to_value(&invalid)?;
            match mutation {
                0 => {
                    wire["invite_event"]["producer_proof"]["event_digest"] =
                        json!(format!("sha256:{}", "0".repeat(64)))
                }
                1 => {
                    let method = wire["invite_event"]["producer_proof"]["verification_method"]
                        .as_str()
                        .context("producer method")?;
                    wire["invite_event"]["producer_proof"]["verification_method"] = json!(format!(
                        "{}#ak:device:00000000",
                        method.split('#').next().context("producer DID")?
                    ));
                }
                _ => {
                    let signature = wire["invite_commit"]["signature"]["signature"]
                        .as_str()
                        .context("commit signature")?;
                    wire["invite_commit"]["signature"]["signature"] = json!(format!(
                        "{}{}",
                        if signature.starts_with('A') { "B" } else { "A" },
                        &signature[1..]
                    ));
                }
            }
            let (status, bytes) = receiver
                .signed_peer_post_with_idempotency_key(
                    source,
                    "/_arkret/peer/invites",
                    &arkret_canonical::canonical_json_bytes(&wire)?,
                    receiver.service_id(),
                    Some(&invalid.idempotency_key),
                )
                .await?;
            let problem: arkret_wire::Problem = serde_json::from_slice(&bytes)?;
            ensure!(
                status == StatusCode::UNAUTHORIZED && problem.code() == "signature_invalid",
                "tampered invite proof was not rejected at proof admission"
            );
            untouched(holder, &realm).await?;
        }
    } else {
        for _ in 0..2 {
            let outcome = expect_json(
                alice.post("/_arkret/self/invites/dispatch").json(&request),
                StatusCode::OK,
            )
            .await?;
            ensure!(
                matches!(outcome["status"].as_str(), Some("deferred" | "duplicate"))
                    && outcome.get("disclosed_outcome").is_none(),
                "self-dispatch retry disclosed low-trust outcome"
            );
        }
        let mut absent = request.clone();
        absent.invite_event_id = alice
            .author_event(
                &realm,
                "ak.invite.create",
                serde_json::to_value(&event.payload)?,
            )
            .await?
            .event_id;
        absent.idempotency_key.push_str("-absent");
        for (client, body) in [(alice, &absent), (holder, &request)] {
            let response = client
                .post("/_arkret/self/invites/dispatch")
                .canonical_json(body)?
                .send()
                .await?;
            ensure!(
                response.status() == StatusCode::CONFLICT,
                "dispatch precondition accepted an absent Event or another actor"
            );
            let value: Value = response.json().await?;
            let problem: arkret_wire::Problem = serde_json::from_value(value.clone())?;
            ensure!(
                problem.code() == "failed_precondition" && value.get("reason_code").is_none(),
                "dispatch exposed a retired reason code"
            );
        }
        untouched(holder, &realm).await?;
    }
    Ok(())
}

pub async fn invite_addressing_api_migration() -> Result<()> {
    let mut first = actual_agent_deployment("api-invite-source").await?;
    let mut second = actual_agent_deployment("api-invite-recipient").await?;
    ensure!(
        first.station.owned_database_url() != second.station.owned_database_url(),
        "invite Stations shared a database"
    );
    first
        .station
        .restart_with_federation_mesh(&[second.station.base_url().to_string()])
        .await?;
    second
        .station
        .restart_with_federation_mesh(&[first.station.base_url().to_string()])
        .await?;
    let issuer = NativeAccountProvisioner::new(&first);
    let source = &first.station;
    let receiver = &second.station;
    let alice = &first.controller;
    let (local, _) = issuer
        .provision(
            source,
            "invite-local",
            "ak:device:01904100-0000-7000-8000-00000000a892",
        )
        .await?;
    let foreign = &second.controller;
    locators::exercise(source, alice).await?;
    exercise(source, source, alice, &local, false).await?;
    exercise(source, receiver, alice, foreign, true).await?;
    println!(
        "invite addressing: real locator lifecycle, opaque retries, dispatch preconditions, first-contact proof admission and zero holder-private writes verified"
    );
    Ok(())
}
