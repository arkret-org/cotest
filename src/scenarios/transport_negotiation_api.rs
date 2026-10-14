//! Transport discovery and RFC 9421 freshness/key isolation on real Stations.

use anyhow::{Context, Result, ensure};
use arkret_signatures::http_signature::{
    SignedRequestParts, canonical_message, format_signature_input_component_list,
    parse_signature_input, sign_message,
};
use reqwest::{Request, StatusCode};
use serde_json::json;

use super::_helpers::bridge::MockCoauthIntrospectionServer;
use super::human_device_producer_live::{
    database, standard_client, station_env, submit_and_expect_commit,
};
use super::identity_test_support::HARNESS_INTERNAL_AUTHORITY_SECRET;
use crate::harness::{ArkretServer, TestServerGroup};

fn resign(
    request: &mut Request,
    source: &ArkretServer,
    expired: bool,
    wrong_key: bool,
) -> Result<()> {
    let parsed = parse_signature_input(request.headers()["signature-input"].to_str()?)?;
    let created = chrono::Utc::now().timestamp() - if expired { 600 } else { 0 };
    let input = format!(
        "{};created={created};expires={};keyid=\"{}\";alg=\"ed25519\"",
        format_signature_input_component_list("sig1", &parsed.covered_components)?,
        created + 300,
        parsed.key_id
    );
    let parts = SignedRequestParts {
        method: request.method().to_string(),
        target_uri: request.url().to_string(),
        authority: request.url()[url::Position::BeforeHost..url::Position::AfterPort].to_owned(),
        path: String::new(),
        headers: request
            .headers()
            .iter()
            .map(|(k, v)| Ok((k.to_string(), v.to_str()?.to_owned())))
            .collect::<Result<_>>()?,
        body_digest: Some(request.headers()["content-digest"].to_str()?.to_owned()),
    };
    let bytes = canonical_message(&parts, &parse_signature_input(&input)?)?;
    let key = if wrong_key {
        ed25519_dalek::SigningKey::from_bytes(&[0xa9; 32])
    } else {
        source.federation_signing_key()?
    };
    request
        .headers_mut()
        .insert("signature-input", input.parse()?);
    request.headers_mut().insert(
        "signature",
        format!("sig1=:{}:", sign_message(&bytes, &key)).parse()?,
    );
    Ok(())
}

pub async fn transport_negotiation_api_migration() -> Result<()> {
    let first =
        database("api-transport-source")?.context("transport migration requires PostgreSQL")?;
    let second = database("api-transport-recipient")?
        .context("transport migration requires a second isolated PostgreSQL database")?;
    ensure!(
        first.connect_url != second.connect_url,
        "transport Stations shared a database"
    );
    let issuer = MockCoauthIntrospectionServer::spawn_with_internal_secret(
        HARNESS_INTERNAL_AUTHORITY_SECRET,
    )
    .await?;
    let group = TestServerGroup::try_multi_external_with_node_envs(
        "api-transport",
        &[
            station_env(&first.connect_url, &issuer),
            station_env(&second.connect_url, &issuer),
        ],
    )
    .await?
    .context("transport migration requires the prebuilt real Station")?;
    let source = group.server(0);
    let recipient = group.server(1);
    for station in [source, recipient] {
        let describe: arkret_models_discovery::ServiceDescribe = station
            .http()
            .get(station.url("/_arkret/describe"))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        let value = serde_json::to_value(describe)?;
        ensure!(
            value["service_id"] == station.service_id().as_str()
                && value["transport_bindings"]
                    .as_array()
                    .context("transport bindings")?
                    .iter()
                    .any(|b| b["kind"] == "http_json"),
            "Station did not advertise its HTTP binding"
        );
    }
    let unsigned = recipient
        .http()
        .post(recipient.url("/_arkret/peer/events"))
        .json(&json!({"events":[]}))
        .send()
        .await?;
    ensure!(
        unsigned.status().is_client_error() && unsigned.status() != StatusCode::NOT_FOUND,
        "peer submit route did not reject unsigned input"
    );
    let (alice, account) = standard_client(
        source,
        &issuer,
        "api-transport-owner",
        "ak:device:01904100-0000-7000-8000-00000000a880",
    )
    .await?;
    let realm = alice.create_realm("transport accepted source").await?;
    let strand = alice.default_strand_id(&realm)?;
    let event = alice
        .author_event(
            &realm,
            "ak.message.create",
            crate::harness::message_create_text_payload(&strand, "transport source")?,
        )
        .await?;
    let commit = submit_and_expect_commit(&alice, &account, &alice.device_id, &event).await?;
    let body = super::fanout_route_miss_live::replication_body(&alice, &event, &commit).await?;
    let mut errors = Vec::new();
    for (expired, wrong_key, code) in [
        (true, false, "signature_window_invalid"),
        (false, true, "signature_invalid"),
    ] {
        let mut request = recipient.signed_peer_post_request_with_idempotency_key(
            source,
            "/_arkret/peer/events",
            &body,
            recipient.service_id(),
            None,
        )?;
        resign(&mut request, source, expired, wrong_key)?;
        let response = recipient.http().execute(request).await?;
        ensure!(
            response.status() == StatusCode::UNAUTHORIZED,
            "invalid transport signature did not fail at authentication"
        );
        let raw = response.text().await?;
        let problem: arkret_wire::Problem = serde_json::from_str(&raw)?;
        ensure!(
            problem.code() == code,
            "transport returned a different registered signature refusal"
        );
        for hint in [
            "key_rotation_hint",
            "signature_expired",
            "unknown_keyid",
            "valid_from",
            "current_keyid",
        ] {
            ensure!(
                !raw.contains(hint),
                "transport leaked a private signature cause"
            );
        }
        errors.push(problem.detail);
    }
    ensure!(
        errors[0] == errors[1],
        "transport signature failures exposed different public detail"
    );
    let request = recipient.signed_peer_post_request_with_idempotency_key(
        source,
        "/_arkret/peer/events",
        &body,
        recipient.service_id(),
        None,
    )?;
    let response = recipient.http().execute(request).await?;
    let status = response.status();
    let text = response.text().await?;
    let problem = serde_json::from_str::<arkret_wire::Problem>(&text).ok();
    ensure!(
        status != StatusCode::UNAUTHORIZED
            || problem.as_ref().map(|p| &p.detail) != Some(&errors[0]),
        "fresh correct signature did not clear the transport authentication gate"
    );
    println!(
        "transport: two real Stations, accepted source, freshness and wrong-key refusal, uniform public detail, fresh re-sign verified"
    );
    Ok(())
}
