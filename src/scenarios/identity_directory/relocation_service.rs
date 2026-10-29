//! A production CLI relocation retains service, Account and Realm authority.
use anyhow::{Context, Result, ensure};
use arkret_identity::{verify_current_service_resolution, verify_service_resolution_floor};
use arkret_models_discovery::StationConnectionBinding;
use arkret_models_identity::{AuthenticatedServiceResolution, ServiceMethodState};
use reqwest::StatusCode;

use crate::harness::{
    ArkretServer, CanonicalJsonBody, TestServerGroup, expect_api_error, expect_json,
    message_create_text_payload,
};

async fn resolution(server: &ArkretServer) -> Result<AuthenticatedServiceResolution> {
    Ok(serde_json::from_value(
        expect_json(
            server.http().get(server.url(&format!(
                "/_arkret/open/services/{}/resolution",
                server.service_id()
            ))),
            StatusCode::OK,
        )
        .await?,
    )?)
}
fn floor(value: &AuthenticatedServiceResolution) -> Result<ServiceMethodState> {
    let p = value.projection()?;
    Ok(ServiceMethodState {
        service_id: p.service_id,
        service_kind: p.service_kind,
        verified_at: chrono::Utc::now(),
        did: p.did,
        method_history_head: p.method_history_head,
        version_id: p.version_id,
    })
}

async fn current_native(server: &ArkretServer) -> Result<arkret_identity::ResolvedDid> {
    use arkret_identity::{
        DidResolver, DidWebvhDocumentHttpResponse, DidWebvhLogHttpResponse, DidWebvhResolver,
    };
    let did = server.service_did().clone();
    let log_url = DidWebvhResolver::log_url(&did)?;
    let log = server
        .http()
        .get(&log_url)
        .send()
        .await?
        .error_for_status()?;
    let log_type = log
        .headers()
        .get("content-type")
        .context("native log media type")?
        .to_str()?
        .to_owned();
    let mut resolver = DidWebvhResolver::new();
    resolver.ingest_log(
        &did,
        DidWebvhLogHttpResponse {
            url: log_url,
            content_type: log_type,
            body: log.bytes().await?.to_vec(),
        },
    )?;
    let doc_url = DidWebvhResolver::document_url(&did)?;
    let doc = server
        .http()
        .get(&doc_url)
        .send()
        .await?
        .error_for_status()?;
    let doc_type = doc
        .headers()
        .get("content-type")
        .context("native document media type")?
        .to_str()?
        .to_owned();
    resolver.insert_from_https_response(
        &did,
        DidWebvhDocumentHttpResponse {
            url: doc_url,
            content_type: doc_type,
            body: doc.bytes().await?.to_vec(),
        },
    )?;
    Ok(resolver.resolve_did(&did)?)
}

pub async fn service_migration_preserves_business_and_refreshes_peer_route() -> Result<()> {
    let bundle_root = std::env::var_os("COTEST_ARTIFACT_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let bundle = bundle_root.join(format!(
        "cotest-service-relocation-{}",
        crate::harness::next_typed_id("request").replace(':', "_")
    ));
    let bundle_s = bundle.to_string_lossy().to_string();
    let source_db =
        crate::scenarios::human_device_producer_live::database("relocation-service-source")?
            .context("service relocation needs isolated PostgreSQL")?;
    let peer_db =
        crate::scenarios::human_device_producer_live::database("relocation-service-peer")?
            .context("service relocation needs a second isolated PostgreSQL")?;
    let issuer = crate::scenarios::_helpers::bridge::MockCoauthIntrospectionServer::spawn_with_internal_secret(
        crate::scenarios::identity_test_support::HARNESS_INTERNAL_AUTHORITY_SECRET,
    ).await?;
    let mut source_env =
        crate::scenarios::human_device_producer_live::station_env(&source_db.connect_url, &issuer);
    source_env.push(("COLAND_SERVICE_IDENTITY_BUNDLE_DIR".into(), bundle_s));
    let peer_env =
        crate::scenarios::human_device_producer_live::station_env(&peer_db.connect_url, &issuer);
    let mut group = TestServerGroup::try_multi_external_with_node_envs(
        "relocation-service",
        &[source_env, peer_env],
    )
    .await?
    .context("service relocation requires the external binary")?;
    let (station, peer) = group.server_pair_mut(0, 1);
    let station_origin = station.base_url().to_string();
    let (owner, _) = crate::scenarios::human_device_producer_live::standard_client(
        station,
        &issuer,
        "service-relocation-owner",
        "ak:device:01904100-0000-7000-8000-000000000181",
    )
    .await?;
    let (member, _) = crate::scenarios::human_device_producer_live::standard_client(
        peer,
        &issuer,
        "service-relocation-member",
        "ak:device:01904100-0000-7000-8000-000000000182",
    )
    .await?;
    // Both Stations are explicit plaintext recipients of this ordinary Realm.
    // A send grant alone cannot disclose the forwarded original to its host.
    let created = owner
        .create_realm_with(serde_json::json!({
            "title": "service relocation authority continuity",
            "summary": "service relocation authority continuity",
            "public": false,
            "plaintext_visible_services": [station.service_id(), peer.service_id()]
        }))
        .await?;
    let realm = created["realm_id"]
        .as_str()
        .context("created Realm id")?
        .to_owned();
    let strand = owner.default_strand_id(&realm)?;
    owner.add_member(&realm, &member).await?;
    owner
        .grant_realm_actions_to_client(&realm, &member, &["ak.message.create"])
        .await?;
    owner
        .send_message(&realm, &strand, "before explicit service migration")
        .await?;
    member
        .send_message(&realm, &strand, "peer before service migration")
        .await?;
    let before = resolution(station).await?;
    let initial_description = serde_json::from_value(
        expect_json(
            station.http().get(station.url("/_arkret/describe")),
            StatusCode::OK,
        )
        .await?,
    )?;
    let initial_binding =
        StationConnectionBinding::from_description(station.base_url(), &initial_description, true)?;
    let original_core = station.service_id().to_owned();
    let old_did = station.service_did().to_owned();
    let target = station.reserve_public_base_target()?;
    station.stop_external_process().await?;
    let plan = station.migrate_public_base(&target, true).await?;
    ensure!(plan["status"] == "preflight");
    ensure!(station.service_did() == &old_did);
    let applied = station.migrate_public_base(&target, false).await?;
    ensure!(applied["status"] == "migrated");
    ensure!(
        plan["target_did"] == applied["did"],
        "apply differs from the preflight target"
    );
    ensure!(station.service_id() == &original_core && station.service_did() != &old_did);
    station.start_external_process().await?;
    let after = resolution(station).await?;
    verify_service_resolution_floor(&after, &floor(&before)?)?;
    let route = verify_current_service_resolution(
        &after,
        &after.service_id,
        "station",
        &current_native(station).await?,
        chrono::Utc::now(),
    )?;
    ensure!(route.base_url == target.as_str());
    ensure!(verify_service_resolution_floor(&before, &floor(&after)?).is_err());
    let target_description: arkret_models_discovery::ServiceDescribe = serde_json::from_value(
        expect_json(
            station.http().get(station.url("/_arkret/describe")),
            StatusCode::OK,
        )
        .await?,
    )?;
    target_description.validate_route_projection(&route)?;
    // The operator explicitly selected the CLI-verified same-core target.
    // Validate its public binding before issuing or sending a new credential.
    let target_binding =
        StationConnectionBinding::from_description(&target, &target_description, true)?;
    let initial_authority = initial_binding
        .authentication_metadata
        .account_authority
        .as_ref()
        .context("original Station Account Authority")?;
    let target_authority = target_binding
        .authentication_metadata
        .account_authority
        .as_ref()
        .context("migrated Station Account Authority")?;
    ensure!(
        target_binding.base_url == target.as_str()
            && target_binding.service_id == initial_binding.service_id
            && target_binding.service_id == original_core
            && target_binding.trust_domain == initial_binding.trust_domain
            && &target_binding.trust_domain == station.trust_domain()
            && target_authority.origin == initial_authority.origin
            && target_authority.gate_account_base_url == initial_authority.gate_account_base_url
            && target_authority.origin.as_str() == issuer.origin(),
        "migration changed the selected Station identity or Account Authority"
    );
    let old_origin: url::Url = station_origin.parse()?;
    let historical_host = station
        .serve_historical_public_base(&old_origin, &old_did)
        .await?;
    let old_log = arkret_identity::DidWebvhResolver::log_url(&old_did)?;
    let new_log = arkret_identity::DidWebvhResolver::log_url(station.service_did())?;
    let historical = station
        .http()
        .get(old_log)
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .await?;
    let current = station
        .http()
        .get(new_log)
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .await?;
    ensure!(
        historical == current,
        "historical origin lost the accepted canonical chain"
    );
    let old_description: arkret_models_discovery::ServiceDescribe = serde_json::from_value(
        expect_json(
            station.http().get(old_origin.join("_arkret/describe")?),
            StatusCode::OK,
        )
        .await?,
    )?;
    old_description.validate_route_projection(&route)?;
    // Historical hosting retains the original method history, but the old
    // request URI is not the newly selected canonical Station binding.
    let historical_probe = owner
        .author_event(
            &realm,
            "ak.message.create",
            message_create_text_payload(&strand, "historical listener before explicit retirement")?,
        )
        .await?;
    let submission = arkret_wire::EventAdmissionSubmission::new(historical_probe.clone());
    expect_api_error(
        owner
            .post("/_arkret/self/events")
            .canonical_json(&submission)?,
        StatusCode::UNAUTHORIZED,
        "unauthenticated",
    )
    .await?;

    let predecessor =
        issuer.own_station_session_state(owner.session().credential(), station.service_id())?;
    // This is a fresh mock-AA issuer record for the same accepted Device,
    // not evidence of production OIDC authentication or token refresh.
    let reissued = station
        .reissue_mock_native_host_session(&owner, &issuer)
        .await?;
    ensure!(
        reissued.session().credential() != owner.session().credential(),
        "migration reused the old credential for a new Station binding"
    );
    let renewed =
        issuer.own_station_session_state(reissued.session().credential(), station.service_id())?;
    ensure!(
        renewed.account_id == predecessor.account_id
            && renewed.device_id == predecessor.device_id
            && renewed.audience_id == predecessor.audience_id
            && renewed.grant_id != predecessor.grant_id
            && renewed.granted_scope == predecessor.granted_scope
            && renewed.dpop_jkt == predecessor.dpop_jkt
            && renewed.session_public_key == predecessor.session_public_key,
        "migration mock authentication changed the Account, Device, holder or scopes"
    );
    let owner = station
        .reconnect_after_public_base_migration(&reissued, &issuer)
        .await?;
    ensure!(
        owner.session().credential() == reissued.session().credential()
            && owner.url("/_arkret/self/events") == station.url("/_arkret/self/events"),
        "reconnected client did not use the fresh credential at the selected canonical base"
    );
    let accepted: arkret_wire::AuthoritySubmitResponseBody = serde_json::from_value(
        expect_json(
            owner
                .post("/_arkret/self/events")
                .canonical_json(&submission)?,
            StatusCode::OK,
        )
        .await?,
    )?;
    accepted.validate_for_request(&arkret_wire::AuthoritySubmitRequestBody::Event(submission))?;
    let arkret_wire::AuthoritySubmitResponseBody::Accepted {
        status: arkret_wire::AuthorityCommitStatus::Committed,
        commit,
    } = accepted
    else {
        anyhow::bail!("the frozen migration probe did not receive a new accepted Commit");
    };
    let arkret_wire::CommittedEventView::Full(original) = owner
        .sdk()
        .committed_event_get(&historical_probe.event_id)
        .await?
    else {
        anyhow::bail!("the accepted frozen migration probe was withheld");
    };
    original.validate_shape()?;
    ensure!(
        original.event == historical_probe && original.commit == commit,
        "migration changed the frozen original Event or its accepted Commit"
    );
    drop(historical_host);
    owner
        .send_message(&realm, &strand, "same owner and Realm after migration")
        .await?;
    peer.restart_with_federation_mesh(&[format!(
        "{}|{}|{}",
        target,
        original_core,
        station.trust_domain()
    )])
    .await?;
    member
        .send_message(&realm, &strand, "peer refresh after service migration")
        .await?;
    station.restart_external_process().await?;
    owner
        .send_message(&realm, &strand, "same Account after restart")
        .await?;
    let restarted = resolution(station).await?;
    ensure!(restarted.method_history_evidence == after.method_history_evidence);
    ensure!(
        station
            .http()
            .get(format!("{station_origin}health"))
            .send()
            .await
            .is_err(),
        "old business origin still listening"
    );
    let alien = resolution(peer).await?;
    ensure!(
        verify_current_service_resolution(
            &alien,
            &after.service_id,
            "station",
            &current_native(peer).await?,
            chrono::Utc::now()
        )
        .is_err(),
        "different core inherited service route"
    );
    ensure!(
        bundle
            .read_dir()
            .context("durable bundle directory")?
            .next()
            .is_some()
    );
    Ok(())
}
