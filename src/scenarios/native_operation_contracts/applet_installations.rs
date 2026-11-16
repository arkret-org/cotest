//! Five real Applet installation operations; observations alone never authorize.
use arkret_models_collaboration::applet_installation_authority::{
    AppletAuthorityMaterialRequestBody, AppletAuthorityMaterialResponseBody,
    AppletInstallationCurrentBinding,
};
use arkret_models_collaboration::events_payloads::CapabilityRevokePayload;
use arkret_models_integration::{
    AppletInstallResponseBody, AppletRevokeEffectRef, AppletRevokePreviewRequestBody,
    AppletRevokePreviewResponseBody, AppletRevokeRequestBody, AppletRevokeResponseBody,
    AppletRevokeSagaStatus,
};
use arkret_wire::{
    AppletRevokeMode, CommittedEventFullView, EventAdmissionSubmission, EventKind, RealmId,
    ScopeRef,
};

use super::*;
use crate::harness::{ArkretServer, expect_json};
use crate::scenarios::call_recording_live::service::RecorderService;
use crate::scenarios::mls_lifecycle_live::{Member, accepted_full_view};

const SCOPE: [&str; 5] = [
    "ak.self.applet.install.command.preview.v1",
    "ak.self.applet.command.install.v1",
    "ak.self.applet.authority.read.material.v1",
    "ak.self.applet.revoke.command.preview.v1",
    "ak.self.applet.command.revoke.v1",
];

/// Observe only this case's durable authority/effects. HTTP nonce/cache rows
/// are not business effects, and are deliberately outside this comparison.
pub(super) async fn originals(
    database: &str,
    realm: &RealmId,
    applet: &arkret_wire::AppletId,
) -> Result<Value> {
    let database = database.to_owned();
    let realm = realm.to_string();
    let applet = applet.to_string();
    tokio::task::spawn_blocking(move || -> Result<Value> {
        let mut db = postgres::Client::connect(&database, postgres::NoTls)?;
        let mut result = serde_json::Map::new();
        for (name, query) in [
            ("installations", "SELECT to_jsonb(r) FROM applet_installations r WHERE applet_id=$2 AND $1<>'' ORDER BY to_jsonb(r)::text"),
            ("registration_instances", "SELECT to_jsonb(r) FROM applet_registration_instances r WHERE realm_id=$1 AND applet_id=$2 ORDER BY to_jsonb(r)::text"),
            ("registration_current", "SELECT to_jsonb(r) FROM applet_registration_current_states r WHERE realm_id=$1 AND applet_id=$2 ORDER BY to_jsonb(r)::text"),
            ("sources", "SELECT to_jsonb(r) FROM applet_grant_registration_sources r WHERE realm_id=$1 AND applet_id=$2 ORDER BY to_jsonb(r)::text"),
            ("grants", "SELECT to_jsonb(r) FROM capability_grant_current_states r WHERE realm_id=$1 AND $2<>'' ORDER BY to_jsonb(r)::text"),
            ("quota_counters", "SELECT to_jsonb(r) FROM capability_quota_counters r WHERE grant_id IN (SELECT grant_id FROM capability_grant_current_states WHERE realm_id=$1) AND $2<>'' ORDER BY to_jsonb(r)::text"),
            ("quota_buckets", "SELECT to_jsonb(r) FROM capability_quota_buckets r WHERE grant_id IN (SELECT grant_id FROM capability_grant_current_states WHERE realm_id=$1) AND $2<>'' ORDER BY to_jsonb(r)::text"),
            ("quota_consumptions", "SELECT to_jsonb(r) FROM capability_quota_consumptions r WHERE grant_id IN (SELECT grant_id FROM capability_grant_current_states WHERE realm_id=$1) AND $2<>'' ORDER BY to_jsonb(r)::text"),
            ("transactions", "SELECT to_jsonb(r) FROM applet_transactions r WHERE applet_id=$2 AND $1<>'' ORDER BY to_jsonb(r)::text"),
        ] {
            let rows = db.query(query, &[&realm, &applet])?;
            result.insert(name.into(), json!(rows.into_iter().map(|r| r.get::<_, Value>(0)).collect::<Vec<_>>()));
        }
        let rows = db.query("SELECT to_jsonb(i) FROM idempotency_keys i WHERE i.operation_id LIKE 'ak.self.applet.%' AND $1<>'' AND $2<>'' ORDER BY to_jsonb(i)::text", &[&realm,&applet])?;
        result.insert("idempotency".into(),json!(rows.into_iter().map(|r|r.get::<_,Value>(0)).collect::<Vec<_>>()));
        let rows = db.query("SELECT to_jsonb(e) FROM canonical_events e WHERE e.realm_id=$1 AND $2<>'' ORDER BY e.id", &[&realm,&applet])?;
        result.insert("events".into(),json!(rows.into_iter().map(|r|r.get::<_,Value>(0)).collect::<Vec<_>>()));
        let rows = db.query("SELECT e.envelope,c.commit_json FROM canonical_events e JOIN realm_commits c ON c.event_pk=e.pk WHERE c.realm_id=$1 AND $2<>'' ORDER BY c.stream_key,c.stream_position", &[&realm,&applet])?;
        result.insert("committed".into(), json!(rows.into_iter().map(|r| json!({"event":r.get::<_,Value>(0),"commit":r.get::<_,Value>(1)})).collect::<Vec<_>>()));
        Ok(Value::Object(result))
    }).await?
}

fn only<'a>(value: &'a Value, name: &str) -> Result<&'a Value> {
    let [row] = value[name]
        .as_array()
        .context("native collection absent")?
        .as_slice()
    else {
        anyhow::bail!("native {name} must contain exactly one real row");
    };
    Ok(row)
}

pub(super) fn require_original(snapshot: &Value, original: &CommittedEventFullView) -> Result<()> {
    let found = snapshot["committed"]
        .as_array()
        .context("native committed originals absent")?
        .iter()
        .filter(|row| row["event"]["event_id"] == json!(original.event.event_id))
        .collect::<Vec<_>>();
    ensure!(
        found.len() == 1
            && found[0]["event"] == json!(original.event)
            && found[0]["commit"] == json!(original.commit),
        "PG original differs from the exact public Event/Commit"
    );
    Ok(())
}

fn require_material(
    material: &AppletAuthorityMaterialResponseBody,
    request: &AppletAuthorityMaterialRequestBody,
    install: &AppletInstallResponseBody,
    registration: &CommittedEventFullView,
    grant: &CommittedEventFullView,
    active: bool,
) -> Result<()> {
    material.validate_for_request(&install.applet_id, request)?;
    ensure!(
        material.service_id == install.service_id
            && material.registration.event == registration.event
            && material.registration.commit == registration.commit
            && material.grant_events.len() == 1
            && material.grant_events[0].event == grant.event
            && material.grant_events[0].commit == grant.commit,
        "material substituted another historical registration or Service parent"
    );
    match (&material.current_binding, active) {
        (
            AppletInstallationCurrentBinding::Active {
                registration_ref,
                registration_epoch,
                service_id,
            },
            true,
        ) => {
            ensure!(
                registration_ref.event_id == registration.event.event_id
                    && registration_ref.commit_id == registration.commit.commit_id
                    && registration_ref.stream_ref == registration.commit.stream_ref
                    && registration_ref.stream_position == registration.commit.stream_position
                    && registration_epoch == &install.registration_epoch
                    && service_id == &install.service_id,
                "active binding has another original cut"
            );
        }
        (AppletInstallationCurrentBinding::Inactive, false) => {}
        _ => anyhow::bail!("material reported the wrong current installation state"),
    }
    Ok(())
}

async fn material(
    service: &RecorderService,
    station: &ArkretServer,
    request: &AppletAuthorityMaterialRequestBody,
) -> Result<AppletAuthorityMaterialResponseBody> {
    Ok(serde_json::from_value(
        expect_json(
            service.authority_material_request(station, request)?,
            reqwest::StatusCode::OK,
        )
        .await?,
    )?)
}

async fn scenario() -> Result<Value> {
    let deployment =
        crate::scenarios::agent_runtime_live::coauth_session_evidence::actual_agent_deployment(
            "native-applet-installations",
        )
        .await?;
    let member = Member::from_client(deployment.controller.clone(), deployment.account.clone())?;
    let realm: RealmId = crate::scenarios::human_device_producer_live::create_realm_with_join_rule(
        &member.client,
        "Native Applet installation",
        "closed",
        &[&deployment.station],
    )
    .await?
    .parse()?;
    let service = RecorderService::start(&deployment.station).await?;
    let resolution = service.current_resolution(&deployment.station).await?;
    ensure!(
        service.service_id() != deployment.station.service_id(),
        "Applet cannot borrow Station identity"
    );
    let database = deployment
        .station
        .owned_database_url()
        .context("native Applet database absent")?;
    let before = originals(database, &realm, &service.package.applet_id).await?;
    ensure!(
        before["installations"] == json!([])
            && before["sources"] == json!([])
            && before["grants"] == json!([]),
        "fresh Applet already has an installation or Grant"
    );

    // This existing shared helper makes the real preview call, preserving the
    // signed package, authoring basis and returned plan digest for exact replay.
    let (install_request, registration_event, grant_event) = service
        .installation_request(&deployment.station, &member, &realm)
        .await?;
    let after_preview = originals(database, &realm, &service.package.applet_id).await?;
    ensure!(
        after_preview == before,
        "install preview wrote business authority"
    );
    let install_key = arkret_identifiers::new_prefixed_uuid7("ak:request:");
    let send_install = || {
        member
            .client
            .post("/_arkret/self/applets/install")
            .header("idempotency-key", &install_key)
            .json(&install_request)
    };
    let installed = expect_json(send_install(), reqwest::StatusCode::CREATED).await?;
    let install: AppletInstallResponseBody = serde_json::from_value(installed.clone())?;
    install.validate()?;
    let registration = accepted_full_view(&member.client, &registration_event.event_id).await?;
    let grant = accepted_full_view(&member.client, &grant_event.event_id).await?;
    ensure!(
        registration.event == registration_event
            && grant.event == grant_event
            && install.applet_id == service.package.applet_id
            && install.service_id == *service.service_id()
            && install.registration_event_ref == registration.event.event_id
            && install.registration_epoch == service.package.registration_epoch
            && install.capability_grant_refs
                == vec![arkret_wire::GrantId::from_event_id(&grant.event.event_id)]
            && install.rejections.is_empty(),
        "install changed its submitted originals or exact source"
    );
    crate::scenarios::call_recording_live::verify_owned_originals(
        &member,
        &[&registration, &grant],
    )
    .await?;
    let installed_rows = originals(database, &realm, &install.applet_id).await?;
    require_original(&installed_rows, &registration)?;
    require_original(&installed_rows, &grant)?;
    ensure!(
        installed_rows["committed"]
            .as_array()
            .context("installed commits absent")?
            .len()
            == before["committed"]
                .as_array()
                .context("before commits absent")?
                .len()
                + 2
            && installed_rows["events"]
                .as_array()
                .context("installed events absent")?
                .len()
                == before["events"]
                    .as_array()
                    .context("before events absent")?
                    .len()
                    + 2,
        "installation accepted or queued an unexpected extra Event"
    );
    let record = &only(&installed_rows, "installations")?["record"];
    let source = only(&installed_rows, "sources")?;
    ensure!(
        record["effective_scope"] == json!(ScopeRef::realm(realm.clone()))
            && record["owner_actor_id"] == json!(member.actor)
            && record["target_station_id"] == json!(deployment.station.service_id())
            && record["install_body_digest"]
                == arkret_canonical::canonical_sha256(&install_request)?,
        "stored installation does not bind the exact authenticated request"
    );
    ensure!(
        record["install_id"] == install.install_id
            && record["status"] == "installed"
            && source["install_id"] == install.install_id
            && source["grant_id"] == json!(install.capability_grant_refs[0])
            && source["registration_event_ref"] == json!(registration.event.event_id)
            && only(&installed_rows, "grants")?["status"] == "active",
        "real installation/Grant did not freeze its exact instance/source"
    );
    let install_replay = expect_json(send_install(), reqwest::StatusCode::OK).await?;
    let install_replay_rows = originals(database, &realm, &install.applet_id).await?;
    ensure!(
        install_replay == installed && install_replay_rows == installed_rows,
        "install exact replay changed its result or durable effects"
    );

    let material_request = AppletAuthorityMaterialRequestBody {
        effective_scope: ScopeRef::realm(realm.clone()),
        grant_ids: install.capability_grant_refs.clone(),
    };
    let active = material(&service, &deployment.station, &material_request).await?;
    require_material(
        &active,
        &material_request,
        &install,
        &registration,
        &grant,
        true,
    )?;
    ensure!(
        originals(database, &realm, &install.applet_id).await? == installed_rows,
        "authority material read wrote business state"
    );
    // One syntactically valid but cryptographically false signature, with the
    // original canonical body and all source/target coordinates unchanged.
    use base64::Engine as _;
    let mut bad_request = service
        .authority_material_request(&deployment.station, &material_request)?
        .build()?;
    bad_request.headers_mut().insert(
        "signature",
        format!(
            "sig1=:{}:",
            base64::engine::general_purpose::STANDARD.encode([0u8; 64])
        )
        .parse()?,
    );
    let bad = deployment.station.http().execute(bad_request).await?;
    let bad_status = bad.status();
    let bad_body = bad.bytes().await?;
    let bad_problem: arkret_wire::Problem = serde_json::from_slice(&bad_body)?;
    ensure!(
        bad_status == reqwest::StatusCode::UNAUTHORIZED
            && bad_problem.error_code() == Some(arkret_wire::ErrorCode::HttpSignatureInvalid),
        "material did not reject the invalid signature at its registered gate"
    );
    ensure!(
        originals(database, &realm, &install.applet_id).await? == installed_rows,
        "invalid material signature changed business effects"
    );

    let revoke_preview_request = AppletRevokePreviewRequestBody {
        service_id: install.service_id.clone(),
        effective_scope: material_request.effective_scope.clone(),
        reason_code: arkret_wire::ReasonCode::from_wire("requested_by_admin"),
        revoke_mode: AppletRevokeMode::RevokeRuntimeOnly,
    };
    let revoke_path = format!("/_arkret/self/applets/{}/revoke", install.applet_id);
    let preview: AppletRevokePreviewResponseBody = serde_json::from_value(
        expect_json(
            member
                .client
                .post(&format!("{revoke_path}/preview"))
                .json(&revoke_preview_request),
            reqwest::StatusCode::OK,
        )
        .await?,
    )?;
    ensure!(
        preview.revoke_plan.capability_revocations.len() == 1
            && preview.revoke_plan.membership_removals.is_empty()
            && preview.revoke_plan.widget_token_refs.is_empty(),
        "revoke preview did not select exactly the accepted Service parent"
    );
    let intent = &preview.revoke_plan.capability_revocations[0];
    ensure!(
        intent.grant_id == install.capability_grant_refs[0]
            && intent.expected_commit_id == grant.commit.commit_id
            && intent.registration_epoch == install.registration_epoch,
        "revoke preview changed the source or scalar current guard"
    );
    let after_revoke_preview = originals(database, &realm, &install.applet_id).await?;
    ensure!(
        after_revoke_preview == installed_rows,
        "revoke preview wrote business authority"
    );
    let revoke_event = member
        .client
        .author_event(
            realm.as_str(),
            EventKind::CapabilityRevoke.as_str(),
            serde_json::to_value(CapabilityRevokePayload {
                grant_id: intent.grant_id.clone(),
                expected_commit_id: intent.expected_commit_id.clone(),
                reason: Some(intent.reason_code.as_str().to_owned()),
            })?,
        )
        .await?;
    let revoke_request = AppletRevokeRequestBody {
        revoke_plan_digest: arkret_wire::Hash::new(arkret_canonical::canonical_sha256(
            &preview.revoke_plan,
        )?)?,
        service_id: install.service_id.clone(),
        effective_scope: material_request.effective_scope.clone(),
        reason_code: revoke_preview_request.reason_code.clone(),
        revoke_mode: revoke_preview_request.revoke_mode,
        capability_revoke_events: vec![EventAdmissionSubmission::new(revoke_event.clone())],
        membership_state_events: Vec::new(),
    };
    let revoke_key = arkret_identifiers::new_prefixed_uuid7("ak:request:");
    let send_revoke = || {
        member
            .client
            .post(&revoke_path)
            .header("idempotency-key", &revoke_key)
            .json(&revoke_request)
    };
    let revoked = expect_json(send_revoke(), reqwest::StatusCode::OK).await?;
    let outcome: AppletRevokeResponseBody = serde_json::from_value(revoked.clone())?;
    let revoke = accepted_full_view(&member.client, &revoke_event.event_id).await?;
    ensure!(outcome.status == AppletRevokeSagaStatus::Complete && outcome.rejections.is_empty()
        && outcome.revoke_plan_digest == revoke_request.revoke_plan_digest
        && revoke.event == revoke_event
        && outcome.revoked_refs.iter().any(|r| matches!(r,AppletRevokeEffectRef::CommittedEvent(c)
            if c.event_id==revoke.event.event_id && c.commit_id==revoke.commit.commit_id
                && c.stream_ref==revoke.commit.stream_ref && c.stream_position==revoke.commit.stream_position)),
        "revoke did not bind its unique real accepted Event/Commit");
    crate::scenarios::call_recording_live::verify_owned_originals(&member, &[&revoke]).await?;
    let revoked_rows = originals(database, &realm, &install.applet_id).await?;
    for original in [&registration, &grant, &revoke] {
        require_original(&revoked_rows, original)?;
    }
    ensure!(
        revoked_rows["committed"]
            .as_array()
            .context("revoked commits absent")?
            .len()
            == installed_rows["committed"]
                .as_array()
                .context("installed commits absent")?
                .len()
                + 1
            && revoked_rows["events"]
                .as_array()
                .context("revoked events absent")?
                .len()
                == installed_rows["events"]
                    .as_array()
                    .context("installed events absent")?
                    .len()
                    + 1,
        "revocation accepted or queued an unexpected extra Event"
    );
    ensure!(
        only(&revoked_rows, "grants")?["status"] == "revoked"
            && only(&revoked_rows, "grants")?["current_commit_id"]
                == json!(revoke.commit.commit_id)
            && only(&revoked_rows, "installations")?["record"]["status"] == "revoked"
            && revoked_rows["sources"] == installed_rows["sources"],
        "revoke lost its original instance/source or failed to revoke current"
    );
    let inactive = material(&service, &deployment.station, &material_request).await?;
    require_material(
        &inactive,
        &material_request,
        &install,
        &registration,
        &grant,
        false,
    )?;
    let revoke_replay = expect_json(send_revoke(), reqwest::StatusCode::OK).await?;
    let old_install_replay = expect_json(send_install(), reqwest::StatusCode::OK).await?;
    let after_replays = originals(database, &realm, &install.applet_id).await?;
    ensure!(
        revoke_replay == revoked
            && old_install_replay == installed
            && after_replays == revoked_rows,
        "exact accepted replay changed outcome, debited twice or revived a fenced installation"
    );
    let still_inactive = material(&service, &deployment.station, &material_request).await?;
    require_material(
        &still_inactive,
        &material_request,
        &install,
        &registration,
        &grant,
        false,
    )?;
    ensure!(
        originals(database, &realm, &install.applet_id).await? == revoked_rows,
        "final audit read wrote business effects"
    );
    Ok(
        json!({"realm_id":realm,"station_id":deployment.station.service_id(),"actor_id":member.actor,"service_resolution":resolution,"package":service.package,
        "install_request":install_request,"install_key":install_key,"installed":installed,"install_replay":install_replay,
        "registration":registration,"grant":grant,"material_request":material_request,"active":active,"invalid_material_signature":{"status":bad_status.as_u16(),"problem":bad_problem},"inactive":inactive,"still_inactive":still_inactive,
        "revoke_preview_request":revoke_preview_request,"revoke_preview":preview,"revoke_request":revoke_request,"revoke_key":revoke_key,
        "revoke":revoke,"revoked":revoked,"revoke_replay":revoke_replay,"old_install_replay":old_install_replay,
        "snapshots":{"before":before,"after_preview":after_preview,"installed":installed_rows,"install_replay":install_replay_rows,
            "revoke_preview":after_revoke_preview,"revoked":revoked_rows,"after_replays":after_replays},
        "processes":[deployment.coauth.server.native_process_identity()?,deployment.station.native_process_identity()?]}),
    )
}

pub(super) async fn run() -> Result<()> {
    let (result, observations) = observe(crate::harness::heap_future(scenario)).await;
    retain_attempt("applet-installations", &observations)?;
    let mut artifact = result?;
    validate_exchange_schemas(&observations, &SCOPE)?;
    let originals = ["registration", "grant", "revoke"]
        .into_iter()
        .map(|name| serde_json::from_value::<CommittedEventFullView>(artifact[name].clone()))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    verify_native_station_commits(&observations, &originals)?;
    artifact["case"] = json!("applet_installations");
    artifact["scope"] = json!(SCOPE);
    artifact["observations"] = serde_json::to_value(observations)?;
    if let Some(directory) = std::env::var_os("COTEST_NATIVE_OPERATION_EVIDENCE_DIR") {
        std::fs::write(
            std::path::PathBuf::from(directory).join("applet-installations.json"),
            serde_json::to_vec_pretty(&artifact)?,
        )?;
    }
    for operation in SCOPE {
        println!("native operation contract passed: {operation}");
    }
    Ok(())
}
