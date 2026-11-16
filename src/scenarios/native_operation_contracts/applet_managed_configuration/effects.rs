//! Read actual owned PostgreSQL effects and independently verify public originals.
use arkret_models_identity::AuthenticatedServiceResolution;
use arkret_models_integration::{
    AppletAuthoringTransactionRequestBody, RealmActorCreatePayload, RealmActorMaterial,
};
use arkret_wire::{AppletId, CommittedEventFullView, DidUrl, Event, EventKind, RealmId, ScopeRef};

use super::*;

pub(super) fn resolution_key(
    resolution: &AuthenticatedServiceResolution,
    method: &DidUrl,
    at: chrono::DateTime<chrono::Utc>,
) -> Result<arkret_signatures::PublicKeyMaterial> {
    arkret_identity::verify_authenticated_service_resolution_history(
        resolution,
        &resolution.service_id,
        at,
    )?;
    arkret_identity::validate_verification_method_relationship(
        &resolution.normalized_did_document,
        method,
        &resolution.normalized_did_document.id,
        arkret_identity::DidVerificationRelationship::AssertionMethod,
    )?;
    Ok(arkret_identity::public_key_material_from_document(
        &resolution.normalized_did_document,
        method,
    )?)
}

pub(super) fn verify_creation(service: &ManagedService, event: &Event) -> Result<()> {
    let candidate: RealmActorCreatePayload =
        serde_json::from_value(serde_json::to_value(&event.payload)?)?;
    candidate.validate()?;
    arkret_identity::verify_realm_actor_initial_resolution(&candidate, event.created_at)?;
    ensure!(
        event.kind == EventKind::RealmActorCreate
            && event.actor_id == ActorId::service(service.package.service_id.clone())
            && event.applet_id.as_ref() == Some(&service.package.applet_id)
            && event.scope_ref
                == ScopeRef::RealmControl {
                    realm_id: event.realm_id.clone()
                }
            && candidate.service_id == service.package.service_id
            && candidate.applet_id == service.package.applet_id
            && candidate
                .actor_id
                .as_realm_actor_id()
                .is_some_and(|actor| actor.realm_id == event.realm_id),
        "source candidate changed its actual full Realm ActorId, Service, Applet or control stream"
    );
    event
        .verify_event_id_matches_content_with_digest_suite(arkret_canonical::DigestSuite::Sha256)?;
    let proof = event
        .producer_proof
        .as_ref()
        .context("Service producer proof absent")?;
    let key = resolution_key(
        &service.identity.resolution,
        &proof.verification_method,
        proof.created_at,
    )?;
    arkret_signatures::verify_ed25519_detached_jws_proof(
        proof,
        &arkret_signatures::EventProofBuilder::new().envelope_bytes(event)?,
        &event.actor_id,
        &key,
    )?;
    Ok(())
}

pub(super) fn verify_commit(
    resolution: &AuthenticatedServiceResolution,
    original: &CommittedEventFullView,
) -> Result<()> {
    original.validate_shape()?;
    original.commit.validate_content_address()?;
    original
        .event
        .verify_event_id_matches_content_with_digest_suite(arkret_canonical::DigestSuite::Sha256)?;
    let key = resolution_key(
        resolution,
        &original.commit.signature.verification_method,
        original.commit.signature.created_at,
    )?;
    arkret_signatures::detached_object::verify_detached_object_signature(
        &original.commit.signature,
        &arkret_canonical::canonical::unsigned_value(&original.commit, &["signature"])?,
        arkret_wire::DetachedSignatureContext::RealmCommit,
        &key,
    )?;
    Ok(())
}

pub(super) async fn snapshot(
    station: &ArkretServer,
    realm: &RealmId,
    applet: &AppletId,
) -> Result<Value> {
    let mut snapshot = super::super::applet_installations::originals(
        station
            .owned_database_url()
            .context("owned governor DB absent")?,
        realm,
        applet,
    )
    .await?;
    let database = station
        .owned_database_url()
        .context("owned governor DB absent")?
        .to_owned();
    let realm = realm.to_string();
    let applet = applet.to_string();
    let additional=tokio::task::spawn_blocking(move||->Result<Value>{
        let mut db=postgres::Client::connect(&database,postgres::NoTls)?;
        let mut result=serde_json::Map::new();
        for (name,sql) in [
            ("actors","SELECT to_jsonb(r) FROM realm_actor_creations r WHERE realm_id=$1 AND applet_id=$2 ORDER BY to_jsonb(r)::text"),
            ("actor_current","SELECT to_jsonb(r) FROM realm_actor_current_states r WHERE realm_id=$1 AND $2<>'' ORDER BY to_jsonb(r)::text"),
            ("configurations","SELECT to_jsonb(r) FROM applet_configurations r WHERE realm_id=$1 AND applet_id=$2 ORDER BY to_jsonb(r)::text"),
            ("reviews","SELECT to_jsonb(r) FROM management_review_requests r WHERE realm_id=$1 AND $2<>'' ORDER BY to_jsonb(r)::text"),
            ("completions","SELECT to_jsonb(r) FROM applet_authoring_completions r WHERE realm_id=$1 AND applet_id=$2 ORDER BY to_jsonb(r)::text"),
        ] {
            let rows=db.query(sql,&[&realm,&applet])?;
            result.insert(name.into(),json!(rows.into_iter().map(|row|row.get::<_,Value>(0)).collect::<Vec<_>>()));
        }
        Ok(Value::Object(result))
    }).await??;
    snapshot
        .as_object_mut()
        .context("base business snapshot absent")?
        .extend(
            additional
                .as_object()
                .context("actor snapshot absent")?
                .clone(),
        );
    Ok(snapshot)
}

pub(super) fn same_canonical(left: &Value, right: &Value) -> Result<()> {
    for key in [
        "events",
        "committed",
        "actors",
        "actor_current",
        "installations",
        "registration_instances",
        "registration_current",
        "sources",
        "grants",
        "quota_counters",
        "quota_buckets",
        "quota_consumptions",
    ] {
        ensure!(
            left.get(key).is_some() && left[key] == right[key],
            "operation changed native business {key}"
        );
    }
    Ok(())
}

pub(super) async fn wait_delivered(
    station: &ArkretServer,
    realm: &RealmId,
    applet: &AppletId,
    originals: &[&CommittedEventFullView],
) -> Result<Value> {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(90);
    loop {
        let state = snapshot(station, realm, applet).await?;
        let rows = state["completions"]
            .as_array()
            .context("native completion outbox absent")?;
        let all_delivered = originals.iter().all(|original| {
            rows.iter().any(|row| {
                row["creation_ref"]["event_id"] == json!(original.event.event_id)
                    && !row["delivered_at"].is_null()
            })
        });
        if all_delivered {
            ensure!(
                rows.len() == originals.len()
                    && state["actors"]
                        .as_array()
                        .is_some_and(|actors| actors.len() == originals.len()),
                "completion or Actor creation duplicated its immutable identity"
            );
            for original in originals {
                super::super::applet_installations::require_original(&state, original)?;
            }
            ensure!(
                state["quota_counters"]
                    .as_array()
                    .is_some_and(|rows| !rows.is_empty())
                    && state["quota_counters"].as_array().is_some_and(|rows| rows
                        .iter()
                        .try_fold(0_i64, |sum, row| row["consumed"]
                            .as_i64()
                            .map(|count| sum + count))
                        == Some(originals.len() as i64))
                    && state["quota_consumptions"]
                        .as_array()
                        .is_some_and(|rows| rows.len() == originals.len()),
                "finite live creation quota did not record exactly the accepted operations"
            );
            return Ok(state);
        }
        ensure!(
            tokio::time::Instant::now() < deadline,
            "native completion worker never delivered both actual creations"
        );
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
}

pub(super) fn require_cold_originals(
    cold: &Value,
    originals: &[&CommittedEventFullView],
) -> Result<()> {
    let rows = cold["records"]["originals"]
        .as_array()
        .context("cold public creation journal absent")?;
    ensure!(
        rows.len() == originals.len(),
        "cold journal duplicated or lost a managed creation"
    );
    for original in originals {
        let mut found = false;
        for row in rows {
            let body: AppletAuthoringTransactionRequestBody =
                serde_json::from_str(row[1].as_str().context("cold journal bytes absent")?)?;
            body.authoring_context.validate()?;
            let RealmActorMaterial::Event {
                event,
                commit,
                producer_signer_fact,
            } = &body.authoring_context.material.material
            else {
                anyhow::bail!("cold creation journal lost original Event material");
            };
            if event.event_id == original.event.event_id {
                ensure!(
                    !found && event == &original.event && commit == &original.commit,
                    "cold journal changed the exact accepted Event/Commit"
                );
                arkret_identity::account_device_signer_evidence::verify_historical_producer_event_signature(
                    event,
                    producer_signer_fact,
                    arkret_canonical::DigestSuite::Sha256,
                )?;
                found = true;
            }
        }
        ensure!(found, "cold journal omitted an exact accepted creation");
    }
    ensure!(
        cold["records"]["configurations"]
            .as_array()
            .is_some_and(|rows| rows.len() == 1),
        "cold native configuration journal is missing or duplicated"
    );
    Ok(())
}
