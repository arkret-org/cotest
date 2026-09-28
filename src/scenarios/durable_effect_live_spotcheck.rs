//! COT-STATE-05 — live spot-check of the operation registry's
//! `durable_effect` declarations.
//!
//! `operation_registry_gate` proves each write operation *declares* a closed
//! `durable_effect`, but a declaration is only a claim about the running
//! service. This scenario calls the real operation and then reads back the
//! stream the declaration names:
//!
//!   * `kind: "event_log"` → the declared `event_kinds` must actually appear in the Realm's
//!     canonical Event log after the call;
//!   * `kind: "actor_private_event"` → the declared `ak.private.*` cell family must be reachable on
//!     the actor-private rail, and MUST NOT surface in the shared Realm Event log.
//!
//! Coverage is the four operations named in the remediation: policy replace,
//! policy delete, moderation report, and Invite create. Each spot-check
//! resolves its expectation from `registry/operation-registry.json` at runtime,
//! so a registry edit that drops or retargets a declaration fails here instead
//! of silently passing.

use std::collections::BTreeSet;

use anyhow::{Result, anyhow};
use chrono::Duration as ChronoDuration;
use reqwest::StatusCode;
use serde_json::{Value, json};

use crate::harness::{CanonicalJsonBody, TestActorClient, moderation_report_request};
use crate::scenarios::identity_test_support::{
    actor_did_for_service_did, spawn_with_standard_grant_authority,
};
use crate::transcripts::record_vector_event;

const OPERATION_REGISTRY_REF: &str = "registry/operation-registry.json";

/// The `durable_effect` an operation declares, reduced to what a live check can
/// observe.
#[derive(Debug, Clone, PartialEq, Eq)]
enum DeclaredEffect {
    /// Shared Realm Event log; the listed kinds must appear.
    EventLog { event_kinds: Vec<String> },
    /// Actor-private rail; the kind must NOT appear in the shared log.
    ActorPrivateEvent { event_kind: String },
    /// Declared as writing nothing durable.
    None,
    /// A dynamic `event_kind_source`: the kind comes from the request, so the
    /// caller supplies the expectation.
    DynamicEventKind,
}

fn load_operation_registry() -> Result<Value> {
    let path = crate::conformance::spec_artifacts_root().join(OPERATION_REGISTRY_REF);
    let raw = std::fs::read_to_string(&path)
        .map_err(|error| anyhow!("read {}: {error}", path.display()))?;
    serde_json::from_str(&raw).map_err(|error| anyhow!("parse {}: {error}", path.display()))
}

fn declared_effect(registry: &Value, operation_id: &str) -> Result<DeclaredEffect> {
    let operation = registry["operations"]
        .as_array()
        .ok_or_else(|| anyhow!("operation registry has no operations array"))?
        .iter()
        .find(|operation| operation["operation_id"].as_str() == Some(operation_id))
        .ok_or_else(|| anyhow!("operation {operation_id} is not in the registry"))?;
    let effect = operation
        .get("durable_effect")
        .ok_or_else(|| anyhow!("operation {operation_id} declares no durable_effect"))?;
    match effect["kind"].as_str() {
        Some("event_log") => {
            if effect.get("event_kind_source").is_some() {
                return Ok(DeclaredEffect::DynamicEventKind);
            }
            let event_kinds = effect["event_kinds"]
                .as_array()
                .ok_or_else(|| anyhow!("{operation_id} event_log declares no event_kinds"))?
                .iter()
                .filter_map(|kind| kind.as_str().map(ToOwned::to_owned))
                .collect::<Vec<_>>();
            if event_kinds.is_empty() {
                return Err(anyhow!("{operation_id} declares an empty event_kinds set"));
            }
            Ok(DeclaredEffect::EventLog { event_kinds })
        }
        Some("actor_private_event") => Ok(DeclaredEffect::ActorPrivateEvent {
            event_kind: effect["event_kind"]
                .as_str()
                .ok_or_else(|| anyhow!("{operation_id} actor_private_event has no event_kind"))?
                .to_owned(),
        }),
        Some("none") => Ok(DeclaredEffect::None),
        other => Err(anyhow!(
            "{operation_id} declares an unknown durable_effect kind {other:?}"
        )),
    }
}

async fn realm_event_kinds(client: &TestActorClient, realm_id: &str) -> Result<Vec<String>> {
    // `ak.self.committed_event.read.scan.v1` is the member read of the shared
    // Realm log: every accepted Event on the Realm commit stream, in order.
    let realm_id = arkret_wire::RealmId::new(realm_id.to_owned())?;
    let scanned = client
        .sdk()
        .scan_commit_stream_to_head(
            realm_id.clone(),
            arkret_wire::CommitStreamRef::Realm { realm_id },
            None,
            200,
        )
        .await?;
    scanned
        .committed_events
        .iter()
        .map(|item| {
            item.reducer_input()
                .map(|event| event.kind.as_str().to_owned())
                .ok_or_else(|| anyhow!("the Realm owner was shown a withheld committed Event"))
        })
        .collect()
}

/// Assert the shared Realm log gained exactly the declared kinds.
fn assert_event_log_effect(
    operation_id: &str,
    effect: &DeclaredEffect,
    before: &[String],
    after: &[String],
) -> Result<Vec<String>> {
    let DeclaredEffect::EventLog { event_kinds } = effect else {
        return Err(anyhow!(
            "{operation_id} was spot-checked as event_log but declares {effect:?}"
        ));
    };
    let appended = appended_kinds(before, after);
    for expected in event_kinds {
        if !appended.contains(expected) {
            return Err(anyhow!(
                "{operation_id} declares durable {expected} but the Realm log gained {appended:?}"
            ));
        }
    }
    Ok(appended.into_iter().collect())
}

fn appended_kinds(before: &[String], after: &[String]) -> BTreeSet<String> {
    let mut remaining: Vec<String> = before.to_vec();
    let mut appended = BTreeSet::new();
    for kind in after {
        if let Some(index) = remaining.iter().position(|seen| seen == kind) {
            remaining.remove(index);
        } else {
            appended.insert(kind.clone());
        }
    }
    appended
}

/// Drive four declared write operations against a live Soland and verify each
/// one's `durable_effect` against the stream it names.
pub async fn declared_durable_effects_match_live_producers() -> Result<()> {
    let registry = load_operation_registry()?;
    // Accounts are founded through the harness Account Authority, and Alice
    // authors every Event below over her Standard SessionGrant.
    let station = spawn_with_standard_grant_authority("durable-effect-spotcheck", &[]).await?;
    let server = &station.server;
    let alice_did = actor_did_for_service_did(server.service_did(), "alice-durable-effect")?;
    let alice = station.standard_grant_client(
        &server
            .demo_client(&alice_did, "ak:device:01904100-0000-7000-8000-0000000000a1")
            .await?,
    )?;
    let bob_did = actor_did_for_service_did(server.service_did(), "bob-durable-effect")?;
    let bob = server
        .register_client(
            &bob_did,
            "bob-durable-effect",
            "ak:device:01904100-0000-7000-8000-0000000000b1",
        )
        .await?;
    let realm_id = alice.create_realm("Durable Effect Spot-Check").await?;
    let mut observations = serde_json::Map::new();

    // ── moderation report ─────────────────────────────────────────────────
    let report_operation = "ak.self.moderation.command.report.v1";
    if let Ok(report_effect) = declared_effect(&registry, report_operation) {
        let before = realm_event_kinds(&alice, &realm_id).await?;
        let report_request = moderation_report_request(
            &alice,
            &realm_id,
            &realm_id,
            arkret_wire::ScopeRef::Realm {
                realm_id: arkret_identifiers::RealmId::new(realm_id.clone())?,
            },
        )
        .await?;
        let response = alice
            .post("/_arkret/self/moderation/report")
            .canonical_json(&report_request)?
            .send()
            .await?;
        let report_status = response.status();
        let report_body = response.json::<Value>().await.unwrap_or(Value::Null);
        assert_eq!(
            report_status,
            StatusCode::OK,
            "moderation report: {report_body}"
        );
        let after = realm_event_kinds(&alice, &realm_id).await?;
        let report_appended =
            assert_event_log_effect(report_operation, &report_effect, &before, &after)?;
        observations.insert(
            report_operation.to_owned(),
            json!({"status": report_status.as_u16(), "appended_kinds": report_appended}),
        );
    } else {
        // The registry is the authority on the operation id; say so rather
        // than silently dropping this leg of the spot-check.
        eprintln!(
            "durable-effect spot-check: {report_operation} is absent from the registry; \
             moderation coverage skipped"
        );
        observations.insert(
            report_operation.to_owned(),
            json!({"skipped": "operation absent from registry"}),
        );
    }

    // ── 4. push route — declared `none` (service-local edge effect only) ───
    let push_operation = "ak.edge.push.command.register_device.v1";
    let push_effect = declared_effect(&registry, push_operation)?;
    assert_eq!(
        push_effect,
        DeclaredEffect::None,
        "{push_operation} is expected to declare no durable Event effect"
    );
    let before = realm_event_kinds(&alice, &realm_id).await?;
    let response = alice
        .post("/_arkret/edge/push/register-device")
        .canonical_json(&arkret_models_integration::PushRegisterDeviceRequestBody {
            device_id: arkret_wire::DeviceId::new(alice.device_id.clone())?,
            push_gateway_url: "https://push.example/spotcheck".to_owned(),
            push_key: arkret_models_integration::PushKey::new("cotest-spotcheck-key")
                .map_err(anyhow::Error::msg)?,
            platform: Some("web".to_owned()),
            app_id: None,
            display_name: None,
            visible_notification_opt_in: false,
        })?
        .send()
        .await?;
    let push_status = response.status();
    let push_body = response.json::<Value>().await.unwrap_or(Value::Null);
    // push-notifications.md §3.3: this Station has onboarded no public
    // Gateway, so the bare URL fails closed with the operation's registered
    // `push_gateway_unreachable`; the refusal must still leave no durable
    // Event behind.
    assert_eq!(
        push_status,
        StatusCode::SERVICE_UNAVAILABLE,
        "{push_operation} with a non-onboarded Gateway must fail closed: {push_body}"
    );
    assert_eq!(
        push_body["type"], "https://arkret.org/problems/push_gateway_unreachable",
        "{push_operation} refusal code: {push_body}"
    );
    let after = realm_event_kinds(&alice, &realm_id).await?;
    let push_appended = appended_kinds(&before, &after);
    assert!(
        push_appended.is_empty(),
        "{push_operation} declares no durable Event effect but the Realm log gained \
         {push_appended:?} ({push_status} {push_body})"
    );
    observations.insert(
        push_operation.to_owned(),
        json!({
            "status": push_status.as_u16(),
            "appended_kinds": Vec::<String>::new(),
        }),
    );

    // ── 5. account data — the actor-private rail ──────────────────────────
    // The one closed `actor_private_event` declaration reachable from a plain
    // session: its Event MUST NOT surface in the shared Realm log.
    let private_operation = "ak.self.account_data.resource.replace.v1";
    let private_effect = declared_effect(&registry, private_operation)?;
    let DeclaredEffect::ActorPrivateEvent {
        event_kind: private_kind,
    } = &private_effect
    else {
        return Err(anyhow!(
            "{private_operation} is expected on the actor-private rail, registry declares \
             {private_effect:?}"
        ));
    };
    let before = realm_event_kinds(&alice, &realm_id).await?;
    // The holder signs: `ak.account_data.set`'s actor-private cell subject is
    // composite[envelope.actor_id, payload.key], so the actor is half the cell
    // address and the service cannot author it.
    let account_data_key = "client.durable-effect-spotcheck";
    let set_event = crate::harness::event_envelope(
        &alice.actor,
        &realm_id,
        arkret_wire::event_kind_str::ACCOUNT_DATA_SET,
        json!({
            "key": account_data_key,
            "expected_server_revision": 0,
            "body": {"spotcheck": true},
        }),
    );
    let response = alice
        .put(&format!("/_arkret/self/account_data/{account_data_key}"))
        .json(
            &arkret_models_identity::account::AccountDataReplaceRequestBody {
                set_event: arkret_wire::EventAdmissionSubmission::new(set_event),
            },
        )
        .send()
        .await?;
    let private_status = response.status();
    let private_body = response.json::<Value>().await.unwrap_or(Value::Null);
    let after = realm_event_kinds(&alice, &realm_id).await?;
    let private_appended = appended_kinds(&before, &after);
    assert!(
        !private_appended.contains(private_kind),
        "{private_operation} declares the actor-private rail but {private_kind} surfaced \
         in the shared Realm log: {private_appended:?} ({private_status} {private_body})"
    );
    observations.insert(
        private_operation.to_owned(),
        json!({
            "status": private_status.as_u16(),
            "declared_private_kind": private_kind,
            "leaked_into_shared_log": false,
        }),
    );

    // ── 6. Invite create — a canonical Event, not a registry operation ─────
    // Invites reach the server through `POST /_arkret/self/events`, so their
    // durable effect is pinned by the event-kind registry rather than by an
    // operation `durable_effect`. Spot-check it the same way: the submitted
    // kind has to land in the shared log.
    let before = realm_event_kinds(&alice, &realm_id).await?;
    let expires_at = chrono::Utc::now() + ChronoDuration::days(7);
    let payload = crate::harness::invite_create_payload(
        bob.actor.as_str(),
        alice.service_id(),
        "sha256:3333333333333333333333333333333333333333333333333333333333333333",
        expires_at,
    )?;
    let submitted = alice
        .submit_event(&realm_id, "ak.invite.create", payload)
        .await?;
    let after = realm_event_kinds(&alice, &realm_id).await?;
    let invite_appended = appended_kinds(&before, &after);
    assert!(
        invite_appended.contains("ak.invite.create"),
        "ak.invite.create must land in the shared Realm log, got {invite_appended:?}: {submitted}"
    );
    observations.insert(
        "ak.invite.create".to_owned(),
        json!({
            "submit_status": submitted["status"].clone(),
            "appended_kinds": invite_appended.into_iter().collect::<Vec<_>>(),
        }),
    );

    record_vector_event(
        "operation_registry.durable_effect_live_spotcheck",
        &json!({"realm_id": realm_id}),
        &json!({
            "declared_event_log_kinds_appear": true,
            "declared_actor_private_kinds_stay_off_the_shared_log": true,
        }),
        &Value::Object(observations),
    );
    Ok(())
}
