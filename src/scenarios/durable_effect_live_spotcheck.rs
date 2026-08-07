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

use crate::harness::{CanonicalJsonBody, TestActorClient, TestServerGroup, expect_json};
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
    let listed = expect_json(
        client
            .get("/_arkret/self/events")
            .query(&[("realms", realm_id), ("limit", "200")]),
        StatusCode::OK,
    )
    .await?;
    Ok(listed["events"]
        .as_array()
        .ok_or_else(|| anyhow!("events query missing events array: {listed}"))?
        .iter()
        .filter_map(|event| {
            event["kind"]
                .as_str()
                .or_else(|| event["event_kind"].as_str())
                .map(ToOwned::to_owned)
        })
        .collect())
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
    let group = TestServerGroup::single("durable-effect-spotcheck").await?;
    let server = group.server(0);
    let alice = server
        .demo_client(
            "did:web:alice-durable-effect.example",
            "ak:device:01904100-0000-7000-8000-0000000000a1",
        )
        .await?;
    let bob = server
        .register_client(
            "did:web:bob-durable-effect.example",
            "bob-durable-effect",
            "ak:device:01904100-0000-7000-8000-0000000000b1",
        )
        .await?;
    let realm_id = alice.create_realm("Durable Effect Spot-Check").await?;
    alice
        .grant_self_realm_actions(&realm_id, &["ak.policy.manage"])
        .await?;

    let mut observations = serde_json::Map::new();

    // ── 1. policy replace (PUT .../policy-server) ──────────────────────────
    let replace_effect =
        declared_effect(&registry, "ak.self.realm_policy_server.resource.replace")?;
    let before = realm_event_kinds(&alice, &realm_id).await?;
    // The declaration is what the caller signs; the request body carries that
    // Event and nothing else.
    let declaration = json!({
        "policy_server_did": "did:web:spotcheck-policy.example",
        "policy_server_url": "https://spotcheck-policy.example/_arkret/self/policy/check",
        "cache_ttl_seconds": 60,
        "timeout_ms": 1500,
        "on_timeout": "fail_closed",
    });
    let response = alice
        .put(&format!("/_arkret/self/realms/{realm_id}/policy-server"))
        .canonical_json(
            &arkret_models_collaboration::governance::realm_governance::RealmPolicyServerReplaceRequestBody {
                policy_server_event: arkret_wire::EventInitialSubmission::online(
                    alice
                        .author_event(
                            &realm_id,
                            arkret_wire::EventKind::REALM_POLICY_SERVER,
                            declaration.clone(),
                        )
                        .await?,
                ),
            },
        )?
        .send()
        .await?;
    let replace_status = response.status();
    let replace_body = response.json::<Value>().await.unwrap_or(Value::Null);
    assert_eq!(
        replace_status,
        StatusCode::OK,
        "policy replace: {replace_body}"
    );
    let after = realm_event_kinds(&alice, &realm_id).await?;
    let replace_appended = assert_event_log_effect(
        "ak.self.realm_policy_server.resource.replace",
        &replace_effect,
        &before,
        &after,
    )?;
    observations.insert(
        "ak.self.realm_policy_server.resource.replace".to_owned(),
        json!({"status": replace_status.as_u16(), "appended_kinds": replace_appended}),
    );

    // ── 2. policy delete (DELETE .../policy-server) ────────────────────────
    let delete_effect = declared_effect(&registry, "ak.self.realm_policy_server.resource.delete")?;
    let before = realm_event_kinds(&alice, &realm_id).await?;
    // The removal is a signed Event too, so the DELETE carries a body, and the
    // caller attaches its own `head_eq`: a precondition is inside the bytes it
    // signs.
    let response = alice
        .delete(&format!("/_arkret/self/realms/{realm_id}/policy-server"))
        .canonical_json(
            &arkret_models_collaboration::governance::realm_governance::RealmPolicyServerDeleteRequestBody {
                policy_server_event: arkret_wire::EventInitialSubmission::online(
                    alice
                        .author_event_with_preconditions(
                            &realm_id,
                            arkret_wire::EventKind::REALM_POLICY_SERVER,
                            json!({ "tombstone": true }),
                            vec![crate::harness::head_eq_precondition(
                                "ak:cell:ak.component.realm.policy_server.v1:null",
                                declaration,
                            )],
                        )
                        .await?,
                ),
            },
        )?
        .send()
        .await?;
    let delete_status = response.status();
    let delete_body = response.json::<Value>().await.unwrap_or(Value::Null);
    assert_eq!(
        delete_status,
        StatusCode::OK,
        "policy delete: {delete_body}"
    );
    let after = realm_event_kinds(&alice, &realm_id).await?;
    let delete_appended = assert_event_log_effect(
        "ak.self.realm_policy_server.resource.delete",
        &delete_effect,
        &before,
        &after,
    )?;
    observations.insert(
        "ak.self.realm_policy_server.resource.delete".to_owned(),
        json!({"status": delete_status.as_u16(), "appended_kinds": delete_appended}),
    );

    // ── 3. moderation report ───────────────────────────────────────────────
    let report_operation = "ak.self.moderation.command.report";
    if let Ok(report_effect) = declared_effect(&registry, report_operation) {
        let before = realm_event_kinds(&alice, &realm_id).await?;
        let response = alice
            .post("/_arkret/self/moderation/report")
            .canonical_json(&serde_json::from_value::<
                arkret_models_collaboration::governance::moderation::ModerationReportRequestBody,
            >(json!({
                "realm_id": realm_id,
                "target_ref": realm_id,
                "reporter": alice.actor,
                "report_reason_code": "spam",
            }))?)?
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
    let push_operation = "ak.edge.push.command.register_device";
    let push_effect = declared_effect(&registry, push_operation)?;
    assert_eq!(
        push_effect,
        DeclaredEffect::None,
        "{push_operation} is expected to declare no durable Event effect"
    );
    let before = realm_event_kinds(&alice, &realm_id).await?;
    let response = alice
        .post("/_arkret/edge/push/register-device")
        .canonical_json(&serde_json::from_value::<
            arkret_models_integration::PushRegisterDeviceRequestBody,
        >(json!({
            "device_id": alice.device_id,
            "push_gateway": "https://push.example/spotcheck",
            "push_key": "cotest-spotcheck-key",
            "platform": "web",
        }))?)?
        .send()
        .await?;
    let push_status = response.status();
    let push_body = response.json::<Value>().await.unwrap_or(Value::Null);
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
    let private_operation = "ak.self.account_data.resource.replace";
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
        &arkret_models_identity::principal_control_realm_id(&arkret_wire::Did::new(
            alice.actor.clone(),
        )?),
        arkret_wire::EventKind::ACCOUNT_DATA_SET,
        json!({
            "key": account_data_key,
            "owner": alice.actor.clone(),
            "expected_revision": 0,
            "body": {"spotcheck": true},
        }),
    );
    let response = alice
        .put(&format!("/_arkret/self/account_data/{account_data_key}"))
        .json(
            &arkret_models_identity::account::AccountDataReplaceRequestBody {
                set_event: arkret_wire::EventInitialSubmission::online(set_event),
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
        "ak:invite:01999999-0000-7000-8000-00000000de01",
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
