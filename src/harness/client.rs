use anyhow::{Result, anyhow};
use arkret_http_client::Client as SdkClient;
use ed25519_dalek::SigningKey;
use reqwest::{Client as HttpClient, StatusCode};
use serde_json::{Value, json};
use url::Url;

use super::assertions::{account_subscribe_delta_from_text, expect_json, expect_response};
use super::event_builder::{
    ensure_submit_event_id, event_envelope_with_causal_refs, event_envelope_with_chain,
    realm_bootstrap_event_batch,
};
use super::{
    member_join_payload, message_create_text_payload, next_typed_id, realm_create_payload,
    refresh_event_proof,
};

#[derive(Clone)]
pub struct TestActorClient {
    pub(super) http: HttpClient,
    pub(super) sdk: SdkClient,
    pub(super) base_url: Url,
    pub(super) service_id: String,
    pub actor: String,
    pub device_id: String,
    pub token: String,
    /// Realms this actor created, i.e. the ones whose authority-root cell it
    /// controls. `capabilities.md` section 3.2: v1 genesis issues no self-grant,
    /// so the controller authorizes its own Events by naming that cell in
    /// `authorization_ref` instead of a grant id. Clones share the set because
    /// scenarios clone the client freely and the controller does not change.
    pub(super) controlled_realms:
        std::sync::Arc<std::sync::Mutex<std::collections::BTreeSet<String>>>,
    /// Grants issued to this actor, keyed by Realm. Membership derives read
    /// access only (`capabilities.md` line 700); every write action still needs
    /// a covering grant, which a DataEvent names in `refs[role=authorized_by]`.
    pub(super) held_grants:
        std::sync::Arc<std::sync::Mutex<std::collections::BTreeMap<String, Vec<String>>>>,
}

impl TestActorClient {
    pub fn sdk(&self) -> SdkClient {
        self.sdk.clone()
    }

    /// Read the Realm Seal frontier, waiting out the control-seal coordinator.
    ///
    /// Control Move finality belongs to the durable coordinator, which runs
    /// asynchronously: between accepting a Realm genesis unit and publishing
    /// the Seal that covers it, the frontier answers `503
    /// frontier_unavailable`. That is a transient state a client waits out,
    /// not an error — every Realm-scoped Seal read here therefore retries it.
    pub async fn realm_seal_frontier(&self, realm_id: &str) -> Result<Value> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            let response = expect_response(
                self.get("/_arkret/self/events/frontier")
                    .query(&[("realm_id", realm_id)]),
                StatusCode::OK,
            )
            .await;
            match response {
                Ok(response) => return response.json(),
                Err(error) if std::time::Instant::now() < deadline => {
                    if !format!("{error}").contains("frontier_unavailable") {
                        return Err(error);
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
                Err(error) => return Err(error),
            }
        }
    }

    /// Whether this actor controls `realm_id`'s authority root, i.e. created it.
    /// Record a grant this actor now holds in `realm_id`, so its later
    /// DataEvents name it as their covering authority.
    pub fn remember_grant(&self, realm_id: &str, grant_id: &str) {
        self.held_grants
            .lock()
            .expect("cotest held-grant map is not poisoned")
            .entry(realm_id.to_owned())
            .or_default()
            .push(grant_id.to_owned());
    }

    pub fn held_grants_for(&self, realm_id: &str) -> Vec<String> {
        self.held_grants
            .lock()
            .expect("cotest held-grant map is not poisoned")
            .get(realm_id)
            .cloned()
            .unwrap_or_default()
    }

    /// Issue a Realm grant and record it on the subject's own client.
    pub async fn grant_realm_actions_to_client(
        &self,
        realm_id: &str,
        subject: &TestActorClient,
        actions: &[&str],
    ) -> Result<String> {
        let (grant_id, _) = self
            .grant_realm_actions_to(realm_id, &subject.actor, actions)
            .await?;
        subject.remember_grant(realm_id, &grant_id);
        Ok(grant_id)
    }

    pub fn controls_realm_authority_root(&self, realm_id: &str) -> bool {
        self.controlled_realms
            .lock()
            .expect("cotest controlled-Realm set is not poisoned")
            .contains(realm_id)
    }

    pub fn service_id(&self) -> &str {
        &self.service_id
    }

    pub fn url(&self, path: &str) -> String {
        self.base_url
            .join(path.trim_start_matches('/'))
            .expect("valid test path")
            .to_string()
    }

    pub fn get(&self, path: &str) -> reqwest::RequestBuilder {
        self.http.get(self.url(path)).bearer_auth(&self.token)
    }

    pub fn post(&self, path: &str) -> reqwest::RequestBuilder {
        self.http.post(self.url(path)).bearer_auth(&self.token)
    }

    pub fn put(&self, path: &str) -> reqwest::RequestBuilder {
        self.http.put(self.url(path)).bearer_auth(&self.token)
    }

    pub fn delete(&self, path: &str) -> reqwest::RequestBuilder {
        self.http.delete(self.url(path)).bearer_auth(&self.token)
    }

    pub async fn create_realm(&self, title: &str) -> Result<String> {
        let created = self
            .create_realm_with(json!({
                "title": title,
                "summary": title,
                "public": false,
                "plaintext_visible_services": [self.service_id.clone()]
            }))
            .await?;
        created["realm_id"]
            .as_str()
            .map(ToOwned::to_owned)
            .ok_or_else(|| anyhow!("create realm response did not include realm_id: {created}"))
    }

    pub async fn create_realm_with(&self, body: Value) -> Result<Value> {
        let realm_id = body
            .get("realm_id")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| next_typed_id("realm"));
        self.controlled_realms
            .lock()
            .expect("cotest controlled-Realm set is not poisoned")
            .insert(realm_id.clone());
        let payload = realm_create_payload(&self.actor, &self.service_id, &realm_id, &body);
        let events = realm_bootstrap_event_batch(&self.actor, &realm_id, payload)?;
        let event_response = expect_json(
            self.post("/_arkret/self/events")
                .json(&json!({"events": events})),
            StatusCode::OK,
        )
        .await?;
        // A DataEvent that writes a cell has to name a covering authority in
        // `refs[role=authorized_by]` / `authorization_ref`. For the creator that
        // authority is the Realm authority-root cell the create contract wrote,
        // not a grant id: v1 genesis issues no capability grant at all.
        Ok(json!({
            "realm_id": realm_id,
            "authority_root_ref": arkret_wire::REALM_AUTHORITY_ROOT_CELL,
            "event_response": event_response,
        }))
    }

    pub async fn add_member(&self, realm_id: &str, member: &TestActorClient) -> Result<Value> {
        self.submit_event(
            realm_id,
            "ak.member.state",
            member_join_payload(realm_id, &member.actor),
        )
        .await
    }

    pub async fn grant_self_realm_actions(
        &self,
        realm_id: &str,
        actions: &[&str],
    ) -> Result<(String, Value)> {
        self.grant_realm_actions_to(realm_id, &self.actor, actions)
            .await
    }

    pub async fn grant_realm_actions_to(
        &self,
        realm_id: &str,
        subject: &str,
        actions: &[&str],
    ) -> Result<(String, Value)> {
        let grant_id = next_typed_id("grant");
        let issued_at = chrono::Utc::now();
        let verification_method = format!("{}#cotest", self.actor);
        let mut grant =
            arkret_models_collaboration::governance::grant_constraint::CapabilityGrant {
                id: arkret_identifiers::GrantId::new(grant_id.clone())?,
                schema: "ak.schema.capability.v1".to_owned(),
                realm_id: Some(arkret_identifiers::RealmId::new(realm_id.to_owned())?),
                issuer: arkret_identifiers::Did::new(self.actor.clone())?,
                subject: arkret_models_collaboration::governance::grant_constraint::CapabilitySubject::Did(
                    arkret_identifiers::Did::new(subject.to_owned())?,
                ),
                actions: actions.iter().map(|action| (*action).to_owned()).collect(),
                resources: vec![serde_json::from_value(json!({
                    "kind": "realm",
                    "realm_id": realm_id,
                    "match_scope": "realm_wide"
                }))?],
                capability_action_registry_digest: Some(
                    arkret::current_capability_action_registry_digest()?,
                ),
                constraints: Vec::new(),
                issuer_authority_refs: vec![arkret::IssuerAuthorityRef::RealmRoot {
                    realm_id: arkret_identifiers::RealmId::new(realm_id.to_owned())?,
                    cell_ref: "ak:cell:ak.component.realm.authority_root.v1:null".to_owned(),
                    controller_epoch_at_issuance: 0,
                    authority_generation: 0,
                }],
                issued_at,
                not_before: None,
                expires_at: None,
                updated_by: None,
                updated_at: None,
                revoked_by: None,
                revoked_at: None,
                proofs: Vec::new(),
            };
        let mut proof = arkret_wire::PayloadProof {
            kind: arkret_wire::proof_kind::DETACHED_JWS.to_owned(),
            alg: "EdDSA".to_owned(),
            verification_method: verification_method.clone(),
            payload_digest: grant.payload_digest()?,
            created_at: issued_at,
            domain: None,
            audience: None,
            proof_purpose: Some(arkret_wire::PayloadProofPurpose::IssuerAttestation),
            jws: String::new(),
        };
        proof.jws = arkret_signatures::sign_eddsa_detached_jws(
            &SigningKey::from_bytes(&arkret::signatures::development_signing_key_seed(
                &verification_method,
            )),
            &grant.canonical_proof_binding_bytes(&proof)?,
        )?;
        grant.proofs.push(proof);
        let payload = arkret_models_collaboration::events_payloads::CapabilityGrantPayload {
            grant: Some(grant),
            grant_id: arkret_identifiers::GrantId::new(grant_id.clone())?,
            subject: None,
            actions: None,
            resources: None,
        };
        let response = self
            .submit_event(
                realm_id,
                arkret_wire::events::EventKind::CAPABILITY_GRANT,
                serde_json::to_value(payload)?,
            )
            .await?;
        Ok((grant_id, response))
    }

    pub async fn send_message(
        &self,
        realm_id: &str,
        _thread_id: &str,
        body: &str,
    ) -> Result<Value> {
        self.submit_event(
            realm_id,
            "ak.message.create",
            message_create_text_payload(realm_id, body)?,
        )
        .await
    }

    pub async fn submit_event(&self, realm_id: &str, kind: &str, payload: Value) -> Result<Value> {
        let event = self.author_event(realm_id, kind, payload).await?;
        let mut body = expect_json(
            self.post("/_arkret/self/events").json(&event),
            StatusCode::OK,
        )
        .await?;
        ensure_submit_event_id(&mut body, &event);
        Ok(body)
    }

    /// Authors and submits an Event carrying explicit semantic causal edges.
    ///
    /// RSVP convergence is defined by `causal_refs`: a response dominates
    /// exactly the heads it names. Two responses that omit each other are
    /// concurrent, which is the case the projection has to keep exposed.
    /// `prev_refs` is passed into the builder before signing rather than
    /// patched on afterwards, so the proof covers the actor chain it claims.
    pub async fn submit_event_with_causal_refs(
        &self,
        realm_id: &str,
        kind: &str,
        payload: Value,
        causal_refs: Vec<String>,
        capability_refs: Vec<String>,
    ) -> Result<Value> {
        let event = self
            .author_event_with_causal_refs(realm_id, kind, payload, causal_refs, capability_refs)
            .await?;
        let mut body = expect_json(
            self.post("/_arkret/self/events").json(&event),
            StatusCode::OK,
        )
        .await?;
        ensure_submit_event_id(&mut body, &event);
        // The digest is what a later response names to dominate this head, so
        // hand it back to the caller alongside the submit result.
        body["cotest_event_digest"] = event["proofs"][0]["event_digest"].clone();
        Ok(body)
    }

    /// Authors, but does not submit, an Event carrying explicit semantic
    /// causal edges. Keeping authoring separate lets convergence tests prepare
    /// genuinely concurrent Events before either client sends one.
    pub async fn author_event_with_causal_refs(
        &self,
        realm_id: &str,
        kind: &str,
        payload: Value,
        causal_refs: Vec<String>,
        capability_refs: Vec<String>,
    ) -> Result<Value> {
        let frontier = expect_json(
            self.get("/_arkret/self/events/frontier")
                .query(&[("actor_id", self.actor.as_str()), ("realm_id", realm_id)]),
            StatusCode::OK,
        )
        .await?;
        let state: arkret_models_collaboration::event_sync::EventsFrontierAccountClientState =
            serde_json::from_value(frontier)?;
        let arkret_models_collaboration::event_sync::EventsFrontierView::RealmActor(frontier) =
            state.frontier
        else {
            return Err(anyhow!(
                "combined selector returned the wrong frontier variant"
            ));
        };
        let mut event = event_envelope_with_causal_refs(
            &self.actor,
            realm_id,
            kind,
            payload,
            Some(frontier.next_actor_seq),
            frontier
                .frontier_event_ids
                .iter()
                .map(|event_id| {
                    arkret_identifiers::EventId::new(event_id.as_str().to_owned())
                        .expect("frontier event id")
                })
                .collect(),
            causal_refs,
        );
        let is_data_event = arkret_wire::events::EventKind::from(kind)
            .descriptor()
            .is_some_and(|descriptor| descriptor.reducer_input && descriptor.plane == Some("data"));
        if is_data_event {
            let seal_frontier = self.realm_seal_frontier(realm_id).await?;
            let state: arkret_models_collaboration::event_sync::EventsFrontierAccountClientState =
                serde_json::from_value(seal_frontier.clone()).map_err(|error| {
                    anyhow!("invalid Realm frontier response `{seal_frontier}`: {error}")
                })?;
            let arkret_models_collaboration::event_sync::EventsFrontierView::RealmSeal(frontier) =
                state.frontier
            else {
                return Err(anyhow!(
                    "Realm selector returned the wrong frontier variant"
                ));
            };
            // A DataEvent anchors its effects with `seal_ref`, not
            // `seal_basis`: carrying a Seal basis is what marks an Event as a
            // Control Move, and a Control Move may not write a data-plane cell.
            event["seal_ref"] = serde_json::to_value(&frontier.seal_id)?;
            // Capability coverage is per DataEvent: the reducer checks that a
            // named grant actually covers this action on this target.
            event["auth_context"] = json!({
                "did": self.actor,
                "key_id": format!("{}#cotest", self.actor),
                "key_epoch": 0
            });
            if self.controls_realm_authority_root(realm_id) {
                event["authorization_ref"] = json!(arkret_wire::REALM_AUTHORITY_ROOT_CELL);
            }
            event["refs"] = Value::Array(
                capability_refs
                    .into_iter()
                    .map(|grant_id| {
                        json!({
                            "id": grant_id,
                            "role": arkret_wire::EVENT_REF_ROLE_AUTHORIZED_BY,
                            "critical": true
                        })
                    })
                    .collect(),
            );
            if kind == arkret_wire::events::EventKind::STRAND_UPDATE
                && payload_patch_touches_calendar(&event["payload"])
            {
                event["requirements"] = json!({
                    "schema": ["ak.schema.calendar_event.v1"]
                });
            }
            refresh_event_proof(&mut event)?;
        }
        Ok(event)
    }

    pub async fn author_event(&self, realm_id: &str, kind: &str, payload: Value) -> Result<Value> {
        let frontier = expect_json(
            self.get("/_arkret/self/events/frontier")
                .query(&[("actor_id", self.actor.as_str()), ("realm_id", realm_id)]),
            StatusCode::OK,
        )
        .await?;
        let state: arkret_models_collaboration::event_sync::EventsFrontierAccountClientState =
            serde_json::from_value(frontier)?;
        let arkret_models_collaboration::event_sync::EventsFrontierView::RealmActor(frontier) =
            state.frontier
        else {
            return Err(anyhow!(
                "combined selector returned the wrong frontier variant"
            ));
        };
        frontier.validate()?;
        if frontier.realm_id.as_str() != realm_id || frontier.actor_id.as_str() != self.actor {
            return Err(anyhow!("combined selector returned the wrong actor scope"));
        }
        let mut event = event_envelope_with_chain(
            &self.actor,
            realm_id,
            kind,
            payload,
            frontier.next_actor_seq,
            None,
        );
        event["prev_refs"] = serde_json::to_value(frontier.frontier_event_ids)?;
        let descriptor = arkret_wire::events::EventKind::from(kind).descriptor();
        let is_control_move = descriptor.is_some_and(|descriptor| {
            descriptor.reducer_input && descriptor.plane == Some("control")
        });
        let is_data_event = descriptor
            .is_some_and(|descriptor| descriptor.reducer_input && descriptor.plane == Some("data"));
        if is_control_move || is_data_event {
            let seal_frontier = self.realm_seal_frontier(realm_id).await?;
            let state: arkret_models_collaboration::event_sync::EventsFrontierAccountClientState =
                serde_json::from_value(seal_frontier.clone()).map_err(|error| {
                    anyhow!("invalid Realm frontier response `{seal_frontier}`: {error}")
                })?;
            let arkret_models_collaboration::event_sync::EventsFrontierView::RealmSeal(frontier) =
                state.frontier
            else {
                return Err(anyhow!(
                    "Realm selector returned the wrong frontier variant"
                ));
            };
            if is_control_move {
                event["seal_basis"] = serde_json::to_value(frontier.seal_basis())?;
                let physical_millis = chrono::Utc::now().timestamp_millis();
                event["hlc"] = json!(format!("{physical_millis:012x}-0000-a13f9c2e"));
            } else {
                event["seal_ref"] = serde_json::to_value(&frontier.seal_id)?;
                event["auth_context"] = json!({
                    "did": self.actor,
                    "key_id": format!("{}#cotest", self.actor),
                    "key_epoch": 0
                });
            }
            // The Realm creator holds no grant, so it names the authority-root
            // cell instead. Actors that only hold grants leave this unset and
            // carry `refs[role=authorized_by]`.
            if self.controls_realm_authority_root(realm_id) {
                event["authorization_ref"] = json!(arkret_wire::REALM_AUTHORITY_ROOT_CELL);
            } else if is_data_event {
                event["refs"] = Value::Array(
                    self.held_grants_for(realm_id)
                        .into_iter()
                        .map(|grant_id| {
                            json!({
                                "id": grant_id,
                                "role": arkret_wire::EVENT_REF_ROLE_AUTHORIZED_BY,
                                "critical": true
                            })
                        })
                        .collect(),
                );
            }
        }
        refresh_event_proof(&mut event)?;
        Ok(event)
    }

    pub async fn sync(&self) -> Result<Value> {
        let response = expect_response(
            self.get("/_arkret/self/account/subscribe?catchup=true")
                .header("accept", "application/x-ndjson"),
            StatusCode::OK,
        )
        .await?;
        account_subscribe_delta_from_text(&response.text())
    }
}

fn payload_patch_touches_calendar(payload: &Value) -> bool {
    payload
        .get("patch")
        .and_then(Value::as_object)
        .is_some_and(|patch| {
            patch.iter().any(|(path, value)| {
                if path == "metadata.fields.calendar"
                    || path.starts_with("metadata.fields.calendar.")
                {
                    return true;
                }
                if path == "metadata.fields" {
                    return value
                        .get("value")
                        .or_else(|| value.get("$value"))
                        .or_else(|| value.get("fields"))
                        .or(Some(value))
                        .and_then(Value::as_object)
                        .is_some_and(|fields| fields.contains_key("calendar"));
                }
                if path == "metadata" {
                    return value
                        .get("value")
                        .or_else(|| value.get("$value"))
                        .and_then(|metadata| metadata.get("fields"))
                        .and_then(Value::as_object)
                        .is_some_and(|fields| fields.contains_key("calendar"));
                }
                false
            })
        })
}
