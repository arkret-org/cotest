use anyhow::{Result, anyhow};
use arkret_http_client::Client as SdkClient;
use reqwest::{Client as HttpClient, StatusCode};
use serde_json::{Value, json};
use url::Url;

use super::assertions::{account_subscribe_delta_from_text, expect_json, expect_response};
use super::event_builder::{
    ensure_submit_event_id, event_envelope_with_chain, realm_bootstrap_event_batch,
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
}

impl TestActorClient {
    pub fn sdk(&self) -> SdkClient {
        self.sdk.clone()
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
        let payload = realm_create_payload(&self.actor, &self.service_id, &realm_id, &body);
        let events = realm_bootstrap_event_batch(&self.actor, &realm_id, payload)?;
        let event_response = expect_json(
            self.post("/_arkret/self/events")
                .json(&json!({"events": events})),
            StatusCode::OK,
        )
        .await?;
        Ok(json!({
            "realm_id": realm_id,
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
        let is_control_move = arkret_wire::events::EventKind::from(kind)
            .descriptor()
            .is_some_and(|descriptor| descriptor.plane == Some("control"));
        if is_control_move
            && event["effects"]
                .as_array()
                .is_some_and(|effects| !effects.is_empty())
        {
            let seal_frontier = expect_json(
                self.get("/_arkret/self/events/frontier")
                    .query(&[("realm_id", realm_id)]),
                StatusCode::OK,
            )
            .await?;
            let state: arkret_models_collaboration::event_sync::EventsFrontierAccountClientState =
                serde_json::from_value(seal_frontier)?;
            let arkret_models_collaboration::event_sync::EventsFrontierView::RealmSeal(frontier) =
                state.frontier
            else {
                return Err(anyhow!(
                    "Realm selector returned the wrong frontier variant"
                ));
            };
            event["seal_basis"] = serde_json::to_value(frontier.seal_basis())?;
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
