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
        let frontier = expect_json(
            self.get(&format!(
                "/_arkret/self/events/frontier?actor_id={}&realm_id={realm_id}",
                self.actor
            )),
            StatusCode::OK,
        )
        .await?;
        let accepted_seq = frontier["frontier"]["actor_seq"]
            .as_u64()
            .ok_or_else(|| anyhow!("actor Realm frontier missing actor_seq: {frontier}"))?;
        let prev_event_id = frontier["frontier"]["event_id"].as_str();
        if (accepted_seq == 0) != prev_event_id.is_none() {
            return Err(anyhow!(
                "actor Realm frontier must pair sequence and Event id: {frontier}"
            ));
        }
        let event = event_envelope_with_chain(
            &self.actor,
            realm_id,
            kind,
            payload,
            accepted_seq + 1,
            prev_event_id,
        );
        let mut body = expect_json(
            self.post("/_arkret/self/events").json(&event),
            StatusCode::OK,
        )
        .await?;
        ensure_submit_event_id(&mut body, &event);
        Ok(body)
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
