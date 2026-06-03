use anyhow::{Result, anyhow};
use cokret_http_client::Client as SdkClient;
use reqwest::{Client as HttpClient, StatusCode};
use serde_json::{Value, json};
use url::Url;

use super::assertions::{account_subscribe_delta_from_text, expect_json, expect_response};
use super::event_builder::event_envelope;
use super::{member_join_payload, next_typed_id, realm_create_payload};

#[derive(Clone)]
pub struct TestActorClient {
    pub(super) http: HttpClient,
    pub(super) sdk: SdkClient,
    pub(super) base_url: Url,
    pub(super) service_did: String,
    pub actor: String,
    pub device_id: String,
    pub token: String,
}

impl TestActorClient {
    pub fn sdk(&self) -> SdkClient {
        self.sdk.clone()
    }

    pub fn service_did(&self) -> &str {
        &self.service_did
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
                "plaintext_visible_services": [self.service_did.clone()]
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
        let payload = realm_create_payload(&self.actor, &self.service_did, &realm_id, &body);
        let event_response = self
            .submit_event(&realm_id, "ck.realm.create", payload)
            .await?;
        Ok(json!({
            "realm_id": realm_id,
            "event_response": event_response,
        }))
    }

    pub async fn add_member(&self, realm_id: &str, member: &TestActorClient) -> Result<Value> {
        self.submit_event(
            realm_id,
            "ck.member.state",
            member_join_payload(&member.actor),
        )
        .await
    }

    pub async fn send_message(&self, realm_id: &str, thread_id: &str, body: &str) -> Result<Value> {
        self.submit_event(
            realm_id,
            "ck.message.create",
            json!({
                "body": body,
                "content": {"body": body},
                "thread_id": thread_id,
            }),
        )
        .await
    }

    pub async fn submit_event(&self, realm_id: &str, kind: &str, payload: Value) -> Result<Value> {
        let event = event_envelope(&self.actor, realm_id, kind, payload);
        expect_json(
            self.post("/_cokret/self/events").json(&event),
            StatusCode::OK,
        )
        .await
    }

    pub async fn sync(&self) -> Result<Value> {
        let response = expect_response(
            self.get("/_cokret/self/account/subscribe?catchup=true")
                .header("accept", "application/x-ndjson"),
            StatusCode::OK,
        )
        .await?;
        account_subscribe_delta_from_text(&response.text())
    }
}
