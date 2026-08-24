use anyhow::{Result, anyhow};
use arkret::contact_operations::{
    ContactAcceptAction, ContactAcceptPrepareRequestBody, ContactAcceptRequestBody,
    ContactAcceptedOutcome, ContactCommitPhase, ContactCommitRequestBody, ContactOperationOutcome,
    ContactOperationRequestBody, ContactPeer, ContactPreparePhase, ContactPrepareRequestBody,
    ContactPreparedOutcome, ContactScope, RequestAcceptanceReceipt,
};
use arkret::{
    ContactIntroductionEvidence, IdempotencyKey, PreparedEventDraft, ProtocolOperationId,
};
use arkret_http_client::Client as SdkClient;
use arkret_identifiers::{DidCoreId, DidFullId, Hash, Hlc, RealmId, project_full_id_to_core_id};
use arkret_models_collaboration::events_payloads::{
    RealmSetDefaultStrandPayload, StrandCreatePayload,
};
use arkret_models_collaboration::objects::profiles::StrandTrack;
use arkret_models_collaboration::objects::strand::Strand;
use arkret_wire::{AuthContext, AuthorizationRef, Event, EventRef, ProfileRef};
use reqwest::{Client as HttpClient, StatusCode};
use serde_json::{Value, json};
use url::Url;

use super::assertions::{account_subscribe_delta_from_text, expect_json, expect_response};
use super::event_builder::{
    ensure_submit_event_id, event_envelope_with_causal_refs_for_device,
    event_envelope_with_chain_for_device, event_signing_identity_for_device,
    realm_bootstrap_event_batch_for_device,
};
use super::{
    events_frontier_request_body, member_join_payload, message_create_text_payload, next_typed_id,
    query_method, realm_create_payload_with_notary, refresh_typed_event_proof_with_signing_seed,
};

#[derive(Clone)]
pub struct TestActorClient {
    pub(super) http: HttpClient,
    pub(super) sdk: SdkClient,
    pub(super) base_url: Url,
    pub(super) service_id: String,
    pub(super) service_notary_signer: arkret_wire::NotarySignerDescriptor,
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
    /// The typed §5.1 provisioning behind this session when the client came
    /// from the canonical actor bootstrap (`demo_client` / `register_client`).
    /// `None` only for explicitly opted-out negative fixtures and raw
    /// token-carrier clients.
    pub principal: Option<super::ProvisionedTestPrincipal>,
    /// Exact accepted default-Strand coordinates for Realms created by this
    /// harness actor. Realm and Strand ids are independent Event-derived
    /// identities, so callers must consume this carrier rather than retype.
    pub(super) default_strands:
        std::sync::Arc<std::sync::Mutex<std::collections::BTreeMap<String, String>>>,
    /// Grants issued to this actor, keyed by Realm. Membership derives read
    /// access only (`capabilities.md` line 700); every write action still needs
    /// a covering grant, which a DataEvent names in `refs[role=authorized_by]`.
    pub(super) held_grants: HeldGrants,
}

/// Grants held per Realm: Realm id -> [(grant id, covered actions)].
type HeldGrants = std::sync::Arc<
    std::sync::Mutex<std::collections::BTreeMap<String, Vec<(String, Vec<String>)>>>,
>;

impl TestActorClient {
    pub fn sdk(&self) -> SdkClient {
        self.sdk.clone()
    }

    pub fn contact_request_prepare(&self, target: &str) -> Result<ContactOperationRequestBody> {
        let operation_id =
            ProtocolOperationId::new(next_typed_id("operation")).map_err(anyhow::Error::msg)?;
        let idempotency_key =
            IdempotencyKey::new(next_typed_id("idempotency")).map_err(anyhow::Error::msg)?;
        Ok(ContactOperationRequestBody::Prepare(
            ContactPrepareRequestBody {
                phase: ContactPreparePhase::Prepare,
                operation_id,
                idempotency_key,
                peer: ContactPeer::Human {
                    principal_id: project_full_id_to_core_id(&DidFullId::new(target.to_owned())?)?,
                },
                granted_to_peer_scopes: vec![ContactScope::DirectMessage],
                introduction_evidence: ContactIntroductionEvidence::ExplicitAddress,
                previous_terminal_contact_round_id: None,
                continuity_evidence: None,
                message: None,
            },
        ))
    }

    pub async fn request_contact(&self, target: &str) -> Result<RequestAcceptanceReceipt> {
        let request = self.contact_request_prepare(target)?;
        let (operation_id, idempotency_key) = match &request {
            ContactOperationRequestBody::Prepare(body) => {
                (body.operation_id.clone(), body.idempotency_key.clone())
            }
            ContactOperationRequestBody::Commit(_) => unreachable!("prepare constructor"),
        };
        let prepared = self.sdk.contacts_request(&request).await?;
        let prepared_replay = self.sdk.contacts_request(&request).await?;
        if serde_json::to_value(&prepared)? != serde_json::to_value(prepared_replay)? {
            return Err(anyhow!(
                "Contact request prepare replay changed its outcome"
            ));
        }
        let (prepared_operation_id, reservation_handle, event_draft) = match prepared {
            ContactOperationOutcome::Prepared {
                outcome:
                    ContactPreparedOutcome::Request {
                        operation_id,
                        reservation_handle,
                        event_draft,
                        ..
                    },
            } => (operation_id, reservation_handle, event_draft),
            ContactOperationOutcome::Failed { outcome } => {
                return Err(anyhow!(
                    "Contact request prepare failed: {:?}",
                    outcome.reason
                ));
            }
            _ => {
                return Err(anyhow!(
                    "Contact request prepare returned the wrong result kind"
                ));
            }
        };
        if prepared_operation_id != operation_id {
            return Err(anyhow!("Contact request prepare changed operation_id"));
        }
        let commit = ContactOperationRequestBody::Commit(ContactCommitRequestBody {
            phase: ContactCommitPhase::Commit,
            operation_id,
            idempotency_key,
            reservation_handle,
            signed_event: self.sign_prepared_contact_event(&event_draft)?,
            control_proposal_ack: None,
        });
        let accepted = self.sdk.contacts_request(&commit).await?;
        let accepted_replay = self.sdk.contacts_request(&commit).await?;
        if serde_json::to_value(&accepted)? != serde_json::to_value(accepted_replay)? {
            return Err(anyhow!("Contact request commit replay changed its outcome"));
        }
        match accepted {
            ContactOperationOutcome::Accepted {
                outcome:
                    ContactAcceptedOutcome::Request {
                        request_acceptance_receipt,
                        ..
                    },
            } => Ok(request_acceptance_receipt),
            ContactOperationOutcome::Failed { outcome } => Err(anyhow!(
                "Contact request commit failed: {:?}",
                outcome.reason
            )),
            _ => Err(anyhow!(
                "Contact request commit returned the wrong result kind"
            )),
        }
    }

    pub async fn accept_contact(&self, request_receipt: RequestAcceptanceReceipt) -> Result<()> {
        let operation_id =
            ProtocolOperationId::new(next_typed_id("operation")).map_err(anyhow::Error::msg)?;
        let idempotency_key =
            IdempotencyKey::new(next_typed_id("idempotency")).map_err(anyhow::Error::msg)?;
        let request = ContactAcceptRequestBody::Prepare(ContactAcceptPrepareRequestBody {
            phase: ContactPreparePhase::Prepare,
            operation_id: operation_id.clone(),
            idempotency_key: idempotency_key.clone(),
            request_receipt,
            action: ContactAcceptAction::Accept,
            granted_to_peer_scopes: vec![ContactScope::DirectMessage],
        });
        let prepared = self.sdk.contacts_respond(&request).await?;
        let (prepared_operation_id, reservation_handle, event_draft) = match prepared {
            ContactOperationOutcome::Prepared {
                outcome:
                    ContactPreparedOutcome::Response {
                        operation_id,
                        reservation_handle,
                        event_draft,
                        ..
                    },
            } => (operation_id, reservation_handle, event_draft),
            ContactOperationOutcome::Failed { outcome } => {
                return Err(anyhow!(
                    "Contact accept prepare failed: {:?}",
                    outcome.reason
                ));
            }
            _ => {
                return Err(anyhow!(
                    "Contact accept prepare returned the wrong result kind"
                ));
            }
        };
        if prepared_operation_id != operation_id {
            return Err(anyhow!("Contact accept prepare changed operation_id"));
        }
        let commit = ContactAcceptRequestBody::Commit(ContactCommitRequestBody {
            phase: ContactCommitPhase::Commit,
            operation_id,
            idempotency_key,
            reservation_handle,
            signed_event: self.sign_prepared_contact_event(&event_draft)?,
            control_proposal_ack: None,
        });
        match self.sdk.contacts_respond(&commit).await? {
            ContactOperationOutcome::Accepted {
                outcome: ContactAcceptedOutcome::Response { .. },
            } => Ok(()),
            ContactOperationOutcome::Failed { outcome } => Err(anyhow!(
                "Contact accept commit failed: {:?}",
                outcome.reason
            )),
            _ => Err(anyhow!(
                "Contact accept commit returned the wrong result kind"
            )),
        }
    }

    fn sign_prepared_contact_event(
        &self,
        draft: &PreparedEventDraft,
    ) -> Result<arkret_wire::Event> {
        let mut event = draft.unsigned_event()?;
        let created_at = event.created_at;
        let (signing_seed, verification_method) =
            event_signing_identity_for_device(&self.actor, &self.device_id);
        let signer = arkret_signatures::Ed25519PayloadSigner::from_did_key_seed(
            signing_seed,
            DidFullId::new(self.actor.clone())?,
            verification_method.clone(),
        );
        arkret_signatures::sign_event(
            &mut event,
            &signer,
            &verification_method,
            arkret_signatures::SignEventOptions::new().with_created_at(created_at),
        )?;
        if Hash::new(event.event_digest_with_digest_suite(draft.event_digest.digest_suite()?)?)?
            != draft.event_digest
        {
            return Err(anyhow!("signing changed the prepared Contact Event digest"));
        }
        Ok(event.into_event())
    }

    /// Read the Realm Seal frontier, waiting out the control-seal coordinator.
    ///
    /// Control Move finality belongs to the durable coordinator, which runs
    /// asynchronously: between accepting a Realm genesis unit and publishing
    /// the Seal that covers it, the frontier answers `503
    /// frontier_unavailable`. That is a transient state a client waits out,
    /// not an error — every Realm-scoped Seal read here therefore retries it.
    pub async fn realm_seal_frontier(&self, realm_id: &str) -> Result<Value> {
        self.events_frontier_with_retry(None, Some(realm_id)).await
    }

    async fn events_frontier_with_retry(
        &self,
        actor_id: Option<&str>,
        realm_id: Option<&str>,
    ) -> Result<Value> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            let response = expect_response(
                self.query("/_arkret/self/events/frontier")
                    .json(&events_frontier_request_body(actor_id, realm_id)?),
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

    /// Record a grant this actor now holds in `realm_id`, so its later Events
    /// name it as their covering authority.
    pub fn remember_grant(&self, realm_id: &str, grant_id: &str, actions: &[&str]) {
        self.held_grants
            .lock()
            .expect("cotest held-grant map is not poisoned")
            .entry(realm_id.to_owned())
            .or_default()
            .push((
                grant_id.to_owned(),
                actions.iter().map(|action| (*action).to_owned()).collect(),
            ));
    }

    /// The grant ids this actor holds in `realm_id` whose actions cover `kind`.
    ///
    /// Coverage is the registry's own `target_event_kinds`, so the harness
    /// never has to spell an action-to-kind table of its own.
    pub fn covering_grants_for(&self, realm_id: &str, kind: &str) -> Vec<String> {
        self.held_grants
            .lock()
            .expect("cotest held-grant map is not poisoned")
            .get(realm_id)
            .map(|grants| {
                grants
                    .iter()
                    .filter(|(_, actions)| {
                        actions
                            .iter()
                            .any(|action| action_covers_kind(action, kind))
                    })
                    .map(|(grant_id, _)| grant_id.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Issue a Realm grant and record it on the subject's own client.
    pub async fn grant_realm_actions_to_client(
        &self,
        realm_id: &str,
        subject: &TestActorClient,
        actions: &[&str],
    ) -> Result<String> {
        let before = self.realm_seal_id(realm_id).await?;
        let (grant_id, response) = self
            .grant_realm_actions_to(realm_id, &subject.actor, actions)
            .await?;
        let proposal_digest = response["control_proposal_acks"][0]["proposal_digest"]
            .as_str()
            .ok_or_else(|| {
                anyhow!("grant response omitted its Control Proposal Ack: {response}")
            })?;
        self.await_control_proposal_settled(realm_id, proposal_digest, &before)
            .await?;
        subject.remember_grant(realm_id, &grant_id, actions);
        Ok(grant_id)
    }

    /// Wait until one exact accepted Control proposal leaves the pending set.
    ///
    /// A different pending proposal may advance the Realm frontier first, so a
    /// bare `seal_id != previous` check is not a finality witness for the Event
    /// just submitted. The proposal's signed Ack digest is the stable identity
    /// exposed by governance health. The caller obtained that signed Ack from
    /// the accepted submit response, which already proves the digest entered
    /// pending; polling waits for the exact digest to leave the pending set
    /// together with a successor Seal.
    pub(crate) async fn await_control_proposal_settled(
        &self,
        realm_id: &str,
        proposal_digest: &str,
        previous_seal_id: &str,
    ) -> Result<String> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
        loop {
            if let Ok(frontier) = self.realm_seal_frontier(realm_id).await {
                let state: arkret_models_collaboration::event_sync::EventsFrontierAccountClientState =
                    serde_json::from_value(frontier)?;
                if let arkret_models_collaboration::event_sync::EventsFrontierView::RealmSeal(
                    frontier,
                ) = state.frontier
                {
                    let pending = frontier
                        .governance_health
                        .pending_proposals
                        .iter()
                        .any(|pending| pending.proposal_digest.as_str() == proposal_digest);
                    let leaf = frontier.sole_leaf()?.clone();
                    if !pending && leaf.as_str() != previous_seal_id {
                        return Ok(leaf.to_string());
                    }
                }
            }
            if std::time::Instant::now() >= deadline {
                return Err(anyhow!(
                    "Control proposal {proposal_digest} did not settle into a successor Seal for {realm_id}"
                ));
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    }

    async fn realm_seal_id(&self, realm_id: &str) -> Result<String> {
        let frontier = self.realm_seal_frontier(realm_id).await?;
        frontier["frontier"]["seal_basis"]["leaves"][0]
            .as_str()
            .map(ToOwned::to_owned)
            .ok_or_else(|| anyhow!("Realm frontier has no seal_id: {frontier}"))
    }

    pub fn controls_realm_authority_root(&self, realm_id: &str) -> bool {
        self.controlled_realms
            .lock()
            .expect("cotest controlled-Realm set is not poisoned")
            .contains(realm_id)
    }

    pub fn controlled_realm_ids(&self) -> Vec<String> {
        self.controlled_realms
            .lock()
            .expect("cotest controlled-Realm set is not poisoned")
            .iter()
            .cloned()
            .collect()
    }

    pub(crate) fn track_controlled_realm(&self, realm_id: &RealmId) {
        self.controlled_realms
            .lock()
            .expect("cotest controlled-Realm set is not poisoned")
            .insert(realm_id.to_string());
    }

    pub fn default_strand_id(&self, realm_id: &str) -> Result<String> {
        self.default_strands
            .lock()
            .expect("cotest default-Strand map is not poisoned")
            .get(realm_id)
            .cloned()
            .ok_or_else(|| anyhow!("accepted default Strand is unavailable for Realm {realm_id}"))
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

    pub fn query(&self, path: &str) -> reqwest::RequestBuilder {
        self.http
            .request(query_method(), self.url(path))
            .bearer_auth(&self.token)
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
        let bootstrap = self.create_realm_bootstrap_with(body).await?;
        let realm_id = arkret_identifiers::RealmId::new(
            bootstrap["realm_id"]
                .as_str()
                .ok_or_else(|| anyhow!("Realm bootstrap response missing realm_id: {bootstrap}"))?
                .to_owned(),
        )?;
        let event_response = bootstrap["event_response"].clone();
        let actor_full_id = arkret_identifiers::DidFullId::new(self.actor.clone())?;
        let actor_id = arkret_identifiers::project_full_id_to_core_id(&actor_full_id)?;
        let mut strand = Strand::new_create(realm_id.clone(), "Discussion", actor_id);
        strand.tracks.clear();
        strand
            .tracks
            .insert("discussion".to_owned(), StrandTrack::discussion_primary());
        let created = self
            .submit_event(
                realm_id.as_str(),
                arkret_wire::event_kind_str::STRAND_CREATE,
                serde_json::to_value(StrandCreatePayload {
                    object: strand,
                    initial_relations: None,
                })?,
            )
            .await?;
        let strand_event_id = created
            .get("event_id")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("default Strand create response missing event_id: {created}"))?;
        let strand_id = arkret_identifiers::StrandId::from_event_id(
            &arkret_identifiers::EventId::new(strand_event_id.to_owned())?,
        );
        self.submit_event(
            realm_id.as_str(),
            arkret_wire::event_kind_str::REALM_SET_DEFAULT_STRAND,
            serde_json::to_value(RealmSetDefaultStrandPayload::new(
                realm_id.clone(),
                strand_id.clone(),
            ))?,
        )
        .await?;
        self.default_strands
            .lock()
            .expect("cotest default-Strand map is not poisoned")
            .insert(realm_id.to_string(), strand_id.to_string());
        // A DataEvent that writes a cell has to name a covering authority in
        // `refs[role=authorized_by]` / `authorization_ref`. For the creator that
        // authority is the Realm authority-root cell the create contract wrote,
        // not a grant id: v1 genesis issues no capability grant at all.
        Ok(json!({
            "realm_id": realm_id,
            "default_strand_id": strand_id,
            "authority_root_ref": arkret_wire::REALM_AUTHORITY_ROOT_CELL,
            "event_response": event_response,
        }))
    }

    /// Submit only the Realm bootstrap control batch.
    ///
    /// Durable convergence scenarios use this entry point so they can wait
    /// for the bootstrap Seal before authoring their first DataEvent, without
    /// racing the convenience helper's default Discussion Strand.
    pub async fn create_realm_bootstrap_with(&self, body: Value) -> Result<Value> {
        let draft = realm_create_payload_with_notary(
            &self.service_id,
            &body,
            self.service_notary_signer.clone(),
        )?;
        let (realm_id, events) = realm_bootstrap_event_batch_for_device(
            &self.actor,
            &self.device_id,
            &DidCoreId::new(self.service_id.clone())?,
            draft,
        )?;
        self.controlled_realms
            .lock()
            .expect("cotest controlled-Realm set is not poisoned")
            .insert(realm_id.clone());
        let events = events
            .into_iter()
            .map(arkret_wire::EventInitialSubmission::online)
            .collect();
        let request = arkret_wire::EventsSubmitBatchRequestBody { events };
        let event_response = expect_json(
            self.post("/_arkret/self/events").json(&request),
            StatusCode::OK,
        )
        .await?;
        let realm_id = arkret_identifiers::RealmId::new(realm_id.clone())?;
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

    /// Name the authority this Event is authored under.
    ///
    /// A grant this actor holds wins when one covers the kind; the Realm
    /// controller otherwise names the authority-root cell. Naming both would be
    /// wrong: the root path deliberately skips the per-cell grant search, so an
    /// Event carrying it is judged only by whether `ak.realm.owner` covers the
    /// kind at all.
    fn stamp_authority(&self, event: &mut Event, realm_id: &str, kind: &str, is_data_event: bool) {
        let covering = self.covering_grants_for(realm_id, kind);
        if !covering.is_empty() {
            if is_data_event {
                event.refs = covering
                    .into_iter()
                    .map(|grant_id| {
                        EventRef::new(grant_id, arkret_wire::EVENT_REF_ROLE_AUTHORIZED_BY)
                    })
                    .collect();
            }
            return;
        }
        if self.controls_realm_authority_root(realm_id) {
            event.authorization_ref = Some(
                AuthorizationRef::new(arkret_wire::REALM_AUTHORITY_ROOT_CELL)
                    .expect("Realm authority root is an AuthorizationRef"),
            );
        }
    }

    /// Make sure this actor can author `kind` in `realm_id`.
    ///
    /// `ak.realm.owner` is not a superset of every action. The closed genesis
    /// unit lets the controller write the facet cells, but outside genesis
    /// `ak.member.state` is governed by `ak.realm.admin` — which nothing issues
    /// on its own, because v1 genesis issues no grant at all. The controller
    /// therefore grants itself the narrowest registered action that covers the
    /// kind, which is exactly what the authority-root ref exists to authorize.
    fn ensure_authority_for_kind<'a>(
        &'a self,
        realm_id: &'a str,
        kind: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move {
            if !self.controls_realm_authority_root(realm_id)
                || !self.covering_grants_for(realm_id, kind).is_empty()
                || owner_may_author_kind(kind)
            {
                return Ok(());
            }
            let Some(action) = self_grant_action_for_kind(kind) else {
                return Ok(());
            };
            let (grant_id, _) = self
                .grant_realm_actions_to(realm_id, &self.actor, &[action])
                .await?;
            self.remember_grant(realm_id, &grant_id, &[action]);
            Ok(())
        })
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
        self.grant_realm_actions_with_constraints_to(realm_id, subject, actions, Vec::new())
            .await
    }

    pub async fn grant_realm_actions_with_constraints_to(
        &self,
        realm_id: &str,
        subject: &str,
        actions: &[&str],
        constraints: Vec<
            arkret_models_collaboration::governance::grant_constraint::GrantConstraint,
        >,
    ) -> Result<(String, Value)> {
        let issued_at = chrono::Utc::now();
        let grant = arkret_models_collaboration::events_payloads::CapabilityGrantCreateBody {
            schema: "ak.schema.capability.v1".to_owned(),
            realm_id: Some(arkret_identifiers::RealmId::new(realm_id.to_owned())?),
            issuer: project_full_id_to_core_id(&DidFullId::new(
                self.actor.clone(),
            )?)?,
            subject:
                arkret_models_collaboration::governance::grant_constraint::CapabilitySubject::CoreDid(
                    project_full_id_to_core_id(&DidFullId::new(
                        subject.to_owned(),
                    )?)?,
                ),
            subject_principal_server_id: Some(DidCoreId::new(self.service_id.clone())?),
            actions: actions.iter().map(|action| (*action).to_owned()).collect(),
            resources: vec![serde_json::from_value(json!({
                "kind": "realm",
                "realm_id": realm_id,
                "match_scope": "realm_wide"
            }))?],
            capability_action_registry_digest: Some(
                arkret::current_capability_action_registry_digest()?,
            ),
            constraints,
            issuer_authority_refs: vec![arkret::IssuerAuthorityRef::RealmRoot {
                realm_id: arkret_identifiers::RealmId::new(realm_id.to_owned())?,
                cell_ref: "ak:cell:ak.component.realm.authority_root.v1:null".to_owned(),
                controller_epoch_at_issuance: 0,
                authority_generation: 0,
            }],
            issued_at,
            not_before: None,
            expires_at: None,
        };
        let payload =
            arkret_models_collaboration::events_payloads::CapabilityGrantPayload { grant };
        let event = self
            .author_event(
                realm_id,
                arkret_wire::event_kind_str::CAPABILITY_GRANT,
                serde_json::to_value(payload)?,
            )
            .await?;
        let grant_id = arkret_identifiers::GrantId::from_event_id(&event.event_id);
        let mut response = expect_json(
            self.post("/_arkret/self/events")
                .json(&crate::publication::initial_submission(event.clone(), "")?),
            StatusCode::OK,
        )
        .await?;
        ensure_submit_event_id(&mut response, &event);
        Ok((grant_id.to_string(), response))
    }

    pub async fn send_message(&self, realm_id: &str, strand_id: &str, body: &str) -> Result<Value> {
        self.submit_event(
            realm_id,
            "ak.message.create",
            message_create_text_payload(strand_id, body)?,
        )
        .await
    }

    pub async fn submit_event(&self, realm_id: &str, kind: &str, payload: Value) -> Result<Value> {
        let event = self.author_event(realm_id, kind, payload).await?;
        let mut body = expect_json(
            self.post("/_arkret/self/events")
                .json(&crate::publication::initial_submission(event.clone(), "")?),
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
            self.post("/_arkret/self/events")
                .json(&crate::publication::initial_submission(event.clone(), "")?),
            StatusCode::OK,
        )
        .await?;
        ensure_submit_event_id(&mut body, &event);
        // The digest is what a later response names to dominate this head, so
        // hand it back to the caller alongside the submit result.
        body["cotest_event_digest"] = json!(
            event
                .proofs
                .iter()
                .find_map(arkret_wire::EventProof::as_producer)
                .expect("authored Event has producer proof")
                .event_digest
        );
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
    ) -> Result<Event> {
        let frontier = self
            .events_frontier_with_retry(Some(self.actor.as_str()), Some(realm_id))
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
        let mut event = event_envelope_with_causal_refs_for_device(
            &self.actor,
            &self.device_id,
            &DidCoreId::new(self.service_id.clone())?,
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
        let is_data_event = arkret_wire::EventKind::from(kind)
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
            event.seal_ref = Some(frontier.sole_leaf()?.clone());
            // Capability coverage is per DataEvent: the reducer checks that a
            // named grant actually covers this action on this target.
            event.auth_context = Some(AuthContext {
                actor_id: project_full_id_to_core_id(&DidFullId::new(self.actor.clone())?)?,
                key_id: arkret_wire::OpaqueLocalId::new("cotest").expect("cotest key id"),
                key_epoch: 0,
                credential_epoch: None,
            });
            if capability_refs.is_empty() {
                self.stamp_authority(&mut event, realm_id, kind, true);
            }
            event.refs = capability_refs
                .into_iter()
                .map(|grant_id| EventRef::new(grant_id, arkret_wire::EVENT_REF_ROLE_AUTHORIZED_BY))
                .collect();
            if kind == arkret_wire::event_kind_str::STRAND_UPDATE
                && event
                    .payload
                    .get("patch")
                    .is_some_and(|patch| payload_patch_touches_calendar(&json!({"patch": patch})))
            {
                event.requirements.schema_profile_refs = vec![
                    ProfileRef::new("ak.schema.calendar_event.v1")
                        .expect("calendar schema profile is registered"),
                ];
            }
            let (signing_seed, _) = event_signing_identity_for_device(&self.actor, &self.device_id);
            refresh_typed_event_proof_with_signing_seed(&mut event, signing_seed)?;
        }
        Ok(event)
    }

    pub async fn author_event(&self, realm_id: &str, kind: &str, payload: Value) -> Result<Event> {
        self.author_event_with_preconditions(realm_id, kind, payload, Vec::new())
            .await
    }

    /// Author an Event that carries its own guards.
    ///
    /// A precondition is inside the bytes the caller signs, so a surface that
    /// requires one -- the policy-server writes, for instance -- can only get it
    /// from the caller. Attaching it here rather than in the scenario is what
    /// keeps it on the same envelope that already resolves `seal_basis` from
    /// the Realm Seal frontier: a Control Move authored without that basis is
    /// refused before any guard is even looked at.
    pub async fn author_event_with_preconditions(
        &self,
        realm_id: &str,
        kind: &str,
        payload: Value,
        preconditions: Vec<arkret_wire::cba::Precondition>,
    ) -> Result<Event> {
        self.ensure_authority_for_kind(realm_id, kind).await?;
        let frontier = self
            .events_frontier_with_retry(Some(self.actor.as_str()), Some(realm_id))
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
        let expected_actor_id = project_full_id_to_core_id(&DidFullId::new(self.actor.clone())?)?;
        if frontier.realm_id.as_str() != realm_id || frontier.actor_id != expected_actor_id {
            return Err(anyhow!("combined selector returned the wrong actor scope"));
        }
        let mut event = event_envelope_with_chain_for_device(
            &self.actor,
            &self.device_id,
            &DidCoreId::new(self.service_id.clone())?,
            realm_id,
            kind,
            payload,
            frontier.next_actor_seq,
        );
        event.prev_refs = frontier.frontier_event_ids;
        event.preconditions = preconditions;
        let descriptor = arkret_wire::EventKind::from(kind).descriptor();
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
                event.seal_basis = Some(frontier.seal_basis());
                let physical_millis = chrono::Utc::now().timestamp_millis();
                event.hlc = Some(Hlc::new(format!("{physical_millis:012x}-0000-a13f9c2e"))?);
            } else {
                event.seal_ref = Some(frontier.sole_leaf()?.clone());
                event.auth_context = Some(AuthContext {
                    actor_id: project_full_id_to_core_id(&DidFullId::new(self.actor.clone())?)?,
                    key_id: arkret_wire::OpaqueLocalId::new("cotest").expect("cotest key id"),
                    key_epoch: 0,
                    credential_epoch: None,
                });
            }
            // Self moderation reports use their holder proof as the complete
            // admission regime. The self endpoint forbids Realm authority or
            // grant attribution on the signed Event.
            if kind != arkret_wire::event_kind_str::SELF_MODERATION_REPORT {
                self.stamp_authority(&mut event, realm_id, kind, is_data_event);
            }
        }
        let (signing_seed, _) = event_signing_identity_for_device(&self.actor, &self.device_id);
        refresh_typed_event_proof_with_signing_seed(&mut event, signing_seed)?;
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

/// Whether `action` is registered as covering `kind`.
///
/// Single direction of truth: the authorizing actions for a kind are exactly
/// the ones whose `target_event_kinds` list it. The per-event
/// `admission_capabilities` list is retired from the registry.
fn action_covers_kind(action: &str, kind: &str) -> bool {
    arkret_schema::capability_action(action)
        .is_some_and(|descriptor| descriptor.target_event_kinds.contains(&kind))
}

/// Whether the Realm owner aggregate authorizes authoring `kind` directly.
fn owner_may_author_kind(kind: &str) -> bool {
    arkret::current_capability_action_registry_digest()
        .ok()
        .and_then(|basis| {
            arkret_policy::authz::owner_may_author_event_kind(kind, Some(&basis)).ok()
        })
        .unwrap_or(false)
}

/// The action this harness self-grants so the Realm controller can author
/// `kind`, when `ak.realm.owner` does not cover it directly.
///
/// Smallest coverage set first, so a self-grant never quietly hands the
/// creator an aggregate admin action when a narrow one would do.
fn self_grant_action_for_kind(kind: &str) -> Option<&'static str> {
    let basis = arkret::current_capability_action_registry_digest().ok()?;
    arkret_schema::REGISTERED_CAPABILITY_ACTIONS
        .iter()
        .filter(|descriptor| descriptor.target_event_kinds.contains(&kind))
        .filter(|descriptor| {
            arkret_policy::authz::owner_may_grant(descriptor.action.as_str(), Some(&basis), &[])
                .unwrap_or(false)
        })
        .min_by_key(|descriptor| descriptor.target_event_kinds.len())
        .map(|descriptor| descriptor.action.as_str())
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
