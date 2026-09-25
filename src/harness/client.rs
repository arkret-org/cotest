use anyhow::{Context, Result, anyhow};
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
use arkret_identifiers::{Did, DidCoreId, EventId, Hash, RealmId, project_did_to_core_id};
use arkret_models_collaboration::events_payloads::{
    CapabilityRevokePayload, RealmSetDefaultStrandPayload, StrandCreatePayload,
};
use arkret_models_collaboration::governance::membership_invite::MembershipPayloadState;
use arkret_models_collaboration::objects::profiles::StrandTrack;
use arkret_models_collaboration::objects::read_receipts::ReadCursorAdvanceRequestBody;
use arkret_models_collaboration::objects::strand::Strand;
use arkret_wire::{
    AccountId, ActorId, AuthorizationRef, Event, EventAdmissionSubmission, SemanticRef,
};
use reqwest::StatusCode;
use serde_json::{Value, json};
use url::Url;

use super::assertions::{account_subscribe_delta_from_text, expect_json, expect_response};
use super::event_builder::{
    event_envelope_with_causal_refs_for_device, event_signing_identity_for_device,
    realm_bootstrap_event_batch_for_device,
};
use super::server::OperationSelectingHttpClient;
use super::{
    member_join_payload, member_transition_payload, message_create_text_payload, next_typed_id,
    query_method, realm_create_payload_for_station, refresh_typed_event_proof_with_signing_seed,
};

#[derive(Clone)]
pub struct TestActorClient {
    pub(super) http: OperationSelectingHttpClient,
    pub(super) sdk: SdkClient,
    pub(super) base_url: Url,
    pub(super) service_id: String,
    pub actor: String,
    pub device_id: String,
    /// How this client authenticates.
    ///
    /// Private on purpose. It used to be a `pub token: String`, and scenarios
    /// that needed a request shape the builders below do not produce reached
    /// for `bearer_auth(&client.token)`. That is correct for a development
    /// session and silently wrong for a canonical one, whose grant is only
    /// valid with a per-request proof. Go through [`Self::authorize`].
    pub(super) session: super::ClientSession,
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
    /// a covering grant, which an ordinary Event names in
    /// `semantic_refs[role=authorized_by]`.
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
                    account_id: AccountId::new(
                        project_did_to_core_id(&Did::new(target.to_owned())?)?,
                        DidCoreId::new(self.service_id.clone())?,
                    ),
                },
                granted_to_peer_scopes: vec![ContactScope::DirectMessage],
                introduction_evidence: ContactIntroductionEvidence::ExplicitAddress,
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
            signed_event: self.sign_prepared_contact_event(
                &event_draft,
                arkret_wire::event_kind_str::CONTACT_REQUESTED,
            )?,
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

    pub async fn accept_contact(&self, requester: &TestActorClient) -> Result<()> {
        let requester = ActorId::account(AccountId::new(
            DidCoreId::new(requester.actor.clone())?,
            DidCoreId::new(requester.service_id.clone())?,
        ));
        let row = self
            .sdk
            .contacts_list()
            .await?
            .contacts
            .into_iter()
            .find(|row| {
                row.state == arkret::ContactState::PendingIncoming
                    && row.peer.contact_actor_id() == requester
            })
            .ok_or_else(|| anyhow!("no pending incoming Contact for requester"))?;
        let request_event_ref = row
            .request_event_ref
            .ok_or_else(|| anyhow!("pending Contact omitted request_event_ref"))?;
        let operation_id =
            ProtocolOperationId::new(next_typed_id("operation")).map_err(anyhow::Error::msg)?;
        let idempotency_key =
            IdempotencyKey::new(next_typed_id("idempotency")).map_err(anyhow::Error::msg)?;
        let request = ContactAcceptRequestBody::Prepare(ContactAcceptPrepareRequestBody {
            phase: ContactPreparePhase::Prepare,
            operation_id: operation_id.clone(),
            idempotency_key: idempotency_key.clone(),
            peer: row.peer,
            request_event_ref,
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
            signed_event: self.sign_prepared_contact_event(
                &event_draft,
                arkret_wire::event_kind_str::CONTACT_ACCEPTED,
            )?,
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
        expected_kind: &str,
    ) -> Result<arkret_wire::Event> {
        let mut event = draft.unsigned_event_for_kind(expected_kind)?;
        let created_at = event.created_at;
        let (signing_seed, verification_method) =
            event_signing_identity_for_device(&self.actor, &self.device_id);
        let signer = arkret_signatures::Ed25519PayloadSigner::from_did_key_seed(
            signing_seed,
            Did::new(self.actor.clone())?,
            verification_method.clone(),
        );
        arkret_signatures::sign_event(
            &mut event,
            &signer,
            arkret_signatures::SignEventOptions::new().with_created_at(created_at),
        )?;
        if Hash::new(event.event_digest_with_digest_suite(draft.event_digest.digest_suite()?)?)?
            != draft.event_digest
        {
            return Err(anyhow!("signing changed the prepared Contact Event digest"));
        }
        Ok(event.into_event())
    }

    /// Read the committed Realm stream from its retained floor to its head.
    /// Callers that still inspect the retired Seal JSON shape must migrate to
    /// the `committed_events[]` and `RealmCommit` fields returned here.
    pub async fn realm_seal_frontier(&self, realm_id: &str) -> Result<Value> {
        let realm_id = RealmId::new(realm_id.to_owned())?;
        let outcome = self
            .sdk
            .scan_commit_stream_to_head(
                realm_id.clone(),
                arkret_wire::CommitStreamRef::Realm { realm_id },
                None,
                1000,
            )
            .await?;
        Ok(serde_json::to_value(outcome)?)
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
        let (grant_id, _response) = self
            .grant_realm_actions_to(realm_id, &subject.actor, actions)
            .await?;
        let grant_id_typed = arkret_identifiers::GrantId::new(grant_id.clone())?;
        let grant_event_id = EventId::from_token_bytes(grant_id_typed.token_bytes())?;
        self.await_event_seal_coverage(realm_id, &grant_event_id)
            .await?;
        subject.remember_grant(realm_id, &grant_id, actions);
        Ok(grant_id)
    }

    /// Wait for one exact Event to appear in the signed RealmCommit stream.
    /// Legacy callers must pass an EventId and a previous CommitId; the old
    /// proposal digest and Seal identity have no current protocol meaning.
    pub(crate) async fn await_control_proposal_settled(
        &self,
        realm_id: &str,
        event_id: &str,
        previous_commit_id: &str,
    ) -> Result<String> {
        let event_id = EventId::new(event_id.to_owned())?;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
        loop {
            let realm = RealmId::new(realm_id.to_owned())?;
            let outcome = self
                .sdk
                .scan_commit_stream_to_head(
                    realm.clone(),
                    arkret_wire::CommitStreamRef::Realm { realm_id: realm },
                    None,
                    1000,
                )
                .await?;
            if let Some(item) = outcome.committed_events.iter().find(|item| {
                item.commit().event_ref == event_id
                    && item.commit().commit_id.as_str() != previous_commit_id
            }) {
                return Ok(item.commit().commit_id.to_string());
            }
            if std::time::Instant::now() >= deadline {
                return Err(anyhow!(
                    "Event {event_id} did not appear after Commit {previous_commit_id} in Realm {realm_id}"
                ));
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    }

    /// Wait for exact signed commit inclusion of one Event in this Realm.
    pub(crate) async fn await_event_seal_coverage(
        &self,
        realm_id: &str,
        event_id: &EventId,
    ) -> Result<String> {
        let expected_realm = RealmId::new(realm_id.to_owned())?;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
        loop {
            if let Ok(item) = self.sdk.committed_event_get(event_id).await {
                item.validate_shape()?;
                if item.commit().realm_id == expected_realm {
                    return Ok(item.commit().commit_id.to_string());
                }
                return Err(anyhow!("Event {event_id} committed in another Realm"));
            }
            if std::time::Instant::now() >= deadline {
                return Err(anyhow!(
                    "Event {event_id} has no accepted RealmCommit in {realm_id}"
                ));
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    }
    pub fn controls_realm_authority_root(&self, realm_id: &str) -> bool {
        self.controlled_realms
            .lock()
            .expect("cotest controlled-Realm set is not poisoned")
            .contains(realm_id)
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

    /// This client's session.
    ///
    /// Read it to assert on the credential or to branch on the kind. To send a
    /// request, use [`Self::authorize`] or the builders below.
    pub fn session(&self) -> &super::ClientSession {
        &self.session
    }

    /// The development bearer, when this client has one.
    ///
    /// `None` for a canonical session. A caller that needs a bearer and finds
    /// `None` is not missing a field — it is holding a principal whose
    /// credential cannot be presented that way.
    pub fn dev_bearer(&self) -> Option<&str> {
        self.session.dev_bearer()
    }

    /// The development bearer, or a panic naming why there is not one.
    ///
    /// For scenarios that hand a bearer to a helper or smuggle one into a query
    /// string — shapes [] cannot serve because they are not a
    /// request yet. A canonical session reaching here is a scenario asking for
    /// a credential its principal does not have, and failing loudly beats
    /// sending a grant as a bearer and reading the 401 as a protocol result.
    /// The development bearer, or a panic naming why there is not one.
    ///
    /// For scenarios that hand a bearer to a helper or smuggle one into a query
    /// string — shapes [`Self::authorize`] cannot serve, because those are not
    /// a request yet. A canonical session reaching here is a scenario asking
    /// for a credential its principal does not have; failing loudly beats
    /// sending a grant as a bearer and reading the 401 back as a protocol
    /// result.
    pub fn expect_dev_bearer(&self) -> &str {
        self.dev_bearer().unwrap_or_else(|| {
            panic!(
                "actor {} holds a canonical session, which has no bearer; build the request and \
                 pass it to `authorize` instead",
                self.actor
            )
        })
    }

    /// Attach this client's credentials to a request the caller built.
    ///
    /// The builders below cover the ordinary shapes; this is for the ones they
    /// do not produce. It is the only supported way to authorize a hand-built
    /// request, because a canonical session needs a proof over that request's
    /// own method and URL, which only this can mint.
    pub fn authorize(&self, builder: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        self.session
            .authorize(builder)
            .expect("authorize a harness request")
    }

    pub fn get(&self, path: &str) -> reqwest::RequestBuilder {
        self.authorize(self.http.get(self.url(path)))
    }

    pub fn post(&self, path: &str) -> reqwest::RequestBuilder {
        self.authorize(self.http.post(self.url(path)))
    }

    pub fn query(&self, path: &str) -> reqwest::RequestBuilder {
        self.authorize(self.http.request(query_method(), self.url(path)))
    }

    pub fn put(&self, path: &str) -> reqwest::RequestBuilder {
        self.authorize(self.http.put(self.url(path)))
    }

    pub fn delete(&self, path: &str) -> reqwest::RequestBuilder {
        self.authorize(self.http.delete(self.url(path)))
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
        let strand_id = self.create_default_strand(realm_id.as_str()).await?;
        Ok(json!({
            "realm_id": realm_id,
            "default_strand_id": strand_id,
            "event_response": event_response,
        }))
    }

    pub async fn create_default_strand(&self, realm_id: &str) -> Result<String> {
        let realm_id = arkret_identifiers::RealmId::new(realm_id.to_owned())?;
        let actor_did = arkret_identifiers::Did::new(self.actor.clone())?;
        let actor_id = ActorId::account(AccountId::new(
            arkret_identifiers::project_did_to_core_id(&actor_did)?,
            DidCoreId::new(self.service_id.clone())?,
        ));
        let mut strand = Strand::new_create(realm_id.clone(), "Discussion", actor_id);
        // The create payload cannot carry the reducer-derived stage axis.
        strand.stage = None;
        strand.tracks.clear();
        strand
            .tracks
            .insert("discussion".to_owned(), StrandTrack::discussion_primary());
        let mut strand_event = self
            .author_event(
                realm_id.as_str(),
                arkret_wire::event_kind_str::STRAND_CREATE,
                serde_json::to_value(StrandCreatePayload { object: strand })?,
            )
            .await?;
        let event_created_at = serde_json::to_value(strand_event.created_at)?;
        // The authored Strand's creation time is the signed Event time. Set it
        // after the envelope clock is chosen, then rederive the Event id/proof.
        strand_event
            .payload
            .get_mut("object")
            .and_then(Value::as_object_mut)
            .context("Strand create payload object")?
            .insert("created_at".to_owned(), event_created_at);
        let (signing_seed, _) = event_signing_identity_for_device(&self.actor, &self.device_id);
        refresh_typed_event_proof_with_signing_seed(&mut strand_event, signing_seed)?;
        let created = expect_json(
            self.post("/_arkret/self/events")
                .json(&crate::publication::initial_submission(strand_event, "")?),
            StatusCode::OK,
        )
        .await?;
        let strand_event_id = super::submitted_event_id(&created)?;
        let strand_id = arkret_identifiers::StrandId::from_event_id(&strand_event_id);
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
        Ok(strand_id.to_string())
    }

    /// Submit only the Realm bootstrap control batch.
    ///
    /// Durable convergence scenarios use this entry point so they can wait
    /// for the bootstrap Seal before authoring their first ordinary Event, without
    /// racing the convenience helper's default Discussion Strand.
    pub async fn create_realm_bootstrap_with(&self, body: Value) -> Result<Value> {
        let draft = realm_create_payload_for_station(&self.service_id, &body)?;
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
        let request = super::event_builder::ordinary_realm_bootstrap_submission(events)?;
        request.validate()?;
        let event_response = expect_json(
            self.post("/_arkret/self/events").json(&request),
            StatusCode::OK,
        )
        .await?;
        let typed_outcome: arkret_models_collaboration::authority_commit::SelfAuthoritySubmitOutcome =
            serde_json::from_value(event_response.clone())
                .context("Realm bootstrap response is not the closed SDK outcome")?;
        typed_outcome.validate_for_request(&arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest::OrdinaryRealmBootstrap(request))?;
        let realm_id = arkret_identifiers::RealmId::new(realm_id.clone())?;
        Ok(json!({
            "realm_id": realm_id,
            "event_response": event_response,
        }))
    }

    /// Submit one ordinary Realm bootstrap unit and return the raw response,
    /// for scenarios that assert a refusal instead of an accepted unit.
    pub async fn post_realm_bootstrap(&self, body: Value) -> Result<reqwest::Response> {
        let draft = realm_create_payload_for_station(&self.service_id, &body)?;
        let (_, events) = realm_bootstrap_event_batch_for_device(
            &self.actor,
            &self.device_id,
            &DidCoreId::new(self.service_id.clone())?,
            draft,
        )?;
        let request = super::event_builder::ordinary_realm_bootstrap_submission(events)?;
        request.validate()?;
        Ok(self
            .post("/_arkret/self/events")
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(arkret_canonical::canonical_json_bytes(&request)?)
            .send()
            .await?)
    }

    pub async fn add_member(&self, realm_id: &str, member: &TestActorClient) -> Result<Value> {
        self.submit_event(
            realm_id,
            "ak.member.state",
            member_join_payload(realm_id, &member.actor),
        )
        .await
    }

    /// Remove one member through the current signed `ak.member.state{leave}`
    /// carrier. This deliberately exercises owner Event authority; no helper
    /// grant or server-authored compatibility write is inserted.
    pub async fn remove_member(&self, realm_id: &str, member: &TestActorClient) -> Result<Value> {
        self.submit_event(
            realm_id,
            "ak.member.state",
            member_transition_payload(
                realm_id,
                &member.actor,
                MembershipPayloadState::Leave,
                Some("removed_by_realm_owner"),
            )?,
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
    fn stamp_authority(
        &self,
        event: &mut Event,
        realm_id: &str,
        kind: &str,
        is_ordinary_event: bool,
    ) {
        let covering = self.covering_grants_for(realm_id, kind);
        if !covering.is_empty() {
            if is_ordinary_event {
                event.semantic_refs = covering
                    .into_iter()
                    .map(|grant_id| {
                        SemanticRef::new(grant_id, arkret_wire::SEMANTIC_REF_ROLE_AUTHORIZED_BY)
                    })
                    .collect();
            }
            return;
        }
        if self.controls_realm_authority_root(realm_id) {
            let genesis_event_id = RealmId::new(realm_id.to_owned())
                .expect("controlled Realm has a typed id")
                .event_id();
            event.authorization_ref = Some(AuthorizationRef::from(genesis_event_id));
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
            issuer_id: ActorId::account(AccountId::new(
                project_did_to_core_id(&Did::new(self.actor.clone())?)?,
                DidCoreId::new(self.service_id.clone())?,
            )),
            subject:
                arkret_models_collaboration::governance::grant_constraint::CapabilitySubject::Actor(
                    ActorId::account(AccountId::new(
                        project_did_to_core_id(&Did::new(subject.to_owned())?)?,
                        DidCoreId::new(self.service_id.clone())?,
                    )),
                ),
            actions: actions.iter().map(|action| (*action).to_owned()).collect(),
            resources: vec![serde_json::from_value(json!({
                "kind": "realm",
                "realm_id": realm_id,
                "match_scope": "realm_wide"
            }))?],
            constraints,
            issuer_authority_refs: vec![arkret::IssuerAuthorityRef::RealmRoot {
                realm_id: arkret_identifiers::RealmId::new(realm_id.to_owned())?,
                authority_event_ref: arkret_identifiers::RealmId::new(realm_id.to_owned())?
                    .event_id(),
                authority_generation: 0,
            }],
            issued_at,
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
        let response = expect_json(
            self.post("/_arkret/self/events")
                .json(&crate::publication::initial_submission(event.clone(), "")?),
            StatusCode::OK,
        )
        .await?;
        Ok((grant_id.to_string(), response))
    }

    /// Revoke an exact accepted grant through the current Event carrier.
    pub async fn revoke_realm_grant(&self, realm_id: &str, grant_id: &str) -> Result<Value> {
        let grant_id = arkret_identifiers::GrantId::new(grant_id.to_owned())?;
        let grant_event_id = EventId::from_token_bytes(grant_id.token_bytes())?;
        let accepted = self.sdk.committed_event_get(&grant_event_id).await?;
        let commit = accepted.commit();
        self.submit_event(
            realm_id,
            arkret_wire::event_kind_str::CAPABILITY_REVOKE,
            serde_json::to_value(CapabilityRevokePayload {
                grant_id,
                expected_revision: arkret_wire::CurrentRevision {
                    commit_id: commit.commit_id.clone(),
                    stream_position: commit.stream_position,
                },
                reason: Some("revoked_by_realm_owner".to_owned()),
            })?,
        )
        .await
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
        let body = expect_json(
            self.post("/_arkret/self/events")
                .json(&crate::publication::initial_submission(event.clone(), "")?),
            StatusCode::OK,
        )
        .await?;
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
        // The digest is what a later response names to dominate this head, so
        // hand it back to the caller alongside the submit result.
        body["cotest_event_digest"] = json!(
            event
                .producer_proof
                .as_ref()
                .expect("authored Event has producer proof")
                .event_digest
        );
        Ok(body)
    }

    /// Author the signed producer Event. Commit order and admission authority
    /// are resolved by the governing Station when it signs the RealmCommit.
    pub async fn author_event_with_causal_refs(
        &self,
        realm_id: &str,
        kind: &str,
        payload: Value,
        causal_refs: Vec<String>,
        capability_refs: Vec<String>,
    ) -> Result<Event> {
        anyhow::ensure!(
            causal_refs.is_empty(),
            "producer Event has no causal_refs; migrate this case to committed RealmCommit references"
        );
        self.ensure_authority_for_kind(realm_id, kind).await?;
        let mut event = event_envelope_with_causal_refs_for_device(
            &self.actor,
            &self.device_id,
            &DidCoreId::new(self.service_id.clone())?,
            realm_id,
            kind,
            payload,
            None,
            Vec::new(),
            Vec::new(),
        );
        if kind != arkret_wire::event_kind_str::SELF_MODERATION_REPORT {
            self.stamp_authority(&mut event, realm_id, kind, true);
        }
        if !capability_refs.is_empty() {
            event.semantic_refs = capability_refs
                .into_iter()
                .map(|grant_id| {
                    SemanticRef::new(grant_id, arkret_wire::SEMANTIC_REF_ROLE_AUTHORIZED_BY)
                })
                .collect();
        }
        let (signing_seed, _) = event_signing_identity_for_device(&self.actor, &self.device_id);
        refresh_typed_event_proof_with_signing_seed(&mut event, signing_seed)?;
        Ok(event)
    }

    pub async fn author_event(&self, realm_id: &str, kind: &str, payload: Value) -> Result<Event> {
        self.author_event_with_causal_refs(realm_id, kind, payload, Vec::new(), Vec::new())
            .await
    }

    /// A producer Event cannot carry the retired Cell precondition array.
    /// Keep this entry point only so old negative cases fail explicitly until
    /// they are rewritten against the typed current revision carried by payload.
    pub async fn author_event_with_preconditions<P: serde::Serialize>(
        &self,
        realm_id: &str,
        kind: &str,
        payload: Value,
        preconditions: Vec<P>,
    ) -> Result<Event> {
        anyhow::ensure!(
            preconditions.is_empty(),
            "producer Event has no Cell preconditions; use payload expected_revision"
        );
        self.author_event(realm_id, kind, payload).await
    }
    /// Author and submit one actor-private `ak.read_cursor.advance`.
    ///
    /// `read-receipts.md` §6.6 keeps this Event off the shared Realm timeline:
    /// the device authors and signs the complete cursor, submits it through
    /// `ak.self.read_cursor.command.advance.v1`
    /// (`POST /_arkret/self/read-cursors`, service-http-binding.md), and the
    /// service forwards those exact bytes without rebuilding or re-signing
    /// them. Submitting through the shared Realm surface instead would test a
    /// path the cursor is defined not to take.
    ///
    /// The cursor object carries no `updated_at` (`read-receipts.md` §6.1): it
    /// is never updated in place, so the time of this update is the envelope
    /// `created_at` and MUST NOT be restated in the payload.
    pub async fn advance_read_cursor(&self, realm_id: &str, payload: Value) -> Result<Value> {
        let event = self
            .author_event(realm_id, "ak.read_cursor.advance", payload)
            .await?;
        expect_json(
            self.post("/_arkret/self/read-cursors")
                .json(&ReadCursorAdvanceRequestBody {
                    advance_event: EventAdmissionSubmission::new(event),
                }),
            StatusCode::OK,
        )
        .await
    }

    /// Read the actor-private read cursors this holder can see in `realm_id`.
    ///
    /// This is the read-back surface `read-receipts.md` §6.6 names, and the
    /// only one that may carry a cursor.
    pub async fn read_cursors(&self, realm_id: &str) -> Result<Value> {
        expect_json(
            self.get("/_arkret/self/read-cursors")
                .query(&[("realm_id", realm_id)]),
            StatusCode::OK,
        )
        .await
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
    arkret_policy::authz::owner_may_author_event_kind(kind).unwrap_or(false)
}

/// The action this harness self-grants so the Realm controller can author
/// `kind`, when `ak.realm.owner` does not cover it directly.
///
/// Smallest coverage set first, so a self-grant never quietly hands the
/// creator an aggregate admin action when a narrow one would do.
fn self_grant_action_for_kind(kind: &str) -> Option<&'static str> {
    arkret_schema::REGISTERED_CAPABILITY_ACTIONS
        .iter()
        .filter(|descriptor| descriptor.target_event_kinds.contains(&kind))
        .filter(|descriptor| {
            arkret_policy::authz::owner_may_grant(descriptor.action.as_str()).unwrap_or(false)
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
