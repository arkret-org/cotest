use anyhow::{Context, Result, anyhow};
use arkret::TypedTrustDomainId;
use arkret_canonical::{canonical_json_bytes, canonical_sha256, sha256_digest};
use arkret_identifiers::{Did, EventId, Hlc, RealmId};
use arkret_signatures::http_signature::{
    ContentDigest, ContentDigestAlgorithm, sign_message, signing_key_from_seed,
};
use arkret_wire::Event;
use reqwest::StatusCode;
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use url::Url;

use crate::harness::{
    ArkretServer, add_member, dev_login, expect_api_error, expect_json, expect_response,
    member_join_payload_with_delivery_binding, message_create_text_payload, message_redact_payload,
    realm_bootstrap_event_batch, submit_event,
};
use crate::scenarios::_helpers::federation_binding::{
    peer_events_submit_body, peer_events_submit_body_with_delivery_frontier,
};

struct FederationSource<'a> {
    service_id: &'a str,
    trust_domain: TypedTrustDomainId,
}

impl<'a> FederationSource<'a> {
    fn new(service_id: &'a str, trust_domain: &str) -> Result<Self> {
        Ok(Self {
            service_id,
            trust_domain: TypedTrustDomainId::new(trust_domain.to_owned())
                .with_context(|| format!("invalid test source trust domain `{trust_domain}`"))?,
        })
    }
}

fn with_signed_federation_request(
    builder: reqwest::RequestBuilder,
    method: &str,
    target_url: &str,
    destination: &ArkretServer,
    source: &FederationSource<'_>,
    body: &impl Serialize,
) -> Result<reqwest::RequestBuilder> {
    let body_bytes = canonical_json_bytes(body)?;
    let content_digest =
        ContentDigest::compute(&body_bytes, ContentDigestAlgorithm::Sha256).wire_value;
    let request_canonical_digest = canonical_sha256(body)?;
    let builder = with_signed_federation_request_digests(
        builder,
        SignedFederationDigests {
            method,
            target_url,
            destination,
            source,
            content_digest,
            request_canonical_digest,
            destination_trust_domain_override: None,
        },
    )?;
    Ok(builder.body(body_bytes))
}

fn with_signed_federation_empty_request(
    builder: reqwest::RequestBuilder,
    method: &str,
    target_url: &str,
    destination: &ArkretServer,
    source: &FederationSource<'_>,
) -> Result<reqwest::RequestBuilder> {
    let content_digest = ContentDigest::compute(&[], ContentDigestAlgorithm::Sha256).wire_value;
    let request_canonical_digest = sha256_digest([]);
    with_signed_federation_request_digests(
        builder,
        SignedFederationDigests {
            method,
            target_url,
            destination,
            source,
            content_digest,
            request_canonical_digest,
            destination_trust_domain_override: None,
        },
    )
}

fn with_signed_federation_empty_request_for_destination(
    builder: reqwest::RequestBuilder,
    method: &str,
    target_url: &str,
    destination: &ArkretServer,
    source: &FederationSource<'_>,
    destination_trust_domain: &str,
) -> Result<reqwest::RequestBuilder> {
    with_signed_federation_request_digests(
        builder,
        SignedFederationDigests {
            method,
            target_url,
            destination,
            source,
            content_digest: ContentDigest::compute(&[], ContentDigestAlgorithm::Sha256).wire_value,
            request_canonical_digest: sha256_digest([]),
            destination_trust_domain_override: Some(destination_trust_domain),
        },
    )
}

struct SignedFederationDigests<'a> {
    method: &'a str,
    target_url: &'a str,
    destination: &'a ArkretServer,
    source: &'a FederationSource<'a>,
    content_digest: String,
    request_canonical_digest: String,
    destination_trust_domain_override: Option<&'a str>,
}

fn with_signed_federation_request_digests(
    builder: reqwest::RequestBuilder,
    digests: SignedFederationDigests<'_>,
) -> Result<reqwest::RequestBuilder> {
    let SignedFederationDigests {
        method,
        target_url,
        destination,
        source,
        content_digest,
        request_canonical_digest,
        destination_trust_domain_override,
    } = digests;
    let source_service_id = source.service_id;
    let source_trust_domain = source.trust_domain.as_str();
    let destination_service_id = destination.service_id();
    let destination_trust_domain =
        destination_trust_domain_override.unwrap_or_else(|| destination.trust_domain().as_str());

    let parsed_url = Url::parse(target_url)?;
    let authority = parsed_url
        .port()
        .map(|port| format!("{}:{port}", parsed_url.host_str().unwrap_or("server")))
        .unwrap_or_else(|| parsed_url.host_str().unwrap_or("server").to_owned());
    let path_and_query = parsed_url
        .query()
        .map(|query| format!("{}?{query}", parsed_url.path()))
        .unwrap_or_else(|| parsed_url.path().to_owned());
    let target_uri = format!("{}://{}{}", parsed_url.scheme(), authority, path_and_query);

    let created = chrono::Utc::now().timestamp();
    let expires = created + 300;
    let keyid = format!("{source_service_id}#federation-fanout-key");
    // Bodyless GET peer reads MUST NOT carry — nor bind in their signature —
    // the body-digest components: soland rejects `content-digest` /
    // `request-canonical-digest` headers AND a Signature-Input that lists those
    // components for a GET (federation.md §3.2; peer.rs GET branch). Only
    // body-carrying requests bind the two digest components.
    let bind_body_digests = !method.eq_ignore_ascii_case("GET");
    let signature_params = if bind_body_digests {
        format!(
            "(\"@method\" \"@target-uri\" \"@authority\" \"content-digest\" \
             \"source-service-id\" \"destination-service-id\" \"source-trust-domain\" \
             \"destination-trust-domain\" \"request-canonical-digest\");created={created};\
             expires={expires};keyid=\"{keyid}\";alg=\"ed25519\""
        )
    } else {
        format!(
            "(\"@method\" \"@target-uri\" \"@authority\" \
             \"source-service-id\" \"destination-service-id\" \"source-trust-domain\" \
             \"destination-trust-domain\");created={created};\
             expires={expires};keyid=\"{keyid}\";alg=\"ed25519\""
        )
    };
    let signature_base = if bind_body_digests {
        format!(
            "\"@method\": {}\n\
             \"@target-uri\": {target_uri}\n\
             \"@authority\": {authority}\n\
             \"content-digest\": {content_digest}\n\
             \"source-service-id\": {source_service_id}\n\
             \"destination-service-id\": {destination_service_id}\n\
             \"source-trust-domain\": {source_trust_domain}\n\
             \"destination-trust-domain\": {destination_trust_domain}\n\
             \"request-canonical-digest\": {request_canonical_digest}\n\
             \"@signature-params\": {signature_params}",
            method.to_ascii_uppercase()
        )
    } else {
        format!(
            "\"@method\": {}\n\
             \"@target-uri\": {target_uri}\n\
             \"@authority\": {authority}\n\
             \"source-service-id\": {source_service_id}\n\
             \"destination-service-id\": {destination_service_id}\n\
             \"source-trust-domain\": {source_trust_domain}\n\
             \"destination-trust-domain\": {destination_trust_domain}\n\
             \"@signature-params\": {signature_params}",
            method.to_ascii_uppercase()
        )
    };
    let signing_key = development_service_signing_key(source_service_id);
    let signature = sign_message(signature_base.as_bytes(), &signing_key);

    let mut builder = builder
        .header("Source-Service-ID", source_service_id)
        .header("Destination-Service-ID", destination_service_id)
        .header("Source-Trust-Domain", source_trust_domain)
        .header("Destination-Trust-Domain", destination_trust_domain)
        .header("Signature-Input", format!("sig1={signature_params}"))
        .header("Signature", format!("sig1=:{signature}:"));
    if bind_body_digests {
        builder = builder
            .header("Content-Digest", content_digest)
            .header("Request-Canonical-Digest", request_canonical_digest);
    }
    Ok(builder)
}

fn development_service_signing_key(
    service_id: &str,
) -> arkret_signatures::http_signature::Ed25519SigningKey {
    let mut hasher = Sha256::new();
    hasher.update(b"soland:notary-ephemeral:");
    hasher.update(service_id.as_bytes());
    let seed: [u8; 32] = hasher.finalize().into();
    signing_key_from_seed(&seed)
}

fn account_delta_from_text(ndjson: &str) -> Result<Value> {
    for line in ndjson
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
    {
        let frame: Value = serde_json::from_str(line)
            .with_context(|| format!("invalid subscribe frame: {line}"))?;
        if frame.get("kind").and_then(Value::as_str) == Some("delta") {
            return Ok(frame.get("payload").cloned().unwrap_or(frame));
        }
    }
    Err(anyhow!(
        "account subscribe response did not include a delta frame"
    ))
}

fn signed_federation_event(
    event_id: &str,
    kind: &str,
    realm_id: &str,
    actor_id: &str,
    actor_seq: u64,
    prev_event_id: Option<&EventId>,
    payload: Value,
) -> Result<Event> {
    let mut event = Event::new(
        kind,
        arkret_wire::ScopeRef::Realm {
            realm_id: RealmId::new(realm_id.to_owned())
                .with_context(|| format!("invalid federation realm_id `{realm_id}`"))?,
        },
        Did::new(actor_id.to_owned())
            .with_context(|| format!("invalid federation actor_id `{actor_id}`"))?,
        actor_seq,
        Hlc::new(format!("01970e589d21-{actor_seq:04x}-a13f9c2e"))
            .context("invalid federation event HLC")?,
        payload,
    )?;
    event.created_at = chrono::DateTime::parse_from_rfc3339("2026-05-02T00:00:00.000Z")
        .context("invalid fixed federation event timestamp")?
        .with_timezone(&chrono::Utc);
    event.event_id = EventId::new(event_id.to_owned())
        .with_context(|| format!("invalid federation event_id `{event_id}`"))?;
    if let Some(prev_event_id) = prev_event_id {
        event.prev_refs.push(prev_event_id.clone());
    }
    sign_federation_contract_event(&mut event)?;
    Ok(event)
}

fn sign_federation_contract_event(event: &mut Event) -> Result<()> {
    let verification_method = crate::fixture_did_url(format!("{}#cotest", event.actor_id));
    let signer = arkret_signatures::Ed25519PayloadSigner::from_did_key_seed(
        arkret::signatures::development_signing_key_seed(&verification_method),
        event.actor_id.clone(),
        verification_method.clone(),
    );
    let created_at = event.created_at;
    event.proofs.clear();
    arkret::signatures::sign_event(
        event,
        &signer,
        &verification_method,
        arkret::signatures::SignEventOptions::new().with_created_at(created_at),
    )
    .context("sign federation contract Event with the provisioned development key")
}

/// Bind the delivery-binding policy Control Move to an empty pre-state.
///
/// Only the CBA precondition is producer-authored. The cell write itself is
/// derived from `kind + payload` through the contract registry, so a producer
/// that declared it would be asserting something the v1 Event wire cannot
/// carry (`models/event-and-patch.md` §2.4.2).
fn attach_delivery_policy_precondition(event: &mut Event) -> Result<()> {
    let cell = arkret_identifiers::CellRef::new(format!(
        "ak:cell:ak.component.realm.delivery_binding_policy.v1:{}",
        arkret_wire::NULL_SUBJECT
    ))?;
    event.preconditions = vec![arkret_wire::Precondition {
        cell,
        predicate: arkret_wire::Predicate {
            op: arkret_wire::PredicateOp::HeadEq,
            value: Some(Value::Null),
            values: None,
            predicate_id: None,
        },
    }];
    Ok(())
}

fn federation_realm_payload(
    realm_id: &str,
    creator: &str,
    trust_domain: &TypedTrustDomainId,
    visible_services: &[&str],
) -> Value {
    // Structured `plaintext_visible_services` entries (`{service_id,
    // data_classes}`) are required for the receiving service to hold the
    // `message_content` plaintext class — bare DIDs only populate the legacy
    // id list and leave the typed data-class map empty, so a plaintext
    // (`encryption_profile: "none"`) federated message would be denied.
    let plaintext_visible_services = visible_services
        .iter()
        .map(|service_id| {
            json!({
                "service_id": service_id,
                "service_kind": "principal_server",
                "data_classes": ["message_content"],
                "purposes": ["federated_plaintext_delivery"],
                "visibility": "private_plaintext"
            })
        })
        .collect::<Vec<_>>();
    json!({
        "object": {
            "id": realm_id,
            "schema": "ak.schema.realm.v1",
            "title": "Federation Contract Realm",
            "summary": "federation contract fixture",
            "trust_domain": trust_domain,
            "created_by": creator,
            "schema_refs": ["ak.schema.realm.v1"],
            "default_discoverability": "invite_only",
            "default_join_rule": "invite",
            "history_visibility": "shared",
            "encryption_profile": "none",
            "security_class": "standard",
            "federation_policy": "open",
            "notary_profile": "single_did",
            "digest_algorithm": "sha256",
            "plaintext_visible_services": plaintext_visible_services,
            "notary": {
                "kind": "single_did",
                "did": creator,
                "recovery_members": ["did:web:recovery-federation-contract.cotest.local"],
                "controller_organization": creator,
                "recovery_controller_organizations": ["did:web:recovery-org-federation-contract.cotest.local"]
            },
            "capability_action_registry_digest":
                arkret::current_capability_action_registry_digest()
                    .expect("embedded capability-action registry"),
            "created_at": "2026-05-02T00:00:00.000Z"
        }
    })
}

pub async fn federation_endpoints_reject_invalid_input_shapes() -> Result<()> {
    let server = ArkretServer::spawn("federation-invalid").await?;
    let invalid_source = FederationSource::new(
        "did:web:invalid-shape.remote",
        "ak:trust_domain:invalid-shape.remote",
    )?;

    // A body that is not even parseable JSON fails at the JSON layer and is
    // reported as `bad_json`.
    expect_api_error(
        server
            .http()
            .post(server.url("/_arkret/peer/events"))
            .header("content-type", "application/json")
            .body("{"),
        StatusCode::BAD_REQUEST,
        "schema_violation",
    )
    .await?;
    // A syntactically valid JSON object that cannot deserialize into the
    // typed peer-events command fails schema validation before federation trust
    // headers are evaluated.
    expect_api_error(
        server
            .http()
            .post(server.url("/_arkret/peer/events"))
            .json(&json!({"operations": []})),
        StatusCode::BAD_REQUEST,
        "schema_violation",
    )
    .await?;
    expect_api_error(
        server.http().get(server.url("/_arkret/peer/events")),
        StatusCode::BAD_REQUEST,
        "schema_violation",
    )
    .await?;
    let valid_realms_url =
        server.url("/_arkret/peer/events?realms=ak:realm:0196419b-0000-7000-8000-00000000f0aa");
    expect_api_error(
        with_signed_federation_empty_request_for_destination(
            server.http().get(&valid_realms_url),
            "GET",
            &valid_realms_url,
            &server,
            &invalid_source,
            "ak:trust_domain:bad%3a443",
        )?,
        StatusCode::BAD_REQUEST,
        "schema_violation",
    )
    .await?;
    let mismatched_destination =
        TypedTrustDomainId::new("ak:trust_domain:other.cotest.local".to_owned())?;
    expect_api_error(
        with_signed_federation_empty_request_for_destination(
            server.http().get(&valid_realms_url),
            "GET",
            &valid_realms_url,
            &server,
            &invalid_source,
            mismatched_destination.as_str(),
        )?,
        StatusCode::CONFLICT,
        "cross_domain_replay_rejected",
    )
    .await?;
    let invalid_realms_url = server.url("/_arkret/peer/events?realms=bad");
    expect_api_error(
        with_signed_federation_empty_request(
            server.http().get(&invalid_realms_url),
            "GET",
            &invalid_realms_url,
            &server,
            &invalid_source,
        )?,
        StatusCode::BAD_REQUEST,
        "invalid_param",
    )
    .await?;

    Ok(())
}

pub async fn federation_replay_snapshot_and_redaction_contracts_work() -> Result<()> {
    // This server is a pure federation replica / observer of `remote.example`'s
    // Realm: it holds a copy but hosts no locally-homed members. Replica posture
    // admits subsequent delivery pushes that a conservative server would reject
    // with `delivery_binding_stale` (no local member binding to be stale
    // against). See AppConfig::federation_replica_observer / member-delivery-binding.md §4.
    let server = ArkretServer::spawn_with_env(
        "federation-replay",
        &[("SOLAND_FEDERATION_REPLICA_OBSERVER", "1")],
    )
    .await?;
    let realm_id = "ak:realm:0196419b-0000-7000-8000-00000000fed0";
    let policy_event_id = "ak:event:0196419b-0000-7000-8000-00000000f0fe";
    let member_event_id = "ak:event:0196419b-0000-7000-8000-00000000f0ff";
    let replay_event_id = "ak:event:0196419b-0000-7000-8000-00000000f101";
    let invalid_event_id = "ak:event:0196419b-0000-7000-8000-00000000f102";
    let redaction_event_id = "ak:event:0196419b-0000-7000-8000-00000000f103";
    let remote_service_id = "did:web:remote.example";
    let remote_source = FederationSource::new(remote_service_id, "ak:trust_domain:remote.example")?;

    let mut bootstrap_events = realm_bootstrap_event_batch(
        remote_service_id,
        realm_id,
        federation_realm_payload(
            realm_id,
            remote_service_id,
            &remote_source.trust_domain,
            &[remote_service_id, server.service_id()],
        ),
    )?
    .into_iter()
    .map(serde_json::from_value::<Event>)
    .collect::<Result<Vec<_>, _>>()?;
    let realm_create = bootstrap_events.remove(0);
    let realm_create_event_id = realm_create.event_id.clone();
    // The originating service is itself the Realm's delivery-bound member (its
    // events are homed on remote.example), so a peer read by that same service
    // is an authorised member read rather than anti-enumeration probing. Declare
    // the delivery-binding policy admitting the binding, then bind the member.
    let mut delivery_policy = signed_federation_event(
        policy_event_id,
        "ak.realm.delivery_binding_policy",
        realm_id,
        remote_service_id,
        1,
        Some(&realm_create_event_id),
        json!({
            "realm_id": realm_id,
            "allowed_binding_sources": ["explicit"],
            "allowed_recipient_services": [remote_service_id]
        }),
    )?;
    attach_delivery_policy_precondition(&mut delivery_policy)?;
    sign_federation_contract_event(&mut delivery_policy)?;
    let member_binding = signed_federation_event(
        member_event_id,
        "ak.member.state",
        realm_id,
        remote_service_id,
        2,
        Some(&delivery_policy.event_id),
        member_join_payload_with_delivery_binding(
            realm_id,
            remote_service_id,
            json!({
                "recipient_service_id": remote_service_id,
                "recipient_service_kind": "principal_server",
                "binding_scope": "realm",
                "binding_source": "explicit",
                "delivery_modes": ["events", "sync"],
                "service_acceptance_ref": realm_create_event_id.as_str(),
                "resolved_at": "2026-05-02T00:00:00.000Z"
            }),
        )?,
    )?;
    let event = signed_federation_event(
        replay_event_id,
        "ak.message.create",
        realm_id,
        remote_service_id,
        3,
        Some(&member_binding.event_id),
        message_create_text_payload(realm_id, "from federation")?,
    )?;

    let first_push_url = server.url("/_arkret/peer/events");
    let bootstrap_push_body = peer_events_submit_body(
        realm_id,
        vec![
            realm_create.clone(),
            delivery_policy.clone(),
            member_binding.clone(),
        ],
        Some("bootstrap-1"),
    )?;
    let bootstrap_push = expect_json(
        with_signed_federation_request(
            server
                .http()
                .post(&first_push_url)
                .json(&bootstrap_push_body),
            "POST",
            &first_push_url,
            &server,
            &remote_source,
            &bootstrap_push_body,
        )?,
        StatusCode::OK,
    )
    .await?;
    assert_json_array_contains(
        &bootstrap_push["accepted"],
        realm_create_event_id.as_str(),
        &bootstrap_push,
    );
    assert!(json_array_absent_or_empty(&bootstrap_push["rejected"]));

    let delivery_frontier = vec![member_binding.event_id.clone()];
    let first_push_body = peer_events_submit_body_with_delivery_frontier(
        realm_id,
        vec![event.clone()],
        &delivery_frontier,
        Some("replay-1"),
    )?;
    let first_push = expect_json(
        with_signed_federation_request(
            server.http().post(&first_push_url).json(&first_push_body),
            "POST",
            &first_push_url,
            &server,
            &remote_source,
            &first_push_body,
        )?,
        StatusCode::OK,
    )
    .await?;
    assert_json_array_contains(&first_push["accepted"], replay_event_id, &first_push);
    assert!(json_array_absent_or_empty(&first_push["rejected"]));

    let pulled_url = server.url(&format!("/_arkret/peer/events?realms={realm_id}"));
    let pulled = expect_json(
        with_signed_federation_empty_request(
            server.http().get(&pulled_url),
            "GET",
            &pulled_url,
            &server,
            &remote_source,
        )?,
        StatusCode::OK,
    )
    .await?;
    assert!(
        peer_events_contain_event_id(&pulled["events"], replay_event_id),
        "peer pull did not include replay event: {pulled}"
    );

    let snapshot_head_url = server.url(&format!("/_arkret/peer/snapshot/head?realm_id={realm_id}"));
    expect_api_error(
        with_signed_federation_empty_request(
            server.http().get(&snapshot_head_url),
            "GET",
            &snapshot_head_url,
            &server,
            &remote_source,
        )?,
        StatusCode::NOT_IMPLEMENTED,
        "not_implemented",
    )
    .await?;

    let replay_url = server.url("/_arkret/peer/events");
    // Replay the already-delivered DataEvent: federation re-delivery MUST be
    // idempotent — the duplicate is accepted as a no-op and the event is not
    // persisted twice (asserted below). The one-time realm-establishing events
    // (realm.create / policy / member binding) are not re-sent; re-delivering a
    // `ak.realm.create` is a distinct create-uniqueness concern, not a
    // message-replay one. The replica delivery gate admits the push
    // (federation_replica_observer), and the message dedupes against its prior
    // persisted copy.
    let replay_body = peer_events_submit_body(realm_id, vec![event.clone()], Some("replay-2"))?;
    let replay = expect_json(
        with_signed_federation_request(
            server.http().post(&replay_url).json(&replay_body),
            "POST",
            &replay_url,
            &server,
            &remote_source,
            &replay_body,
        )?,
        StatusCode::OK,
    )
    .await?;
    assert_json_array_contains(&replay["accepted"], replay_event_id, &replay);
    assert!(json_array_absent_or_empty(&replay["rejected"]));

    let after_replay_pull_url = server.url(&format!("/_arkret/peer/events?realms={realm_id}"));
    let after_replay_pull = expect_json(
        with_signed_federation_empty_request(
            server.http().get(&after_replay_pull_url),
            "GET",
            &after_replay_pull_url,
            &server,
            &remote_source,
        )?,
        StatusCode::OK,
    )
    .await?;
    let after_replay_events = after_replay_pull["events"].as_array().unwrap();
    assert_eq!(
        after_replay_events
            .iter()
            .filter(|event| peer_event_id(event) == Some(replay_event_id))
            .count(),
        1,
        "idempotent federation replay must not duplicate persisted events: {}",
        serde_json::to_string_pretty(&after_replay_pull)?
    );

    let invalid_event = signed_federation_event(
        invalid_event_id,
        "ak.message.create",
        realm_id,
        remote_service_id,
        5,
        Some(&event.event_id),
        json!({
            "encrypted": true,
            "content": {"ciphertext": "missing-envelope-fields"}
        }),
    )?;
    let invalid_push_url = server.url("/_arkret/peer/events");
    let invalid_push_body =
        peer_events_submit_body(realm_id, vec![invalid_event], Some("invalid-1"))?;
    let invalid_push = expect_json(
        with_signed_federation_request(
            server
                .http()
                .post(&invalid_push_url)
                .json(&invalid_push_body),
            "POST",
            &invalid_push_url,
            &server,
            &remote_source,
            &invalid_push_body,
        )?,
        StatusCode::OK,
    )
    .await?;
    assert!(invalid_push["accepted"].as_array().unwrap().is_empty());
    // An encrypted (`ciphertext`-bearing) federation DataEvent requires the
    // source peer's ServiceDescribe to advertise the MLS governance binding
    // profile (`ak.profile.mls_governance_binding.full.v1`) — the receiver MUST
    // NOT accept ciphertext it cannot bind to a supported governance profile
    // (crypto-media/encryption-and-audit.md §295). `remote.example` is a test
    // stand-in with no reachable describe, so the federation profile-intersection
    // gate rejects the push with `profile_unsupported` before payload schema
    // validation is reached.
    assert_eq!(
        invalid_push["rejected"][0]["reason_code"], "profile_unsupported",
        "invalid encrypted federation event response: {invalid_push}"
    );

    let redaction = signed_federation_event(
        redaction_event_id,
        "ak.message.redact",
        realm_id,
        remote_service_id,
        5,
        Some(&event.event_id),
        message_redact_payload(replay_event_id, None)?,
    )?;
    let redaction_push_url = server.url("/_arkret/peer/events");
    let redaction_push_body =
        peer_events_submit_body(realm_id, vec![redaction], Some("redaction-1"))?;
    let redaction_push = expect_json(
        with_signed_federation_request(
            server
                .http()
                .post(&redaction_push_url)
                .json(&redaction_push_body),
            "POST",
            &redaction_push_url,
            &server,
            &remote_source,
            &redaction_push_body,
        )?,
        StatusCode::OK,
    )
    .await?;
    assert_json_array_contains(
        &redaction_push["accepted"],
        redaction_event_id,
        &redaction_push,
    );

    let redacted_pull_url = server.url(&format!("/_arkret/peer/events?realms={realm_id}"));
    let redacted_pull = expect_json(
        with_signed_federation_empty_request(
            server.http().get(&redacted_pull_url),
            "GET",
            &redacted_pull_url,
            &server,
            &remote_source,
        )?,
        StatusCode::OK,
    )
    .await?;
    assert!(
        peer_events_contain_event_id(&redacted_pull["events"], replay_event_id),
        "peer history should retain the redacted target event: {redacted_pull}"
    );
    assert!(
        peer_events_contain_event_id(&redacted_pull["events"], redaction_event_id),
        "peer history should include the redaction event: {redacted_pull}"
    );

    Ok(())
}

pub async fn federation_remote_operations_project_to_sync_and_index() -> Result<()> {
    let server = ArkretServer::spawn("federation-project").await?;
    let remote_source = FederationSource::new(
        "did:web:remote-server.example",
        "ak:trust_domain:remote-server.example",
    )?;
    let alice = dev_login(
        &server,
        "did:web:alice.example",
        "ak:device:01904100-0000-7000-8000-0000000000a1",
    )
    .await?;
    let realm_id = "ak:realm:0196419b-0000-7000-8000-00000000fe20";
    let realm_events = realm_bootstrap_event_batch(
        "did:web:alice.example",
        realm_id,
        federation_realm_payload(
            realm_id,
            "did:web:alice.example",
            server.trust_domain(),
            &[server.service_id()],
        ),
    )?;
    let created = expect_json(
        server
            .http()
            .post(server.url("/_arkret/self/events"))
            .bearer_auth(&alice)
            .json(&json!({"events": realm_events})),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(created["status"], "accepted");

    // A routable member delivery_binding is only projected once the Realm
    // declares a `ak.realm.delivery_binding_policy` admitting the binding's
    // source + recipient (join-policy.md §5.1.3 — fail-closed, no DID-document
    // fallback). Without it the reducer rejects the routable join with
    // `delivery_binding_policy_unset` and no member is projected.
    let policy = submit_event(
        &server,
        &alice,
        "did:web:alice.example",
        realm_id,
        "ak.realm.delivery_binding_policy",
        json!({
            "realm_id": realm_id,
            "allowed_binding_sources": ["explicit"],
            "allowed_recipient_services": [server.service_id()]
        }),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(policy["status"], "accepted");

    // Bind the local owner to this server: a federation push to a Realm the
    // receiver already hosts is gated on an effective member
    // `delivery_binding.recipient_service_id = Destination-Service-ID`
    // (federation.md §4.1); absent it the receiver fails closed with
    // `delivery_binding_stale`. soland projects this member.state's own
    // event_id as the delivery-binding causal frontier ref, so capture it and
    // assert exactly that frontier on the push.
    let bound = submit_event(
        &server,
        &alice,
        "did:web:alice.example",
        realm_id,
        "ak.member.state",
        member_join_payload_with_delivery_binding(
            realm_id,
            "did:web:alice.example",
            json!({
                "recipient_service_id": server.service_id(),
                "recipient_service_kind": "principal_server",
                "binding_scope": "realm",
                "binding_source": "explicit",
                "delivery_modes": ["events", "sync"],
                "service_acceptance_ref": "ak:event:0196419b-0000-7000-8000-00000000fe10",
                "resolved_at": "2026-05-02T00:00:00.000Z"
            }),
        )?,
        StatusCode::OK,
    )
    .await?;
    assert_eq!(bound["status"], "accepted");
    let delivery_binding_frontier_id = bound["event_id"]
        .as_str()
        .context("member.state binding response missing event_id")?
        .to_owned();

    add_member(
        &server,
        &alice,
        "did:web:alice.example",
        realm_id,
        remote_source.service_id,
    )
    .await?;

    let event_id = "ak:event:0196419b-0000-7000-8000-00000000fe22";
    let event = signed_federation_event(
        event_id,
        "ak.message.create",
        realm_id,
        remote_source.service_id,
        0,
        None,
        json!({
            "strand_id": realm_id.replacen("ak:realm:", "ak:strand:", 1),
            "track_name": "discussion",
            "content": {
                "kind": "ak.content.text",
                "body": "searchable federated payload",
                "format": "plain"
            }
        }),
    )?;

    let delivery_binding_frontier = vec![
        EventId::new(delivery_binding_frontier_id)
            .context("invalid delivery binding frontier id")?,
    ];
    let txn_url = server.url("/_arkret/peer/events");
    let txn_body = peer_events_submit_body_with_delivery_frontier(
        realm_id,
        vec![event],
        &delivery_binding_frontier,
        Some("project-1"),
    )?;
    let txn = expect_json(
        with_signed_federation_request(
            server.http().post(&txn_url).json(&txn_body),
            "POST",
            &txn_url,
            &server,
            &remote_source,
            &txn_body,
        )?,
        StatusCode::OK,
    )
    .await?;
    if txn["accepted"][0] != event_id {
        return Err(anyhow!(
            "federation project message event was not accepted: {}",
            serde_json::to_string_pretty(&txn)?
        ));
    }

    let sync_response = expect_response(
        server
            .http()
            .get(server.url("/_arkret/self/account/subscribe?catchup=true"))
            .bearer_auth(&alice)
            .header("accept", "application/x-ndjson"),
        StatusCode::OK,
    )
    .await?;
    let sync = account_delta_from_text(&sync_response.text())?;
    let timeline_events = sync["realms"][realm_id]["timeline"]["events"]
        .as_array()
        .ok_or_else(|| anyhow!("sync response missing timeline events: {sync}"))?;
    if !timeline_events
        .iter()
        .any(|event| event_body(event) == Some("searchable federated payload"))
    {
        return Err(anyhow!(
            "federated realm sync did not expose projected message body: {}",
            serde_json::to_string_pretty(&sync["realms"][realm_id])?
        ));
    }

    Ok(())
}

fn peer_event_id(event: &Value) -> Option<&str> {
    event
        .get("event")
        .unwrap_or(event)
        .get("event_id")
        .and_then(Value::as_str)
}

fn peer_events_contain_event_id(events: &Value, expected: &str) -> bool {
    events.as_array().is_some_and(|events| {
        events
            .iter()
            .any(|event| peer_event_id(event) == Some(expected))
    })
}

fn event_body(event: &Value) -> Option<&str> {
    event
        .pointer("/content/body")
        .or_else(|| event.pointer("/payload/content/body"))
        .or_else(|| event.pointer("/payload/body"))
        .and_then(Value::as_str)
}

fn json_array_absent_or_empty(value: &Value) -> bool {
    value.is_null() || value.as_array().is_some_and(Vec::is_empty)
}

fn assert_json_array_contains(array: &Value, expected: &str, context: &Value) {
    assert!(
        array
            .as_array()
            .unwrap()
            .iter()
            .any(|value| value.as_str() == Some(expected)),
        "expected {array} to contain {expected}; response: {context}"
    );
}
