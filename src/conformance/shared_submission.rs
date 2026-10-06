//! Actual shared transport observations reused by server fixtures and client oracles.
use anyhow::{Context, Result, bail, ensure};
use arkret_wire::ActorId;
use reqwest::StatusCode;
use serde_json::{Value, json};

use crate::harness::TestActorClient;

/// A real sender observation; elapsed transport time is regression evidence,
/// not an invented timing bucket or a proof of statistical indistinguishability.
pub struct SharedSubmissionObservation {
    sender_actor: ActorId,
    event_kind: arkret_wire::EventKind,
    scope_ref: arkret_wire::ScopeRef,
    authorization_ref: Option<arkret_wire::AuthorizationRef>,
    status: StatusCode,
    content_type: String,
    transport_protocol: String,
    response_shape: Value,
    pub outcome: arkret_wire::AuthoritySubmitOutcome,
    elapsed: std::time::Duration,
    attempts: Vec<(StatusCode, Option<String>)>,
}

pub fn json_shape(value: &Value) -> Value {
    match value {
        Value::Null => json!("null"),
        Value::Bool(_) => json!("boolean"),
        Value::Number(_) => json!("number"),
        Value::String(_) => json!("string"),
        Value::Array(values) => Value::Array(values.iter().map(json_shape).collect()),
        Value::Object(fields) => Value::Object(
            fields
                .iter()
                .map(|(key, value)| (key.clone(), json_shape(value)))
                .collect(),
        ),
    }
}

pub async fn observed_shared_message(
    peer: &TestActorClient,
    realm: &str,
    strand: &str,
    text: &str,
) -> Result<SharedSubmissionObservation> {
    let event = peer
        .author_event(
            realm,
            "ak.message.create",
            crate::harness::message_create_text_payload(strand, text)?,
        )
        .await?;
    observed_authored_shared_message(peer, event).await
}

pub async fn observed_authored_shared_message(
    peer: &TestActorClient,
    event: arkret_wire::Event,
) -> Result<SharedSubmissionObservation> {
    use arkret_models_collaboration::authority_commit::{
        SelfAuthoritySubmitOutcome, SelfAuthoritySubmitRequest,
    };
    let request = SelfAuthoritySubmitRequest::Event(crate::publication::initial_submission(
        event.clone(),
        "",
    )?);
    let request_bytes = arkret_canonical::canonical_json_bytes(&request)?;
    let started = std::time::Instant::now();
    let mut attempts = Vec::new();
    let (status, transport_protocol, content_type, bytes) = loop {
        let response = peer
            .post("/_arkret/self/events")
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(request_bytes.clone())
            .send()
            .await?;
        let status = response.status();
        let transport_protocol = format!("{:?}", response.version());
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .context("sender response lacks Content-Type")?
            .to_str()?
            .to_owned();
        ensure!(
            !response.headers().iter().any(|(_, value)| value
                .to_str()
                .is_ok_and(|value| value.contains("blocked_by_user"))),
            "private block leaked through a response header"
        );
        let bytes = response.bytes().await?;
        let problem_type = serde_json::from_slice::<Value>(&bytes)
            .ok()
            .and_then(|value| value.get("type")?.as_str().map(ToOwned::to_owned));
        attempts.push((status, problem_type.clone()));
        if status == StatusCode::SERVICE_UNAVAILABLE
            && problem_type.as_deref()
                == Some("https://arkret.org/problems/temporarily_unavailable")
            && attempts.len() < 3
        {
            tokio::time::sleep(std::time::Duration::from_millis(
                100 * attempts.len() as u64,
            ))
            .await;
            continue;
        }
        break (status, transport_protocol, content_type, bytes);
    };
    let elapsed = started.elapsed();
    eprintln!(
        "blocklist exact signed Message request attempts: event={}, attempts={attempts:?}, total_start_to_full_response_ns={}",
        event.event_id,
        elapsed.as_nanos(),
    );
    ensure!(
        status == StatusCode::OK,
        "shared Message submission failed after {attempts:?}: {}",
        String::from_utf8_lossy(&bytes)
    );
    ensure!(
        !String::from_utf8_lossy(&bytes).contains("blocked_by_user"),
        "private block leaked through the sender result"
    );
    let response_shape = json_shape(&serde_json::from_slice::<Value>(&bytes)?);
    let outcome: SelfAuthoritySubmitOutcome = serde_json::from_slice(&bytes)?;
    outcome.validate_for_request(&request)?;
    let SelfAuthoritySubmitOutcome::Ordinary(outcome) = outcome else {
        bail!("shared Message returned an unrelated authoring branch");
    };
    let arkret_wire::AuthoritySubmitOutcome::Accepted {
        status: accepted_status,
        commit,
    } = &outcome
    else {
        bail!("shared Message was rejected: {outcome:?}");
    };
    ensure!(
        *accepted_status == arkret_wire::AuthorityCommitStatus::Committed,
        "fresh shared Message did not commit"
    );
    let sender_actor = event.actor_id.clone();
    let event_kind = event.kind.clone();
    let scope_ref = event.scope_ref.clone();
    let authorization_ref = event.authorization_ref.clone();
    arkret_wire::CommittedEventFullView {
        event,
        commit: commit.clone(),
    }
    .validate_shape()?;
    Ok(SharedSubmissionObservation {
        sender_actor,
        event_kind,
        scope_ref,
        authorization_ref,
        status,
        content_type,
        transport_protocol,
        response_shape,
        outcome,
        elapsed,
        attempts,
    })
}

pub fn compare_shared_sender_observations(
    blocked: &SharedSubmissionObservation,
    unblocked: &SharedSubmissionObservation,
) -> Result<()> {
    ensure!(
        blocked.attempts.len() == 1 && unblocked.attempts.len() == 1,
        "paired one-shot transport differs because a registered retry occurred: blocked={:?}, unblocked={:?}; retries are recorded as availability evidence, not response-independence proof",
        blocked.attempts,
        unblocked.attempts,
    );
    ensure!(
        blocked.sender_actor == unblocked.sender_actor
            && blocked.event_kind == unblocked.event_kind
            && blocked.scope_ref == unblocked.scope_ref
            && blocked.authorization_ref == unblocked.authorization_ref
            && blocked.status == unblocked.status
            && blocked.content_type == unblocked.content_type
            && blocked.transport_protocol == unblocked.transport_protocol
            && blocked.response_shape == unblocked.response_shape,
        "paired submissions changed sender, scope, authority, operation, protocol or response shape"
    );
    let arkret_wire::AuthoritySubmitOutcome::Accepted {
        status: blocked_status,
        commit: blocked_commit,
    } = &blocked.outcome
    else {
        bail!("blocked peer was not accepted");
    };
    let arkret_wire::AuthoritySubmitOutcome::Accepted {
        status: unblocked_status,
        commit: unblocked_commit,
    } = &unblocked.outcome
    else {
        bail!("unblocked peer was not accepted");
    };
    ensure!(
        blocked_status == unblocked_status
            && blocked_commit.realm_id == unblocked_commit.realm_id
            && blocked_commit.stream_ref == unblocked_commit.stream_ref
            && blocked_commit.governance_generation == unblocked_commit.governance_generation,
        "private block changed the sender's accepted authority result"
    );
    ensure!(
        blocked_commit.event_ref != unblocked_commit.event_ref
            && blocked_commit.commit_id != unblocked_commit.commit_id,
        "distinct observations reused a fabricated acceptance"
    );
    let response_shape_digest =
        arkret_canonical::sha256_digest(&serde_json::to_vec(&blocked.response_shape)?);
    eprintln!(
        "blocklist shared sender paired transport: actor={}, operation={}, realm={}, protocol={}, status={}, content_type={}, response_shape_digest={}, outcome=committed/no_problem_reason, blocked_start_to_full_response_ns={}, unblocked_start_to_full_response_ns={}; durations are regression observations without a pass threshold",
        blocked.sender_actor,
        blocked.event_kind.as_str(),
        blocked_commit.realm_id,
        blocked.transport_protocol,
        blocked.status,
        blocked.content_type,
        response_shape_digest,
        blocked.elapsed.as_nanos(),
        unblocked.elapsed.as_nanos()
    );
    Ok(())
}
