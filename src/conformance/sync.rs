//! `ak.vector.sync.client_account_stream.v1` — own-Station account aggregate
//! stream (`fixtures/client-sync-fixture.json`).
//!
//! The fixture states the client-side contract as decision tables. The SDK ships
//! its own consumer that re-derives each verdict from the case data; this suite
//! is deliberately the *other* kind of evidence. Every table row is bound to the
//! shipped wire and state types and then executed:
//!
//! * each `stream_ref` is parsed into [`CommitStreamRef`] and each `commit_id`
//!   into [`RealmCommitId`], so a fixture stream shape the closed enum cannot
//!   express fails here instead of being read as a string;
//! * every declared tail is replayed through [`MemoryAuthorityCommitStore`] —
//!   the store a governance Station actually commits with — so "accepted" means
//!   a real commit log took it and "rejected" means that store refused it;
//! * a broken tail is replayed against a store that already carries the sibling
//!   Realm and Sidecar streams, which is what makes "stops only that stream"
//!   an executed claim rather than a fixture flag;
//! * each reconnect `server_outcome` is resolved through a registry —
//!   [`arkret_wire::ErrorCode`], or [`arkret_wire::ReasonCode`] for the one
//!   stream condition that is not an HTTP error — so an outcome string no
//!   registry defines fails.
//!
//! Structural closure is taken from the types, never from the fixture: there is
//! no Realm-global position and no per-Realm position to compare because
//! [`RealmCommit`] declares neither member, and [`CommitStreamRef`] admits
//! exactly the Realm, Circle and Sidecar streams.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, anyhow, bail, ensure};
use arkret_hlc::Cursor;
use arkret_identifiers::{CircleId, RealmCommitId, RealmId, SidecarId};
use arkret_state::{
    AppendOutcome, AuthorityCommitStore, CommitLogError, MemoryAuthorityCommitStore,
};
use arkret_wire::{
    ActorId, Base64UrlString, CommitStreamRef, DetachedObjectSignature, DetachedSignatureAlgorithm,
    DetachedSignatureContext, DidUrl, ErrorCode, Event, EventKind, Hash, RealmCommit,
    RealmCommitAuthorityRef, ReasonCode, ScopeRef, project_did_to_core_id,
};
use chrono::{DateTime, TimeZone, Utc};
use serde_json::{Value, json};

use super::{
    fixture_runner_entrypoint, load_fixture_value, required_bool, required_field, required_str,
    required_u64, value_array,
};

/// Registry vector this suite executes.
pub const VECTOR_ID_CLIENT_ACCOUNT_STREAM: &str = "ak.vector.sync.client_account_stream.v1";

const FIXTURE: &str = "client-sync-fixture.json";
const SUITE: &str = "client_sync";
const RUNNER_ENTRYPOINT: &str = "ak.suite.sync.client_account_stream.v1";
const SUBSCRIBE_OPERATION_ID: &str = "ak.self.account.stream.subscribe.v1";

const AUTHORITY_DID: &str = "did:web:station.example";
const PRODUCER_DID: &str = "did:web:alice.example";

/// Stream classes the account aggregate multiplexes, in fixture order.
const STREAM_CLASSES: [&str; 3] = ["authority_committed", "account_private", "delivery"];

/// Run every section of the client-sync fixture.
pub fn run_sync_fixture_suite() -> Result<()> {
    let fixture = load_fixture_value(FIXTURE)?;
    verify_fixture_identity(&fixture)?;

    verify_subscription_has_no_aggregate_position(&fixture)?;
    verify_commit_carries_no_global_or_realm_position()?;
    verify_stream_ref_is_closed_to_three_streams()?;

    let tails = parse_stream_tails(&fixture)?;
    verify_every_stream_class_is_exercised(&tails)?;
    verify_tails_commit_exactly_when_continuous(&tails)?;
    verify_broken_tail_stops_only_its_own_stream(&tails)?;

    verify_checkpoint_never_outruns_projection(&fixture)?;
    verify_reconnect_resets_only_the_failed_surface(&fixture)?;
    verify_only_an_explicit_ack_cancels_a_delivery(&fixture)?;
    verify_stored_cursors_are_opaque(&fixture)?;
    Ok(())
}

// ── Fixture identity ────────────────────────────────────────────────────────

fn verify_fixture_identity(fixture: &Value) -> Result<()> {
    ensure!(
        required_str(fixture, "suite")? == SUITE,
        "client-sync fixture suite drifted"
    );
    ensure!(
        fixture_runner_entrypoint(fixture)? == RUNNER_ENTRYPOINT,
        "client-sync fixture runner entrypoint drifted"
    );
    let covers = value_array(required_field(fixture, "covers_vectors")?, "covers_vectors")?;
    ensure!(
        covers
            .iter()
            .any(|vector| vector.as_str() == Some(VECTOR_ID_CLIENT_ACCOUNT_STREAM)),
        "client-sync fixture is no longer bound to {VECTOR_ID_CLIENT_ACCOUNT_STREAM}"
    );
    for section in [
        "subscription",
        "stream_tails",
        "checkpoint_ordering",
        "reconnect",
        "delivery_cancellation",
    ] {
        ensure!(
            fixture.get(section).is_some(),
            "client-sync fixture lost the {section} section"
        );
    }
    Ok(())
}

// ── The aggregate stream has no position of its own ─────────────────────────

fn verify_subscription_has_no_aggregate_position(fixture: &Value) -> Result<()> {
    let subscription = required_field(fixture, "subscription")?;
    ensure!(
        required_str(subscription, "operation_id")? == SUBSCRIBE_OPERATION_ID,
        "account stream subscribe operation id drifted"
    );
    ensure!(
        !required_bool(subscription, "global_position_exists")?,
        "a Realm-global commit position must not exist"
    );
    ensure!(
        !required_bool(subscription, "realm_position_exists")?,
        "a per-Realm aggregate commit position must not exist"
    );
    let classes = value_array(
        required_field(subscription, "stream_classes")?,
        "stream_classes",
    )?
    .iter()
    .map(|class| {
        class
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| anyhow!("stream class must be a string"))
    })
    .collect::<Result<Vec<_>>>()?;
    ensure!(
        classes == STREAM_CLASSES,
        "account stream classes drifted: {classes:?}"
    );
    Ok(())
}

/// The fixture's `*_position_exists: false` flags are only trustworthy if the
/// shipped commit type has no such member to read. Take that from the type.
fn verify_commit_carries_no_global_or_realm_position() -> Result<()> {
    let commit = sample_commit()?;
    let value = serde_json::to_value(&commit)?;
    let members: BTreeSet<&str> = value
        .as_object()
        .ok_or_else(|| anyhow!("RealmCommit must serialize as an object"))?
        .keys()
        .map(String::as_str)
        .collect();
    ensure!(
        members.contains("stream_ref") && members.contains("stream_position"),
        "RealmCommit lost its per-stream position"
    );
    for forbidden in [
        "global_position",
        "realm_position",
        "realm_stream_position",
        "position",
        "sequence",
        "seal_ref",
        "frontier",
    ] {
        ensure!(
            !members.contains(forbidden),
            "RealmCommit reintroduced the removed member {forbidden}"
        );
    }
    Ok(())
}

/// `CommitStreamRef` is a closed tagged union. Round-trip each declared kind and
/// prove a fourth kind is unrepresentable on the wire.
fn verify_stream_ref_is_closed_to_three_streams() -> Result<()> {
    let realm_id = fixture_realm_id()?;
    let circle = CommitStreamRef::Circle {
        realm_id: realm_id.clone(),
        circle_id: CircleId::new(
            "ak:circle:AUD2WOhX-Xh47vBHtRJPMRfXRQXGiOWQqOrJGJnE8CaI".to_owned(),
        )?,
    };
    let sidecar = CommitStreamRef::Sidecar {
        realm_id: realm_id.clone(),
        sidecar_id: SidecarId::new(
            "ak:sidecar:AUD2WOhX-Xh47vBHtRJPMRfXRQXGiOWQqOrJGJnE8CaI".to_owned(),
        )?,
    };
    let realm = CommitStreamRef::Realm {
        realm_id: realm_id.clone(),
    };

    let mut kinds = BTreeSet::new();
    for stream_ref in [&realm, &circle, &sidecar] {
        let value = serde_json::to_value(stream_ref)?;
        let kind = value
            .get("kind")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("CommitStreamRef must carry a kind tag"))?
            .to_owned();
        ensure!(
            stream_ref.realm_id() == &realm_id,
            "every commit stream is anchored in its Realm"
        );
        let decoded: CommitStreamRef = serde_json::from_value(value)?;
        ensure!(
            &decoded == stream_ref,
            "CommitStreamRef did not round-trip through its wire form"
        );
        ensure!(kinds.insert(kind), "two stream kinds collided");
    }
    ensure!(
        kinds.iter().map(String::as_str).collect::<Vec<_>>() == ["circle", "realm", "sidecar"],
        "CommitStreamRef kinds drifted: {kinds:?}"
    );

    // A Realm-global chain would need a fourth, Realm-wide stream that is not
    // any of the three. It cannot be deserialized.
    let global: std::result::Result<CommitStreamRef, _> = serde_json::from_value(json!({
        "kind": "realm_global",
        "realm_id": realm_id,
    }));
    ensure!(
        global.is_err(),
        "a Realm-global commit stream must not be representable"
    );

    // The three streams are distinct keys even under one Realm.
    let distinct: BTreeSet<CommitStreamRef> = [realm, circle, sidecar].into_iter().collect();
    ensure!(
        distinct.len() == 3,
        "Realm, Circle and Sidecar streams must be three independent keys"
    );
    Ok(())
}

// ── Stream tails ────────────────────────────────────────────────────────────

/// One declared commit of a fixture tail, with its ids bound to typed ids.
#[derive(Clone, Debug)]
struct DeclaredCommit {
    stream_position: u64,
    commit_id: RealmCommitId,
    previous_commit_ref: Option<RealmCommitId>,
}

#[derive(Clone, Debug)]
struct DeclaredTail {
    name: String,
    stream_ref: CommitStreamRef,
    scope_ref: ScopeRef,
    commits: Vec<DeclaredCommit>,
    expected_accepted: bool,
    case: Value,
}

fn parse_stream_ref(value: &Value) -> Result<(CommitStreamRef, ScopeRef)> {
    let realm_id = RealmId::new(required_str(value, "realm_id")?.to_owned())?;
    Ok(match required_str(value, "kind")? {
        "realm" => (
            CommitStreamRef::Realm {
                realm_id: realm_id.clone(),
            },
            ScopeRef::Realm { realm_id },
        ),
        "circle" => {
            let circle_id = CircleId::new(required_str(value, "circle_id")?.to_owned())?;
            (
                CommitStreamRef::Circle {
                    realm_id: realm_id.clone(),
                    circle_id: circle_id.clone(),
                },
                ScopeRef::Circle {
                    realm_id,
                    circle_id,
                },
            )
        }
        "sidecar" => {
            let sidecar_id = SidecarId::new(required_str(value, "sidecar_id")?.to_owned())?;
            (
                CommitStreamRef::Sidecar {
                    realm_id: realm_id.clone(),
                    sidecar_id: sidecar_id.clone(),
                },
                ScopeRef::Sidecar {
                    realm_id,
                    sidecar_id,
                },
            )
        }
        other => bail!("client-sync fixture declared an unregistered stream kind {other}"),
    })
}

fn parse_stream_tails(fixture: &Value) -> Result<Vec<DeclaredTail>> {
    let mut tails = Vec::new();
    for case in value_array(required_field(fixture, "stream_tails")?, "stream_tails")? {
        let (stream_ref, scope_ref) = parse_stream_ref(required_field(case, "stream_ref")?)?;
        let mut commits = Vec::new();
        for commit in value_array(required_field(case, "commits")?, "commits")? {
            let previous_commit_ref = match commit.get("previous_commit_ref") {
                None | Some(Value::Null) => None,
                Some(value) => Some(RealmCommitId::new(
                    value
                        .as_str()
                        .ok_or_else(|| anyhow!("previous_commit_ref must be a string"))?
                        .to_owned(),
                )?),
            };
            commits.push(DeclaredCommit {
                stream_position: required_u64(commit, "stream_position")?,
                commit_id: RealmCommitId::new(required_str(commit, "commit_id")?.to_owned())?,
                previous_commit_ref,
            });
        }
        ensure!(
            !commits.is_empty(),
            "a declared stream tail must carry at least one commit"
        );
        let expected = required_str(case, "expected")?;
        tails.push(DeclaredTail {
            name: required_str(case, "name")?.to_owned(),
            stream_ref,
            scope_ref,
            commits,
            expected_accepted: match expected {
                "accepted" => true,
                "rejected" => false,
                other => bail!("unregistered stream tail verdict {other}"),
            },
            case: case.clone(),
        });
    }
    ensure!(
        !tails.is_empty(),
        "client-sync fixture declares no stream tails"
    );
    Ok(tails)
}

fn verify_every_stream_class_is_exercised(tails: &[DeclaredTail]) -> Result<()> {
    let mut seen = BTreeSet::new();
    for tail in tails {
        seen.insert(match tail.stream_ref {
            CommitStreamRef::Realm { .. } => "realm",
            CommitStreamRef::Circle { .. } => "circle",
            CommitStreamRef::Sidecar { .. } => "sidecar",
            // `CommitStreamRef` is `#[non_exhaustive]`; a fourth stream kind is
            // exactly the Realm-global chain this suite exists to rule out.
            _ => bail!("an unregistered commit stream kind reached the account stream"),
        });
    }
    for kind in ["realm", "circle", "sidecar"] {
        ensure!(
            seen.contains(kind),
            "the fixture must exercise the independent {kind} stream"
        );
    }
    Ok(())
}

/// Replay each declared tail through the shipped commit store. The fixture's
/// verdict is only satisfied when a real store reaches the same decision.
fn verify_tails_commit_exactly_when_continuous(tails: &[DeclaredTail]) -> Result<()> {
    for tail in tails {
        let store = MemoryAuthorityCommitStore::default();
        let outcome = append_tail(&store, tail)?;
        match (tail.expected_accepted, &outcome) {
            (true, Ok(())) => {}
            (false, Err(error)) => {
                ensure!(
                    matches!(error, CommitLogError::HeadConflict),
                    "{}: a broken tail must fail the head compare-and-swap, got {error}",
                    tail.name
                );
            }
            (true, Err(error)) => bail!(
                "{}: the fixture says accepted but the commit store refused it: {error}",
                tail.name
            ),
            (false, Ok(())) => bail!(
                "{}: the fixture says rejected but the commit store accepted every commit",
                tail.name
            ),
        }

        if !tail.expected_accepted {
            continue;
        }
        let head = store
            .stream_head(&tail.stream_ref)
            .ok_or_else(|| anyhow!("{}: accepted tail left no stream head", tail.name))?;
        let last = tail.commits.last().expect("tail is non-empty");
        ensure!(
            head.stream_position == last.stream_position && head.commit_id == last.commit_id,
            "{}: the stream head must be the last accepted commit",
            tail.name
        );
        ensure!(
            head.stream_ref == tail.stream_ref,
            "{}: the head belongs to another stream",
            tail.name
        );
    }
    Ok(())
}

/// An unexplained position jump stops that one stream. Replay the broken tail on
/// a store that already holds the sibling Realm and Sidecar streams and show the
/// siblings keep their heads and stay appendable.
fn verify_broken_tail_stops_only_its_own_stream(tails: &[DeclaredTail]) -> Result<()> {
    let broken = tails
        .iter()
        .find(|tail| !tail.expected_accepted)
        .ok_or_else(|| anyhow!("the fixture needs one discontinuous tail"))?;
    ensure!(
        required_str(&broken.case, "expected_client_action")?
            == "stop_this_stream_and_refetch_snapshot",
        "{}: a broken tail refetches its own snapshot",
        broken.name
    );
    ensure!(
        !required_bool(&broken.case, "other_streams_reset")?,
        "{}: a broken tail must not reset a sibling stream",
        broken.name
    );
    ensure!(
        !required_bool(&broken.case, "to_device_acks_reset")?,
        "{}: a broken tail must not invalidate the delivery queue",
        broken.name
    );

    let store = MemoryAuthorityCommitStore::default();
    let siblings: Vec<&DeclaredTail> = tails
        .iter()
        .filter(|tail| tail.expected_accepted && tail.stream_ref != broken.stream_ref)
        .collect();
    ensure!(
        siblings.len() >= 2,
        "the isolation check needs at least two sibling streams"
    );
    for sibling in &siblings {
        append_tail(&store, sibling)?
            .map_err(|error| anyhow!("{}: sibling tail was refused: {error}", sibling.name))?;
    }
    let before: BTreeMap<String, u64> = siblings
        .iter()
        .map(|sibling| head_position(&store, sibling))
        .collect::<Result<_>>()?;

    append_tail(&store, broken)?
        .err()
        .ok_or_else(|| anyhow!("{}: the broken tail was accepted", broken.name))?;

    let after: BTreeMap<String, u64> = siblings
        .iter()
        .map(|sibling| head_position(&store, sibling))
        .collect::<Result<_>>()?;
    ensure!(
        before == after,
        "a refused commit moved a sibling stream head: {before:?} -> {after:?}"
    );

    // The siblings are not merely unchanged, they are still writable: a stopped
    // stream is not a stopped Realm.
    for sibling in &siblings {
        let head = store
            .stream_head(&sibling.stream_ref)
            .ok_or_else(|| anyhow!("{}: sibling lost its head", sibling.name))?;
        let next = DeclaredCommit {
            stream_position: head.stream_position + 1,
            commit_id: derived_commit_id(&sibling.name, head.stream_position + 1),
            previous_commit_ref: Some(head.commit_id.clone()),
        };
        let event = producer_event(&sibling.scope_ref, &next)?;
        let commit = commit_for(sibling, &next, &event)?;
        match store.append(&event, commit) {
            Ok(AppendOutcome::Committed(_)) => {}
            other => bail!(
                "{}: sibling stream stopped advancing after an unrelated rejection: {other:?}",
                sibling.name
            ),
        }
    }
    Ok(())
}

fn head_position(store: &MemoryAuthorityCommitStore, tail: &DeclaredTail) -> Result<(String, u64)> {
    let head = store
        .stream_head(&tail.stream_ref)
        .ok_or_else(|| anyhow!("{}: stream has no head", tail.name))?;
    Ok((tail.name.clone(), head.stream_position))
}

/// Append every declared commit of a tail. The outer `Result` is a harness
/// failure; the inner one is the commit log's own verdict.
fn append_tail(
    store: &MemoryAuthorityCommitStore,
    tail: &DeclaredTail,
) -> Result<std::result::Result<(), CommitLogError>> {
    for declared in &tail.commits {
        let event = producer_event(&tail.scope_ref, declared)?;
        let commit = commit_for(tail, declared, &event)?;
        commit.validate_shape().map_err(|error| {
            anyhow!(
                "{}: declared commit is not a valid RealmCommit: {error}",
                tail.name
            )
        })?;
        match store.append(&event, commit) {
            Ok(AppendOutcome::Committed(_)) => {}
            Ok(AppendOutcome::Duplicate(_)) => bail!(
                "{}: a fixture tail must not declare the same commit twice",
                tail.name
            ),
            Err(error) => return Ok(Err(error)),
        }
    }
    Ok(Ok(()))
}

// ── Commit construction ─────────────────────────────────────────────────────

fn fixture_realm_id() -> Result<RealmId> {
    Ok(RealmId::new(
        "ak:realm:Ac1aCK8aQdnkYImvdH3DFjq4jDCP198pXYWCGzGuVyj5".to_owned(),
    )?)
}

fn fixed_time(offset_seconds: i64) -> DateTime<Utc> {
    Utc.timestamp_opt(1_800_000_000 + offset_seconds, 0)
        .single()
        .unwrap_or_else(Utc::now)
}

fn producer_actor() -> Result<ActorId> {
    let principal = project_did_to_core_id(&arkret_wire::Did::new(PRODUCER_DID.to_owned())?)?;
    let station = project_did_to_core_id(&arkret_wire::Did::new(AUTHORITY_DID.to_owned())?)?;
    Ok(ActorId::account(arkret_wire::AccountId::new(
        principal, station,
    )))
}

/// A producer Event carries no position, no predecessor and no stream: the
/// commit supplies all three. Each declared commit therefore gets its own
/// distinct Event, distinguished only by payload.
fn producer_event(scope_ref: &ScopeRef, declared: &DeclaredCommit) -> Result<Event> {
    Ok(arkret_wire::test_support::raw_event_for_actor_at(
        EventKind::MessageCreate.as_str(),
        scope_ref.clone(),
        producer_actor()?,
        json!({ "cotest_commit_id": declared.commit_id }),
        fixed_time(declared.stream_position as i64),
    )?)
}

fn authority_signature() -> Result<DetachedObjectSignature> {
    Ok(DetachedObjectSignature {
        context: DetachedSignatureContext::RealmCommit,
        signature_algorithm: DetachedSignatureAlgorithm::Ed25519,
        verification_method: DidUrl::new(format!("{AUTHORITY_DID}#key-1"))
            .map_err(anyhow::Error::msg)?,
        signed_digest: Hash::new(format!("sha256:{}", "11".repeat(32)))?,
        created_at: fixed_time(0),
        sig: Base64UrlString::new("AQ").map_err(anyhow::Error::msg)?,
    })
}

fn commit_for(
    tail: &DeclaredTail,
    declared: &DeclaredCommit,
    event: &Event,
) -> Result<RealmCommit> {
    Ok(RealmCommit {
        commit_id: declared.commit_id.clone(),
        realm_id: tail.stream_ref.realm_id().clone(),
        stream_ref: tail.stream_ref.clone(),
        stream_position: declared.stream_position,
        previous_commit_ref: declared.previous_commit_ref.clone(),
        event_ref: event.event_id.clone(),
        authority_generation: 0,
        authority_ref: RealmCommitAuthorityRef::GenesisOrChangeEvent(event.event_id.clone()),
        committed_at: fixed_time(1),
        signature: authority_signature()?,
    })
}

fn sample_commit() -> Result<RealmCommit> {
    let realm_id = fixture_realm_id()?;
    let declared = DeclaredCommit {
        stream_position: 0,
        commit_id: derived_commit_id("sample", 0),
        previous_commit_ref: None,
    };
    let tail = DeclaredTail {
        name: "sample".to_owned(),
        stream_ref: CommitStreamRef::Realm {
            realm_id: realm_id.clone(),
        },
        scope_ref: ScopeRef::Realm { realm_id },
        commits: vec![declared.clone()],
        expected_accepted: true,
        case: Value::Null,
    };
    let event = producer_event(&tail.scope_ref, &declared)?;
    commit_for(&tail, &declared, &event)
}

/// A canonical `RealmCommitId` for a commit the fixture does not declare.
fn derived_commit_id(label: &str, position: u64) -> RealmCommitId {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(b"cotest.client_sync.");
    hasher.update(label.as_bytes());
    hasher.update(position.to_be_bytes());
    RealmCommitId::from_digest(hasher.finalize().into())
}

// ── Durable checkpoint ordering ─────────────────────────────────────────────

/// A client may only advance its durable cursor after the projection that the
/// cursor claims is installed. Replay each declared step order through a small
/// durable-state model and crash after every step: the accepted orders never
/// lose the delta, the rejected order does.
fn verify_checkpoint_never_outruns_projection(fixture: &Value) -> Result<()> {
    let mut ordering_cases = 0_u32;
    let mut merge_cases = 0_u32;

    for case in value_array(
        required_field(fixture, "checkpoint_ordering")?,
        "checkpoint_ordering",
    )? {
        let name = required_str(case, "name")?;
        let steps = value_array(required_field(case, "steps")?, "steps")?;
        for (index, step) in steps.iter().enumerate() {
            ensure!(
                required_u64(step, "step")? == index as u64,
                "{name}: declared steps must be ordered from zero"
            );
        }
        let expected = required_str(case, "expected")?;

        let action_at = |action: &str| {
            steps
                .iter()
                .position(|step| step.get("action").and_then(Value::as_str) == Some(action))
        };

        if let (Some(install), Some(advance)) = (
            action_at("install_typed_current_result"),
            action_at("advance_durable_cursor"),
        ) {
            ordering_cases += 1;
            let loses_delta = replay_loses_delta_on_crash(steps)?;
            let verdict = if loses_delta { "rejected" } else { "accepted" };
            ensure!(
                verdict == expected,
                "{name}: replaying the declared order gives {verdict}, fixture says {expected}"
            );
            ensure!(
                loses_delta == (advance < install),
                "{name}: the delta is lost exactly when the cursor precedes the projection"
            );
            if loses_delta {
                ensure!(
                    case.get("reason").and_then(Value::as_str).is_some(),
                    "{name}: a rejected order must state why"
                );
            }
            continue;
        }

        // The merge rule: an incremental delivered before the baseline section
        // completes survives, because the baseline was cut at an older position.
        merge_cases += 1;
        let delivered = steps
            .iter()
            .find(|step| step.get("action").and_then(Value::as_str) == Some("deliver_incremental"))
            .ok_or_else(|| anyhow!("{name}: merge case delivers no incremental"))?;
        let delivered_position = required_u64(delivered, "stream_position")?;
        let (delivered_stream, _) = parse_stream_ref(required_field(delivered, "stream_ref")?)?;
        let baseline = steps
            .iter()
            .find(|step| {
                step.get("action").and_then(Value::as_str)
                    == Some("deliver_baseline_section_complete")
            })
            .ok_or_else(|| anyhow!("{name}: merge case completes no baseline section"))?;
        let cut = required_u64(baseline, "as_of_stream_position")?;
        ensure!(
            cut < delivered_position,
            "{name}: the merge rule only bites when the baseline cut is older"
        );
        ensure!(
            matches!(delivered_stream, CommitStreamRef::Realm { .. }),
            "{name}: the declared incremental must name a real commit stream"
        );
        // Merge by position: the higher position wins regardless of arrival.
        let merged = delivered_position.max(cut);
        ensure!(
            merged == delivered_position && expected == "accepted",
            "{name}: an older baseline must not overwrite a newer delta"
        );
        ensure!(
            required_str(case, "expected_state")?.contains("MUST NOT overwrite"),
            "{name}: the merge case must state the non-overwrite rule"
        );
    }

    ensure!(
        ordering_cases >= 2 && merge_cases >= 1,
        "both the checkpoint ordering rule and the merge rule must stay covered"
    );
    Ok(())
}

/// Durable client state for one commit delivery.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct DurableClientState {
    projection_installed: bool,
    cursor_advanced: bool,
}

/// Replay the declared steps, crashing after each one, and report whether any
/// crash point leaves a durable cursor past a projection that was never
/// installed — the state in which the delta is gone forever.
fn replay_loses_delta_on_crash(steps: &[Value]) -> Result<bool> {
    for crash_after in 0..steps.len() {
        let mut state = DurableClientState::default();
        for step in &steps[..=crash_after] {
            match step
                .get("action")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("every checkpoint step declares an action"))?
            {
                "deliver_commit" => {}
                "install_typed_current_result" => {
                    ensure!(
                        required_bool(step, "durable")?,
                        "a projection install that is not durable cannot support a checkpoint"
                    );
                    state.projection_installed = true;
                }
                "advance_durable_cursor" => state.cursor_advanced = true,
                other => bail!("unregistered checkpoint action {other}"),
            }
        }
        if state.cursor_advanced && !state.projection_installed {
            return Ok(true);
        }
    }
    Ok(false)
}

// ── Reconnect ───────────────────────────────────────────────────────────────

/// The one declared reconnect outcome that is a reason code rather than a wire
/// error code.
///
/// This used to be a fixture-local allowance: `stream_tail_missing` appeared in
/// `client-sync-fixture.json` and in no registry at all. The spec has since
/// registered it — `ReasonCode::StreamTailMissing` carries a descriptor — so the
/// gap is closed and the allowance is gone. It is deliberately *not* an
/// [`ErrorCode`]: a missing stream tail is a condition the client resumes from,
/// not an HTTP error, so it resolves through the reason-code registry while
/// every other failure outcome must still be a registered wire error code.
const REASON_CODE_RECONNECT_OUTCOME: &str = "stream_tail_missing";

/// Resolve a declared reconnect outcome. Every failure outcome except the one
/// reason-code condition above must be a registered wire error code, so a
/// fixture typo cannot pass for a verdict.
fn reconnect_verdict(server_outcome: &str) -> Result<&'static str> {
    if server_outcome == "accepted" || server_outcome == REASON_CODE_RECONNECT_OUTCOME {
        return Ok("resume");
    }
    let code = ErrorCode::from_wire(server_outcome).ok_or_else(|| {
        anyhow!("reconnect outcome {server_outcome} is not a registered wire error code")
    })?;
    Ok(match code {
        ErrorCode::CursorExpired
        | ErrorCode::CursorIntegrityInvalid
        | ErrorCode::CursorUnrecognized => "reset",
        _ => "resume",
    })
}

/// Guard the split above from both sides.
///
/// The registration is what licenses the branch in [`reconnect_verdict`], so it
/// is asserted rather than assumed: were the descriptor withdrawn, the fixture
/// would be back to declaring an outcome no registry defines and this gate would
/// be accepting it on the strength of a stale comment. And if the code ever also
/// becomes an [`ErrorCode`], the branch is redundant and the outcome must be
/// resolved through `ErrorCode` like every other one.
fn verify_reason_code_outcome_is_registered() -> Result<()> {
    ensure!(
        ReasonCode::from_wire(REASON_CODE_RECONNECT_OUTCOME)
            .descriptor()
            .is_some(),
        "{REASON_CODE_RECONNECT_OUTCOME} is no longer a registered reason code;          the reconnect fixture would be declaring an outcome no registry defines"
    );
    ensure!(
        ErrorCode::from_wire(REASON_CODE_RECONNECT_OUTCOME).is_none(),
        "{REASON_CODE_RECONNECT_OUTCOME} is now a wire error code as well;          drop the reason-code branch in reconnect_verdict and resolve it through          ErrorCode like every other outcome"
    );
    Ok(())
}

fn verify_reconnect_resets_only_the_failed_surface(fixture: &Value) -> Result<()> {
    verify_reason_code_outcome_is_registered()?;
    let mut resets = 0_u32;
    let mut resumes = 0_u32;

    for case in value_array(required_field(fixture, "reconnect")?, "reconnect")? {
        let name = required_str(case, "name")?;
        let outcome = required_str(case, "server_outcome")?;
        let expected = required_str(case, "expected")?;
        ensure!(
            reconnect_verdict(outcome)? == expected,
            "{name}: reconnect verdict does not follow its server outcome {outcome}"
        );

        match expected {
            "reset" => {
                resets += 1;
                ensure!(
                    required_bool(case, "baseline_redone")?,
                    "{name}: a discarded cursor redoes its surface baseline"
                );
                ensure!(
                    required_bool(case, "discard_old_cursor")?,
                    "{name}: the failed cursor must never be reused"
                );
            }
            "resume" => {
                resumes += 1;
                ensure!(
                    !flag(case, "baseline_redone").unwrap_or(false),
                    "{name}: a resumable reconnect must not redo a baseline"
                );
                ensure!(
                    !flag(case, "discard_old_cursor").unwrap_or(false),
                    "{name}: a resumable reconnect keeps its cursor"
                );
            }
            other => bail!("{name}: unregistered reconnect verdict {other}"),
        }

        // Neither branch may widen. Locally verified commits, MLS private state
        // and issued delivery ACKs survive every reconnect.
        for preserved in [
            "local_verified_commits_deleted",
            "mls_private_state_deleted",
            "delivery_acks_invalidated",
            "other_streams_reset",
            "to_device_acks_reset",
            "server_state_advanced",
        ] {
            ensure!(
                !flag(case, preserved).unwrap_or(false),
                "{name}: a reconnect must not set {preserved}"
            );
        }

        if outcome == REASON_CODE_RECONNECT_OUTCOME {
            verify_single_tail_recovery(name, case)?;
        }
    }

    ensure!(
        resets >= 3 && resumes >= 3,
        "the reconnect table must keep both the reset and the resume branch covered"
    );
    Ok(())
}

/// One missing tail recovers exactly that stream. The affected stream is parsed
/// as a real `CommitStreamRef` so the recovery names a stream that exists.
fn verify_single_tail_recovery(name: &str, case: &Value) -> Result<()> {
    let affected = required_field(case, "affected_stream_ref")?;
    let (stream_ref, _) = parse_stream_ref(affected)?;
    let affected_kind = required_str(affected, "kind")?;
    let recovered = value_array(
        required_field(case, "recovered_streams")?,
        "recovered_streams",
    )?
    .iter()
    .map(|value| {
        value
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| anyhow!("{name}: recovered stream kind must be a string"))
    })
    .collect::<Result<Vec<_>>>()?;
    ensure!(
        recovered == [affected_kind],
        "{name}: only the missing tail is recovered, got {recovered:?}"
    );
    ensure!(
        matches!(stream_ref, CommitStreamRef::Circle { .. }),
        "{name}: the fixture recovers a Circle tail while the Realm tail keeps its cursor"
    );
    Ok(())
}

fn flag(case: &Value, key: &str) -> Option<bool> {
    case.get(key).and_then(Value::as_bool)
}

// ── Delivery cancellation ───────────────────────────────────────────────────

/// A recipient delivery leaves the queue only on an explicit ACK issued after
/// the client durably processed it. Model the queue and run each declared
/// action against it.
fn verify_only_an_explicit_ack_cancels_a_delivery(fixture: &Value) -> Result<()> {
    let mut queue: BTreeSet<String> = BTreeSet::new();
    let mut cancelled = 0_u32;
    let mut retained = 0_u32;

    for case in value_array(
        required_field(fixture, "delivery_cancellation")?,
        "delivery_cancellation",
    )? {
        let name = required_str(case, "name")?;
        let message_id = required_str(case, "device_message_id")?.to_owned();
        ensure!(
            queue.insert(message_id.clone()),
            "{name}: each case owns its own delivery"
        );

        let action = required_str(case, "action")?;
        let durably_processed = required_bool(case, "durably_processed")?;
        let removed = action.starts_with("ack") && durably_processed;
        if removed {
            queue.remove(&message_id);
            cancelled += 1;
        } else {
            retained += 1;
        }

        let expected = required_str(case, "expected")?;
        let observed = if queue.contains(&message_id) {
            "still_queued"
        } else {
            "removed_from_recipient_queue"
        };
        ensure!(
            observed == expected,
            "{name}: the recipient queue reached {observed}, fixture says {expected}"
        );
        if expected == "still_queued" {
            ensure!(
                case.get("reason").and_then(Value::as_str).is_some(),
                "{name}: a retained delivery must state why the action did not cancel it"
            );
        }
        // The backfill path shares the one queue and the one ACK token; it never
        // mints a second copy.
        ensure!(
            !flag(case, "second_copy_created").unwrap_or(false),
            "{name}: a delivery must never be duplicated by the path that reads it"
        );
    }

    ensure!(
        cancelled >= 1 && retained >= 1,
        "the delivery table must keep both the cancelling and the non-cancelling action"
    );
    Ok(())
}

// ── Cursor opacity ──────────────────────────────────────────────────────────

/// Every cursor in the fixture is a stable label for a stored client position,
/// not an issued token. `Cursor::decode` is the only path from a token to a
/// position, and it must fail closed on all of them: a client persists its
/// cursor as opaque bytes and never parses ordering out of it.
fn verify_stored_cursors_are_opaque(fixture: &Value) -> Result<()> {
    let mut checked = 0_u32;
    let mut check = |token: &str, context: &str| -> Result<()> {
        ensure!(
            token.starts_with("ak:cursor:"),
            "{context}: a stored cursor keeps the transport prefix"
        );
        ensure!(
            Cursor::decode(token).is_err(),
            "{context}: a fixture label must not decode as a live cursor"
        );
        checked += 1;
        Ok(())
    };

    for case in value_array(required_field(fixture, "reconnect")?, "reconnect")? {
        let name = required_str(case, "name")?;
        check(required_str(case, "stored_cursor")?, name)?;
    }
    for case in value_array(
        required_field(fixture, "checkpoint_ordering")?,
        "checkpoint_ordering",
    )? {
        let name = required_str(case, "name")?;
        for step in value_array(required_field(case, "steps")?, "steps")? {
            if let Some(token) = step.get("cursor").and_then(Value::as_str) {
                check(token, name)?;
            }
        }
    }

    ensure!(checked >= 7, "every fixture cursor must be exercised");
    Ok(())
}
