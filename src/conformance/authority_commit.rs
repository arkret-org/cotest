//! Authority commit-log conformance suite (`ak.suite.authority_commit.v1`).
//!
//! Drives `arkret-spec/spec/v1/artifacts/fixtures/authority-commit-fixture.json`
//! against the SDK's own commit-log types and validators. Nothing in this module
//! re-implements a protocol type: every shape comes from `arkret_wire`, every
//! acceptance decision from `arkret_state::AuthorityCommitStore`, and every
//! reason code from the generated `arkret_wire::ReasonCode` constants.
//!
//! The fixture's `commit_id` placeholders (`ak:realm_commit:AAAA…`) are not
//! canonical suite-tagged content ids — their first decoded byte is not the
//! SHA-256 suite code — so they cannot be parsed as `RealmCommitId`. The suite
//! therefore takes the fixture's *linkage* (stream kind, position, and which
//! declared id each `previous_commit_ref` names) as the contract and binds each
//! declared id to a canonical `RealmCommitId` derived from that string, so the
//! identity relation the fixture asserts is preserved one-for-one.

use anyhow::{Result, anyhow, bail, ensure};
use arkret_canonical::DigestSuite;
use arkret_identifiers::{
    CircleId, DidCoreId, EventId, KeypackageClaimId, MlsWelcomeDeliveryId, RealmAuthorityHandoffId,
    RealmCommitId, RealmId, RealmSnapshotId, SidecarId,
};
use arkret_models_collaboration::governance::circle::{
    CircleScopeError, validate_mls_activation_is_irreversible, validate_scope_mls_activation,
};
use arkret_state::{
    AppendOutcome, AuthorityCommitStore, CommitLogError, MemoryAuthorityCommitStore,
};
use arkret_wire::{
    ActorId, AuthorityBundleRequest, AuthoritySubmitOutcome, AuthoritySubmitRequest,
    Base64UrlString, CommitStreamHead, CommitStreamRef, CommittedEventRef, DetachedObjectSignature,
    DetachedSignatureAlgorithm, DetachedSignatureContext, DidUrl, Event, EventCommitSubmission,
    EventKind, Hash, HistoryAccess, MlsCommitSubmission, MlsWelcomeDelivery,
    MlsWelcomeRecipientEndpoint, RealmAuthorityBundle, RealmAuthorityCurrentAssertion,
    RealmAuthorityHandoff, RealmAuthorityTransition, RealmCommit, RealmCommitAuthorityRef,
    RealmStateSnapshot, ReasonCode, RetentionAndHistoryFloor, ScopeRef, StreamScanRequest, UuidV7,
    project_did_to_core_id,
};
use chrono::{DateTime, TimeZone, Utc};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::{load_fixture_value, required_bool, required_field, required_str, required_u64};

/// Registry vector this suite executes.
pub const VECTOR_ID_AUTHORITY_COMMIT_INDEPENDENT_STREAMS: &str =
    "ak.vector.authority_commit.independent_streams.v1";

const FIXTURE: &str = "authority-commit-fixture.json";
const RUNNER_ENTRYPOINT: &str = "ak.suite.authority_commit.v1";
const FIXTURE_SCHEMA: &str = "arkret.authority-commit-fixture.v1";

const OLD_AUTHORITY_DID: &str = "did:web:old-authority.example";
const NEW_AUTHORITY_DID: &str = "did:web:new-authority.example";
const PRODUCER_DID: &str = "did:web:alice.example";
const NONCE: &str = "Y290ZXN0LWF1dGhvcml0eS1ub25jZS0x";

/// Run every section of the authority commit-log fixture.
pub fn run_authority_commit_suite() -> Result<()> {
    let fixture = load_fixture_value(FIXTURE)?;
    verify_fixture_identity(&fixture)?;

    let streams = parse_independent_streams(&fixture)?;
    verify_declared_single_chain_per_stream(&streams)?;
    verify_streams_have_no_global_position(&streams)?;
    verify_declared_streams_commit(&streams)?;
    verify_broken_chain_is_rejected(&streams)?;
    verify_forked_position_is_rejected(&streams)?;
    verify_cross_stream_predecessor_is_rejected(&streams)?;
    verify_scan_walks_one_stream_only(&streams)?;

    verify_producer_event_carries_no_commit_ordering()?;
    verify_event_commit_submission_is_the_only_event_dto()?;

    verify_join_bootstrap(&fixture)?;
    verify_handoff(&fixture)?;
    verify_mls_atomic_submission(&fixture)?;
    verify_mls_activation_is_irreversible()?;
    verify_recovery_completion_is_two_consecutive_commits()?;
    Ok(())
}

// ── Fixture projection ──────────────────────────────────────────────────────

fn verify_fixture_identity(fixture: &Value) -> Result<()> {
    ensure!(
        required_str(fixture, "schema")? == FIXTURE_SCHEMA,
        "authority-commit fixture schema drifted"
    );
    ensure!(
        required_str(fixture, "vector_id")? == VECTOR_ID_AUTHORITY_COMMIT_INDEPENDENT_STREAMS,
        "authority-commit fixture vector id drifted"
    );
    let runner = required_field(fixture, "runner")?;
    ensure!(
        required_str(runner, "entrypoint")? == RUNNER_ENTRYPOINT,
        "authority-commit fixture runner entrypoint drifted"
    );
    Ok(())
}

/// One declared commit in the fixture, with its placeholder ids bound to
/// canonical typed ids.
#[derive(Clone, Debug)]
struct DeclaredCommit {
    declared_id: String,
    declared_previous: Option<String>,
    stream_position: u64,
    commit_id: RealmCommitId,
    previous_commit_ref: Option<RealmCommitId>,
}

#[derive(Clone, Debug)]
struct DeclaredStream {
    realm_id: RealmId,
    stream_ref: CommitStreamRef,
    scope_ref: ScopeRef,
    commits: Vec<DeclaredCommit>,
}

/// Bind a fixture placeholder id to a canonical suite-tagged `RealmCommitId`.
///
/// The mapping is injective on the fixture's own strings, so "this commit names
/// that commit as its predecessor" survives the binding unchanged.
fn bind_declared_commit_id(declared: &str) -> RealmCommitId {
    let mut hasher = Sha256::new();
    hasher.update(b"cotest-authority-commit-fixture-id-v1");
    hasher.update(declared.as_bytes());
    RealmCommitId::from_digest(hasher.finalize().into())
}

fn parse_independent_streams(fixture: &Value) -> Result<Vec<DeclaredStream>> {
    let declared = required_field(fixture, "independent_streams")?
        .as_array()
        .ok_or_else(|| anyhow!("independent_streams must be an array"))?;
    ensure!(
        declared.len() == 3,
        "the fixture must declare a Realm, a Circle and a Sidecar stream"
    );

    let mut streams = Vec::with_capacity(declared.len());
    for entry in declared {
        let stream_value = required_field(entry, "stream_ref")?;
        let realm_id = RealmId::new(required_str(stream_value, "realm_id")?.to_owned())
            .map_err(|error| anyhow!("fixture realm_id is not a typed Realm id: {error}"))?;
        let (stream_ref, scope_ref) = match required_str(stream_value, "kind")? {
            "realm" => (
                CommitStreamRef::Realm {
                    realm_id: realm_id.clone(),
                },
                ScopeRef::Realm {
                    realm_id: realm_id.clone(),
                },
            ),
            "circle" => {
                let circle_id = CircleId::new(required_str(stream_value, "circle_id")?.to_owned())
                    .map_err(|error| anyhow!("fixture circle_id is not typed: {error}"))?;
                (
                    CommitStreamRef::Circle {
                        realm_id: realm_id.clone(),
                        circle_id: circle_id.clone(),
                    },
                    ScopeRef::Circle {
                        realm_id: realm_id.clone(),
                        circle_id,
                    },
                )
            }
            "sidecar" => {
                let sidecar_id =
                    SidecarId::new(required_str(stream_value, "sidecar_id")?.to_owned())
                        .map_err(|error| anyhow!("fixture sidecar_id is not typed: {error}"))?;
                (
                    CommitStreamRef::Sidecar {
                        realm_id: realm_id.clone(),
                        sidecar_id: sidecar_id.clone(),
                    },
                    ScopeRef::Sidecar {
                        realm_id: realm_id.clone(),
                        sidecar_id,
                    },
                )
            }
            other => bail!("unknown declared commit stream kind {other}"),
        };

        let mut commits = Vec::new();
        for commit in required_field(entry, "commits")?
            .as_array()
            .ok_or_else(|| anyhow!("stream commits must be an array"))?
        {
            let declared_id = required_str(commit, "commit_id")?.to_owned();
            let declared_previous = commit
                .get("previous_commit_ref")
                .and_then(Value::as_str)
                .map(str::to_owned);
            commits.push(DeclaredCommit {
                commit_id: bind_declared_commit_id(&declared_id),
                previous_commit_ref: declared_previous.as_deref().map(bind_declared_commit_id),
                declared_id,
                declared_previous,
                stream_position: required_u64(commit, "stream_position")?,
            });
        }
        ensure!(
            !commits.is_empty(),
            "a declared stream must carry at least its genesis commit"
        );
        streams.push(DeclaredStream {
            realm_id,
            stream_ref,
            scope_ref,
            commits,
        });
    }
    Ok(streams)
}

// ── Verdict 3: one chain per stream, position strictly +1 ───────────────────

fn verify_declared_single_chain_per_stream(streams: &[DeclaredStream]) -> Result<()> {
    for stream in streams {
        let first = &stream.commits[0];
        ensure!(
            first.stream_position == 0 && first.declared_previous.is_none(),
            "a stream must open at position 0 with a null previous_commit_ref"
        );
        for pair in stream.commits.windows(2) {
            ensure!(
                pair[1].stream_position == pair[0].stream_position + 1,
                "declared stream positions must increase by exactly one"
            );
            ensure!(
                pair[1].declared_previous.as_deref() == Some(pair[0].declared_id.as_str()),
                "each commit must name the previous stream head as its predecessor"
            );
        }
    }
    Ok(())
}

// ── Verdict 4: three independent streams, no global position ────────────────

fn verify_streams_have_no_global_position(streams: &[DeclaredStream]) -> Result<()> {
    let realm_ids = streams
        .iter()
        .map(|stream| stream.realm_id.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    ensure!(
        realm_ids.len() == 1,
        "the fixture's independent streams must belong to one Realm"
    );

    let mut kinds = std::collections::BTreeSet::new();
    for stream in streams {
        kinds.insert(match stream.stream_ref {
            CommitStreamRef::Realm { .. } => "realm",
            CommitStreamRef::Circle { .. } => "circle",
            CommitStreamRef::Sidecar { .. } => "sidecar",
            _ => bail!("the fixture declared an unknown commit stream kind"),
        });
        ensure!(
            stream
                .commits
                .iter()
                .any(|commit| commit.stream_position == 0),
            "every independent stream allocates its own position 0"
        );
    }
    ensure!(
        kinds.len() == 3,
        "Realm, Circle and Sidecar must each own a separate stream"
    );

    // A global sequence would make the three position-0 commits collide. Every
    // declared id is distinct while positions repeat across streams, which is
    // exactly the property a Realm-wide cursor would destroy.
    let declared_ids = streams
        .iter()
        .flat_map(|stream| {
            stream
                .commits
                .iter()
                .map(|commit| commit.declared_id.as_str())
        })
        .collect::<std::collections::BTreeSet<_>>();
    let declared_count: usize = streams.iter().map(|stream| stream.commits.len()).sum();
    ensure!(
        declared_ids.len() == declared_count,
        "declared commit ids must be unique across streams"
    );
    Ok(())
}

// ── Store-backed execution of the declared streams ──────────────────────────

fn authority_signature(
    context: DetachedSignatureContext,
    did: &str,
) -> Result<DetachedObjectSignature> {
    Ok(DetachedObjectSignature {
        context,
        signature_algorithm: DetachedSignatureAlgorithm::Ed25519,
        verification_method: DidUrl::new(format!("{did}#key-1")).map_err(anyhow::Error::msg)?,
        signed_digest: Hash::new(format!("sha256:{}", "11".repeat(32)))?,
        created_at: fixed_time(0),
        sig: Base64UrlString::new("AQ").map_err(anyhow::Error::msg)?,
    })
}

fn fixed_time(offset_seconds: i64) -> DateTime<Utc> {
    Utc.timestamp_opt(1_800_000_000 + offset_seconds, 0)
        .single()
        .unwrap_or_else(Utc::now)
}

fn producer_actor() -> Result<ActorId> {
    let principal = project_did_to_core_id(&arkret_wire::Did::new(PRODUCER_DID.to_owned())?)?;
    let station = project_did_to_core_id(&arkret_wire::Did::new(OLD_AUTHORITY_DID.to_owned())?)?;
    Ok(ActorId::account(arkret_wire::AccountId::new(
        principal, station,
    )))
}

fn producer_event(stream: &DeclaredStream, nonce: u8) -> Result<Event> {
    Ok(arkret_wire::test_support::raw_event_for_actor_at(
        EventKind::MessageCreate.as_str(),
        stream.scope_ref.clone(),
        producer_actor()?,
        json!({ "cotest_stream_nonce": nonce }),
        fixed_time(i64::from(nonce)),
    )?)
}

fn commit_for(
    stream: &DeclaredStream,
    declared: &DeclaredCommit,
    event: &Event,
    generation: u64,
    authority_did: &str,
) -> Result<RealmCommit> {
    Ok(RealmCommit {
        commit_id: declared.commit_id.clone(),
        realm_id: stream.realm_id.clone(),
        stream_ref: stream.stream_ref.clone(),
        stream_position: declared.stream_position,
        previous_commit_ref: declared.previous_commit_ref.clone(),
        event_ref: event.event_id.clone(),
        governance_generation: generation,
        authority_ref: RealmCommitAuthorityRef::GenesisOrChangeEvent(event.event_id.clone()),
        committed_at: fixed_time(1),
        signature: authority_signature(DetachedSignatureContext::RealmCommit, authority_did)?,
    })
}

/// Append every declared commit and assert the store keeps three separate heads.
fn verify_declared_streams_commit(streams: &[DeclaredStream]) -> Result<()> {
    let store = MemoryAuthorityCommitStore::default();
    let mut nonce = 0_u8;
    for stream in streams {
        for declared in &stream.commits {
            nonce += 1;
            let event = producer_event(stream, nonce)?;
            let commit = commit_for(stream, declared, &event, 0, OLD_AUTHORITY_DID)?;
            commit
                .validate_shape()
                .map_err(|error| anyhow!("declared commit is not a valid RealmCommit: {error}"))?;
            match store.append(&event, commit.clone()) {
                Ok(AppendOutcome::Committed(_)) => {}
                other => bail!("declared commit was not accepted: {other:?}"),
            }
            // Exact retry returns the same commit and never takes a position.
            match store.append(&event, commit) {
                Ok(AppendOutcome::Duplicate(_)) => {}
                other => bail!("exact retry must be a duplicate, not {other:?}"),
            }
        }
    }

    for stream in streams {
        let head = store
            .stream_head(&stream.stream_ref)
            .ok_or_else(|| anyhow!("declared stream has no head after committing"))?;
        let last = stream
            .commits
            .last()
            .ok_or_else(|| anyhow!("declared stream is empty"))?;
        ensure!(
            head.stream_position == last.stream_position && head.commit_id == last.commit_id,
            "stream head must be the last declared commit of that stream"
        );
    }
    Ok(())
}

fn verify_broken_chain_is_rejected(streams: &[DeclaredStream]) -> Result<()> {
    let stream = streams
        .iter()
        .find(|stream| stream.commits.len() > 1)
        .ok_or_else(|| anyhow!("the fixture needs one stream with a successor commit"))?;
    let store = MemoryAuthorityCommitStore::default();

    let genesis_event = producer_event(stream, 101)?;
    let genesis = commit_for(
        stream,
        &stream.commits[0],
        &genesis_event,
        0,
        OLD_AUTHORITY_DID,
    )?;
    store
        .append(&genesis_event, genesis)
        .map_err(|error| anyhow!("genesis commit rejected: {error}"))?;

    // A null predecessor at a non-zero position is structurally invalid.
    let orphan_event = producer_event(stream, 102)?;
    let mut orphan = commit_for(
        stream,
        &stream.commits[1],
        &orphan_event,
        0,
        OLD_AUTHORITY_DID,
    )?;
    orphan.previous_commit_ref = None;
    ensure!(
        orphan.validate_shape().is_err(),
        "a non-genesis position with no predecessor must fail shape validation"
    );
    ensure!(
        matches!(
            store.append(&orphan_event, orphan),
            Err(CommitLogError::InvalidCommit(_))
        ),
        "a broken chain must not be appended"
    );

    // A predecessor that is not the current head is a gap, not a link.
    let gap_event = producer_event(stream, 103)?;
    let mut gap = commit_for(stream, &stream.commits[1], &gap_event, 0, OLD_AUTHORITY_DID)?;
    gap.stream_position = stream.commits[1].stream_position + 1;
    ensure!(
        matches!(
            store.append(&gap_event, gap),
            Err(CommitLogError::HeadConflict)
        ),
        "a position skip must be rejected"
    );
    Ok(())
}

fn verify_forked_position_is_rejected(streams: &[DeclaredStream]) -> Result<()> {
    let stream = streams
        .iter()
        .find(|stream| stream.commits.len() > 1)
        .ok_or_else(|| anyhow!("the fixture needs one stream with a successor commit"))?;
    let store = MemoryAuthorityCommitStore::default();

    let genesis_event = producer_event(stream, 111)?;
    let genesis = commit_for(
        stream,
        &stream.commits[0],
        &genesis_event,
        0,
        OLD_AUTHORITY_DID,
    )?;
    store
        .append(&genesis_event, genesis)
        .map_err(|error| anyhow!("genesis commit rejected: {error}"))?;

    let first_event = producer_event(stream, 112)?;
    let first = commit_for(
        stream,
        &stream.commits[1],
        &first_event,
        0,
        OLD_AUTHORITY_DID,
    )?;
    store
        .append(&first_event, first.clone())
        .map_err(|error| anyhow!("successor commit rejected: {error}"))?;

    // A second, differently-identified commit at the same position is a fork.
    let fork_event = producer_event(stream, 113)?;
    let mut fork = first;
    fork.commit_id = bind_declared_commit_id("cotest-fork-of-position-one");
    fork.event_ref = fork_event.event_id.clone();
    fork.authority_ref = RealmCommitAuthorityRef::GenesisOrChangeEvent(fork_event.event_id.clone());
    ensure!(
        matches!(
            store.append(&fork_event, fork),
            Err(CommitLogError::HeadConflict)
        ),
        "a fork at an occupied stream position must be rejected"
    );
    Ok(())
}

fn verify_cross_stream_predecessor_is_rejected(streams: &[DeclaredStream]) -> Result<()> {
    let realm_stream = streams
        .iter()
        .find(|stream| matches!(stream.stream_ref, CommitStreamRef::Realm { .. }))
        .ok_or_else(|| anyhow!("the fixture must declare a Realm stream"))?;
    let circle_stream = streams
        .iter()
        .find(|stream| matches!(stream.stream_ref, CommitStreamRef::Circle { .. }))
        .ok_or_else(|| anyhow!("the fixture must declare a Circle stream"))?;

    let realm_event = producer_event(realm_stream, 121)?;
    let realm_commit = commit_for(
        realm_stream,
        &realm_stream.commits[0],
        &realm_event,
        0,
        OLD_AUTHORITY_DID,
    )?;
    let circle_event = producer_event(circle_stream, 122)?;
    let mut circle_commit = commit_for(
        circle_stream,
        &circle_stream.commits[0],
        &circle_event,
        0,
        OLD_AUTHORITY_DID,
    )?;
    circle_commit.stream_position = 1;
    circle_commit.previous_commit_ref = Some(realm_commit.commit_id.clone());

    ensure!(
        circle_commit.validate_successor_of(&realm_commit).is_err(),
        "a predecessor in another independent stream must be rejected"
    );

    let store = MemoryAuthorityCommitStore::default();
    store
        .append(&realm_event, realm_commit)
        .map_err(|error| anyhow!("realm genesis commit rejected: {error}"))?;
    ensure!(
        matches!(
            store.append(&circle_event, circle_commit),
            Err(CommitLogError::HeadConflict)
        ),
        "a cross-stream predecessor must not be appendable"
    );
    Ok(())
}

fn verify_scan_walks_one_stream_only(streams: &[DeclaredStream]) -> Result<()> {
    let store = MemoryAuthorityCommitStore::default();
    let mut nonce = 130_u8;
    for stream in streams {
        for declared in &stream.commits {
            nonce += 1;
            let event = producer_event(stream, nonce)?;
            let commit = commit_for(stream, declared, &event, 0, OLD_AUTHORITY_DID)?;
            store
                .append(&event, commit)
                .map_err(|error| anyhow!("commit rejected while seeding scan: {error}"))?;
        }
    }

    for stream in streams {
        let request = StreamScanRequest {
            realm_id: stream.realm_id.clone(),
            stream_ref: stream.stream_ref.clone(),
            direction: arkret_wire::StreamScanDirection::After(None),
            limit: 1000,
        };
        let outcome = store
            .scan(&request)
            .map_err(|error| anyhow!("stream scan failed: {error}"))?;
        outcome
            .validate_for_request(&request)
            .map_err(|error| anyhow!("stream scan outcome is not a contiguous chain: {error}"))?;
        ensure!(
            outcome.committed_events.len() == stream.commits.len(),
            "a scan must return exactly its own stream's commits"
        );
        ensure!(
            outcome
                .committed_events
                .iter()
                .all(|item| item.commit().stream_ref == stream.stream_ref),
            "a scan must never leak another stream's commits"
        );
    }
    Ok(())
}

// ── Verdict 2: producer Events carry no ordering or linkage ─────────────────

fn verify_producer_event_carries_no_commit_ordering() -> Result<()> {
    let realm_id = RealmId::from_event_id(&EventId::from_digest(DigestSuite::Sha256, [0x41; 32]));
    let stream = DeclaredStream {
        realm_id: realm_id.clone(),
        stream_ref: CommitStreamRef::Realm {
            realm_id: realm_id.clone(),
        },
        scope_ref: ScopeRef::Realm { realm_id },
        commits: Vec::new(),
    };
    let event = producer_event(&stream, 1)?;
    let encoded = serde_json::to_value(&event)?;
    let event_keys = encoded
        .as_object()
        .ok_or_else(|| anyhow!("an Event must serialize as an object"))?;

    // The ordering vocabulary is read off the RealmCommit type itself rather
    // than restated here, so a member added to the commit can never silently
    // become legal on a producer Event.
    let commit_keys = commit_member_names()?;
    for member in &commit_keys {
        if member == "event_ref" || member == "realm_id" {
            continue;
        }
        ensure!(
            !event_keys.contains_key(member),
            "a producer Event must not carry the RealmCommit member {member}"
        );
        let mut tampered = encoded.clone();
        tampered
            .as_object_mut()
            .ok_or_else(|| anyhow!("tampered Event is not an object"))?
            .insert(member.clone(), json!(0));
        ensure!(
            serde_json::from_value::<Event>(tampered).is_err(),
            "an Event carrying {member} must be rejected"
        );
    }

    // The retired mechanisms have no SDK type left to read members from, so
    // their names are asserted as a closed residue guard.
    for member in [
        "seal",
        "seal_ref",
        "seal_basis",
        "cell",
        "cell_ref",
        "basis",
        "frontier",
        "closure",
        "previous_event",
        "previous_event_id",
    ] {
        let mut tampered = encoded.clone();
        tampered
            .as_object_mut()
            .ok_or_else(|| anyhow!("tampered Event is not an object"))?
            .insert(member.to_owned(), json!(null));
        ensure!(
            serde_json::from_value::<Event>(tampered).is_err(),
            "an Event carrying the retired member {member} must be rejected"
        );
    }
    Ok(())
}

fn commit_member_names() -> Result<Vec<String>> {
    let realm_id = RealmId::from_event_id(&EventId::from_digest(DigestSuite::Sha256, [0x42; 32]));
    let commit = RealmCommit {
        commit_id: bind_declared_commit_id("cotest-member-probe"),
        realm_id: realm_id.clone(),
        stream_ref: CommitStreamRef::Realm { realm_id },
        stream_position: 0,
        previous_commit_ref: None,
        event_ref: EventId::from_digest(DigestSuite::Sha256, [0x43; 32]),
        governance_generation: 0,
        authority_ref: RealmCommitAuthorityRef::GenesisOrChangeEvent(EventId::from_digest(
            DigestSuite::Sha256,
            [0x44; 32],
        )),
        committed_at: fixed_time(0),
        signature: authority_signature(DetachedSignatureContext::RealmCommit, OLD_AUTHORITY_DID)?,
    };
    Ok(serde_json::to_value(commit)?
        .as_object()
        .ok_or_else(|| anyhow!("a RealmCommit must serialize as an object"))?
        .keys()
        .cloned()
        .collect())
}

// ── Verdict 5: one Event submission DTO ─────────────────────────────────────

fn verify_event_commit_submission_is_the_only_event_dto() -> Result<()> {
    let realm_id = RealmId::from_event_id(&EventId::from_digest(DigestSuite::Sha256, [0x45; 32]));
    let stream = DeclaredStream {
        realm_id: realm_id.clone(),
        stream_ref: CommitStreamRef::Realm {
            realm_id: realm_id.clone(),
        },
        scope_ref: ScopeRef::Realm { realm_id },
        commits: Vec::new(),
    };
    let event = signed_event(producer_event(&stream, 2)?)?;
    let submission = EventCommitSubmission::new(event.clone());
    let encoded = serde_json::to_value(&submission)?;
    ensure!(
        encoded
            .as_object()
            .ok_or_else(|| anyhow!("submission must serialize as an object"))?
            .keys()
            .map(String::as_str)
            .eq(["event"]),
        "EventCommitSubmission is closed over exactly one member"
    );

    for extra in [
        "basis",
        "expected_revision",
        "commit_base",
        "preconditions",
        "seal",
    ] {
        let mut tampered = encoded.clone();
        tampered
            .as_object_mut()
            .ok_or_else(|| anyhow!("tampered submission is not an object"))?
            .insert(extra.to_owned(), json!(null));
        ensure!(
            serde_json::from_value::<EventCommitSubmission>(tampered).is_err(),
            "the submission DTO must reject {extra}"
        );
    }

    let request = AuthoritySubmitRequest::Event(submission);
    request
        .validate()
        .map_err(|error| anyhow!("a well-formed Event submission must validate: {error}"))?;
    Ok(())
}

/// Attach the single structural producer proof `validate_structural` requires.
fn signed_event(mut event: Event) -> Result<Event> {
    let digest = Hash::new(format!("sha256:{}", "22".repeat(32)))?;
    event.producer_proof = Some(arkret_wire::ProducerEventProof {
        kind: arkret_wire::proof_kind::DETACHED_JWS.to_owned(),
        verification_method: DidUrl::new(format!("{PRODUCER_DID}#key-1"))
            .map_err(anyhow::Error::msg)?,
        event_digest: digest.clone(),
        created_at: fixed_time(0),
        domain: None,
        audience: None,
        proof_purpose: None,
        jws: arkret_wire::test_support::structural_only_detached_jws(&digest),
    });
    event
        .validate_for_submit_structural()
        .map_err(|error| anyhow!("structurally signed Event is invalid: {error}"))?;
    Ok(event)
}

// ── Verdict 6: join bootstrap authenticates the current authority ───────────

struct AuthorityFixture {
    bundle: RealmAuthorityBundle,
    handoff: RealmAuthorityHandoff,
    snapshot: RealmStateSnapshot,
    final_stream_heads: Vec<CommitStreamHead>,
    realm_id: RealmId,
    /// The fixture's declared streams re-rooted at the Realm the genesis
    /// `ak.realm.create` Event derives, so every binding the bundle checks is
    /// the one the protocol actually produces.
    streams: Vec<DeclaredStream>,
}

/// Re-root the declared streams at `realm_id`, keeping each Circle / Sidecar
/// id and the declared commit chain intact.
fn reroot_streams(streams: &[DeclaredStream], realm_id: &RealmId) -> Result<Vec<DeclaredStream>> {
    streams
        .iter()
        .map(|stream| {
            let (stream_ref, scope_ref) = match &stream.stream_ref {
                CommitStreamRef::Realm { .. } => (
                    CommitStreamRef::Realm {
                        realm_id: realm_id.clone(),
                    },
                    ScopeRef::Realm {
                        realm_id: realm_id.clone(),
                    },
                ),
                CommitStreamRef::Circle { circle_id, .. } => (
                    CommitStreamRef::Circle {
                        realm_id: realm_id.clone(),
                        circle_id: circle_id.clone(),
                    },
                    ScopeRef::Circle {
                        realm_id: realm_id.clone(),
                        circle_id: circle_id.clone(),
                    },
                ),
                CommitStreamRef::Sidecar { sidecar_id, .. } => (
                    CommitStreamRef::Sidecar {
                        realm_id: realm_id.clone(),
                        sidecar_id: sidecar_id.clone(),
                    },
                    ScopeRef::Sidecar {
                        realm_id: realm_id.clone(),
                        sidecar_id: sidecar_id.clone(),
                    },
                ),
                _ => bail!("the fixture declared an unknown commit stream kind"),
            };
            Ok(DeclaredStream {
                realm_id: realm_id.clone(),
                stream_ref,
                scope_ref,
                commits: stream.commits.clone(),
            })
        })
        .collect()
}

fn build_authority_fixture(declared: &[DeclaredStream]) -> Result<AuthorityFixture> {
    // `ak.realm.create` uses the genesis scope, so the Realm id is derived from
    // the create Event itself. Every stream below is re-rooted at that Realm.
    let genesis_event = signed_event(genesis_create_event()?)?;
    let realm_id = genesis_event.realm_id.clone();
    let streams = reroot_streams(declared, &realm_id)?;
    let realm_stream = streams
        .iter()
        .find(|stream| matches!(stream.stream_ref, CommitStreamRef::Realm { .. }))
        .ok_or_else(|| anyhow!("the fixture must declare a Realm stream"))?;
    let realm_stream_ref = realm_stream.stream_ref.clone();
    let genesis_commit = RealmCommit {
        commit_id: bind_declared_commit_id("cotest-genesis-commit"),
        realm_id: realm_id.clone(),
        stream_ref: realm_stream_ref.clone(),
        stream_position: 0,
        previous_commit_ref: None,
        event_ref: genesis_event.event_id.clone(),
        governance_generation: 0,
        authority_ref: RealmCommitAuthorityRef::GenesisOrChangeEvent(
            genesis_event.event_id.clone(),
        ),
        committed_at: fixed_time(1),
        signature: authority_signature(DetachedSignatureContext::RealmCommit, OLD_AUTHORITY_DID)?,
    };

    let change_event = signed_event(arkret_wire::test_support::raw_event_for_actor_at(
        EventKind::RealmGovernanceStationChange.as_str(),
        ScopeRef::Realm {
            realm_id: realm_id.clone(),
        },
        producer_actor()?,
        json!({ "cotest_change": 1 }),
        fixed_time(10),
    )?)?;
    let change_commit = RealmCommit {
        commit_id: bind_declared_commit_id("cotest-change-commit"),
        realm_id: realm_id.clone(),
        stream_ref: realm_stream_ref.clone(),
        stream_position: 1,
        previous_commit_ref: Some(genesis_commit.commit_id.clone()),
        event_ref: change_event.event_id.clone(),
        governance_generation: 0,
        authority_ref: RealmCommitAuthorityRef::GenesisOrChangeEvent(change_event.event_id.clone()),
        committed_at: fixed_time(11),
        signature: authority_signature(DetachedSignatureContext::RealmCommit, OLD_AUTHORITY_DID)?,
    };

    // The private manifest carries every frozen head; the public bundle only
    // ever names the Realm stream head.
    let mut final_stream_heads = streams
        .iter()
        .map(|stream| {
            let (position, commit_id) = if stream.stream_ref == realm_stream_ref {
                (
                    change_commit.stream_position,
                    change_commit.commit_id.clone(),
                )
            } else {
                let last = stream
                    .commits
                    .last()
                    .ok_or_else(|| anyhow!("declared stream is empty"))?;
                (last.stream_position, last.commit_id.clone())
            };
            Ok(CommitStreamHead {
                stream_ref: stream.stream_ref.clone(),
                stream_position: position,
                commit_id,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    final_stream_heads.sort();

    let snapshot_signature =
        authority_signature(DetachedSignatureContext::RealmSnapshot, OLD_AUTHORITY_DID)?;
    let snapshot = RealmStateSnapshot {
        snapshot_id: RealmSnapshotId::from_digest(Sha256::digest(b"cotest-snapshot").into()),
        realm_id: realm_id.clone(),
        governance_generation: 0,
        visible_stream_heads: final_stream_heads.clone(),
        current_state_entries: Vec::new(),
        retention_and_history_floor: RetentionAndHistoryFloor {
            history_access: HistoryAccess::SinceJoin,
            stream_floors: Vec::new(),
        },
        created_at: fixed_time(12),
        signature: snapshot_signature.clone(),
    };

    let handoff = RealmAuthorityHandoff {
        handoff_id: RealmAuthorityHandoffId::from_digest(Sha256::digest(b"cotest-handoff").into()),
        realm_id: realm_id.clone(),
        from_generation: 0,
        to_generation: 1,
        from_service_id: service_id(OLD_AUTHORITY_DID)?,
        to_service_id: service_id(NEW_AUTHORITY_DID)?,
        final_stream_heads_digest: Hash::new(arkret_canonical::canonical_sha256(
            &final_stream_heads,
        )?)?,
        snapshot_ref: snapshot.snapshot_id.clone(),
        snapshot_digest: snapshot_signature.signed_digest.clone(),
        change_event_ref: change_event.event_id.clone(),
        change_commit_id: change_commit.commit_id.clone(),
        old_authority_signature: authority_signature(
            DetachedSignatureContext::RealmAuthorityHandoffOld,
            OLD_AUTHORITY_DID,
        )?,
        new_authority_acceptance_signature: authority_signature(
            DetachedSignatureContext::RealmAuthorityHandoffNewAcceptance,
            NEW_AUTHORITY_DID,
        )?,
    };

    let realm_head = final_stream_heads
        .iter()
        .find(|head| head.stream_ref == realm_stream_ref)
        .cloned()
        .ok_or_else(|| anyhow!("the manifest must include the Realm stream head"))?;

    let current_assertion = RealmAuthorityCurrentAssertion {
        realm_id: realm_id.clone(),
        current_generation: 1,
        current_service_id: service_id(NEW_AUTHORITY_DID)?,
        last_handoff_ref: Some(handoff.handoff_id.clone()),
        realm_stream_head: realm_head.clone(),
        nonce: Base64UrlString::new(NONCE).map_err(anyhow::Error::msg)?,
        expires_at: fixed_time(3600),
        signature: authority_signature(
            DetachedSignatureContext::RealmAuthorityCurrentAssertion,
            NEW_AUTHORITY_DID,
        )?,
    };

    let bundle = RealmAuthorityBundle {
        realm_id: realm_id.clone(),
        genesis_event,
        genesis_commit,
        authority_transitions: vec![RealmAuthorityTransition {
            change_event,
            change_commit,
            handoff: handoff.clone(),
        }],
        current_generation: 1,
        current_service_id: service_id(NEW_AUTHORITY_DID)?,
        current_route_record: json!({ "id": NEW_AUTHORITY_DID }),
        realm_stream_head: realm_head,
        bundle_issued_at: fixed_time(20),
        current_assertion,
    };

    Ok(AuthorityFixture {
        bundle,
        handoff,
        snapshot,
        final_stream_heads,
        realm_id,
        streams,
    })
}

fn genesis_create_event() -> Result<Event> {
    Ok(arkret_wire::test_support::raw_event_for_actor_at(
        EventKind::RealmCreate.as_str(),
        ScopeRef::RealmGenesis,
        producer_actor()?,
        json!({ "cotest_genesis": 1 }),
        fixed_time(0),
    )?)
}

fn service_id(did: &str) -> Result<DidCoreId> {
    Ok(project_did_to_core_id(&arkret_wire::Did::new(
        did.to_owned(),
    )?)?)
}

fn verify_join_bootstrap(fixture: &Value) -> Result<()> {
    let bootstrap = required_field(fixture, "join_bootstrap")?;
    ensure!(
        !required_bool(bootstrap, "locator_is_authority")?,
        "the invite locator is never the bootstrap authority"
    );
    ensure!(
        required_str(bootstrap, "source")? == "current_governance_station",
        "join bootstrap must resolve to the current governance Station"
    );
    ensure!(
        required_bool(bootstrap, "returns_snapshot_and_visible_stream_tails")?,
        "join bootstrap must return a snapshot and the approved stream tails"
    );

    let streams = parse_independent_streams(fixture)?;
    let authority = build_authority_fixture(&streams)?;

    let request = AuthorityBundleRequest {
        realm_id: authority.realm_id.clone(),
        nonce: Base64UrlString::new(NONCE).map_err(anyhow::Error::msg)?,
    };
    authority
        .bundle
        .validate_for_request(&request, fixed_time(30))
        .map_err(|error| anyhow!("a fresh nonce-bound authority bundle must validate: {error}"))?;

    // A cached prefix is not proof that no later handoff exists.
    ensure!(
        authority
            .bundle
            .validate_for_request(&request, fixed_time(7_200))
            .is_err(),
        "an expired current assertion must fail closed"
    );
    let replayed = AuthorityBundleRequest {
        realm_id: authority.realm_id.clone(),
        nonce: Base64UrlString::new("Y290ZXN0LWF1dGhvcml0eS1ub25jZS0y")
            .map_err(anyhow::Error::msg)?,
    };
    ensure!(
        authority
            .bundle
            .validate_for_request(&replayed, fixed_time(30))
            .is_err(),
        "a bundle bound to another nonce must not satisfy this request"
    );

    // The invite-side locator cannot substitute itself for the chain's end.
    let mut inviter_claims_authority = authority.bundle.clone();
    inviter_claims_authority.current_service_id = service_id(OLD_AUTHORITY_DID)?;
    ensure!(
        inviter_claims_authority.validate_shape().is_err(),
        "the original governance service must not remain current after a handoff"
    );

    let mut broken_chain = authority.bundle.clone();
    broken_chain.authority_transitions.clear();
    ensure!(
        broken_chain.validate_shape().is_err(),
        "a bundle whose handoff chain does not reach current_generation must be rejected"
    );

    verify_snapshot_and_tails_are_complete(&authority)?;
    Ok(())
}

/// The snapshot names every approved stream head, and each tail scan must reach
/// exactly that head with no gap.
fn verify_snapshot_and_tails_are_complete(authority: &AuthorityFixture) -> Result<()> {
    let streams = &authority.streams;
    ensure!(
        authority.snapshot.visible_stream_heads.len() == streams.len(),
        "the snapshot must bind every approved stream head"
    );

    let store = MemoryAuthorityCommitStore::default();
    let mut nonce = 140_u8;
    for stream in streams {
        for declared in &stream.commits {
            nonce += 1;
            let event = producer_event(stream, nonce)?;
            let commit = commit_for(stream, declared, &event, 0, OLD_AUTHORITY_DID)?;
            store
                .append(&event, commit)
                .map_err(|error| anyhow!("commit rejected while seeding tails: {error}"))?;
        }
    }

    for stream in streams {
        let head = store
            .stream_head(&stream.stream_ref)
            .ok_or_else(|| anyhow!("seeded stream has no head"))?;
        let request = StreamScanRequest {
            realm_id: stream.realm_id.clone(),
            stream_ref: stream.stream_ref.clone(),
            direction: arkret_wire::StreamScanDirection::After(None),
            limit: 1000,
        };
        let outcome = store
            .scan(&request)
            .map_err(|error| anyhow!("tail scan failed: {error}"))?;
        outcome
            .validate_for_request(&request)
            .map_err(|error| anyhow!("tail is not a verifiable contiguous chain: {error}"))?;
        let last = outcome
            .committed_events
            .last()
            .ok_or_else(|| anyhow!("an approved tail must not be empty"))?;
        ensure!(
            last.commit().commit_id == head.commit_id
                && last.commit().stream_position == head.stream_position,
            "the tail must reach the head the snapshot binds"
        );
    }
    Ok(())
}

// ── Verdict 7: planned handoff, and no writes from the old authority ────────

fn verify_handoff(fixture: &Value) -> Result<()> {
    let manifest = required_field(fixture, "handoff_private_manifest")?;
    let head_count = required_u64(manifest, "head_count")?;
    let public_head_count = required_u64(manifest, "public_bundle_head_count")?;
    ensure!(
        required_bool(manifest, "new_generation_first_commit_uses_imported_head")?,
        "the new generation must continue each imported stream head"
    );
    ensure!(
        public_head_count == 1 && head_count > public_head_count,
        "the public bundle exposes only the Realm head while the private manifest carries all"
    );

    let streams = parse_independent_streams(fixture)?;
    let authority = build_authority_fixture(&streams)?;
    ensure!(
        authority.final_stream_heads.len() == usize::try_from(head_count)?,
        "the private manifest must carry exactly the declared head count"
    );

    let request = arkret_wire::AuthorityHandoffRequest {
        handoff: authority.handoff.clone(),
        final_stream_heads: authority.final_stream_heads.clone(),
        snapshot: authority.snapshot.clone(),
        authority_bundle: authority.bundle.clone(),
    };
    request
        .validate_shape()
        .map_err(|error| anyhow!("a planned handoff must validate: {error}"))?;

    // Dropping a private head changes the manifest digest the handoff signed.
    let mut truncated = request.clone();
    truncated.final_stream_heads.pop();
    ensure!(
        truncated.validate_shape().is_err(),
        "a manifest missing an approved stream head must be rejected"
    );

    // Generations must be consecutive, and neither side may sign for the other.
    let mut skipped = authority.handoff.clone();
    skipped.to_generation = authority.handoff.from_generation + 2;
    ensure!(
        skipped.validate_shape().is_err(),
        "handoff generations must be consecutive"
    );
    let mut misattributed = authority.handoff.clone();
    misattributed.new_authority_acceptance_signature = authority_signature(
        DetachedSignatureContext::RealmAuthorityHandoffNewAcceptance,
        OLD_AUTHORITY_DID,
    )?;
    ensure!(
        misattributed.validate_shape().is_err(),
        "the incoming authority must sign its own acceptance"
    );

    verify_old_authority_writes_are_rejected(&authority)?;
    verify_new_generation_continues_imported_heads(&authority)?;
    Ok(())
}

/// After the handoff takes effect, the pre-handoff generation can no longer
/// produce a commit a consumer will accept for this Realm.
fn verify_old_authority_writes_are_rejected(authority: &AuthorityFixture) -> Result<()> {
    let realm_stream = authority
        .streams
        .iter()
        .find(|stream| matches!(stream.stream_ref, CommitStreamRef::Realm { .. }))
        .ok_or_else(|| anyhow!("the fixture must declare a Realm stream"))?;
    let head = authority
        .final_stream_heads
        .iter()
        .find(|head| head.stream_ref == realm_stream.stream_ref)
        .ok_or_else(|| anyhow!("the manifest must include the Realm head"))?;

    let event = signed_event(producer_event(realm_stream, 151)?)?;
    let late_write = RealmCommit {
        commit_id: bind_declared_commit_id("cotest-old-authority-late-write"),
        realm_id: authority.realm_id.clone(),
        stream_ref: realm_stream.stream_ref.clone(),
        stream_position: head.stream_position + 1,
        previous_commit_ref: Some(head.commit_id.clone()),
        event_ref: event.event_id.clone(),
        governance_generation: authority.handoff.from_generation,
        authority_ref: RealmCommitAuthorityRef::Handoff(authority.handoff.handoff_id.clone()),
        committed_at: fixed_time(60),
        signature: authority_signature(DetachedSignatureContext::RealmCommit, OLD_AUTHORITY_DID)?,
    };

    ensure!(
        commit_governance_generation_is_current(&authority.bundle, &late_write).is_err(),
        "a commit signed by the superseded generation must be rejected after handoff"
    );

    let accepted = RealmCommit {
        governance_generation: authority.bundle.current_generation,
        signature: authority_signature(DetachedSignatureContext::RealmCommit, NEW_AUTHORITY_DID)?,
        ..late_write
    };
    commit_governance_generation_is_current(&authority.bundle, &accepted).map_err(|error| {
        anyhow!("the incoming authority's own commit must be accepted: {error}")
    })?;
    Ok(())
}

/// The §6 step-1 check: the commit's generation and signing service must be the
/// ones the genesis-plus-handoff chain currently authorizes.
fn commit_governance_generation_is_current(
    bundle: &RealmAuthorityBundle,
    commit: &RealmCommit,
) -> Result<()> {
    bundle
        .validate_shape()
        .map_err(|error| anyhow!("authority bundle is invalid: {error}"))?;
    ensure!(
        commit.realm_id == bundle.realm_id,
        "commit belongs to another Realm"
    );
    ensure!(
        commit.governance_generation == bundle.current_generation,
        "commit governance generation {} is not the current generation {}",
        commit.governance_generation,
        bundle.current_generation
    );
    let signing_service = commit
        .signature
        .verification_method
        .as_str()
        .split_once('#')
        .map(|(controller, _)| controller.to_owned())
        .ok_or_else(|| anyhow!("commit signature needs a verification method fragment"))?;
    ensure!(
        service_id(&signing_service)? == bundle.current_service_id,
        "commit was not signed by the current governance Station"
    );
    Ok(())
}

fn verify_new_generation_continues_imported_heads(authority: &AuthorityFixture) -> Result<()> {
    for stream in &authority.streams {
        let head = authority
            .final_stream_heads
            .iter()
            .find(|head| head.stream_ref == stream.stream_ref)
            .ok_or_else(|| anyhow!("the manifest must carry every stream head"))?;
        let event = producer_event(stream, 161)?;
        let first = RealmCommit {
            commit_id: bind_declared_commit_id(&format!(
                "cotest-new-generation-first-{}",
                head.stream_position
            )),
            realm_id: stream.realm_id.clone(),
            stream_ref: stream.stream_ref.clone(),
            stream_position: head.stream_position + 1,
            previous_commit_ref: Some(head.commit_id.clone()),
            event_ref: event.event_id.clone(),
            governance_generation: authority.bundle.current_generation,
            authority_ref: RealmCommitAuthorityRef::Handoff(authority.handoff.handoff_id.clone()),
            committed_at: fixed_time(70),
            signature: authority_signature(
                DetachedSignatureContext::RealmCommit,
                NEW_AUTHORITY_DID,
            )?,
        };
        first
            .validate_shape()
            .map_err(|error| anyhow!("the new generation's first commit is malformed: {error}"))?;
        ensure!(
            first.previous_commit_ref.as_ref() == Some(&head.commit_id),
            "the new generation must continue from the imported head of that stream"
        );

        let mut restarted = first;
        restarted.stream_position = 0;
        restarted.previous_commit_ref = None;
        ensure!(
            restarted.validate_shape().is_ok(),
            "a position-0 commit is structurally valid in isolation"
        );
        ensure!(
            restarted.previous_commit_ref != Some(head.commit_id.clone()),
            "a restarted stream cannot claim the imported head"
        );
    }
    Ok(())
}

// ── Verdict 8: MLS Commit and Welcome deliveries share one transaction ──────

fn verify_mls_atomic_submission(fixture: &Value) -> Result<()> {
    let atomic = required_field(fixture, "mls_atomic_submission")?;
    ensure!(
        required_bool(atomic, "commit_and_welcomes_share_one_transaction")?,
        "the MLS Commit and its Welcome deliveries share one transaction"
    );
    ensure!(
        required_bool(atomic, "missing_welcome_writes_nothing")?,
        "an invalid Welcome must leave zero writes"
    );

    let streams = parse_independent_streams(fixture)?;
    let circle_stream = streams
        .iter()
        .find(|stream| matches!(stream.stream_ref, CommitStreamRef::Circle { .. }))
        .ok_or_else(|| anyhow!("the fixture must declare a Circle stream"))?;

    let commit_event = signed_event(arkret_wire::test_support::raw_event_for_actor_at(
        EventKind::MlsCommit.as_str(),
        circle_stream.scope_ref.clone(),
        producer_actor()?,
        json!({ "cotest_mls_commit": 1 }),
        fixed_time(80),
    )?)?;

    let welcomes = vec![
        welcome_delivery(circle_stream, &commit_event, 1)?,
        welcome_delivery(circle_stream, &commit_event, 2)?,
    ];
    let submission = MlsCommitSubmission {
        commit_event: commit_event.clone(),
        welcomes: welcomes.clone(),
        idempotency_key: idempotency_key()?,
    };
    submission
        .validate()
        .map_err(|error| anyhow!("a well-formed MLS commit submission must validate: {error}"))?;

    // A Welcome bound to another Commit, an out-of-order list, and a Welcome in
    // another scope each invalidate the whole submission.
    let mut rebound = submission.clone();
    rebound.welcomes[1].commit_event_ref = EventId::from_digest(DigestSuite::Sha256, [0x47; 32]);
    ensure!(
        rebound.validate().is_err(),
        "a Welcome must bind the exact submitted Commit Event"
    );

    let mut unsorted = submission.clone();
    unsorted.welcomes.swap(0, 1);
    ensure!(
        unsorted.validate().is_err(),
        "Welcome deliveries must be sorted and unique by welcome_id"
    );

    let realm_stream = streams
        .iter()
        .find(|stream| matches!(stream.stream_ref, CommitStreamRef::Realm { .. }))
        .ok_or_else(|| anyhow!("the fixture must declare a Realm stream"))?;
    let mut cross_scope = submission.clone();
    cross_scope.welcomes[1].effective_scope = realm_stream.scope_ref.clone();
    ensure!(
        cross_scope.validate().is_err(),
        "a Welcome must live in the Commit's own effective scope"
    );

    let mut wrong_context = submission.clone();
    wrong_context.welcomes[1].producer_proof =
        authority_signature(DetachedSignatureContext::RealmCommit, PRODUCER_DID)?;
    ensure!(
        wrong_context.validate().is_err(),
        "a Welcome delivery needs its own producer signature context"
    );

    verify_invalid_welcome_writes_nothing(circle_stream, &submission, &rebound)?;
    verify_welcome_carries_no_recipient_ack(&welcomes[0])?;
    verify_welcome_is_not_an_event(&welcomes[0])?;
    Ok(())
}

fn welcome_delivery(
    stream: &DeclaredStream,
    commit_event: &Event,
    ordinal: u8,
) -> Result<MlsWelcomeDelivery> {
    Ok(MlsWelcomeDelivery {
        welcome_id: MlsWelcomeDeliveryId::new(format!(
            "ak:mls_welcome_delivery:019a8400-0000-7000-8000-00000000000{ordinal}"
        ))
        .map_err(|error| anyhow!("welcome id is not a typed producer-allocated id: {error}"))?,
        realm_id: stream.realm_id.clone(),
        effective_scope: stream.scope_ref.clone(),
        commit_event_ref: commit_event.event_id.clone(),
        recipient_actor_id: producer_actor()?,
        recipient_endpoint: MlsWelcomeRecipientEndpoint::Device {
            device_id: arkret_wire::DeviceId::new(format!(
                "ak:device:019a8400-0000-7000-8000-00000000010{ordinal}"
            ))
            .map_err(|error| anyhow!("device id is not typed: {error}"))?,
        },
        keypackage_claim_ref: KeypackageClaimId::new(format!(
            "ak:keypackage_claim:019a8400-0000-7000-8000-00000000020{ordinal}"
        ))
        .map_err(|error| anyhow!("keypackage claim id is not typed: {error}"))?,
        ciphertext_b64: Base64UrlString::new("d2VsY29tZQ").map_err(anyhow::Error::msg)?,
        producer_proof: authority_signature(
            DetachedSignatureContext::MlsWelcomeDelivery,
            PRODUCER_DID,
        )?,
    })
}

fn idempotency_key() -> Result<UuidV7> {
    UuidV7::new(
        "019a8400-0000-7000-8000-0000000003a1"
            .parse()
            .map_err(|error| anyhow!("idempotency key is not a UUID: {error}"))?,
    )
    .map_err(|error| anyhow!("idempotency key is not a UUIDv7: {error}"))
}

/// A rejected submission must leave the Commit stream exactly as it was: the
/// Commit Event is never appended when one Welcome is invalid.
fn verify_invalid_welcome_writes_nothing(
    stream: &DeclaredStream,
    valid: &MlsCommitSubmission,
    invalid: &MlsCommitSubmission,
) -> Result<()> {
    let store = MemoryAuthorityCommitStore::default();
    ensure!(
        submit_mls_commit(&store, stream, invalid, 0).is_err(),
        "an invalid MLS submission must not reach the commit store"
    );
    ensure!(
        store.stream_head(&stream.stream_ref).is_none(),
        "a rejected MLS submission must leave zero writes"
    );

    submit_mls_commit(&store, stream, valid, 0)
        .map_err(|error| anyhow!("a valid MLS submission must commit: {error}"))?;
    let head = store
        .stream_head(&stream.stream_ref)
        .ok_or_else(|| anyhow!("a committed MLS submission must advance the stream"))?;
    ensure!(
        head.stream_position == 0,
        "the first MLS commit opens its own stream at position 0"
    );
    Ok(())
}

fn submit_mls_commit(
    store: &MemoryAuthorityCommitStore,
    stream: &DeclaredStream,
    submission: &MlsCommitSubmission,
    position: u64,
) -> Result<()> {
    let request = AuthoritySubmitRequest::MlsCommit(submission.clone());
    request
        .validate()
        .map_err(|error| anyhow!("MLS submission rejected before any write: {error}"))?;
    let commit = RealmCommit {
        commit_id: bind_declared_commit_id(&format!("cotest-mls-commit-{position}")),
        realm_id: stream.realm_id.clone(),
        stream_ref: stream.stream_ref.clone(),
        stream_position: position,
        previous_commit_ref: None,
        event_ref: submission.commit_event.event_id.clone(),
        governance_generation: 0,
        authority_ref: RealmCommitAuthorityRef::GenesisOrChangeEvent(
            submission.commit_event.event_id.clone(),
        ),
        committed_at: fixed_time(81),
        signature: authority_signature(DetachedSignatureContext::RealmCommit, OLD_AUTHORITY_DID)?,
    };
    let outcome = AuthoritySubmitOutcome::Accepted {
        status: arkret_wire::AuthorityCommitStatus::Committed,
        commit: commit.clone(),
    };
    outcome
        .validate_for_request(&request)
        .map_err(|error| anyhow!("outcome does not commit the submitted Event: {error}"))?;
    store
        .append(&submission.commit_event, commit)
        .map_err(|error| anyhow!("commit store rejected the MLS commit: {error}"))?;
    Ok(())
}

/// The sender installs staged state once the transaction succeeds; the delivery
/// object carries no recipient acknowledgement member to wait on.
fn verify_welcome_carries_no_recipient_ack(welcome: &MlsWelcomeDelivery) -> Result<()> {
    let encoded = serde_json::to_value(welcome)?;
    let members = encoded
        .as_object()
        .ok_or_else(|| anyhow!("a Welcome delivery must serialize as an object"))?;
    for forbidden in [
        "ack",
        "acked",
        "ack_required",
        "awaiting_ack",
        "delivery_receipt",
        "recipient_ack",
    ] {
        ensure!(
            !members.contains_key(forbidden),
            "a Welcome delivery must not carry {forbidden}"
        );
        let mut tampered = encoded.clone();
        tampered
            .as_object_mut()
            .ok_or_else(|| anyhow!("tampered Welcome is not an object"))?
            .insert(forbidden.to_owned(), json!(true));
        ensure!(
            serde_json::from_value::<MlsWelcomeDelivery>(tampered).is_err(),
            "a Welcome delivery must reject {forbidden}"
        );
    }
    Ok(())
}

/// A Welcome is a recipient delivery object, not a shared Event.
fn verify_welcome_is_not_an_event(welcome: &MlsWelcomeDelivery) -> Result<()> {
    ensure!(
        welcome
            .welcome_id
            .as_str()
            .starts_with("ak:mls_welcome_delivery:"),
        "a Welcome delivery carries its own typed id"
    );
    let encoded = serde_json::to_value(welcome)?;
    ensure!(
        serde_json::from_value::<Event>(encoded).is_err(),
        "a Welcome delivery must not parse as a shared Event"
    );
    Ok(())
}

// ── Verdict 10: MLS activation is irreversible ─────────────────────────────

fn verify_mls_activation_is_irreversible() -> Result<()> {
    const GROUP: &str = "ak:mls_group:cotest-activated-scope";
    const OTHER_GROUP: &str = "ak:mls_group:cotest-other-scope";

    // Before the scope's own accepted ak.mls.genesis, plaintext is legal.
    validate_scope_mls_activation(None, false)
        .map_err(|error| anyhow!("a plaintext scope must accept plaintext writes: {error}"))?;
    validate_scope_mls_activation(Some(GROUP), true)
        .map_err(|error| anyhow!("an activated scope must accept MLS writes: {error}"))?;

    let plaintext_after_activation = validate_scope_mls_activation(Some(GROUP), false)
        .err()
        .ok_or_else(|| anyhow!("a plaintext write into an activated scope must be rejected"))?;
    ensure!(
        matches!(
            plaintext_after_activation,
            CircleScopeError::MlsActivationRequired
        ),
        "the rejection must be mls_activation_required"
    );
    ensure!(
        plaintext_after_activation
            .to_string()
            .contains(ReasonCode::MLS_ACTIVATION_REQUIRED),
        "the reason text must name the generated mls_activation_required code"
    );

    validate_mls_activation_is_irreversible(None, Some(GROUP))
        .map_err(|error| anyhow!("first activation must be allowed: {error}"))?;
    validate_mls_activation_is_irreversible(Some(GROUP), Some(GROUP))
        .map_err(|error| anyhow!("an unchanged activation must be allowed: {error}"))?;

    for (previous, next) in [(Some(GROUP), None), (Some(GROUP), Some(OTHER_GROUP))] {
        let error = validate_mls_activation_is_irreversible(previous, next)
            .err()
            .ok_or_else(|| anyhow!("an accepted activation must not be cleared or replaced"))?;
        ensure!(
            matches!(error, CircleScopeError::MlsActivationIrreversible),
            "the rejection must be mls_activation_irreversible"
        );
        ensure!(
            error
                .to_string()
                .contains(ReasonCode::MLS_ACTIVATION_IRREVERSIBLE),
            "the reason text must name the generated mls_activation_irreversible code"
        );
    }
    Ok(())
}

// ── Verdict 11: recovery completes on two consecutive PCR commits ───────────

fn verify_recovery_completion_is_two_consecutive_commits() -> Result<()> {
    let realm_id = RealmId::from_event_id(&EventId::from_digest(DigestSuite::Sha256, [0x48; 32]));
    let realm_stream = CommitStreamRef::Realm {
        realm_id: realm_id.clone(),
    };
    let circle_stream = CommitStreamRef::Circle {
        realm_id: realm_id.clone(),
        circle_id: CircleId::from_event_id(&EventId::from_digest(DigestSuite::Sha256, [0x49; 32])),
    };

    let reanchor = committed_ref(&realm_stream, 7, 0x50);
    let authorization = committed_ref(&realm_stream, 8, 0x51);
    recovery_attestation(&reanchor, &authorization)
        .map_err(|error| anyhow!("two consecutive PCR Realm commits must complete: {error}"))?;

    let cases: [(CommittedEventRef, CommittedEventRef, &str); 4] = [
        (
            reanchor.clone(),
            committed_ref(&realm_stream, 7, 0x52),
            "the same position is not a successor",
        ),
        (
            reanchor.clone(),
            committed_ref(&realm_stream, 9, 0x53),
            "a gap of two positions is not consecutive",
        ),
        (
            reanchor.clone(),
            committed_ref(&circle_stream, 8, 0x54),
            "the pair must live in one stream",
        ),
        (
            committed_ref(&circle_stream, 7, 0x55),
            committed_ref(&circle_stream, 8, 0x56),
            "recovery completes only in the PCR Realm stream",
        ),
    ];
    for (first, second, why) in cases {
        ensure!(
            recovery_attestation(&first, &second).is_err(),
            "recovery completion must reject this pair: {why}"
        );
    }
    Ok(())
}

fn committed_ref(stream_ref: &CommitStreamRef, position: u64, seed: u8) -> CommittedEventRef {
    CommittedEventRef {
        event_id: EventId::from_digest(DigestSuite::Sha256, [seed; 32]),
        commit_id: RealmCommitId::from_digest([seed; 32]),
        stream_ref: stream_ref.clone(),
        stream_position: position,
    }
}

fn recovery_attestation(
    reanchor_ref: &CommittedEventRef,
    device_authorization_ref: &CommittedEventRef,
) -> Result<()> {
    let body = arkret_wire::UnsignedRecoveryCompletionAttestationBody {
        transaction_id: arkret_wire::TransactionId::new(
            "ak:transaction:019a8400-0000-7000-8000-000000000401".to_owned(),
        )
        .map_err(anyhow::Error::msg)?,
        transaction_request_digest: Hash::new(format!("sha256:{}", "33".repeat(32)))?,
        prepared_plan_digest: Hash::new(format!("sha256:{}", "44".repeat(32)))?,
        account_id: arkret_wire::AccountId::new(
            service_id(PRODUCER_DID)?,
            service_id(OLD_AUTHORITY_DID)?,
        ),
        recovery_session_id: arkret_wire::RecoverySessionId::new(
            "ak:recovery_session:019a8400-0000-7000-8000-000000000402".to_owned(),
        )
        .map_err(anyhow::Error::msg)?,
        terminal_receipt_id: arkret_wire::ReceiptId::new(
            "ak:receipt:019a8400-0000-7000-8000-000000000403".to_owned(),
        )
        .map_err(anyhow::Error::msg)?,
        terminal_receipt_digest: Hash::new(format!("sha256:{}", "55".repeat(32)))?,
        replacement_device_id: arkret_wire::DeviceId::new(
            "ak:device:019a8400-0000-7000-8000-000000000404".to_owned(),
        )
        .map_err(anyhow::Error::msg)?,
        reanchor_event_ref: reanchor_ref.clone(),
        device_authorization_event_ref: device_authorization_ref.clone(),
        result_model_generation_ref: 1,
        completed_at: fixed_time(90),
    };
    arkret_wire::UnsignedRecoveryCompletionAttestation::new(
        body,
        DidUrl::new(format!("{OLD_AUTHORITY_DID}#key-1")).map_err(anyhow::Error::msg)?,
    )
    .map_err(|error| anyhow!("{error}"))?;
    Ok(())
}
