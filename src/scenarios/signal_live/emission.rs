//! Actual encrypted frames paused after recipient key resolution, before the
//! shared final gate. The positive release excludes a probe-only false green.

use std::path::Path;
use std::time::Duration;

use arkret_wire::{EventKind, SignalDeliveryAuthority};

use super::*;
use crate::harness::ArkretServer;
use crate::scenarios::_helpers::acceptance_footprint::acceptance_rows;
use crate::scenarios::human_device_producer_live::{membership_payload, submit_and_expect_commit};

#[derive(Clone, Copy, Debug)]
pub(crate) enum Boundary {
    Leave,
    Ban,
    Tombstone,
}

enum Rail {
    Http(arkret_http_client::SignalSubscribeFrameStream),
    WebSocket(Box<super::super::websocket_live::LiveSignalReader>),
}

impl Rail {
    async fn next(&mut self) -> Result<Option<SignalStreamFrame>> {
        match self {
            Self::Http(stream) => Ok(stream.next_frame().await?),
            Self::WebSocket(stream) => stream.next_frame().await,
        }
    }

    async fn quiet(&mut self) -> Result<()> {
        let result = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                match self.next().await?.context("recipient rail remains open")? {
                    SignalStreamFrame::Heartbeat => {}
                    frame => {
                        break Err::<(), _>(anyhow::anyhow!(
                            "closed authority emitted a live frame: {frame:?}"
                        ));
                    }
                }
            }
        })
        .await;
        match result {
            Err(_) => Ok(()),
            Ok(result) => result,
        }
    }
}

fn arm(path: &Path, signal: &SignalEnvelope) -> Result<()> {
    for extension in ["reached.json", "outcome.json"] {
        match std::fs::remove_file(path.with_extension(extension)) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    std::fs::write(path, signal.envelope_digest()?.as_str())?;
    Ok(())
}

fn retain_observation(path: &Path, boundary: Boundary, phase: &str) -> Result<()> {
    let Some(root) = std::env::var_os("COTEST_SERVICE_LOG_DIR") else {
        return Ok(());
    };
    let root = std::path::PathBuf::from(root).join(format!("signal-emission-{boundary:?}"));
    std::fs::create_dir_all(&root)?;
    for extension in ["reached.json", "outcome.json"] {
        std::fs::copy(
            path.with_extension(extension),
            root.join(format!("{phase}-{extension}")),
        )?;
    }
    Ok(())
}

async fn observation(path: &Path) -> Result<serde_json::Value> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        match tokio::fs::read(path).await {
            Ok(bytes) => {
                // A concurrent small file write may not yet have completed.
                if let Ok(value) = serde_json::from_slice(&bytes) {
                    return Ok(value);
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        ensure!(
            tokio::time::Instant::now() < deadline,
            "emission observation missing: {}",
            path.display()
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn reached(path: &Path, signal: &SignalEnvelope) -> Result<()> {
    let exact: SignalEnvelope =
        serde_json::from_value(observation(&path.with_extension("reached.json")).await?)?;
    ensure!(
        arkret_canonical::canonical_json_bytes(&exact)?
            == arkret_canonical::canonical_json_bytes(signal)?,
        "the actual pending frame is the complete original ciphertext"
    );
    ensure!(
        Utc::now() + chrono::Duration::seconds(8) < signal.expires_at,
        "queued frame has enough original TTL for the authority change"
    );
    Ok(())
}

async fn outcome(path: &Path, signal: &SignalEnvelope, admitted: bool) -> Result<()> {
    let observed = observation(&path.with_extension("outcome.json")).await?;
    ensure!(observed["envelope_digest"] == signal.proof.envelope_digest.as_str());
    ensure!(
        observed["admitted"] == admitted,
        "actual final gate decision: {observed}"
    );
    let decided_at = chrono::DateTime::parse_from_rfc3339(
        observed["observed_at"]
            .as_str()
            .context("gate observation time")?,
    )?;
    ensure!(
        decided_at < signal.expires_at
            && Utc::now() + chrono::Duration::seconds(3) < signal.expires_at,
        "the denial is before TTL expiry"
    );
    if !admitted {
        ensure!(
            observed["error_code"] == "signal_class_denied",
            "membership/lifecycle gate, not timeout or malformed proof: {observed}"
        );
    }
    Ok(())
}

#[expect(
    clippy::too_many_arguments,
    reason = "Exact sender, recipient and MLS binding"
)]
fn verify_plaintext(
    sender: &Member,
    receiver: &Member,
    group: &ArkretMlsGroup,
    signal: &SignalEnvelope,
    authority: &SignalDeliveryAuthority,
    state: &EventId,
    head: &RealmCommitId,
    sequence: u64,
) -> Result<()> {
    authority.validate_for_envelope(signal)?;
    ensure!(authority.recipient_account_id == receiver.account);
    ensure!(
        authority.key.actor == sender.actor
            && authority.key.authorization_ref == sender.authorize_event_id
    );
    let bytes = arkret_canonical::base64url_decode(authority.key.public_key_b64u.as_str())?;
    ensure!(bytes == sender.key.verifying_key().to_bytes());
    let public = arkret_signatures::PublicKeyMaterial::Ed25519Raw { bytes };
    let plaintext = group.open_signal_envelope(
        signal,
        SignalSenderAuthority::AccountDevice {
            public_key: &public,
            device_authorize_event_id: &authority.key.authorization_ref,
        },
        state.as_str(),
        head,
        &mut arkret::AeadNonceReplayTracker::default(),
    )?;
    let payload = arkret_models_collaboration::signal_plaintext::open_signal_plaintext(&plaintext)?;
    ensure!(
        payload.signal_class() == SignalClass::Session && payload.payload_sequence() == sequence
    );
    Ok(())
}

async fn transition(
    alice: &Member,
    bob: &Member,
    realm: &RealmId,
    boundary: Boundary,
) -> Result<arkret_wire::RealmCommit> {
    use arkret_models_collaboration::governance::membership_invite::MembershipPayloadState;
    use arkret_models_collaboration::governance::realm_lifecycle::RealmTombstonePayload;
    let (author, kind, payload) = match boundary {
        Boundary::Leave => (
            bob,
            EventKind::MemberState,
            membership_payload(
                realm.as_str(),
                bob.account.clone(),
                MembershipPayloadState::Leave,
                "Signal emission departure",
            )?,
        ),
        Boundary::Ban => (
            alice,
            EventKind::MemberState,
            membership_payload(
                realm.as_str(),
                bob.account.clone(),
                MembershipPayloadState::Ban,
                "Signal emission ban",
            )?,
        ),
        Boundary::Tombstone => {
            let successor = alice
                .client
                .create_realm("Signal terminal successor")
                .await?;
            (
                alice,
                EventKind::RealmTombstone,
                RealmTombstonePayload::new(RealmId::new(successor)?, "migration").to_value()?,
            )
        }
    };
    let event = author
        .client
        .author_event(realm.as_str(), kind.as_str(), payload)
        .await?;
    submit_and_expect_commit(
        &author.client,
        &author.account,
        author.device.as_str(),
        &event,
    )
    .await
}

#[expect(
    clippy::too_many_arguments,
    reason = "Exact actual MLS and Station fixture bindings"
)]
pub(super) async fn exercise(
    alice: &Member,
    bob: &Member,
    alice_group: &mut ArkretMlsGroup,
    bob_group: &ArkretMlsGroup,
    realm: &RealmId,
    strand: &str,
    state: &EventId,
    head: &RealmCommitId,
    x: &ArkretServer,
    y: &ArkretServer,
    urls: &[&str; 2],
    pause_file: &Path,
    boundary: Boundary,
) -> Result<()> {
    let websocket = matches!(boundary, Boundary::Tombstone);
    let mut rail = if websocket {
        Rail::WebSocket(Box::new(
            super::super::websocket_live::LiveSignalReader::connect(y, &bob.client, realm.as_str())
                .await?,
        ))
    } else {
        Rail::Http(bob.client.sdk().signal_subscribe_frames().await?)
    };
    ensure!(matches!(
        rail.next().await?,
        Some(SignalStreamFrame::Heartbeat)
    ));

    // The same pause/resume mechanism must successfully emit and decrypt a
    // qualifying frame while governance remains live.
    let control = envelope(
        alice,
        alice_group,
        realm,
        strand,
        state,
        head,
        SignalClass::Session,
        20,
    )?;
    arm(pause_file, &control)?;
    ensure!(alice.client.sdk().signal_send(&control).await?.accepted);
    reached(pause_file, &control).await?;
    std::fs::remove_file(pause_file)?;
    outcome(pause_file, &control, true).await?;
    retain_observation(pause_file, boundary, "control")?;
    let (received, authority) = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match rail.next().await?.context("positive resumed rail open")? {
                SignalStreamFrame::Heartbeat => {}
                SignalStreamFrame::Signal {
                    envelope,
                    delivery_authority,
                } => break Ok::<_, anyhow::Error>((envelope, delivery_authority)),
                frame => anyhow::bail!("unexpected positive control: {frame:?}"),
            }
        }
    })
    .await??;
    ensure!(received == control);
    verify_plaintext(
        alice, bob, bob_group, &received, &authority, state, head, 20,
    )?;

    let queued = envelope(
        alice,
        alice_group,
        realm,
        strand,
        state,
        head,
        SignalClass::Session,
        21,
    )?;
    let delayed = envelope(
        alice,
        alice_group,
        realm,
        strand,
        state,
        head,
        SignalClass::Session,
        22,
    )?;
    // Prove both negative candidates are real, decryptable MLS plaintexts.
    verify_plaintext(alice, bob, bob_group, &queued, &authority, state, head, 21)?;
    verify_plaintext(alice, bob, bob_group, &delayed, &authority, state, head, 22)?;
    ensure!(queued.envelope_digest()? != delayed.envelope_digest()?);
    arm(pause_file, &queued)?;
    let before = [counts(urls[0], realm).await?, counts(urls[1], realm).await?];
    ensure!(alice.client.sdk().signal_send(&queued).await?.accepted);
    reached(pause_file, &queued).await?;
    for (index, url) in urls.iter().enumerate() {
        let after = counts(url, realm).await?;
        ensure!(
            after[0..2] == before[index][0..2] && after[2] == before[index][2] + 1,
            "exact queued envelope traversed self and peer durable transient rails"
        );
    }
    let commit = transition(alice, bob, realm, boundary).await?;
    wait_for_replica_cut(urls[1], &commit).await?;
    let url = urls[1].to_owned();
    let id = commit.commit_id.to_string();
    let held: arkret_wire::RealmCommit = tokio::task::spawn_blocking(move || -> Result<_> {
        let mut conn = postgres::Client::connect(&url, postgres::NoTls)?;
        Ok(serde_json::from_value(
            conn.query_one(
                "SELECT commit_json FROM realm_commits WHERE commit_id=$1",
                &[&id],
            )?
            .get(0),
        )?)
    })
    .await??;
    ensure!(
        held == commit,
        "recipient installed the exact source transition before release"
    );
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let url = urls[0].to_owned();
        let event = commit.event_ref.to_string();
        let complete = tokio::task::spawn_blocking(move || -> Result<bool> {
            let mut conn = postgres::Client::connect(&url, postgres::NoTls)?;
            let row = conn.query_one("SELECT count(*) FROM federation_outbox WHERE realm_fanout->'source_event_ids' ? $1 AND state != 'delivered'", &[&event])?;
            Ok(row.get::<_, i64>(0) == 0)
        }).await??;
        if complete {
            break;
        }
        ensure!(
            tokio::time::Instant::now() < deadline,
            "source marks actual transition delivery before zero-effect observations"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let snapshots = [
        acceptance_rows(urls[0]).await?,
        acceptance_rows(urls[1]).await?,
    ];
    let closed = [counts(urls[0], realm).await?, counts(urls[1], realm).await?];
    std::fs::remove_file(pause_file)?;
    outcome(pause_file, &queued, false).await?;
    retain_observation(pause_file, boundary, "closed")?;
    rail.quiet().await?;
    ensure!(Utc::now() + chrono::Duration::seconds(3) < delayed.expires_at);
    deny_peer(&delayed, x, y, urls).await?;
    ensure!(
        Utc::now() < delayed.expires_at,
        "delayed peer refusal completed before the original TTL expired"
    );
    rail.quiet().await?;
    for (index, url) in urls.iter().enumerate() {
        ensure!(
            counts(url, realm).await? == closed[index],
            "no new Event, Commit or relay position after eligibility closed"
        );
        ensure!(
            acceptance_rows(url).await? == snapshots[index],
            "frame denial and delayed peer ingress have zero acceptance footprint at Station {index}"
        );
    }
    if let Rail::WebSocket(rail) = &mut rail {
        rail.finish().await?;
    }
    eprintln!(
        "[signal-emission] boundary={boundary:?} transport={} paused_positive_frame_decrypted=1 exact_queued_frame=1 final_gate_denied_before_ttl=1 delayed_signed_peer_opaque_drop=1 acceptance_rows_unchanged=2",
        if websocket { "websocket" } else { "http" }
    );
    Ok(())
}
