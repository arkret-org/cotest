//! DID-P1-C02 — the joint call-count contract, read off soland's DID-boundary
//! counters.
//!
//! `zh/identity/did-usage-and-verification.md` §6 makes two claims that are
//! easy to state and easy to fake: ordinary business verifies **every** object's
//! signature, and ordinary business performs **no** per-object online DID
//! resolution. Those are two independent counters, and this module asserts on
//! both at once for every scenario, exactly as the task requires:
//!
//! | name | series |
//! | --- | --- |
//! | `authority_network_call_count` | `soland_did_resolve_total{source="network"}` |
//! | `signature_verify_count` | `soland_signature_verify_total` (all labels) |
//!
//! Asserting only the first would pass trivially for a server that skipped
//! verification altogether; asserting only the second would pass for a server
//! that resolved a DID per Event. The pair is the contract.
//!
//! # Why a metrics scrape and not a resolver spy
//!
//! See [`super::_helpers::service_metrics`] — cotest drives soland as a
//! pre-built binary over HTTP, so no in-process spy can be injected, and the
//! counting DID host cannot be reached by a resolver whose SSRF gate rejects
//! loopback while the URL is still being built.
//!
//! # Coverage boundary
//!
//! Every function here needs soland's metrics listener, which the harness binds
//! for the process spawn modes but **not** for the docker mode (the container
//! publishes only the HTTP port). Those runs skip with a printed `skip:` line
//! rather than silently reading an unreachable counter as zero.
//!
//! coauth / inkson / bridges expose no metrics endpoint at all, so the matrix
//! rows that belong to them are not implemented here. They are reported as
//! uncovered rather than approximated. In particular:
//!
//! - **Row 4 (Inkson restart)** — inkson has no metrics endpoint and cotest cannot observe its
//!   resolver from outside the process. The equivalent evidence is inkson's own in-process test
//!   `state::did_bindings::tests::restart_serves_the_accepted_binding_with_zero_resolver_calls`.
//!   Its coverage boundary is *within one process*: it proves the persisted accepted binding is
//!   served after a restart with zero resolver calls, but not that a live inkson process serving
//!   live sync/render traffic makes no outbound request. Nothing here substitutes for that.
//! - **Rows 1 / 5 / 6 / 7** need soland to actually enter the authority path, which needs a
//!   reachable DID authority. The harness's soland resolves nothing at all
//!   (`soland_did_resolve_total` has no series after a full ordinary run), and the mock DID host
//!   cannot be reached by a resolver whose SSRF gate rejects loopback. They are not asserted here;
//!   writing a scenario that "passes" by observing a counter that can never move would be a false
//!   green.

use anyhow::{Context, Result, bail};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use super::_helpers::service_metrics::{DidBoundaryDelta, ServiceMetricsClient};
use crate::harness::{ArkretServer, CanonicalJsonBody, TestActorClient};

/// Bring up soland with its metrics listener, or explain why the scenario
/// cannot observe the counters in this run.
///
/// Returns `Ok(None)` — a skip, not a pass — when the metrics endpoint is not
/// reachable. A DID-boundary claim read off an endpoint that does not answer is
/// worth nothing, so the caller must not continue.
async fn metered_soland(name: &str) -> Result<Option<(ArkretServer, ServiceMetricsClient)>> {
    let server = ArkretServer::spawn(name).await?;
    let Some(metrics) = server.did_boundary_metrics()? else {
        eprintln!(
            "skip: {name}: this soland spawn mode publishes no metrics listener, so \
             authority_network_call_count is unobservable"
        );
        return Ok(None);
    };
    // Prove the endpoint answers before any assertion depends on it.
    metrics
        .snapshot()
        .await
        .with_context(|| format!("{name}: soland metrics endpoint is not answering"))?;
    Ok(Some((server, metrics)))
}

/// Assert the `soland_signature_verify_total` family is live before reading a
/// zero out of `soland_did_resolve_total`.
///
/// The Prometheus exporter only renders series that have been touched, so an
/// absent `soland_did_resolve_total` is indistinguishable from a build that
/// never had the counter. What rescues the reading is that the *sibling*
/// counter, incremented on the very same code path this scenario just drove,
/// **is** present: the DID-boundary instrumentation is demonstrably wired, and
/// the resolve counter's silence is therefore a real "no resolution happened",
/// not a missing metric.
fn assert_signature_counter_is_live(
    delta: DidBoundaryDelta,
    label: &str,
    at_least: u64,
) -> Result<()> {
    if delta.signature_verify_count < at_least {
        bail!(
            "{label}: expected at least {at_least} signature verification(s), saw {}. \
             A zero authority_network_call_count means nothing unless signatures were \
             actually verified.",
            delta.signature_verify_count
        );
    }
    Ok(())
}

async fn seeded_actor(server: &ArkretServer, actor: &str, device: &str) -> Result<TestActorClient> {
    server.demo_client(actor, device).await
}

/// Flip one character of `producer_proof.jws`'s signature segment, leaving every
/// other byte — including `event_digest` and `verification_method` — intact.
///
/// The Event therefore stays structurally valid and correctly authorized; the
/// only thing wrong with it is the signature, which is precisely the property
/// under test.
fn corrupt_detached_jws(event: &mut arkret_wire::Event) -> Result<()> {
    let jws = event
        .producer_proof
        .as_ref()
        .map(|proof| proof.jws.as_str())
        .context("authored Event carries no producer_proof.jws")?
        .to_owned();
    let (header, signature) = jws
        .rsplit_once('.')
        .context("producer_proof.jws is not a detached JWS")?;
    let mut bytes = URL_SAFE_NO_PAD
        .decode(signature)
        .context("producer_proof.jws signature is not canonical base64url")?;
    let first = bytes
        .first_mut()
        .context("producer_proof.jws has an empty signature segment")?;
    // Mutate a real signature bit, then re-encode canonically. Ed25519's
    // 64-byte signature encodes to 86 base64url characters, so replacing its
    // final character can accidentally alter padding bits and be rejected by
    // the structural decoder before signature verification.
    *first ^= 1;
    let corrupted = URL_SAFE_NO_PAD.encode(bytes);
    event
        .producer_proof
        .as_mut()
        .context("authored Event carries no producer_proof")?
        .jws = format!("{header}.{corrupted}");
    Ok(())
}

/// DID-P1-C02 row 2 — two ordinary Events under one key epoch:
/// `signature_verify_count == 2`, `authority_network_call_count == 0`.
///
/// The two Events are authored by the same actor, same device, same key epoch,
/// back to back. `did-usage-and-verification.md` §4 lists no trigger for either
/// of them, so the second must cost exactly what the first did in signature
/// verification and nothing at all in DID authority.
pub async fn two_ordinary_events_under_one_key_epoch_run() -> Result<()> {
    let Some((server, metrics)) = metered_soland("did-c02-ordinary-events").await? else {
        return Ok(());
    };
    let alice_did = crate::scenarios::identity_test_support::actor_did_for_service_did(
        server.service_did(),
        "did-c02-ordinary-alice",
    )?;
    let alice = seeded_actor(
        &server,
        &alice_did,
        "ak:device:01904100-0000-7000-8000-a11ce0000c02",
    )
    .await?;
    let realm_id = alice.create_realm("DID-P1-C02 ordinary Events").await?;
    let strand_id = alice.default_strand_id(&realm_id)?;

    let (_, delta) = metrics
        .expect_no_additional_authority_calls(
            None,
            "two ordinary Events under one key epoch",
            || async {
                alice
                    .send_message(&realm_id, &strand_id, "first ordinary Event")
                    .await?;
                alice
                    .send_message(&realm_id, &strand_id, "second ordinary Event")
                    .await?;
                Ok(())
            },
        )
        .await?;

    assert_signature_counter_is_live(delta, "two ordinary Events", 2)?;
    if delta.signature_verify_count != 2 {
        bail!(
            "two ordinary Events: expected exactly 2 signature verifications \
             (one per Event, `verifier.rs` module doc), saw {}",
            delta.signature_verify_count
        );
    }
    println!(
        "DID-P1-C02 row 2: signature_verify_count={} authority_network_call_count={}",
        delta.signature_verify_count, delta.authority_network_call_count
    );
    Ok(())
}

/// DID-P1-C02 row 2, negative twin — reusing an accepted binding must not
/// weaken verification.
///
/// A zero `authority_network_call_count` is only meaningful if the signature
/// still has to be right. The Event here is authored exactly the way an
/// accepted one is — same actor, same device key epoch, same authority ref, so
/// it clears every gate ahead of the verifier — and only then is its `jws`
/// corrupted. That is what makes the rejection attributable to signature
/// verification rather than to authorization: an Event that is merely
/// unauthorized is turned away *before* the DID boundary and would prove
/// nothing about it.
pub async fn a_reused_binding_still_rejects_a_bad_signature_run() -> Result<()> {
    let Some((server, metrics)) = metered_soland("did-c02-bad-signature").await? else {
        return Ok(());
    };
    let alice_did = crate::scenarios::identity_test_support::actor_did_for_service_did(
        server.service_did(),
        "did-c02-badsig-alice",
    )?;
    let alice = seeded_actor(
        &server,
        &alice_did,
        "ak:device:01904100-0000-7000-8000-a11ce0000c03",
    )
    .await?;
    let realm_id = alice.create_realm("DID-P1-C02 bad signature").await?;
    let strand_id = alice.default_strand_id(&realm_id)?;

    // Establish the binding with a genuine Event first, so the forged one below
    // differs from an accepted submission in exactly one respect.
    alice
        .send_message(&realm_id, &strand_id, "establishes the binding")
        .await?;

    let mut forged = alice
        .author_event(
            &realm_id,
            "ak.message.create",
            crate::harness::message_create_text_payload(&strand_id, "corrupted signature")?,
        )
        .await?;
    corrupt_detached_jws(&mut forged)?;

    let ((status, body), delta) = metrics
        .measure_did_boundary(None, || async {
            let response = alice
                .post("/_arkret/self/events")
                .canonical_json(&crate::publication::initial_submission(forged.clone(), "")?)?
                .send()
                .await?;
            let status = response.status();
            let body = response.text().await?;
            Ok((status, body))
        })
        .await?;

    if status.is_success() {
        bail!(
            "an Event whose detached JWS was corrupted was accepted (HTTP {status}): {body} \
             — binding reuse must not weaken verification"
        );
    }
    // The rejection has to be attributable to the verifier, not to a gate in
    // front of it: exactly one signature verification must have been counted.
    if delta.signature_verify_count == 0 {
        bail!(
            "the corrupted Event was rejected with HTTP {status} without a single signature \
             verification being counted, so the rejection came from a gate ahead of the DID \
             boundary and proves nothing about it: {body}"
        );
    }
    if delta.authority_network_call_count != 0 {
        bail!(
            "a bad signature must not trigger a \"resolve to be safe\" authority call, saw {}",
            delta.authority_network_call_count
        );
    }
    println!(
        "DID-P1-C02 row 2 (negative): rejected with HTTP {status}, \
         signature_verify_count={} authority_network_call_count={}",
        delta.signature_verify_count, delta.authority_network_call_count
    );
    Ok(())
}

/// DID-P1-C02 row 8 — an issuer the server has never admitted fails closed, and
/// the server does not go looking for a reason to trust it.
///
/// The Event is internally self-consistent: its detached JWS verifies against
/// the DID URL it names, and the DID's `did:key`-style development seed makes
/// the signature genuinely checkable. The only thing missing is any local basis
/// for admitting that issuer.
///
/// Two things are asserted, and the second is the interesting one:
///
/// 1. the submission is rejected;
/// 2. `authority_network_call_count == 0` — soland turns the request away at the admission gate
///    instead of resolving the unknown DID and reading a successful resolution as trust. §4's last
///    row *permits* entering the authority path for a third-party claim, but this is not that:
///    there is no local admission for this issuer, so a resolver success would be the only thing
///    standing between a stranger and an accepted Event.
///
/// What this does **not** show is a rejection attributable to the verifier —
/// `signature_verify_count` stays at 0 because the gate is ahead of it. That is
/// correct behaviour, and it is stated rather than dressed up.
pub async fn unknown_issuer_fails_closed_run() -> Result<()> {
    let Some((server, metrics)) = metered_soland("did-c02-unknown-issuer").await? else {
        return Ok(());
    };
    let alice_did = crate::scenarios::identity_test_support::actor_did_for_service_did(
        server.service_did(),
        "did-c02-unknown-alice",
    )?;
    let alice = seeded_actor(
        &server,
        &alice_did,
        "ak:device:01904100-0000-7000-8000-a11ce0000c08",
    )
    .await?;
    let realm_id = alice.create_realm("DID-P1-C02 unknown issuer").await?;
    let strand_id = alice.default_strand_id(&realm_id)?;

    let foreign = "did:web:never-admitted.example";
    let foreign_method = crate::harness::default_event_verification_method(foreign);
    let event = crate::harness::event_envelope_with_signing_seed_and_verification_method(
        foreign,
        &realm_id,
        "ak.message.create",
        crate::harness::message_create_text_payload(&strand_id, "from an unknown issuer")?,
        arkret::signatures::development_signing_key_seed(&foreign_method),
        &foreign_method,
    );

    let ((status, body), delta) = metrics
        .measure_did_boundary(None, || async {
            let response = alice
                .post("/_arkret/self/events")
                .json(&crate::publication::initial_submission(event.clone(), "")?)
                .send()
                .await?;
            let status = response.status();
            let body = response.text().await?;
            Ok((status, body))
        })
        .await?;

    if status.is_success() {
        bail!(
            "an Event from an issuer this server never admitted was accepted (HTTP {status}): \
             {body}"
        );
    }
    if delta.authority_network_call_count != 0 {
        bail!(
            "an unknown issuer must not send the server out to resolve it — a resolver success \
             would then be the only thing between a stranger and an accepted Event. Saw {} \
             authority network call(s).",
            delta.authority_network_call_count
        );
    }
    println!(
        "DID-P1-C02 row 8: unknown issuer rejected with HTTP {status}, \
         signature_verify_count={} authority_network_call_count={}",
        delta.signature_verify_count, delta.authority_network_call_count
    );
    Ok(())
}

/// DID-P1-C02 row 3 (soland half) — many ordinary requests against one accepted
/// service/actor binding cost one signature verification each and zero
/// authority calls.
///
/// Row 3 names federation / applet / directory requests. bridges (applet) and
/// teabay (directory) own two of those three surfaces and only teabay exports
/// counters, so what is provable *here* is the shape of the claim on soland's
/// own request face: N ordinary signed requests → N verifications, 0 authority
/// calls, no matter how many.
pub async fn repeated_requests_under_one_binding_run() -> Result<()> {
    let Some((server, metrics)) = metered_soland("did-c02-repeated-requests").await? else {
        return Ok(());
    };
    let alice_did = crate::scenarios::identity_test_support::actor_did_for_service_did(
        server.service_did(),
        "did-c02-repeated-alice",
    )?;
    let alice = seeded_actor(
        &server,
        &alice_did,
        "ak:device:01904100-0000-7000-8000-a11ce0000c04",
    )
    .await?;
    let realm_id = alice.create_realm("DID-P1-C02 repeated requests").await?;
    let strand_id = alice.default_strand_id(&realm_id)?;

    const REQUESTS: u64 = 5;
    let (_, delta) = metrics
        .expect_no_additional_authority_calls(
            None,
            "five ordinary requests under one binding",
            || async {
                for index in 0..REQUESTS {
                    alice
                        .send_message(&realm_id, &strand_id, &format!("ordinary request {index}"))
                        .await?;
                }
                Ok(())
            },
        )
        .await?;

    if delta.signature_verify_count != REQUESTS {
        bail!(
            "expected {REQUESTS} signature verifications (one per request), saw {}",
            delta.signature_verify_count
        );
    }
    println!(
        "DID-P1-C02 row 3 (soland face): signature_verify_count={} \
         authority_network_call_count={}",
        delta.signature_verify_count, delta.authority_network_call_count
    );
    Ok(())
}
