// DID-P1-C02 — the joint call-count contract, read off the services' own
// DID-boundary counters.
//
// Contract: arkret-spec/spec/v1/zh/identity/did-usage-and-verification.md §6 —
// ordinary business verifies every object's signature and performs no
// per-object online DID resolution. Those are two independent counts, and every
// assertion below records both:
//
//   authority_network_call_count  → *_did_resolve_total{source="network"}
//   signature_verify_count        → *_signature_verify_total (all labels)
//
// Asserting only the first would pass for a server that skipped verification
// entirely; asserting only the second would pass for a server that resolved a
// DID per Event.
//
// These counters are exported by soland and teabay only. coauth / inkson /
// bridges have no metrics endpoint, so the matrix rows that belong to them are
// not asserted here — see src/scenarios/did_boundary_call_counts.rs for the
// full coverage boundary, including which rows are deliberately uncovered.
//
// Skips (not passes) when the joint runner did not bind the metrics listener:
// run with scripts/run-joint-e2e.ps1, which exports COTEST_SOLAND_METRICS_URL /
// COTEST_TEABAY_METRICS_URL from ports it owns.

import { expect, test } from "@playwright/test";
import { teabayBaseUrl } from "../../helpers/env";
import {
  createRealmApi,
  sendMessageApi,
} from "../../helpers/soland-api";
import {
  createServiceMetricsClient,
  didResolveMetric,
  hasMetric,
  seriesOf,
  signatureVerifyMetric,
  type MeteredService,
} from "../../helpers/service-metrics";
import { ensureRegistered, issueDevSession, uniqueUser } from "../../helpers/users";

/// Dump both counter families so a run leaves a resolver call-count trace
/// behind even when every assertion passes.
function traceCounters(
  service: MeteredService,
  label: string,
  samples: Parameters<typeof seriesOf>[0],
): void {
  // eslint-disable-next-line no-console
  console.log(
    `[did-boundary][${service}][${label}] ` +
      `${didResolveMetric(service)}=${JSON.stringify(seriesOf(samples, didResolveMetric(service)))} ` +
      `${signatureVerifyMetric(service)}=${JSON.stringify(
        seriesOf(samples, signatureVerifyMetric(service)),
      )}`,
  );
}

test.describe("DID boundary call counts @fully-implemented", () => {
  test("row 2/3: ordinary Events verify per Event and add zero soland authority calls", async ({
    request,
  }) => {
    const metrics = createServiceMetricsClient(request, "soland");
    if (!metrics) {
      test.skip(
        true,
        "COTEST_SOLAND_METRICS_URL is unset — start the stack with scripts/run-joint-e2e.ps1",
      );
      return;
    }
    test.setTimeout(180_000);

    const alice = uniqueUser(`did-boundary-${Date.now()}`);
    await ensureRegistered(request, alice);
    const token = await issueDevSession(request, alice);
    const realmId = await createRealmApi(request, token, {
      title: `did boundary ${Date.now()}`,
    });

    traceCounters("soland", "before", await metrics.snapshot());

    const MESSAGES = 3;
    const { delta } = await metrics.expectNoAdditionalAuthorityCalls(
      async () => {
        for (let index = 0; index < MESSAGES; index += 1) {
          await sendMessageApi(request, token, realmId, `ordinary message ${index}`);
        }
      },
      { label: `${MESSAGES} ordinary messages under one key epoch` },
    );

    const after = await metrics.snapshot();
    traceCounters("soland", "after", after);

    // A zero authority count proves nothing unless the signatures were
    // actually checked. The sibling counter being live is also what rescues the
    // reading of an absent `*_did_resolve_total` family: the exporter only
    // renders series that have been touched, so its silence here is a genuine
    // "no resolution happened", not a missing metric.
    expect(
      hasMetric(after, signatureVerifyMetric("soland")),
      "soland exposes no signature-verification counter, so a zero authority " +
        "count would be unfalsifiable",
    ).toBe(true);
    expect(
      delta.signature_verify_count,
      `expected at least ${MESSAGES} signature verifications, one per message`,
    ).toBeGreaterThanOrEqual(MESSAGES);
    expect(delta.authority_network_call_count).toBe(0);
  });

  test("row 6 (low-risk read): teabay directory searches add zero authority calls", async ({
    request,
  }) => {
    const metrics = createServiceMetricsClient(request, "teabay");
    const directory = teabayBaseUrl();
    if (!metrics || !directory) {
      test.skip(
        true,
        "COTEST_TEABAY_METRICS_URL / COTEST_TEABAY_BASE_URL are unset — teabay is not part of this run",
      );
      return;
    }
    test.setTimeout(120_000);

    traceCounters("teabay", "before", await metrics.snapshot());

    // A public directory search is the canonical low-risk read. DID-P0-C03:
    // it must not live-resolve an unknown display subject, and a stale binding
    // must not block it or fall back to the network. Its authority delta is
    // therefore zero regardless of what it finds — including "nothing", which
    // is the blinded not-found path.
    const { delta } = await metrics.expectNoAdditionalAuthorityCalls(
      async () => {
        for (let index = 0; index < 3; index += 1) {
          const response = await request.post(
            `${directory}/_arkret/find/directory/search-actors`,
            { data: { query: `did-boundary-probe-${index}` } },
          );
          // Both "found" and blinded not-found are acceptable outcomes; what
          // must never happen is the directory going out to the network to
          // answer. A request that never reached the handler — a 404 from a
          // renamed route, say — would make the zero meaningless, so the
          // search has to have been served and have produced a result set.
          expect(
            response.status(),
            "teabay directory search did not answer, so a zero authority count proves nothing",
          ).toBe(200);
          const body = (await response.json()) as { actors?: unknown };
          expect(
            Array.isArray(body.actors),
            "teabay directory search returned no `actors` array, so it did not run the query",
          ).toBe(true);
        }
      },
      { label: "three ordinary directory searches" },
    );

    traceCounters("teabay", "after", await metrics.snapshot());
    expect(delta.authority_network_call_count).toBe(0);
  });
});
