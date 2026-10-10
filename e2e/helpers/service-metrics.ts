// DID-boundary call counting over the services' Prometheus endpoints
// (DID-P1-C01/C02) — the TypeScript twin of
// src/scenarios/_helpers/service_metrics.rs.
//
// Why metrics rather than a resolver spy: cotest drives soland / flagon as
// pre-built binaries over HTTP, so no in-process spy can be injected, and the
// network-layer counting DID host (mock-did-host.mjs, e2e/helpers/did-host.ts)
// cannot be wired to them because DID→URL derivation hard-codes `https` and the
// SSRF gate rejects loopback hosts while the URL is still being built. soland
// and flagon therefore export two counters each, and this module turns them
// into the two numbers the joint contract is written in:
//
//   authority_network_call_count  → *_did_resolve_total{source="network"}
//   signature_verify_count        → *_signature_verify_total (all labels)
//
// Only `source="network"` counts: both services increment it exclusively on the
// branches that actually issue an outbound request, so binding_store /
// local_snapshot / sdk_cache / did_key hits — which are exactly what "reused the
// accepted binding" means — never inflate it.
//
// Coverage boundary: only soland and flagon expose these counters. coauth,
// inkson and bridges have no metrics endpoint, so a scenario about them cannot
// be expressed here.

import { expect, type APIRequestContext } from "@playwright/test";
import { solandMetricsUrl, teabayMetricsUrl } from "./env";

export type MeteredService = "soland" | "flagon";

/// A single Prometheus sample line.
export type MetricSample = {
  name: string;
  labels: Record<string, string>;
  value: number;
};

/// The two counts DID-P1-C02 requires every scenario to record. They are
/// deliberately independent: only `signature_verify_count` may scale with
/// ordinary traffic.
export type DidBoundaryDelta = {
  authority_network_call_count: number;
  signature_verify_count: number;
};

/// The one `source` label value that means an outbound request was issued.
export const SOURCE_NETWORK = "network";

const METRIC_NAMES: Record<MeteredService, { didResolve: string; signatureVerify: string }> = {
  soland: {
    didResolve: "soland_did_resolve_total",
    signatureVerify: "soland_signature_verify_total",
  },
  flagon: {
    didResolve: "teabay_did_resolve_total",
    signatureVerify: "teabay_signature_verify_total",
  },
};

export function didResolveMetric(service: MeteredService): string {
  return METRIC_NAMES[service].didResolve;
}

export function signatureVerifyMetric(service: MeteredService): string {
  return METRIC_NAMES[service].signatureVerify;
}

/// Parse Prometheus text-exposition format. HELP/TYPE comments and blank lines
/// are skipped; a line that does not parse is skipped rather than failing the
/// whole snapshot, because a scrape carries dozens of unrelated families and
/// one malformed one must not blind an unrelated assertion.
export function parseMetrics(body: string): MetricSample[] {
  const samples: MetricSample[] = [];
  for (const raw of body.split("\n")) {
    const line = raw.trim();
    if (line === "" || line.startsWith("#")) continue;
    const sample = parseSampleLine(line);
    if (sample) samples.push(sample);
  }
  return samples;
}

function parseSampleLine(line: string): MetricSample | undefined {
  const split = line.lastIndexOf(" ");
  if (split < 0) return undefined;
  const head = line.slice(0, split).trim();
  const value = Number(line.slice(split + 1).trim());
  if (!Number.isFinite(value)) return undefined;

  const brace = head.indexOf("{");
  if (brace < 0) return { name: head, labels: {}, value };
  if (!head.endsWith("}")) return undefined;
  const name = head.slice(0, brace).trim();
  const labels: Record<string, string> = {};
  for (const pair of splitLabelPairs(head.slice(brace + 1, head.length - 1))) {
    const eq = pair.indexOf("=");
    if (eq < 0) return undefined;
    const key = pair.slice(0, eq).trim();
    const rawValue = pair.slice(eq + 1).trim();
    if (!rawValue.startsWith('"') || !rawValue.endsWith('"') || rawValue.length < 2) {
      return undefined;
    }
    labels[key] = unescapeLabelValue(rawValue.slice(1, -1));
  }
  return { name, labels, value };
}

/// Split `a="1",b="2"` on commas that are not inside a quoted value.
function splitLabelPairs(rest: string): string[] {
  const out: string[] = [];
  let current = "";
  let inQuotes = false;
  let escaped = false;
  for (const character of rest) {
    if (escaped) {
      current += character;
      escaped = false;
      continue;
    }
    if (character === "\\" && inQuotes) {
      current += character;
      escaped = true;
      continue;
    }
    if (character === '"') {
      inQuotes = !inQuotes;
      current += character;
      continue;
    }
    if (character === "," && !inQuotes) {
      if (current.trim() !== "") out.push(current);
      current = "";
      continue;
    }
    current += character;
  }
  if (current.trim() !== "") out.push(current);
  return out;
}

function unescapeLabelValue(raw: string): string {
  return raw.replace(/\\(.)/g, (_, character: string) => {
    if (character === "n") return "\n";
    if (character === "\\") return "\\";
    if (character === '"') return '"';
    return `\\${character}`;
  });
}

function matches(sample: MetricSample, selector: Record<string, string>): boolean {
  return Object.entries(selector).every(([key, value]) => sample.labels[key] === value);
}

/// Sum every sample of `name` whose labels match `selector`. An absent series
/// reads as 0, which is what a counter that never fired means.
export function sumMetric(
  samples: MetricSample[],
  name: string,
  selector: Record<string, string> = {},
): number {
  return samples
    .filter((sample) => sample.name === name && matches(sample, selector))
    .reduce((total, sample) => total + sample.value, 0);
}

/// Every series of `name` keyed by its rendered label set, for diagnostics.
export function seriesOf(samples: MetricSample[], name: string): Record<string, number> {
  const out: Record<string, number> = {};
  for (const sample of samples.filter((candidate) => candidate.name === name)) {
    const key = Object.entries(sample.labels)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
      .map(([label, value]) => `${label}="${value}"`)
      .join(",");
    out[`{${key}}`] = sample.value;
  }
  return out;
}

export function hasMetric(samples: MetricSample[], name: string): boolean {
  return samples.some((sample) => sample.name === name);
}

/// `authority_network_call_count` in `samples`, optionally narrowed to one DID
/// `method` label.
export function authorityCalls(
  samples: MetricSample[],
  service: MeteredService,
  method?: string,
): number {
  const selector: Record<string, string> = { source: SOURCE_NETWORK };
  if (method) selector.method = method;
  return sumMetric(samples, didResolveMetric(service), selector);
}

/// `signature_verify_count` in `samples`, summed over every label.
export function signatureVerifies(samples: MetricSample[], service: MeteredService): number {
  return sumMetric(samples, signatureVerifyMetric(service));
}

/// Counter increments between two snapshots. Increments, not absolutes: the
/// counters are process-lifetime totals shared with every other scenario, so
/// only a before/after delta is a statement about one operation.
export function diffDidBoundary(
  before: MetricSample[],
  after: MetricSample[],
  service: MeteredService,
  method?: string,
): DidBoundaryDelta {
  return {
    authority_network_call_count:
      authorityCalls(after, service, method) - authorityCalls(before, service, method),
    signature_verify_count: signatureVerifies(after, service) - signatureVerifies(before, service),
  };
}

export type ServiceMetricsClient = {
  service: MeteredService;
  baseUrl: string;
  metricsUrl: string;

  /// Scrape and parse `GET /metrics`.
  snapshot(): Promise<MetricSample[]>;
  /// `*_did_resolve_total{source="network"}`, optionally narrowed to a method.
  getAuthorityNetworkCallCount(method?: string): Promise<number>;
  /// `*_signature_verify_total` over every label.
  getSignatureVerifyCount(): Promise<number>;
  /// Throw when the build under test predates the DID-boundary counters, so an
  /// absent series is never read as a passing zero.
  requireDidBoundaryCounters(): Promise<void>;
  /// Run `body` and report the counter increments it caused.
  measureDidBoundary<T>(
    body: () => Promise<T>,
    options?: { method?: string },
  ): Promise<{ result: T; delta: DidBoundaryDelta }>;
  /// Assert `body` caused zero additional authority network calls; returns the
  /// delta too, so the scenario records both DID-P1-C02 numbers.
  expectNoAdditionalAuthorityCalls<T>(
    body: () => Promise<T>,
    options?: { method?: string; label?: string },
  ): Promise<{ result: T; delta: DidBoundaryDelta }>;
  /// Assert `body` caused exactly `expected` additional authority calls.
  expectAuthorityCalls<T>(
    expected: number,
    body: () => Promise<T>,
    options?: { method?: string; label?: string },
  ): Promise<{ result: T; delta: DidBoundaryDelta }>;
};

function normalizeBaseUrl(value: string): string {
  return value.trim().replace(/\/$/, "").replace(/\/metrics$/, "");
}

export function metricsUrlFor(service: MeteredService): string | undefined {
  return service === "soland" ? solandMetricsUrl() : teabayMetricsUrl();
}

/// Build a client bound to `request`, or `undefined` when the service's metrics
/// listener is not part of this run. Mirrors `createDidHostClient`.
export function createServiceMetricsClient(
  request: APIRequestContext,
  service: MeteredService,
): ServiceMetricsClient | undefined {
  const configured = metricsUrlFor(service);
  if (!configured) return undefined;
  const baseUrl = normalizeBaseUrl(configured);
  const metricsUrl = `${baseUrl}/metrics`;

  async function snapshot(): Promise<MetricSample[]> {
    const response = await request.get(metricsUrl);
    if (!response.ok()) {
      throw new Error(
        `${service} GET ${metricsUrl} failed: HTTP ${response.status()} ${await response.text()}`,
      );
    }
    return parseMetrics(await response.text());
  }

  async function measure<T>(body: () => Promise<T>, method?: string) {
    const before = await snapshot();
    const result = await body();
    const after = await snapshot();
    return { result, before, after, delta: diffDidBoundary(before, after, service, method) };
  }

  async function expectAuthorityCalls<T>(
    expected: number,
    body: () => Promise<T>,
    options?: { method?: string; label?: string },
  ) {
    const { result, before, after, delta } = await measure(body, options?.method);
    const label = options?.label ?? "operation";
    const scope = options?.method ? ` for method=${options.method}` : "";
    expect(
      delta.authority_network_call_count,
      `${label}: expected ${expected} ${service} authority network call(s)${scope}, saw ` +
        `${delta.authority_network_call_count}. signature_verify_count delta was ` +
        `${delta.signature_verify_count}. before=${JSON.stringify(
          seriesOf(before, didResolveMetric(service)),
        )} after=${JSON.stringify(seriesOf(after, didResolveMetric(service)))}`,
    ).toBe(expected);
    return { result, delta };
  }

  return {
    service,
    baseUrl,
    metricsUrl,
    snapshot,

    async getAuthorityNetworkCallCount(method) {
      return authorityCalls(await snapshot(), service, method);
    },

    async getSignatureVerifyCount() {
      return signatureVerifies(await snapshot(), service);
    },

    async requireDidBoundaryCounters() {
      const samples = await snapshot();
      for (const name of [didResolveMetric(service), signatureVerifyMetric(service)]) {
        if (!hasMetric(samples, name)) {
          throw new Error(
            `${service} at ${metricsUrl} exposes no \`${name}\` series — the binary under test ` +
              "predates the DID-boundary counters, so a zero reading would prove nothing",
          );
        }
      }
    },

    async measureDidBoundary(body, options) {
      const { result, delta } = await measure(body, options?.method);
      return { result, delta };
    },

    expectNoAdditionalAuthorityCalls: (body, options) => expectAuthorityCalls(0, body, options),
    expectAuthorityCalls,
  };
}
