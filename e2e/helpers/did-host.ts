// Counting DID-authority helper — the scenario-facing half of DID-P1-C01.
//
// `mock-did-host.mjs` hosts DID documents / did:webvh logs / witness files and
// counts every fetch per (DID, purpose). This module turns those counters into
// the two things scenarios actually need:
//
//   authority_network_call_count  → getAuthorityNetworkCallCount()
//   "this operation must not talk
//    to the authority again"      → expectNoAdditionalAuthorityCalls()
//
// The second is the workhorse for the DID-P1-C02 scenario matrix: it resets the
// counters, runs the caller's operation, re-reads the counters, and fails with
// a diff (which DID, which purpose, how many) when anything moved.
//
// Every helper here degrades to `undefined` / a skip when the mock is not part
// of the current run, matching the other mock helpers in this directory.

import { expect, type APIRequestContext } from "@playwright/test";
import { mockDidHostAuthority, mockDidHostBaseUrl, mockDidHostScid } from "./env";

/// Per-purpose fetch counters for a single DID. `total` is the sum of the
/// three purposes, i.e. the DID's `authority_network_call_count`.
export type DidHostCounts = {
  /// `did.json` fetches (did:web document, or did:webvh current document).
  document: number;
  /// `did.jsonl` fetches (did:webvh log).
  log: number;
  /// `did-witness.json` fetches.
  witness: number;
  total: number;
};

export type DidHostCountsResponse = {
  service: string;
  now: string;
  /// Sum of every DID's `total` (or of the filtered DID, when `did` was given).
  total: number;
  counts: Record<string, DidHostCounts>;
};

/// One registered DID as reported by `GET /control/dids`.
export type DidHostDid = {
  did: string;
  method: string;
  authority: string;
  base_path: string;
  scid: string | null;
  version_index: number;
  version_id: string;
  version_count: number;
  deactivated: boolean;
  status_override: { status: number; leaf: string | null } | null;
  witness_attestation_count: number;
  urls: string[];
};

/// Counters that moved between two snapshots, keyed by DID. Only DIDs with a
/// non-zero delta appear.
export type DidHostCountDelta = Record<string, DidHostCounts>;

const ZERO: DidHostCounts = { document: 0, log: 0, witness: 0, total: 0 };

function countsOrZero(
  snapshot: DidHostCountsResponse,
  did: string,
): DidHostCounts {
  return snapshot.counts[did] ?? { ...ZERO };
}

/// Subtract `before` from `after`, dropping DIDs whose counters did not move.
export function diffDidHostCounts(
  before: DidHostCountsResponse,
  after: DidHostCountsResponse,
): DidHostCountDelta {
  const delta: DidHostCountDelta = {};
  for (const did of new Set([...Object.keys(before.counts), ...Object.keys(after.counts)])) {
    const a = countsOrZero(after, did);
    const b = countsOrZero(before, did);
    const entry: DidHostCounts = {
      document: a.document - b.document,
      log: a.log - b.log,
      witness: a.witness - b.witness,
      total: a.total - b.total,
    };
    if (entry.total !== 0 || entry.document !== 0 || entry.log !== 0 || entry.witness !== 0) {
      delta[did] = entry;
    }
  }
  return delta;
}

export type DidHostClient = {
  baseUrl: string;
  authority?: string;
  scid?: string;

  // ── counting ───────────────────────────────────────────────────────────
  /// Zero every counter and clear the forensic fetch log.
  resetCounts(): Promise<void>;
  /// Full counter snapshot (optionally narrowed to one DID).
  getCounts(did?: string): Promise<DidHostCountsResponse>;
  /// `authority_network_call_count`: total authority fetches, for one DID when
  /// `did` is given, otherwise across every DID (including the `<unresolved>`
  /// bucket for fetches that matched no registered DID).
  getAuthorityNetworkCallCount(did?: string): Promise<number>;
  /// Run `body`, then report how many authority calls it caused.
  measureAuthorityCalls<T>(
    body: () => Promise<T>,
  ): Promise<{ result: T; delta: DidHostCountDelta; total: number }>;
  /// Assert `body` caused **zero** additional authority fetches. This is the
  /// primary DID-P1-C02 tool: reset → run → re-read → assert delta 0.
  expectNoAdditionalAuthorityCalls<T>(
    body: () => Promise<T>,
    options?: { did?: string; label?: string },
  ): Promise<T>;
  /// Assert `body` caused exactly `expected` additional authority fetches
  /// (e.g. the *first* resolution of a DID is allowed to cost one fetch).
  expectAuthorityCalls<T>(
    expected: number,
    body: () => Promise<T>,
    options?: { did?: string; label?: string },
  ): Promise<T>;
  /// Raw `GET /inspect` dump (bounded fetch log + counts + DID states).
  inspect(): Promise<Record<string, unknown>>;

  // ── document lifecycle control ─────────────────────────────────────────
  listDids(): Promise<DidHostDid[]>;
  registerDid(did: string, versions?: number): Promise<DidHostDid>;
  /// Advance to the next preset version, or jump to an index / versionId.
  rotate(did: string, to?: number | string): Promise<DidHostDid>;
  deactivate(did: string): Promise<DidHostDid>;
  /// Force fetches for `did` to fail with `status` (null clears the override).
  forceStatus(did: string, status: number | null, leaf?: string): Promise<DidHostDid>;
  /// Ask the configured mock-witness to attest the current entry.
  attest(did: string): Promise<DidHostDid>;
  /// Restore every DID to version 0 / active / no override. Does NOT touch
  /// counters — call `resetCounts()` for that.
  resetDocuments(): Promise<void>;
  /// URL a resolver would fetch for `did`'s document / log / witness file.
  documentUrl(did: string, leaf?: "did.json" | "did.jsonl" | "did-witness.json"): string;
};

async function okJson(
  response: Awaited<ReturnType<APIRequestContext["get"]>>,
  what: string,
): Promise<Record<string, unknown>> {
  if (!response.ok()) {
    throw new Error(`mock-did-host ${what} failed: HTTP ${response.status()} ${await response.text()}`);
  }
  return (await response.json()) as Record<string, unknown>;
}

/// Build a client bound to `request`, or `undefined` when the mock is not
/// running for this stack. Mirrors `createMimiFacadeClient`.
export function createDidHostClient(request: APIRequestContext): DidHostClient | undefined {
  const baseUrl = mockDidHostBaseUrl();
  if (!baseUrl) return undefined;

  async function control(pathname: string, data: Record<string, unknown>): Promise<DidHostDid> {
    const response = await request.post(`${baseUrl}${pathname}`, { data });
    const body = await okJson(response, `POST ${pathname}`);
    return body.did as DidHostDid;
  }

  async function getCounts(did?: string): Promise<DidHostCountsResponse> {
    const suffix = did ? `?did=${encodeURIComponent(did)}` : "";
    const response = await request.get(`${baseUrl}/inspect/counts${suffix}`);
    return (await okJson(response, "GET /inspect/counts")) as unknown as DidHostCountsResponse;
  }

  async function resetCounts(): Promise<void> {
    const response = await request.post(`${baseUrl}/inspect/reset`);
    await okJson(response, "POST /inspect/reset");
  }

  async function measure<T>(body: () => Promise<T>) {
    await resetCounts();
    const before = await getCounts();
    const result = await body();
    const after = await getCounts();
    return { result, delta: diffDidHostCounts(before, after), total: after.total, after };
  }

  async function expectAuthorityCalls<T>(
    expected: number,
    body: () => Promise<T>,
    options?: { did?: string; label?: string },
  ): Promise<T> {
    const { result, delta, after } = await measure(body);
    const observed = options?.did ? countsOrZero(after, options.did).total : after.total;
    const label = options?.label ?? "operation";
    const scope = options?.did ? ` for ${options.did}` : "";
    expect(
      observed,
      `${label}: expected ${expected} authority network call(s)${scope}, saw ${observed}. ` +
        `Per-DID delta: ${JSON.stringify(delta)}`,
    ).toBe(expected);
    return result;
  }

  return {
    baseUrl,
    authority: mockDidHostAuthority(),
    scid: mockDidHostScid(),

    resetCounts,
    getCounts,

    async getAuthorityNetworkCallCount(did) {
      const snapshot = await getCounts(did);
      return did ? countsOrZero(snapshot, did).total : snapshot.total;
    },

    async measureAuthorityCalls(body) {
      const { result, delta, total } = await measure(body);
      return { result, delta, total };
    },

    expectNoAdditionalAuthorityCalls: (body, options) => expectAuthorityCalls(0, body, options),
    expectAuthorityCalls,

    async inspect() {
      const response = await request.get(`${baseUrl}/inspect`);
      return okJson(response, "GET /inspect");
    },

    async listDids() {
      const response = await request.get(`${baseUrl}/control/dids`);
      const body = await okJson(response, "GET /control/dids");
      return body.dids as DidHostDid[];
    },

    registerDid: (did, versions) => control("/control/register", { did, versions }),
    rotate: (did, to) => control("/control/rotate", { did, to }),
    deactivate: (did) => control("/control/deactivate", { did }),
    forceStatus: (did, status, leaf) => control("/control/fail", { did, status, leaf }),
    attest: (did) => control("/control/attest", { did }),

    async resetDocuments() {
      const response = await request.post(`${baseUrl}/control/reset`);
      await okJson(response, "POST /control/reset");
    },

    documentUrl(did, leaf = "did.json") {
      return `${baseUrl}/${didBasePath(did)}/${leaf}`;
    },
  };
}

/// HTTP base path a resolver derives from `did`. Mirrors the SDK
/// (arkret-rust-sdk crates/identity/src/helpers.rs `did_webvh_url`,
/// crates/models-identity/src/did_document.rs `did_web_document_url`):
/// no path segments → `.well-known`, otherwise the segments verbatim.
export function didBasePath(did: string): string {
  let rest: string;
  if (did.startsWith("did:webvh:")) {
    // strip scid + authority
    rest = did.slice("did:webvh:".length).split(":").slice(2).join("/");
  } else if (did.startsWith("did:web:")) {
    rest = did.slice("did:web:".length).split(":").slice(1).join("/");
  } else {
    throw new Error(`did host only serves did:web / did:webvh, got ${did}`);
  }
  return rest === "" ? ".well-known" : rest;
}
