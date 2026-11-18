import { isDeepStrictEqual } from "node:util";
import type { scanRealmStreamApi } from "./coland-api";

function streamPosition(value: unknown): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw new Error("Expected a nonnegative safe integer stream_position");
  }
  return value;
}

// This only checks the fixture's exact public bindings. The caller must obtain
// the scan through the SDK-validated original Event/Commit path; this helper
// neither establishes native authority nor replaces recipient HPKE/AEAD checks.
export function contentHistoryProof(
  scan: Awaited<ReturnType<typeof scanRealmStreamApi>>,
  expected: { realmId: string; sourceEventId: string; sourceKind: "ak.space.create" | "ak.strand.create"; issuerActor: unknown;
    recipientActor: unknown; recipientDeviceId: string },
) {
  const requireFact = (value: boolean, message: string) => {
    if (!value) throw new Error(message);
  };
  requireFact(!scan.truncated, "Content history proof requires a complete scan");
  const source = scan.events.find(event => event.kind === expected.sourceKind && event.event_id === expected.sourceEventId);
  if (!source) return undefined;
  for (const grant of scan.events.filter(event => event.kind === "ak.mls.history_grant")) {
    const granted = grant.payload as Record<string, any>;
    if (!isDeepStrictEqual(granted.recipient?.actor_id, expected.recipientActor)
        || granted.recipient?.endpoint?.device_id !== expected.recipientDeviceId) continue;
    if (!granted.entries.some((entry: Record<string, any>) => entry.selector.kind === "content_key"
        && entry.selector.source_event_ref === source.event_id
        && entry.selector.content_path === "/payload/object/encrypted_metadata")) continue;
    const originalRequest = scan.events.find(event => event.kind === "ak.mls.history_request"
      && event.event_id === granted.recipient_key_event_ref);
    if (!originalRequest) continue;
    const requested = originalRequest.payload as Record<string, any>;
    requireFact([source, originalRequest, grant].every(event => event.realm_id === expected.realmId),
      "Content history originals must belong to the exact Realm");
    requireFact(isDeepStrictEqual(originalRequest.actor_id, expected.recipientActor)
      && isDeepStrictEqual(grant.actor_id, expected.issuerActor), "Content history request and grant must have the exact authors");
    requireFact(["recipient", "recipient_hpke_key_base64url", "history_cut", "expires_at"]
      .every(field => isDeepStrictEqual(granted[field], requested[field])), "Content history grant must bind the exact request fields");
    const cut = granted.history_cut;
    const indices = [source.event_id, cut.event_id, originalRequest.event_id, grant.event_id]
      .map(id => scan.eventSlots.findIndex(event => event?.event_id === id));
    requireFact(indices.every(index => index >= 0), "Content history originals must have accepted Commit slots");
    const [sourceCommit, cutCommit, requestCommit, grantCommit] = indices.map(index => scan.commits[index]!);
    requireFact(cutCommit.commit_id === cut.commit_id && cutCommit.stream_position === cut.stream_position
      && isDeepStrictEqual(cut.stream_ref, { kind: "realm", realm_id: expected.realmId }),
    "Content history cut must bind the exact accepted Commit and stream");
    const [sourcePosition, cutPosition, requestPosition, grantPosition] =
      [sourceCommit, cutCommit, requestCommit, grantCommit].map(commit => streamPosition(commit.stream_position));
    requireFact(sourcePosition <= cutPosition && cutPosition < requestPosition && requestPosition < grantPosition,
    "Content history source, cut, request and grant must have their accepted order");
    const created = Date.parse(String(originalRequest.created_at));
    const expires = Date.parse(String(requested.expires_at));
    const delivered = Date.parse(String(grantCommit.committed_at));
    requireFact(expires > created && expires - created <= 900_000 && delivered < expires,
      "Content history grant must have been accepted within the original request TTL");
    return { source, request: originalRequest, grant };
  }
  return undefined;
}
