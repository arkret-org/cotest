import type { NativeSearchObservation } from "./native-search";
import { publicProjection, structuralFingerprint } from "./secret-safe";

// Keep protocol objects in the test's assertions. Retained reports need only
// exact source coordinates and structural handles, never signed Commit bytes
// or the searched message plaintext.
export function nativeSearchEvidence(observation: NativeSearchObservation) {
  const commitReference = (value: Record<string, unknown> | undefined) => value
    ? publicProjection(value, ["commit_id", "stream_ref", "stream_position"])
    : undefined;
  return {
    account_id: publicProjection(observation.account_id, ["principal_id", "station_id"]),
    recheck_at: observation.recheck_at,
    query_fingerprint: structuralFingerprint(observation.view.query),
    result_count: observation.view.results.length,
    results: observation.view.results.map(result => ({
      ...publicProjection(result, ["realm_id", "strand_id", "kind", "surface", "event_id",
        "message_id", "actor_id", "source_event_id", "index_profile", "index_source"]),
      covering_commit: commitReference(result.covering_commit),
      source_commit: commitReference(result.source_commit),
      content_fingerprint: structuralFingerprint(result.content),
    })),
  };
}
