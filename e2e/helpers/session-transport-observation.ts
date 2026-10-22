import type { scanRealmStreamApi } from "./coland-api";

// Response events arrive in protocol order; asynchronous header/body reads
// must not reorder a refresh and the captured predecessor's later denial.
export function orderedResponseObservation<T extends object>(
  observe: (response: T) => Promise<void>,
  failed: () => void,
) {
  let tail = Promise.resolve();
  const jobs = new WeakMap<T, Promise<void>>();
  return {
    enqueue(response: T) {
      tail = tail.then(() => observe(response)).catch(failed);
      jobs.set(response, tail);
    },
    async observed(response: T) {
      const job = jobs.get(response);
      if (!job) throw new Error("response was not registered with the ordered observer");
      await job;
    },
    async settled() { await tail; },
  };
}

export function assertAcceptedRealmScanAlignment(
  realm: string,
  scan: Awaited<ReturnType<typeof scanRealmStreamApi>>,
) {
  if (scan.truncated || scan.events.length !== scan.commits.length) {
    throw new Error("accepted Realm scan is truncated or has unpaired rows");
  }
  const eventIds = new Set<unknown>();
  const commitIds = new Set<unknown>();
  for (const [position, event] of scan.events.entries()) {
    const commit = scan.commits[position];
    const stream = commit?.stream_ref as Record<string, unknown> | null | undefined;
    if (!event || !commit || typeof event.event_id !== "string" || typeof commit.commit_id !== "string"
      || eventIds.has(event.event_id) || commitIds.has(commit.commit_id)
      || event.realm_id !== realm || commit.realm_id !== realm
      || commit.event_ref !== event.event_id || commit.stream_position !== position
      || !stream || typeof stream !== "object"
      || Object.keys(stream).sort().join(",") !== "kind,realm_id"
      || stream.kind !== "realm" || stream.realm_id !== realm
      || commit.previous_commit_ref !== (position === 0 ? null : scan.commits[position - 1]!.commit_id)) {
      throw new Error(`accepted Realm Event/Commit pair is not exact at position ${position}`);
    }
    eventIds.add(event.event_id);
    commitIds.add(commit.commit_id);
  }
}
