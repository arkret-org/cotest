import { isDeepStrictEqual } from "node:util";
import type { CommitStreamHead } from "./generated/spec-wire-objects";

// The authenticated exact-cut reader returns undefined until replication has
// reached the original acknowledged Commit. Presence is not this barrier.
export async function waitForAcceptedDirectCut(
  observe: () => Promise<CommitStreamHead | undefined>,
  acknowledged: CommitStreamHead,
  { timeoutMs = 90_000, retryDelayMs = 250 } = {},
): Promise<CommitStreamHead> {
  if (acknowledged.stream_ref.kind !== "realm" || !acknowledged.commit_id
    || !Number.isSafeInteger(acknowledged.stream_position) || acknowledged.stream_position < 0) {
    throw new Error("Direct accepted cut requires an acknowledged Realm Commit");
  }
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const observed = await observe();
    if (observed !== undefined) {
      if (!isDeepStrictEqual(observed, acknowledged)) {
        throw new Error("Direct observed cut differs from the acknowledged Commit");
      }
      return observed;
    }
    if (Date.now() >= deadline) break;
    await new Promise(resolve => setTimeout(resolve, Math.min(retryDelayMs, deadline - Date.now())));
    if (Date.now() >= deadline) break;
  }
  throw new Error("Direct acknowledged Commit was not observed before the readiness deadline");
}
