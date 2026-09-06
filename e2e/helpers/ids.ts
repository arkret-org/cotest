// Test-generated Arkret identifiers.
//
// The device id shape below was written out by hand in three places before this
// module existed, which is two places too many for a literal that has to keep
// matching what the servers accept.

import { randomUUID } from "node:crypto";

/**
 * A fresh `ak:device:<uuid>` for a device this run is about to found.
 *
 * The UUID is v7-shaped — a fixed timestamp prefix, version `7`, variant `8` —
 * because that is the form the suite has always produced and the servers have
 * always accepted. The entropy is in the last 48 bits, so ids stay distinct
 * within a run without the prefix pretending to carry a real clock reading.
 */
export function newDeviceId(): string {
  return `ak:device:01904100-0000-7000-8000-${deviceSuffix()}`;
}

/** The random tail of a device id, exposed for callers that already hold one. */
export function deviceSuffix(seed?: string): string {
  return (seed ?? randomUUID()).replace(/-/g, "").slice(0, 12);
}
