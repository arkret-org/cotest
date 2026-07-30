// Assertion helpers that keep secret-bearing values out of failure output.
//
// Playwright serialises the full received value into stdout and
// `error-context.md` whenever a matcher fails. An assertion written as
//
//   expect(retry.materialization_draft).toEqual(resolved.materialization_draft)
//
// therefore publishes an entire protocol object -- key material, invite
// secrets, tokens and all -- the moment the two drift apart, in an artifact the
// runner then collects and retains. The joint runner's secret scan found six
// such leaks this way, none of which any test had asked to print.
//
// The runner also redacts the collected artifacts after scanning
// (`scripts/lib/secret-scan.ps1`), but that is the backstop. The fix is not to
// hand the matcher the object in the first place:
//
//   * compare whole structures through `expectStructurallyIdentical`, whose
//     failure message carries two fingerprints and nothing else;
//   * assert on `publicProjection(value, [...])` when only some fields matter;
//   * assert existence of a secret through `secretPresence`, which yields a
//     boolean and a coarse length class, never the value.

import { createHash } from "node:crypto";

/// Deterministic structural handle for test-local comparison.
///
/// NOT a protocol digest, and MUST NOT be compared against one. Arkret's
/// canonical JSON lives in the Rust SDK and is reached through `cotest-wire`;
/// this is only a stable way to say "these two structures are the same" without
/// putting either into an assertion message. Object keys are sorted so member
/// order does not affect the result.
export function structuralFingerprint(value: unknown): string {
  return createHash("sha256").update(stableStringify(value)).digest("hex");
}

function stableStringify(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value) ?? "null";
  }
  if (Array.isArray(value)) {
    return `[${value.map(stableStringify).join(",")}]`;
  }
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, member]) => member !== undefined)
    .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0));
  return `{${entries
    .map(([key, member]) => `${JSON.stringify(key)}:${stableStringify(member)}`)
    .join(",")}}`;
}

/// Assert two structures are identical without passing either to a matcher.
///
/// On failure the message names the comparison and the two fingerprints. That
/// is enough to know the structures diverged; reproducing *how* is a debugging
/// step the developer takes locally, where dumping the objects is safe.
export function expectStructurallyIdentical(
  actual: unknown,
  expected: unknown,
  label: string,
): void {
  const actualFingerprint = structuralFingerprint(actual);
  const expectedFingerprint = structuralFingerprint(expected);
  if (actualFingerprint !== expectedFingerprint) {
    throw new Error(
      `${label}: structures differ (actual sha256=${actualFingerprint}, ` +
        `expected sha256=${expectedFingerprint}). The values are withheld ` +
        `because this object may carry secret-bearing fields; re-run the ` +
        `single test locally to inspect them.`,
    );
  }
}

/// Keep only the named fields, so the matcher never receives the rest.
///
/// Use for objects that mix public projection fields with secret-bearing ones:
/// name the fields the test is actually about.
export function publicProjection<T extends object, K extends keyof T>(
  value: T,
  keys: readonly K[],
): Pick<T, K> {
  const projection = {} as Pick<T, K>;
  for (const key of keys) {
    if (Object.prototype.hasOwnProperty.call(value, key)) {
      projection[key] = value[key];
    }
  }
  return projection;
}

/// Coarse size buckets. Deliberately coarse: an exact length is a meaningful
/// oracle against some secrets.
export type SecretLengthClass = "absent" | "short" | "medium" | "long";

/// Presence and coarse size of a secret-bearing value, safe to assert on.
///
/// Use when a test must show a secret was issued (or withheld) without the
/// value reaching an assertion message.
export function secretPresence(value: unknown): {
  present: boolean;
  lengthClass: SecretLengthClass;
} {
  if (value === null || value === undefined || value === "") {
    return { present: false, lengthClass: "absent" };
  }
  const length =
    typeof value === "string" ? value.length : stableStringify(value).length;
  const lengthClass: SecretLengthClass =
    length < 16 ? "short" : length < 128 ? "medium" : "long";
  return { present: true, lengthClass };
}
