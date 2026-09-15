// Isolation rules for the in-worker memo of canonical provisioning.
//
// `ensureRegistered` founds a principal through Coauth once and hands the same
// identity to every later caller for the same user. That memo is load-bearing
// rather than an optimization: the Coauth handle it registers is a fresh
// `e2e-oidc-<uuid>` unrelated to the caller's user name, so the server has
// nothing to deduplicate against. Two lookups that should have hit one entry
// therefore do not fail loudly -- they quietly found a *second* principal and
// rebind the caller's object to it, orphaning every Realm, Event and grant the
// first one created.
//
// So the key has to name the thing being provisioned exactly, and a user object
// must not be allowed to mean two principals. This module is that rule, kept
// free of Playwright imports so `scripts/provisioning-cache.test.mjs` can drive
// it directly.
//
// What this is NOT: a stand-in for server-side idempotency. The memo lives in
// one worker process and answers "has *this* worker already founded this
// principal". Whether the Authority rejects a duplicate registration is a
// property of the Authority, and a test that means to assert it must issue the
// second request rather than ask this cache.

/// The full address of one canonical provisioning.
///
/// `stationBaseUrl` and `authorityBaseUrl` are resolved URLs, never the
/// `SolandKey` alias: `undefined`, `"default"` and `"server1"` are three names
/// for one Station, and a memo keyed by the name provisions the same user once
/// per name.
export type ProvisioningTarget = {
  stationBaseUrl: string;
  authorityBaseUrl: string;
  principalName: string;
};

/// The identity fields canonical provisioning rebinds on the caller's user.
export type ProvisionedIdentity = {
  id: string;
  did: string;
  deviceId: string;
  handle: string;
  displayName: string;
};

const IDENTITY_FIELDS = [
  "id",
  "did",
  "deviceId",
  "handle",
  "displayName",
] as const;

/**
 * The cache key for one provisioning target.
 *
 * JSON rather than a delimiter join: a base URL may contain any character a
 * separator might pick, and a key that can be collided by punctuation is the
 * same defect one level down.
 */
export function provisioningKey(target: ProvisioningTarget): string {
  for (const [field, value] of Object.entries(target)) {
    if (typeof value !== "string" || value.length === 0) {
      throw new Error(
        `provisioning cache key needs a non-empty ${field}; got ${JSON.stringify(value)}`,
      );
    }
  }
  return JSON.stringify([
    target.stationBaseUrl.replace(/\/$/, ""),
    target.authorityBaseUrl.replace(/\/$/, ""),
    target.principalName,
  ]);
}

/**
 * Rejects an identity that is only partly founded.
 *
 * A cached half-identity is worse than a failed one: it never retries, and the
 * missing field surfaces as an unrelated assertion in whichever test happens to
 * read it first.
 */
export function assertCompleteIdentity(
  identity: ProvisionedIdentity,
  key: string,
): ProvisionedIdentity {
  const missing = IDENTITY_FIELDS.filter(
    (field) => typeof identity[field] !== "string" || identity[field].length === 0,
  );
  if (missing.length > 0) {
    throw new Error(
      `canonical provisioning for ${key} returned no ${missing.join(", ")}; ` +
        "refusing to cache a partly founded principal",
    );
  }
  return identity;
}

/**
 * Who provisioned what, within one worker.
 *
 * Two independent claims, both about not crossing numbers:
 *
 * - a user object belongs to exactly one provisioning target. A second call for
 *   the same object under a different key is a mistake somewhere in the caller
 *   -- most often a Station alias mismatch -- and rebinding the object would
 *   silently retarget everything it has already created.
 * - a founding device belongs to exactly one principal. The Station picks the
 *   device id, so two principals reported under one device id means a response
 *   was attributed to the wrong request, and no later assertion would say so.
 */
export class ProvisioningLedger {
  #claims = new WeakMap<object, string>();
  #deviceOwners = new Map<string, string>();

  /// Bind `user` to `key`, or throw if it already belongs to another target.
  claim(user: object, key: string): void {
    const existing = this.#claims.get(user);
    if (existing !== undefined && existing !== key) {
      throw new Error(
        "this user was already provisioned against a different target: " +
          `${existing} then ${key}. One user object means one principal; ` +
          "pass the same Station to every call, or use a separate user.",
      );
    }
    this.#claims.set(user, key);
  }

  /// Undo a claim after a failed provisioning, so a retry is not refused.
  release(user: object, key: string): void {
    if (this.#claims.get(user) === key) {
      this.#claims.delete(user);
    }
  }

  /// Record the founded device, or throw if it already names another principal.
  recordDevice(identity: ProvisionedIdentity): void {
    const owner = this.#deviceOwners.get(identity.deviceId);
    if (owner !== undefined && owner !== identity.id) {
      throw new Error(
        `founding device ${identity.deviceId} was already founded by ${owner}, ` +
          `now reported for ${identity.id}: a provisioning response was ` +
          "attributed to the wrong request",
      );
    }
    this.#deviceOwners.set(identity.deviceId, identity.id);
  }
}
