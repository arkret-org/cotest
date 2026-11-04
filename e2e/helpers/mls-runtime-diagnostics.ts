const runtimeCodes = [
  "MLS reconciliation requires a complete verified membership cut",
  "MLS reconciliation checkpoint key is unavailable",
  "MLS reconciliation checkpoint restore failed",
  "MLS reconciliation verified leaf bindings are unavailable",
  "MLS reconciliation checkpoint has no accepted group-state reference",
  "MLS reconciliation verified current group result is unavailable",
  "MLS reconciliation current result does not match local checkpoint",
  "MLS application payload remains decryption-pending",
  "accepted MLS artifact convergence is pending",
  "accepted MLS Welcome is not installable yet",
  "MLS send readiness dependencies observed",
  "Realm stream follow interrupted; retrying",
  "committed chat producer proof rejected",
] as const;

// Only fixed code labels, booleans and public epoch counters cross this boundary.
// In particular, never retain the original console message or error object.
export function publicMlsRuntimeDiagnostic(raw: string) {
  const code = runtimeCodes.find(code => raw.includes(code));
  if (!code) return undefined;
  const fields: Record<string, boolean | string> = {};
  for (const field of ["scope_matches", "epoch_matches", "commit_matches", "key_access_covered", "checkpoint_present", "private_root_available", "current_cut_ready", "required_ready", "scope_current_known"]) {
    const match = raw.match(new RegExp(`${field}["']?\\s*[:=]\\s*(true|false)\\b`));
    if (match) fields[field] = match[1] === "true";
  }
  for (const field of ["payload_epoch", "snapshot_epoch"]) {
    const match = raw.match(new RegExp(`${field}["']?\\s*[:=]\\s*(?:Some\\()?["']?([0-9]{1,16})\\b`));
    if (match) fields[field] = match[1];
  }
  const categories = ["unavailable", "fork", "session", "ratchet", "epoch", "roster", "reference", "secret", "base"].filter(word => raw.toLowerCase().includes(word));
  const reasons = [
    "current cut regresses or forks the durable stream",
    "live current route ended",
    "live current account changed",
    "current cut changed",
    "read fence",
    "superseded",
    "generation",
    "frozen head",
    "floor",
    "proof",
    "digest",
    "signature",
  ].filter(reason => raw.includes(reason));
  return { code, fields, categories, ...(reasons.length ? { reasons } : {}) };
}

