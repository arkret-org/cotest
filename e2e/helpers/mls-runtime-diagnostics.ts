const runtimeCodes = [
  "MLS reconciliation requires a complete verified membership cut",
  "MLS reconciliation checkpoint key is unavailable",
  "MLS reconciliation checkpoint restore failed",
  "MLS reconciliation verified leaf bindings are unavailable",
  "MLS reconciliation checkpoint has no accepted group-state reference",
  "MLS reconciliation verified current group result is unavailable",
  "MLS reconciliation current result does not match local checkpoint",
  "MLS application payload remains decryption-pending",
  "public original content material boundary",
  "public historical attribution remains pending",
  "live historical attribution remains pending",
  "retained historical attribution remains pending",
  "retained public historical attribution remains pending",
  "accepted MLS artifact convergence is pending",
  "accepted MLS Welcome is not installable yet",
  "MLS send readiness dependencies observed",
  "ordinary message pre-submit stage",
  "ordinary message pre-submit gate failed",
  "ordinary message outbound stage",
  "encrypted message authoring failed",
  "Realm stream follow interrupted; retrying",
  "committed chat producer proof rejected",
  "Ordinary timeline projection inputs observed",
  "Ordinary live checkpoint waits for its continuous history",
  "timeline presentation host did not mount",
  "timeline presentation host failed",
  "timeline configuration could not be serialized",
] as const;

// Only fixed code labels, booleans and public epoch counters cross this boundary.
// In particular, never retain the original console message or error object.
export function publicMlsRuntimeDiagnostic(raw: string) {
  const code = runtimeCodes.find(code => raw.includes(code));
  if (!code) return undefined;
  const fields: Record<string, boolean | string> = {};
  for (const field of ["passed", "scope_matches", "epoch_matches", "commit_matches", "key_access_covered", "checkpoint_present", "private_root_available", "current_cut_ready", "required_ready", "scope_current_known"]) {
    const match = raw.match(new RegExp(`\\b${field}["']?\\s*[:=]\\s*(true|false)\\b`));
    if (match) fields[field] = match[1] === "true";
  }
  for (const field of ["payload_epoch", "snapshot_epoch", "raw_message_rows", "live_raw_message_rows", "projected_message_rows", "stored_position", "candidate_position"]) {
    const match = raw.match(new RegExp(`\\b${field}["']?\\s*[:=]\\s*(?:Some\\()?["']?([0-9]{1,16})\\b`));
    if (match) fields[field] = match[1];
  }
  const stage = raw.match(/\bstage["']?\s*[:=]\s*["']?([a-z_]+)\b/)?.[1];
  if (stage && ["freezing", "authoring", "frozen", "persisting", "waiting_writer", "driving", "settled"].includes(stage)) fields.stage = stage;
  const gate = raw.match(/\bgate["']?\s*[:=]\s*["']?([a-z_]+)\b/)?.[1];
  if (gate && ["retained_root", "public_epoch", "installed_epoch"].includes(gate)) fields.gate = gate;
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
    "HTTP request failed",
    "application current is unavailable",
    "verified native authoring authority",
  ].filter(reason => raw.includes(reason));
  return { code, fields, categories, ...(reasons.length ? { reasons } : {}) };
}

