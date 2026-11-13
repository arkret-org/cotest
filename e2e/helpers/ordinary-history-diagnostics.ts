import type { Page } from "@playwright/test";

// A diagnostic is not a protocol result. Never retain arbitrary hook output.
export function publicOrdinaryHistoryDiagnostic(value: unknown) {
  const output: Record<string, unknown> = {};
  if (!value || typeof value !== "object" || Array.isArray(value)) return output;
  const row = value as Record<string, unknown>;
  if (["owner_retired", "account_absent", "account_mismatch", "invalid_realm", "invalid_event", "unavailable"].includes(String(row.error))) output.error = row.error;
  for (const name of ["raw_message_count", "verified_message_count", "exact_committed_count"]) {
    if (typeof row[name] === "number" && Number.isSafeInteger(row[name]) && (row[name] as number) >= 0) output[name] = row[name];
  }
  if (typeof row.checkpoint_readable === "boolean") output.checkpoint_readable = row.checkpoint_readable;
  if (row.checkpoint_position === null || typeof row.checkpoint_position === "string" && /^[0-9]{1,20}$/.test(row.checkpoint_position)) output.checkpoint_position = row.checkpoint_position;
  if (Array.isArray(row.exact_records)) output.exact_records = row.exact_records.slice(0, 8).filter(item => item && typeof item === "object").map(item => {
    const record: Record<string, unknown> = {};
    for (const name of ["top_level_signed", "nested_signed"]) if (typeof item[name] === "boolean") record[name] = item[name];
    if (["verified", "rejected", "unresolved", "unattributed"].includes(String(item.proof_verdict))) record.proof_verdict = item.proof_verdict;
    if (typeof item.strand_id === "string" && /^ak:strand:[A-Za-z0-9_-]{44}$/.test(item.strand_id)) record.strand_id = item.strand_id;
    if (item.material && typeof item.material === "object") {
      const material: Record<string, boolean> = {};
      for (const name of ["original_decodes", "encrypted_envelope_decodes", "root_cached", "public_epoch_ready",
        "checkpoint_present", "checkpoint_epoch_matches", "epoch_reference_matches", "header_reconstructs",
        "protected_original_retained", "accepted_original_retained", "aead_opens"]) {
        if (typeof item.material[name] === "boolean") material[name] = item.material[name];
      }
      record.material = material;
    }
    return record;
  });
  return output;
}

export async function readOrdinaryHistoryDiagnostic(page: Page, realm: string, event = "") {
  const value: unknown = await page.evaluate(({ realm, event }) => {
    const hook = (window as unknown as Record<string, unknown>).__inkson_ordinary_timeline_evidence;
    if (typeof hook !== "function") return { error: "unavailable" };
    try { return JSON.parse(hook(realm, event)); }
    catch { return { error: "unavailable" }; }
  }, { realm, event });
  return publicOrdinaryHistoryDiagnostic(value);
}
