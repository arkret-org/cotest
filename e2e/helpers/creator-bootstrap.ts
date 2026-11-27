import type { Page } from "@playwright/test";

// Holder diagnostics are fixture evidence, never portable authority proof.
export async function readCreatorRecords(page: Page, checkpointCoordinates = false): Promise<Record<string, any>[]> {
  return page.evaluate(async includeCheckpoints => {
    const result = <T>(request: IDBRequest<T>): Promise<T> => new Promise((resolve, reject) => {
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
    const db = await result(indexedDB.open("inkson.secret.inkson", 1));
    try {
      const tx = db.transaction(["entries", "wrapping_keys"], "readonly");
      const entries = tx.objectStore("entries");
      const [key, names, encrypted] = await Promise.all([
        result(tx.objectStore("wrapping_keys").get("primary")) as Promise<CryptoKey>,
        result(entries.getAllKeys()),
        result(entries.getAll()),
      ]);
      if (!key || key.extractable) throw new Error("creator vault has no non-extractable wrapping key");
      const records: Record<string, any>[] = [];
      const checkpoints: Record<string, any>[] = [];
      for (let index = 0; index < names.length; index += 1) {
        const name = String(names[index]);
        const vault = name.startsWith("inkson.outbound.v1::") && name.endsWith(".standard");
        const account = includeCheckpoints && name.startsWith("inkson.local_state.v1.account.");
        if (!vault && !account) continue;
        const entry = encrypted[index] as { iv: Uint8Array; ct: Uint8Array };
        const plaintext = await crypto.subtle.decrypt(
          { name: "AES-GCM", iv: Uint8Array.from(entry.iv).buffer }, key, Uint8Array.from(entry.ct).buffer,
        );
        const state = JSON.parse(new TextDecoder().decode(plaintext));
        if (vault) records.push(...(state.creator_bootstrap_records ?? []).map((record: Record<string, any>) => ({ ...record, queue_items: state.items, ready_index: state.creator_ready_index ?? [], vault_commit_position: state.commit_position })));
        if (account) checkpoints.push(...Object.entries(state.mls_snapshots ?? {}).map(([scope, value]) => {
          const snapshot = value as Record<string, any>;
          return { scope, group: snapshot.group_id, epoch: snapshot.epoch, ref: snapshot.group_state_event_id };
        }));
      }
      if (includeCheckpoints) records.forEach(record => { record.checkpoint_coordinates = checkpoints; });
      return records;
    } finally {
      db.close();
    }
  }, checkpointCoordinates);
}
