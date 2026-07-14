import type { Page } from "@playwright/test";

export type BrowserStorageAudit = {
  indexedDbEnumerationSupported: boolean;
  indexedDbEntryKeys: string[];
  indexedDbStores: string[];
  localStorageKeys: string[];
  plaintextMatches: string[];
  weakE2eeLocalStorageKeys: string[];
};

const WEAK_E2EE_LOCAL_STORAGE_MARKERS = [
  "arkret.pending_logout.v1",
  "inkson.e2ee_plaintext_cache.v1.",
  "inkson.mls_history_secret.v1.",
  "inkson.mls_key_package.identity_state.v1.",
  "inkson.mls_snapshot.account_secret.",
  "inkson.recovery.pending_key.v1.",
];

export async function auditBrowserStorage(
  page: Page,
  plaintextNeedles: string[],
): Promise<BrowserStorageAudit> {
  return page.evaluate(
    async ({ needles, weakMarkers }) => {
      const plaintextMatches: string[] = [];
      const localStorageKeys: string[] = [];
      const weakE2eeLocalStorageKeys: string[] = [];
      const indexedDbEntryKeys: string[] = [];
      const indexedDbStores: string[] = [];

      const inspectValue = async (root: unknown): Promise<string[]> => {
        const fragments: string[] = [];
        const seen = new Set<object>();
        const visit = async (value: unknown): Promise<void> => {
          if (value == null) {
            fragments.push(String(value));
            return;
          }
          if (
            typeof value === "string" ||
            typeof value === "number" ||
            typeof value === "boolean" ||
            typeof value === "bigint"
          ) {
            fragments.push(String(value));
            return;
          }
          if (value instanceof ArrayBuffer) {
            fragments.push(new TextDecoder().decode(new Uint8Array(value)));
            return;
          }
          if (ArrayBuffer.isView(value)) {
            const view = value as ArrayBufferView;
            fragments.push(
              new TextDecoder().decode(
                new Uint8Array(
                  view.buffer as ArrayBuffer,
                  view.byteOffset,
                  view.byteLength,
                ),
              ),
            );
            return;
          }
          if (value instanceof Blob) {
            fragments.push(
              new TextDecoder().decode(new Uint8Array(await value.arrayBuffer())),
            );
            return;
          }
          if (typeof CryptoKey !== "undefined" && value instanceof CryptoKey) {
            fragments.push(
              JSON.stringify({
                algorithm: value.algorithm,
                extractable: value.extractable,
                type: value.type,
                usages: value.usages,
              }),
            );
            return;
          }
          if (typeof value !== "object" || seen.has(value)) {
            return;
          }
          seen.add(value);
          if (value instanceof Map) {
            for (const [key, item] of value.entries()) {
              await visit(key);
              await visit(item);
            }
            return;
          }
          if (value instanceof Set) {
            for (const item of value.values()) {
              await visit(item);
            }
            return;
          }
          for (const [key, item] of Object.entries(value)) {
            fragments.push(key);
            await visit(item);
          }
        };
        await visit(root);
        return fragments;
      };

      const recordMatches = (surface: string, fragments: string[]) => {
        const searchable = fragments.join("\n");
        for (const needle of needles) {
          if (needle && searchable.includes(needle)) {
            plaintextMatches.push(`${surface}: ${needle}`);
          }
        }
      };

      for (let index = 0; index < localStorage.length; index += 1) {
        const key = localStorage.key(index);
        if (!key) {
          continue;
        }
        localStorageKeys.push(key);
        if (weakMarkers.some((marker) => key.includes(marker))) {
          weakE2eeLocalStorageKeys.push(key);
        }
        recordMatches(`localStorage/${key}`, [
          key,
          localStorage.getItem(key) ?? "",
        ]);
      }

      const factory = indexedDB as IDBFactory & {
        databases?: () => Promise<Array<{ name?: string; version?: number }>>;
      };
      const indexedDbEnumerationSupported =
        typeof factory.databases === "function";
      const databaseNames = indexedDbEnumerationSupported
        ? (await factory.databases!())
            .map((database) => database.name)
            .filter((name): name is string => Boolean(name))
        : [];

      const requestResult = <T>(request: IDBRequest<T>): Promise<T> =>
        new Promise<T>((resolve, reject) => {
          request.onsuccess = () => resolve(request.result);
          request.onerror = () =>
            reject(request.error ?? new Error("IndexedDB request failed"));
        });
      const openDatabase = (name: string): Promise<IDBDatabase> =>
        new Promise<IDBDatabase>((resolve, reject) => {
          const request = indexedDB.open(name);
          request.onsuccess = () => resolve(request.result);
          request.onerror = () =>
            reject(request.error ?? new Error(`IndexedDB open failed: ${name}`));
        });

      for (const databaseName of databaseNames.sort()) {
        const database = await openDatabase(databaseName);
        try {
          for (const storeName of Array.from(database.objectStoreNames).sort()) {
            indexedDbStores.push(`${databaseName}/${storeName}`);
            const transaction = database.transaction(storeName, "readonly");
            const store = transaction.objectStore(storeName);
            const [keys, values] = await Promise.all([
              requestResult(store.getAllKeys()),
              requestResult(store.getAll()),
            ]);
            for (let index = 0; index < values.length; index += 1) {
              const keyFragments = await inspectValue(keys[index]);
              const keyLabel = keyFragments.join("|");
              indexedDbEntryKeys.push(
                `${databaseName}/${storeName}/${keyLabel}`,
              );
              const valueFragments = await inspectValue(values[index]);
              recordMatches(
                `indexedDB/${databaseName}/${storeName}/${keyLabel}`,
                [...keyFragments, ...valueFragments],
              );
            }
          }
        } finally {
          database.close();
        }
      }

      return {
        indexedDbEnumerationSupported,
        indexedDbEntryKeys,
        indexedDbStores,
        localStorageKeys,
        plaintextMatches,
        weakE2eeLocalStorageKeys,
      };
    },
    {
      needles: plaintextNeedles,
      weakMarkers: WEAK_E2EE_LOCAL_STORAGE_MARKERS,
    },
  );
}
