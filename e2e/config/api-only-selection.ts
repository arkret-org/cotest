// The `joint-api` project's file set, derived from `api-only-migration.json`.
//
// That manifest is already the closed set of Playwright specs that never reach
// a browser: `scripts/check_api_only_migration.py` fails when a browserless
// spec is in neither `specialized_api_lanes` nor `pending_migration`, and fails
// again when a listed source has gone missing or started driving a browser.
// Reading it here rather than restating the list keeps one source of truth —
// two renames in one day (`4fa5656f`, `4c6f69ad`) already showed what a second
// hand-written copy costs.
//
// `pending_migration` is migration debt: entries leave as R03 batch C ports
// them to Rust. `specialized_api_lanes` is not debt — those lanes stay in
// Playwright — so an empty `pending_migration` does not by itself mean this
// project can be deleted.

import { readFileSync } from "node:fs";
import path from "node:path";

const MANIFEST_SCHEMA = "arkret.api-only-rust-migration.v1";
// Every entry is workspace-relative, and every entry the Playwright projects
// care about lives under the suite's own test root.
const TESTS_PREFIX = "cotest/e2e/tests/";

type ApiOnlyManifest = {
  schema?: unknown;
  specialized_api_lanes?: unknown;
  pending_migration?: unknown;
};

function fail(reason: string): never {
  throw new Error(
    `api-only-migration.json cannot drive the joint-api project: ${reason}`,
  );
}

function pendingSources(value: unknown): string[] {
  if (!Array.isArray(value)) {
    fail("pending_migration must be an array");
  }
  return value.map((entry, index) => {
    if (typeof entry !== "object" || entry === null) {
      fail(`pending_migration[${index}] must be an object`);
    }
    const source = (entry as { source?: unknown }).source;
    if (typeof source !== "string") {
      fail(`pending_migration[${index}] has no string source`);
    }
    return source;
  });
}

function specializedSources(value: unknown): string[] {
  if (!Array.isArray(value) || !value.every((item) => typeof item === "string")) {
    fail("specialized_api_lanes must be a string array");
  }
  return value as string[];
}

/**
 * Spec paths, relative to the suite `testDir` (`./tests`), that reach no
 * browser.
 *
 * Fails closed: a manifest that cannot be read, a duplicate entry, a path that
 * escapes the test root, or a listed spec that is not on disk aborts the
 * Playwright run rather than silently selecting fewer tests. Selecting nothing
 * is also an error — a `joint-api` run that collects zero files would report
 * green having tested nothing.
 */
export function apiOnlyTestMatch(e2eRoot: string): string[] {
  const manifestPath = path.resolve(e2eRoot, "..", "api-only-migration.json");
  let manifest: ApiOnlyManifest;
  try {
    manifest = JSON.parse(readFileSync(manifestPath, "utf8")) as ApiOnlyManifest;
  } catch (error) {
    fail(`${manifestPath} is unreadable (${String(error)})`);
  }
  if (manifest.schema !== MANIFEST_SCHEMA) {
    fail(`unsupported schema ${String(manifest.schema)}`);
  }

  const sources = [
    ...specializedSources(manifest.specialized_api_lanes),
    ...pendingSources(manifest.pending_migration),
  ];

  const seen = new Set<string>();
  const relative: string[] = [];
  for (const source of sources) {
    if (seen.has(source)) {
      fail(`duplicate source ${source}`);
    }
    seen.add(source);
    if (!source.startsWith(TESTS_PREFIX) || source.includes("..")) {
      fail(`source outside ${TESTS_PREFIX}: ${source}`);
    }
    const withinTests = source.slice(TESTS_PREFIX.length);
    // `testMatch` entries are matched against the file path, so a spec that no
    // longer exists would just contribute nothing. The Python gate already
    // refuses that state; check here too, because this project's whole claim is
    // that its selection equals the manifest.
    const onDisk = path.resolve(e2eRoot, "tests", withinTests);
    try {
      readFileSync(onDisk);
    } catch {
      fail(`listed source is not on disk: ${source}`);
    }
    relative.push(withinTests);
  }

  if (relative.length === 0) {
    fail("selected no specs; delete the project instead of running it empty");
  }
  return relative;
}
