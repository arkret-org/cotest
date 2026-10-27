import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join } from "node:path";
import { test } from "node:test";
import ts from "typescript";
import { checkProject, findCanonicalAliases } from "./check-wire-type-ownership.mjs";

function fixture(sources, check) {
  const base = realpathSync(tmpdir());
  const root = mkdtempSync(join(base, "arkret-wire-ownership-"));
  try {
    const canonical = join(root, "spec-wire-objects.ts");
    writeFileSync(canonical, "export type CircleView = { title: string };\n");
    for (const [name, source] of Object.entries(sources)) writeFileSync(join(root, name), source);
    const project = join(root, "tsconfig.json");
    writeFileSync(project, JSON.stringify({ compilerOptions: {
      target: "ES2022", module: "ESNext", moduleResolution: "Bundler", strict: true, noEmit: true,
    }, include: ["*.ts"] }));
    check(checkProject(project, canonical));
  } finally {
    const verified = realpathSync(root);
    assert.equal(dirname(verified), base);
    assert.match(basename(verified), /^arkret-wire-ownership-/);
    rmSync(verified, { recursive: true, force: true });
  }
}

test("canonical wire names cannot gain local, import, namespace or export aliases", () => {
  fixture({
    "local.ts": 'import type { CircleView } from "./spec-wire-objects"; export type CircleOutcome = CircleView;',
    "import.ts": 'import type { CircleView as CircleRow } from "./spec-wire-objects"; export {};',
    "namespace.ts": 'import type * as wire from "./spec-wire-objects"; type CircleResult = wire.CircleView;',
    "export.ts": 'export type { CircleView as CircleEntry } from "./spec-wire-objects";',
  }, findings => {
    assert.deepEqual(new Set(findings.map(row => row.name)), new Set(["CircleOutcome", "CircleRow", "CircleResult", "CircleEntry"]));
    assert.ok(findings.every(row => row.canonical === "CircleView"));
  });
});

test("canonical re-exports and explicitly derived test projections remain distinct", () => {
  fixture({ "projection.ts": `
    import type { CircleView } from "./spec-wire-objects";
    export type { CircleView };
    type CircleTitle = CircleView["title"];
    type CircleTestProjection = Omit<CircleView, "title"> & { label: string };
  ` }, findings => assert.deepEqual(findings, []));
});

test("missing generated type ownership fails closed", () => {
  const program = ts.createProgram([], {});
  assert.throws(() => findCanonicalAliases(program, "missing-spec-wire-objects.ts"), /canonical generated wire types are absent/);
});
