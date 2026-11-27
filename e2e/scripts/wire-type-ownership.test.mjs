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
    writeFileSync(canonical, "export type ContactView = { title: string };\n");
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
    "local.ts": 'import type { ContactView } from "./spec-wire-objects"; export type ContactOutcome = ContactView;',
    "import.ts": 'import type { ContactView as ContactRow } from "./spec-wire-objects"; export {};',
    "namespace.ts": 'import type * as wire from "./spec-wire-objects"; type ContactResult = wire.ContactView;',
    "export.ts": 'export type { ContactView as ContactEntry } from "./spec-wire-objects";',
  }, findings => {
    assert.deepEqual(new Set(findings.map(row => row.name)), new Set(["ContactOutcome", "ContactRow", "ContactResult", "ContactEntry"]));
    assert.ok(findings.every(row => row.canonical === "ContactView"));
  });
});

test("canonical re-exports and explicitly derived test projections remain distinct", () => {
  fixture({ "projection.ts": `
    import type { ContactView } from "./spec-wire-objects";
    export type { ContactView };
    type ContactTitle = ContactView["title"];
    type ContactTestProjection = Omit<ContactView, "title"> & { label: string };
  ` }, findings => assert.deepEqual(findings, []));
});

test("missing generated type ownership fails closed", () => {
  const program = ts.createProgram([], {});
  assert.throws(() => findCanonicalAliases(program, "missing-spec-wire-objects.ts"), /canonical generated wire types are absent/);
});
