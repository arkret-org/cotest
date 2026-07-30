// Generate TypeScript mirrors of the closed arkret-spec object schemas.
//
// The e2e suite hand-builds protocol objects as TS object literals. Nothing
// tied those literals to the normative schemas, so an unregistered member
// (`plaintext_visible_services`, `history_sharing_policy`, `retention_policy`)
// only failed on a live server — or, worse, never failed because the test that
// would have caught it was never run. Generating the types from
// `spec/v1/artifacts/schemas/*.json` and annotating the literals turns that
// class of drift into a `tsc --noEmit` error.
//
//   npm run gen:wire-types     regenerate the committed output
//   npm run check:wire-types   fail when the committed output is stale
//
// Only the wire *shape* is generated. Conditional refinements (`allOf` if/then,
// `not`, `pattern`, numeric bounds) stay with the server and the Rust models;
// this file exists to pin the member set and the primitive kinds.

import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
// scripts → e2e → cotest → arkret root → arkret-spec/spec/v1/artifacts/schemas.
const SCHEMAS_ROOT = resolve(
  HERE,
  "..",
  "..",
  "..",
  "arkret-spec",
  "spec",
  "v1",
  "artifacts",
  "schemas",
);
export const OUTPUT_PATH = resolve(
  HERE,
  "..",
  "helpers",
  "generated",
  "spec-wire-objects.ts",
);

/** Schema file → exported TS type name. */
const TARGETS = [
  { file: "realm.schema.json", typeName: "RealmObject" },
  { file: "space.schema.json", typeName: "SpaceObject" },
];

const schemaCache = new Map();

function loadSchema(file) {
  if (!schemaCache.has(file)) {
    schemaCache.set(
      file,
      JSON.parse(readFileSync(join(SCHEMAS_ROOT, file), "utf8")),
    );
  }
  return schemaCache.get(file);
}

function resolvePointer(root, pointer) {
  let node = root;
  for (const rawSegment of pointer.split("/").slice(1)) {
    const segment = rawSegment.replace(/~1/g, "/").replace(/~0/g, "~");
    if (node === undefined || node === null) return undefined;
    node = node[segment];
  }
  return node;
}

/** Resolve a `$ref` against the file it appears in. */
function deref(ref, file) {
  const [rawTarget, pointer = ""] = ref.split("#");
  const target = rawTarget.replace(/^\.\//, "");
  const nextFile = target === "" ? file : target;
  const root = loadSchema(nextFile);
  const node = pointer === "" ? root : resolvePointer(root, pointer);
  return { node, file: nextFile };
}

const INDENT = "  ";

function isPlainObject(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Render one schema node as a TS type expression.
 * `depth` guards against a self-referential `$ref` chain.
 */
function renderType(node, file, indent, depth = 0) {
  if (!isPlainObject(node) || depth > 12) return "unknown";

  if (typeof node.$ref === "string") {
    const resolved = deref(node.$ref, file);
    if (resolved.node === undefined) return "unknown";
    return renderType(resolved.node, resolved.file, indent, depth + 1);
  }

  for (const key of ["oneOf", "anyOf"]) {
    if (Array.isArray(node[key]) && node[key].length > 0) {
      const parts = node[key].map((branch) =>
        renderType(branch, file, indent, depth + 1),
      );
      const unique = [...new Set(parts)];
      return unique.length === 1 ? unique[0] : unique.join(" | ");
    }
  }

  if (node.const !== undefined) return JSON.stringify(node.const);

  if (Array.isArray(node.enum) && node.enum.length > 0) {
    return [...new Set(node.enum.map((value) => JSON.stringify(value)))].join(
      " | ",
    );
  }

  const declared = Array.isArray(node.type) ? node.type : [node.type];
  const types = declared.filter((value) => typeof value === "string");

  if (types.length > 1) {
    return types
      .map((single) => renderType({ ...node, type: single }, file, indent, depth))
      .join(" | ");
  }

  const type = types[0] ?? (node.properties ? "object" : undefined);
  switch (type) {
    case "string":
      return "string";
    case "integer":
    case "number":
      return "number";
    case "boolean":
      return "boolean";
    case "null":
      return "null";
    case "array": {
      const item = renderType(node.items ?? {}, file, indent, depth + 1);
      return /[ |&]/.test(item) ? `Array<${item}>` : `${item}[]`;
    }
    case "object":
      return renderObject(node, file, indent, depth);
    default:
      return "unknown";
  }
}

function renderObject(node, file, indent, depth) {
  const properties = isPlainObject(node.properties) ? node.properties : {};
  const names = Object.keys(properties);
  const open = node.additionalProperties !== false &&
    node.unevaluatedProperties !== false;
  if (names.length === 0) {
    return open ? "Record<string, unknown>" : "Record<string, never>";
  }
  const required = new Set(
    Array.isArray(node.required) ? node.required : [],
  );
  const inner = indent + INDENT;
  const lines = names.map((name) => {
    const optional = required.has(name) ? "" : "?";
    const rendered = renderType(properties[name], file, inner, depth + 1);
    return `${inner}${JSON.stringify(name)}${optional}: ${rendered};`;
  });
  if (open) {
    lines.push(`${inner}[key: string]: unknown;`);
  }
  return `{\n${lines.join("\n")}\n${indent}}`;
}

const HEADER = `// GENERATED FILE — DO NOT EDIT BY HAND.
//
// Source: arkret-spec/spec/v1/artifacts/schemas/*.json
// Producer: e2e/scripts/generate-wire-types.mjs
//
// Regenerate with \`npm run gen:wire-types\`; \`npm run check:wire-types\` fails
// when this file no longer matches the spec artifacts. Annotate hand-built wire
// literals with these types so an unregistered member is a \`tsc\` error rather
// than a live-server rejection.
`;

export function renderModule() {
  const blocks = TARGETS.map(({ file, typeName }) => {
    const schema = loadSchema(file);
    const body = renderType(schema, file, "");
    return `/** \`${file}\` — closed object schema. */\nexport type ${typeName} = ${body};\n`;
  });
  return `${HEADER}\n${blocks.join("\n")}`;
}

const invokedDirectly =
  process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));

if (invokedDirectly) {
  // The committed output is what `tsc --noEmit` consumes, so the type gate
  // itself never needs the spec repo. Regenerating does. A checkout that has
  // only `cotest` says so instead of silently reporting success.
  if (!existsSync(SCHEMAS_ROOT)) {
    process.stdout.write(
      `SKIP spec wire types: ${SCHEMAS_ROOT} is absent (sibling arkret-spec checkout required)\n`,
    );
    process.exit(0);
  }
  const rendered = renderModule();
  const check = process.argv.includes("--check");
  if (check) {
    let current = "";
    try {
      current = readFileSync(OUTPUT_PATH, "utf8");
    } catch {
      current = "";
    }
    if (current !== rendered) {
      process.stderr.write(
        `spec wire types are stale: ${OUTPUT_PATH}\n` +
          "run `npm run gen:wire-types` and commit the result\n",
      );
      process.exit(1);
    }
    process.stdout.write("spec wire types are up to date\n");
  } else {
    writeFileSync(OUTPUT_PATH, rendered, "utf8");
    process.stdout.write(`wrote ${OUTPUT_PATH}\n`);
  }
}
