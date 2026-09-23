// Generate TypeScript mirrors of the closed arkret-spec object schemas.
//
// The e2e suite hand-builds protocol objects as TS object literals. Nothing
// tied those literals to the normative schemas, so an unregistered member
// (`plaintext_visible_services`, `history_access`, `retention_policy`)
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

/**
 * Schema file (optionally one `$defs` entry inside it) → exported TS type name.
 *
 * A target belongs here only when the spec node is a *closed* object: that is
 * what makes an unregistered member a `tsc` error. Hand-written types that
 * mirror something cotest owns rather than something the spec defines (the
 * CLI-command DTOs, the local signer bookkeeping) stay hand-written.
 */
const TARGETS = [
  { file: "realm-join-intake.schema.json", pointer: "#/$defs/self_prepare_request_body", typeName: "RealmJoinPrepareRequestBody" },
  { file: "message-authoring.schema.json", pointer: "#/$defs/message_prepare_request_body", typeName: "MessagePrepareRequestBody" },
  { file: "identity-resolution.schema.json", pointer: "#/$defs/public_principal_resolution", typeName: "PublicPrincipalResolution" },
  { file: "circle-operations.schema.json", pointer: "#/$defs/circle_view", typeName: "CircleView" },
  { file: "circle-operations.schema.json", pointer: "#/$defs/circle_membership_outcome", typeName: "CircleMembershipOutcome" },
  { file: "contact-operations.schema.json", pointer: "#/$defs/contact_peer", typeName: "ContactPeer" },
  { file: "common-ids.schema.json", pointer: "#/$defs/actor_id", typeName: "ActorId" },
  { file: "common-ids.schema.json", pointer: "#/$defs/account_id", typeName: "AccountId" },
  { file: "invite.schema.json", typeName: "InviteObject" },
  { file: "event-payload.schema.json", pointer: "#/$defs/membership_payload", typeName: "MembershipPayload" },
  { file: "realm.schema.json", typeName: "RealmObject" },
  // The closed security-root a `ak.realm.create` carries. Its three initial
  // policy axes live here, not in separate bootstrap facet Events.
  { file: "realm-genesis.schema.json", typeName: "RealmGenesisObject" },
  { file: "space.schema.json", typeName: "SpaceObject" },
  { file: "capability-grant.schema.json", typeName: "CapabilityGrantObject" },
  { file: "event-payload.schema.json", pointer: "#/$defs/capability_grant_payload", typeName: "CapabilityGrantPayload" },
  {
    file: "invite-delivery-request.schema.json",
    typeName: "InviteDeliveryRequestBody",
  },
  // The client-facing dispatch body is its own closed `$def`, not a projection
  // of the peer body: it carries `invite_event_id` instead of `invite_event`
  // and refers to a previously accepted Event (the inviter-side Station
  // builds those from its own accepted state). Deriving it from the peer type
  // with `Omit` silently inherited every future peer-only member, so it is
  // generated from the spec node that actually defines it.
  {
    file: "invite-delivery-request.schema.json",
    pointer: "#/$defs/self_invite_dispatch_request_body",
    typeName: "SelfInviteDispatchRequestBody",
  },
  // One independent stream's current head. A Realm, each Circle and each
  // Sidecar own separate linear streams, so a head names its own stream and
  // there is no Realm-global position.
  {
    file: "realm-commit.schema.json",
    pointer: "#/$defs/stream_head",
    typeName: "CommitStreamHead",
  },
  {
    file: "service-operation-dtos.schema.json",
    pointer: "#/$defs/EventAdmissionSubmission",
    typeName: "EventAdmissionSubmission",
  },
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

/**
 * The bound only exists to stop a self-referential `$ref` chain, so keep it
 * well above the deepest real one. It was 12, which is *below* the real depth
 * of `EventFederationSubmission` → Control Proposal Ack → proof → digest; the
 * effect was not an error but a silent `unknown`, i.e. a generated type that
 * constrains nothing. Raise this rather than accept a bare `unknown`.
 */
const MAX_DEPTH = 32;

function isPlainObject(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Fold the object-shaped branches of an `allOf` into one node.
 *
 * Branches that only constrain (`not`, `if`/`then`, bare `type: object`)
 * contribute nothing to the member set and are skipped. Returns `undefined`
 * when no branch carries `properties`, so the caller can fall through.
 *
 * The merged node is rendered against a single file, because a local `#/$defs/…`
 * inside a merged property only resolves there. When two property-carrying
 * branches come from different files that assumption breaks, so this bails out
 * rather than resolve pointers against the wrong document.
 */
function mergeAllOf(branches, file, depth) {
  const properties = {};
  const required = new Set();
  let closed = false;
  let sourceFile;
  let sawProperties = false;
  for (const rawBranch of branches) {
    let branch = rawBranch;
    let branchFile = file;
    let hops = 0;
    while (isPlainObject(branch) && typeof branch.$ref === "string" && hops < 8) {
      const resolved = deref(branch.$ref, branchFile);
      if (resolved.node === undefined) break;
      branch = resolved.node;
      branchFile = resolved.file;
      hops += 1;
    }
    if (!isPlainObject(branch) || !isPlainObject(branch.properties)) continue;
    if (sourceFile !== undefined && sourceFile !== branchFile) return undefined;
    sourceFile = branchFile;
    sawProperties = true;
    Object.assign(properties, branch.properties);
    for (const name of branch.required ?? []) required.add(name);
    if (branch.additionalProperties === false ||
      branch.unevaluatedProperties === false) {
      closed = true;
    }
  }
  if (!sawProperties || depth > MAX_DEPTH) return undefined;
  return {
    node: {
      type: "object",
      properties,
      required: [...required],
      ...(closed ? { additionalProperties: false } : {}),
    },
    file: sourceFile,
  };
}

/**
 * Render one schema node as a TS type expression.
 * `depth` guards against a self-referential `$ref` chain.
 */
function renderType(node, file, indent, depth = 0) {
  if (!isPlainObject(node) || depth > MAX_DEPTH) return "unknown";

  if (typeof node.$ref === "string") {
    const resolved = deref(node.$ref, file);
    if (resolved.node === undefined) return "unknown";
    return renderType(resolved.node, resolved.file, indent, depth + 1);
  }

  // A node that is *only* a composition (`allOf` with no own shape) still has
  // one member set; merge it so the target does not silently degrade to
  // `unknown`. A node that carries its own `properties` is left alone — its
  // `allOf` is the conditional-refinement dispatch this generator skips.
  if (
    Array.isArray(node.allOf) && !node.properties && !node.oneOf &&
    !node.anyOf && node.type !== "array"
  ) {
    const merged = mergeAllOf(node.allOf, file, depth);
    if (merged) return renderObject(merged.node, merged.file, indent, depth);

    // Primitive profiles commonly intersect a reusable base (`opaque_id`)
    // with a second string refinement. They carry no object properties, so
    // mergeAllOf intentionally has nothing to merge; still preserve the
    // common primitive instead of silently widening the generated type to
    // `unknown`. Constraint-only branches render as unknown and can be
    // ignored because this generator pins wire shapes, not refinements.
    const concrete = [
      ...new Set(
        node.allOf
          .map((branch) => renderType(branch, file, indent, depth + 1))
          .filter((part) => part !== "unknown"),
      ),
    ];
    if (concrete.length === 1) return concrete[0];
    if (concrete.length > 1) return concrete.join(" & ");
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
  const blocks = TARGETS.map(({ file, pointer, typeName }) => {
    const root = loadSchema(file);
    const node = pointer ? resolvePointer(root, pointer.replace(/^#/, "")) : root;
    if (node === undefined) {
      throw new Error(`${file}${pointer ?? ""} does not resolve`);
    }
    const source = pointer ? `${file}${pointer}` : file;
    const body = renderType(node, file, "");
    return `/** \`${source}\` — closed object schema. */\nexport type ${typeName} = ${body};\n`;
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
