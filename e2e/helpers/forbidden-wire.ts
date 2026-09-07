import { readFileSync } from "node:fs";
import { resolve } from "node:path";

type Selector = { document_kind: string; schema_ref: string; instance_pointer: string; match_scope: string };
type Entry = { id: string; context: string; rejection_level: string; match: { kind: string; values: string[]; value_pointer?: string } };
export type WireViolation = { id: string; rule: string; path: string; detail: string };

/** Interpret the spec registry; no private context-name table or id heuristics. */
export function forbiddenWireScanner(artifactsRoot: string) {
  const registry = JSON.parse(readFileSync(resolve(artifactsRoot, "registry/forbidden-wire-fields.json"), "utf8")) as {
    entries: Entry[]; context_definitions: Record<string, { selectors: Selector[] }>;
  };
  const kinds = JSON.parse(readFileSync(resolve(artifactsRoot, "registry/event-kind-registry.json"), "utf8")) as {
    event_kinds: Array<{ event_kind: string; payload_schema_ref: string }>;
  };
  for (const entry of registry.entries) {
    if (!registry.context_definitions[entry.context] || !entry.match) throw new Error(`undefined forbidden-wire contract: ${entry.context}/${entry.id}`);
  }
  function* pointers(value: unknown, pointer: string, path = ""): Generator<{ value: unknown; path: string }> {
    if (!pointer) { yield { value, path }; return; }
    if (!value || typeof value !== "object") return;
    const [raw, ...rest] = pointer.slice(1).split("/");
    const tail = rest.length ? `/${rest.join("/")}` : "";
    const token = raw.replace(/~1/g, "/").replace(/~0/g, "~");
    for (const [key, child] of Object.entries(value)) {
      if (raw === "*" || token === key) yield* pointers(child, tail, `${path}/${key.replace(/~/g, "~0").replace(/\//g, "~1")}`);
    }
  }
  function* nodes(value: unknown, path: string, recursive: boolean): Generator<{ value: unknown; path: string }> {
    yield { value, path };
    if (recursive && value && typeof value === "object") {
      for (const [key, child] of Object.entries(value)) yield* nodes(child, `${path}/${key}`, true);
    }
  }
  function scan(document: unknown, documentKind: string, schemaRef: string): WireViolation[] {
    schemaRef = schemaRef.replace(/^\.\//, "").replace(/^schemas\//, "");
    const violations: WireViolation[] = [];
    for (const entry of registry.entries) {
      if (entry.rejection_level !== "hard_reject") continue;
      for (const selector of registry.context_definitions[entry.context].selectors) {
        if (!(selector.document_kind === documentKind || selector.document_kind === "schema_instance" || (selector.document_kind === "wire" && documentKind !== "executable_artifact"))) continue;
        if (selector.schema_ref !== "*" && selector.schema_ref !== schemaRef) continue;
        for (const root of pointers(document, selector.instance_pointer)) {
          for (const node of nodes(root.value, root.path, selector.match_scope === "descendants")) {
            const object = node.value && typeof node.value === "object" ? node.value as Record<string, unknown> : undefined;
            for (const expected of entry.match.values) {
              let hit = false;
              switch (selector.match_scope === "patch" && ["field", "path"].includes(entry.match.kind) ? "patch_path" : entry.match.kind) {
                case "field": hit = !!object && Object.hasOwn(object, expected); break;
                case "path": hit = [...pointers(node.value, `/${expected.split(".").join("/")}`)].length > 0; break;
                case "patch_path": hit = !!object?.patch && typeof object.patch === "object" && !Array.isArray(object.patch) && Object.entries(object.patch).some(([path, op]) => {
                  if (path === expected || path.startsWith(`${expected}.`)) return true;
                  if (!expected.startsWith(`${path}.`)) return false;
                  const explicit = op && typeof op === "object" && Object.hasOwn(op, "$op") ? op as { $op: string; value?: unknown } : undefined;
                  const replacement = explicit ? ["set", "add"].includes(explicit.$op) ? explicit.value : undefined : op;
                  return [...pointers(replacement, `/${expected.slice(path.length + 1).split(".").join("/")}`)].length > 0;
                }); break;
                case "value": case "prefix": case "pattern":
                  hit = [...pointers(node.value, entry.match.value_pointer ?? "")].some(({ value }) => typeof value === "string" && (
                    entry.match.kind === "value" ? value === expected : entry.match.kind === "prefix" ? value.startsWith(expected) : new RegExp(expected).test(value)
                  )); break;
                default: throw new Error(`unknown matcher ${entry.match.kind}`);
              }
              if (hit) violations.push({ id: entry.id, rule: entry.match.kind, path: node.path, detail: expected });
            }
          }
        }
      }
    }
    return violations;
  }
  function scanEvent(event: Record<string, unknown>): WireViolation[] {
    const violations = scan(event, "event_envelope", "event-envelope.schema.json");
    const descriptor = kinds.event_kinds.find(row => row.event_kind === event.kind);
    if (!descriptor) throw new Error(`unregistered Event kind: ${event.kind}`);
    violations.push(...scan(event.payload, "event_payload", descriptor.payload_schema_ref).map(v => ({ ...v, path: `/payload${v.path}` })));
    return violations;
  }
  return { scan, scanEvent, ruleCount: registry.entries.length };
}
