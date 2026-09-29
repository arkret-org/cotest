// `ak.relation.create` payload builder.
// Contract: arkret-spec/spec/v1/zh/models/relation.md sections 2 and 6;
// schemas/event-payload.schema.json#/$defs/relation_create_payload.
//
// The payload is exactly `{primary_conflict_domain, expected_revision,
// relation}`. `relation` is the closed six-field `relation_definition`
// authoring region; the materialized members (`schema`, `realm_id`, `id`,
// `state`, `created_by`, `created_at`, ...) are reducer-derived and rejected.
// The domain kind is not caller-selectable: it is the one registered in
// `relation-kind-registry.json` for the relation kind.

import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export type RelationEndpoint = string | Record<string, unknown>;

export type CurrentRevision = { commit_id: string; stream_position: number };

const registryPath = resolve(
  dirname(fileURLToPath(import.meta.url)),
  "../../../arkret-spec/spec/v1/artifacts/registry/relation-kind-registry.json",
);

let domainKinds: Map<string, string> | undefined;

function registeredDomainKind(relationKind: string): "tuple" | "from" {
  if (!domainKinds) {
    const registry = JSON.parse(readFileSync(registryPath, "utf8")) as {
      relation_kinds: Array<{
        canonical_id: string;
        primary_conflict_domain?: string;
      }>;
    };
    domainKinds = new Map(
      registry.relation_kinds.flatMap((row) =>
        row.primary_conflict_domain
          ? [[row.canonical_id, row.primary_conflict_domain] as const]
          : [],
      ),
    );
  }
  const domain = domainKinds.get(relationKind);
  if (domain === "tuple" || domain === "from") return domain;
  // Shape-dependent kinds (`contains`) register only a tuple domain for the
  // directly writable shape.
  if (relationKind === "contains") return "tuple";
  throw new Error(`${relationKind} has no directly writable primary conflict domain`);
}

export function relationCreatePayload(args: {
  relationKind: string;
  fromRef: RelationEndpoint;
  toRef: RelationEndpoint;
  scopeCircleId?: string;
  rank?: string;
  fields?: Record<string, unknown>;
  expectedRevision?: CurrentRevision | null;
}): Record<string, unknown> {
  const domainKind = registeredDomainKind(args.relationKind);
  return {
    primary_conflict_domain: {
      domain_kind: domainKind,
      relation_kind: args.relationKind,
      from_ref: args.fromRef,
      ...(domainKind === "tuple" ? { to_ref: args.toRef } : {}),
    },
    expected_revision: args.expectedRevision ?? null,
    relation: {
      ...(args.scopeCircleId ? { scope_circle_id: args.scopeCircleId } : {}),
      relation_kind: args.relationKind,
      from_ref: args.fromRef,
      to_ref: args.toRef,
      ...(args.rank ? { rank: args.rank } : {}),
      ...(args.fields ? { fields: args.fields } : {}),
    },
  };
}
