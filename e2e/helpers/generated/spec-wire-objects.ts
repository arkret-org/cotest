// GENERATED FILE — DO NOT EDIT BY HAND.
//
// Source: arkret-spec/spec/v1/artifacts/schemas/*.json
// Producer: e2e/scripts/generate-wire-types.mjs
//
// Regenerate with `npm run gen:wire-types`; `npm run check:wire-types` fails
// when this file no longer matches the spec artifacts. Annotate hand-built wire
// literals with these types so an unregistered member is a `tsc` error rather
// than a live-server rejection.

/** `realm.schema.json` — closed object schema. */
export type RealmObject = {
  "id": string;
  "schema": "ak.schema.realm.v1";
  "title": string;
  "summary"?: string;
  "security_class"?: "standard" | "high_assurance";
  "trust_domain": string;
  "owning_organizations"?: string[];
  "schema_refs": string[];
  "fields"?: {
    "purpose"?: "principal_control";
    "collaboration_role"?: "direct_conversation";
    [key: string]: unknown;
  };
  "relation_profiles"?: Array<{
    "relation_kind": string;
    "from_kind"?: string;
    "to_kind"?: string;
    "relation_scope"?: "realm" | "space" | "board" | "global";
    "cardinality": "one_to_one" | "one_to_many" | "many_to_one" | "many_to_many";
    "dedupe_key"?: string[];
    "max_to_per_from"?: number;
    "max_from_per_to"?: number;
    "multi_edge"?: boolean;
    "rank_field"?: string;
    "on_conflict"?: "reject" | "close_previous" | "deterministic_winner" | "require_review";
    [key: string]: unknown;
  }>;
  "policy_id"?: string;
  "preview_policy_id"?: string;
  "default_strand_id"?: string | null;
  "default_discoverability": "public" | "listed" | "restricted" | "unlisted" | "invite_only" | "secret";
  "default_join_rule": "public" | "invite" | "knock" | "restricted" | "knock_restricted" | "closed";
  "history_visibility": "world_readable" | "shared" | "invited" | "joined" | "restricted";
  "encryption_profile": "none" | "mls_rfc9420" | "external";
  "content_scheme"?: "mls_rfc9420" | "mls_exporter_aead_v1";
  "content_encryption_floor"?: "allow_plaintext" | "e2ee_required";
  "metadata_encryption_floor"?: "allow_plaintext" | "e2ee_required";
  "agent_participation"?: {
    "native_agent"?: {
      "reply"?: boolean;
      "accept_third_party_mention"?: boolean;
      "act_on_behalf"?: boolean;
    };
  };
  "durability_policy"?: {
    "mode": "none" | "org_recovery_key" | "threshold";
    "recovery_recipients"?: Array<{
      "recipient_id": string;
      "principal_id": string;
      "verification_method": string;
      "controller_organization"?: string;
    }>;
    "threshold"?: {
      "k": number;
      "n": number;
    };
  };
  "federation_policy"?: "open" | "restricted" | "closed" | "quarantine";
  "sync_endpoints"?: Array<{
    "did": string;
    "endpoint": string;
    "role": "primary" | "mirror" | "notary" | "sync" | "search_projection" | "federation_peer";
    "service_kind": "principal_server" | "sync_node" | "notary" | "search_service" | "archive_node" | "key_recovery_service" | "recovery_service";
    "plaintext_visible": boolean;
    "visibility_scope"?: "metadata_only" | "encrypted_events" | "plaintext_events";
    "policy_id"?: string;
    "expires_at"?: string;
  }>;
  "notary_profile": "single_did" | "threshold" | "open_set" | "mixed";
  "availability_policy"?: {
    "min_holders": number;
    "holder_roles": Array<"notary" | "independent_witness" | "sync_mirror" | "archive_node">;
    "applies_to": Array<"seal_include" | "snapshot" | "backfill">;
    "minimum_retention_ms"?: number;
  };
  "audit_policy"?: {
    "range_completeness_witnesses": string[];
    "witnessed_min_attestations": number;
    "witness_independence": "distinct_did" | "distinct_controlling_organization";
  };
  "digest_algorithm"?: "sha256" | "blake3";
  "notary": {
    "did"?: string;
    "members"?: string[];
    "threshold"?: number;
    "forensic_attribution"?: "quorum_intersection" | "waived";
    "recovery_members"?: string[];
    "controller_organization"?: string;
    "recovery_controller_organizations"?: string[];
    "kind": "single_did" | "threshold" | "open_set" | "mixed";
  };
  "revocation_freshness_window_ms"?: number;
  "recovery_witness_freshness_window_ms"?: number;
  "receipt_sla_ms"?: number;
  "proposal_decision_window_ms"?: number;
  "proposal_absolute_deadline_ms"?: number;
  "max_proposal_defers"?: number;
  "seal_compaction_max_interval_ms"?: number;
  "max_delegation_lifetime_ms"?: number;
  "bottom_escalation_after_ms"?: number;
  "cell_lattices"?: Array<{
    "cell_family": string;
    "lattice": "or_set" | "mv_register" | "cas_register" | "fsm" | "counter" | "ordered_log";
    "bottom": "reject" | "expose";
    "cell_role": "authorization_root" | "policy_root" | "notary_root" | "membership" | "lifecycle" | "ui_affordance" | "content" | "draft" | "cosmetic" | "audit" | "telemetry";
    "plane": "data" | "control";
    "sealed"?: boolean;
    "parameters"?: Record<string, unknown>;
    "initial_value"?: unknown;
    "sentinel_writers"?: string[];
  }>;
  "co_write_policy"?: string[][];
  "retention_policy_id"?: string;
  "avatar_blob_ref"?: string;
  "created_by": string;
  "created_at": string;
  "updated_by"?: string;
  "updated_at"?: string;
};

/** `space.schema.json` — closed object schema. */
export type SpaceObject = {
  "id": string;
  "schema": "ak.schema.space.v1";
  "realm_id": string;
  "default_realm_id"?: string;
  "scope_circle_id"?: string;
  "child_scope_policy"?: {
    "kind": "allow_any" | "require_e2ee" | "require_same_scope" | "require_scope_circle_id";
    "scope_circle_id"?: string;
  };
  "parent_space_id"?: string;
  "kind": string;
  "rank"?: string;
  "schema_refs"?: string[];
  "title": string;
  "summary"?: string;
  "labels"?: string[];
  "fields"?: {
    "wip_limit"?: number;
    "wip_limit_enforcement"?: "warn" | "reject" | "require_review";
    [key: string]: unknown;
  };
  "avatar_blob_ref"?: string;
  "state"?: "active" | "archived" | "tombstoned";
  "state_changed_at"?: string;
  "created_by": string;
  "created_at": string;
  "updated_by"?: string;
  "updated_at"?: string;
};
