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
  "cowrite_policy"?: string[][];
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

/** `capability-grant.schema.json` — closed object schema. */
export type CapabilityGrantObject = {
  "id": string;
  "schema": "ak.schema.capability.v1";
  "realm_id"?: string;
  "issuer": string;
  "subject": string | {
    "kind": "condition";
    "required_claims": unknown[];
    [key: string]: unknown;
  };
  "actions": string[];
  "resources": Array<{
    "kind": "realm" | "space" | "circle" | "strand" | "message" | "morph" | "object" | "relation" | "view" | "event" | "actor" | "schema" | "policy" | "invite" | "notification" | "read_cursor" | "blob" | "*";
    "realm_id"?: string;
    "space_id"?: string;
    "circle_id"?: string;
    "object_kind"?: string;
    "object_ref"?: string;
    "strand_id"?: string;
    "message_id"?: string;
    "morph_id"?: string;
    "morph_kind"?: string;
    "relation_kind"?: string;
    "relation_id"?: string;
    "view_id"?: string;
    "event_id"?: string;
    "actor_id"?: string;
    "schema_ref"?: string;
    "policy_id"?: string;
    "invite_id"?: string;
    "blob_ref"?: string;
    "match_scope"?: "exact" | "subtree" | "children" | "realm_wide";
  }>;
  "capability_action_registry_digest"?: string;
  "constraints"?: Array<{
    "constraint_id"?: string;
    "constraint_kind": "temporal" | "field_access" | "kind_restriction" | "scope_limitation" | "delegation_control" | "quota" | "claim_based" | "confidentiality";
    "effect": "allow" | "deny" | "quarantine" | "require_review";
    "evaluation_class"?: "stateless" | "grant_local" | "realm_state" | "external";
    "constraint_subkind"?: "claim" | "approval" | "accountability" | "rate" | "resource" | "encryption" | "visibility" | "window" | "edit_window" | "redact_window" | "session" | "applet_delegation";
    "applies_to_actions"?: string[];
    "not_before"?: string;
    "expires_at"?: string;
    "recurrence"?: {
      "frequency"?: "daily" | "weekly" | "monthly" | "custom";
      "days"?: Array<"mon" | "tue" | "wed" | "thu" | "fri" | "sat" | "sun">;
      "window_start"?: string;
      "window_end"?: string;
      "timezone"?: string;
      [key: string]: unknown;
    };
    "max_duration"?: string;
    "max_session_duration"?: string;
    "inactivity_timeout"?: string;
    "expires_after"?: string;
    "message_edit_window"?: string;
    "message_redact_window"?: string;
    "redact_after_window_allowed"?: boolean;
    "condition"?: {
      "kind": "object_is_owned_by_actor" | "actor_is_assignee" | "actor_is_responsible" | "actor_is_guardian" | "actor_is_controller" | "object_in_actor_container" | "object_is_unencrypted" | "object_is_encrypted" | "always" | "never";
      [key: string]: unknown;
    };
    "allowed_write_fields"?: string[];
    "denied_write_fields"?: string[];
    "allowed_read_fields"?: string[];
    "denied_read_fields"?: string[];
    "sensitive_fields"?: string[];
    "sensitive_handling"?: "redact" | "hash" | "omit";
    "allowed_object_kinds"?: string[];
    "denied_object_kinds"?: string[];
    "allowed_morph_kinds"?: string[];
    "denied_morph_kinds"?: string[];
    "allowed_space_kinds"?: string[];
    "denied_space_kinds"?: string[];
    "allowed_facets"?: Array<"container" | "replyable" | "schedulable" | "assignable" | "stateful" | "rankable" | "reviewable" | "notifiable" | "documentable" | "renderable">;
    "denied_facets"?: Array<"container" | "replyable" | "schedulable" | "assignable" | "stateful" | "rankable" | "reviewable" | "notifiable" | "documentable" | "renderable">;
    "allowed_view_ids"?: string[];
    "allowed_strand_ids"?: string[];
    "denied_strand_ids"?: string[];
    "allowed_space_ids"?: string[];
    "denied_space_ids"?: string[];
    "allowed_circle_ids"?: string[];
    "allowed_session_ids"?: string[];
    "allowed_view_kinds"?: string[];
    "allowed_view_renderers"?: string[];
    "denied_view_kinds"?: string[];
    "denied_view_renderers"?: string[];
    "allowed_relation_kinds"?: string[];
    "allowed_from_container_refs"?: string[];
    "allowed_to_container_refs"?: string[];
    "wip_limit_override"?: boolean;
    "allowed_tracks"?: string[];
    "denied_tracks"?: string[];
    "blob_presign_scope"?: {
      "allowed_purposes": Array<"media_inline" | "thumbnail" | "download">;
      "blob_ref_pattern"?: string;
      "realm_ids"?: string[];
    };
    "allowed_data_labels"?: string[];
    "allowed_endpoints"?: string[];
    "max_delegation_depth"?: number;
    "delegation_path"?: string[];
    "prohibit_subdelegation"?: boolean;
    "delegation_scope"?: "narrowing_only" | "same_scope" | "custom";
    "scope_expansion_allowed"?: boolean;
    "parent_reference_required"?: boolean;
    "applet_id"?: string;
    "executed_by"?: string;
    "registration_epoch"?: string;
    "blob_max_bytes"?: number;
    "blob_presign_max_ttl_seconds"?: number;
    "max_total_blob_bytes"?: number;
    "max_artifact_bytes"?: number;
    "max_operations"?: number;
    "period"?: string;
    "burst"?: number;
    "constraint_scope"?: "per_actor" | "per_space" | "per_realm" | "global";
    "max_resources"?: number;
    "resource_kind"?: string;
    "approval_required"?: boolean;
    "approval_mode"?: "before_commit" | "proposal_then_approve" | "after_commit_review";
    "approval_actor_ids"?: string[];
    "approval_relation"?: "responsible" | "controller" | "guardian" | "realm_admin" | "custom";
    "timeout"?: string;
    "auto_reject_on_timeout"?: boolean;
    "proposal_morph_kind"?: string;
    "approval_threshold"?: "majority" | "unanimous" | "quorum" | "custom";
    "approvers"?: string[];
    "accountability_required"?: boolean;
    "guardian_approval_required"?: boolean;
    "controller_approval_required"?: boolean;
    "required_claims"?: unknown[];
    "trusted_claim_issuers"?: string[];
    "claim_refresh_required"?: boolean;
    "claim_max_age"?: string;
    "allowed_history_visibility_values"?: Array<"world_readable" | "shared" | "invited" | "joined" | "restricted">;
    "redacted_history_allowed"?: boolean;
    "encryption_required"?: boolean;
    "min_encryption_level"?: "none" | "mls_rfc9420" | "external";
    "plaintext_fallback_allowed"?: boolean;
    "audit_trail_required"?: boolean;
    "key_rotation_period"?: string;
    "max_key_age"?: string;
    "key_backup_required"?: boolean;
    "approved_key_issuers"?: string[];
    "depends_on_moderation_state"?: boolean;
  }>;
  "parent_grant_id"?: string;
  "issued_at"?: string;
  "not_before"?: string;
  "expires_at"?: string;
  "updated_by"?: string;
  "updated_at"?: string;
  "revoked_by"?: string;
  "revoked_at"?: string;
  "proofs": Array<{
    "kind": "detached_jws";
    "verification_method": string;
    "alg": "EdDSA" | "ES256" | "ML-DSA-65";
    "payload_digest": string;
    "created_at": string;
    "domain"?: string;
    "audience"?: string | string[];
    "proof_purpose"?: "issuer_attestation" | "holder_acceptance";
    "jws": string;
  }>;
};

/** `invite-delivery-request.schema.json` — closed object schema. */
export type InviteDeliveryRequestBody = {
  "schema": "ak.schema.invite_delivery_request.v1";
  "invite_event": {
    "event_id": string;
    "kind": string;
    "realm_id": string;
    "scope_ref": {
      "kind": "realm";
      "realm_id": string;
    } | {
      "kind": "circle";
      "realm_id": string;
      "circle_id": string;
    };
    "actor_id": string;
    "executed_by"?: string;
    "authorization_ref"?: string;
    "applet_id"?: string;
    "external_ref"?: {
      "schema"?: string;
      "protocol"?: string;
      "network_id"?: string;
      "instance_id"?: string;
      "user_id"?: string;
      "location_id"?: string;
      "event_id"?: string;
      "external_id"?: string;
      "url"?: string;
      [key: string]: unknown;
    };
    "actor_kind"?: "user" | "org" | "team" | "agent" | "service" | "integration";
    "actor_seq": number;
    "created_at": string;
    "hlc"?: string;
    "prev_refs": string[];
    "refs": Array<{
      "id": string;
      "role": string;
      "critical"?: boolean;
      "proof"?: {
        "kind"?: "rfc6962_merkle";
        "leaf_digest"?: string;
        "audit_path"?: string[];
        "leaf_index"?: number;
        "leaf_count"?: number;
      };
    }>;
    "causal_refs"?: string[];
    "preconditions"?: Array<{
      "cell": string;
      "predicate": {
        "op": "head_eq" | "head_in" | "satisfies" | "contains";
        "value"?: unknown;
        "values"?: unknown[];
        "predicate_id"?: string;
      };
    }>;
    "seal_ref"?: string;
    "auth_context"?: {
      "did": string;
      "key_id": string;
      "key_epoch": number;
      "credential_epoch"?: number;
    };
    "seal_basis"?: {
      "leaves": string[];
      "control_event_set_root": string;
      "state_root": string;
    };
    "payload": Record<string, unknown>;
    "redacts"?: string;
    "unsigned"?: Record<string, unknown>;
    "proofs": Array<{
      "kind": "detached_jws";
      "verification_method": string;
      "alg": "EdDSA" | "ES256" | "ML-DSA-65";
      "event_digest": string;
      "created_at": string;
      "domain"?: string;
      "audience"?: string | string[];
      "proof_purpose"?: "issuer_attestation" | "holder_acceptance";
      "jws": string;
    }>;
    "requirements"?: {
      "schema"?: string[];
      "reducer"?: string;
      "features"?: string[];
      "critical_extensions"?: Array<{
        "id": string;
        "extension_scope": "event" | "payload" | "proof" | "authz" | "reducer" | "projection" | "encryption";
        "schema_ref"?: string;
        "profile_ref"?: string;
        "parameters"?: Record<string, unknown>;
        "material_digest"?: string;
        "evidence_ref"?: string;
        "fail_closed": true;
      }>;
    };
  };
  "invite_address": {
    "subject_id": string;
    "recipient_service_id": string;
    "recipient_service_kind"?: "principal_server";
  };
  "introduction_evidence": {
    "kind": "locator_ref";
    "principal_locator": {
      "schema": "ak.schema.principal_locator.v1";
      "subject_id": string;
      "recipient_service_id": string;
      "recipient_service_kind"?: "principal_server";
      "issued_at": string;
      "expires_at": string;
      "locator_ref_digest": string;
      "delivery_modes"?: Array<"events" | "sync" | "to_device" | "push" | "key_packages">;
      "display_hint"?: {
        "display_name_hint"?: string;
        "avatar_blob_ref"?: string;
      };
      "proofs": Array<{
        "proof_purpose": "subject_locator_authorization" | "recipient_service_acceptance";
        "proof": {
          "kind": "detached_jws";
          "verification_method": string;
          "alg": "EdDSA" | "ES256" | "ML-DSA-65";
          "payload_digest": string;
          "created_at": string;
          "domain"?: string;
          "audience"?: string | string[];
          "proof_purpose"?: "issuer_attestation" | "holder_acceptance";
          "jws": string;
        };
      }>;
    };
  } | {
    "kind": "consent_grant";
    "consent_grant_ref": string;
    "consent_id"?: string;
  } | {
    "kind": "shared_realm";
    "realm_id": string;
    "inviter_member_ref": string;
    "invitee_member_ref": string;
  } | {
    "kind": "handle_claim";
    "handle": string;
    "handle_claim": {
      "schema": "ak.schema.handle_claim.v1";
      "handle": string;
      "handle_aliases"?: string[];
      "subject": string;
      "issuer": string;
      "issuer_service_id"?: string;
      "binding_state": "pending" | "verified" | "revoked" | "expired";
      "claim_kind"?: "handle_binding" | "organization_handle";
      "visibility"?: "public" | "restricted" | "private";
      "audience"?: string;
      "challenge"?: string;
      "claim_scope"?: Record<string, unknown>;
      "member_delivery_binding"?: {
        "recipient_service_id": string;
        "recipient_service_kind"?: "principal_server";
        "binding_source": "explicit" | "invite" | "join_policy" | "organization_policy" | "realm_policy";
        "delivery_modes"?: Array<"events" | "sync" | "to_device" | "push" | "key_packages">;
        "service_acceptance_ref"?: string;
        "policy_event_ref"?: string;
      };
      "claims"?: Array<Record<string, unknown>>;
      "expires_at"?: string;
      "created_at": string;
      "verified_at"?: string;
      "source_refs"?: string[];
      "proofs": Array<{
        "kind": "detached_jws";
        "verification_method": string;
        "alg": "EdDSA" | "ES256" | "ML-DSA-65";
        "payload_digest": string;
        "created_at": string;
        "domain"?: string;
        "audience"?: string | string[];
        "proof_purpose"?: "issuer_attestation" | "holder_acceptance";
        "jws": string;
      }>;
      [key: string]: unknown;
    };
    "member_delivery_binding_candidate"?: {
      "subject_id": string;
      "handle": string;
      "handle_aliases"?: string[];
      "member_delivery_binding": {
        "recipient_service_id": string;
        "recipient_service_kind"?: "principal_server";
        "binding_source": "explicit" | "invite" | "join_policy" | "organization_policy" | "realm_policy";
        "delivery_modes"?: Array<"events" | "sync" | "to_device" | "push" | "key_packages">;
        "service_acceptance_ref"?: string;
        "policy_event_ref"?: string;
      };
      "issuer_service_id": string;
      "audience": string;
      "issued_at": string;
      "expires_at": string;
      "source_refs": string[];
      "proofs": Array<{
        "kind": "detached_jws";
        "verification_method": string;
        "alg": "EdDSA" | "ES256" | "ML-DSA-65";
        "payload_digest": string;
        "created_at": string;
        "domain"?: string;
        "audience"?: string | string[];
        "proof_purpose"?: "issuer_attestation" | "holder_acceptance";
        "jws": string;
      }>;
      "claim_digest"?: string;
      "intent": "member_add" | "invite";
    };
    "resolved_by"?: string;
    "resolved_at"?: string;
  } | {
    "kind": "same_principal_server";
  } | {
    "kind": "explicit_address";
  };
  "idempotency_key": string;
};

/** `service-operation-dtos.schema.json#/$defs/RealmSealFrontierView` — closed object schema. */
export type RealmSealFrontierView = {
  "kind": "realm_seal";
  "realm_id": string;
  "seal_id": string;
  "control_event_set_root": string;
  "state_root": string;
  "governance_health": {
    "status": "healthy" | "degraded";
    "pending_proposals": Array<{
      "proposal_digest": string;
      "receipt": {
        "kind": "proposal_receipt";
        "realm_id": string;
        "proposal_digest": string;
        "received_at": string;
        "decision_due_at": string;
        "absolute_due_at": string;
        "defer_count": 0;
        "authority_set_ref": string;
        "member_receipts": Array<{
          "realm_id": string;
          "proposal_digest": string;
          "received_at": string;
          "decision_due_at": string;
          "absolute_due_at": string;
          "authority_set_ref": string;
          "signature": {
            "verification_method": string;
            "alg": "EdDSA" | "ES256" | "ML-DSA-65";
            "payload_digest": string;
            "created_at": string;
            "jws": string;
          };
        }>;
      };
      "decisions": Array<{
        "kind": "signed_reject" | "signed_defer";
        "realm_id": string;
        "proposal_digest": string;
        "receipt_digest": string;
        "decided_at": string;
        "decision_due_at": string;
        "absolute_due_at": string;
        "defer_count": number;
        "reason_code": string;
        "authority_set_ref": string;
        "proofs": Array<{
          "verification_method": string;
          "alg": "EdDSA" | "ES256" | "ML-DSA-65";
          "payload_digest": string;
          "created_at": string;
          "jws": string;
        }>;
      }>;
      "current_decision_due_at": string;
      "absolute_due_at": string;
      "defer_count": number;
      "decision_state": "pending" | "deferred" | "overdue";
      "fault_reason"?: "control_proposal_decision_overdue";
    }>;
    "retained_faults": Array<{
      "proposal_digest": string;
      "receipt": {
        "kind": "proposal_receipt";
        "realm_id": string;
        "proposal_digest": string;
        "received_at": string;
        "decision_due_at": string;
        "absolute_due_at": string;
        "defer_count": 0;
        "authority_set_ref": string;
        "member_receipts": Array<{
          "realm_id": string;
          "proposal_digest": string;
          "received_at": string;
          "decision_due_at": string;
          "absolute_due_at": string;
          "authority_set_ref": string;
          "signature": {
            "verification_method": string;
            "alg": "EdDSA" | "ES256" | "ML-DSA-65";
            "payload_digest": string;
            "created_at": string;
            "jws": string;
          };
        }>;
      };
      "decisions": Array<{
        "kind": "signed_defer";
        "realm_id": string;
        "proposal_digest": string;
        "receipt_digest": string;
        "decided_at": string;
        "decision_due_at": string;
        "absolute_due_at": string;
        "defer_count": number;
        "reason_code": string;
        "authority_set_ref": string;
        "proofs": Array<{
          "verification_method": string;
          "alg": "EdDSA" | "ES256" | "ML-DSA-65";
          "payload_digest": string;
          "created_at": string;
          "jws": string;
        }>;
      }>;
      "accepted_seal_id": string;
      "accepted_at": string;
      "fault_reason": "control_proposal_decision_overdue";
    }>;
  };
  "hlc"?: string;
};

/** `service-operation-dtos.schema.json#/$defs/EventFederationSubmission` — closed object schema. */
export type EventFederationSubmission = {
  "event": {
    "event_id": string;
    "kind": string;
    "realm_id": string;
    "scope_ref": {
      "kind": "realm";
      "realm_id": string;
    } | {
      "kind": "circle";
      "realm_id": string;
      "circle_id": string;
    };
    "actor_id": string;
    "executed_by"?: string;
    "authorization_ref"?: string;
    "applet_id"?: string;
    "external_ref"?: {
      "schema"?: string;
      "protocol"?: string;
      "network_id"?: string;
      "instance_id"?: string;
      "user_id"?: string;
      "location_id"?: string;
      "event_id"?: string;
      "external_id"?: string;
      "url"?: string;
      [key: string]: unknown;
    };
    "actor_kind"?: "user" | "org" | "team" | "agent" | "service" | "integration";
    "actor_seq": number;
    "created_at": string;
    "hlc"?: string;
    "prev_refs": string[];
    "refs": Array<{
      "id": string;
      "role": string;
      "critical"?: boolean;
      "proof"?: {
        "kind"?: "rfc6962_merkle";
        "leaf_digest"?: string;
        "audit_path"?: string[];
        "leaf_index"?: number;
        "leaf_count"?: number;
      };
    }>;
    "causal_refs"?: string[];
    "preconditions"?: Array<{
      "cell": string;
      "predicate": {
        "op": "head_eq" | "head_in" | "satisfies" | "contains";
        "value"?: unknown;
        "values"?: unknown[];
        "predicate_id"?: string;
      };
    }>;
    "seal_ref"?: string;
    "auth_context"?: {
      "did": string;
      "key_id": string;
      "key_epoch": number;
      "credential_epoch"?: number;
    };
    "seal_basis"?: {
      "leaves": string[];
      "control_event_set_root": string;
      "state_root": string;
    };
    "payload": Record<string, unknown>;
    "redacts"?: string;
    "unsigned"?: Record<string, unknown>;
    "proofs": Array<{
      "kind": "detached_jws";
      "verification_method": string;
      "alg": "EdDSA" | "ES256" | "ML-DSA-65";
      "event_digest": string;
      "created_at": string;
      "domain"?: string;
      "audience"?: string | string[];
      "proof_purpose"?: "issuer_attestation" | "holder_acceptance";
      "jws": string;
    }>;
    "requirements"?: {
      "schema"?: string[];
      "reducer"?: string;
      "features"?: string[];
      "critical_extensions"?: Array<{
        "id": string;
        "extension_scope": "event" | "payload" | "proof" | "authz" | "reducer" | "projection" | "encryption";
        "schema_ref"?: string;
        "profile_ref"?: string;
        "parameters"?: Record<string, unknown>;
        "material_digest"?: string;
        "evidence_ref"?: string;
        "fail_closed": true;
      }>;
    };
  };
  "authorization_lease": {
    "authorization_lease_id": string;
    "basis_ref": string | {
      "leaves": string[];
      "control_event_set_root": string;
      "state_root": string;
    } | {
      "anchor_unit": {
        "realm_id": string;
        "event_digests": string[];
        "unit_digest": string;
      };
    };
    "actor_id": string;
    "device_id": string;
    "scope_ref": {
      "kind": "realm";
      "realm_id": string;
    } | {
      "kind": "circle";
      "realm_id": string;
      "circle_id": string;
    };
    "action": string;
    "authorization_rule_id": string;
    "risk_tier": "low" | "medium" | "high";
    "issued_at": string;
    "expires_at": string;
    "authority_set_ref": {
      "authority_set_id": string;
      "authority_set_digest": string;
    };
    "authority_set_policy": {
      "schema": "ak.schema.authority_set_policy.v1";
      "authority_set_id": string;
      "policy_kind": "principal_control" | "realm_admission";
      "scope_ref": {
        "kind": "realm";
        "realm_id": string;
      } | {
        "kind": "circle";
        "realm_id": string;
        "circle_id": string;
      };
      "source": {
        "source_kind": "cross_signing_publish" | "did_document" | "recovery_policy" | "realm_control";
        "source_ref": string;
        "source_digest": string;
        "generation_ref": string;
      };
      "authorization_rules": Array<{
        "rule_id": string;
        "issuer_role": "cross_signing_self_signing" | "identity_recovery" | "account_enrollment_authority" | "realm_admission";
        "allowed_actions": string[];
        "issuers": Array<{
          "verification_method": string;
        }>;
        "threshold": number;
      }>;
    };
    "proofs": Array<{
      "kind": "detached_jws";
      "verification_method": string;
      "alg": "EdDSA" | "ES256" | "ML-DSA-65";
      "payload_digest": string;
      "created_at": string;
      "domain"?: string;
      "audience"?: string | string[];
      "proof_purpose"?: "issuer_attestation" | "holder_acceptance";
      "jws": string;
    }>;
  };
  "ingress_receipts": Array<{
    "receipt_id": string;
    "event_digest": string;
    "authorization_lease_id": string;
    "received_at": string;
    "service_id": string;
    "authority_set_ref": {
      "authority_set_id": string;
      "authority_set_digest": string;
    };
    "proofs": Array<{
      "kind": "detached_jws";
      "verification_method": string;
      "alg": "EdDSA" | "ES256" | "ML-DSA-65";
      "payload_digest": string;
      "created_at": string;
      "domain"?: string;
      "audience"?: string | string[];
      "proof_purpose"?: "issuer_attestation" | "holder_acceptance";
      "jws": string;
    }>;
  }>;
  "control_proposal_receipt"?: {
    "kind": "proposal_receipt";
    "realm_id": string;
    "proposal_digest": string;
    "received_at": string;
    "decision_due_at": string;
    "absolute_due_at": string;
    "defer_count": 0;
    "authority_set_ref": string;
    "member_receipts": Array<{
      "realm_id": string;
      "proposal_digest": string;
      "received_at": string;
      "decision_due_at": string;
      "absolute_due_at": string;
      "authority_set_ref": string;
      "signature": {
        "verification_method": string;
        "alg": "EdDSA" | "ES256" | "ML-DSA-65";
        "payload_digest": string;
        "created_at": string;
        "jws": string;
      };
    }>;
  };
};
