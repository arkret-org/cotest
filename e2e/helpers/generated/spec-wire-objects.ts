// GENERATED FILE — DO NOT EDIT BY HAND.
//
// Source: arkret-spec/spec/v1/artifacts/schemas/*.json
// Producer: e2e/scripts/generate-wire-types.mjs
//
// Regenerate with `npm run gen:wire-types`; `npm run check:wire-types` fails
// when this file no longer matches the spec artifacts. Annotate hand-built wire
// literals with these types so an unregistered member is a `tsc` error rather
// than a live-server rejection.

/** `applet-package.schema.json` — closed object schema. */
export type AppletPackage = {
  "schema": "ak.schema.applet_package.v1";
  "package_id": string;
  "applet_id": string;
  "service_id": string;
  "controller_principal_id": string;
  "base_url": string;
  "claimed_profiles": string[];
  "protocols": string[];
  "namespaces": {
    "actors": Array<{
      "exclusive": boolean;
      "pattern": string;
    }>;
    "realms": Array<{
      "exclusive": boolean;
      "pattern": string;
    }>;
    "handles": Array<{
      "exclusive": boolean;
      "pattern": string;
    }>;
  };
  "requested_scopes": string[];
  "endpoint_policy": {
    "endpoints": Array<{
      "method": "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
      "path": string;
      "auth"?: "none" | "webhook_signature" | "bearer" | "mtls";
      "description"?: string;
    }>;
  };
  "webhook_auth": {
    "key_ref": string;
    "accepted_signature_algorithms": Array<"ed25519" | "ecdsa-p256-sha256">;
    "signature_header"?: string;
    "kind": "http_message_signature";
  };
  "receive_events": boolean;
  "receive_signals": boolean;
  "rate_limited": boolean;
  "limits": {
    "max_transaction_events"?: number;
    "max_payload_bytes"?: number;
    "rate_limit_per_minute"?: number;
  };
  "ghost_policy": {
    "enabled": boolean;
    "accountability_template"?: string;
  };
  "delegation_policy": {
    "enabled": boolean;
  };
  "e2ee_policy": {
    "enabled": boolean;
    "mls_join_requested"?: boolean;
  };
  "widget"?: {
    "schema": "ak.schema.applet_widget_declaration.v1";
    "widget_origin": string;
    "csp": string;
    "token_scope": {
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
        "actor_id"?: {
          "kind": "account";
          "account_id": {
            "principal_id": string;
            "station_id": string;
          };
        } | {
          "kind": "service";
          "service_id": string;
        };
        "schema_ref"?: string;
        "policy_id"?: string;
        "invite_id"?: string;
        "blob_ref"?: string;
        "match_scope"?: "exact" | "realm_wide";
      }>;
      "realm_ids"?: string[];
      "expires_at": string;
      "max_ttl_seconds"?: number;
    };
    "consent_required": boolean;
  };
  "package_digest": string;
  "registration_epoch": string;
  "expires_at"?: string;
  "created_at": string;
  "proof": {
    "kind": "detached_jws";
    "verification_method": string;
    "payload_digest": string;
    "created_at": string;
    "domain"?: string;
    "audience"?: string | string[];
    "jws": string;
  };
};

/** `applet-install-operations.schema.json#/$defs/applet_install_request_body` — closed object schema. */
export type AppletInstallRequestBody = {
  "applet_package": {
    "schema": "ak.schema.applet_package.v1";
    "package_id": string;
    "applet_id": string;
    "service_id": string;
    "controller_principal_id": string;
    "base_url": string;
    "claimed_profiles": string[];
    "protocols": string[];
    "namespaces": {
      "actors": Array<{
        "exclusive": boolean;
        "pattern": string;
      }>;
      "realms": Array<{
        "exclusive": boolean;
        "pattern": string;
      }>;
      "handles": Array<{
        "exclusive": boolean;
        "pattern": string;
      }>;
    };
    "requested_scopes": string[];
    "endpoint_policy": {
      "endpoints": Array<{
        "method": "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
        "path": string;
        "auth"?: "none" | "webhook_signature" | "bearer" | "mtls";
        "description"?: string;
      }>;
    };
    "webhook_auth": {
      "key_ref": string;
      "accepted_signature_algorithms": Array<"ed25519" | "ecdsa-p256-sha256">;
      "signature_header"?: string;
      "kind": "http_message_signature";
    };
    "receive_events": boolean;
    "receive_signals": boolean;
    "rate_limited": boolean;
    "limits": {
      "max_transaction_events"?: number;
      "max_payload_bytes"?: number;
      "rate_limit_per_minute"?: number;
    };
    "ghost_policy": {
      "enabled": boolean;
      "accountability_template"?: string;
    };
    "delegation_policy": {
      "enabled": boolean;
    };
    "e2ee_policy": {
      "enabled": boolean;
      "mls_join_requested"?: boolean;
    };
    "widget"?: {
      "schema": "ak.schema.applet_widget_declaration.v1";
      "widget_origin": string;
      "csp": string;
      "token_scope": {
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
          "actor_id"?: {
            "kind": "account";
            "account_id": {
              "principal_id": string;
              "station_id": string;
            };
          } | {
            "kind": "service";
            "service_id": string;
          };
          "schema_ref"?: string;
          "policy_id"?: string;
          "invite_id"?: string;
          "blob_ref"?: string;
          "match_scope"?: "exact" | "realm_wide";
        }>;
        "realm_ids"?: string[];
        "expires_at": string;
        "max_ttl_seconds"?: number;
      };
      "consent_required": boolean;
    };
    "package_digest": string;
    "registration_epoch": string;
    "expires_at"?: string;
    "created_at": string;
    "proof": {
      "kind": "detached_jws";
      "verification_method": string;
      "payload_digest": string;
      "created_at": string;
      "domain"?: string;
      "audience"?: string | string[];
      "jws": string;
    };
  };
  "authoring_request_basis": {
    "schema": "ak.schema.applet_install_authoring_request_basis.v1";
    "purpose": "install_applet";
    "target_station_id": string;
    "install_actor_id": {
      "kind": "account";
      "account_id": {
        "principal_id": string;
        "station_id": string;
      };
    } | {
      "kind": "service";
      "service_id": string;
    };
    "applet_id": string;
    "service_id": string;
    "package_digest": string;
    "effective_scope": {
      "kind": "realm";
      "realm_id": string;
    } | {
      "kind": "circle";
      "realm_id": string;
      "circle_id": string;
    };
    "approval_request": {
      "approve_actions": string[];
      "ghost_actor_mode": "disallowed" | "controller_approved" | "policy_declared";
      "delegated_native_actors_allowed": boolean;
      "e2ee_join_allowed": boolean;
      "widget_allowed": boolean;
    };
    "actor_policy"?: {
      "ghost_actor_mode"?: "disallowed" | "controller_approved" | "policy_declared";
    };
    "e2ee_policy"?: {
      "mls_join_allowed"?: boolean;
    };
    "widget_policy"?: {
      "widget_allowed"?: boolean;
    };
    "registration_event": {
      "event_id": string;
      "kind": string;
      "realm_id"?: string;
      "scope_ref": {
        "kind": "realm";
        "realm_id": string;
      } | {
        "kind": "circle";
        "realm_id": string;
        "circle_id": string;
      } | {
        "kind": "sidecar";
        "realm_id": string;
        "sidecar_id": string;
      } | {
        "kind": "realm_genesis";
      };
      "actor_id": {
        "kind": "account";
        "account_id": {
          "principal_id": string;
          "station_id": string;
        };
      } | {
        "kind": "service";
        "service_id": string;
      };
      "executed_by"?: {
        "kind": "account";
        "account_id": {
          "principal_id": string;
          "station_id": string;
        };
      } | {
        "kind": "service";
        "service_id": string;
      };
      "authorization_ref"?: string | "ak.authority.direct_conversation_participant.v1" | "ak.authority.direct_conversation_bootstrap_participant.v1";
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
        "uri"?: string;
        [key: string]: unknown;
      };
      "created_at": string;
      "semantic_refs"?: Array<{
        "id": string;
        "role": "authorized_by";
        "critical": boolean;
      } | {
        "id": string;
        "role": "attestation" | "parent_event" | "after" | "audit_pair" | "recovery_capability" | "accountability" | "bootstrap_genesis" | "disclosure_authorization" | "capture_stop" | "direct_conversation_binding" | "direct_conversation_founding_unit" | "direct_conversation_contact_round" | "direct_conversation_agent_provision" | "applet_managed_actor_provision";
        "critical": boolean;
      }>;
      "payload": Record<string, unknown>;
      "producer_proof": {
        "kind": "detached_jws";
        "verification_method": string;
        "event_digest": string;
        "created_at": string;
        "domain"?: string;
        "audience"?: string | string[];
        "proof_purpose"?: "issuer_attestation" | "holder_acceptance";
        "jws": string;
      };
    } & {
      "kind": "ak.applet.registration";
      "payload": {
        "manifest": {
          "registration_epoch_evidence": {
            "did": string;
            "document_digest": string;
            "method_version_evidence": {
              "method": "did:webvh" | "did:key";
              "unversioned_refetch": false;
              [key: string]: unknown;
            } | {
              "method": "did:webvh";
              "unversioned_refetch": false;
              [key: string]: unknown;
            };
            "accepted_signing_keys": Array<{
              "key_ref": string;
              "public_key_digest": string;
            }>;
          };
          [key: string]: unknown;
        };
        [key: string]: unknown;
      };
      [key: string]: unknown;
    };
    "capability_grant_events": Array<{
      "event_id": string;
      "kind": string;
      "realm_id"?: string;
      "scope_ref": {
        "kind": "realm";
        "realm_id": string;
      } | {
        "kind": "circle";
        "realm_id": string;
        "circle_id": string;
      } | {
        "kind": "sidecar";
        "realm_id": string;
        "sidecar_id": string;
      } | {
        "kind": "realm_genesis";
      };
      "actor_id": {
        "kind": "account";
        "account_id": {
          "principal_id": string;
          "station_id": string;
        };
      } | {
        "kind": "service";
        "service_id": string;
      };
      "executed_by"?: {
        "kind": "account";
        "account_id": {
          "principal_id": string;
          "station_id": string;
        };
      } | {
        "kind": "service";
        "service_id": string;
      };
      "authorization_ref"?: string | "ak.authority.direct_conversation_participant.v1" | "ak.authority.direct_conversation_bootstrap_participant.v1";
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
        "uri"?: string;
        [key: string]: unknown;
      };
      "created_at": string;
      "semantic_refs"?: Array<{
        "id": string;
        "role": "authorized_by";
        "critical": boolean;
      } | {
        "id": string;
        "role": "attestation" | "parent_event" | "after" | "audit_pair" | "recovery_capability" | "accountability" | "bootstrap_genesis" | "disclosure_authorization" | "capture_stop" | "direct_conversation_binding" | "direct_conversation_founding_unit" | "direct_conversation_contact_round" | "direct_conversation_agent_provision" | "applet_managed_actor_provision";
        "critical": boolean;
      }>;
      "payload": Record<string, unknown>;
      "producer_proof": {
        "kind": "detached_jws";
        "verification_method": string;
        "event_digest": string;
        "created_at": string;
        "domain"?: string;
        "audience"?: string | string[];
        "proof_purpose"?: "issuer_attestation" | "holder_acceptance";
        "jws": string;
      };
    } & {
      "kind": "ak.capability.grant";
      [key: string]: unknown;
    }>;
  };
  "plan_digest": string;
};

/** `applet-install-operations.schema.json#/$defs/applet_install_outcome` — closed object schema. */
export type AppletInstallOutcome = {
  "install_id": string;
  "applet_id": string;
  "registration_event_ref": string;
  "registration_epoch": string;
  "capability_grant_refs": string[];
  "e2ee_authorization_refs": string[];
  "widget_policy_ref": string | null;
  "effective_status": "installed" | "partially_installed";
  "rejections": Array<{
    "requested_scope"?: string;
    "reason_code": string;
  }>;
};

/** `applet-bot-operations.schema.json#/$defs/bot_preview_request_body` — closed object schema. */
export type AppletBotPreviewRequestBody = {
  "effective_scope": {
    "kind": "realm";
    "realm_id": string;
  } | {
    "kind": "circle";
    "realm_id": string;
    "circle_id": string;
  };
  "request_id": string;
  "display_name"?: string;
};

/** `applet-bot-operations.schema.json#/$defs/bot_actor_provision_request_body` — closed object schema. */
export type AppletBotProvisionRequestBody = {
  "authoring_request": {
    "schema": "ak.schema.applet_managed_actor_authoring_request.v1";
    "purpose": "provision_bot" | "provision_ghost";
    "basis": {
      "schema": "ak.schema.applet_bot_authoring_request_basis.v1";
      "purpose": "provision_bot";
      "target_station_id": string;
      "applet_id": string;
      "service_id": string;
      "display_name"?: string;
      "registration_event_ref": string;
      "authorization_ref": string;
      "registration_epoch_evidence": {
        "did": string;
        "document_digest": string;
        "method_version_evidence": {
          "method": "did:webvh" | "did:key";
          "unversioned_refetch": false;
          [key: string]: unknown;
        } | {
          "method": "did:webvh";
          "unversioned_refetch": false;
          [key: string]: unknown;
        };
        "accepted_signing_keys": Array<{
          "key_ref": string;
          "public_key_digest": string;
        }>;
      };
      "package_digest": string;
      "effective_scope": {
        "kind": "realm";
        "realm_id": string;
      } | {
        "kind": "circle";
        "realm_id": string;
        "circle_id": string;
      };
      "request_id": string;
    } | {
      "schema": "ak.schema.applet_ghost_authoring_request_basis.v1";
      "purpose": "provision_ghost";
      "target_station_id": string;
      "applet_id": string;
      "service_id": string;
      "external_ref": {
        "protocol": string;
        "instance_id": string;
        "external_id": string;
      };
      "display_name"?: string;
      "registration_event_ref": string;
      "authorization_ref": string;
      "registration_epoch_evidence": {
        "did": string;
        "document_digest": string;
        "method_version_evidence": {
          "method": "did:webvh" | "did:key";
          "unversioned_refetch": false;
          [key: string]: unknown;
        } | {
          "method": "did:webvh";
          "unversioned_refetch": false;
          [key: string]: unknown;
        };
        "accepted_signing_keys": Array<{
          "key_ref": string;
          "public_key_digest": string;
        }>;
      };
      "package_digest": string;
      "effective_scope": {
        "kind": "realm";
        "realm_id": string;
      } | {
        "kind": "circle";
        "realm_id": string;
        "circle_id": string;
      };
      "existing_managed_actor"?: {
        "ghost_actor_id": {
          "kind": "account";
          "account_id": {
            "principal_id": string;
            "station_id": string;
          };
        } | {
          "kind": "service";
          "service_id": string;
        };
        "managed_actor_provision_ref": string;
        "principal_control_realm_id": string;
        "profile_event_ref": string;
        "accountability_grant_ref": string;
      };
    };
    "governance_station_id": string;
    "issued_at": string;
    "expires_at": string;
    "proof": {
      "kind": "detached_jws";
      "verification_method": string;
      "payload_digest": string;
      "created_at": string;
      "audience_id": string;
      "jws": string;
    };
  } & {
    "purpose"?: "provision_bot";
    [key: string]: unknown;
  };
  "managed_actor_bundle": {
    "schema": "ak.schema.applet_managed_actor_authoring_bundle.v1";
    "authoring_request_digest": string;
    "managed_actor_provision_event": {
      "event_id": string;
      "kind": string;
      "realm_id"?: string;
      "scope_ref": {
        "kind": "realm";
        "realm_id": string;
      } | {
        "kind": "circle";
        "realm_id": string;
        "circle_id": string;
      } | {
        "kind": "sidecar";
        "realm_id": string;
        "sidecar_id": string;
      } | {
        "kind": "realm_genesis";
      };
      "actor_id": {
        "kind": "account";
        "account_id": {
          "principal_id": string;
          "station_id": string;
        };
      } | {
        "kind": "service";
        "service_id": string;
      };
      "executed_by"?: {
        "kind": "account";
        "account_id": {
          "principal_id": string;
          "station_id": string;
        };
      } | {
        "kind": "service";
        "service_id": string;
      };
      "authorization_ref"?: string | "ak.authority.direct_conversation_participant.v1" | "ak.authority.direct_conversation_bootstrap_participant.v1";
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
        "uri"?: string;
        [key: string]: unknown;
      };
      "created_at": string;
      "semantic_refs"?: Array<{
        "id": string;
        "role": "authorized_by";
        "critical": boolean;
      } | {
        "id": string;
        "role": "attestation" | "parent_event" | "after" | "audit_pair" | "recovery_capability" | "accountability" | "bootstrap_genesis" | "disclosure_authorization" | "capture_stop" | "direct_conversation_binding" | "direct_conversation_founding_unit" | "direct_conversation_contact_round" | "direct_conversation_agent_provision" | "applet_managed_actor_provision";
        "critical": boolean;
      }>;
      "payload": Record<string, unknown>;
      "producer_proof": {
        "kind": "detached_jws";
        "verification_method": string;
        "event_digest": string;
        "created_at": string;
        "domain"?: string;
        "audience"?: string | string[];
        "proof_purpose"?: "issuer_attestation" | "holder_acceptance";
        "jws": string;
      };
    } & {
      "kind": "ak.applet.managed_actor.provision";
      [key: string]: unknown;
    };
    "pcr_genesis_event": {
      "event_id": string;
      "kind": string;
      "realm_id"?: string;
      "scope_ref": {
        "kind": "realm";
        "realm_id": string;
      } | {
        "kind": "circle";
        "realm_id": string;
        "circle_id": string;
      } | {
        "kind": "sidecar";
        "realm_id": string;
        "sidecar_id": string;
      } | {
        "kind": "realm_genesis";
      };
      "actor_id": {
        "kind": "account";
        "account_id": {
          "principal_id": string;
          "station_id": string;
        };
      } | {
        "kind": "service";
        "service_id": string;
      };
      "executed_by"?: {
        "kind": "account";
        "account_id": {
          "principal_id": string;
          "station_id": string;
        };
      } | {
        "kind": "service";
        "service_id": string;
      };
      "authorization_ref"?: string | "ak.authority.direct_conversation_participant.v1" | "ak.authority.direct_conversation_bootstrap_participant.v1";
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
        "uri"?: string;
        [key: string]: unknown;
      };
      "created_at": string;
      "semantic_refs"?: Array<{
        "id": string;
        "role": "authorized_by";
        "critical": boolean;
      } | {
        "id": string;
        "role": "attestation" | "parent_event" | "after" | "audit_pair" | "recovery_capability" | "accountability" | "bootstrap_genesis" | "disclosure_authorization" | "capture_stop" | "direct_conversation_binding" | "direct_conversation_founding_unit" | "direct_conversation_contact_round" | "direct_conversation_agent_provision" | "applet_managed_actor_provision";
        "critical": boolean;
      }>;
      "payload": Record<string, unknown>;
      "producer_proof": {
        "kind": "detached_jws";
        "verification_method": string;
        "event_digest": string;
        "created_at": string;
        "domain"?: string;
        "audience"?: string | string[];
        "proof_purpose"?: "issuer_attestation" | "holder_acceptance";
        "jws": string;
      };
    } & {
      "kind": "ak.realm.create";
      [key: string]: unknown;
    };
    "accountability_grant_event": {
      "event_id": string;
      "kind": string;
      "realm_id"?: string;
      "scope_ref": {
        "kind": "realm";
        "realm_id": string;
      } | {
        "kind": "circle";
        "realm_id": string;
        "circle_id": string;
      } | {
        "kind": "sidecar";
        "realm_id": string;
        "sidecar_id": string;
      } | {
        "kind": "realm_genesis";
      };
      "actor_id": {
        "kind": "account";
        "account_id": {
          "principal_id": string;
          "station_id": string;
        };
      } | {
        "kind": "service";
        "service_id": string;
      };
      "executed_by"?: {
        "kind": "account";
        "account_id": {
          "principal_id": string;
          "station_id": string;
        };
      } | {
        "kind": "service";
        "service_id": string;
      };
      "authorization_ref"?: string | "ak.authority.direct_conversation_participant.v1" | "ak.authority.direct_conversation_bootstrap_participant.v1";
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
        "uri"?: string;
        [key: string]: unknown;
      };
      "created_at": string;
      "semantic_refs"?: Array<{
        "id": string;
        "role": "authorized_by";
        "critical": boolean;
      } | {
        "id": string;
        "role": "attestation" | "parent_event" | "after" | "audit_pair" | "recovery_capability" | "accountability" | "bootstrap_genesis" | "disclosure_authorization" | "capture_stop" | "direct_conversation_binding" | "direct_conversation_founding_unit" | "direct_conversation_contact_round" | "direct_conversation_agent_provision" | "applet_managed_actor_provision";
        "critical": boolean;
      }>;
      "payload": Record<string, unknown>;
      "producer_proof": {
        "kind": "detached_jws";
        "verification_method": string;
        "event_digest": string;
        "created_at": string;
        "domain"?: string;
        "audience"?: string | string[];
        "proof_purpose"?: "issuer_attestation" | "holder_acceptance";
        "jws": string;
      };
    } & {
      "kind": "ak.identity.accountability_grant";
      [key: string]: unknown;
    };
    "profile_event": {
      "event_id": string;
      "kind": string;
      "realm_id"?: string;
      "scope_ref": {
        "kind": "realm";
        "realm_id": string;
      } | {
        "kind": "circle";
        "realm_id": string;
        "circle_id": string;
      } | {
        "kind": "sidecar";
        "realm_id": string;
        "sidecar_id": string;
      } | {
        "kind": "realm_genesis";
      };
      "actor_id": {
        "kind": "account";
        "account_id": {
          "principal_id": string;
          "station_id": string;
        };
      } | {
        "kind": "service";
        "service_id": string;
      };
      "executed_by"?: {
        "kind": "account";
        "account_id": {
          "principal_id": string;
          "station_id": string;
        };
      } | {
        "kind": "service";
        "service_id": string;
      };
      "authorization_ref"?: string | "ak.authority.direct_conversation_participant.v1" | "ak.authority.direct_conversation_bootstrap_participant.v1";
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
        "uri"?: string;
        [key: string]: unknown;
      };
      "created_at": string;
      "semantic_refs"?: Array<{
        "id": string;
        "role": "authorized_by";
        "critical": boolean;
      } | {
        "id": string;
        "role": "attestation" | "parent_event" | "after" | "audit_pair" | "recovery_capability" | "accountability" | "bootstrap_genesis" | "disclosure_authorization" | "capture_stop" | "direct_conversation_binding" | "direct_conversation_founding_unit" | "direct_conversation_contact_round" | "direct_conversation_agent_provision" | "applet_managed_actor_provision";
        "critical": boolean;
      }>;
      "payload": Record<string, unknown>;
      "producer_proof": {
        "kind": "detached_jws";
        "verification_method": string;
        "event_digest": string;
        "created_at": string;
        "domain"?: string;
        "audience"?: string | string[];
        "proof_purpose"?: "issuer_attestation" | "holder_acceptance";
        "jws": string;
      };
    } & {
      "kind": "ak.profile.create";
      [key: string]: unknown;
    };
    "proof": {
      "kind": "detached_jws";
      "verification_method": string;
      "payload_digest": string;
      "created_at": string;
      "audience_id": string;
      "jws": string;
    };
  };
  "approval_signatures"?: Array<{
    "input": {
      "approval_context": {
        "context_kind": "grant";
        "grant_id": string;
      } | {
        "context_kind": "realm_governance";
      } | {
        "context_kind": "list_wip";
        "list_space_id": string;
        "list_policy_revision": {
          "commit_id": string;
          "stream_position": number;
        };
      } | {
        "context_kind": "management";
        "management_operation": "join" | "publish" | "create_bot" | "map_ghost";
        "effective_scope": {
          "kind": "realm";
          "realm_id": string;
        } | {
          "kind": "circle";
          "realm_id": string;
          "circle_id": string;
        };
        "request_id": string;
      };
      "approval_target": {
        "target_kind": "event";
        "event_id": string;
      } | {
        "target_kind": "operation";
      };
      "request_canonical_digest": string;
      "operation": string;
      "action": string;
      "realm_id": string;
      "initiating_actor_id": {
        "kind": "account";
        "account_id": {
          "principal_id": string;
          "station_id": string;
        };
      } | {
        "kind": "service";
        "service_id": string;
      };
      "approver_did": string;
      "approved_at": string;
      "nonce": string;
    };
    "proof": {
      "kind": "detached_jws";
      "verification_method": string;
      "jws": string;
    };
  }>;
};

/** `applet-bot-operations.schema.json#/$defs/bot_actor_provision_outcome` — closed object schema. */
export type AppletBotProvisionOutcome = {
  "managed_actor_provision_ref": string;
  "principal_control_realm_id": string;
  "profile_event_ref": string;
  "accountability_grant_ref": string;
  "authorization_ref": string;
  "display_name"?: string;
  "bot_actor_id": {
    "kind": "account";
    "account_id": {
      "principal_id": string;
      "station_id": string;
    };
  } | {
    "kind": "service";
    "service_id": string;
  };
};

/** `applet-authority-material.schema.json#/$defs/request` — closed object schema. */
export type AppletAuthorityMaterialRequestBody = {
  "effective_scope": {
    "kind": "realm";
    "realm_id": string;
  } | {
    "kind": "circle";
    "realm_id": string;
    "circle_id": string;
  };
  "grant_ids": string[];
};

/** `applet-authority-material.schema.json#/$defs/outcome` — closed object schema. */
export type AppletAuthorityMaterialOutcome = {
  "applet_id": string;
  "effective_scope": {
    "kind": "realm";
    "realm_id": string;
  } | {
    "kind": "circle";
    "realm_id": string;
    "circle_id": string;
  };
  "registration": {
    "commit": {
      "commit_id": string;
      "realm_id": string;
      "stream_ref": {
        "kind": "realm";
        "realm_id": string;
      } | {
        "kind": "circle";
        "realm_id": string;
        "circle_id": string;
      } | {
        "kind": "sidecar";
        "realm_id": string;
        "sidecar_id": string;
      };
      "stream_position": number;
      "previous_commit_ref": string | null;
      "event_ref": string;
      "governance_generation": number;
      "authority_ref": string;
      "committed_at": string;
      "producer_signer_fact_digest"?: string;
      "signature": {
        "context": "ak.realm_commit_signature.v1";
        "signature_algorithm": "Ed25519";
        "verification_method": string;
        "signed_digest": string;
        "created_at": string;
        "sig": string;
      };
    };
    "event": {
      "event_id": string;
      "kind": "ak.agent.action_approve" | "ak.agent.interaction.set" | "ak.agent.key.authorize" | "ak.agent.key.revoke" | "ak.agent.provision" | "ak.agent.sidecar.exchange.control" | "ak.applet.bridge_error" | "ak.applet.discovery" | "ak.applet.managed_actor.provision" | "ak.applet.registration" | "ak.audit.accessed" | "ak.audit.erasure_receipt" | "ak.call.create" | "ak.call.recording.start" | "ak.call.state" | "ak.capability.grant" | "ak.capability.relinquish" | "ak.capability.revoke" | "ak.circle.archive" | "ak.circle.create" | "ak.circle.history_access" | "ak.circle.member.state" | "ak.circle.restore" | "ak.circle.tombstone" | "ak.circle.update" | "ak.consent.grant" | "ak.consent.revoke" | "ak.contact.accepted" | "ak.contact.rejected" | "ak.contact.requested" | "ak.contact.scope.update" | "ak.contact.tombstone" | "ak.device.authorize" | "ak.device.reanchor" | "ak.device.revoke" | "ak.direct_conversation.bound" | "ak.identity.accountability_grant" | "ak.identity.resolution.update" | "ak.invite.accept" | "ak.invite.cancel" | "ak.invite.claim" | "ak.invite.create" | "ak.invite.revoke" | "ak.invite.third_party" | "ak.key_backup.active_series" | "ak.member.identity.update" | "ak.member.state" | "ak.message.create" | "ak.message.redact" | "ak.message.revise" | "ak.mimi.room_binding" | "ak.mls.commit" | "ak.mls.genesis" | "ak.moderation.decision" | "ak.moderation.decision.lift" | "ak.moderation.franking_proof" | "ak.morph.archive" | "ak.morph.create" | "ak.morph.restore" | "ak.morph.stage.set" | "ak.morph.update" | "ak.organization.moderation_policy" | "ak.pin.add" | "ak.pin.remove" | "ak.pin.reorder" | "ak.policy.action" | "ak.policy.set" | "ak.profile.create" | "ak.profile.realm_override" | "ak.profile.update" | "ak.reaction.add" | "ak.reaction.remove" | "ak.realm.alias" | "ak.realm.archive" | "ak.realm.asset_privacy_policy" | "ak.realm.authority.reset" | "ak.realm.create" | "ak.realm.destroy" | "ak.realm.discovery" | "ak.realm.freeze" | "ak.realm.governance_station.change" | "ak.realm.history_access" | "ak.realm.join_rule" | "ak.realm.link" | "ak.realm.media_service" | "ak.realm.organization" | "ak.realm.owner.transfer" | "ak.realm.plaintext_visible_services" | "ak.realm.policy_bundle" | "ak.realm.preview_policy" | "ak.realm.profile" | "ak.realm.read_receipt_policy" | "ak.realm.restore" | "ak.realm.schema" | "ak.realm.search_policy" | "ak.realm.set_default_strand" | "ak.realm.tombstone" | "ak.realm.unfreeze" | "ak.redaction" | "ak.relation.create" | "ak.relation.tombstone" | "ak.relation.update" | "ak.rsvp.set" | "ak.schema.define" | "ak.self.agent.deactivate" | "ak.self.agent.pause" | "ak.self.agent.resume" | "ak.self.moderation.report" | "ak.sidecar.context.attach" | "ak.sidecar.create" | "ak.space.archive" | "ak.space.create" | "ak.space.parent" | "ak.space.restore" | "ak.space.tombstone" | "ak.space.update" | "ak.strand.archive" | "ak.strand.create" | "ak.strand.move" | "ak.strand.reorder" | "ak.strand.restore" | "ak.strand.stage.set" | "ak.strand.tracks.update" | "ak.strand.update" | "ak.strand.watch.set" | "ak.view.create" | "ak.view.reconcile" | "ak.view.update";
      "realm_id"?: string;
      "scope_ref": {
        "kind": "realm";
        "realm_id": string;
      } | {
        "kind": "circle";
        "realm_id": string;
        "circle_id": string;
      } | {
        "kind": "sidecar";
        "realm_id": string;
        "sidecar_id": string;
      } | {
        "kind": "realm_genesis";
      };
      "actor_id": {
        "kind": "account";
        "account_id": {
          "principal_id": string;
          "station_id": string;
        };
      } | {
        "kind": "service";
        "service_id": string;
      };
      "executed_by"?: {
        "kind": "account";
        "account_id": {
          "principal_id": string;
          "station_id": string;
        };
      } | {
        "kind": "service";
        "service_id": string;
      };
      "authorization_ref"?: string | "ak.authority.direct_conversation_participant.v1" | "ak.authority.direct_conversation_bootstrap_participant.v1";
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
        "uri"?: string;
        [key: string]: unknown;
      };
      "created_at": string;
      "semantic_refs"?: Array<{
        "id": string;
        "role": "authorized_by";
        "critical": boolean;
      } | {
        "id": string;
        "role": "attestation" | "parent_event" | "after" | "audit_pair" | "recovery_capability" | "accountability" | "bootstrap_genesis" | "disclosure_authorization" | "capture_stop" | "direct_conversation_binding" | "direct_conversation_founding_unit" | "direct_conversation_contact_round" | "direct_conversation_agent_provision" | "applet_managed_actor_provision";
        "critical": boolean;
      }>;
      "payload": Record<string, unknown>;
      "producer_proof": {
        "kind": "detached_jws";
        "verification_method": string;
        "event_digest": string;
        "created_at": string;
        "domain"?: string;
        "audience"?: string | string[];
        "proof_purpose"?: "issuer_attestation" | "holder_acceptance";
        "jws": string;
      };
    };
    "producer_device_evidence"?: {
      "device_projection_attestation": {
        "attestation": {
          "account_id": {
            "principal_id": string;
            "station_id": string;
          };
          "device_id": string;
          "device_signing_key_did": string;
          "hpke_key": string;
          "device_authorize_event_id": string;
          "authorized_generation_ref": number;
          "device_status": "active";
          "attested_at": string;
          "expires_at": string;
          "authorization_window": {
            "not_before": string;
            "expires_at": string | null;
          };
        };
        "proof": {
          "verification_method": string;
          "created_at": string;
          "jws": string;
        };
      };
      "service_resolution": {
        "service_id": string;
        "service_kind": string;
        "method_history_evidence": {
          "evidence_kind": "webvh_log";
          "boundary": {
            "from_method_history_head": string;
            "from_version_id": string;
            "to_method_history_head": string;
            "to_version_id": string;
          };
          "evidence": {
            "kind": "ak.did.binding_evidence.v1";
            "method": string;
            "document_digest": string;
            "method_proofs": Array<{
              "kind": "webvh_log";
              "history_head": string;
              "witnesses": Array<{
                "witness_did": string;
                "controlling_organization_did": string;
              }>;
              "witness_proofs_digest": string;
            }>;
          };
          "log_entries": Array<Record<string, unknown>>;
          "witness_records": Array<Record<string, unknown>>;
        } | {
          "evidence_kind": "did_web_document";
          "boundary": {
            "from_method_history_head": string;
            "from_version_id": string;
            "to_method_history_head": string;
            "to_version_id": string;
          };
          "evidence": {
            "kind": "ak.did.binding_evidence.v1";
            "method": string;
            "document_digest": string;
            "method_proofs": Array<{
              "kind": "webvh_log";
              "history_head": string;
              "witnesses": Array<{
                "witness_did": string;
                "controlling_organization_did": string;
              }>;
              "witness_proofs_digest": string;
            }>;
          };
        } | {
          "evidence_kind": "did_key_expansion";
          "boundary": {
            "from_method_history_head": string;
            "from_version_id": string;
            "to_method_history_head": string;
            "to_version_id": string;
          };
          "evidence": {
            "kind": "ak.did.binding_evidence.v1";
            "method": string;
            "document_digest": string;
            "method_proofs": Array<{
              "kind": "webvh_log";
              "history_head": string;
              "witnesses": Array<{
                "witness_did": string;
                "controlling_organization_did": string;
              }>;
              "witness_proofs_digest": string;
            }>;
          };
        };
        "normalized_did_document": {
          "did": string;
          "contexts": Array<string | Record<string, unknown>>;
          "controller_dids": string[];
          "also_known_as": string[];
          "verification_methods": Array<{
            "verification_method": string;
            "controller_did": string;
            "verification_method_suite": string;
            "public_key_material": Record<string, unknown>;
            "extensions": Array<{
              "name": string;
              "value": unknown;
            }>;
          }>;
          "authentication": Array<{
            "verification_method": string;
          }>;
          "assertion_methods": Array<{
            "verification_method": string;
          }>;
          "key_agreements": Array<{
            "verification_method": string;
          }>;
          "capability_invocations": Array<{
            "verification_method": string;
          }>;
          "capability_delegations": Array<{
            "verification_method": string;
          }>;
          "services": Array<{
            "uri": string;
            "protocol_names": string[];
            "endpoint": unknown;
            "extensions": Array<{
              "name": string;
              "value": unknown;
            }>;
          }>;
          "metadata": {
            "primary_handle"?: string;
          };
          "extensions": Array<{
            "name": string;
            "value": unknown;
          }>;
        };
      };
    };
  };
  "grant_events": Array<{
    "commit": {
      "commit_id": string;
      "realm_id": string;
      "stream_ref": {
        "kind": "realm";
        "realm_id": string;
      } | {
        "kind": "circle";
        "realm_id": string;
        "circle_id": string;
      } | {
        "kind": "sidecar";
        "realm_id": string;
        "sidecar_id": string;
      };
      "stream_position": number;
      "previous_commit_ref": string | null;
      "event_ref": string;
      "governance_generation": number;
      "authority_ref": string;
      "committed_at": string;
      "producer_signer_fact_digest"?: string;
      "signature": {
        "context": "ak.realm_commit_signature.v1";
        "signature_algorithm": "Ed25519";
        "verification_method": string;
        "signed_digest": string;
        "created_at": string;
        "sig": string;
      };
    };
    "event": {
      "event_id": string;
      "kind": "ak.agent.action_approve" | "ak.agent.interaction.set" | "ak.agent.key.authorize" | "ak.agent.key.revoke" | "ak.agent.provision" | "ak.agent.sidecar.exchange.control" | "ak.applet.bridge_error" | "ak.applet.discovery" | "ak.applet.managed_actor.provision" | "ak.applet.registration" | "ak.audit.accessed" | "ak.audit.erasure_receipt" | "ak.call.create" | "ak.call.recording.start" | "ak.call.state" | "ak.capability.grant" | "ak.capability.relinquish" | "ak.capability.revoke" | "ak.circle.archive" | "ak.circle.create" | "ak.circle.history_access" | "ak.circle.member.state" | "ak.circle.restore" | "ak.circle.tombstone" | "ak.circle.update" | "ak.consent.grant" | "ak.consent.revoke" | "ak.contact.accepted" | "ak.contact.rejected" | "ak.contact.requested" | "ak.contact.scope.update" | "ak.contact.tombstone" | "ak.device.authorize" | "ak.device.reanchor" | "ak.device.revoke" | "ak.direct_conversation.bound" | "ak.identity.accountability_grant" | "ak.identity.resolution.update" | "ak.invite.accept" | "ak.invite.cancel" | "ak.invite.claim" | "ak.invite.create" | "ak.invite.revoke" | "ak.invite.third_party" | "ak.key_backup.active_series" | "ak.member.identity.update" | "ak.member.state" | "ak.message.create" | "ak.message.redact" | "ak.message.revise" | "ak.mimi.room_binding" | "ak.mls.commit" | "ak.mls.genesis" | "ak.moderation.decision" | "ak.moderation.decision.lift" | "ak.moderation.franking_proof" | "ak.morph.archive" | "ak.morph.create" | "ak.morph.restore" | "ak.morph.stage.set" | "ak.morph.update" | "ak.organization.moderation_policy" | "ak.pin.add" | "ak.pin.remove" | "ak.pin.reorder" | "ak.policy.action" | "ak.policy.set" | "ak.profile.create" | "ak.profile.realm_override" | "ak.profile.update" | "ak.reaction.add" | "ak.reaction.remove" | "ak.realm.alias" | "ak.realm.archive" | "ak.realm.asset_privacy_policy" | "ak.realm.authority.reset" | "ak.realm.create" | "ak.realm.destroy" | "ak.realm.discovery" | "ak.realm.freeze" | "ak.realm.governance_station.change" | "ak.realm.history_access" | "ak.realm.join_rule" | "ak.realm.link" | "ak.realm.media_service" | "ak.realm.organization" | "ak.realm.owner.transfer" | "ak.realm.plaintext_visible_services" | "ak.realm.policy_bundle" | "ak.realm.preview_policy" | "ak.realm.profile" | "ak.realm.read_receipt_policy" | "ak.realm.restore" | "ak.realm.schema" | "ak.realm.search_policy" | "ak.realm.set_default_strand" | "ak.realm.tombstone" | "ak.realm.unfreeze" | "ak.redaction" | "ak.relation.create" | "ak.relation.tombstone" | "ak.relation.update" | "ak.rsvp.set" | "ak.schema.define" | "ak.self.agent.deactivate" | "ak.self.agent.pause" | "ak.self.agent.resume" | "ak.self.moderation.report" | "ak.sidecar.context.attach" | "ak.sidecar.create" | "ak.space.archive" | "ak.space.create" | "ak.space.parent" | "ak.space.restore" | "ak.space.tombstone" | "ak.space.update" | "ak.strand.archive" | "ak.strand.create" | "ak.strand.move" | "ak.strand.reorder" | "ak.strand.restore" | "ak.strand.stage.set" | "ak.strand.tracks.update" | "ak.strand.update" | "ak.strand.watch.set" | "ak.view.create" | "ak.view.reconcile" | "ak.view.update";
      "realm_id"?: string;
      "scope_ref": {
        "kind": "realm";
        "realm_id": string;
      } | {
        "kind": "circle";
        "realm_id": string;
        "circle_id": string;
      } | {
        "kind": "sidecar";
        "realm_id": string;
        "sidecar_id": string;
      } | {
        "kind": "realm_genesis";
      };
      "actor_id": {
        "kind": "account";
        "account_id": {
          "principal_id": string;
          "station_id": string;
        };
      } | {
        "kind": "service";
        "service_id": string;
      };
      "executed_by"?: {
        "kind": "account";
        "account_id": {
          "principal_id": string;
          "station_id": string;
        };
      } | {
        "kind": "service";
        "service_id": string;
      };
      "authorization_ref"?: string | "ak.authority.direct_conversation_participant.v1" | "ak.authority.direct_conversation_bootstrap_participant.v1";
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
        "uri"?: string;
        [key: string]: unknown;
      };
      "created_at": string;
      "semantic_refs"?: Array<{
        "id": string;
        "role": "authorized_by";
        "critical": boolean;
      } | {
        "id": string;
        "role": "attestation" | "parent_event" | "after" | "audit_pair" | "recovery_capability" | "accountability" | "bootstrap_genesis" | "disclosure_authorization" | "capture_stop" | "direct_conversation_binding" | "direct_conversation_founding_unit" | "direct_conversation_contact_round" | "direct_conversation_agent_provision" | "applet_managed_actor_provision";
        "critical": boolean;
      }>;
      "payload": Record<string, unknown>;
      "producer_proof": {
        "kind": "detached_jws";
        "verification_method": string;
        "event_digest": string;
        "created_at": string;
        "domain"?: string;
        "audience"?: string | string[];
        "proof_purpose"?: "issuer_attestation" | "holder_acceptance";
        "jws": string;
      };
    };
    "producer_device_evidence"?: {
      "device_projection_attestation": {
        "attestation": {
          "account_id": {
            "principal_id": string;
            "station_id": string;
          };
          "device_id": string;
          "device_signing_key_did": string;
          "hpke_key": string;
          "device_authorize_event_id": string;
          "authorized_generation_ref": number;
          "device_status": "active";
          "attested_at": string;
          "expires_at": string;
          "authorization_window": {
            "not_before": string;
            "expires_at": string | null;
          };
        };
        "proof": {
          "verification_method": string;
          "created_at": string;
          "jws": string;
        };
      };
      "service_resolution": {
        "service_id": string;
        "service_kind": string;
        "method_history_evidence": {
          "evidence_kind": "webvh_log";
          "boundary": {
            "from_method_history_head": string;
            "from_version_id": string;
            "to_method_history_head": string;
            "to_version_id": string;
          };
          "evidence": {
            "kind": "ak.did.binding_evidence.v1";
            "method": string;
            "document_digest": string;
            "method_proofs": Array<{
              "kind": "webvh_log";
              "history_head": string;
              "witnesses": Array<{
                "witness_did": string;
                "controlling_organization_did": string;
              }>;
              "witness_proofs_digest": string;
            }>;
          };
          "log_entries": Array<Record<string, unknown>>;
          "witness_records": Array<Record<string, unknown>>;
        } | {
          "evidence_kind": "did_web_document";
          "boundary": {
            "from_method_history_head": string;
            "from_version_id": string;
            "to_method_history_head": string;
            "to_version_id": string;
          };
          "evidence": {
            "kind": "ak.did.binding_evidence.v1";
            "method": string;
            "document_digest": string;
            "method_proofs": Array<{
              "kind": "webvh_log";
              "history_head": string;
              "witnesses": Array<{
                "witness_did": string;
                "controlling_organization_did": string;
              }>;
              "witness_proofs_digest": string;
            }>;
          };
        } | {
          "evidence_kind": "did_key_expansion";
          "boundary": {
            "from_method_history_head": string;
            "from_version_id": string;
            "to_method_history_head": string;
            "to_version_id": string;
          };
          "evidence": {
            "kind": "ak.did.binding_evidence.v1";
            "method": string;
            "document_digest": string;
            "method_proofs": Array<{
              "kind": "webvh_log";
              "history_head": string;
              "witnesses": Array<{
                "witness_did": string;
                "controlling_organization_did": string;
              }>;
              "witness_proofs_digest": string;
            }>;
          };
        };
        "normalized_did_document": {
          "did": string;
          "contexts": Array<string | Record<string, unknown>>;
          "controller_dids": string[];
          "also_known_as": string[];
          "verification_methods": Array<{
            "verification_method": string;
            "controller_did": string;
            "verification_method_suite": string;
            "public_key_material": Record<string, unknown>;
            "extensions": Array<{
              "name": string;
              "value": unknown;
            }>;
          }>;
          "authentication": Array<{
            "verification_method": string;
          }>;
          "assertion_methods": Array<{
            "verification_method": string;
          }>;
          "key_agreements": Array<{
            "verification_method": string;
          }>;
          "capability_invocations": Array<{
            "verification_method": string;
          }>;
          "capability_delegations": Array<{
            "verification_method": string;
          }>;
          "services": Array<{
            "uri": string;
            "protocol_names": string[];
            "endpoint": unknown;
            "extensions": Array<{
              "name": string;
              "value": unknown;
            }>;
          }>;
          "metadata": {
            "primary_handle"?: string;
          };
          "extensions": Array<{
            "name": string;
            "value": unknown;
          }>;
        };
      };
    };
  }>;
  "current_results": Array<{
    "status": "present";
    "realm_id": string;
    "governance_generation": number;
    "effective_stream_head": {
      "stream_ref": {
        "kind": "realm";
        "realm_id": string;
      } | {
        "kind": "circle";
        "realm_id": string;
        "circle_id": string;
      } | {
        "kind": "sidecar";
        "realm_id": string;
        "sidecar_id": string;
      };
      "stream_position": number;
      "commit_id": string;
    };
    "entry": {
      "selector": {
        "kind": "relation";
        "primary_conflict_domain": {
          "domain_kind": "tuple" | "from";
          "relation_kind": string;
          "from_ref": string | {
            "kind": "account";
            "account_id": {
              "principal_id": string;
              "station_id": string;
            };
          } | {
            "kind": "service";
            "service_id": string;
          };
          "to_ref"?: string | {
            "kind": "account";
            "account_id": {
              "principal_id": string;
              "station_id": string;
            };
          } | {
            "kind": "service";
            "service_id": string;
          };
        };
      };
      "source_stream_ref": {
        "kind": "realm";
        "realm_id": string;
      } | {
        "kind": "circle";
        "realm_id": string;
        "circle_id": string;
      } | {
        "kind": "sidecar";
        "realm_id": string;
        "sidecar_id": string;
      };
      "revision": {
        "commit_id": string;
        "stream_position": number;
      };
      "value": {
        "id"?: string;
        "schema": "ak.schema.relation.v1";
        "realm_id": string;
        "scope_circle_id"?: string;
        "effective_scope"?: {
          "kind": "realm";
          "realm_id": string;
        } | {
          "kind": "circle";
          "realm_id": string;
          "circle_id": string;
        };
        "relation_kind": string;
        "from_ref": string | {
          "kind": "account";
          "account_id": {
            "principal_id": string;
            "station_id": string;
          };
        } | {
          "kind": "service";
          "service_id": string;
        };
        "to_ref": string | {
          "kind": "account";
          "account_id": {
            "principal_id": string;
            "station_id": string;
          };
        } | {
          "kind": "service";
          "service_id": string;
        };
        "rank"?: string;
        "fields"?: Record<string, unknown>;
        "state"?: "active" | "tombstoned";
        "state_changed_at"?: string;
        "created_by": {
          "kind": "account";
          "account_id": {
            "principal_id": string;
            "station_id": string;
          };
        } | {
          "kind": "service";
          "service_id": string;
        };
        "created_at": string;
        "updated_by"?: {
          "kind": "account";
          "account_id": {
            "principal_id": string;
            "station_id": string;
          };
        } | {
          "kind": "service";
          "service_id": string;
        };
        "updated_at"?: string;
      };
    } | {
      "selector": {
        "kind": "moderation_state";
        "target_ref": string;
      };
      "source_stream_ref": {
        "kind": "realm";
        "realm_id": string;
      } | {
        "kind": "circle";
        "realm_id": string;
        "circle_id": string;
      } | {
        "kind": "sidecar";
        "realm_id": string;
        "sidecar_id": string;
      };
      "revision": {
        "commit_id": string;
        "stream_position": number;
      };
      "value": {
        "assertions": Array<{
          "tag_id": string;
          "value": {
            "target_ref": string;
            "decision": "hard_deny" | "quarantine" | "require_review" | "dismiss";
            "issuer_id": string;
            "request_canonical_digest": string;
            "action"?: "deny_join" | "deny_restricted_join" | "deny_invite" | "deny_write" | "deny_federation" | "quarantine_message" | "require_review" | "redact_on_accept" | "shadow_collapse";
            "reason_code"?: string;
            "reason"?: string;
            "effective_at"?: string;
            "expires_at"?: string | null;
          } | {
            "target_ref": string;
            "decision_ref": string;
            "expected_revision": {
              "commit_id": string;
              "stream_position": number;
            };
            "reason_code"?: string;
            "reason"?: string;
            "effective_at"?: string;
          };
        }>;
      };
    } | {
      "selector": {
        "kind": "agent_interaction";
        "agent_account_id": {
          "principal_id": string;
          "station_id": string;
        };
      };
      "source_stream_ref": {
        "kind": "realm";
        "realm_id": string;
      } | {
        "kind": "circle";
        "realm_id": string;
        "circle_id": string;
      } | {
        "kind": "sidecar";
        "realm_id": string;
        "sidecar_id": string;
      };
      "revision": {
        "commit_id": string;
        "stream_position": number;
      };
      "value": {
        "controller_account_id": {
          "principal_id": string;
          "station_id": string;
        };
        "interaction_mode": "private" | "public";
      };
    } | {
      "selector": {
        "kind": "capability_grant";
        "grant_id": string;
      };
      "source_stream_ref": {
        "kind": "realm";
        "realm_id": string;
      } | {
        "kind": "circle";
        "realm_id": string;
        "circle_id": string;
      } | {
        "kind": "sidecar";
        "realm_id": string;
        "sidecar_id": string;
      };
      "revision": {
        "commit_id": string;
        "stream_position": number;
      };
      "value": {
        "id": string;
        "schema": "ak.schema.capability.v1";
        "realm_id"?: string;
        "issuer_id": {
          "kind": "account";
          "account_id": {
            "principal_id": string;
            "station_id": string;
          };
        } | {
          "kind": "service";
          "service_id": string;
        };
        "subject": {
          "kind": "account";
          "account_id": {
            "principal_id": string;
            "station_id": string;
          };
        } | {
          "kind": "service";
          "service_id": string;
        } | {
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
          "actor_id"?: {
            "kind": "account";
            "account_id": {
              "principal_id": string;
              "station_id": string;
            };
          } | {
            "kind": "service";
            "service_id": string;
          };
          "schema_ref"?: string;
          "policy_id"?: string;
          "invite_id"?: string;
          "blob_ref"?: string;
          "match_scope"?: "exact" | "realm_wide";
        }>;
        "constraints"?: Array<{
          "constraint_id"?: string;
          "constraint_kind": "temporal" | "field_access" | "kind_restriction" | "scope_limitation" | "authority_control" | "quota" | "claim_based" | "confidentiality";
          "effect": "allow" | "deny" | "quarantine" | "require_review";
          "evaluation_class"?: "stateless" | "grant_local" | "realm_state" | "external";
          "constraint_subkind"?: "claim" | "approval" | "accountability" | "rate" | "resource" | "encryption" | "visibility" | "window" | "edit_window" | "redact_window" | "session" | "applet_authority";
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
          "max_authority_depth"?: number;
          "authority_path_ids"?: string[];
          "authority_regrant_allowed"?: boolean;
          "authority_scope"?: "narrowing_only" | "same_scope" | "custom";
          "applet_id"?: string;
          "executed_by"?: {
            "kind": "account";
            "account_id": {
              "principal_id": string;
              "station_id": string;
            };
          } | {
            "kind": "service";
            "service_id": string;
          };
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
          "approval_mode"?: "before_commit";
          "approval_actor_ids"?: string[];
          "approval_relation"?: "responsible" | "controller" | "guardian" | "realm_admin" | "custom";
          "timeout"?: string;
          "approval_threshold"?: "majority" | "unanimous" | number;
          "accountability_required"?: boolean;
          "guardian_approval_required"?: boolean;
          "controller_approval_required"?: boolean;
          "required_claims"?: unknown[];
          "trusted_claim_issuer_ids"?: string[];
          "claim_refresh_required"?: boolean;
          "claim_max_age"?: string;
          "allowed_history_access_values"?: Array<"since_join" | "all_history_for_current_members">;
          "redacted_history_allowed"?: boolean;
          "encryption_required"?: boolean;
          "min_encryption_level"?: "none" | "mls_rfc9420" | "external";
          "plaintext_fallback_allowed"?: boolean;
          "audit_trail_required"?: boolean;
          "key_rotation_period"?: string;
          "max_key_age"?: string;
          "key_backup_required"?: boolean;
          "approved_key_issuer_ids"?: string[];
          "depends_on_moderation_state"?: boolean;
          "allowed_managed_actor_roles"?: Array<"bot" | "ghost">;
        }>;
        "issued_at": string;
        "status": "active" | "revoked" | "relinquished";
        "updated_by"?: {
          "kind": "account";
          "account_id": {
            "principal_id": string;
            "station_id": string;
          };
        } | {
          "kind": "service";
          "service_id": string;
        };
        "updated_at"?: string;
        "revoked_by"?: {
          "kind": "account";
          "account_id": {
            "principal_id": string;
            "station_id": string;
          };
        } | {
          "kind": "service";
          "service_id": string;
        };
        "revoked_at"?: string;
        "issuer_authority_refs": Array<{
          "kind": "grant";
          "grant_id": string;
        } | {
          "kind": "realm_root";
          "realm_id": string;
          "authority_event_ref": string;
          "authority_generation": number;
        } | {
          "kind": "owned_agent";
          "realm_id": string;
          "controller_account_id": {
            "principal_id": string;
            "station_id": string;
          };
          "controller_join_event_id": string;
          "agent_join_event_id": string;
        }>;
        "authority_depth": number;
        "authority_root_refs": Array<{
          "kind": "realm_root";
          "realm_id": string;
          "authority_event_ref": string;
          "authority_generation": number;
        } | {
          "kind": "owned_agent";
          "realm_id": string;
          "controller_account_id": {
            "principal_id": string;
            "station_id": string;
          };
          "controller_join_event_id": string;
          "agent_join_event_id": string;
        }>;
      };
    } | {
      "selector": {
        "kind": "calendar_schedule_source";
        "strand_id": string;
      };
      "source_stream_ref": {
        "kind": "realm";
        "realm_id": string;
      } | {
        "kind": "circle";
        "realm_id": string;
        "circle_id": string;
      } | {
        "kind": "sidecar";
        "realm_id": string;
        "sidecar_id": string;
      };
      "revision": {
        "commit_id": string;
        "stream_position": number;
      };
      "value": {
        "effective_scope": {
          "kind": "realm";
          "realm_id": string;
        } | {
          "kind": "circle";
          "realm_id": string;
          "circle_id": string;
        } | {
          "kind": "sidecar";
          "realm_id": string;
          "sidecar_id": string;
        } | {
          "kind": "realm_genesis";
        };
        "source": {
          "event_id": string;
          "commit_id": string;
          "stream_ref": {
            "kind": "realm";
            "realm_id": string;
          } | {
            "kind": "circle";
            "realm_id": string;
            "circle_id": string;
          } | {
            "kind": "sidecar";
            "realm_id": string;
            "sidecar_id": string;
          };
          "stream_position": number;
        } | null;
        "strand_revision": {
          "commit_id": string;
          "stream_position": number;
        };
        "metadata_context": {
          "source": {
            "event_id": string;
            "commit_id": string;
            "stream_ref": {
              "kind": "realm";
              "realm_id": string;
            } | {
              "kind": "circle";
              "realm_id": string;
              "circle_id": string;
            } | {
              "kind": "sidecar";
              "realm_id": string;
              "sidecar_id": string;
            };
            "stream_position": number;
          };
          "event_kind": "ak.strand.create" | "ak.strand.update";
          "signer_id": {
            "kind": "account";
            "account_id": {
              "principal_id": string;
              "station_id": string;
            };
          } | {
            "kind": "service";
            "service_id": string;
          };
          "payload_digest": string;
        } | null;
      };
    } | {
      "selector": {
        "kind": "policy";
        "policy_id": string;
      };
      "source_stream_ref": {
        "kind": "realm";
        "realm_id": string;
      } | {
        "kind": "circle";
        "realm_id": string;
        "circle_id": string;
      } | {
        "kind": "sidecar";
        "realm_id": string;
        "sidecar_id": string;
      };
      "revision": {
        "commit_id": string;
        "stream_position": number;
      };
      "value": {
        "id": string;
        "schema": "ak.schema.policy.v1";
        "realm_id"?: string;
        "policy_kind": "access" | "encryption" | "retention" | "federation" | "moderation" | "discoverability" | "join" | "history_access" | "plaintext_visibility" | "media" | "applet" | "agent";
        "rules": Array<{
          "rule_id": string;
          "kind": "action" | "resource" | "server" | "actor" | "temporal" | "rate_limit" | "crypto" | "moderation" | "extension" | "agent" | "applet";
          "effect": "allow" | "deny" | "quarantine" | "require_review";
          "priority"?: number;
          "actions"?: string[];
          "resources"?: Array<{
            "kind": "realm" | "strand" | "space" | "object" | "service";
            "realm_id"?: string;
            "resource_ref"?: string;
          }>;
          "servers"?: Array<{
            "kind": "service_id" | "domain" | "trust_domain";
            "service_id"?: string;
            "domain"?: string;
            "match_subdomains"?: boolean;
            "trust_domain"?: string;
          }>;
          "conditions"?: Record<string, unknown>;
          "schema_ref"?: string;
          "profile_ref"?: string;
          "params"?: Record<string, unknown>;
          "agent_target"?: {
            "kind": "all";
          } | {
            "kind": "controller";
            "controller_account_id": {
              "principal_id": string;
              "station_id": string;
            };
          } | {
            "kind": "agent";
            "agent_account_id": {
              "principal_id": string;
              "station_id": string;
            };
          };
          "agent_operations"?: Array<"join" | "authorize" | "execute" | "read" | "deliver" | "publish" | "serve">;
          "applet_target"?: {
            "kind": "all";
          } | {
            "kind": "requester";
            "actor_id": {
              "kind": "account";
              "account_id": {
                "principal_id": string;
                "station_id": string;
              };
            } | {
              "kind": "service";
              "service_id": string;
            };
          } | {
            "kind": "installation";
            "applet_id": string;
            "effective_scope": {
              "kind": "realm";
              "realm_id": string;
            } | {
              "kind": "circle";
              "realm_id": string;
              "circle_id": string;
            };
          } | {
            "kind": "managed_actor";
            "actor_id": {
              "kind"?: "account";
              [key: string]: unknown;
            };
          };
          "applet_operations"?: Array<"install" | "create_bot" | "map_ghost" | "join" | "authorize" | "execute" | "read" | "deliver" | "publish" | "serve" | "invoke">;
          "review_requirement"?: {
            "approver_actor_ids": Array<{
              "kind": "account";
              "account_id": {
                "principal_id": string;
                "station_id": string;
              };
            } | {
              "kind": "service";
              "service_id": string;
            }>;
            "threshold": number;
            "max_age_seconds": number;
          };
        }>;
        "default_effect": "allow" | "deny" | "quarantine" | "require_review";
        "default_review_requirement"?: {
          "approver_actor_ids": Array<{
            "kind": "account";
            "account_id": {
              "principal_id": string;
              "station_id": string;
            };
          } | {
            "kind": "service";
            "service_id": string;
          }>;
          "threshold": number;
          "max_age_seconds": number;
        };
        "default_operations"?: Array<"join" | "publish" | "create_bot" | "map_ghost">;
        "priority"?: number;
        "not_before"?: string;
        "expires_at"?: string;
        "created_by": {
          "kind": "account";
          "account_id": {
            "principal_id": string;
            "station_id": string;
          };
        } | {
          "kind": "service";
          "service_id": string;
        };
        "created_at": string;
        "updated_by"?: {
          "kind": "account";
          "account_id": {
            "principal_id": string;
            "station_id": string;
          };
        } | {
          "kind": "service";
          "service_id": string;
        };
        "updated_at"?: string;
      } | {
        "schema": "ak.schema.recovery_policy.v1";
        "policy_id": string;
        "account_id": {
          "principal_id": string;
          "station_id": string;
        };
        "version": number;
        "supersedes_id": null | string;
        "trust_domain": string;
        "cooldown_seconds"?: number;
        "issued_at": string;
        "not_before"?: string;
        "expires_at"?: null | string;
        "auth_data": {
          "verification_method": string;
          "signature_algorithm": "Ed25519";
          "signature": string;
        };
        "methods": Array<{
          "kind": "did_root";
        } | {
          "kind": "recovery_unlock";
          "keys": Array<{
            "verification_method": string;
            "public_key_multibase": string;
            "signature_algorithm": "Ed25519";
            "not_before": string;
            "expires_at": string;
            "revoked_at"?: null | string;
            "backup_hpke": {
              "key_agreement_ref": string;
              "key_agreement_algorithm": "X25519";
              "public_key_multibase": string;
              "hpke_suites": Array<"ak.hpke_x25519_aead_chacha20poly1305.v1" | "ak.hpke_x25519_aead_aes256gcm.v1">;
              "use": "backup_hpke";
              "not_before": string;
              "expires_at": string;
              "revoked_at"?: null | string;
            };
          }>;
        } | {
          "kind": "device_quorum";
          "k": number;
          "member_ids": string[];
        } | {
          "kind": "trusted_recovery_service";
          "services": Array<{
            "service_id": string;
            "audience": string;
            "authorization_verification_method": string;
          }>;
        }>;
      };
    };
  }>;
};

/** `applet-device-authentication.schema.json` — closed object schema. */
export type AppletManagedDeviceMetadata = {
  "account_id": {
    "principal_id": string;
    "station_id": string;
  };
  "device_id": string;
  "authorization_event_id": string;
  "applet_id": string;
  "effective_scope": {
    "kind": "realm";
    "realm_id": string;
  } | {
    "kind": "circle";
    "realm_id": string;
    "circle_id": string;
  };
  "nonce": string;
};

/** `realm-join-intake.schema.json#/$defs/self_prepare_request_body` — closed object schema. */
export type RealmJoinPrepareRequestBody = {
  "request_id": string;
  "target": {
    "realm_id": string;
    "invite_id"?: string;
    "authority_locator_hints": Array<{
      "service_kind": "station";
      "service_id": string;
      "endpoint_url"?: string;
      "source": "invite" | "directory" | "cache";
    }>;
  };
  "intent": {
    "kind": "invite_accept";
    "invite_id": string;
  } | {
    "kind": "member_join" | "knock";
  };
};

/** `message-authoring.schema.json#/$defs/message_prepare_request_body` — closed object schema. */
export type MessagePrepareRequestBody = {
  "request_id": string;
  "account_id": {
    "principal_id": string;
    "station_id": string;
  };
  "realm_id": string;
  "intent": {
    "strand_id": string;
    "track_name": "discussion";
    "content": {
      "kind": "plaintext";
      "content": {
        "kind": string;
        "body": string;
        "format"?: "plain" | "markdown" | "prosemirror_json";
        "formatted_body"?: string | Record<string, unknown>;
        "parts"?: Array<{
          "kind": string;
          "body": string;
          "format"?: "plain" | "markdown" | "prosemirror_json";
          "formatted_body"?: string | Record<string, unknown>;
          "parts"?: Array<{
            "kind": string;
            "body": string;
            "format"?: "plain" | "markdown" | "prosemirror_json";
            "formatted_body"?: string | Record<string, unknown>;
            "parts"?: Array<{
              "kind": string;
              "body": string;
              "format"?: "plain" | "markdown" | "prosemirror_json";
              "formatted_body"?: string | Record<string, unknown>;
              "parts"?: Array<{
                "kind": string;
                "body": string;
                "format"?: "plain" | "markdown" | "prosemirror_json";
                "formatted_body"?: string | Record<string, unknown>;
                "parts"?: Array<{
                  "kind": string;
                  "body": string;
                  "format"?: "plain" | "markdown" | "prosemirror_json";
                  "formatted_body"?: string | Record<string, unknown>;
                  "parts"?: Array<{
                    "kind": string;
                    "body": string;
                    "format"?: "plain" | "markdown" | "prosemirror_json";
                    "formatted_body"?: string | Record<string, unknown>;
                    "parts"?: Array<{
                      "kind": string;
                      "body": string;
                      "format"?: "plain" | "markdown" | "prosemirror_json";
                      "formatted_body"?: string | Record<string, unknown>;
                      "parts"?: Array<{
                        "kind": unknown;
                        "body": string;
                        "format"?: "plain" | "markdown" | "prosemirror_json";
                        "formatted_body"?: unknown;
                        "parts"?: unknown[];
                        "mentions"?: unknown[];
                        "audience_mentions"?: unknown[];
                        "attachments"?: unknown[];
                        "reply_context"?: {
                          "message_ref"?: unknown;
                          "sender_actor_id"?: unknown;
                          "excerpt"?: unknown;
                          [key: string]: unknown;
                        };
                        [key: string]: unknown;
                      }>;
                      "mentions"?: Array<{
                        "kind": "mention";
                        "subject_account_id": unknown;
                        "display_name_at_time"?: string;
                        "handle_at_time"?: unknown;
                        "controller_subject_account_id"?: unknown;
                        "controller_handle_at_time"?: unknown;
                        "agent_slug_at_time"?: unknown;
                        "mention_text_original"?: string;
                        "resolved_at"?: unknown;
                      }>;
                      "audience_mentions"?: Array<{
                        "kind": "audience_mention";
                        "audience": "effective_scope_members" | "strand_participants" | "strand_watchers" | "strand_engaged" | "assigned_actors";
                        "mention_text_original"?: string;
                        "resolved_at"?: unknown;
                      }>;
                      "attachments"?: Array<Record<string, unknown>>;
                      "reply_context"?: {
                        "message_ref"?: string;
                        "sender_actor_id"?: {
                          "kind": unknown;
                          "account_id": unknown;
                        } | {
                          "kind": unknown;
                          "service_id": unknown;
                        };
                        "excerpt"?: string;
                        [key: string]: unknown;
                      };
                      [key: string]: unknown;
                    }>;
                    "mentions"?: Array<{
                      "kind": "mention";
                      "subject_account_id": {
                        "principal_id": string;
                        "station_id": string;
                      };
                      "display_name_at_time"?: string;
                      "handle_at_time"?: string;
                      "controller_subject_account_id"?: {
                        "principal_id": string;
                        "station_id": string;
                      };
                      "controller_handle_at_time"?: string;
                      "agent_slug_at_time"?: string;
                      "mention_text_original"?: string;
                      "resolved_at"?: string;
                    }>;
                    "audience_mentions"?: Array<{
                      "kind": "audience_mention";
                      "audience": "effective_scope_members" | "strand_participants" | "strand_watchers" | "strand_engaged" | "assigned_actors";
                      "mention_text_original"?: string;
                      "resolved_at"?: string;
                    }>;
                    "attachments"?: Array<Record<string, unknown>>;
                    "reply_context"?: {
                      "message_ref"?: string;
                      "sender_actor_id"?: {
                        "kind": "account";
                        "account_id": {
                          "principal_id": unknown;
                          "station_id": unknown;
                        };
                      } | {
                        "kind": "service";
                        "service_id": string;
                      };
                      "excerpt"?: string;
                      [key: string]: unknown;
                    };
                    [key: string]: unknown;
                  }>;
                  "mentions"?: Array<{
                    "kind": "mention";
                    "subject_account_id": {
                      "principal_id": string;
                      "station_id": string;
                    };
                    "display_name_at_time"?: string;
                    "handle_at_time"?: string;
                    "controller_subject_account_id"?: {
                      "principal_id": string;
                      "station_id": string;
                    };
                    "controller_handle_at_time"?: string;
                    "agent_slug_at_time"?: string;
                    "mention_text_original"?: string;
                    "resolved_at"?: string;
                  }>;
                  "audience_mentions"?: Array<{
                    "kind": "audience_mention";
                    "audience": "effective_scope_members" | "strand_participants" | "strand_watchers" | "strand_engaged" | "assigned_actors";
                    "mention_text_original"?: string;
                    "resolved_at"?: string;
                  }>;
                  "attachments"?: Array<Record<string, unknown>>;
                  "reply_context"?: {
                    "message_ref"?: string;
                    "sender_actor_id"?: {
                      "kind": "account";
                      "account_id": {
                        "principal_id": string;
                        "station_id": string;
                      };
                    } | {
                      "kind": "service";
                      "service_id": string;
                    };
                    "excerpt"?: string;
                    [key: string]: unknown;
                  };
                  [key: string]: unknown;
                }>;
                "mentions"?: Array<{
                  "kind": "mention";
                  "subject_account_id": {
                    "principal_id": string;
                    "station_id": string;
                  };
                  "display_name_at_time"?: string;
                  "handle_at_time"?: string;
                  "controller_subject_account_id"?: {
                    "principal_id": string;
                    "station_id": string;
                  };
                  "controller_handle_at_time"?: string;
                  "agent_slug_at_time"?: string;
                  "mention_text_original"?: string;
                  "resolved_at"?: string;
                }>;
                "audience_mentions"?: Array<{
                  "kind": "audience_mention";
                  "audience": "effective_scope_members" | "strand_participants" | "strand_watchers" | "strand_engaged" | "assigned_actors";
                  "mention_text_original"?: string;
                  "resolved_at"?: string;
                }>;
                "attachments"?: Array<Record<string, unknown>>;
                "reply_context"?: {
                  "message_ref"?: string;
                  "sender_actor_id"?: {
                    "kind": "account";
                    "account_id": {
                      "principal_id": string;
                      "station_id": string;
                    };
                  } | {
                    "kind": "service";
                    "service_id": string;
                  };
                  "excerpt"?: string;
                  [key: string]: unknown;
                };
                [key: string]: unknown;
              }>;
              "mentions"?: Array<{
                "kind": "mention";
                "subject_account_id": {
                  "principal_id": string;
                  "station_id": string;
                };
                "display_name_at_time"?: string;
                "handle_at_time"?: string;
                "controller_subject_account_id"?: {
                  "principal_id": string;
                  "station_id": string;
                };
                "controller_handle_at_time"?: string;
                "agent_slug_at_time"?: string;
                "mention_text_original"?: string;
                "resolved_at"?: string;
              }>;
              "audience_mentions"?: Array<{
                "kind": "audience_mention";
                "audience": "effective_scope_members" | "strand_participants" | "strand_watchers" | "strand_engaged" | "assigned_actors";
                "mention_text_original"?: string;
                "resolved_at"?: string;
              }>;
              "attachments"?: Array<Record<string, unknown>>;
              "reply_context"?: {
                "message_ref"?: string;
                "sender_actor_id"?: {
                  "kind": "account";
                  "account_id": {
                    "principal_id": string;
                    "station_id": string;
                  };
                } | {
                  "kind": "service";
                  "service_id": string;
                };
                "excerpt"?: string;
                [key: string]: unknown;
              };
              [key: string]: unknown;
            }>;
            "mentions"?: Array<{
              "kind": "mention";
              "subject_account_id": {
                "principal_id": string;
                "station_id": string;
              };
              "display_name_at_time"?: string;
              "handle_at_time"?: string;
              "controller_subject_account_id"?: {
                "principal_id": string;
                "station_id": string;
              };
              "controller_handle_at_time"?: string;
              "agent_slug_at_time"?: string;
              "mention_text_original"?: string;
              "resolved_at"?: string;
            }>;
            "audience_mentions"?: Array<{
              "kind": "audience_mention";
              "audience": "effective_scope_members" | "strand_participants" | "strand_watchers" | "strand_engaged" | "assigned_actors";
              "mention_text_original"?: string;
              "resolved_at"?: string;
            }>;
            "attachments"?: Array<Record<string, unknown>>;
            "reply_context"?: {
              "message_ref"?: string;
              "sender_actor_id"?: {
                "kind": "account";
                "account_id": {
                  "principal_id": string;
                  "station_id": string;
                };
              } | {
                "kind": "service";
                "service_id": string;
              };
              "excerpt"?: string;
              [key: string]: unknown;
            };
            [key: string]: unknown;
          }>;
          "mentions"?: Array<{
            "kind": "mention";
            "subject_account_id": {
              "principal_id": string;
              "station_id": string;
            };
            "display_name_at_time"?: string;
            "handle_at_time"?: string;
            "controller_subject_account_id"?: {
              "principal_id": string;
              "station_id": string;
            };
            "controller_handle_at_time"?: string;
            "agent_slug_at_time"?: string;
            "mention_text_original"?: string;
            "resolved_at"?: string;
          }>;
          "audience_mentions"?: Array<{
            "kind": "audience_mention";
            "audience": "effective_scope_members" | "strand_participants" | "strand_watchers" | "strand_engaged" | "assigned_actors";
            "mention_text_original"?: string;
            "resolved_at"?: string;
          }>;
          "attachments"?: Array<Record<string, unknown>>;
          "reply_context"?: {
            "message_ref"?: string;
            "sender_actor_id"?: {
              "kind": "account";
              "account_id": {
                "principal_id": string;
                "station_id": string;
              };
            } | {
              "kind": "service";
              "service_id": string;
            };
            "excerpt"?: string;
            [key: string]: unknown;
          };
          [key: string]: unknown;
        }>;
        "mentions"?: Array<{
          "kind": "mention";
          "subject_account_id": {
            "principal_id": string;
            "station_id": string;
          };
          "display_name_at_time"?: string;
          "handle_at_time"?: string;
          "controller_subject_account_id"?: {
            "principal_id": string;
            "station_id": string;
          };
          "controller_handle_at_time"?: string;
          "agent_slug_at_time"?: string;
          "mention_text_original"?: string;
          "resolved_at"?: string;
        }>;
        "audience_mentions"?: Array<{
          "kind": "audience_mention";
          "audience": "effective_scope_members" | "strand_participants" | "strand_watchers" | "strand_engaged" | "assigned_actors";
          "mention_text_original"?: string;
          "resolved_at"?: string;
        }>;
        "attachments"?: Array<Record<string, unknown>>;
        "reply_context"?: {
          "message_ref"?: string;
          "sender_actor_id"?: {
            "kind": "account";
            "account_id": {
              "principal_id": string;
              "station_id": string;
            };
          } | {
            "kind": "service";
            "service_id": string;
          };
          "excerpt"?: string;
          [key: string]: unknown;
        };
        [key: string]: unknown;
      };
      "metadata"?: {
        "fields"?: Record<string, unknown>;
        [key: string]: unknown;
      };
    } | {
      "kind": "mls";
      "encrypted_content": {
        "version": "1.0";
        "content_type": string;
        "encryption_context": {
          "epoch": number;
          "group_state_ref": string;
          "routing_context"?: {
            "target_ref": string;
            "routing_tag": string;
          };
        };
        "ciphertext": string;
      };
      "encrypted_metadata"?: {
        "version": "1.0";
        "content_type": string;
        "encryption_context": {
          "epoch": number;
          "group_state_ref": string;
          "routing_context"?: {
            "target_ref": string;
            "routing_tag": string;
          };
        };
        "ciphertext": string;
      };
      "encryption_context": {
        "scheme": "mls_rfc9420";
        "effective_scope": {
          "kind": "realm";
          "realm_id": string;
        } | {
          "kind": "circle";
          "realm_id": string;
          "circle_id": string;
        } | {
          "kind": "sidecar";
          "realm_id": string;
          "sidecar_id": string;
        } | {
          "kind": "realm_genesis";
        };
        "sender_domain": string;
      };
    };
    "blob_refs"?: string[];
    "reply_to_id"?: string;
  };
  "created_at": string;
};

/** `identity-resolution.schema.json#/$defs/public_principal_resolution` — closed object schema. */
export type PublicPrincipalResolution = {
  "account_id": {
    "principal_id": string;
    "station_id": string;
  };
  "resolution_projection": {
    "did": string;
    "method_history_head": string;
    "version_id": string;
    "resolution_event_ref": string;
    "updated_at": string;
  };
  "method_history_evidence": {
    "evidence_kind": "webvh_log";
    "boundary": {
      "from_method_history_head": string;
      "from_version_id": string;
      "to_method_history_head": string;
      "to_version_id": string;
    };
    "evidence": {
      "kind": "ak.did.binding_evidence.v1";
      "method": string;
      "document_digest": string;
      "method_proofs": Array<{
        "kind": "webvh_log";
        "history_head": string;
        "witnesses": Array<{
          "witness_did": string;
          "controlling_organization_did": string;
        }>;
        "witness_proofs_digest": string;
      }>;
    };
    "log_entries": Array<Record<string, unknown>>;
    "witness_records": Array<Record<string, unknown>>;
  } | {
    "evidence_kind": "did_web_document";
    "boundary": {
      "from_method_history_head": string;
      "from_version_id": string;
      "to_method_history_head": string;
      "to_version_id": string;
    };
    "evidence": {
      "kind": "ak.did.binding_evidence.v1";
      "method": string;
      "document_digest": string;
      "method_proofs": Array<{
        "kind": "webvh_log";
        "history_head": string;
        "witnesses": Array<{
          "witness_did": string;
          "controlling_organization_did": string;
        }>;
        "witness_proofs_digest": string;
      }>;
    };
  } | {
    "evidence_kind": "did_key_expansion";
    "boundary": {
      "from_method_history_head": string;
      "from_version_id": string;
      "to_method_history_head": string;
      "to_version_id": string;
    };
    "evidence": {
      "kind": "ak.did.binding_evidence.v1";
      "method": string;
      "document_digest": string;
      "method_proofs": Array<{
        "kind": "webvh_log";
        "history_head": string;
        "witnesses": Array<{
          "witness_did": string;
          "controlling_organization_did": string;
        }>;
        "witness_proofs_digest": string;
      }>;
    };
  };
  "projection_attestation": {
    "attestation": {
      "account_id": {
        "principal_id": string;
        "station_id": string;
      };
      "resolution_projection": {
        "did": string;
        "method_history_head": string;
        "version_id": string;
        "resolution_event_ref": string;
        "updated_at": string;
      };
      "method_history_evidence_digest": string;
      "issued_at": string;
      "expires_at": string;
    };
    "proof": {
      "verification_method": string;
      "created_at": string;
      "jws": string;
    };
  };
};

/** `circle-operations.schema.json#/$defs/circle_view` — closed object schema. */
export type CircleView = {
  "circle_id": string;
  "realm_id": string;
  "profile_ref"?: string;
  "title": string;
  "summary"?: string;
  "display": {
    "short_name": string;
    "color_token": "slate" | "red" | "orange" | "amber" | "yellow" | "lime" | "green" | "emerald" | "teal" | "cyan" | "sky" | "blue" | "indigo" | "violet" | "fuchsia" | "pink" | "gray_high_contrast";
    "symbol": unknown;
  };
  "directory_visibility": "members" | "realm_members";
  "join_rule": "invite" | "knock" | "public";
  "history_access": "since_join" | "all_history_for_current_members";
  "mls_group_id"?: string;
  "state": "active" | "archived" | "tombstoned";
  "viewer_membership"?: "join" | "knock" | "leave" | "ban";
  "member_ids": Array<{
    "kind": "account";
    "account_id": {
      "principal_id": string;
      "station_id": string;
    };
  } | {
    "kind": "service";
    "service_id": string;
  }>;
  "created_by": {
    "kind": "account";
    "account_id": {
      "principal_id": string;
      "station_id": string;
    };
  } | {
    "kind": "service";
    "service_id": string;
  };
  "created_at": string;
  "updated_by"?: {
    "kind": "account";
    "account_id": {
      "principal_id": string;
      "station_id": string;
    };
  } | {
    "kind": "service";
    "service_id": string;
  };
  "updated_at"?: string;
};

/** `circle-operations.schema.json#/$defs/circle_membership_outcome` — closed object schema. */
export type CircleMembershipOutcome = {
  "circle_id": string;
  "member_id": {
    "kind": "account";
    "account_id": {
      "principal_id": string;
      "station_id": string;
    };
  } | {
    "kind": "service";
    "service_id": string;
  };
  "membership": "join" | "knock" | "leave" | "ban";
};

/** `contact-operations.schema.json#/$defs/contact_peer` — closed object schema. */
export type ContactPeer = {
  "kind": "human";
  "account_id": {
    "principal_id": string;
    "station_id": string;
  };
} | {
  "kind": "agent";
  "actor_id": {
    "kind": "account";
    "account_id": {
      "principal_id": string;
      "station_id": string;
    };
  } | {
    "kind": "service";
    "service_id": string;
  };
  "controller_account_id": {
    "principal_id": string;
    "station_id": string;
  };
};

/** `common-ids.schema.json#/$defs/actor_id` — closed object schema. */
export type ActorId = {
  "kind": "account";
  "account_id": {
    "principal_id": string;
    "station_id": string;
  };
} | {
  "kind": "service";
  "service_id": string;
};

/** `common-ids.schema.json#/$defs/account_id` — closed object schema. */
export type AccountId = {
  "principal_id": string;
  "station_id": string;
};

/** `principal-operations.schema.json#/$defs/sidecar_ensure_outcome/oneOf/2` — closed object schema. */
export type SidecarEnsureAcceptedOutcome = {
  "status": "accepted";
  "operation_id": string;
  "accepted_phase": "commit" | "attach";
  "sidecar_id": string;
  "source_context_ref": {
    "kind": "relation";
    "relation_id": string;
  } | {
    "kind": "strand";
    "strand_id": string;
  };
  "access_readiness": "opening" | "key_material_pending" | "epoch_update_required" | "ready" | "failed";
  "pending_access_reconciliations": Array<{
    "agent_id": string;
    "provisioning_phase": "mls_welcome" | "mls_remove" | "epoch_rotation" | "device_key_material";
  }>;
};

/** `agent-operations.schema.json#/$defs/agent_sidecar_view` — closed object schema. */
export type AgentSidecarView = {
  "sidecar": {
    "id": string;
    "schema": "ak.schema.agent_sidecar.v1";
    "realm_id": string;
    "controller_account_id": {
      "principal_id": string;
      "station_id": string;
    };
    "state": "active" | "suspended" | "tombstoned";
    "state_changed_at"?: string;
    "created_at": string;
    "updated_at"?: string;
  };
  "desired_agent_ids": string[];
  "effective_agent_ids": string[];
  "mls_context": {
    "participant_authority_digest": string;
    "authority_stream_head": string[];
    "mls_group_id"?: string;
    "epoch"?: number;
    "genesis_event_ref"?: string;
    "current_controller_device_ready": boolean;
  };
  "access_readiness": "opening" | "key_material_pending" | "epoch_update_required" | "ready" | "failed";
  "pending_access_reconciliations": Array<{
    "agent_id": string;
    "provisioning_phase": "mls_welcome" | "mls_remove" | "epoch_rotation" | "device_key_material";
  }>;
};

/** `agent-sidecar-exchange-projection.schema.json` — closed object schema. */
export type AgentSidecarExchangeProjection = {
  "schema": "ak.schema.agent_sidecar_exchange_projection.v1";
  "controller_account_id": {
    "principal_id": string;
    "station_id": string;
  };
  "sidecar_id": string;
  "exchange_id": string;
  "source_track_ref": {
    "realm_id": string;
    "strand_id": string;
    "track_name": string;
  };
  "source_event_id"?: string;
  "source_hlc": string;
  "client_order_key": string;
  "addressed_agent_ids": string[];
  "coordinator_agent_id": string;
  "coordinator_assignment_event_id": string;
  "participating_agent_ids": string[];
  "private_request_event_id": string;
  "user_facing_response_event_ids": string[];
  "status": "delivered" | "responding" | "complete" | "failed";
  "failure_reason_code"?: string;
  "terminal_event_id"?: string;
  "folded_checkpoint": {
    "event_ids": string[];
    "event_set_digest": string;
    "max_hlc": string;
  };
};

/** `invite.schema.json` — closed object schema. */
export type InviteObject = {
  "id": string;
  "schema": "ak.schema.invite.v1";
  "realm_id": string;
  "inviter_account_id": {
    "principal_id": string;
    "station_id": string;
  };
  "invitee_account_id"?: {
    "principal_id": string;
    "station_id": string;
  };
  "introduction_evidence_digest"?: string;
  "third_party_invite"?: {
    "display_name_hint"?: string;
    "token_commitment": string;
    "token_salt_id"?: string;
    "lookup_table_ref"?: string;
    "pepper_id"?: string;
    "oob_code_kind": "offline_token" | "lookup";
    "token_entropy_bits"?: number;
    "verification_id": string;
    "verification_public_key": string;
    "max_claims"?: number;
  };
  "capability_grant_refs"?: string[];
  "state": "pending" | "accepted" | "rejected" | "revoked" | "expired" | "claimed" | "send_failed" | "revoked_by_capability_loss" | "revoked_by_inviter_left" | "invalidated_by_rate_limit";
  "expires_at": string;
  "created_at": string;
  "updated_by"?: {
    "kind": "account";
    "account_id": {
      "principal_id": string;
      "station_id": string;
    };
  } | {
    "kind": "service";
    "service_id": string;
  };
  "updated_at"?: string;
};

/** `event-payload.schema.json#/$defs/membership_payload` — closed object schema. */
export type MembershipPayload = {
  "strand_id"?: string;
  "realm_id"?: string;
  "member_id": {
    "kind": "account";
    "account_id": {
      "principal_id": string;
      "station_id": string;
    };
  } | {
    "kind": "service";
    "service_id": string;
  };
  "membership": "join" | "knock" | "leave" | "ban";
  "gate_proofs"?: Array<{
    "gate_id": string;
    "kind": "challenge_response" | "claim_required";
    "realm_id": string;
    "applicant_actor_id": {
      "kind": "account";
      "account_id": {
        "principal_id": string;
        "station_id": string;
      };
    } | {
      "kind": "service";
      "service_id": string;
    };
    "policy_digest": string;
    "created_at": string;
    "challenge_kind"?: "captcha" | "pow" | "attested_human" | "idp_oidc";
    "challenge_id"?: string;
    "issuer_id"?: string;
    "claims"?: string[];
    "proofs": Array<{
      "kind": "detached_jws";
      "verification_method": string;
      "payload_digest": string;
      "created_at": string;
      "domain"?: string;
      "audience"?: string | string[];
      "proof_purpose"?: "issuer_attestation" | "holder_acceptance" | "status_attestation" | "revocation_authorization" | "governance_authorization";
      "jws": string;
    }>;
  }>;
  "reason"?: string;
  "membership_cause"?: "controller_membership_ended";
  "agent_controller_binding"?: {
    "controller_account_id": {
      "principal_id": string;
      "station_id": string;
    };
    "controller_membership_generation_ref": string;
    "controller_terminal_event_ref"?: string;
  };
  "invite_ref"?: string;
};

/** `realm.schema.json` — closed object schema. */
export type RealmObject = {
  "id"?: string;
  "schema": "ak.schema.realm.v1";
  "title": string;
  "summary"?: string;
  "security_class"?: "standard" | "high_assurance";
  "trust_domain": string;
  "owning_organization_ids"?: string[];
  "schema_refs": string[];
  "fields"?: {
    "purpose"?: "principal_control" | "agent_control" | "applet_managed_control";
    "collaboration_role"?: "direct_conversation";
    [key: string]: unknown;
  };
  "policy_id"?: string;
  "preview_policy_id"?: string;
  "default_strand_id"?: string | null;
  "default_discoverability": "public" | "listed" | "restricted" | "unlisted" | "invite_only" | "secret";
  "default_join_rule": "public" | "invite" | "knock" | "restricted" | "knock_restricted" | "closed";
  "history_access": "since_join" | "all_history_for_current_members";
  "governance_station_id": string;
  "agent_participation"?: {
    "agent": {
      "reply_message": boolean;
      "reaction_add": boolean;
      "reaction_remove": boolean;
      "accept_third_party_mention": boolean;
      "act_on_behalf": boolean;
    };
  };
  "federation_policy"?: "open" | "restricted" | "closed" | "quarantine";
  "max_authority_lifetime_ms"?: number;
  "retention_policy_id"?: string;
  "avatar_blob_ref"?: string;
  "created_by": {
    "kind": "account";
    "account_id": {
      "principal_id": string;
      "station_id": string;
    };
  } | {
    "kind": "service";
    "service_id": string;
  };
  "created_at": string;
  "updated_by"?: {
    "kind": "account";
    "account_id": {
      "principal_id": string;
      "station_id": string;
    };
  } | {
    "kind": "service";
    "service_id": string;
  };
  "updated_at"?: string;
};

/** `realm-genesis.schema.json` — closed object schema. */
export type RealmGenesisObject = {
  "schema": "ak.schema.realm_genesis.v1";
  "purpose": "collaboration" | "direct_conversation" | "principal_control" | "agent_control" | "applet_managed_control";
  "genesis_salt": string;
  "founding_device_descriptor"?: {
    "descriptor_version": 1;
    "device_id": string;
    "device_public_key_did": string;
    "device_key_algorithm": "Ed25519";
    "device_key_purpose": "event_signing_and_mls_identity";
    "hpke_key": string;
    "hpke_key_algorithm": "X25519";
    "algorithms": string[];
    "founding_authorize_payload_digest": string;
  };
  "initial_resolution"?: {
    "did": string;
    "method_history_head": string;
    "version_id": string;
  };
  "trust_domain": string;
  "security_class": "standard" | "high_assurance";
  "governance_station_id": string;
  "initial_join_rule": "public" | "invite" | "knock" | "restricted" | "knock_restricted" | "closed";
  "initial_history_access": "since_join" | "all_history_for_current_members";
  "initial_discoverability": "public" | "listed" | "restricted" | "unlisted" | "invite_only" | "secret";
};

/** `space.schema.json` — closed object schema. */
export type SpaceObject = {
  "id"?: string;
  "schema": "ak.schema.space.v1";
  "realm_id": string;
  "scope_circle_id"?: string;
  "child_scope_policy"?: {
    "kind": "allow_any" | "require_e2ee" | "require_same_scope" | "require_scope_circle_id";
    "scope_circle_id"?: string;
  };
  "parent_space_id"?: string;
  "kind": string;
  "rank"?: string;
  "schema_refs"?: string[];
  "title"?: string;
  "summary"?: string;
  "labels"?: string[];
  "fields"?: {
    "wip_limit"?: number;
    "wip_limit_enforcement"?: "warn" | "reject" | "require_review";
    [key: string]: unknown;
  };
  "avatar_blob_ref"?: string;
  "encrypted_metadata"?: {
    "version": "1.0";
    "content_type": string;
    "encryption_context": {
      "epoch": number;
      "group_state_ref": string;
      "routing_context"?: {
        "target_ref": string;
        "routing_tag": string;
      };
    };
    "ciphertext": string;
  };
  "state"?: "active" | "archived" | "tombstoned";
  "state_changed_at"?: string;
  "created_by": {
    "kind": "account";
    "account_id": {
      "principal_id": string;
      "station_id": string;
    };
  } | {
    "kind": "service";
    "service_id": string;
  };
  "created_at": string;
  "updated_by"?: {
    "kind": "account";
    "account_id": {
      "principal_id": string;
      "station_id": string;
    };
  } | {
    "kind": "service";
    "service_id": string;
  };
  "updated_at"?: string;
};

/** `capability-grant.schema.json` — closed object schema. */
export type CapabilityGrantObject = {
  "id": string;
  "schema": "ak.schema.capability.v1";
  "realm_id"?: string;
  "issuer_id": {
    "kind": "account";
    "account_id": {
      "principal_id": string;
      "station_id": string;
    };
  } | {
    "kind": "service";
    "service_id": string;
  };
  "subject": {
    "kind": "account";
    "account_id": {
      "principal_id": string;
      "station_id": string;
    };
  } | {
    "kind": "service";
    "service_id": string;
  } | {
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
    "actor_id"?: {
      "kind": "account";
      "account_id": {
        "principal_id": string;
        "station_id": string;
      };
    } | {
      "kind": "service";
      "service_id": string;
    };
    "schema_ref"?: string;
    "policy_id"?: string;
    "invite_id"?: string;
    "blob_ref"?: string;
    "match_scope"?: "exact" | "realm_wide";
  }>;
  "constraints"?: Array<{
    "constraint_id"?: string;
    "constraint_kind": "temporal" | "field_access" | "kind_restriction" | "scope_limitation" | "authority_control" | "quota" | "claim_based" | "confidentiality";
    "effect": "allow" | "deny" | "quarantine" | "require_review";
    "evaluation_class"?: "stateless" | "grant_local" | "realm_state" | "external";
    "constraint_subkind"?: "claim" | "approval" | "accountability" | "rate" | "resource" | "encryption" | "visibility" | "window" | "edit_window" | "redact_window" | "session" | "applet_authority";
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
    "max_authority_depth"?: number;
    "authority_path_ids"?: string[];
    "authority_regrant_allowed"?: boolean;
    "authority_scope"?: "narrowing_only" | "same_scope" | "custom";
    "applet_id"?: string;
    "executed_by"?: {
      "kind": "account";
      "account_id": {
        "principal_id": string;
        "station_id": string;
      };
    } | {
      "kind": "service";
      "service_id": string;
    };
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
    "approval_mode"?: "before_commit";
    "approval_actor_ids"?: string[];
    "approval_relation"?: "responsible" | "controller" | "guardian" | "realm_admin" | "custom";
    "timeout"?: string;
    "approval_threshold"?: "majority" | "unanimous" | number;
    "accountability_required"?: boolean;
    "guardian_approval_required"?: boolean;
    "controller_approval_required"?: boolean;
    "required_claims"?: unknown[];
    "trusted_claim_issuer_ids"?: string[];
    "claim_refresh_required"?: boolean;
    "claim_max_age"?: string;
    "allowed_history_access_values"?: Array<"since_join" | "all_history_for_current_members">;
    "redacted_history_allowed"?: boolean;
    "encryption_required"?: boolean;
    "min_encryption_level"?: "none" | "mls_rfc9420" | "external";
    "plaintext_fallback_allowed"?: boolean;
    "audit_trail_required"?: boolean;
    "key_rotation_period"?: string;
    "max_key_age"?: string;
    "key_backup_required"?: boolean;
    "approved_key_issuer_ids"?: string[];
    "depends_on_moderation_state"?: boolean;
    "allowed_managed_actor_roles"?: Array<"bot" | "ghost">;
  }>;
  "issued_at": string;
  "status": "active" | "revoked" | "relinquished";
  "updated_by"?: {
    "kind": "account";
    "account_id": {
      "principal_id": string;
      "station_id": string;
    };
  } | {
    "kind": "service";
    "service_id": string;
  };
  "updated_at"?: string;
  "revoked_by"?: {
    "kind": "account";
    "account_id": {
      "principal_id": string;
      "station_id": string;
    };
  } | {
    "kind": "service";
    "service_id": string;
  };
  "revoked_at"?: string;
  "issuer_authority_refs": Array<{
    "kind": "grant";
    "grant_id": string;
  } | {
    "kind": "realm_root";
    "realm_id": string;
    "authority_event_ref": string;
    "authority_generation": number;
  } | {
    "kind": "owned_agent";
    "realm_id": string;
    "controller_account_id": {
      "principal_id": string;
      "station_id": string;
    };
    "controller_join_event_id": string;
    "agent_join_event_id": string;
  }>;
  "authority_depth": number;
  "authority_root_refs": Array<{
    "kind": "realm_root";
    "realm_id": string;
    "authority_event_ref": string;
    "authority_generation": number;
  } | {
    "kind": "owned_agent";
    "realm_id": string;
    "controller_account_id": {
      "principal_id": string;
      "station_id": string;
    };
    "controller_join_event_id": string;
    "agent_join_event_id": string;
  }>;
};

/** `event-payload.schema.json#/$defs/capability_grant_payload` — closed object schema. */
export type CapabilityGrantPayload = {
  "grant": {
    "schema": "ak.schema.capability.v1";
    "realm_id"?: string;
    "issuer_id": {
      "kind": "account";
      "account_id": {
        "principal_id": string;
        "station_id": string;
      };
    } | {
      "kind": "service";
      "service_id": string;
    };
    "subject": {
      "kind": "account";
      "account_id": {
        "principal_id": string;
        "station_id": string;
      };
    } | {
      "kind": "service";
      "service_id": string;
    } | {
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
      "actor_id"?: {
        "kind": "account";
        "account_id": {
          "principal_id": string;
          "station_id": string;
        };
      } | {
        "kind": "service";
        "service_id": string;
      };
      "schema_ref"?: string;
      "policy_id"?: string;
      "invite_id"?: string;
      "blob_ref"?: string;
      "match_scope"?: "exact" | "realm_wide";
    }>;
    "constraints"?: Array<{
      "constraint_id"?: string;
      "constraint_kind": "temporal" | "field_access" | "kind_restriction" | "scope_limitation" | "authority_control" | "quota" | "claim_based" | "confidentiality";
      "effect": "allow" | "deny" | "quarantine" | "require_review";
      "evaluation_class"?: "stateless" | "grant_local" | "realm_state" | "external";
      "constraint_subkind"?: "claim" | "approval" | "accountability" | "rate" | "resource" | "encryption" | "visibility" | "window" | "edit_window" | "redact_window" | "session" | "applet_authority";
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
      "max_authority_depth"?: number;
      "authority_path_ids"?: string[];
      "authority_regrant_allowed"?: boolean;
      "authority_scope"?: "narrowing_only" | "same_scope" | "custom";
      "applet_id"?: string;
      "executed_by"?: {
        "kind": "account";
        "account_id": {
          "principal_id": string;
          "station_id": string;
        };
      } | {
        "kind": "service";
        "service_id": string;
      };
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
      "approval_mode"?: "before_commit";
      "approval_actor_ids"?: string[];
      "approval_relation"?: "responsible" | "controller" | "guardian" | "realm_admin" | "custom";
      "timeout"?: string;
      "approval_threshold"?: "majority" | "unanimous" | number;
      "accountability_required"?: boolean;
      "guardian_approval_required"?: boolean;
      "controller_approval_required"?: boolean;
      "required_claims"?: unknown[];
      "trusted_claim_issuer_ids"?: string[];
      "claim_refresh_required"?: boolean;
      "claim_max_age"?: string;
      "allowed_history_access_values"?: Array<"since_join" | "all_history_for_current_members">;
      "redacted_history_allowed"?: boolean;
      "encryption_required"?: boolean;
      "min_encryption_level"?: "none" | "mls_rfc9420" | "external";
      "plaintext_fallback_allowed"?: boolean;
      "audit_trail_required"?: boolean;
      "key_rotation_period"?: string;
      "max_key_age"?: string;
      "key_backup_required"?: boolean;
      "approved_key_issuer_ids"?: string[];
      "depends_on_moderation_state"?: boolean;
      "allowed_managed_actor_roles"?: Array<"bot" | "ghost">;
    }>;
    "issued_at": string;
    "issuer_authority_refs": Array<{
      "kind": "grant";
      "grant_id": string;
    } | {
      "kind": "realm_root";
      "realm_id": string;
      "authority_event_ref": string;
      "authority_generation": number;
    } | {
      "kind": "owned_agent";
      "realm_id": string;
      "controller_account_id": {
        "principal_id": string;
        "station_id": string;
      };
      "controller_join_event_id": string;
      "agent_join_event_id": string;
    }>;
  };
};

/** `invite-delivery-request.schema.json` — closed object schema. */
export type InviteDeliveryRequestBody = {
  "schema": "ak.schema.invite_delivery_request.v1";
  "invite_event": {
    "event_id": string;
    "kind": string;
    "realm_id"?: string;
    "scope_ref": {
      "kind": "realm";
      "realm_id": string;
    } | {
      "kind": "circle";
      "realm_id": string;
      "circle_id": string;
    } | {
      "kind": "sidecar";
      "realm_id": string;
      "sidecar_id": string;
    } | {
      "kind": "realm_genesis";
    };
    "actor_id": {
      "kind": "account";
      "account_id": {
        "principal_id": string;
        "station_id": string;
      };
    } | {
      "kind": "service";
      "service_id": string;
    };
    "executed_by"?: {
      "kind": "account";
      "account_id": {
        "principal_id": string;
        "station_id": string;
      };
    } | {
      "kind": "service";
      "service_id": string;
    };
    "authorization_ref"?: string | "ak.authority.direct_conversation_participant.v1" | "ak.authority.direct_conversation_bootstrap_participant.v1";
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
      "uri"?: string;
      [key: string]: unknown;
    };
    "created_at": string;
    "semantic_refs"?: Array<{
      "id": string;
      "role": "authorized_by";
      "critical": boolean;
    } | {
      "id": string;
      "role": "attestation" | "parent_event" | "after" | "audit_pair" | "recovery_capability" | "accountability" | "bootstrap_genesis" | "disclosure_authorization" | "capture_stop" | "direct_conversation_binding" | "direct_conversation_founding_unit" | "direct_conversation_contact_round" | "direct_conversation_agent_provision" | "applet_managed_actor_provision";
      "critical": boolean;
    }>;
    "payload": Record<string, unknown>;
    "producer_proof": {
      "kind": "detached_jws";
      "verification_method": string;
      "event_digest": string;
      "created_at": string;
      "domain"?: string;
      "audience"?: string | string[];
      "proof_purpose"?: "issuer_attestation" | "holder_acceptance";
      "jws": string;
    };
  };
  "invite_commit": {
    "commit_id": string;
    "realm_id": string;
    "stream_ref": {
      "kind": "realm";
      "realm_id": string;
    } | {
      "kind": "circle";
      "realm_id": string;
      "circle_id": string;
    } | {
      "kind": "sidecar";
      "realm_id": string;
      "sidecar_id": string;
    };
    "stream_position": number;
    "previous_commit_ref": string | null;
    "event_ref": string;
    "governance_generation": number;
    "authority_ref": string;
    "committed_at": string;
    "producer_signer_fact_digest"?: string;
    "signature": {
      "context": "ak.realm_commit_signature.v1";
      "signature_algorithm": "Ed25519";
      "verification_method": string;
      "signed_digest": string;
      "created_at": string;
      "sig": string;
    };
  };
  "producer_signer_fact"?: {
    "event_id": string;
    "actor": {
      "kind": "account";
      "account_id": {
        "principal_id": string;
        "station_id": string;
      };
    };
    "device_id": string;
    "verification_method": string;
    "key": {
      "public_key_b64u": string;
      "authorization_ref": {
        "event_id": string;
        "commit_id": string;
        "stream_ref": {
          "kind": "realm";
          "realm_id": string;
        } | {
          "kind": "circle";
          "realm_id": string;
          "circle_id": string;
        } | {
          "kind": "sidecar";
          "realm_id": string;
          "sidecar_id": string;
        };
        "stream_position": number;
      };
      "revision": {
        "commit_id": string;
        "stream_position": number;
      };
      "governance_generation": number;
    };
    "accepted_at": string;
  };
  "authority_locator_hints": Array<{
    "service_kind": "station";
    "service_id": string;
    "endpoint_url"?: string;
    "source": "invite" | "directory" | "cache";
  }>;
  "invite_address": {
    "account_id": {
      "principal_id": string;
      "station_id": string;
    };
    "service_resolution": {
      "inline": {
        "service_id": string;
        "service_kind": string;
        "method_history_evidence": {
          "evidence_kind": "webvh_log";
          "boundary": {
            "from_method_history_head": string;
            "from_version_id": string;
            "to_method_history_head": string;
            "to_version_id": string;
          };
          "evidence": {
            "kind": "ak.did.binding_evidence.v1";
            "method": string;
            "document_digest": string;
            "method_proofs": Array<{
              "kind": "webvh_log";
              "history_head": string;
              "witnesses": Array<{
                "witness_did": string;
                "controlling_organization_did": string;
              }>;
              "witness_proofs_digest": string;
            }>;
          };
          "log_entries": Array<Record<string, unknown>>;
          "witness_records": Array<Record<string, unknown>>;
        } | {
          "evidence_kind": "did_web_document";
          "boundary": {
            "from_method_history_head": string;
            "from_version_id": string;
            "to_method_history_head": string;
            "to_version_id": string;
          };
          "evidence": {
            "kind": "ak.did.binding_evidence.v1";
            "method": string;
            "document_digest": string;
            "method_proofs": Array<{
              "kind": "webvh_log";
              "history_head": string;
              "witnesses": Array<{
                "witness_did": string;
                "controlling_organization_did": string;
              }>;
              "witness_proofs_digest": string;
            }>;
          };
        } | {
          "evidence_kind": "did_key_expansion";
          "boundary": {
            "from_method_history_head": string;
            "from_version_id": string;
            "to_method_history_head": string;
            "to_version_id": string;
          };
          "evidence": {
            "kind": "ak.did.binding_evidence.v1";
            "method": string;
            "document_digest": string;
            "method_proofs": Array<{
              "kind": "webvh_log";
              "history_head": string;
              "witnesses": Array<{
                "witness_did": string;
                "controlling_organization_did": string;
              }>;
              "witness_proofs_digest": string;
            }>;
          };
        };
        "normalized_did_document": {
          "did": string;
          "contexts": Array<string | Record<string, unknown>>;
          "controller_dids": string[];
          "also_known_as": string[];
          "verification_methods": Array<{
            "verification_method": string;
            "controller_did": string;
            "verification_method_suite": string;
            "public_key_material": Record<string, unknown>;
            "extensions": Array<{
              "name": string;
              "value": unknown;
            }>;
          }>;
          "authentication": Array<{
            "verification_method": string;
          }>;
          "assertion_methods": Array<{
            "verification_method": string;
          }>;
          "key_agreements": Array<{
            "verification_method": string;
          }>;
          "capability_invocations": Array<{
            "verification_method": string;
          }>;
          "capability_delegations": Array<{
            "verification_method": string;
          }>;
          "services": Array<{
            "uri": string;
            "protocol_names": string[];
            "endpoint": unknown;
            "extensions": Array<{
              "name": string;
              "value": unknown;
            }>;
          }>;
          "metadata": {
            "primary_handle"?: string;
          };
          "extensions": Array<{
            "name": string;
            "value": unknown;
          }>;
        };
      };
    } | {
      "resolution_url": string;
    };
    "route_assistance"?: {
      "mirror_hints": Array<{
        "mirror_id": string;
        "service_resolution": {
          "inline": {
            "service_id": string;
            "service_kind": string;
            "method_history_evidence": {
              "evidence_kind": "webvh_log";
              "boundary": {
                "from_method_history_head": string;
                "from_version_id": string;
                "to_method_history_head": string;
                "to_version_id": string;
              };
              "evidence": {
                "kind": "ak.did.binding_evidence.v1";
                "method": string;
                "document_digest": string;
                "method_proofs": Array<{
                  "kind": "webvh_log";
                  "history_head": string;
                  "witnesses": Array<{
                    "witness_did": string;
                    "controlling_organization_did": string;
                  }>;
                  "witness_proofs_digest": string;
                }>;
              };
              "log_entries": Array<Record<string, unknown>>;
              "witness_records": Array<Record<string, unknown>>;
            } | {
              "evidence_kind": "did_web_document";
              "boundary": {
                "from_method_history_head": string;
                "from_version_id": string;
                "to_method_history_head": string;
                "to_version_id": string;
              };
              "evidence": {
                "kind": "ak.did.binding_evidence.v1";
                "method": string;
                "document_digest": string;
                "method_proofs": Array<{
                  "kind": "webvh_log";
                  "history_head": string;
                  "witnesses": Array<{
                    "witness_did": string;
                    "controlling_organization_did": string;
                  }>;
                  "witness_proofs_digest": string;
                }>;
              };
            } | {
              "evidence_kind": "did_key_expansion";
              "boundary": {
                "from_method_history_head": string;
                "from_version_id": string;
                "to_method_history_head": string;
                "to_version_id": string;
              };
              "evidence": {
                "kind": "ak.did.binding_evidence.v1";
                "method": string;
                "document_digest": string;
                "method_proofs": Array<{
                  "kind": "webvh_log";
                  "history_head": string;
                  "witnesses": Array<{
                    "witness_did": string;
                    "controlling_organization_did": string;
                  }>;
                  "witness_proofs_digest": string;
                }>;
              };
            };
            "normalized_did_document": {
              "did": string;
              "contexts": Array<string | Record<string, unknown>>;
              "controller_dids": string[];
              "also_known_as": string[];
              "verification_methods": Array<{
                "verification_method": string;
                "controller_did": string;
                "verification_method_suite": string;
                "public_key_material": Record<string, unknown>;
                "extensions": Array<{
                  "name": string;
                  "value": unknown;
                }>;
              }>;
              "authentication": Array<{
                "verification_method": string;
              }>;
              "assertion_methods": Array<{
                "verification_method": string;
              }>;
              "key_agreements": Array<{
                "verification_method": string;
              }>;
              "capability_invocations": Array<{
                "verification_method": string;
              }>;
              "capability_delegations": Array<{
                "verification_method": string;
              }>;
              "services": Array<{
                "uri": string;
                "protocol_names": string[];
                "endpoint": unknown;
                "extensions": Array<{
                  "name": string;
                  "value": unknown;
                }>;
              }>;
              "metadata": {
                "primary_handle"?: string;
              };
              "extensions": Array<{
                "name": string;
                "value": unknown;
              }>;
            };
          };
        } | {
          "resolution_url": string;
        };
      }>;
    };
  };
  "introduction_evidence": {
    "kind": "locator_ref";
    "principal_locator": {
      "schema": "ak.schema.principal_locator.v1";
      "account_id": {
        "principal_id": string;
        "station_id": string;
      };
      "service_resolution": {
        "inline": {
          "service_id": string;
          "service_kind": string;
          "method_history_evidence": {
            "evidence_kind": "webvh_log";
            "boundary": {
              "from_method_history_head": string;
              "from_version_id": string;
              "to_method_history_head": string;
              "to_version_id": string;
            };
            "evidence": {
              "kind": "ak.did.binding_evidence.v1";
              "method": string;
              "document_digest": string;
              "method_proofs": Array<{
                "kind": "webvh_log";
                "history_head": string;
                "witnesses": Array<{
                  "witness_did": string;
                  "controlling_organization_did": string;
                }>;
                "witness_proofs_digest": string;
              }>;
            };
            "log_entries": Array<Record<string, unknown>>;
            "witness_records": Array<Record<string, unknown>>;
          } | {
            "evidence_kind": "did_web_document";
            "boundary": {
              "from_method_history_head": string;
              "from_version_id": string;
              "to_method_history_head": string;
              "to_version_id": string;
            };
            "evidence": {
              "kind": "ak.did.binding_evidence.v1";
              "method": string;
              "document_digest": string;
              "method_proofs": Array<{
                "kind": "webvh_log";
                "history_head": string;
                "witnesses": Array<{
                  "witness_did": string;
                  "controlling_organization_did": string;
                }>;
                "witness_proofs_digest": string;
              }>;
            };
          } | {
            "evidence_kind": "did_key_expansion";
            "boundary": {
              "from_method_history_head": string;
              "from_version_id": string;
              "to_method_history_head": string;
              "to_version_id": string;
            };
            "evidence": {
              "kind": "ak.did.binding_evidence.v1";
              "method": string;
              "document_digest": string;
              "method_proofs": Array<{
                "kind": "webvh_log";
                "history_head": string;
                "witnesses": Array<{
                  "witness_did": string;
                  "controlling_organization_did": string;
                }>;
                "witness_proofs_digest": string;
              }>;
            };
          };
          "normalized_did_document": {
            "did": string;
            "contexts": Array<string | Record<string, unknown>>;
            "controller_dids": string[];
            "also_known_as": string[];
            "verification_methods": Array<{
              "verification_method": string;
              "controller_did": string;
              "verification_method_suite": string;
              "public_key_material": Record<string, unknown>;
              "extensions": Array<{
                "name": string;
                "value": unknown;
              }>;
            }>;
            "authentication": Array<{
              "verification_method": string;
            }>;
            "assertion_methods": Array<{
              "verification_method": string;
            }>;
            "key_agreements": Array<{
              "verification_method": string;
            }>;
            "capability_invocations": Array<{
              "verification_method": string;
            }>;
            "capability_delegations": Array<{
              "verification_method": string;
            }>;
            "services": Array<{
              "uri": string;
              "protocol_names": string[];
              "endpoint": unknown;
              "extensions": Array<{
                "name": string;
                "value": unknown;
              }>;
            }>;
            "metadata": {
              "primary_handle"?: string;
            };
            "extensions": Array<{
              "name": string;
              "value": unknown;
            }>;
          };
        };
      } | {
        "resolution_url": string;
      };
      "route_assistance"?: {
        "mirror_hints": Array<{
          "mirror_id": string;
          "service_resolution": {
            "inline": {
              "service_id": string;
              "service_kind": string;
              "method_history_evidence": {
                "evidence_kind": "webvh_log";
                "boundary": {
                  "from_method_history_head": string;
                  "from_version_id": string;
                  "to_method_history_head": string;
                  "to_version_id": string;
                };
                "evidence": {
                  "kind": "ak.did.binding_evidence.v1";
                  "method": string;
                  "document_digest": string;
                  "method_proofs": Array<{
                    "kind": "webvh_log";
                    "history_head": string;
                    "witnesses": Array<{
                      "witness_did": string;
                      "controlling_organization_did": string;
                    }>;
                    "witness_proofs_digest": string;
                  }>;
                };
                "log_entries": Array<Record<string, unknown>>;
                "witness_records": Array<Record<string, unknown>>;
              } | {
                "evidence_kind": "did_web_document";
                "boundary": {
                  "from_method_history_head": string;
                  "from_version_id": string;
                  "to_method_history_head": string;
                  "to_version_id": string;
                };
                "evidence": {
                  "kind": "ak.did.binding_evidence.v1";
                  "method": string;
                  "document_digest": string;
                  "method_proofs": Array<{
                    "kind": "webvh_log";
                    "history_head": string;
                    "witnesses": Array<{
                      "witness_did": string;
                      "controlling_organization_did": string;
                    }>;
                    "witness_proofs_digest": string;
                  }>;
                };
              } | {
                "evidence_kind": "did_key_expansion";
                "boundary": {
                  "from_method_history_head": string;
                  "from_version_id": string;
                  "to_method_history_head": string;
                  "to_version_id": string;
                };
                "evidence": {
                  "kind": "ak.did.binding_evidence.v1";
                  "method": string;
                  "document_digest": string;
                  "method_proofs": Array<{
                    "kind": "webvh_log";
                    "history_head": string;
                    "witnesses": Array<{
                      "witness_did": string;
                      "controlling_organization_did": string;
                    }>;
                    "witness_proofs_digest": string;
                  }>;
                };
              };
              "normalized_did_document": {
                "did": string;
                "contexts": Array<string | Record<string, unknown>>;
                "controller_dids": string[];
                "also_known_as": string[];
                "verification_methods": Array<{
                  "verification_method": string;
                  "controller_did": string;
                  "verification_method_suite": string;
                  "public_key_material": Record<string, unknown>;
                  "extensions": Array<{
                    "name": string;
                    "value": unknown;
                  }>;
                }>;
                "authentication": Array<{
                  "verification_method": string;
                }>;
                "assertion_methods": Array<{
                  "verification_method": string;
                }>;
                "key_agreements": Array<{
                  "verification_method": string;
                }>;
                "capability_invocations": Array<{
                  "verification_method": string;
                }>;
                "capability_delegations": Array<{
                  "verification_method": string;
                }>;
                "services": Array<{
                  "uri": string;
                  "protocol_names": string[];
                  "endpoint": unknown;
                  "extensions": Array<{
                    "name": string;
                    "value": unknown;
                  }>;
                }>;
                "metadata": {
                  "primary_handle"?: string;
                };
                "extensions": Array<{
                  "name": string;
                  "value": unknown;
                }>;
              };
            };
          } | {
            "resolution_url": string;
          };
        }>;
      };
      "issued_at": string;
      "expires_at": string;
      "locator_ref_digest": string;
      "display_hint"?: {
        "display_name_hint"?: string;
        "avatar_blob_ref"?: string;
      };
      "proofs": Array<{
        "proof_purpose": "subject_locator_authorization" | "recipient_service_acceptance";
        "proof": {
          "kind": "detached_jws";
          "verification_method": string;
          "payload_digest": string;
          "created_at": string;
          "domain"?: string;
          "audience"?: string | string[];
          "proof_purpose"?: "issuer_attestation" | "holder_acceptance" | "status_attestation" | "revocation_authorization" | "governance_authorization";
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
      "claim": {
        "schema": "ak.schema.handle_claim_core.v1";
        "handle": string;
        "handle_aliases": string[];
        "subject_account_id": {
          "principal_id": string;
          "station_id": string;
        };
        "issuer_id": string;
        "claim": {
          "kind": "handle_binding";
        } | {
          "kind": "organization_handle";
          "organization_id": string;
        };
        "visibility": "public" | "restricted" | "private";
        "audience": string | null;
        "issued_at": string;
        "expires_at": string | null;
        "source_refs": string[];
        "proofs": unknown[];
      };
      "status": "pending" | "verified" | "revoked";
      "as_of": string;
      "verifier_id": string;
      "verified_at": string | null;
      "revocation": {
        "schema": "ak.schema.handle_claim_revocation.v1";
        "claim_digest": string;
        "revoked_at": string;
        "revoker": {
          "role": "issuer";
          "issuer_id": string;
        } | {
          "role": "holder";
          "subject_account_id": {
            "principal_id": string;
            "station_id": string;
          };
        };
        "proof": {
          "kind": "detached_jws";
          "verification_method": string;
          "payload_digest": string;
          "created_at": string;
          "domain"?: string;
          "audience"?: string | string[];
          "proof_purpose"?: "issuer_attestation" | "holder_acceptance" | "status_attestation" | "revocation_authorization" | "governance_authorization";
          "jws": string;
        } & {
          "domain": "ak.handle_claim_revocation.v1";
          "proof_purpose": "revocation_authorization";
          [key: string]: unknown;
        };
      } | null;
      "fresh_until": string;
      "status_proof": {
        "kind": "detached_jws";
        "verification_method": string;
        "payload_digest": string;
        "created_at": string;
        "domain"?: string;
        "audience"?: string | string[];
        "proof_purpose"?: "issuer_attestation" | "holder_acceptance" | "status_attestation" | "revocation_authorization" | "governance_authorization";
        "jws": string;
      } & {
        "domain": "ak.handle_claim_status.v1";
        "proof_purpose": "status_attestation";
        [key: string]: unknown;
      };
    };
    "resolved_by"?: string;
    "resolved_at"?: string;
  } | {
    "kind": "explicit_address";
  };
  "idempotency_key": string;
};

/** `invite-delivery-request.schema.json#/$defs/self_invite_dispatch_request_body` — closed object schema. */
export type SelfInviteDispatchRequestBody = {
  "schema": "ak.schema.invite_delivery_request.v1";
  "invite_event_id": string;
  "invite_address": {
    "account_id": {
      "principal_id": string;
      "station_id": string;
    };
    "service_resolution": {
      "inline": {
        "service_id": string;
        "service_kind": string;
        "method_history_evidence": {
          "evidence_kind": "webvh_log";
          "boundary": {
            "from_method_history_head": string;
            "from_version_id": string;
            "to_method_history_head": string;
            "to_version_id": string;
          };
          "evidence": {
            "kind": "ak.did.binding_evidence.v1";
            "method": string;
            "document_digest": string;
            "method_proofs": Array<{
              "kind": "webvh_log";
              "history_head": string;
              "witnesses": Array<{
                "witness_did": string;
                "controlling_organization_did": string;
              }>;
              "witness_proofs_digest": string;
            }>;
          };
          "log_entries": Array<Record<string, unknown>>;
          "witness_records": Array<Record<string, unknown>>;
        } | {
          "evidence_kind": "did_web_document";
          "boundary": {
            "from_method_history_head": string;
            "from_version_id": string;
            "to_method_history_head": string;
            "to_version_id": string;
          };
          "evidence": {
            "kind": "ak.did.binding_evidence.v1";
            "method": string;
            "document_digest": string;
            "method_proofs": Array<{
              "kind": "webvh_log";
              "history_head": string;
              "witnesses": Array<{
                "witness_did": string;
                "controlling_organization_did": string;
              }>;
              "witness_proofs_digest": string;
            }>;
          };
        } | {
          "evidence_kind": "did_key_expansion";
          "boundary": {
            "from_method_history_head": string;
            "from_version_id": string;
            "to_method_history_head": string;
            "to_version_id": string;
          };
          "evidence": {
            "kind": "ak.did.binding_evidence.v1";
            "method": string;
            "document_digest": string;
            "method_proofs": Array<{
              "kind": "webvh_log";
              "history_head": string;
              "witnesses": Array<{
                "witness_did": string;
                "controlling_organization_did": string;
              }>;
              "witness_proofs_digest": string;
            }>;
          };
        };
        "normalized_did_document": {
          "did": string;
          "contexts": Array<string | Record<string, unknown>>;
          "controller_dids": string[];
          "also_known_as": string[];
          "verification_methods": Array<{
            "verification_method": string;
            "controller_did": string;
            "verification_method_suite": string;
            "public_key_material": Record<string, unknown>;
            "extensions": Array<{
              "name": string;
              "value": unknown;
            }>;
          }>;
          "authentication": Array<{
            "verification_method": string;
          }>;
          "assertion_methods": Array<{
            "verification_method": string;
          }>;
          "key_agreements": Array<{
            "verification_method": string;
          }>;
          "capability_invocations": Array<{
            "verification_method": string;
          }>;
          "capability_delegations": Array<{
            "verification_method": string;
          }>;
          "services": Array<{
            "uri": string;
            "protocol_names": string[];
            "endpoint": unknown;
            "extensions": Array<{
              "name": string;
              "value": unknown;
            }>;
          }>;
          "metadata": {
            "primary_handle"?: string;
          };
          "extensions": Array<{
            "name": string;
            "value": unknown;
          }>;
        };
      };
    } | {
      "resolution_url": string;
    };
    "route_assistance"?: {
      "mirror_hints": Array<{
        "mirror_id": string;
        "service_resolution": {
          "inline": {
            "service_id": string;
            "service_kind": string;
            "method_history_evidence": {
              "evidence_kind": "webvh_log";
              "boundary": {
                "from_method_history_head": string;
                "from_version_id": string;
                "to_method_history_head": string;
                "to_version_id": string;
              };
              "evidence": {
                "kind": "ak.did.binding_evidence.v1";
                "method": string;
                "document_digest": string;
                "method_proofs": Array<{
                  "kind": "webvh_log";
                  "history_head": string;
                  "witnesses": Array<{
                    "witness_did": string;
                    "controlling_organization_did": string;
                  }>;
                  "witness_proofs_digest": string;
                }>;
              };
              "log_entries": Array<Record<string, unknown>>;
              "witness_records": Array<Record<string, unknown>>;
            } | {
              "evidence_kind": "did_web_document";
              "boundary": {
                "from_method_history_head": string;
                "from_version_id": string;
                "to_method_history_head": string;
                "to_version_id": string;
              };
              "evidence": {
                "kind": "ak.did.binding_evidence.v1";
                "method": string;
                "document_digest": string;
                "method_proofs": Array<{
                  "kind": "webvh_log";
                  "history_head": string;
                  "witnesses": Array<{
                    "witness_did": string;
                    "controlling_organization_did": string;
                  }>;
                  "witness_proofs_digest": string;
                }>;
              };
            } | {
              "evidence_kind": "did_key_expansion";
              "boundary": {
                "from_method_history_head": string;
                "from_version_id": string;
                "to_method_history_head": string;
                "to_version_id": string;
              };
              "evidence": {
                "kind": "ak.did.binding_evidence.v1";
                "method": string;
                "document_digest": string;
                "method_proofs": Array<{
                  "kind": "webvh_log";
                  "history_head": string;
                  "witnesses": Array<{
                    "witness_did": string;
                    "controlling_organization_did": string;
                  }>;
                  "witness_proofs_digest": string;
                }>;
              };
            };
            "normalized_did_document": {
              "did": string;
              "contexts": Array<string | Record<string, unknown>>;
              "controller_dids": string[];
              "also_known_as": string[];
              "verification_methods": Array<{
                "verification_method": string;
                "controller_did": string;
                "verification_method_suite": string;
                "public_key_material": Record<string, unknown>;
                "extensions": Array<{
                  "name": string;
                  "value": unknown;
                }>;
              }>;
              "authentication": Array<{
                "verification_method": string;
              }>;
              "assertion_methods": Array<{
                "verification_method": string;
              }>;
              "key_agreements": Array<{
                "verification_method": string;
              }>;
              "capability_invocations": Array<{
                "verification_method": string;
              }>;
              "capability_delegations": Array<{
                "verification_method": string;
              }>;
              "services": Array<{
                "uri": string;
                "protocol_names": string[];
                "endpoint": unknown;
                "extensions": Array<{
                  "name": string;
                  "value": unknown;
                }>;
              }>;
              "metadata": {
                "primary_handle"?: string;
              };
              "extensions": Array<{
                "name": string;
                "value": unknown;
              }>;
            };
          };
        } | {
          "resolution_url": string;
        };
      }>;
    };
  };
  "introduction_evidence": {
    "kind": "locator_ref";
    "principal_locator": {
      "schema": "ak.schema.principal_locator.v1";
      "account_id": {
        "principal_id": string;
        "station_id": string;
      };
      "service_resolution": {
        "inline": {
          "service_id": string;
          "service_kind": string;
          "method_history_evidence": {
            "evidence_kind": "webvh_log";
            "boundary": {
              "from_method_history_head": string;
              "from_version_id": string;
              "to_method_history_head": string;
              "to_version_id": string;
            };
            "evidence": {
              "kind": "ak.did.binding_evidence.v1";
              "method": string;
              "document_digest": string;
              "method_proofs": Array<{
                "kind": "webvh_log";
                "history_head": string;
                "witnesses": Array<{
                  "witness_did": string;
                  "controlling_organization_did": string;
                }>;
                "witness_proofs_digest": string;
              }>;
            };
            "log_entries": Array<Record<string, unknown>>;
            "witness_records": Array<Record<string, unknown>>;
          } | {
            "evidence_kind": "did_web_document";
            "boundary": {
              "from_method_history_head": string;
              "from_version_id": string;
              "to_method_history_head": string;
              "to_version_id": string;
            };
            "evidence": {
              "kind": "ak.did.binding_evidence.v1";
              "method": string;
              "document_digest": string;
              "method_proofs": Array<{
                "kind": "webvh_log";
                "history_head": string;
                "witnesses": Array<{
                  "witness_did": string;
                  "controlling_organization_did": string;
                }>;
                "witness_proofs_digest": string;
              }>;
            };
          } | {
            "evidence_kind": "did_key_expansion";
            "boundary": {
              "from_method_history_head": string;
              "from_version_id": string;
              "to_method_history_head": string;
              "to_version_id": string;
            };
            "evidence": {
              "kind": "ak.did.binding_evidence.v1";
              "method": string;
              "document_digest": string;
              "method_proofs": Array<{
                "kind": "webvh_log";
                "history_head": string;
                "witnesses": Array<{
                  "witness_did": string;
                  "controlling_organization_did": string;
                }>;
                "witness_proofs_digest": string;
              }>;
            };
          };
          "normalized_did_document": {
            "did": string;
            "contexts": Array<string | Record<string, unknown>>;
            "controller_dids": string[];
            "also_known_as": string[];
            "verification_methods": Array<{
              "verification_method": string;
              "controller_did": string;
              "verification_method_suite": string;
              "public_key_material": Record<string, unknown>;
              "extensions": Array<{
                "name": string;
                "value": unknown;
              }>;
            }>;
            "authentication": Array<{
              "verification_method": string;
            }>;
            "assertion_methods": Array<{
              "verification_method": string;
            }>;
            "key_agreements": Array<{
              "verification_method": string;
            }>;
            "capability_invocations": Array<{
              "verification_method": string;
            }>;
            "capability_delegations": Array<{
              "verification_method": string;
            }>;
            "services": Array<{
              "uri": string;
              "protocol_names": string[];
              "endpoint": unknown;
              "extensions": Array<{
                "name": string;
                "value": unknown;
              }>;
            }>;
            "metadata": {
              "primary_handle"?: string;
            };
            "extensions": Array<{
              "name": string;
              "value": unknown;
            }>;
          };
        };
      } | {
        "resolution_url": string;
      };
      "route_assistance"?: {
        "mirror_hints": Array<{
          "mirror_id": string;
          "service_resolution": {
            "inline": {
              "service_id": string;
              "service_kind": string;
              "method_history_evidence": {
                "evidence_kind": "webvh_log";
                "boundary": {
                  "from_method_history_head": string;
                  "from_version_id": string;
                  "to_method_history_head": string;
                  "to_version_id": string;
                };
                "evidence": {
                  "kind": "ak.did.binding_evidence.v1";
                  "method": string;
                  "document_digest": string;
                  "method_proofs": Array<{
                    "kind": "webvh_log";
                    "history_head": string;
                    "witnesses": Array<{
                      "witness_did": string;
                      "controlling_organization_did": string;
                    }>;
                    "witness_proofs_digest": string;
                  }>;
                };
                "log_entries": Array<Record<string, unknown>>;
                "witness_records": Array<Record<string, unknown>>;
              } | {
                "evidence_kind": "did_web_document";
                "boundary": {
                  "from_method_history_head": string;
                  "from_version_id": string;
                  "to_method_history_head": string;
                  "to_version_id": string;
                };
                "evidence": {
                  "kind": "ak.did.binding_evidence.v1";
                  "method": string;
                  "document_digest": string;
                  "method_proofs": Array<{
                    "kind": "webvh_log";
                    "history_head": string;
                    "witnesses": Array<{
                      "witness_did": string;
                      "controlling_organization_did": string;
                    }>;
                    "witness_proofs_digest": string;
                  }>;
                };
              } | {
                "evidence_kind": "did_key_expansion";
                "boundary": {
                  "from_method_history_head": string;
                  "from_version_id": string;
                  "to_method_history_head": string;
                  "to_version_id": string;
                };
                "evidence": {
                  "kind": "ak.did.binding_evidence.v1";
                  "method": string;
                  "document_digest": string;
                  "method_proofs": Array<{
                    "kind": "webvh_log";
                    "history_head": string;
                    "witnesses": Array<{
                      "witness_did": string;
                      "controlling_organization_did": string;
                    }>;
                    "witness_proofs_digest": string;
                  }>;
                };
              };
              "normalized_did_document": {
                "did": string;
                "contexts": Array<string | Record<string, unknown>>;
                "controller_dids": string[];
                "also_known_as": string[];
                "verification_methods": Array<{
                  "verification_method": string;
                  "controller_did": string;
                  "verification_method_suite": string;
                  "public_key_material": Record<string, unknown>;
                  "extensions": Array<{
                    "name": string;
                    "value": unknown;
                  }>;
                }>;
                "authentication": Array<{
                  "verification_method": string;
                }>;
                "assertion_methods": Array<{
                  "verification_method": string;
                }>;
                "key_agreements": Array<{
                  "verification_method": string;
                }>;
                "capability_invocations": Array<{
                  "verification_method": string;
                }>;
                "capability_delegations": Array<{
                  "verification_method": string;
                }>;
                "services": Array<{
                  "uri": string;
                  "protocol_names": string[];
                  "endpoint": unknown;
                  "extensions": Array<{
                    "name": string;
                    "value": unknown;
                  }>;
                }>;
                "metadata": {
                  "primary_handle"?: string;
                };
                "extensions": Array<{
                  "name": string;
                  "value": unknown;
                }>;
              };
            };
          } | {
            "resolution_url": string;
          };
        }>;
      };
      "issued_at": string;
      "expires_at": string;
      "locator_ref_digest": string;
      "display_hint"?: {
        "display_name_hint"?: string;
        "avatar_blob_ref"?: string;
      };
      "proofs": Array<{
        "proof_purpose": "subject_locator_authorization" | "recipient_service_acceptance";
        "proof": {
          "kind": "detached_jws";
          "verification_method": string;
          "payload_digest": string;
          "created_at": string;
          "domain"?: string;
          "audience"?: string | string[];
          "proof_purpose"?: "issuer_attestation" | "holder_acceptance" | "status_attestation" | "revocation_authorization" | "governance_authorization";
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
      "claim": {
        "schema": "ak.schema.handle_claim_core.v1";
        "handle": string;
        "handle_aliases": string[];
        "subject_account_id": {
          "principal_id": string;
          "station_id": string;
        };
        "issuer_id": string;
        "claim": {
          "kind": "handle_binding";
        } | {
          "kind": "organization_handle";
          "organization_id": string;
        };
        "visibility": "public" | "restricted" | "private";
        "audience": string | null;
        "issued_at": string;
        "expires_at": string | null;
        "source_refs": string[];
        "proofs": unknown[];
      };
      "status": "pending" | "verified" | "revoked";
      "as_of": string;
      "verifier_id": string;
      "verified_at": string | null;
      "revocation": {
        "schema": "ak.schema.handle_claim_revocation.v1";
        "claim_digest": string;
        "revoked_at": string;
        "revoker": {
          "role": "issuer";
          "issuer_id": string;
        } | {
          "role": "holder";
          "subject_account_id": {
            "principal_id": string;
            "station_id": string;
          };
        };
        "proof": {
          "kind": "detached_jws";
          "verification_method": string;
          "payload_digest": string;
          "created_at": string;
          "domain"?: string;
          "audience"?: string | string[];
          "proof_purpose"?: "issuer_attestation" | "holder_acceptance" | "status_attestation" | "revocation_authorization" | "governance_authorization";
          "jws": string;
        } & {
          "domain": "ak.handle_claim_revocation.v1";
          "proof_purpose": "revocation_authorization";
          [key: string]: unknown;
        };
      } | null;
      "fresh_until": string;
      "status_proof": {
        "kind": "detached_jws";
        "verification_method": string;
        "payload_digest": string;
        "created_at": string;
        "domain"?: string;
        "audience"?: string | string[];
        "proof_purpose"?: "issuer_attestation" | "holder_acceptance" | "status_attestation" | "revocation_authorization" | "governance_authorization";
        "jws": string;
      } & {
        "domain": "ak.handle_claim_status.v1";
        "proof_purpose": "status_attestation";
        [key: string]: unknown;
      };
    };
    "resolved_by"?: string;
    "resolved_at"?: string;
  } | {
    "kind": "explicit_address";
  };
  "idempotency_key": string;
};

/** `realm-commit.schema.json#/$defs/stream_head` — closed object schema. */
export type CommitStreamHead = {
  "stream_ref": {
    "kind": "realm";
    "realm_id": string;
  } | {
    "kind": "circle";
    "realm_id": string;
    "circle_id": string;
  } | {
    "kind": "sidecar";
    "realm_id": string;
    "sidecar_id": string;
  };
  "stream_position": number;
  "commit_id": string;
};

/** `service-operation-dtos.schema.json#/$defs/EventAdmissionSubmission` — closed object schema. */
export type EventAdmissionSubmission = {
  "event": {
    "event_id": string;
    "kind": string;
    "realm_id"?: string;
    "scope_ref": {
      "kind": "realm";
      "realm_id": string;
    } | {
      "kind": "circle";
      "realm_id": string;
      "circle_id": string;
    } | {
      "kind": "sidecar";
      "realm_id": string;
      "sidecar_id": string;
    } | {
      "kind": "realm_genesis";
    };
    "actor_id": {
      "kind": "account";
      "account_id": {
        "principal_id": string;
        "station_id": string;
      };
    } | {
      "kind": "service";
      "service_id": string;
    };
    "executed_by"?: {
      "kind": "account";
      "account_id": {
        "principal_id": string;
        "station_id": string;
      };
    } | {
      "kind": "service";
      "service_id": string;
    };
    "authorization_ref"?: string | "ak.authority.direct_conversation_participant.v1" | "ak.authority.direct_conversation_bootstrap_participant.v1";
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
      "uri"?: string;
      [key: string]: unknown;
    };
    "created_at": string;
    "semantic_refs"?: Array<{
      "id": string;
      "role": "authorized_by";
      "critical": boolean;
    } | {
      "id": string;
      "role": "attestation" | "parent_event" | "after" | "audit_pair" | "recovery_capability" | "accountability" | "bootstrap_genesis" | "disclosure_authorization" | "capture_stop" | "direct_conversation_binding" | "direct_conversation_founding_unit" | "direct_conversation_contact_round" | "direct_conversation_agent_provision" | "applet_managed_actor_provision";
      "critical": boolean;
    }>;
    "payload": Record<string, unknown>;
    "producer_proof": {
      "kind": "detached_jws";
      "verification_method": string;
      "event_digest": string;
      "created_at": string;
      "domain"?: string;
      "audience"?: string | string[];
      "proof_purpose"?: "issuer_attestation" | "holder_acceptance";
      "jws": string;
    };
  };
  "approval_signatures"?: Array<{
    "input": {
      "approval_context": {
        "context_kind": "grant";
        "grant_id": string;
      } | {
        "context_kind": "realm_governance";
      } | {
        "context_kind": "list_wip";
        "list_space_id": string;
        "list_policy_revision": {
          "commit_id": string;
          "stream_position": number;
        };
      } | {
        "context_kind": "management";
        "management_operation": "join" | "publish" | "create_bot" | "map_ghost";
        "effective_scope": {
          "kind": "realm";
          "realm_id": string;
        } | {
          "kind": "circle";
          "realm_id": string;
          "circle_id": string;
        };
        "request_id": string;
      };
      "approval_target": {
        "target_kind": "event";
        "event_id": string;
      } | {
        "target_kind": "operation";
      };
      "request_canonical_digest": string;
      "operation": string;
      "action": string;
      "realm_id": string;
      "initiating_actor_id": {
        "kind": "account";
        "account_id": {
          "principal_id": string;
          "station_id": string;
        };
      } | {
        "kind": "service";
        "service_id": string;
      };
      "approver_did": string;
      "approved_at": string;
      "nonce": string;
    };
    "proof": {
      "kind": "detached_jws";
      "verification_method": string;
      "jws": string;
    };
  }>;
};
