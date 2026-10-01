// GENERATED FILE — DO NOT EDIT BY HAND.
//
// Source: arkret-spec/spec/v1/artifacts/schemas/*.json
// Producer: e2e/scripts/generate-wire-types.mjs
//
// Regenerate with `npm run gen:wire-types`; `npm run check:wire-types` fails
// when this file no longer matches the spec artifacts. Annotate hand-built wire
// literals with these types so an unregistered member is a `tsc` error rather
// than a live-server rejection.

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
  }>;
  "authority_depth": number;
  "authority_root_refs": Array<{
    "kind": "realm_root";
    "realm_id": string;
    "authority_event_ref": string;
    "authority_generation": number;
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
    "signature": {
      "context": "ak.realm_commit_signature.v1";
      "signature_algorithm": "Ed25519";
      "verification_method": string;
      "signed_digest": string;
      "created_at": string;
      "sig": string;
    };
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
