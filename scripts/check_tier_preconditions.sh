#!/usr/bin/env bash
# CT-003: fail-closed preflight for controlled CI lanes.

set -euo pipefail

lane="${1:-}"

fail() {
  local code="$1" name="$2"
  echo "${code} lane=${lane:-unset} name=${name}" >&2
  exit 2
}

require_env() {
  local name="$1"
  if [ -z "${!name:-}" ]; then
    fail "PRECONDITION_MISSING" "$name"
  fi
}

require_version() {
  local component="$1"
  if ! printf '%s' "$COTEST_SERVICE_VERSIONS" | grep -Eq "(^|,)${component}@[A-Za-z0-9._/-]+(,|$)"; then
    fail "PRECONDITION_VERSION_MISSING" "$component"
  fi
}

case "$lane" in
  mls-data-plane)
    require_env COTEST_SERVICE_VERSIONS
    require_env COTEST_SOLAND_BASE_URL
    require_env COTEST_COAUTH_BASE_URL
    require_env COTEST_INKSON_BASE_URL
    require_env COTEST_MLS_HARNESS_VERSION
    require_version coauth
    require_version soland
    require_version inkson
    ;;
  platform-live)
    require_env COTEST_SERVICE_VERSIONS
    require_env COTEST_PLATFORM_PROVIDER
    require_env COTEST_PLATFORM_ADAPTER_VERSION
    require_env COTEST_PLATFORM_LIVE_TOKEN
    require_env COTEST_PLATFORM_LIVE_BASE_URL
    require_env COTEST_PLATFORM_WEBHOOK_PATH
    require_env COTEST_PLATFORM_WEBHOOK_BODY_BASE64
    require_env COTEST_PLATFORM_WEBHOOK_HEADERS_JSON
    require_version bridges
    ;;
  *)
    fail "PRECONDITION_INVALID_LANE" "lane"
    ;;
esac

if ! printf '%s' "$COTEST_SERVICE_VERSIONS" | grep -Eq '^[a-z0-9._-]+@[A-Za-z0-9._/-]+(,[a-z0-9._-]+@[A-Za-z0-9._/-]+)*$'; then
  fail "PRECONDITION_VERSION_FORMAT_INVALID" "COTEST_SERVICE_VERSIONS"
fi

echo "PRECONDITION_OK lane=$lane versions=$COTEST_SERVICE_VERSIONS"
