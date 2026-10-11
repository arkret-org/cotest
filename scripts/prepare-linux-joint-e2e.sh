#!/usr/bin/env bash
# Provision and restore prerequisites on an ephemeral GitHub Actions runner.
set -euo pipefail

if [[ ${GITHUB_ACTIONS:-} != true || $(uname -s) != Linux ]]; then
  echo 'This adapter requires a Linux GitHub Actions runner.' >&2
  exit 1
fi
: "${RUNNER_TEMP:?RUNNER_TEMP is required}"
state="$RUNNER_TEMP/cotest-joint-prerequisites"
acl_backup="$state/hosts.acl"

case ${1:-setup} in
  restore)
    if [[ -f "$acl_backup" ]]; then
      sudo setfacl --restore="$acl_backup"
      echo 'Restored the original hosts ACL.'
    fi
    exit 0
    ;;
  setup) ;;
  *) echo 'Expected setup or restore.' >&2; exit 1 ;;
esac

: "${GITHUB_PATH:?GITHUB_PATH is required}"
: "${GITHUB_ENV:?GITHUB_ENV is required}"

# Freshness inventories use complete offline Cargo metadata for each local
# dependency root. Host builds and Docker builds do not populate all of those
# workspace and platform dependencies on a cold runner.
script_directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
workspace_root=$(dirname -- "$(dirname -- "$script_directory")")
for repository in arkret-rust-sdk floria coland coauth garth chime inkson cotest; do
  (
    cd -- "$workspace_root/$repository"
    cargo fetch --locked --manifest-path Cargo.toml
  )
done

case $(uname -m) in
  x86_64)
    architecture=amd64
    archive_hash=727b91701a392de6ebc5027509f548bf39979e5216340d0faed8fa5e69c84f8b
    ;;
  aarch64)
    architecture=arm64
    archive_hash=d8fc6d179a5d283028a472a5618564f6ad8a86fed513e64f032b3b0b7cc45e42
    ;;
  *) echo 'Unsupported Caddy release architecture.' >&2; exit 1 ;;
esac

mkdir -p "$state/bin"
archive="$state/caddy.tar.gz"
curl --fail --silent --show-error --location --retry 3 \
  "https://github.com/caddyserver/caddy/releases/download/v2.11.7/caddy_2.11.7_linux_${architecture}.tar.gz" \
  --output "$archive"
printf '%s  %s\n' "$archive_hash" "$archive" | sha256sum --check --strict
tar --extract --gzip --file "$archive" --directory "$state/bin" caddy
chmod 755 "$state/bin/caddy"
"$state/bin/caddy" version
binary_hash=$(sha256sum "$state/bin/caddy" | cut -d ' ' -f 1)
printf '%s\n' "$state/bin" >> "$GITHUB_PATH"
printf 'COTEST_CADDY_SOURCE=official-static\nCOTEST_CADDY_EXPECTED_SHA256=%s\n' "$binary_hash" >> "$GITHUB_ENV"

sudo apt-get update
sudo apt-get install -y acl
if [[ ! -f "$acl_backup" ]]; then
  getfacl --absolute-names /etc/hosts > "$acl_backup"
fi
sudo setfacl --modify "u:$(id -un):rw" /etc/hosts
printf 'COTEST_LINUX_HOSTS_ACL_BACKUP=%s\n' "$acl_backup" >> "$GITHUB_ENV"
# This checks the same write capability used by the PowerShell preflight.
test -r /etc/hosts && test -w /etc/hosts
