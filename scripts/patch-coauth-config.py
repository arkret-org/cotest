#!/usr/bin/env python3
"""Patch a generated coauth config for cotest joint E2E runs."""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys


def yaml_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=True)


def replace_first_line(src: str, pattern: str, replacement: str) -> str:
    patched, count = re.subn(pattern, replacement, src, count=1, flags=re.MULTILINE)
    if count != 1:
        raise SystemExit(f"FATAL: failed to patch pattern {pattern!r}")
    return patched


def replace_http_listeners(src: str, bind_addr: str) -> str:
    http_match = re.search(r"^http:\s*$", src, flags=re.MULTILINE)
    if not http_match:
        raise SystemExit("FATAL: no `http:` section in generated config")

    http_start = http_match.end() + 1
    listeners_match = re.search(r"^  listeners:\s*$", src[http_start:], flags=re.MULTILINE)
    if not listeners_match:
        raise SystemExit("FATAL: no `http.listeners:` key in generated config")

    listeners_abs_start = http_start + listeners_match.start()
    lines = src[listeners_abs_start:].splitlines(keepends=True)
    offset = len(lines[0])
    for line in lines[1:]:
        if line and not line[0].isspace():
            break
        if len(line) > 2 and line[0] == " " and line[1] == " " and line[2].isalpha():
            break
        offset += len(line)

    tail_start = listeners_abs_start + offset
    replacement = (
        "  listeners:\n"
        "  - name: web\n"
        "    resources:\n"
        "    - name: discovery\n"
        "    - name: human\n"
        "    - name: oauth\n"
        "    - name: restapi\n"
        "    - name: assets\n"
        "    - name: adminapi\n"
        "    - name: health\n"
        "    binds:\n"
        f"    - address: {yaml_string(bind_addr)}\n"
        "    proxy_protocol: false\n"
    )
    return src[:listeners_abs_start] + replacement + src[tail_start:]


def replace_top_level_section(src: str, section: str, replacement: str) -> str:
    section_match = re.search(rf"^{re.escape(section)}:\s*$", src, flags=re.MULTILINE)
    replacement = replacement.rstrip() + "\n"
    if not section_match:
        return src.rstrip() + "\n\n" + replacement

    tail = src[section_match.end() :]
    next_match = re.search(r"^\S[^:\n]*:\s*$", tail, flags=re.MULTILINE)
    if next_match:
        end = section_match.end() + next_match.start()
    else:
        end = len(src)
    return src[: section_match.start()] + replacement + src[end:].lstrip("\n")


def trailing_slash(value: str) -> str:
    return value.rstrip("/") + "/"


def replace_named_pem_key(src: str, kid: str, pem_body: str) -> str:
    pattern = (
        rf"(^  - kid: {re.escape(kid)}\s*$\n^    key: \|\s*$\n)"
        r"(?:^      .*\n)+"
    )
    replacement = (
        rf"\g<1>      -----BEGIN PRIVATE KEY-----\n"
        f"      {pem_body}\n"
        "      -----END PRIVATE KEY-----\n"
    )
    patched, count = re.subn(pattern, replacement, src, count=1, flags=re.MULTILINE)
    if count != 1:
        raise SystemExit(f"FATAL: failed to patch configured key {kid!r}")
    return patched


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("raw_config", type=pathlib.Path)
    parser.add_argument("output_config", type=pathlib.Path)
    parser.add_argument("--postgres-url", required=True)
    parser.add_argument("--coauth-base-url", required=True)
    parser.add_argument("--coauth-bind", required=True)
    parser.add_argument("--cedar-policy-file", required=True, type=pathlib.Path)
    # Optional: a browserless lane (the `joint-api` Playwright project) starts no
    # Inkson, so it has no callback origin to register. The OAuth client itself is
    # still registered either way — `oidc-login-chain` asserts the advertised
    # `client_id` without opening a browser.
    parser.add_argument("--inkson-base-url", action="append", default=[])
    parser.add_argument("--inkson-server2-base-url")
    parser.add_argument("--oauth-client-id", required=True)
    parser.add_argument("--station", action="append", default=[])
    parser.add_argument("--soland-base-url")
    parser.add_argument("--soland-server2-base-url")
    parser.add_argument("--owning-station", default="server1")
    parser.add_argument("--admin-audience")
    parser.add_argument("--session-grant-introspection-bearer", required=True)
    parser.add_argument("--embedded-webvh-registration-bearer", required=True)
    parser.add_argument("--mock-email-base-url")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    src = args.raw_config.read_text(encoding="utf-8-sig")
    src = replace_named_pem_key(
        src,
        "coauth-account-authority-v1",
        "MC4CAQAwBQYDK2VwBCIEIAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI",
    )
    coauth_base = trailing_slash(args.coauth_base_url)
    station_items = list(args.station)
    if not station_items and args.soland_base_url:
        station_items.append(f"server1={args.soland_base_url}")
        if args.soland_server2_base_url:
            station_items.append(f"server2={args.soland_server2_base_url}")
    if not station_items:
        raise SystemExit("FATAL: at least one --station serverN=URL is required")
    stations_by_name: list[tuple[str, str]] = []
    for item in station_items:
        name, separator, endpoint = item.partition("=")
        if not separator or not re.fullmatch(r"server[1-9][0-9]*", name):
            raise SystemExit(f"FATAL: invalid --station value {item!r}; expected serverN=URL")
        if any(existing == name for existing, _ in stations_by_name):
            raise SystemExit(f"FATAL: duplicate Station name {name!r}")
        stations_by_name.append((name, trailing_slash(endpoint)))
    if args.owning_station not in {name for name, _ in stations_by_name}:
        raise SystemExit("FATAL: owning Station is not present in --station values")
    inkson_urls = list(args.inkson_base_url)
    if args.inkson_server2_base_url:
        inkson_urls.append(args.inkson_server2_base_url)
    inkson_callbacks = list(dict.fromkeys(
        trailing_slash(value) + "auth/callback" for value in inkson_urls
    ))
    admin_audience = args.admin_audience or coauth_base.rstrip("/") + "/api/v1"

    src = replace_first_line(
        src,
        r"^(\s*uri:).*$",
        rf"\1 {args.postgres_url}",
    )
    src = replace_first_line(
        src,
        r"^(\s*public_base_url:).*$",
        rf"\1 {coauth_base}",
    )
    src = replace_first_line(
        src,
        r"^(\s*issuer:).*$",
        rf"\1 {coauth_base}",
    )
    src = replace_http_listeners(src, args.coauth_bind)

    policy = (
        "policy:\n"
        "  engine: cedar\n"
        f"  cedar_policy_file: {yaml_string(str(args.cedar_policy_file.resolve()))}\n"
    )
    src = replace_top_level_section(src, "policy", policy)

    email_bypass = "false" if args.mock_email_base_url else "true"
    account = (
        "account:\n"
        "  password_registration_enabled: true\n"
        f"  registration_email_delivery_bypass_allowed: {email_bypass}\n"
    )
    src = replace_top_level_section(src, "account", account)

    rate_limiting = (
        "rate_limiting:\n"
        "  registration:\n"
        "    burst: 100000\n"
        "    per_second: 100000\n"
        "  login:\n"
        "    per_ip:\n"
        "      burst: 100000\n"
        "      per_second: 100000\n"
        "    per_account:\n"
        "      burst: 100000\n"
        "      per_second: 100000\n"
        "  email_authentication:\n"
        "    per_ip:\n"
        "      burst: 100000\n"
        "      per_second: 100000\n"
        "    per_address:\n"
        "      burst: 100000\n"
        "      per_second: 100000\n"
    )
    src = replace_top_level_section(src, "rate_limiting", rate_limiting)

    if args.mock_email_base_url:
        mock_email_send = trailing_slash(args.mock_email_base_url) + "mock/email/verification/send"
        email = (
            "email:\n"
            "  from: \"Coauth Joint E2E <noreply@joint-e2e.local>\"\n"
            "  reply_to: \"Coauth Joint E2E <noreply@joint-e2e.local>\"\n"
            "  provider:\n"
            "    type: http_webhook\n"
            f"    url: {yaml_string(mock_email_send)}\n"
            "    headers:\n"
            "      X-Cotest-Mock: mock-email\n"
        )
        src = replace_top_level_section(src, "email", email)

    # Order is unchanged when Inkson is present: its first callback, the two
    # loopback callbacks the non-browser flows use, then any further origins.
    # With no Inkson only the loopback pair remains.
    redirect_uris = [
        *(yaml_string(callback) for callback in inkson_callbacks[:1]),
        "http://127.0.0.1/auth/callback",
        "http://localhost/auth/callback",
        *(yaml_string(callback) for callback in inkson_callbacks[1:]),
    ]
    clients = (
        "clients:\n"
        f"- client_id: {yaml_string(args.oauth_client_id)}\n"
        "  client_name: Inkson Joint E2E\n"
        "  client_auth_method: none\n"
        "  redirect_uris:\n"
    )
    for redirect_uri in redirect_uris:
        clients += f"  - {redirect_uri}\n"
    src = replace_top_level_section(src, "clients", clients)

    stations = ""
    for station_name, station_endpoint in stations_by_name:
        stations += (
            f"  - name: {station_name}\n"
            f"    endpoint: {yaml_string(station_endpoint)}\n"
            "    session_grant_introspection_bearer: "
            f"{yaml_string(args.session_grant_introspection_bearer)}\n"
            "    embedded_webvh_registration_bearer: "
            f"{yaml_string(args.embedded_webvh_registration_bearer)}\n"
        )
    arkret = (
        "arkret:\n"
        f"  owning_station: {args.owning_station}\n"
        "  stations:\n"
        f"{stations}"
        "  deployment_profile: organization\n"
        "  principal_method: \"did:webvh\"\n"
        "  trust_domain: ak:trust_domain:local.host\n"
        f"  admin_audience: {yaml_string(admin_audience)}\n"
        "  password_login_session_grants_enabled: true\n"
    )
    src = replace_top_level_section(src, "arkret", arkret)

    args.output_config.parent.mkdir(parents=True, exist_ok=True)
    args.output_config.write_text(src, encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
