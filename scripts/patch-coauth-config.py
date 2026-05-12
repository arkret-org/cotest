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


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("raw_config", type=pathlib.Path)
    parser.add_argument("output_config", type=pathlib.Path)
    parser.add_argument("--postgres-url", required=True)
    parser.add_argument("--coauth-base-url", required=True)
    parser.add_argument("--coauth-bind", required=True)
    parser.add_argument("--soland-base-url", required=True)
    parser.add_argument("--soland-service-did", required=True)
    parser.add_argument("--coauth-service-did", required=True)
    parser.add_argument("--admin-audience")
    parser.add_argument("--oauth-introspection-bearer", required=True)
    parser.add_argument("--session-grant-introspection-bearer", required=True)
    parser.add_argument("--embedded-webvh-registration-bearer", required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    src = args.raw_config.read_text(encoding="utf-8")
    coauth_base = trailing_slash(args.coauth_base_url)
    soland_base = trailing_slash(args.soland_base_url)
    admin_audience = args.admin_audience or coauth_base.rstrip("/") + "/api/v1"

    src = replace_first_line(
        src,
        r"^(\s*uri:).*$",
        rf"\1 {args.postgres_url}",
    )
    src = replace_first_line(
        src,
        r"^(\s*public_base:).*$",
        rf"\1 {coauth_base}",
    )
    src = replace_first_line(
        src,
        r"^(\s*issuer:).*$",
        rf"\1 {coauth_base}",
    )
    src = replace_http_listeners(src, args.coauth_bind)

    contrix = (
        "contrix:\n"
        "  principal_servers:\n"
        "  - name: soland\n"
        f"    audience: {yaml_string(args.soland_service_did)}\n"
        f"    endpoint: {yaml_string(soland_base)}\n"
        f"    did: {yaml_string(args.soland_service_did)}\n"
        f"    oauth_introspection_bearer: {yaml_string(args.oauth_introspection_bearer)}\n"
        "    session_grant_introspection_bearer: "
        f"{yaml_string(args.session_grant_introspection_bearer)}\n"
        "    embedded_webvh_registration_bearer: "
        f"{yaml_string(args.embedded_webvh_registration_bearer)}\n"
        f"  service_did: {yaml_string(args.coauth_service_did)}\n"
        f"  issuer_did: {yaml_string(args.coauth_service_did)}\n"
        f"  admin_audience: {yaml_string(admin_audience)}\n"
        f"  principal_server_url: {yaml_string(soland_base)}\n"
    )
    src = replace_top_level_section(src, "contrix", contrix)

    args.output_config.parent.mkdir(parents=True, exist_ok=True)
    args.output_config.write_text(src, encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
