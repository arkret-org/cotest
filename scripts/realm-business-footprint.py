#!/usr/bin/env python3
"""Read a runner-owned PG cut; emit only public counts and sorted row digests.

Private connection details and selected rows never leave this process. This is
a test facility, not a production read port or a substitute for signed outcomes.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
from urllib.parse import parse_qsl, unquote, urlsplit


class PostgresSamplingFailure(RuntimeError):
    def __init__(self, sqlstate):
        self.sqlstate = sqlstate
        super().__init__("readonly PostgreSQL sampling failed")


def connection_environment(connection):
    address = urlsplit(connection)
    if (address.scheme not in ("postgres", "postgresql") or not address.hostname
            or not address.username or not address.path.startswith("/") or len(address.path) < 2):
        raise ValueError("invalid runner PostgreSQL connection")
    env = dict(os.environ)
    for key in ("PGSERVICE", "PGSERVICEFILE", "PGHOSTADDR", "PGPASSWORD"):
        env.pop(key, None)
    # PGDATABASE is a database name, not a URI expansion point. Keep every
    # connection field in the child environment so no secret appears in argv.
    env["PGHOST"] = address.hostname
    env["PGPORT"] = str(address.port or 5432)
    env["PGUSER"] = unquote(address.username)
    env["PGDATABASE"] = unquote(address.path[1:])
    if address.password is not None:
        env["PGPASSWORD"] = unquote(address.password)
    options = {"sslmode": "PGSSLMODE", "sslcert": "PGSSLCERT", "sslkey": "PGSSLKEY",
               "sslrootcert": "PGSSLROOTCERT", "connect_timeout": "PGCONNECT_TIMEOUT",
               "application_name": "PGAPPNAME", "options": "PGOPTIONS",
               "target_session_attrs": "PGTARGETSESSIONATTRS"}
    seen = set()
    for name, value in parse_qsl(address.query, keep_blank_values=True, strict_parsing=True):
        if name not in options or name in seen:
            raise ValueError("unsupported or duplicate PostgreSQL connection option")
        seen.add(name)
        env[options[name]] = value
    return env


def private_path(path, directory=False):
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode):
        raise ValueError("private control cannot be a symlink")
    if directory != stat.S_ISDIR(info.st_mode):
        raise ValueError("private control has the wrong kind")
    if os.name != "nt" and (info.st_mode & 0o077 or info.st_uid != os.getuid()):
        raise ValueError("private control permissions or owner differ")


def connection_for(server):
    if not re.fullmatch(r"server[1-9][0-9]*", server):
        raise ValueError("invalid Station locator")
    topology = json.loads(Path(os.environ["COTEST_TOPOLOGY_PATH"]).read_text())
    matches = [s for s in topology["servers"] if s["name"] == server]
    if len(matches) != 1 or topology["lifecycle"] != "running":
        raise ValueError("Station is not a current runner lease")
    directory = Path(os.environ["COTEST_READONLY_DATABASE_CONTROLS"])
    private_path(directory, directory=True)
    path = directory / (server + ".json")
    private_path(path)
    control = json.loads(path.read_text())
    coland = matches[0]["coland"]
    if (control["server"] != server
            or control["station_id"] != coland["service_id"]
            or control["public_url"] != coland["public_url"]):
        raise ValueError("database control does not belong to this Station lease")
    connection = control["database_url"]
    if not isinstance(connection, str) or not connection.startswith(("postgres://", "postgresql://")):
        raise ValueError("database control is not a PostgreSQL connection")
    return connection


def sql_for(realm, candidate, stream_after=None, stream_end=None):
    # Identifiers come from metadata, with PostgreSQL format(%I) quoting them.
    # Realm/Event locators are validated before interpolation into SQL literals.
    if not re.fullmatch(r"ak:realm:[A-Za-z0-9_-]+", realm):
        raise ValueError("invalid Realm locator")
    if candidate and not re.fullmatch(r"ak:event:[A-Za-z0-9_-]+", candidate):
        raise ValueError("invalid candidate Event locator")
    if (stream_after is None) != (stream_end is None):
        raise ValueError("both exact stream bounds are required")
    if stream_after is not None and not (0 <= stream_after <= stream_end <= 9007199254740991):
        raise ValueError("invalid exact stream bounds")
    sql = f"""
BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET LOCAL statement_timeout = '15s';
SELECT format('SELECT json_build_object(''table'',%L,''rows'',COALESCE(jsonb_agg(x ORDER BY x::text),''[]''::jsonb))::text FROM (SELECT %s AS x FROM public.%I t WHERE realm_id=%L) selected;',
    table_name,
    CASE WHEN table_name='notifications' THEN 'to_jsonb(t)-ARRAY[''state'',''read_at'',''updated_at'']' ELSE 'to_jsonb(t)' END,
    table_name, '{realm}')
FROM information_schema.columns
WHERE table_schema='public' AND column_name='realm_id'
  AND (table_name IN ('canonical_events','realm_commits','notifications')
       OR right(table_name,16)='_current_results')
ORDER BY table_name
\\gexec
"""
    for table in ["capability_quota_counters", "capability_quota_buckets", "capability_quota_consumptions"]:
        sql += f"""SELECT json_build_object('table','{table}','rows',COALESCE(jsonb_agg(x ORDER BY x::text),'[]'::jsonb))::text
FROM (SELECT to_jsonb(t) AS x FROM public.{table} t WHERE grant_id IN
(SELECT grant_id FROM public.capability_grant_current_results WHERE realm_id='{realm}')) selected;
"""
    # Delivery business identity/payload is included. Worker leases, attempt
    # counters, TTL relay rows and UI read receipts can change independently.
    sql += f"""SELECT json_build_object('table','event_federation_outbox_business','rows',COALESCE(jsonb_agg(x ORDER BY x::text),'[]'::jsonb))::text
FROM (SELECT jsonb_build_object('event_pk',e.pk,'outbox_id',f.id,'peer_id',f.peer_id,'endpoint',f.endpoint,
'idempotency_key',f.idempotency_key,'payload_json',f.payload_json,'realm_fanout',f.realm_fanout) AS x
FROM public.event_federation_outbox x JOIN public.canonical_events e ON e.pk=x.event_pk
JOIN public.federation_outbox f ON f.id=x.outbox_id WHERE e.realm_id='{realm}') selected;
"""
    if candidate:
        sql += f"""SELECT json_build_object('candidate_absence',json_build_object(
'canonical_events',(SELECT count(*) FROM public.canonical_events WHERE envelope->>'event_id'='{candidate}'),
'realm_commits',(SELECT count(*) FROM public.realm_commits WHERE commit_json->>'event_ref'='{candidate}'),
'notifications',(SELECT count(*) FROM public.notifications WHERE source_event_id='{candidate}'),
'event_notification_relay',(SELECT count(*) FROM public.event_notification_relay WHERE strpos(payload,'{candidate}')>0),
'event_federation_outbox',(SELECT count(*) FROM public.event_federation_outbox x JOIN public.canonical_events e ON e.pk=x.event_pk WHERE e.envelope->>'event_id'='{candidate}'),
'federation_outbox',(SELECT count(*) FROM public.federation_outbox WHERE strpos(payload_json,'{candidate}')>0)
))::text;
"""
    if stream_after is not None:
        # Withheld is a legal reader outcome. This private test oracle exports
        # only the already disclosed full Commit and its accepted kind/ID,
        # never the hidden Event payload, ciphertext or producer proof.
        sql += f"""SELECT json_build_object('stream_successors',COALESCE(jsonb_agg(
jsonb_build_object('commit',c.commit_json,'event_id',e.envelope->>'event_id','event_kind',e.kind)
ORDER BY c.stream_position),'[]'::jsonb))::text
FROM public.realm_commits c JOIN public.canonical_events e ON e.pk=c.event_pk
WHERE c.realm_id='{realm}' AND c.stream_ref=jsonb_build_object('kind','realm','realm_id','{realm}')
AND c.stream_position>{stream_after} AND c.stream_position<={stream_end}
AND e.state='committed' AND e.kind=e.envelope->>'kind'
AND c.commit_json->>'event_ref'=e.envelope->>'event_id';
"""
    return sql + "COMMIT;\n"


def summarize(output):
    tables = {}
    candidate = None
    successors = None
    for line in output.splitlines():
        row = json.loads(line)
        if "stream_successors" in row:
            if successors is not None or not isinstance(row["stream_successors"], list):
                raise ValueError("invalid accepted stream metadata cut")
            successors = row["stream_successors"]
            continue
        if "candidate_absence" in row:
            if candidate is not None:
                raise ValueError("duplicate candidate cut")
            candidate = row["candidate_absence"]
            if not all(isinstance(v, int) and v >= 0 for v in candidate.values()):
                raise ValueError("invalid candidate counts")
            continue
        table, rows = row["table"], row["rows"]
        if table in tables or not isinstance(rows, list):
            raise ValueError("invalid table cut")
        canonical_rows = sorted(json.dumps(x, sort_keys=True, separators=(",", ":"), ensure_ascii=False) for x in rows)
        digest = hashlib.sha256(json.dumps(canonical_rows, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
        tables[table] = {"count": len(rows), "sha256": digest}
    required = {"canonical_events", "realm_commits", "notifications", "capability_grant_current_results",
                "capability_quota_counters", "capability_quota_buckets", "capability_quota_consumptions",
                "event_federation_outbox_business"}
    if not required.issubset(tables):
        raise ValueError("required business tables are absent")
    result = {"tables": dict(sorted(tables.items())),
              "excluded_independent_bookkeeping": ["worker leases and attempts", "relay TTL collection", "notification read receipts"]}
    if candidate is not None:
        result["candidate_absence"] = candidate
    if successors is not None:
        result["stream_successors"] = successors
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", required=True)
    parser.add_argument("--realm", required=True)
    parser.add_argument("--candidate-event")
    parser.add_argument("--stream-after-position", type=int)
    parser.add_argument("--stream-end-position", type=int)
    args = parser.parse_args()
    sql = sql_for(args.realm, args.candidate_event, args.stream_after_position, args.stream_end_position)
    connection = connection_for(args.server)
    executable = shutil.which("psql")
    if not executable:
        raise ValueError("psql is required for real readonly sampling")
    env = connection_environment(connection)
    process = subprocess.run([executable, "--no-psqlrc", "--no-password", "--quiet", "--tuples-only", "--no-align",
                              "--set=ON_ERROR_STOP=1", "--set=VERBOSITY=sqlstate"], input=sql, text=True, env=env,
                             capture_output=True, timeout=40, check=False)
    if process.returncode != 0:
        code = re.search(r"(?:ERROR|FATAL):\s*([0-9A-Z]{5})\b", process.stderr)
        raise PostgresSamplingFailure(code.group(1) if code else "unavailable")
    result = summarize(process.stdout)
    if args.candidate_event and "candidate_absence" not in result:
        raise ValueError("candidate absence cut is missing")
    print(json.dumps(result, separators=(",", ":"), sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        # psql errors/rows/DSNs are private even on test failure.
        diagnostic = ("PostgresSamplingFailure SQLSTATE=" + error.sqlstate
                      if isinstance(error, PostgresSamplingFailure) else type(error).__name__)
        print("readonly business sampling failed (" + diagnostic + ")", file=sys.stderr)
        sys.exit(1)
