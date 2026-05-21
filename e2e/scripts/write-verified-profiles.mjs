#!/usr/bin/env node
// write-verified-profiles.mjs
//
// G4.T3 — link cotest profile suite results back to soland/coauth's
// `/server/describe.verified_profiles` slot.
//
// Reads Playwright's `junit.xml` from a joint-e2e artifacts directory, walks
// the test entries, and — for the small allow-list of strict profile-contract
// suites in PROFILE_SUITE_MAP — emits `<artifacts_dir>/verified-profiles.json`
// describing which canonical Contrix v1 profile IDs the run actually
// verified end-to-end. The Rust side of the pipeline (soland + coauth) loads
// this file at startup behind a per-service env var
// (SOLAND_VERIFIED_PROFILES_ARTIFACT / COAUTH_VERIFIED_PROFILES_ARTIFACT) and
// populates the wire `verified_profiles[]` from it; absent / unset env vars
// keep the dev-mode `verified_profiles=[]` invariant in service-surface.md
// §3.0.
//
// USAGE
//   node cotest/e2e/scripts/write-verified-profiles.mjs <artifacts_dir>
//   node cotest/e2e/scripts/write-verified-profiles.mjs --help
//
// EXIT
//   0  artifact written (or no profile suites passed → empty `verified[]`)
//   1  bad CLI arguments
//   2  junit.xml missing or unparseable
//
// SCOPE
//   The PROFILE_SUITE_MAP below is intentionally narrow: only suites that run
//   a STRICT spec contract against a real service surface promote to a
//   verified profile entry. UI smoke tests and scenario walkthroughs MUST
//   stay out of this list — `verified_profiles` is an auditable claim, not
//   "we ran a test against the thing once".
//
// Node 18+; ESM; no external dependencies.

import { readFileSync, writeFileSync, existsSync, statSync } from 'node:fs';
import { basename, resolve, join } from 'node:path';
import { createHash } from 'node:crypto';

// ---------------------------------------------------------------------------
// Profile-suite allow-list.
//
// Key: posix-style spec path relative to repo root (as Playwright emits it
// in junit.xml's `<testsuite name="...">` attribute).
//
// Value: { profile_id, service_role } per profile-id this suite verifies.
//   - `service_role` MUST match the role string the target service advertises
//     in its `service_roles[]` describe field. Today:
//       - soland → "principal_server"
//       - coauth → "auth_server"
//     The Rust loaders use this to filter their respective subset.
//   - Empty array → suite is recognised but does not promote any profile
//     (e.g. registry-drift.spec.ts is a producer-side artifact check that
//     does not bind a service surface).
// ---------------------------------------------------------------------------
const PROFILE_SUITE_MAP = {
  'cotest/e2e/tests/sync/service-surface-contract.spec.ts': [
    {
      profile_id: 'cx.profile.auth_server.v1',
      service_role: 'auth_server',
    },
  ],
  'cotest/e2e/tests/conformance/profile-gates.spec.ts': [
    {
      profile_id: 'cx.profile.principal_server.v1',
      service_role: 'principal_server',
    },
    {
      profile_id: 'cx.profile.principal_server_events_api.v1',
      service_role: 'principal_server',
    },
    {
      profile_id: 'cx.profile.core_event_store.v1',
      service_role: 'principal_server',
    },
  ],
  // Producer-side catalog drift check — does not bind a service surface.
  'cotest/e2e/tests/conformance/registry-drift.spec.ts': [],
  // Grow this map as additional strict profile contract suites land. Each
  // entry MUST be backed by a spec section + canonical profile id in
  // contrix-spec/spec/v1/artifacts/profiles/conformance-profiles.json.
};

function printUsage() {
  process.stdout.write(
    [
      'write-verified-profiles.mjs — emit verified-profiles.json from a Playwright junit.xml',
      '',
      'USAGE:',
      '  node cotest/e2e/scripts/write-verified-profiles.mjs <artifacts_dir>',
      '  node cotest/e2e/scripts/write-verified-profiles.mjs --help',
      '',
      'ARGS:',
      '  <artifacts_dir>   Directory holding a Playwright junit.xml (typically',
      '                    cotest/artifacts/runs/<ts>/joint-e2e/). The output',
      '                    verified-profiles.json is written into the same dir.',
      '',
      'OUTPUT SCHEMA (verified-profiles.json):',
      '  {',
      '    "version": "1",',
      '    "generated_at": "<RFC3339>",',
      '    "run_id": "<basename(artifacts_dir)>",',
      '    "verified": [',
      '      {',
      '        "profile_id": "cx.profile.principal_server.v1",',
      '        "service_role": "principal_server",',
      '        "test_count": 3,',
      '        "spec_file": "cotest/e2e/tests/conformance/profile-gates.spec.ts",',
      '        "artifact_hash": "sha256:<hex>"',
      '      }',
      '    ]',
      '  }',
      '',
      'PROMOTION RULES:',
      '  - Only suites in the embedded PROFILE_SUITE_MAP can promote a profile.',
      '  - A suite promotes only if it has >=1 passing test AND zero failures',
      '    in that suite for this run (any failed/skipped/errored test in the',
      '    suite blocks promotion of every profile id it claims).',
      '  - artifact_hash = sha256(canonical JSON of {run_id, profile_id, test_count}).',
      '',
      'ENV CONSUMERS:',
      '  - soland reads SOLAND_VERIFIED_PROFILES_ARTIFACT=<path-to-this-json>',
      '    and filters to entries with service_role == "principal_server".',
      '  - coauth reads COAUTH_VERIFIED_PROFILES_ARTIFACT=<path-to-this-json>',
      '    and filters to entries with service_role == "auth_server".',
      '',
    ].join('\n'),
  );
}

function die(code, msg) {
  process.stderr.write(`write-verified-profiles: ${msg}\n`);
  process.exit(code);
}

// ---------------------------------------------------------------------------
// Tiny JUnit XML parser.
//
// Playwright emits a `<testsuites>` root with nested `<testsuite name="<spec
// path>">` children. Each `<testsuite>` contains `<testcase>` elements that
// MAY carry one of `<failure>`, `<error>`, or `<skipped>` as a child to mark
// non-pass. A testcase without any of those is a pass.
//
// The parser is regex-based on purpose — pulling in a real XML lib for one
// well-shaped file would violate the "no deps" constraint of this script.
// Robustness assumption: Playwright's reporter is stable; we only need
// element names + the `name` attribute and a few child-tag presence checks.
// ---------------------------------------------------------------------------
function parseJunitXml(xml) {
  const suites = [];
  const suiteRe =
    /<testsuite\b[^>]*\bname="([^"]+)"[^>]*>([\s\S]*?)<\/testsuite>/g;
  let suiteMatch;
  while ((suiteMatch = suiteRe.exec(xml)) !== null) {
    const name = decodeXmlAttr(suiteMatch[1]);
    const inner = suiteMatch[2];
    const cases = [];
    // Match either `<testcase ... />` (self-closing, no children → always
    // passed) OR `<testcase ...>...</testcase>` (with children that may
    // carry <failure>/<error>/<skipped>). `[^/>]` keeps `[^>]` semantics
    // but ALSO refuses to swallow the leading `/` of `/>`, so the two
    // alternatives are disjoint.
    const caseRe =
      /<testcase\b([^/>]*)(\/>|>([\s\S]*?)<\/testcase>)/g;
    let caseMatch;
    while ((caseMatch = caseRe.exec(inner)) !== null) {
      const attrs = caseMatch[1] ?? '';
      const body = caseMatch[3] ?? '';
      const status = classifyTestcase(body);
      const tcNameMatch = /\bname="([^"]*)"/.exec(attrs);
      cases.push({
        name: tcNameMatch ? decodeXmlAttr(tcNameMatch[1]) : '',
        status,
      });
    }
    suites.push({ name, cases });
  }
  return suites;
}

function classifyTestcase(body) {
  if (/<failure\b/.test(body)) return 'failed';
  if (/<error\b/.test(body)) return 'errored';
  if (/<skipped\b/.test(body)) return 'skipped';
  return 'passed';
}

function decodeXmlAttr(s) {
  return s
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&amp;/g, '&');
}

// ---------------------------------------------------------------------------
// Canonical JSON for hashing — keys sorted lexicographically; no whitespace.
// Matches the convention used elsewhere in contrix-spec for canonical bytes.
// ---------------------------------------------------------------------------
function canonicalJson(value) {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return '[' + value.map((v) => canonicalJson(v)).join(',') + ']';
  }
  const keys = Object.keys(value).sort();
  return (
    '{' +
    keys
      .map((k) => JSON.stringify(k) + ':' + canonicalJson(value[k]))
      .join(',') +
    '}'
  );
}

function sha256Hex(s) {
  return createHash('sha256').update(s).digest('hex');
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------
function main(argv) {
  if (argv.includes('--help') || argv.includes('-h')) {
    printUsage();
    process.exit(0);
  }
  if (argv.length < 1) {
    printUsage();
    die(1, 'missing <artifacts_dir> argument');
  }
  const artifactsDir = resolve(argv[0]);
  if (!existsSync(artifactsDir) || !statSync(artifactsDir).isDirectory()) {
    die(1, `artifacts_dir does not exist or is not a directory: ${artifactsDir}`);
  }
  const junitPath = join(artifactsDir, 'junit.xml');
  if (!existsSync(junitPath)) {
    die(2, `junit.xml not found in ${artifactsDir}`);
  }

  let xml;
  try {
    xml = readFileSync(junitPath, 'utf8');
  } catch (e) {
    die(2, `failed to read ${junitPath}: ${e.message}`);
  }

  let suites;
  try {
    suites = parseJunitXml(xml);
  } catch (e) {
    die(2, `failed to parse junit.xml: ${e.message}`);
  }

  // Aggregate suite-level pass/fail counts keyed by spec_file (suite name).
  const perSuite = new Map();
  for (const suite of suites) {
    const key = suite.name;
    if (!perSuite.has(key)) {
      perSuite.set(key, { passed: 0, failed: 0, skipped: 0, errored: 0 });
    }
    const agg = perSuite.get(key);
    for (const tc of suite.cases) {
      agg[tc.status] = (agg[tc.status] ?? 0) + 1;
    }
  }

  const runId = basename(artifactsDir);
  const verified = [];
  for (const [specFile, profiles] of Object.entries(PROFILE_SUITE_MAP)) {
    if (profiles.length === 0) continue;
    const agg = perSuite.get(specFile);
    if (!agg) {
      // Suite was not run in this artifacts set (e.g. profile suite skipped
      // by `joint-smoke` filter). Don't promote.
      continue;
    }
    // Strict promotion: any non-pass test in this suite blocks all of its
    // claimed profile ids. Skipped (fixme) tests do NOT block — the test
    // file may carry pinned future-work specs.
    if (agg.failed > 0 || agg.errored > 0 || agg.passed === 0) {
      continue;
    }
    for (const { profile_id, service_role } of profiles) {
      const hashInput = canonicalJson({
        profile_id,
        run_id: runId,
        test_count: agg.passed,
      });
      verified.push({
        profile_id,
        service_role,
        test_count: agg.passed,
        spec_file: specFile,
        artifact_hash: `sha256:${sha256Hex(hashInput)}`,
      });
    }
  }

  const payload = {
    version: '1',
    generated_at: new Date().toISOString(),
    run_id: runId,
    verified,
  };

  const outPath = join(artifactsDir, 'verified-profiles.json');
  writeFileSync(outPath, JSON.stringify(payload, null, 2) + '\n');
  process.stdout.write(
    `wrote ${outPath} (${verified.length} verified profile entr${
      verified.length === 1 ? 'y' : 'ies'
    })\n`,
  );
}

main(process.argv.slice(2));
