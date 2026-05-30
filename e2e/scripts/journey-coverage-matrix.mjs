#!/usr/bin/env node
// journey-coverage-matrix.mjs
//
// Reports e2e coverage by user journey. Explicit `@UJ-A` style tags in spec
// sources win; otherwise the script falls back to the journey-domain map in
// e2e/scenarios/user-journeys.md.

import { existsSync, mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join, relative, resolve, sep, posix } from 'node:path';
import { fileURLToPath } from 'node:url';

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
const E2E_ROOT = dirname(SCRIPT_DIR);
const REPO_ROOT = dirname(E2E_ROOT);
const TESTS_DIR = join(E2E_ROOT, 'tests');

const JOURNEYS = [
  {
    id: 'UJ-A',
    title: 'First login and multi-device recovery',
    patterns: ['identity/*', 'encryption/key-backup', 'encryption/mls-group'],
  },
  {
    id: 'UJ-B',
    title: 'Workspace creation, invites, and archive visibility',
    patterns: ['spaces/*', 'invites/*'],
  },
  {
    id: 'UJ-C',
    title: 'Daily messaging, edits, reactions, receipts, and mentions',
    patterns: ['messaging/*', 'discovery/notifications'],
  },
  {
    id: 'UJ-D',
    title: 'Encrypted realm lifecycle and cross-device decrypt',
    patterns: ['encryption/*'],
  },
  {
    id: 'UJ-E',
    title: 'Federation and cross-domain collaboration',
    patterns: ['federation/*', 'extensions/mimi-federation'],
  },
  {
    id: 'UJ-F',
    title: 'Kanban collaboration and concurrent work',
    patterns: ['kanban/*', 'workflows/*', 'messaging/discussion-upgrade'],
  },
  {
    id: 'UJ-G',
    title: 'Privacy rights, governance, appeal, and GDPR',
    patterns: ['governance/*', 'identity/consent-grant', 'spaces/moderation-ban'],
  },
  {
    id: 'UJ-H',
    title: 'Calls, push, and cross-platform sync',
    patterns: ['calls/*', 'discovery/notifications', 'sync/transport-negotiation'],
  },
  {
    id: 'UJ-I',
    title: 'Circle lifecycle and anti-enumeration (CXP-0007)',
    patterns: ['circle/*', 'directory/anti-enumeration'],
  },
  {
    id: 'UJ-J',
    title: 'Personal agent + sidecar (CXP-0008 / CXP-0009)',
    patterns: ['profile/*', 'spec-section-11/*', 'legacy-alias/*', 'did/format-normalization'],
  },
];

const RUST_SCENARIO_EVIDENCE = [
  {
    journey: 'UJ-D',
    key: 'encryption/key-backup-tri-state',
    verified: 6,
    promised: 6,
    note: 'SDK-pure key-backup tri-state scenarios under src/scenarios/key_backup.',
  },
  { journey: 'UJ-F', key: 'circle/flow-scope-visibility', verified: 1, promised: 1 },
  { journey: 'UJ-F', key: 'circle/effective-scope-mismatch', verified: 1, promised: 1 },
  { journey: 'UJ-I', key: 'circle/create-circle', verified: 1, promised: 1 },
  { journey: 'UJ-I', key: 'circle/member-strict-subset', verified: 1, promised: 1 },
  { journey: 'UJ-I', key: 'circle/flow-scope-visibility', verified: 1, promised: 1 },
  { journey: 'UJ-I', key: 'circle/effective-scope-mismatch', verified: 1, promised: 1 },
  { journey: 'UJ-I', key: 'circle/confidential-discussion-relation', verified: 1, promised: 1 },
  { journey: 'UJ-I', key: 'circle/cap-action-grant', verified: 1, promised: 1 },
  { journey: 'UJ-I', key: 'circle/error-code-paths', verified: 1, promised: 1 },
  { journey: 'UJ-I', key: 'directory/anti-enumeration-buckets', verified: 1, promised: 1 },
  { journey: 'UJ-I', key: 'directory/latency-jitter', verified: 1, promised: 1 },
  { journey: 'UJ-I', key: 'directory/takedown-audit-log', verified: 1, promised: 1 },
  { journey: 'UJ-I', key: 'directory/circle-not-indexed', verified: 1, promised: 1 },
  { journey: 'UJ-J', key: 'profile/personal-agent-provisioning.v1', verified: 1, promised: 1 },
  { journey: 'UJ-J', key: 'profile/agent-auth.v1', verified: 1, promised: 1 },
  { journey: 'UJ-J', key: 'profile/agent-delegation-policy.v1', verified: 1, promised: 1 },
  { journey: 'UJ-J', key: 'profile/agent-sidecar-thread.v1', verified: 1, promised: 1 },
  { journey: 'UJ-J', key: 'spec-section-11/provisioning-pairing-grant-order', verified: 1, promised: 1 },
  { journey: 'UJ-J', key: 'spec-section-11/pairing-expiry-auto-revoke', verified: 1, promised: 1 },
  { journey: 'UJ-J', key: 'spec-section-11/session-grant-replay-guard', verified: 1, promised: 1 },
  { journey: 'UJ-J', key: 'spec-section-11/controller-deactivate-cascade', verified: 1, promised: 1 },
  { journey: 'UJ-J', key: 'spec-section-11/act-on-behalf-attribution', verified: 1, promised: 1 },
  { journey: 'UJ-J', key: 'spec-section-11/sidecar-circle-idempotent-ensure', verified: 1, promised: 1 },
  { journey: 'UJ-J', key: 'spec-section-11/existence-privacy', verified: 1, promised: 1 },
  { journey: 'UJ-J', key: 'spec-section-11/eligibility-tristate-and-revocation', verified: 1, promised: 1 },
  { journey: 'UJ-J', key: 'spec-section-11/multi-agent-publish-attribution', verified: 1, promised: 1 },
  { journey: 'UJ-J', key: 'legacy-alias/renamed-fields', verified: 1, promised: 1 },
  { journey: 'UJ-J', key: 'legacy-alias/legacy-secret-storage-wire', verified: 1, promised: 1 },
  { journey: 'UJ-J', key: 'legacy-alias/ann-announce-id', verified: 1, promised: 1 },
  { journey: 'UJ-J', key: 'did/format-normalization', verified: 1, promised: 1 },
];

function parseArgs(argv) {
  const out = {
    output: join(REPO_ROOT, 'journey-coverage.md'),
    jsonOutput: null,
    json: false,
    help: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--output') out.output = resolve(argv[++i]);
    else if (arg.startsWith('--output=')) out.output = resolve(arg.slice('--output='.length));
    else if (arg === '--json-output') out.jsonOutput = resolve(argv[++i]);
    else if (arg.startsWith('--json-output=')) out.jsonOutput = resolve(arg.slice('--json-output='.length));
    else if (arg === '--json') out.json = true;
    else if (arg === '--help' || arg === '-h') out.help = true;
    else throw new Error(`unknown arg: ${arg}`);
  }
  return out;
}

const HELP = `journey-coverage-matrix.mjs

Usage:
  node e2e/scripts/journey-coverage-matrix.mjs [--output journey-coverage.md] [--json-output journey-coverage.json] [--json]
`;

function walk(root, predicate, acc = []) {
  if (!existsSync(root)) return acc;
  for (const name of readdirSync(root)) {
    const full = join(root, name);
    let st;
    try {
      st = statSync(full);
    } catch {
      continue;
    }
    if (st.isDirectory()) walk(full, predicate, acc);
    else if (st.isFile() && predicate(full, name)) acc.push(full);
  }
  return acc;
}

function rel(base, full) {
  return relative(base, full).split(sep).join(posix.sep);
}

function specKey(specPath) {
  return rel(TESTS_DIR, specPath).replace(/\.spec\.ts$/, '');
}

function matchesPattern(key, pattern) {
  if (pattern.endsWith('/*')) return key.startsWith(pattern.slice(0, -1));
  return key === pattern;
}

function fallbackJourneysFor(key) {
  return JOURNEYS
    .filter((journey) => journey.patterns.some((pattern) => matchesPattern(key, pattern)))
    .map((journey) => journey.id);
}

function explicitJourneyTags(source) {
  const tags = new Set();
  for (const match of source.matchAll(/@UJ-[A-J]\b/g)) tags.add(match[0].slice(1));
  return [...tags].sort();
}

function countSpec(source) {
  const lines = source.split(/\r?\n/);
  let live = 0;
  let fixme = 0;
  for (const line of lines) {
    const trimmed = line.replace(/^[\t ]+/, '');
    if (/^test\.fixme\s*\(/.test(trimmed)) {
      fixme++;
      continue;
    }
    if (/^test\.skip\s*\(/.test(trimmed)) continue;
    if (/^test\.only\s*\(/.test(trimmed) || /^test\s*\(/.test(trimmed)) live++;
  }
  return {
    verified: live,
    promised: live + fixme,
    blocking: fixme,
  };
}

function buildMatrix() {
  const rows = new Map();
  for (const journey of JOURNEYS) {
    rows.set(journey.id, {
      id: journey.id,
      title: journey.title,
      verified: 0,
      live_verified: 0,
      promised: 0,
      blocking: 0,
      explicit_tag_promised: 0,
      explicit_tag_live_verified: 0,
      domain_fallback_promised: 0,
      domain_fallback_live_verified: 0,
      rust_scenario_promised: 0,
      rust_scenario_live_verified: 0,
      specs: [],
    });
  }

  const specs = walk(TESTS_DIR, (_, name) => name.endsWith('.spec.ts')).sort();
  for (const path of specs) {
    const source = readFileSync(path, 'utf8');
    const key = specKey(path);
    const explicit = explicitJourneyTags(source);
    const journeyIds = explicit.length > 0 ? explicit : fallbackJourneysFor(key);
    const counts = countSpec(source);
    const mapping = explicit.length > 0 ? 'explicit-tag' : 'domain-fallback';
    for (const id of journeyIds) {
      const row = rows.get(id);
      if (!row) continue;
      addEvidence(row, key, mapping, counts);
    }
  }

  for (const evidence of RUST_SCENARIO_EVIDENCE) {
    const row = rows.get(evidence.journey);
    if (!row) continue;
    addEvidence(row, evidence.key, 'rust-scenario', {
      verified: evidence.verified,
      promised: evidence.promised,
      blocking: evidence.blocking ?? 0,
    });
  }

  const generatedAt = new Date().toISOString();
  const matrix = [...rows.values()].map((row) => ({
    ...row,
    verified_ratio: row.promised === 0 ? 1 : row.verified / row.promised,
    live_verified_ratio: row.promised === 0 ? 1 : row.live_verified / row.promised,
    explicit_tag_ratio:
      row.explicit_tag_promised === 0 ? 1 : row.explicit_tag_live_verified / row.explicit_tag_promised,
    domain_fallback_ratio:
      row.domain_fallback_promised === 0
        ? 1
        : row.domain_fallback_live_verified / row.domain_fallback_promised,
    rust_scenario_ratio:
      row.rust_scenario_promised === 0 ? 1 : row.rust_scenario_live_verified / row.rust_scenario_promised,
  }));
  return { generated_at: generatedAt, journeys: matrix };
}

function addEvidence(row, key, mapping, counts) {
  row.verified += counts.verified;
  row.live_verified += counts.verified;
  row.promised += counts.promised;
  row.blocking += counts.blocking;
  if (mapping === 'explicit-tag') {
    row.explicit_tag_promised += counts.promised;
    row.explicit_tag_live_verified += counts.verified;
  } else if (mapping === 'rust-scenario') {
    row.rust_scenario_promised += counts.promised;
    row.rust_scenario_live_verified += counts.verified;
  } else {
    row.domain_fallback_promised += counts.promised;
    row.domain_fallback_live_verified += counts.verified;
  }
  row.specs.push({
    key,
    mapping,
    domain_fallback_promised: mapping === 'domain-fallback' ? counts.promised : 0,
    domain_fallback_live_verified: mapping === 'domain-fallback' ? counts.verified : 0,
    explicit_tag_promised: mapping === 'explicit-tag' ? counts.promised : 0,
    explicit_tag_live_verified: mapping === 'explicit-tag' ? counts.verified : 0,
    rust_scenario_promised: mapping === 'rust-scenario' ? counts.promised : 0,
    rust_scenario_live_verified: mapping === 'rust-scenario' ? counts.verified : 0,
    ...counts,
  });
}

function pct(value) {
  return `${(value * 100).toFixed(1)}%`;
}

function renderMarkdown(report) {
  const lines = [];
  lines.push('# journey coverage');
  lines.push('');
  lines.push(`Generated: ${report.generated_at}`);
  lines.push('');
  lines.push('Domain-fallback rows come from journey-domain mapping, not explicit journey tags. Rust-scenario rows are executable SDK-pure coverage.');
  lines.push('');
  lines.push('| Journey | Live verified | Promised | Live coverage | Domain-fallback promised | Explicit-tag promised | Rust-scenario promised | Blocking fixme |');
  lines.push('|---|---:|---:|---:|---:|---:|---:|---:|');
  for (const row of report.journeys) {
    lines.push(`| ${row.id} - ${row.title} | ${row.live_verified} | ${row.promised} | ${pct(row.live_verified_ratio)} | ${row.domain_fallback_promised} | ${row.explicit_tag_promised} | ${row.rust_scenario_promised} | ${row.blocking} |`);
  }
  lines.push('');
  for (const row of report.journeys) {
    lines.push(`## ${row.id} - ${row.title}`);
    lines.push('');
    lines.push('| spec | mapping | live verified | promised | domain-fallback promised | rust-scenario promised | blocking |');
    lines.push('|---|---|---:|---:|---:|---:|---:|');
    for (const spec of row.specs.sort((a, b) => a.key.localeCompare(b.key))) {
      lines.push(`| ${spec.key} | ${spec.mapping} | ${spec.verified} | ${spec.promised} | ${spec.domain_fallback_promised} | ${spec.rust_scenario_promised} | ${spec.blocking} |`);
    }
    if (row.specs.length === 0) lines.push('| - | - | 0 | 0 | 0 | 0 | 0 |');
    lines.push('');
  }
  return lines.join('\n');
}

function main() {
  let args;
  try {
    args = parseArgs(process.argv.slice(2));
  } catch (err) {
    console.error(err.message);
    console.error(HELP);
    return 2;
  }
  if (args.help) {
    console.log(HELP);
    return 0;
  }

  const report = buildMatrix();
  const markdown = renderMarkdown(report);
  mkdirSync(dirname(args.output), { recursive: true });
  writeFileSync(args.output, markdown, 'utf8');
  if (args.jsonOutput) {
    mkdirSync(dirname(args.jsonOutput), { recursive: true });
    writeFileSync(args.jsonOutput, JSON.stringify(report, null, 2), 'utf8');
  }
  if (args.json) console.log(JSON.stringify(report, null, 2));
  else console.log(`journey coverage: ${args.output}`);
  return 0;
}

process.exit(main());
