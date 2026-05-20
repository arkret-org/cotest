#!/usr/bin/env node
// summarize-e2e-coverage.mjs
//
// Reports the current state of the cotest e2e test tree directly from the
// filesystem. Walks `cotest/e2e/scenarios/**/*.md` and
// `cotest/e2e/tests/**/*.spec.ts`, counts live tests / fixme / conditional
// skip statements per spec, and rolls them up per domain. Also detects spec
// files without a matching scenario doc (and vice versa) and warns when the
// catalog still references known-stale hardcoded numbers.
//
// USAGE:
//   node scripts/summarize-e2e-coverage.mjs              # markdown report on stdout
//   node scripts/summarize-e2e-coverage.mjs --json       # JSON report on stdout
//   node scripts/summarize-e2e-coverage.mjs --quiet      # totals line only
//   node scripts/summarize-e2e-coverage.mjs --domain X   # filter to one domain
//   node scripts/summarize-e2e-coverage.mjs --check      # exit non-zero on orphan/drift
//   node scripts/summarize-e2e-coverage.mjs --help
//
// Paths are resolved from this script's own location via `import.meta.url`,
// so the script can be run from any cwd. Node 18+; no external deps.

import { readFileSync, readdirSync, statSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join, relative, sep, posix } from 'node:path';

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
const E2E_ROOT = dirname(SCRIPT_DIR);
const SCENARIOS_DIR = join(E2E_ROOT, 'scenarios');
const TESTS_DIR = join(E2E_ROOT, 'tests');
const CATALOG_PATH = join(SCENARIOS_DIR, 'catalog.md');

// Top-level scenario files we don't treat as individual scenarios.
const SCENARIO_NON_DOC_FILES = new Set(['catalog.md', 'README.md']);

// Known-stale phrases the catalog used to contain. If any are still present,
// the catalog has drifted from the file tree.
const STALE_CATALOG_PHRASES = [
  '31 scenarios',
  '206 playwright',
  '206 tests',
  '~30 live',
  '~176 fixme',
];

// Tag substrings to collect from spec source.
const TAG_PATTERNS = [
  '@fully-implemented',
  '@flaky',
];
// `@needs-mock-*` is matched by regex separately.
const NEEDS_MOCK_RE = /@needs-mock-[\w-]+/g;

// ---------------------------------------------------------------------------
// Args
// ---------------------------------------------------------------------------

function parseArgs(argv) {
  const out = {
    json: false,
    quiet: false,
    check: false,
    help: false,
    domain: null,
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--json') out.json = true;
    else if (a === '--quiet') out.quiet = true;
    else if (a === '--check') out.check = true;
    else if (a === '--help' || a === '-h') out.help = true;
    else if (a === '--domain') out.domain = argv[++i] ?? null;
    else if (a.startsWith('--domain=')) out.domain = a.slice('--domain='.length);
    else {
      console.error(`unknown arg: ${a}`);
      out.help = true;
    }
  }
  return out;
}

const HELP = `summarize-e2e-coverage.mjs — report current cotest/e2e coverage

Usage:
  node scripts/summarize-e2e-coverage.mjs [--json] [--quiet] [--domain NAME] [--check]

Flags:
  --json          Emit JSON instead of markdown.
  --quiet         Only print the totals line (still respects --json).
  --domain NAME   Filter the per-domain and per-spec sections to one domain.
                  Totals, orphans, and drift are still computed across all
                  domains so CI signals are not lost.
  --check         Exit with code 1 if any orphans are detected or if the
                  catalog still contains known-stale phrases.
  --help, -h      Show this help.

Counts come straight from the file tree:
  - scenarios:  cotest/e2e/scenarios/<domain>/<name>.md
  - specs:      cotest/e2e/tests/<domain>/<name>.spec.ts
  - live:       lines matching /^\\s*test\\s*\\(/ or /^\\s*test\\.only\\s*\\(/
  - fixme:      lines matching /^\\s*test\\.fixme\\s*\\(/
  - skip:       occurrences of /test\\.skip\\s*\\(/ anywhere in the file
`;

// ---------------------------------------------------------------------------
// Filesystem helpers
// ---------------------------------------------------------------------------

function walk(root, predicate, acc = []) {
  if (!existsSync(root)) return acc;
  for (const name of readdirSync(root)) {
    const full = join(root, name);
    let st;
    try { st = statSync(full); } catch { continue; }
    if (st.isDirectory()) walk(full, predicate, acc);
    else if (st.isFile() && predicate(full, name)) acc.push(full);
  }
  return acc;
}

// Returns the path of a file relative to a base, using forward slashes.
function rel(base, full) {
  return relative(base, full).split(sep).join(posix.sep);
}

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

// A scenario doc is `scenarios/<domain>/<name>.md`. We exclude the top-level
// catalog.md and README.md.
function discoverScenarios() {
  const files = walk(SCENARIOS_DIR, (full, name) => {
    if (!name.endsWith('.md')) return false;
    const r = rel(SCENARIOS_DIR, full);
    if (!r.includes('/')) return !SCENARIO_NON_DOC_FILES.has(name);
    return true;
  });
  return files.map((full) => {
    const r = rel(SCENARIOS_DIR, full);
    const [domain, ...rest] = r.split('/');
    const name = rest.join('/').replace(/\.md$/, '');
    return { full, rel: r, domain, name, key: `${domain}/${name}` };
  }).sort((a, b) => a.key.localeCompare(b.key));
}

function discoverSpecs() {
  const files = walk(TESTS_DIR, (full, name) => name.endsWith('.spec.ts'));
  return files.map((full) => {
    const r = rel(TESTS_DIR, full);
    const [domain, ...rest] = r.split('/');
    const name = rest.join('/').replace(/\.spec\.ts$/, '');
    return { full, rel: r, domain, name, key: `${domain}/${name}` };
  }).sort((a, b) => a.key.localeCompare(b.key));
}

// ---------------------------------------------------------------------------
// Counting
// ---------------------------------------------------------------------------

// Per-spec stats. We split on \r?\n to be safe on Windows checkouts.
//
// live:   line begins with optional whitespace, then `test(` or `test.only(`.
//         We match `\btest\s*\(` and `\btest\.only\s*\(` separately, so the
//         opening paren can be wrapped or padded.
// fixme:  line begins with optional whitespace, then `test.fixme(`.
// skip:   we count *all* occurrences of `test.skip(` anywhere in the file,
//         since these typically appear inside a live test body as a guard.
//         (A skip statement is not itself a "test" so it doesn't subtract
//         from the live count.)
function analyzeSpec(specPath) {
  const src = readFileSync(specPath, 'utf8');
  const lines = src.split(/\r?\n/);
  let live = 0;
  let fixme = 0;
  for (const line of lines) {
    // Strip leading whitespace once for line-anchored matches.
    const trimmed = line.replace(/^[\t ]+/, '');
    if (/^test\.fixme\s*\(/.test(trimmed)) {
      fixme++;
      continue;
    }
    if (/^test\.skip\s*\(/.test(trimmed)) {
      // A top-of-line `test.skip(...)` would not be live. We still count it
      // below via the global skip scan, so don't double-count as live.
      continue;
    }
    if (/^test\.only\s*\(/.test(trimmed)) {
      live++;
      continue;
    }
    // Plain `test(` — match `\btest\s*\(` so we tolerate `test ("..."` and
    // similar formatting variants.
    if (/^test\s*\(/.test(trimmed)) {
      live++;
      continue;
    }
  }
  // Count *all* test.skip(...) occurrences anywhere in the file. We also use
  // a global regex on the original source so a skip nested in an arrow body
  // (which has indentation) is still counted.
  const skipMatches = src.match(/test\.skip\s*\(/g);
  const skip = skipMatches ? skipMatches.length : 0;

  // Collect tags.
  const tagSet = new Set();
  for (const tag of TAG_PATTERNS) {
    if (src.includes(tag)) tagSet.add(tag);
  }
  for (const m of src.matchAll(NEEDS_MOCK_RE)) tagSet.add(m[0]);
  const tags = [...tagSet].sort();

  return { live, fixme, skip, tags };
}

function statusFor(stats) {
  if (stats.live > 0 && stats.fixme === 0) return 'live-only';
  if (stats.live === 0 && stats.fixme > 0) return 'fixme-only';
  if (stats.live > 0 && stats.fixme > 0) return 'mixed';
  return 'empty';
}

// ---------------------------------------------------------------------------
// Reporting
// ---------------------------------------------------------------------------

function buildReport() {
  const scenarios = discoverScenarios();
  const specs = discoverSpecs();

  const scenarioKeys = new Set(scenarios.map((s) => s.key));
  const specKeys = new Set(specs.map((s) => s.key));

  const specsWithoutScenario = specs
    .filter((s) => !scenarioKeys.has(s.key))
    .map((s) => s.key);
  const scenariosWithoutSpec = scenarios
    .filter((s) => !specKeys.has(s.key))
    .map((s) => s.key);

  // Per-spec analysis.
  const specStats = specs.map((s) => {
    const a = analyzeSpec(s.full);
    return {
      domain: s.domain,
      name: s.name,
      key: s.key,
      rel: s.rel,
      hasScenario: scenarioKeys.has(s.key),
      live: a.live,
      fixme: a.fixme,
      skip: a.skip,
      tags: a.tags,
      status: statusFor(a),
    };
  });

  // Per-domain rollup. The domain universe is the union of domains seen in
  // either tree, so a scenario-only or spec-only domain still appears.
  const domains = new Map();
  function bucket(domain) {
    if (!domains.has(domain)) {
      domains.set(domain, {
        domain,
        scenarios: 0,
        specs: 0,
        live: 0,
        fixme: 0,
        skip: 0,
      });
    }
    return domains.get(domain);
  }
  for (const s of scenarios) bucket(s.domain).scenarios++;
  for (const s of specStats) {
    const b = bucket(s.domain);
    b.specs++;
    b.live += s.live;
    b.fixme += s.fixme;
    b.skip += s.skip;
  }
  const perDomain = [...domains.values()].sort((a, b) =>
    a.domain.localeCompare(b.domain),
  );

  // Totals.
  const totals = {
    scenarios: scenarios.length,
    specs: specs.length,
    live: specStats.reduce((a, s) => a + s.live, 0),
    fixme: specStats.reduce((a, s) => a + s.fixme, 0),
    skip: specStats.reduce((a, s) => a + s.skip, 0),
    domains: perDomain.length,
  };

  // Catalog drift.
  const catalogDrift = checkCatalogDrift();

  return {
    totals,
    perDomain,
    specStats,
    orphans: { specsWithoutScenario, scenariosWithoutSpec },
    catalogDrift,
  };
}

function checkCatalogDrift() {
  if (!existsSync(CATALOG_PATH)) {
    return { present: false, stalePhrases: [] };
  }
  const text = readFileSync(CATALOG_PATH, 'utf8').toLowerCase();
  const hits = [];
  for (const phrase of STALE_CATALOG_PHRASES) {
    if (text.includes(phrase.toLowerCase())) hits.push(phrase);
  }
  return { present: true, stalePhrases: hits };
}

// ---------------------------------------------------------------------------
// Formatting
// ---------------------------------------------------------------------------

function totalsLine(t) {
  return `${t.scenarios} scenarios / ${t.specs} specs / ${t.live} live / ${t.fixme} fixme / ${t.skip} skip (${t.domains} domains)`;
}

function pad(s, n) {
  s = String(s);
  if (s.length >= n) return s;
  return s + ' '.repeat(n - s.length);
}

function padNum(n, w) {
  const s = String(n);
  if (s.length >= w) return s;
  return ' '.repeat(w - s.length) + s;
}

function renderMarkdown(report, { quiet, domain }) {
  const { totals, perDomain, specStats, orphans, catalogDrift } = report;
  const lines = [];
  lines.push(`# cotest e2e coverage`);
  lines.push('');
  lines.push(`Totals: ${totalsLine(totals)}`);
  if (quiet) return lines.join('\n');

  lines.push('');
  lines.push('## Totals');
  lines.push('');
  lines.push('| metric | count |');
  lines.push('|---|---:|');
  lines.push(`| scenario docs | ${totals.scenarios} |`);
  lines.push(`| spec files | ${totals.specs} |`);
  lines.push(`| live tests | ${totals.live} |`);
  lines.push(`| test.fixme | ${totals.fixme} |`);
  lines.push(`| test.skip (conditional) | ${totals.skip} |`);
  lines.push(`| domains | ${totals.domains} |`);

  // Per-domain
  const domainRows = domain
    ? perDomain.filter((d) => d.domain === domain)
    : perDomain;
  lines.push('');
  lines.push('## Per-domain rollup');
  lines.push('');
  lines.push('| domain | scenarios | specs | live | fixme | skip |');
  lines.push('|---|---:|---:|---:|---:|---:|');
  for (const d of domainRows) {
    lines.push(
      `| ${d.domain} | ${d.scenarios} | ${d.specs} | ${d.live} | ${d.fixme} | ${d.skip} |`,
    );
  }
  if (domain && domainRows.length === 0) {
    lines.push(`| _(no domain named \`${domain}\`)_ |  |  |  |  |  |`);
  }

  // Per-spec
  const specRows = domain
    ? specStats.filter((s) => s.domain === domain)
    : specStats;
  lines.push('');
  lines.push('## Per-spec');
  lines.push('');
  lines.push('| spec | live | fixme | skip | status | scenario? | tags |');
  lines.push('|---|---:|---:|---:|---|---|---|');
  for (const s of specRows) {
    const tags = s.tags.length ? s.tags.join(' ') : '';
    lines.push(
      `| ${s.key} | ${s.live} | ${s.fixme} | ${s.skip} | ${s.status} | ${s.hasScenario ? 'yes' : 'NO'} | ${tags} |`,
    );
  }

  // Orphans
  lines.push('');
  lines.push('## Orphans');
  lines.push('');
  if (orphans.specsWithoutScenario.length === 0) {
    lines.push('- specs without scenario doc: none');
  } else {
    lines.push('- specs without scenario doc:');
    for (const k of orphans.specsWithoutScenario) lines.push(`  - ${k}`);
  }
  if (orphans.scenariosWithoutSpec.length === 0) {
    lines.push('- scenarios without spec file: none');
  } else {
    lines.push('- scenarios without spec file:');
    for (const k of orphans.scenariosWithoutSpec) lines.push(`  - ${k}`);
  }

  // Catalog drift
  lines.push('');
  lines.push('## Catalog drift');
  lines.push('');
  if (!catalogDrift.present) {
    lines.push('- `scenarios/catalog.md` not present — skipped.');
  } else if (catalogDrift.stalePhrases.length === 0) {
    lines.push('- no known-stale phrases detected in `scenarios/catalog.md`.');
  } else {
    lines.push('- `scenarios/catalog.md` still contains known-stale phrases:');
    for (const p of catalogDrift.stalePhrases) lines.push(`  - \`${p}\``);
  }

  return lines.join('\n');
}

function renderJson(report, { quiet, domain }) {
  if (quiet) {
    return JSON.stringify({ totals: report.totals }, null, 2);
  }
  const out = {
    totals: report.totals,
    perDomain: domain
      ? report.perDomain.filter((d) => d.domain === domain)
      : report.perDomain,
    specs: domain
      ? report.specStats.filter((s) => s.domain === domain)
      : report.specStats,
    orphans: report.orphans,
    catalogDrift: report.catalogDrift,
  };
  return JSON.stringify(out, null, 2);
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    console.log(HELP);
    return 0;
  }

  const report = buildReport();
  const text = args.json
    ? renderJson(report, args)
    : renderMarkdown(report, args);
  console.log(text);

  if (args.check) {
    const orphanCount =
      report.orphans.specsWithoutScenario.length +
      report.orphans.scenariosWithoutSpec.length;
    const drift = report.catalogDrift.stalePhrases.length;
    if (orphanCount > 0 || drift > 0) return 1;
  }
  return 0;
}

process.exit(main());
