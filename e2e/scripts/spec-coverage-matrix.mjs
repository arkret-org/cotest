#!/usr/bin/env node
// spec-coverage-matrix.mjs
//
// Produces a *spec-first* coverage matrix: walks every contrix-spec spec file
// under `contrix-spec/spec/v1/zh/` and maps each one to:
//
//   - the cotest scenario doc(s) that cite it     (many-to-many)
//   - the cotest spec.ts file(s) that cite it     (many-to-many)
//   - an aggregate status                         (live / fixme / missing / meta)
//
// The point is to surface NEW spec files as "missing e2e" the moment they
// land in contrix-spec, without anyone having to update a catalog by hand.
//
// USAGE:
//   node scripts/spec-coverage-matrix.mjs              # markdown report on stdout
//   node scripts/spec-coverage-matrix.mjs --json       # JSON report on stdout
//   node scripts/spec-coverage-matrix.mjs --quiet      # totals + missing count only
//   node scripts/spec-coverage-matrix.mjs --domain X   # filter to one spec domain
//   node scripts/spec-coverage-matrix.mjs --check      # exit non-zero if any spec is missing
//   node scripts/spec-coverage-matrix.mjs --help
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
const COTEST_ROOT = dirname(E2E_ROOT);
const REPO_ROOT = dirname(COTEST_ROOT);
const SPEC_ROOT = join(REPO_ROOT, 'contrix-spec', 'spec', 'v1', 'zh');
const SCENARIOS_DIR = join(E2E_ROOT, 'scenarios');
const TESTS_DIR = join(E2E_ROOT, 'tests');

// Spec files that are not themselves testable units. We mark them `meta`
// instead of `missing` so they don't pollute the "newly missing" list.
// Pure filename matches (case-insensitive on the basename).
const META_BASENAMES = new Set(['README.md', 'overview.md', 'index.md', 'spec-map.md']);

// Title-prefix heuristics for meta docs (catalog / index / overview pages).
// Matched against the title found in the YAML frontmatter or the first
// `# ` heading in the body.
const META_TITLE_PATTERNS = [
  /概述/,
  /目录/,
  /索引/,
  /\bOverview\b/i,
  /\bIndex\b/i,
  /\bContents?\b/i,
];

// Top-level scenario files we don't treat as individual scenarios.
const SCENARIO_NON_DOC_FILES = new Set(['catalog.md', 'README.md']);

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

const HELP = `spec-coverage-matrix.mjs — map every contrix-spec spec to its cotest coverage

Usage:
  node scripts/spec-coverage-matrix.mjs [--json] [--quiet] [--domain NAME] [--check]

Flags:
  --json          Emit JSON instead of markdown.
  --quiet         Only print totals + missing count (still respects --json).
  --domain NAME   Filter per-spec table to one top-level spec dir
                  (e.g. identity, models, sync). Totals are still global.
  --check         Exit with code 1 if any spec is status=missing.
                  Spec files classified as meta do NOT trigger --check.
  --help, -h      Show this help.

Status derivation:
  - For each spec file we collect every cotest spec.ts that mentions it
    (by full path "identity/account-lifecycle.md" or bare "account-lifecycle.md").
  - status = live    if any matched spec.ts has at least one live test
                     (line-anchored /^test\\s*\\(/ or /^test\\.only\\s*\\(/).
           = fixme   else if any matched spec.ts has at least one test.fixme.
           = missing if no spec.ts matches OR all matches have zero tests.
           = meta    if the spec file is itself a README / overview / index /
                     spec-map page (heuristic on filename and document title).

Paths:
  - spec files:  contrix-spec/spec/v1/zh/**/*.md
  - scenarios:   cotest/e2e/scenarios/**/*.md
  - tests:       cotest/e2e/tests/**/*.spec.ts
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

function rel(base, full) {
  return relative(base, full).split(sep).join(posix.sep);
}

// ---------------------------------------------------------------------------
// Spec discovery
// ---------------------------------------------------------------------------

// A spec entry is `contrix-spec/spec/v1/zh/<...>/<name>.md`. We index by the
// relative posix path with `.md` stripped, e.g. `identity/account-lifecycle`.
function discoverSpecs() {
  const files = walk(SPEC_ROOT, (full, name) => name.endsWith('.md'));
  return files.map((full) => {
    const r = rel(SPEC_ROOT, full);
    const key = r.replace(/\.md$/, '');
    const segs = r.split('/');
    const basename = segs[segs.length - 1];
    const domain = segs.length > 1 ? segs[0] : '(root)';
    return {
      full,
      rel: r,            // e.g. identity/account-lifecycle.md
      relMd: r,          // same; convenience
      key,               // e.g. identity/account-lifecycle
      basename,          // account-lifecycle.md
      basenameKey: basename.replace(/\.md$/, ''),
      domain,
      meta: classifyMeta(full, basename),
    };
  }).sort((a, b) => a.key.localeCompare(b.key));
}

function classifyMeta(full, basename) {
  if (META_BASENAMES.has(basename)) return true;
  // Read first ~30 lines for frontmatter title or first heading.
  let head = '';
  try {
    const src = readFileSync(full, 'utf8');
    head = src.split(/\r?\n/).slice(0, 30).join('\n');
  } catch {
    return false;
  }
  // YAML frontmatter title.
  const fm = head.match(/^---\s*\n([\s\S]*?)\n---/);
  let title = '';
  if (fm) {
    const m = fm[1].match(/^title:\s*(.+)$/m);
    if (m) title = m[1].trim().replace(/^["']|["']$/g, '');
  }
  // First markdown heading.
  if (!title) {
    const m = head.match(/^#\s+(.+)$/m);
    if (m) title = m[1].trim();
  }
  if (!title) return false;
  return META_TITLE_PATTERNS.some((re) => re.test(title));
}

// ---------------------------------------------------------------------------
// Scenario / spec.ts discovery
// ---------------------------------------------------------------------------

function discoverScenarios() {
  const files = walk(SCENARIOS_DIR, (full, name) => {
    if (!name.endsWith('.md')) return false;
    const r = rel(SCENARIOS_DIR, full);
    if (!r.includes('/')) return !SCENARIO_NON_DOC_FILES.has(name);
    return true;
  });
  return files.map((full) => ({
    full,
    rel: rel(SCENARIOS_DIR, full),
    text: readFileSync(full, 'utf8'),
  }));
}

function discoverTestFiles() {
  const files = walk(TESTS_DIR, (_full, name) => name.endsWith('.spec.ts'));
  return files.map((full) => {
    const src = readFileSync(full, 'utf8');
    return {
      full,
      rel: rel(TESTS_DIR, full),
      text: src,
      stats: analyzeSpec(src),
    };
  });
}

// ---------------------------------------------------------------------------
// Spec.ts counting (mirrors summarize-e2e-coverage.mjs)
// ---------------------------------------------------------------------------

function analyzeSpec(src) {
  const lines = src.split(/\r?\n/);
  let live = 0;
  let fixme = 0;
  for (const line of lines) {
    const trimmed = line.replace(/^[\t ]+/, '');
    if (/^test\.fixme\s*\(/.test(trimmed)) { fixme++; continue; }
    if (/^test\.skip\s*\(/.test(trimmed)) continue;
    if (/^test\.only\s*\(/.test(trimmed)) { live++; continue; }
    if (/^test\s*\(/.test(trimmed)) { live++; continue; }
  }
  const skipMatches = src.match(/test\.skip\s*\(/g);
  const skip = skipMatches ? skipMatches.length : 0;
  return { live, fixme, skip };
}

// ---------------------------------------------------------------------------
// Citation matching
// ---------------------------------------------------------------------------

// For each spec we look for two strings in the body of every scenario doc and
// every spec.ts:
//   - the full posix relative path `identity/account-lifecycle.md`
//   - the bare basename `account-lifecycle.md`
//
// The bare-basename match can be ambiguous if two specs in different domains
// share a name (none today, but defensive). To stay safe we only credit a
// bare-basename hit if the basename is unique across the whole spec tree.
function buildSpecMatcher(specs) {
  const basenameCount = new Map();
  for (const s of specs) {
    basenameCount.set(s.basename, (basenameCount.get(s.basename) ?? 0) + 1);
  }
  return function findMentions(specEntry, text) {
    if (text.includes(specEntry.rel)) return true;
    if (basenameCount.get(specEntry.basename) === 1 && text.includes(specEntry.basename)) {
      return true;
    }
    return false;
  };
}

// ---------------------------------------------------------------------------
// Report build
// ---------------------------------------------------------------------------

function buildReport() {
  const specs = discoverSpecs();
  const scenarios = discoverScenarios();
  const tests = discoverTestFiles();
  const mentions = buildSpecMatcher(specs);

  const rows = specs.map((s) => {
    const scenarioHits = scenarios.filter((sc) => mentions(s, sc.text)).map((sc) => sc.rel);
    const testHits = tests.filter((t) => mentions(s, t.text));

    let aggLive = 0;
    let aggFixme = 0;
    for (const t of testHits) {
      aggLive += t.stats.live;
      aggFixme += t.stats.fixme;
    }

    let status;
    if (s.meta) status = 'meta';
    else if (aggLive > 0) status = 'live';
    else if (aggFixme > 0) status = 'fixme';
    else status = 'missing';

    return {
      key: s.key,
      rel: s.rel,
      domain: s.domain,
      basename: s.basename,
      meta: s.meta,
      scenarios: scenarioHits.sort(),
      tests: testHits.map((t) => t.rel).sort(),
      live: aggLive,
      fixme: aggFixme,
      status,
    };
  });

  // Totals.
  const totals = {
    specs: rows.length,
    withScenario: rows.filter((r) => r.scenarios.length > 0).length,
    withSpecTs: rows.filter((r) => r.tests.length > 0).length,
    live: rows.filter((r) => r.status === 'live').length,
    fixme: rows.filter((r) => r.status === 'fixme').length,
    missing: rows.filter((r) => r.status === 'missing').length,
    meta: rows.filter((r) => r.status === 'meta').length,
  };

  // Per-domain rollup.
  const domains = new Map();
  function bucket(d) {
    if (!domains.has(d)) {
      domains.set(d, {
        domain: d,
        specs: 0,
        live: 0,
        fixme: 0,
        missing: 0,
        meta: 0,
        withScenario: 0,
        withSpecTs: 0,
      });
    }
    return domains.get(d);
  }
  for (const r of rows) {
    const b = bucket(r.domain);
    b.specs++;
    b[r.status]++;
    if (r.scenarios.length > 0) b.withScenario++;
    if (r.tests.length > 0) b.withSpecTs++;
  }
  const perDomain = [...domains.values()].sort((a, b) => a.domain.localeCompare(b.domain));

  // Newly missing = no scenario AND no spec.ts AND not meta.
  const newlyMissing = rows
    .filter((r) => !r.meta && r.scenarios.length === 0 && r.tests.length === 0)
    .map((r) => r.key)
    .sort();

  return { totals, perDomain, rows, newlyMissing };
}

// ---------------------------------------------------------------------------
// Formatting
// ---------------------------------------------------------------------------

// Sort order for the per-spec table: missing first, then fixme, then live,
// then meta. Within a bucket, sort by spec key.
const STATUS_ORDER = { missing: 0, fixme: 1, live: 2, meta: 3 };
function sortRows(rows) {
  return [...rows].sort((a, b) => {
    const sa = STATUS_ORDER[a.status] ?? 99;
    const sb = STATUS_ORDER[b.status] ?? 99;
    if (sa !== sb) return sa - sb;
    return a.key.localeCompare(b.key);
  });
}

function totalsLine(t) {
  return `${t.specs} specs / ${t.live} live / ${t.fixme} fixme / ${t.missing} missing / ${t.meta} meta (with-scenario=${t.withScenario}, with-spec.ts=${t.withSpecTs})`;
}

function renderMarkdown(report, { quiet, domain }) {
  const { totals, perDomain, rows, newlyMissing } = report;
  const lines = [];
  lines.push(`# contrix-spec → cotest e2e coverage matrix`);
  lines.push('');
  lines.push(`Totals: ${totalsLine(totals)}`);
  if (quiet) {
    lines.push('');
    lines.push(`Newly missing (no scenario AND no spec.ts): ${newlyMissing.length}`);
    return lines.join('\n');
  }

  lines.push('');
  lines.push('## Totals');
  lines.push('');
  lines.push('| metric | count |');
  lines.push('|---|---:|');
  lines.push(`| spec files | ${totals.specs} |`);
  lines.push(`| with scenario doc | ${totals.withScenario} |`);
  lines.push(`| with spec.ts | ${totals.withSpecTs} |`);
  lines.push(`| status=live | ${totals.live} |`);
  lines.push(`| status=fixme | ${totals.fixme} |`);
  lines.push(`| status=missing | ${totals.missing} |`);
  lines.push(`| status=meta | ${totals.meta} |`);

  // Per-domain
  const domainRows = domain
    ? perDomain.filter((d) => d.domain === domain)
    : perDomain;
  lines.push('');
  lines.push('## Per-domain rollup');
  lines.push('');
  lines.push('| domain | specs | live | fixme | missing | meta | w/ scenario | w/ spec.ts |');
  lines.push('|---|---:|---:|---:|---:|---:|---:|---:|');
  for (const d of domainRows) {
    lines.push(
      `| ${d.domain} | ${d.specs} | ${d.live} | ${d.fixme} | ${d.missing} | ${d.meta} | ${d.withScenario} | ${d.withSpecTs} |`,
    );
  }
  if (domain && domainRows.length === 0) {
    lines.push(`| _(no domain named \`${domain}\`)_ |  |  |  |  |  |  |  |`);
  }

  // Per-spec table
  const specRows = domain ? rows.filter((r) => r.domain === domain) : rows;
  lines.push('');
  lines.push('## Per-spec');
  lines.push('');
  lines.push('| status | spec | scenarios | spec.ts | live | fixme |');
  lines.push('|---|---|---|---|---:|---:|');
  for (const r of sortRows(specRows)) {
    const sc = r.scenarios.length ? r.scenarios.map((p) => `\`${p}\``).join('<br/>') : '_(none)_';
    const ts = r.tests.length ? r.tests.map((p) => `\`${p}\``).join('<br/>') : '_(none)_';
    lines.push(`| ${r.status} | \`${r.rel}\` | ${sc} | ${ts} | ${r.live} | ${r.fixme} |`);
  }

  // Newly missing
  lines.push('');
  lines.push('## Newly missing');
  lines.push('');
  lines.push('Spec files with NO scenario doc AND NO spec.ts. These are the highest-priority gaps —');
  lines.push('every new contrix-spec file will appear here until cotest catches up.');
  lines.push('');
  if (newlyMissing.length === 0) {
    lines.push('- _(none — every non-meta spec has at least a scenario or a spec.ts)_');
  } else {
    for (const k of newlyMissing) lines.push(`- \`${k}\``);
  }

  return lines.join('\n');
}

function renderJson(report, { quiet, domain }) {
  if (quiet) {
    return JSON.stringify({
      totals: report.totals,
      newlyMissingCount: report.newlyMissing.length,
    }, null, 2);
  }
  const out = {
    totals: report.totals,
    perDomain: domain
      ? report.perDomain.filter((d) => d.domain === domain)
      : report.perDomain,
    specs: domain
      ? sortRows(report.rows.filter((r) => r.domain === domain))
      : sortRows(report.rows),
    newlyMissing: report.newlyMissing,
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

  if (!existsSync(SPEC_ROOT)) {
    console.error(`spec root not found: ${SPEC_ROOT}`);
    console.error(`(expected layout: <repo>/contrix-spec/spec/v1/zh/)`);
    return 2;
  }

  const report = buildReport();
  const text = args.json
    ? renderJson(report, args)
    : renderMarkdown(report, args);
  console.log(text);

  if (args.check && report.totals.missing > 0) return 1;
  return 0;
}

process.exit(main());
