#!/usr/bin/env node
// fixme-debt-report.mjs
//
// Builds a debt ledger for Playwright `test.fixme(...)` entries plus Rust
// scenario `unimplemented!()` scaffolds. Each Playwright fixme is expected to
// carry three magic comments near the fixme body:
//   @blocking-on:
//   @user-promise:
//   @expected-live-by:
//
// Strict mode also verifies that @blocking-on points at an owner gap, the
// @user-promise scenario doc exists, and the fixme has an executable body (or
// an explicit @blocked-reason comment).

import { existsSync, mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join, relative, resolve, sep, posix } from 'node:path';
import { fileURLToPath } from 'node:url';

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
const E2E_ROOT = dirname(SCRIPT_DIR);
const REPO_ROOT = dirname(E2E_ROOT);
const TESTS_DIR = join(E2E_ROOT, 'tests');
const RUST_SCENARIOS_DIR = join(REPO_ROOT, 'src', 'scenarios');
const RUST_SCAFFOLD_EXPECTED_LIVE_BY = '2026Q3';

function parseArgs(argv) {
  const out = {
    output: join(REPO_ROOT, 'fixme-debt.md'),
    strict: false,
    json: false,
    help: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--output') out.output = resolve(argv[++i]);
    else if (arg.startsWith('--output=')) out.output = resolve(arg.slice('--output='.length));
    else if (arg === '--strict' || arg === '--ci') out.strict = true;
    else if (arg === '--json') out.json = true;
    else if (arg === '--help' || arg === '-h') out.help = true;
    else throw new Error(`unknown arg: ${arg}`);
  }
  return out;
}

const HELP = `fixme-debt-report.mjs

Usage:
  node e2e/scripts/fixme-debt-report.mjs [--output fixme-debt.md] [--strict] [--json]

Options:
  --output PATH   Markdown report path. Defaults to ./fixme-debt.md.
  --strict        Exit non-zero on missing metadata or expired expected-live-by.
  --json          Print JSON summary to stdout after writing the report.
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

function findNextFixmeOrEof(lines, startLineIndex) {
  for (let i = startLineIndex + 1; i < lines.length; i++) {
    if (/^\s*test\.(fixme|only|skip)\s*\(/.test(lines[i]) || /^\s*test\s*\(/.test(lines[i])) {
      return i;
    }
  }
  return lines.length;
}

function extractTitle(lines, lineIndex) {
  const windowText = lines.slice(lineIndex, Math.min(lines.length, lineIndex + 12)).join('\n');
  const afterOpen = windowText.replace(/^[\s\S]*?test\.fixme\s*\(\s*/, '');
  const withoutLeadingComments = afterOpen.replace(/^(?:\s*\/\/[^\n]*(?:\n|$))+\s*/, '');
  const match = withoutLeadingComments.match(/^(["'`])((?:\\.|(?!\1)[\s\S])*?)\1/);
  if (!match) return '(unparsed title)';
  return match[2].replace(/\s+/g, ' ').trim();
}

function firstMagic(block, name) {
  const re = new RegExp(`@${name}:\\s*(.+)`);
  for (const line of block.split(/\r?\n/)) {
    const match = line.match(re);
    if (match) return match[1].trim();
  }
  return null;
}

const OWNER_GAP_RE =
  /^(?:soland|yougen|coauth|cotest|mock-[a-z0-9-]+|soland\/yougen|soland\/coauth|coauth\/yougen)#[A-Za-z0-9._-]+$|^GAP-P\d+-\d+$/;

function validateBlockingOn(value) {
  if (!value) return null;
  return OWNER_GAP_RE.test(value) ? null : 'blocking-on-not-owner-gap';
}

function validateUserPromise(value) {
  if (!value) return null;
  if (value.startsWith('e2e/scenarios/') && value.endsWith('.md')) {
    return existsSync(join(REPO_ROOT, value)) ? null : 'user-promise-missing-file';
  }
  if (value.startsWith('src/scenarios/') && value.endsWith('.rs')) {
    return existsSync(join(REPO_ROOT, value)) ? null : 'user-promise-missing-file';
  }
  if (!value.startsWith('e2e/scenarios/') || !value.endsWith('.md')) {
    return 'user-promise-not-scenario-ref';
  }
  return null;
}

function validateFixmeBody(block) {
  if (/@blocked-reason:\s*\S+/.test(block)) return null;
  if (/,\s*(?:async\s*)?(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*=>\s*{/.test(block)) {
    return null;
  }
  if (/,\s*async\s+function\b/.test(block)) return null;
  return 'missing-executable-body-or-blocked-reason';
}

function expectedSortKey(value) {
  if (!value) return '9999-Z';
  const quarter = value.match(/^(\d{4})Q([1-4])$/i);
  if (quarter) return `${quarter[1]}-${String(Number(quarter[2]) * 3).padStart(2, '0')}-99`;
  const isoDate = value.match(/^(\d{4})-(\d{2})-(\d{2})$/);
  if (isoDate) return value;
  return value;
}

function isExpired(value, now = new Date()) {
  if (!value) return false;
  const quarter = value.match(/^(\d{4})Q([1-4])$/i);
  let deadline = null;
  if (quarter) {
    const year = Number(quarter[1]);
    const q = Number(quarter[2]);
    deadline = new Date(Date.UTC(year, q * 3, 0, 23, 59, 59));
  } else if (/^\d{4}-\d{2}-\d{2}$/.test(value)) {
    deadline = new Date(`${value}T23:59:59Z`);
  }
  return deadline ? deadline.getTime() < now.getTime() : false;
}

function analyzePlaywrightFixmes() {
  const files = walk(TESTS_DIR, (_, name) => name.endsWith('.spec.ts')).sort();
  const items = [];
  for (const file of files) {
    const text = readFileSync(file, 'utf8');
    const lines = text.split(/\r?\n/);
    for (let i = 0; i < lines.length; i++) {
      if (!/^\s*test\.fixme\s*\(/.test(lines[i])) continue;
      const end = findNextFixmeOrEof(lines, i);
      const block = lines.slice(i, end).join('\n');
      const blockingOn = firstMagic(block, 'blocking-on');
      const userPromise = firstMagic(block, 'user-promise');
      const expectedLiveBy = firstMagic(block, 'expected-live-by');
      const missing = [];
      if (!blockingOn) missing.push('blocking-on');
      if (!userPromise) missing.push('user-promise');
      if (!expectedLiveBy) missing.push('expected-live-by');
      const invalid = [];
      const blockingOnError = validateBlockingOn(blockingOn);
      if (blockingOnError) invalid.push(blockingOnError);
      const userPromiseError = validateUserPromise(userPromise);
      if (userPromiseError) invalid.push(userPromiseError);
      const bodyError = validateFixmeBody(block);
      if (bodyError) invalid.push(bodyError);
      items.push({
        kind: 'playwright-fixme',
        file: rel(REPO_ROOT, file),
        line: i + 1,
        title: extractTitle(lines, i),
        blocking_on: blockingOn,
        user_promise: userPromise,
        expected_live_by: expectedLiveBy,
        missing,
        invalid,
        expired: isExpired(expectedLiveBy),
        call_sites: 1,
      });
    }
  }
  return items;
}

function activeUnimplementedLineIndexes(lines) {
  const indexes = [];
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (/^\s*\/\//.test(line) || /^\s*\*/.test(line)) continue;
    if (/\bunimplemented!\s*\(/.test(line)) indexes.push(i);
  }
  return indexes;
}

function rustScenarioTitle(text, fallback) {
  const runFn =
    text.match(/\bpub\s+async\s+fn\s+([A-Za-z0-9_]+_run)\s*\(/) ??
    text.match(/\bpub\s+fn\s+([A-Za-z0-9_]+_run)\s*\(/) ??
    text.match(/\bpub\s+async\s+fn\s+([A-Za-z0-9_]+)\s*\(/) ??
    text.match(/\bpub\s+fn\s+([A-Za-z0-9_]+)\s*\(/);
  if (runFn) return `Rust scenario scaffold: ${runFn[1]}`;
  return `Rust scenario scaffold: ${fallback.replace(/\.rs$/, '')}`;
}

function analyzeRustScaffolds() {
  const files = walk(RUST_SCENARIOS_DIR, (_, name) => name.endsWith('.rs')).sort();
  const items = [];
  for (const file of files) {
    const text = readFileSync(file, 'utf8');
    const lines = text.split(/\r?\n/);
    const callIndexes = activeUnimplementedLineIndexes(lines);
    if (callIndexes.length === 0) continue;
    const userPromise = rel(REPO_ROOT, file);
    const blockingOn = 'cotest#rust-scenario-scaffold';
    const expectedLiveBy = RUST_SCAFFOLD_EXPECTED_LIVE_BY;
    const invalid = [];
    const blockingOnError = validateBlockingOn(blockingOn);
    if (blockingOnError) invalid.push(blockingOnError);
    const userPromiseError = validateUserPromise(userPromise);
    if (userPromiseError) invalid.push(userPromiseError);
    items.push({
      kind: 'rust-unimplemented-scaffold',
      file: userPromise,
      line: callIndexes[0] + 1,
      title: `${rustScenarioTitle(text, file.split(/[\\/]/).pop())} (${callIndexes.length} unimplemented! call sites)`,
      blocking_on: blockingOn,
      user_promise: userPromise,
      expected_live_by: expectedLiveBy,
      missing: [],
      invalid,
      expired: isExpired(expectedLiveBy),
      call_sites: callIndexes.length,
    });
  }
  return items;
}

function analyzeDebtItems() {
  const items = [...analyzePlaywrightFixmes(), ...analyzeRustScaffolds()];
  items.sort((a, b) => {
    const group = (a.blocking_on ?? '(missing)').localeCompare(b.blocking_on ?? '(missing)');
    if (group !== 0) return group;
    const eta = expectedSortKey(a.expected_live_by).localeCompare(expectedSortKey(b.expected_live_by));
    if (eta !== 0) return eta;
    return `${a.file}:${a.line}`.localeCompare(`${b.file}:${b.line}`);
  });
  return items;
}

function escapeCell(value) {
  if (value === null || value === undefined || value === '') return '-';
  return String(value).replace(/\|/g, '\\|').replace(/\r?\n/g, ' ');
}

function renderMarkdown(items) {
  const missingCount = items.filter((i) => i.missing.length > 0).length;
  const expiredCount = items.filter((i) => i.expired).length;
  const invalidCount = items.filter((i) => i.invalid.length > 0).length;
  const playwrightCount = items.filter((i) => i.kind === 'playwright-fixme').length;
  const rustScaffoldCount = items.filter((i) => i.kind === 'rust-unimplemented-scaffold').length;
  const rustScaffoldCallSites = items
    .filter((i) => i.kind === 'rust-unimplemented-scaffold')
    .reduce((sum, item) => sum + (item.call_sites ?? 1), 0);
  const groups = new Map();
  for (const item of items) {
    const key = item.blocking_on ?? '(missing @blocking-on)';
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(item);
  }

  const lines = [];
  lines.push('# fixme debt');
  lines.push('');
  lines.push(`Generated: ${new Date().toISOString()}`);
  lines.push('');
  lines.push('| metric | count |');
  lines.push('|---|---:|');
  lines.push(`| total debt entries | ${items.length} |`);
  lines.push(`| playwright fixme | ${playwrightCount} |`);
  lines.push(`| rust unimplemented scaffold files | ${rustScaffoldCount} |`);
  lines.push(`| rust unimplemented call sites | ${rustScaffoldCallSites} |`);
  lines.push(`| missing metadata | ${missingCount} |`);
  lines.push(`| invalid metadata/body | ${invalidCount} |`);
  lines.push(`| expired expected_live_by | ${expiredCount} |`);
  lines.push('');
  for (const [blockingOn, groupItems] of groups) {
    lines.push(`## ${blockingOn}`);
    lines.push('');
    lines.push('| kind | expected_live_by | status | file:line | title | user_promise | missing | invalid | call_sites |');
    lines.push('|---|---|---|---|---|---|---|---|---:|');
    for (const item of groupItems) {
      const status = item.expired
        ? 'expired'
        : item.missing.length > 0
          ? 'metadata-missing'
          : item.invalid.length > 0
            ? 'invalid'
            : 'tracked';
      lines.push(
        `| ${escapeCell(item.kind)} | ${escapeCell(item.expected_live_by)} | ${status} | ${escapeCell(`${item.file}:${item.line}`)} | ${escapeCell(item.title)} | ${escapeCell(item.user_promise)} | ${escapeCell(item.missing.join(', '))} | ${escapeCell(item.invalid.join(', '))} | ${item.call_sites ?? 1} |`,
      );
    }
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

  const items = analyzeDebtItems();
  const markdown = renderMarkdown(items);
  mkdirSync(dirname(args.output), { recursive: true });
  writeFileSync(args.output, markdown, 'utf8');

  const missingCount = items.filter((i) => i.missing.length > 0).length;
  const expiredCount = items.filter((i) => i.expired).length;
  const invalidCount = items.filter((i) => i.invalid.length > 0).length;
  const playwrightCount = items.filter((i) => i.kind === 'playwright-fixme').length;
  const rustScaffoldCount = items.filter((i) => i.kind === 'rust-unimplemented-scaffold').length;
  const rustScaffoldCallSites = items
    .filter((i) => i.kind === 'rust-unimplemented-scaffold')
    .reduce((sum, item) => sum + (item.call_sites ?? 1), 0);
  const summary = {
    output: args.output,
    total_debt: items.length,
    total_fixme: playwrightCount,
    rust_unimplemented_scaffolds: rustScaffoldCount,
    rust_unimplemented_call_sites: rustScaffoldCallSites,
    missing_metadata: missingCount,
    invalid_metadata_or_body: invalidCount,
    expired_expected_live_by: expiredCount,
    strict_pass: missingCount === 0 && invalidCount === 0 && expiredCount === 0,
  };
  if (args.json) console.log(JSON.stringify({ summary, items }, null, 2));
  else console.log(`fixme debt report: ${args.output}`);

  return args.strict && !summary.strict_pass ? 1 : 0;
}

process.exit(main());
