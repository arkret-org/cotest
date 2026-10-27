// Canonical generated wire types are re-exported, never renamed by aliases.
import ts from "typescript";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export function findCanonicalAliases(program, generatedPath) {
  const canonical = resolve(generatedPath);
  if (!program.getSourceFiles().some(source => resolve(source.fileName) === canonical)) {
    throw new Error(`canonical generated wire types are absent: ${canonical}`);
  }
  const checker = program.getTypeChecker();
  const findings = [];
  function canonicalName(node) {
    let symbol = checker.getSymbolAtLocation(node);
    const seen = new Set();
    while (symbol && symbol.flags & ts.SymbolFlags.Alias && !seen.has(symbol)) {
      seen.add(symbol);
      symbol = checker.getAliasedSymbol(symbol);
    }
    return symbol?.declarations?.some(declaration => resolve(declaration.getSourceFile().fileName) === canonical)
      ? symbol.getName() : undefined;
  }
  for (const source of program.getSourceFiles()) {
    if (source.isDeclarationFile || resolve(source.fileName) === canonical || program.isSourceFileFromExternalLibrary(source)) continue;
    function visit(node) {
      let target;
      if (ts.isTypeAliasDeclaration(node) && ts.isTypeReferenceNode(node.type)) {
        target = canonicalName(node.type.typeName);
      } else if (ts.isImportSpecifier(node) || ts.isExportSpecifier(node)) {
        const original = canonicalName(node.name);
        if (original && node.name.text !== original) target = original;
      }
      if (target) {
        const { line, character } = source.getLineAndCharacterOfPosition(node.getStart(source));
        findings.push({ file: source.fileName, line: line + 1, column: character + 1, name: node.name.text, canonical: target });
      }
      ts.forEachChild(node, visit);
    }
    visit(source);
  }
  return findings;
}

export function checkProject(project, generated) {
  const config = ts.readConfigFile(project, ts.sys.readFile);
  if (config.error) throw new Error(ts.flattenDiagnosticMessageText(config.error.messageText, "\n"));
  const parsed = ts.parseJsonConfigFileContent(config.config, ts.sys, dirname(project));
  if (parsed.errors.length) throw new Error(parsed.errors.map(error => ts.flattenDiagnosticMessageText(error.messageText, "\n")).join("\n"));
  return findCanonicalAliases(ts.createProgram(parsed.fileNames, parsed.options), generated);
}

const invokedDirectly = process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));
if (invokedDirectly) {
  const here = dirname(fileURLToPath(import.meta.url));
  const option = process.argv.indexOf("--project");
  const project = option < 0 ? resolve(here, "../tsconfig.json") : resolve(process.argv[option + 1]);
  const findings = checkProject(project, resolve(here, "../helpers/generated/spec-wire-objects.ts"));
  for (const finding of findings) process.stderr.write(`${finding.file}:${finding.line}:${finding.column}: ${finding.name} duplicates canonical ${finding.canonical}; import or re-export the canonical name\n`);
  if (findings.length) process.exitCode = 1;
  else process.stdout.write("canonical wire type ownership passed\n");
}
