import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import ts from "typescript";

const root = path.resolve("tests");
const files = [];

function walk(directory) {
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    const target = path.join(directory, entry.name);
    if (entry.isDirectory()) {
      walk(target);
    } else if (entry.name.endsWith(".spec.ts")) {
      files.push(target);
    }
  }
}

function isFixmeCall(node, sourceFile) {
  return (
    ts.isCallExpression(node) &&
    ts.isPropertyAccessExpression(node.expression) &&
    node.expression.expression.getText(sourceFile) === "test" &&
    node.expression.name.text === "fixme"
  );
}

walk(root);
const errors = [];
let count = 0;

for (const file of files) {
  const source = fs.readFileSync(file, "utf8");
  const sourceFile = ts.createSourceFile(
    file,
    source,
    ts.ScriptTarget.Latest,
    true,
  );

  function visit(node) {
    if (isFixmeCall(node, sourceFile)) {
      count += 1;
      const line =
        sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile)).line +
        1;
      const relative = path.relative(process.cwd(), file).replaceAll("\\", "/");
      const location = `${relative}:${line}`;
      const title = node.arguments[0];
      const body = node.arguments[1];
      if (!title || !ts.isStringLiteralLike(title) || title.text.trim() === "") {
        errors.push(`${location}: fixme title must be a non-empty string literal`);
      }
      if (
        !body ||
        (!ts.isArrowFunction(body) && !ts.isFunctionExpression(body)) ||
        !ts.isBlock(body.body) ||
        body.body.statements.length === 0
      ) {
        errors.push(`${location}: empty fixme bodies are forbidden`);
      }
      const metadataEnd = title?.getStart(sourceFile) ?? node.getStart(sourceFile);
      const metadata = source.slice(node.getFullStart(), metadataEnd);
      for (const tag of [
        "@blocking-on",
        "@user-promise",
        "@expected-live-by",
      ]) {
        if (!metadata.includes(tag)) {
          errors.push(`${location}: missing ${tag}`);
        }
      }
    }
    ts.forEachChild(node, visit);
  }

  visit(sourceFile);
}

if (errors.length > 0) {
  process.stderr.write(`${errors.join("\n")}\n`);
  process.exit(1);
}

process.stdout.write(
  `Playwright fixme quality gate passed: ${count} executable, fully attributed fixme tests\n`,
);

