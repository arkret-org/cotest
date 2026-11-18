"""Plan and reconcile two file-disjoint browser runs on independent three-Station stacks."""

import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import uuid
import xml.etree.ElementTree as ET


E2E = Path(__file__).resolve().parents[1] / "e2e"
P0 = "federation/three-server-p0.spec.ts"
SETUP = "inkson-build-id"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def load(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def discover(command):
    result = subprocess.run([*command, "--list", "--reporter=json"], cwd=E2E,
                            stdout=subprocess.PIPE, check=True)
    report = json.loads(result.stdout)
    require(not report.get("errors"), "Playwright collection reported errors")
    files = defaultdict(list)
    setup = []

    def visit(suite, file, titles):
        for spec in suite["specs"]:
            name = " › ".join([*titles, spec["title"]])
            for test in spec["tests"]:
                project = test["projectName"]
                require(project in ("chrome", SETUP), f"unexpected project {project}")
                if project == SETUP:
                    setup.append([file, name])
                else:
                    files[file].append(name)
        for child in suite.get("suites", []):
            visit(child, file, [*titles, child["title"]])

    for suite in report["suites"]:
        visit(suite, suite["file"].replace("\\", "/"), [])
    require(len(files.get(P0, [])) >= 5 and setup, "missing mandatory P0 or browser setup")
    require(all(len(set(names)) == len(names) for names in files.values()), "duplicate case identity")
    return {file: sorted(names) for file, names in files.items()}, sorted(setup)


def junit(path):
    for suite in ET.parse(path).getroot().findall("testsuite"):
        file = suite.attrib["name"].replace("\\", "/")
        for case in suite.findall("testcase"):
            yield suite.attrib["hostname"], file, case.attrib["name"], case


def plan(args):
    files, setup = discover(["node", str(E2E / "node_modules/@playwright/test/cli.js"), "test",
                             "--config", "playwright.config.ts", "--project=chrome",
                             "--grep-invert", "@platform-live|@native-public-reply"])
    durations = {}
    if args.history:
        durations = {(file, name): float(case.attrib["time"]) for project, file, name, case
                     in junit(args.history) if project == "chrome" and case.find("skipped") is None}
    # Unseen cases get the mean known duration, or one unit for a count-only plan.
    fallback = sum(durations.values()) / len(durations) if durations else 1
    weights = {file: sum(durations.get((file, name), fallback) for name in names)
               for file, names in files.items()}
    parts, loads = [[], []], [0.0, 0.0]
    for file in sorted(files, key=lambda f: (-weights[f], f)):
        index = min(range(2), key=lambda i: (loads[i], len(parts[i]), i))
        parts[index].append(file)
        loads[index] += weights[file]
    with args.output.open("x", encoding="utf8") as output:
        json.dump(dict(run_id=str(uuid.uuid4()), files=files, setup=setup, parts=parts),
                  output, ensure_ascii=False, indent=2)
    print(f"{sum(map(len, files.values()))} business tests, files per shard: {list(map(len, parts))}")


def read_plan(path):
    data = load(path)
    parts = data["parts"]
    require(len(parts) == 2 and all(parts), "expected two nonempty shards")
    require(Counter(parts[0] + parts[1]) == Counter(data["files"].keys()), "invalid file partition")
    return data


def select(args):
    data = read_plan(args.plan)
    files, setup = discover(args.command)
    require(files == data["files"] and setup == data["setup"], "plan differs from full runner collection")
    print(json.dumps(data["parts"][args.index - 1]))


def merge(args):
    data = read_plan(args.plan)
    digest = hashlib.sha256(args.plan.read_bytes()).hexdigest()
    sources = None
    settings = None
    seen = set()
    skipped = 0
    for run in args.runs:
        summary = load(run / "summary.json")
        index = summary["joint_full_shard"]
        require(index in (1, 2) and index not in seen, "missing or duplicate shard")
        seen.add(index)
        require(summary["run_profile"] == "joint-full-shard" and summary["shard_plan_sha256"] == digest
                and summary["server_count"] == 3 and summary["playwright_projects"] == "chrome",
                f"shard {index}: different plan or topology")
        require(summary["exit_code"] == 0 and summary["status"] == "success"
                and summary["source_stable"] and summary["source_coverage"] == "complete"
                and summary["secret_scan_status"] == "passed" and not summary["managed_service_failure_count"]
                and not summary["selection_gate_failures"], f"shard {index}: runner gates failed")
        controls = (summary["network_shape"], sorted(summary["shard_required_scenarios"]),
                    summary["forbid_skipped_tests"])
        require(settings in (None, controls), "different acceptance settings")
        settings = controls
        inputs = load(run / "source-freeze.json")["inputs"]
        frozen = sorted((r["repository"], r["head"], r["source_sha256"], r["dirty_sha256"]) for r in inputs)
        require(frozen and sources in (None, frozen), "different frozen inputs")
        sources = frozen
        expected = Counter(("chrome", file, name) for file in data["parts"][index - 1]
                           for name in data["files"][file])
        expected.update((SETUP, file, name) for file, name in data["setup"])
        actual = Counter()
        for project, file, name, case in junit(run / "junit.xml"):
            require(case.find("failure") is None and case.find("error") is None, f"failed case: {name}")
            if project == SETUP or file == P0:
                require(case.find("skipped") is None, f"mandatory case skipped: {name}")
            if project == "chrome" and case.find("skipped") is not None:
                skipped += 1
            actual[project, file, name] += 1
        require(actual == expected, f"shard {index}: missing, duplicate or unexpected JUnit cases")
        if index == 1:
            native = load(run / "native-api-migrations/summary.json")
            require(native["passed"] and native["scheduled"] == native["executed"] > 0, "native API gate failed")
    total = sum(map(len, data["files"].values()))
    print(f"Both shards passed runner gates. Business cases: {total - skipped} passed, {skipped} skipped (including fixme).")


def main():
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="action", required=True)
    create = commands.add_parser("plan")
    create.add_argument("--history", type=Path)
    create.add_argument("--output", required=True, type=Path)
    select_files = commands.add_parser("select")
    select_files.add_argument("plan", type=Path)
    select_files.add_argument("index", type=int, choices=(1, 2))
    select_files.add_argument("command", nargs=argparse.REMAINDER)
    verify = commands.add_parser("merge")
    verify.add_argument("plan", type=Path)
    verify.add_argument("runs", nargs=2, type=Path)
    args = parser.parse_args()
    {"plan": plan, "select": select, "merge": merge}[args.action](args)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, OSError, ET.ParseError, subprocess.CalledProcessError) as error:
        sys.exit(str(error))
