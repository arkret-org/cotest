"""Record the eleven repository inputs for a security production run."""

import argparse
import hashlib
import json
import pathlib
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument("root", type=pathlib.Path)
parser.add_argument("output", type=pathlib.Path)
args = parser.parse_args()
result = {}
for name in (
    "arkret-spec", "arkret-rust-sdk", "coland", "cotest", "inkson", "garth",
    "coauth", "chime", "floria", "bridges", "savfox",
):
    repo = args.root.parent / "savfox-ai" / "savfox" if name == "savfox" else args.root / name

    def git(*arguments):
        return subprocess.check_output(("git", *arguments), cwd=repo)

    paths = git("diff", "--name-only", "HEAD").decode().splitlines()
    paths += git("ls-files", "--others", "--exclude-standard").decode().splitlines()
    result[name] = {
        "head": git("rev-parse", "HEAD").decode().strip(),
        "diff_sha256": hashlib.sha256(git("diff", "--binary", "HEAD")).hexdigest(),
        "changed_file_sha256": {
            path: hashlib.sha256((repo / path).read_bytes()).hexdigest()
            for path in sorted(set(paths))
        },
    }
args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
