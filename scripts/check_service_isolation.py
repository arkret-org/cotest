"""Enforce production isolation; this gate never grants native coverage."""
import argparse
import json
from pathlib import Path
import re
import subprocess
import tomllib
from urllib.parse import parse_qs, unquote, urlsplit

ROOT = Path(__file__).resolve().parents[2]
OWNERS = ("coland", "coauth")


def foreign_git(source, owner):
    return bool(re.search(r"(?:/|:)arkret-org/" + owner + r"(?:\.git)?(?:[/?#]|$)", (source or "").lower()))


def compose_errors(document):
    services = document.get("services", {})
    if not all(owner in services for owner in OWNERS):
        return ["isolation Compose must describe both services"]
    errors = []
    bindings = {}
    for owner in OWNERS:
        environment = services[owner].get("environment", {})
        if isinstance(environment, list):
            environment = dict(item.split("=", 1) for item in environment if "=" in item)
        names = ("COLAND_DATABASE_URL", "DATABASE_URL") if owner == "coland" else ("COAUTH_DATABASE__URI", "DATABASE_URL")
        ids = set()
        for name in names:
            value = environment.get(name)
            if not value:
                continue
            url = urlsplit(value)
            if {"host", "hostaddr", "port", "dbname", "database", "service", "servicefile"} & parse_qs(url.query, keep_blank_values=True).keys():
                errors.append("database selection overrides are forbidden for " + owner)
            if url.scheme not in ("postgres", "postgresql") or not url.hostname or not url.path.strip("/"):
                errors.append("invalid explicit database binding for " + owner)
            else:
                ids.add((url.hostname.lower(), url.port or 5432, unquote(url.path)))
        if not ids:
            errors.append("missing explicit database binding for " + owner)
        bindings[owner] = ids
    if bindings["coland"] & bindings["coauth"]:
        errors.append("Coland and Coauth must not use the same database")

    def mounts(service, private_only=False):
        result = set()
        for mount in services.get(service, {}).get("volumes", []):
            if isinstance(mount, dict):
                source, target = mount.get("source"), mount.get("target", "")
            else:
                pieces = mount.split(":")
                source, target = (pieces[0], pieces[1]) if len(pieces) >= 2 else (None, pieces[0])
            if source and (not private_only or target.startswith(("/var/lib/", "/etc/coauth", "/etc/coland"))):
                result.add(source)
        return result
    if mounts("coland", True) & mounts("coauth", True):
        errors.append("Coland and Coauth must not share private storage/configuration volumes")
    for coland in bindings["coland"]:
        for coauth in bindings["coauth"]:
            if coland[0] != coauth[0] and mounts(coland[0]) & mounts(coauth[0]):
                errors.append("independent database services must not share their data volume")
    return errors


def tracked_sources(root):
    result = {}
    for owner in OWNERS:
        rows = subprocess.check_output([
            "git", "-C", str(root / owner), "ls-files", "-z", "--cached",
            "--others", "--exclude-standard",
        ]).decode("utf-8").split("\0")
        for name in rows:
            if name and (root / owner / name).is_file():
                result[owner + "/" + name] = None
    sdk = root / "arkret-rust-sdk"
    rows = subprocess.check_output([
        "git", "-C", str(sdk), "ls-files", "-z", "--cached", "--others",
        "--exclude-standard", "--", "crates/deployment-contracts",
    ]).decode("utf-8").split("\0")
    for name in rows:
        if name and (sdk / name).is_file():
            result["arkret-rust-sdk/" + name] = None
    return result


def source_errors(root, sources):
    root = Path(root).resolve()
    errors = []
    for required in ("coland/crates/server/Cargo.toml", "coauth/crates/backend/Cargo.toml"):
        if required not in sources:
            errors.append("deployment manifest provenance absent: " + required)
    for relative in sorted(sources):
        owner = relative.split("/", 1)[0]
        if owner not in OWNERS:
            continue
        other = next(name for name in OWNERS if name != owner)
        path = root / relative
        if not path.is_file():
            continue
        if path.name == "Cargo.toml":
            document = tomllib.loads(path.read_text(encoding="utf-8"))
            workspace_path = root / owner / "Cargo.toml"
            if workspace_path.exists() and owner + "/Cargo.toml" not in sources:
                errors.append("workspace manifest provenance absent: " + owner)
            workspace = tomllib.loads(workspace_path.read_text(encoding="utf-8")) if workspace_path.exists() else {}
            shared = workspace.get("workspace", {}).get("dependencies", {})

            def inspect(table):
                for key, value in table.items():
                    if key in ("dependencies", "build-dependencies"):
                        for name, item in value.items():
                            item = item if isinstance(item, dict) else {}
                            base = path.parent
                            if item.get("workspace"):
                                item = shared.get(name, {})
                                item = item if isinstance(item, dict) else {}
                                base = root / owner
                            package = item.get("package", name).replace("_", "-")
                            location = (base / item["path"]).resolve() if "path" in item else None
                            forbidden = package == other or package.startswith(other + "-")
                            forbidden |= location is not None and location.is_relative_to(root / other)
                            forbidden |= foreign_git(item.get("git"), other)
                            if forbidden:
                                errors.append(f"{owner} must not load {other} production code: {relative}: {name}")
                    elif key not in ("workspace", "dev-dependencies") and isinstance(value, dict):
                        inspect(value)
            inspect(document)
        elif path.suffix == ".rs":
            text = path.read_text(encoding="utf-8")
            if re.search(r"\bpub\s+(?:governance_database_url|coauth_database_url|coland_database_url)\s*:", text):
                errors.append("foreign database configuration: " + relative)
            for match in re.finditer(r'(?:include(?:_str|_bytes)?!\s*\(|#\s*\[\s*path\s*=)\s*"([^"\n]+)"', text):
                location = (path.parent / match[1]).resolve()
                if location.is_relative_to(root / other):
                    errors.append("foreign source/file inclusion: " + relative)
    transport = root / "arkret-rust-sdk/crates/deployment-contracts"
    if transport.exists():
        allowed = {"arkret-canonical", "arkret-identifiers", "arkret-models-collaboration",
                   "arkret-wire", "chrono", "salvo-oapi", "serde", "url"}
        manifest = transport / "Cargo.toml"
        key = manifest.relative_to(root).as_posix()
        if key not in sources:
            errors.append("shared transport manifest provenance absent")
        document = tomllib.loads(manifest.read_text(encoding="utf-8"))
        library = document.get("lib", {}).get("path", "src/lib.rs")
        if not (transport / library).resolve().is_relative_to(transport.resolve()):
            errors.append("shared transport library points outside its source ownership")
        for name, value in document.get("dependencies", {}).items():
            package = value.get("package", name) if isinstance(value, dict) else name
            if package not in allowed:
                errors.append("shared transport has non-carrier dependency: " + package)
        if (transport / "build.rs").exists() or document.get("build-dependencies") or document.get("package", {}).get("build") not in (None, False):
            errors.append("shared transport must not run build code")
        for path in transport.rglob("*.rs"):
            key = path.relative_to(root).as_posix()
            if key not in sources:
                errors.append("shared transport source provenance absent: " + key)
            text = path.read_text(encoding="utf-8")
            if not path.resolve().is_relative_to(transport.resolve()):
                errors.append("shared transport borrows an external source link: " + key)
            for match in re.finditer(r'(?:include(?:_str|_bytes)?!\s*\(|#\s*\[\s*path\s*=)\s*"([^"\n]+)"', text):
                if not (path.parent / match[1]).resolve().is_relative_to(transport.resolve()):
                    errors.append("shared transport includes external source: " + key)
            if re.search(r"\b(?:std::(?:fs|net|process)|tokio|reqwest|diesel|sqlx|postgres|arkret_keystore)\b", text):
                errors.append("shared transport must not access IO or custody: " + key)
    compose = root / "coauth/docker-compose.integration.yaml"
    if compose.exists():
        import yaml
        class UniqueMapping(yaml.SafeLoader):
            pass
        def mapping(loader, node, deep=False):
            loader.flatten_mapping(node)
            result = {}
            for key_node, value_node in node.value:
                key = loader.construct_object(key_node, deep=deep)
                if key in result:
                    raise ValueError("duplicate deployment mapping key: " + str(key))
                result[key] = loader.construct_object(value_node, deep=deep)
            return result
        UniqueMapping.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, mapping)
        if compose.relative_to(root).as_posix() not in sources:
            errors.append("deployment Compose provenance absent")
        errors.extend(compose_errors(yaml.load(compose.read_text(encoding="utf-8"), Loader=UniqueMapping)))
    for relative in ("coland/.dockerignore", "coauth/.dockerignore", "arkret-rust-sdk/.dockerignore"):
        path = root / relative
        expected = (path.parent / "Dockerfile").exists() or (path.parent.name == "arkret-rust-sdk" and transport.exists())
        if expected and not path.exists():
            errors.append("Docker evidence exclusion is absent: " + relative)
        elif path.exists() and not re.search(r"(?m)^/?artifacts/?\s*$", path.read_text(encoding="utf-8")):
            errors.append("Docker context includes private evidence: " + relative)
    docker_ignore = root / "coauth/Dockerfile.dockerignore"
    if (root / "coauth/Dockerfile").exists() and not docker_ignore.exists():
        errors.append("parent Docker evidence exclusion is absent")
    if docker_ignore.exists():
        lines = set(docker_ignore.read_text(encoding="utf-8").splitlines())
        for owner in ("coland", "coauth", "cotest", "arkret-rust-sdk"):
            if owner + "/artifacts/" not in lines:
                errors.append("parent Docker context includes private evidence: " + owner)
        if "**/artifacts/" in lines or "arkret-spec/spec/v1/artifacts/" in lines:
            errors.append("formal Spec artifacts must remain Docker source inputs")
    return errors


def graph_errors(root, owner, metadata):
    """Follow normal/build edges, including aliases, optional and target edges."""
    root = Path(root).resolve()
    other = next(name for name in OWNERS if name != owner)
    packages = {item["id"]: item for item in metadata["packages"]}
    nodes = {item["id"]: item for item in metadata["resolve"]["nodes"]}
    pending = list(metadata["workspace_members"])
    if not pending or any(item not in packages or item not in nodes for item in pending):
        return [owner + " runtime metadata has no complete workspace roots"], 0
    if Path(metadata["workspace_root"]).resolve() != root / owner:
        return [owner + " runtime metadata belongs to another workspace"], 0
    seen = set()
    errors = []
    while pending:
        current = pending.pop()
        if current in seen:
            continue
        seen.add(current)
        package = packages[current]
        path = Path(package["manifest_path"]).resolve()
        name = package["name"].replace("_", "-")
        if path.is_relative_to(root / other) or name == other or name.startswith(other + "-") or foreign_git(package.get("source"), other):
            errors.append(f"{owner} production graph reaches {other}: {name}")
        for target in package.get("targets", []):
            if any(kind in ("lib", "bin", "proc-macro", "custom-build", "dylib", "staticlib", "cdylib", "rlib") for kind in target["kind"]):
                if Path(target["src_path"]).resolve().is_relative_to(root / other):
                    errors.append(f"{owner} production target loads {other} source: {name}")
        for dependency in nodes[current].get("deps", []):
            if any(kind.get("kind") in (None, "build") for kind in dependency["dep_kinds"]):
                pending.append(dependency["pkg"])
    return errors, len(seen)


def live_graph_errors(root):
    errors = []
    graphs = {}
    for owner in OWNERS:
        completed = subprocess.run(
            ["cargo", "metadata", "--locked", "--all-features", "--format-version", "1"],
            cwd=Path(root) / owner, capture_output=True, text=True, encoding="utf-8", timeout=1800,
        )
        if completed.returncode:
            errors.append(f"{owner} locked runtime metadata failed: exit {completed.returncode}")
            continue
        failures, count = graph_errors(root, owner, json.loads(completed.stdout))
        errors.extend(failures)
        graphs[owner] = count
    return errors, graphs


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--metadata", action="append", nargs=2, metavar=("OWNER", "JSON"), default=[])
    parser.add_argument("--source-only", action="store_true", help="Static component check; never native coverage.")
    args = parser.parse_args()
    errors = source_errors(ROOT, tracked_sources(ROOT))
    graphs = {}
    if args.source_only and args.metadata:
        parser.error("source-only cannot consume runtime metadata")
    if args.metadata and {owner for owner, _ in args.metadata} != set(OWNERS):
        parser.error("both production metadata graphs are required")
    for owner, path in args.metadata:
        if owner not in OWNERS:
            parser.error("metadata owner must be coland or coauth")
        failures, count = graph_errors(ROOT, owner, json.loads(Path(path).read_text(encoding="utf-8")))
        errors.extend(failures)
        graphs[owner] = count
    if not args.metadata and not args.source_only:
        failures, graphs = live_graph_errors(ROOT)
        errors.extend(failures)
    print(json.dumps({"errors": errors, "runtime_packages": graphs, "native_coverage": False}, indent=2))
    return bool(errors)


if __name__ == "__main__":
    raise SystemExit(main())
