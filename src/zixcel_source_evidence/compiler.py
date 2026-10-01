"""Source-only compiler observations, independently pinned to trusted tools.

Compilation context is deliberately incomplete: no dependency download, build
scripts, proc macros, environment values or sysroot discovery. Results describe
the supplied projection, not runtime dispatch or external crate implementation.
"""
from pathlib import Path
import posixpath
import json
import subprocess
import tomllib
from .language import parser, walk
from .lsp import RustSession
from .model import Code, EvidenceError, digest, pack, unpack, canonical
from .source import observe


def normalize_targets(db, limits, selected_files):
    """Persist compiler observations as indexed, scope-qualified candidates.

    Projected compilation is not runtime proof. Resolved syntax edges are
    retained, while additional compiler targets are CandidateTargets. Consumers
    get the same identities forward and backward, without rescanning source.
    """
    for fid in sorted(selected_files):
        additions = {}
        for row in db.execute("SELECT data FROM edges WHERE file=? ORDER BY id", (fid,)):
            edge = unpack(row[0])
            compiler = edge.get("compiler")
            if not compiler:
                continue
            for target in compiler["targets"]:
                if target == edge["target"]:
                    continue
                observed = {**edge, "target": target, "targets": compiler["targets"],
                            "resolution": "CandidateTargets", "basis": "compiler_projection"}
                observed["id"] = digest([edge["source"], fid, edge["kind"], edge["start"], target, "compiler_projection"])
                additions[observed["id"]] = observed
                if len(additions) > limits.result_size:
                    raise EvidenceError(Code.ResourceLimitExceeded, "compiler target normalization")
        for edge in additions.values():
            db.execute("INSERT INTO edges VALUES (?,?,?,?,?,?,?)", (edge["id"], edge["source"], edge["target"],
                       edge["kind"], edge["resolution"], fid, pack(edge)))


def rust_projection(raw, limits):
    output = bytearray(raw)
    for node in walk(parser("rust").parse(raw).root_node, limits.ast_nodes):
        if node.type in {"string_literal", "raw_string_literal", "char_literal"}:
            # Preserve byte/line positions; keep a valid inert literal. In
            # particular include!/include_str!/env! cannot access external paths.
            replacement = bytearray(b" "*(node.end_byte-node.start_byte))
            for i, b in enumerate(raw[node.start_byte:node.end_byte]):
                if b in (10, 13):
                    replacement[i] = b
            replacement[0], replacement[-1] = (39, 39) if node.type == "char_literal" else (34, 34)
            output[node.start_byte:node.end_byte] = replacement
    return bytes(output)


def enrich_rust(db, root, limits, selected_files, configuration):
    executable = Path(configuration["executable"])
    if not executable.is_absolute() or not executable.is_file():
        raise EvidenceError(Code.AnalyzerUnavailable, "explicit rust-analyzer artifact required")
    expected = configuration.get("sha256")
    if digest(executable.read_bytes()) != expected:
        raise EvidenceError(Code.InvalidEvidence, "rust-analyzer artifact digest mismatch")
    owners = {r[0] for r in db.execute("SELECT DISTINCT owner FROM files WHERE language='rust'")}
    observed, requested = 0, 0
    for owner in sorted(owners):
        rows = list(db.execute("SELECT id,path FROM files WHERE owner=? AND language='rust' ORDER BY path", (owner,)))
        if not any(r["id"] in selected_files for r in rows):
            continue
        if len(rows) > limits.result_size:
            raise EvidenceError(Code.ResourceLimitExceeded, "compiler package files")
        manifest = db.execute("SELECT manifest FROM packages WHERE id=?", (owner,)).fetchone()[0]
        base = posixpath.dirname(manifest) if manifest else ""
        declaration = tomllib.loads(observe(root, manifest, limits)[0].decode()) if manifest else {}
        edition = declaration.get("package", {}).get("edition", "2015")
        manifest_inputs = {manifest: digest(observe(root, manifest, limits)[0])} if manifest else {}
        edition_resolution = "Declared" if manifest else "ProjectionDefault"
        if isinstance(edition, dict) and edition.get("workspace") is True:
            edition = None
            for parent in Path(base).parents:
                candidate = posixpath.join(str(parent), "Cargo.toml").removeprefix("./")
                if not db.execute("SELECT 1 FROM files WHERE path=?", (candidate,)).fetchone():
                    continue
                data = observe(root, candidate, limits)[0]
                parent_manifest = tomllib.loads(data.decode())
                if "workspace" in parent_manifest:
                    manifest_inputs[candidate] = digest(data)
                    edition = parent_manifest["workspace"].get("package", {}).get("edition")
                    break
            edition_resolution = "Inherited" if edition else "ProjectionDefault"
        if edition is None:
            edition = "2021"
        if edition not in {"2015", "2018", "2021", "2024"}:
            raise EvidenceError(Code.InvalidEvidence, "unsupported declared Rust edition")
        inputs, originals, uri_files = {}, {}, {}
        for row in rows:
            name = posixpath.relpath(row["path"], base or ".")
            if ".." in Path(name).parts:
                raise EvidenceError(Code.UnsafePath, "compiler package relative file")
            raw, _ = observe(root, row["path"], limits)
            originals[name] = raw
            inputs[name] = rust_projection(raw, limits).decode()
            uri_files[name] = row["id"]
        roots = [name for name in inputs if name in {"src/lib.rs", "src/main.rs", "lib.rs", "main.rs"}]
        context_digest = digest({"inputs": {n: digest(b) for n, b in originals.items()},
                                 "tool": expected, "roots": roots, "edition": edition,
                                 "manifests": manifest_inputs,
                                 "cfg": [], "literal_projection": "inert", "dependencies": []})
        with RustSession(executable, seconds=limits.parser_seconds, max_bytes=limits.file_bytes*2,
                         files=inputs, roots=roots, edition=edition, memory_bytes=limits.memory_bytes//2) as session:
            for name, text in inputs.items():
                fid = uri_files[name]
                if fid not in selected_files:
                    continue
                uri = session.open(name, text)
                projected = text.encode()
                for row in list(db.execute("SELECT id,data FROM edges WHERE file=? AND kind IN ('Call','Property') ORDER BY id", (fid,))):
                    edge = unpack(row["data"])
                    start = edge["start"]
                    # Member calls resolve the member token, not the receiver.
                    local_name = edge["name"].replace("::", ".").rsplit(".", 1)[-1]
                    if not local_name.isidentifier():
                        continue
                    search = projected[start:start+len(edge["name"].encode())]
                    at = search.rfind(local_name.encode())
                    if at < 0:
                        continue
                    position = start+at
                    line = projected[:position].count(b"\n")
                    column = position-(projected.rfind(b"\n", 0, position)+1)
                    targets = session.definition(uri, line, column)
                    requested += 1
                    matches = set()
                    for target in targets:
                        target_uri = target.get("uri", target.get("targetUri"))
                        for target_name, target_fid in uri_files.items():
                            if target_uri != (session.root/target_name).as_uri():
                                continue
                            point = target.get("range", target.get("targetSelectionRange"))["start"]
                            lines = inputs[target_name].encode().splitlines(keepends=True)
                            offset = sum(len(b) for b in lines[:point["line"]])+point["character"]
                            candidates = [unpack(r[0]) for r in db.execute("SELECT data FROM symbols WHERE file=?", (target_fid,))]
                            within = [s for s in candidates if s["start"] <= offset < s["end"]]
                            if within:
                                smallest = min(within, key=lambda s: s["end"]-s["start"])
                                # A variable/field declaration inside a function is
                                # not a reference to that containing function.
                                if smallest["name"] == local_name:
                                    matches.add(smallest["id"])
                    edge["compiler"] = {"tool_digest": expected, "context_digest": context_digest,
                                        "edition": edition, "edition_resolution": edition_resolution,
                                        "scope": "source_only_projection", "targets": sorted(matches),
                                        "resolution": "Resolved" if len(matches) == 1 else "CandidateTargets" if matches else "Unresolved",
                                        "missing": ["external_crates", "sysroot", "cfg_configuration", "literal_semantics", "proc_macros"]}
                    if matches:
                        observed += 1
                    # Do not silently overwrite syntax edges with projected runtime
                    # claims. Compiler evidence has its own exact context/provenance.
                    db.execute("UPDATE edges SET data=? WHERE id=?", (pack(edge), row["id"]))
    if digest(executable.read_bytes()) != expected:
        raise EvidenceError(Code.SourceChangedDuringAnalysis, "compiler artifact changed")
    return {"requests": requested, "source_targets_observed": observed}


def enrich_typescript(db, root, limits, selected_files, configuration):
    module, node = Path(configuration["module"]), Path(configuration["node"])
    for artifact, key in [(module, "sha256"), (node, "node_sha256")]:
        if not artifact.is_absolute() or not artifact.is_file():
            raise EvidenceError(Code.AnalyzerUnavailable, "explicit compiler artifact required")
        if digest(artifact.read_bytes()) != configuration.get(key):
            raise EvidenceError(Code.InvalidEvidence, "TS compiler artifact digest mismatch")
    owners = {r[0] for r in db.execute("SELECT DISTINCT owner FROM files WHERE language IN ('typescript','tsx','javascript','vue')")}
    requests, observed = 0, 0
    for owner in sorted(owners):
        rows = list(db.execute("SELECT id,path,language FROM files WHERE owner=? AND language IN ('typescript','tsx','javascript','vue') ORDER BY path", (owner,)))
        if not any(r["id"] in selected_files for r in rows):
            continue
        inputs, ids = {}, {}
        for row in rows:
            raw, _ = observe(root, row["path"], limits)
            if row["language"] == "vue":
                projected = bytearray(10 if b == 10 else 32 for b in raw)
                for n in walk(parser("vue").parse(raw).root_node, limits.ast_nodes):
                    if n.type == "script_element":
                        body = next((c for c in n.named_children if c.type == "raw_text"), None)
                        if body:
                            projected[body.start_byte:body.end_byte] = raw[body.start_byte:body.end_byte]
                text, suffix = projected.decode(), ".ts"
            else:
                text, suffix = raw.decode(), ""
            name = "/"+row["path"]+suffix
            inputs[name], ids[name] = text, row["id"]
        context_digest = digest({"inputs": {p: digest(v.encode()) for p, v in inputs.items()},
                                 "artifacts": configuration, "no_lib": True, "no_plugins": True})
        payload = canonical({"module": str(module), "files": inputs, "max_nodes": limits.ast_nodes,
                             "max_results": limits.result_size, "memory_bytes": limits.memory_bytes//2}).encode()
        if len(payload) > 32*1024*1024:
            raise EvidenceError(Code.ResourceLimitExceeded, "compiler input envelope")
        try:
            result = subprocess.run([str(node), "--max-old-space-size=256", str(Path(__file__).with_name("typescript.mjs"))],
                input=payload, capture_output=True, timeout=limits.parser_seconds,
                env={"PATH": "/usr/bin:/bin"}, cwd="/")
        except (OSError, subprocess.TimeoutExpired) as error:
            raise EvidenceError(Code.ResourceLimitExceeded, "TS compiler process unavailable/deadline") from error
        try:
            response = json.loads(result.stdout)
        except ValueError as error:
            raise EvidenceError(Code.ResolutionFailure, "TS compiler returned no bounded evidence") from error
        if "error" in response:
            raise EvidenceError(Code(response["error"]), response.get("detail", ""))
        if result.returncode:
            raise EvidenceError(Code.ResolutionFailure, "TS compiler process exit")
        for observation in response["observations"]:
            fid = ids[observation["path"]]
            if fid not in selected_files:
                continue
            requests += 1
            matching = db.execute("SELECT id,data FROM edges WHERE file=? AND kind=?", (fid, observation["kind"]))
            rows_at = [r for r in matching if unpack(r["data"])["start"] == observation["start"]]
            targets = set()
            for target in observation["targets"]:
                target_fid = ids[target["path"]]
                for s in db.execute("SELECT id,data FROM symbols WHERE file=?", (target_fid,)):
                    entry = unpack(s["data"])
                    if (entry["start"] >= target["start"] and entry["end"] == target["end"]
                            and entry["kind"] in {"Function", "Method"}):
                        targets.add(s["id"])
            for row in rows_at:
                edge = unpack(row["data"])
                edge["compiler"] = {"tool_digest": configuration["sha256"], "version": response["version"],
                    "context_digest": context_digest, "scope": "source_only_projection", "targets": sorted(targets),
                    "resolution": "Resolved" if len(targets) == 1 else "CandidateTargets" if targets else "Unresolved",
                    "type": observation["type"],
                    "missing": ["external_packages", "standard_library", "application_configuration", "dynamic_runtime"]}
                db.execute("UPDATE edges SET data=? WHERE id=?", (pack(edge), row["id"]))
                if targets:
                    observed += 1
    for artifact, key in [(module, "sha256"), (node, "node_sha256")]:
        if digest(artifact.read_bytes()) != configuration.get(key):
            raise EvidenceError(Code.SourceChangedDuringAnalysis, "TS compiler artifact changed")
    return {"requests": requests, "source_targets_observed": observed}
