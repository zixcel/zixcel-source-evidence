"""Immutable SQLite publications with indexed reads and atomic replacement.

Writers prepare outside the publication lock, then compare the old digest under
an advisory lock. Existing readers keep the old inode. There is no repair on open.
"""
from collections import deque
from dataclasses import asdict
import fcntl
import json
import os
from pathlib import Path
import resource
import sqlite3
import tempfile
import time
import posixpath
import re
from .language import provenance, implementation_digest, ANALYZER_DIGEST
from .model import (FORMAT, VERSION, Code, EvidenceError, Limits, PacketLimits, RepositoryRef,
                    PackageRef, SourceFileRef, SymbolRef, TypeRef, ExternalEffectRef,
                    Effect, Relation, EvidenceRequest, canonical, digest, ref, pack, unpack, packed_canonical)
from .source import inventory, observe, directory, repositories
from .worker import ParserWorker

SCHEMA = """
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE files (id TEXT PRIMARY KEY, path TEXT UNIQUE NOT NULL, language TEXT NOT NULL,
 owner TEXT NOT NULL, digest TEXT NOT NULL, adapter TEXT NOT NULL, analysis TEXT NOT NULL);
CREATE TABLE symbols (id TEXT PRIMARY KEY, file TEXT NOT NULL REFERENCES files(id), name TEXT NOT NULL,
 body_digest TEXT NOT NULL, data TEXT NOT NULL);
CREATE INDEX names ON symbols(name,file);
CREATE TABLE packages (id TEXT PRIMARY KEY, manifest TEXT, name TEXT NOT NULL, repository TEXT NOT NULL);
CREATE TABLE types (id TEXT PRIMARY KEY, file TEXT NOT NULL REFERENCES files(id), data TEXT NOT NULL);
CREATE TABLE edges (id TEXT PRIMARY KEY, source TEXT NOT NULL, target TEXT, kind TEXT NOT NULL,
 resolution TEXT NOT NULL, file TEXT NOT NULL, data TEXT NOT NULL);
CREATE INDEX forward ON edges(source,kind,id);
CREATE INDEX reverse ON edges(target,kind,id);
CREATE TABLE effects (id TEXT PRIMARY KEY, source TEXT NOT NULL, kind TEXT NOT NULL, data TEXT NOT NULL);
CREATE INDEX effect_source ON effects(source,kind,id);
"""

# Physical access paths, not a second authority or a data compatibility layer.
# Explicit candidate construction establishes these even when SQLite backup
# copied an older physical index layout. Read-only open never creates indexes.
ACCESS_INDEXES = """
CREATE INDEX IF NOT EXISTS symbol_file ON symbols(file,id);
CREATE INDEX IF NOT EXISTS type_file ON types(file,id);
CREATE INDEX IF NOT EXISTS edge_file ON edges(file,id);
CREATE INDEX IF NOT EXISTS file_owner ON files(owner,language,id);
"""


def connect(path, readonly=False):
    try:
        db = sqlite3.connect(Path(path).absolute().as_uri() + ("?mode=ro" if readonly else "?mode=rw"), uri=True)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("PRAGMA cache_size=-8192")
        if readonly:
            db.execute("PRAGMA query_only=ON")
        return db
    except sqlite3.Error as error:
        raise EvidenceError(Code.CorruptIndex, "database open") from error


def check_memory(limits):
    if resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024 > limits.memory_bytes:
        raise EvidenceError(Code.ResourceLimitExceeded, "analyzer memory")


def state_digest(db):
    import hashlib
    h = hashlib.sha256()
    for table in ["files", "symbols", "types", "edges", "effects", "packages"]:
        for row in db.execute(f"SELECT * FROM {table} ORDER BY id"):
            # pack() already emits canonical JSON. Hash the same exact byte
            # representation without decoding/re-encoding every indexed AST.
            # This keeps the digest identical while removing a full JSON pass.
            h.update(b"["+canonical(table).encode()+b",[")
            for ordinal, value in enumerate(row):
                if ordinal:
                    h.update(b",")
                h.update(packed_canonical(value) if isinstance(value, bytes) else canonical(value).encode())
            h.update(b"]]")
    for row in db.execute("SELECT * FROM meta WHERE key NOT IN ('digest','measurements') ORDER BY key"):
        h.update(canonical(list(row)).encode())
    return h.hexdigest()


def metadata(db, key):
    row = db.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
    if row is None:
        raise EvidenceError(Code.CorruptIndex, "missing metadata")
    return json.loads(row[0])


def owner_for(path, manifests, repository, boundary="."):
    candidates = [p for p in manifests
                  if (boundary == "." or p.startswith(boundary+"/"))
                  and (str(Path(p).parent) == "." or path.startswith(str(Path(p).parent) + "/"))]
    selected = max(candidates, key=lambda x: len(Path(x).parts), default=None)
    name = manifests.get(selected, "<root>")
    return ref(PackageRef, repository.value, selected or "<root>", name).value, selected


class Index:
    def __init__(self, path, db):
        self.path, self.db = Path(path), db
        self.limits = Limits(**metadata(db, "limits"))

    def close(self):
        self.db.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    @classmethod
    def open_existing(cls, path):
        path = Path(path)
        directory(path.parent)
        if path.is_symlink():
            raise EvidenceError(Code.UnsafePath, "index symlink")
        if not path.exists():
            raise EvidenceError(Code.MissingIndex)
        db = connect(path, True)
        try:
            if metadata(db, "format") != FORMAT:
                raise EvidenceError(Code.CorruptIndex, "index format mismatch")
            reader_limits = Limits(**metadata(db, "limits"))
            reader_limits.validate()
            db.execute("PRAGMA cache_size=-"+str(max(1024, min(65536, reader_limits.memory_bytes//16//1024))))
            if db.execute("PRAGMA quick_check").fetchone()[0] != "ok" or state_digest(db) != metadata(db, "digest"):
                raise EvidenceError(Code.CorruptIndex, "integrity digest")
            result = cls(path, db)
            result.validate()
            return result
        except (sqlite3.Error, ValueError, KeyError, TypeError) as error:
            db.close()
            raise EvidenceError(Code.CorruptIndex, "invalid persisted records") from error
        except Exception:
            db.close()
            raise

    @classmethod
    def create(cls, path, root, repository, limits=Limits(), rules=None, failpoint=None):
        path = Path(path).absolute()
        directory(path.parent)
        if path.exists() or path.is_symlink():
            raise EvidenceError(Code.PublicationConflict, "index already exists")
        return cls._build(path, root, repository, limits, rules or {"version": VERSION, "effects": []}, None, failpoint)

    @classmethod
    def update(cls, path, rules=None, failpoint=None, rebuild=False):
        old = cls.open_existing(path)
        try:
            return cls._build(Path(path).absolute(), metadata(old.db, "root"), metadata(old.db, "repository"),
                              old.limits, rules if rules is not None else metadata(old.db, "rules"),
                              old, failpoint, rebuild)
        finally:
            old.close()

    @classmethod
    def _build(cls, path, root, repository, limits, rules, old, failpoint, rebuild=False):
        limits.validate()
        root = directory(root)
        if not isinstance(repository, str) or not repository or len(repository) > 200:
            raise EvidenceError(Code.InvalidEvidence, "repository identity")
        repository_ref = ref(RepositoryRef, repository)
        paths, findings = inventory(root, limits)
        repository_roots = repositories(root, paths, repository)
        if any(f["code"] == Code.UnsafePath.value for f in findings):
            raise EvidenceError(Code.UnsafePath, "inventory contains unsafe entries")
        manifests = {}
        import tomllib
        for p, language in paths:
            if Path(p).name not in {"Cargo.toml", "package.json", "pyproject.toml"}:
                continue
            raw, _ = observe(root, p, limits)
            try:
                declaration = json.loads(raw) if language == "json" else tomllib.loads(raw.decode())
                package = declaration if language == "json" else declaration.get("package", declaration.get("project", {}))
                name = package.get("name", "<workspace>")
                if not isinstance(name, str) or not re.fullmatch(r"[\w@/<>.-]{1,200}", name):
                    raise EvidenceError(Code.InvalidEvidence, "package name")
                manifests[p] = name
            except ValueError as error:
                raise EvidenceError(Code.ParseFailure, p) from error
        packages = {}
        fd, candidate = tempfile.mkstemp(prefix=".source-evidence-", suffix=".db", dir=path.parent)
        os.close(fd)
        db = connect(candidate)
        db.executescript(SCHEMA)
        analyzer_changed = old is not None and any(
            json.loads(row[0]).get("implementation") != ANALYZER_DIGEST
            for row in old.db.execute("SELECT DISTINCT adapter FROM files"))
        # A changed analyzer invalidates its parse products. Bulk reconstruction
        # avoids copying then deleting the complete old index. Ordinary source
        # edits continue to use indexed incremental replacement.
        incremental = old is not None and not rebuild and not analyzer_changed
        db.execute("PRAGMA cache_size=-"+str(max(1024, min(262144, limits.memory_bytes//4//1024))))
        if incremental:
            old.db.backup(db)
            db.execute("DELETE FROM meta")
            db.execute("DELETE FROM packages")
        db.executescript(ACCESS_INDEXES)
        started, analyzed, count_symbols, count_edges = time.monotonic(), 0, 0, 0
        expected = metadata(old.db, "digest") if old else None
        worker, validated = None, None
        visited, changed_owners, changed_files = set(), set(), set()
        try:
            for p, language in paths:
                check_memory(limits)
                raw, sha = observe(root, p, limits)
                fid = ref(SourceFileRef, repository_ref.value, p).value
                visited.add(fid)
                boundary = max((b for b in repository_roots if b == "." or p.startswith(b+"/")), key=len)
                file_repository = RepositoryRef(repository_roots[boundary])
                owner, manifest = owner_for(p, manifests, file_repository, boundary)
                packages[owner] = manifest
                db.execute("INSERT OR IGNORE INTO packages VALUES (?,?,?,?)",
                           (owner, manifest, manifests.get(manifest, "<root>"), file_repository.value))
                previous = old.db.execute("SELECT * FROM files WHERE id=?", (fid,)).fetchone() if old else None
                adapter = provenance(language)
                if (not rebuild and previous and previous["digest"] == sha and previous["owner"] == owner
                        and json.loads(previous["adapter"]) == adapter):
                    analysis = unpack(previous["analysis"])
                else:
                    if failpoint == "parse":
                        raise EvidenceError(Code.ParseFailure, "injected")
                    worker = worker or ParserWorker(limits)
                    analysis = worker.analyze(language, p, raw, fid, owner)
                    analyzed += 1
                if failpoint == "resolution":
                    raise EvidenceError(Code.ResolutionFailure, "injected")
                count_symbols += len(analysis["symbols"])
                count_edges += len(analysis["edges"])
                if count_symbols > limits.symbols or count_edges > limits.edges:
                    raise EvidenceError(Code.ResourceLimitExceeded, "index cardinality")
                unchanged = (incremental and previous and previous["digest"] == sha and previous["owner"] == owner
                             and json.loads(previous["adapter"]) == adapter)
                if unchanged:
                    continue
                changed_files.add(fid)
                changed_owners.add(owner)
                if previous:
                    changed_owners.add(previous["owner"])
                if incremental:
                    cls._remove_file(db, fid)
                db.execute("INSERT INTO files VALUES (?,?,?,?,?,?,?)", (fid, p, language, owner, sha,
                           canonical(adapter), pack(analysis)))
                for symbol in analysis["symbols"]:
                    db.execute("INSERT INTO symbols VALUES (?,?,?,?,?)", (symbol["id"], fid, symbol["name"],
                               symbol["body_digest"], pack(symbol)))
                for type_ in analysis["types"]:
                    db.execute("INSERT INTO types VALUES (?,?,?)", (type_["id"], fid, pack(type_)))
            if failpoint == "index":
                raise EvidenceError(Code.InvalidEvidence, "injected")
            if worker:
                worker.close()
                worker = None  # Never retain an idle parser beside a compiler.
            for row in list(db.execute("SELECT id,owner FROM files")):
                if row["id"] not in visited:
                    changed_files.add(row["id"])
                    changed_owners.add(row["owner"])
                    cls._remove_file(db, row["id"])
            # Changed declarations can resolve previously-unresolved names in the
            # same package. Include importers/reexports through persisted reverse edges.
            affected = {r["id"] for r in db.execute("SELECT id,owner FROM files") if r["owner"] in changed_owners}
            compiler_config = rules.get("rust_compiler")
            if old and metadata(old.db, "rules").get("rust_compiler") != compiler_config:
                affected.update(r[0] for r in db.execute("SELECT id FROM files WHERE language='rust'"))
            ts_config = rules.get("typescript_compiler")
            if old and metadata(old.db, "rules").get("typescript_compiler") != ts_config:
                affected.update(r[0] for r in db.execute("SELECT id FROM files WHERE language IN ('typescript','tsx','javascript','vue')"))
            if incremental and affected != visited:
                # Group old symbol targets once. A LEFT JOIN with an OR across
                # target/file prevents the reverse index from being used and
                # otherwise scans all edges once per changed file.
                symbols_by_file = {}
                for symbol in old.db.execute("SELECT id,file FROM symbols"):
                    symbols_by_file.setdefault(symbol["file"], []).append(symbol["id"])
                todo = deque(changed_files | affected)
                seen = set(todo)
                while todo:
                    target_file = todo.popleft()
                    targets = [target_file, *symbols_by_file.get(target_file, [])]
                    for start in range(0, len(targets), 256):
                        batch = targets[start:start+256]
                        sql = "SELECT DISTINCT file FROM edges WHERE target IN ("+",".join("?" for _ in batch)+")"
                        for r in old.db.execute(sql, batch):
                            if r[0] not in seen:
                                seen.add(r[0]); todo.append(r[0])
                                if r[0] in visited:
                                    affected.add(r[0])
            for fid in affected:
                db.execute("DELETE FROM edges WHERE file=?", (fid,))
            cls._resolve(db, limits, affected)
            compiler_measurements = {}
            if compiler_config:
                from .compiler import enrich_rust
                compiler_measurements = enrich_rust(db, root, limits, affected, compiler_config)
            ts_measurements = {}
            if ts_config:
                from .compiler import enrich_typescript
                ts_measurements = enrich_typescript(db, root, limits, affected, ts_config)
            if compiler_config or ts_config:
                from .compiler import normalize_targets
                normalize_targets(db, limits, affected)
            if db.execute("SELECT count(*) FROM edges").fetchone()[0] > limits.edges:
                raise EvidenceError(Code.ResourceLimitExceeded, "resolved index edge count")
            effect_files = None if old and metadata(old.db, "rules") != rules else affected
            cls._effects(db, rules, effect_files)
            meta = {"format": FORMAT, "package_version": VERSION, "root": str(root), "repository": repository,
                    "repository_ref": repository_ref.value, "repository_roots": repository_roots,
                    "packages": packages, "limits": asdict(limits),
                    "rules": rules, "findings": findings,
                    "measurements": {"files_analyzed": analyzed, "files_reresolved": len(affected),
                                     "publication_mode": "incremental" if incremental else "reconstruction",
                                     "rust_compiler": compiler_measurements,
                                     "typescript_compiler": ts_measurements,
                                     "duration_seconds": time.monotonic() - started}}
            for key, value in meta.items():
                db.execute("INSERT INTO meta VALUES (?,?)", (key, canonical(value)))
            # Recheck the complete observed input set. This is a byte-validation pass, not reanalysis.
            if inventory(root, limits)[0] != paths:
                raise EvidenceError(Code.SourceChangedDuringAnalysis, "inventory changed")
            if repositories(root, paths, repository) != repository_roots:
                raise EvidenceError(Code.SourceChangedDuringAnalysis, "repository ownership changed")
            for row in db.execute("SELECT path,digest FROM files ORDER BY path"):
                if observe(root, row[0], limits)[1] != row[1]:
                    raise EvidenceError(Code.SourceChangedDuringAnalysis, row[0])
            if implementation_digest() != ANALYZER_DIGEST:
                raise EvidenceError(Code.SourceChangedDuringAnalysis, "analyzer changed during execution")
            db.execute("INSERT INTO meta VALUES ('digest',?)", (canonical(state_digest(db)),))
            if failpoint == "persistence":
                raise EvidenceError(Code.InternalFailure, "injected persistence failure")
            db.commit()
            db.close()
            validated = cls.open_existing(candidate)
            if failpoint == "before_publish":
                raise EvidenceError(Code.InternalFailure, "injected before publication")
            with open(candidate, "rb") as stream:
                os.fsync(stream.fileno())
            # A lock is used only for CAS publication, never while parsing.
            lock = os.open(str(path) + ".lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
            try:
                fcntl.flock(lock, fcntl.LOCK_EX)
                current = None
                if path.exists():
                    with cls.open_existing(path) as existing:
                        current = metadata(existing.db, "digest")
                if current != expected:
                    raise EvidenceError(Code.PublicationConflict, "another writer published")
                os.replace(candidate, path)
                directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
            finally:
                os.close(lock)
            # The validated reader already pins precisely the published inode.
            # Reopening would repeat the entire integrity scan and could race a
            # subsequent writer. Rename changes location, not this snapshot.
            validated.path = path
            result, validated = validated, None
            return result
        finally:
            if validated:
                validated.close()
            if worker:
                worker.close()
            db.close()
            if os.path.exists(candidate):
                os.unlink(candidate)  # only this invocation's unpublished file

    @staticmethod
    def _remove_file(db, file_id):
        db.execute("DELETE FROM effects WHERE source IN (SELECT id FROM symbols WHERE file=?)", (file_id,))
        db.execute("DELETE FROM edges WHERE file=?", (file_id,))
        db.execute("DELETE FROM symbols WHERE file=?", (file_id,))
        db.execute("DELETE FROM types WHERE file=?", (file_id,))
        db.execute("DELETE FROM files WHERE id=?", (file_id,))

    @staticmethod
    def _resolve(db, limits, file_ids=None):
        paths = {row["path"]: row["id"] for row in db.execute("SELECT id,path FROM files")}
        for row in db.execute("SELECT id,path,owner,analysis FROM files ORDER BY id"):
            if file_ids is not None and row["id"] not in file_ids:
                continue
            data = unpack(row["analysis"])
            module_bindings = {}
            for ordinal, item in enumerate(data["edges"]):
                targets = item["targets"]
                resolution = item["resolution"]
                module = item.get("module", "")
                if item["kind"] in {"Import", "Module", "Include"}:
                    if item["kind"] == "Module":
                        base = posixpath.dirname(row["path"]) if posixpath.basename(row["path"]) in {"lib.rs", "main.rs", "mod.rs"} else row["path"][:-3]
                        candidates = [base + "/" + item["name"] + ".rs", base + "/" + item["name"] + "/mod.rs"]
                    elif module.startswith(".") or item["kind"] == "Include":
                        base = posixpath.normpath(posixpath.join(posixpath.dirname(row["path"]), module))
                        candidates = [base, *[base+suffix for suffix in [".ts", ".tsx", ".mts", ".cts", ".js", ".mjs", ".cjs", ".vue", ".rs", "/index.ts", "/index.js"]]]
                    elif module.startswith("crate::") and "{" not in module:
                        manifest = db.execute("SELECT manifest FROM packages WHERE id=?", (row["owner"],)).fetchone()[0]
                        base = posixpath.join(posixpath.dirname(manifest or ""), "src", *module.split("::")[1:-1])
                        candidates = [base+".rs", base+"/mod.rs", base+"/lib.rs"]
                    else:
                        candidates = []
                    targets = sorted({paths[p] for p in candidates if p in paths})
                    resolution = "Resolved" if len(targets) == 1 else "CandidateTargets" if targets else "Unresolved"
                    for alias in item.get("aliases", []):
                        module_bindings[alias["local"]] = [(fid, alias["name"]) for fid in targets]
                if item["kind"] == "Call" and item["name"].isidentifier():
                    candidates = list(db.execute("SELECT id,data FROM symbols WHERE file=? AND name=? ORDER BY id",
                                                (row["id"], item["name"])))
                    targets = [c["id"] for c in candidates]
                    # Only free same-module declarations are eligible for direct binding.
                    # Compiler-dependent member/trait calls remain unresolved/candidate sets.
                    exact = [c for c in candidates if unpack(c["data"])["qualified"] == item["name"]]
                    source_row = db.execute("SELECT data FROM symbols WHERE id=?", (item["source"],)).fetchone()
                    source_scope = unpack(source_row[0])["qualified"] if source_row else ""
                    resolution = "Resolved" if len(exact) == 1 and len(candidates) == 1 and not unpack(exact[0]["data"]).get("attributes") and not item.get("shadowed") and "::" not in source_scope else (
                        "CandidateTargets" if targets else "Unresolved")
                    if not targets:
                        for imported_file, imported_name in module_bindings.get(item["name"], []):
                            targets.extend(c[0] for c in db.execute("SELECT id FROM symbols WHERE file=? AND name=? ORDER BY id", (imported_file, imported_name)))
                        resolution = "CandidateTargets" if targets else "Unresolved"
                elif item["kind"] == "Call" and re.fullmatch(r"(?:self|Self)[.:]+\w+", item["name"]):
                    source_row = db.execute("SELECT data FROM symbols WHERE id=?", (item["source"],)).fetchone()
                    if source_row:
                        source = unpack(source_row[0])
                        enclosing = source["qualified"].rsplit("::", 1)[0]
                        name = re.split(r"[.:]+", item["name"])[-1]
                        targets = [r["id"] for r in db.execute("SELECT id,data FROM symbols WHERE name=? AND file=? ORDER BY id", (name, row["id"]))
                                   if unpack(r["data"])["qualified"] == enclosing+"::"+name]
                        resolution = "CandidateTargets" if targets else "Unresolved"
                if len(targets) > limits.result_size:
                    raise EvidenceError(Code.ResourceLimitExceeded, "dispatch targets")
                for target in targets or [None]:
                    edge = {**item, "target": target, "resolution": resolution, "file": row["id"]}
                    edge["id"] = digest([row["id"], ordinal, target])
                    db.execute("INSERT INTO edges VALUES (?,?,?,?,?,?,?)", (edge["id"], edge["source"], target,
                               edge["kind"], resolution, row["id"], pack(edge)))

    @staticmethod
    def _effects(db, rules, file_ids=None):
        # Rule witnesses must be exact source revisions. No filename/word/confidence rules.
        declared = {item["symbol"]: item for item in rules.get("effects", [])}
        if len(declared) != len(rules.get("effects", [])):
            raise EvidenceError(Code.InvalidEvidence, "duplicate effect rule subject")
        for identity, rule in declared.items():
            witness = db.execute("SELECT body_digest FROM symbols WHERE id=?", (identity,)).fetchone()
            if witness is None or witness[0] != rule.get("source_digest") or rule.get("kind") not in Effect:
                raise EvidenceError(Code.InvalidEvidence, "effect rule witness missing or stale")
        for row in db.execute("SELECT id,file,body_digest,data FROM symbols ORDER BY id"):
            if file_ids is not None and row["file"] not in file_ids:
                continue
            db.execute("DELETE FROM effects WHERE source=?", (row["id"],))
            symbol = unpack(row["data"])
            if symbol["kind"] == "DataDeclaration":
                # A configuration key is not a potentially executing function.
                # Its adapter explicitly withholds runtime semantics; never
                # inflate StoreEffectIndex with one UNKNOWN per data key.
                continue
            calls = list(db.execute("SELECT data FROM edges WHERE source=? AND kind IN ('Call','Macro')", (row["id"],)))
            rule = declared.get(row["id"])
            kind, basis = "UNKNOWN", "missing_effect_proof"
            if rule:
                if rule.get("source_digest") != row["body_digest"] or rule.get("kind") not in Effect:
                    raise EvidenceError(Code.InvalidEvidence, "effect rule witness mismatch")
                kind, basis = rule["kind"], "explicit_source_rule"
            elif (not calls and not symbol.get("attributes") and symbol.get("parameter_count") == 0
                  and symbol["kind"] == "Function"):
                body = symbol["source"].split("{", 1)[-1].strip()
                if body == "}":
                    kind, basis = "PURE", "empty_function_body"
            record = {"source": row["id"], "kind": kind, "basis": basis,
                      "source_digest": row["body_digest"], "rule_digest": digest(rules),
                      "store": None, "store_resolution": "NotApplicable" if kind in {"PURE", "EXTERNAL_EFFECT"} else "Unresolved",
                      "external_effect": ref(ExternalEffectRef, row["id"]).value if kind == "EXTERNAL_EFFECT" else None}
            record["id"] = digest(record)
            db.execute("INSERT INTO effects VALUES (?,?,?,?)", (record["id"], row["id"], kind, pack(record)))

    def validate(self):
        if self.db.execute("PRAGMA foreign_key_check").fetchone():
            raise EvidenceError(Code.CorruptIndex, "dangling source")
        for endpoint in ["source", "target"]:
            missing = self.db.execute(f"""SELECT 1 FROM edges e
                LEFT JOIN symbols s ON s.id=e.{endpoint}
                LEFT JOIN files f ON f.id=e.{endpoint}
                LEFT JOIN types t ON t.id=e.{endpoint}
                WHERE e.{endpoint} IS NOT NULL AND s.id IS NULL AND f.id IS NULL AND t.id IS NULL LIMIT 1""").fetchone()
            if missing:
                raise EvidenceError(Code.CorruptIndex, "dangling edge")
        if self.db.execute("SELECT 1 FROM edges WHERE resolution='Resolved' AND target IS NULL LIMIT 1").fetchone():
            raise EvidenceError(Code.CorruptIndex, "resolved edge missing target")
        if self.db.execute("SELECT 1 FROM files f LEFT JOIN packages p ON f.owner=p.id WHERE p.id IS NULL LIMIT 1").fetchone():
            raise EvidenceError(Code.CorruptIndex, "missing package owner")
        if self.db.execute("SELECT 1 FROM effects e LEFT JOIN symbols s ON e.source=s.id WHERE s.id IS NULL LIMIT 1").fetchone():
            raise EvidenceError(Code.CorruptIndex, "effect source missing")

    def symbol(self, subject):
        if not isinstance(subject, SymbolRef):
            raise EvidenceError(Code.InvalidEvidence, "SymbolRef required")
        row = self.db.execute("SELECT data FROM symbols WHERE id=?", (subject.value,)).fetchone()
        if row is None:
            raise EvidenceError(Code.InvalidEvidence, "symbol not in baseline")
        return unpack(row[0])

    def type(self, subject):
        if not isinstance(subject, TypeRef):
            raise EvidenceError(Code.InvalidEvidence, "TypeRef required")
        row = self.db.execute("SELECT data FROM types WHERE id=?", (subject.value,)).fetchone()
        if row is None:
            raise EvidenceError(Code.InvalidEvidence, "type not in baseline")
        return unpack(row[0])

    def find_symbols(self, name, limit=128, path=None):
        if path is not None:
            file = self.inspect_file(path)
            return self._rows("SELECT data FROM symbols WHERE name=? AND file=? ORDER BY id", (name, file["id"]), limit)
        return self._rows("SELECT data FROM symbols WHERE name=? ORDER BY id", (name,), limit)

    def inspect_file(self, path):
        row = self.db.execute("SELECT id,path,language,owner,digest,adapter FROM files WHERE path=?", (path,)).fetchone()
        if row is None:
            raise EvidenceError(Code.InvalidEvidence, "file not indexed")
        return dict(row)

    def source_evidence(self, subject):
        if isinstance(subject, SymbolRef):
            return self.symbol(subject)
        if not isinstance(subject, SourceFileRef):
            raise EvidenceError(Code.InvalidEvidence, "SymbolRef or SourceFileRef required")
        self._source_subject(subject)
        row = self.db.execute("SELECT * FROM files WHERE id=?", (subject.value,)).fetchone()
        analysis = unpack(row["analysis"])
        return {"id": row["id"], "file": row["id"], "owner": row["owner"], "name": row["path"],
                "kind": "SourceUnit", "line": 1, "body_digest": row["digest"],
                "source": analysis["module_source"], "resolution": "PartiallyResolved",
                "adapter_coverage": analysis["coverage"],
                "missing": [*analysis["missing"], "top_level_effect_inference"]}

    def _rows(self, sql, args, limit=None):
        limit = self.limits.result_size if limit is None else limit
        if not 0 <= limit <= self.limits.result_size:
            raise EvidenceError(Code.ResourceLimitExceeded, "query result limit")
        rows = list(self.db.execute(sql + " LIMIT ?", (*args, limit + 1)))
        if len(rows) > limit:
            raise EvidenceError(Code.ResourceLimitExceeded, "query requires narrower selection")
        return [unpack(row[0]) for row in rows]

    def dependencies_of(self, subject):
        self._source_subject(subject)
        return self._rows("SELECT data FROM edges WHERE source=? ORDER BY id", (subject.value,))

    def dependents_of(self, subject):
        self._source_subject(subject)
        return self._rows("SELECT data FROM edges WHERE target=? ORDER BY id", (subject.value,))

    def effects_of(self, subject):
        self.symbol(subject)
        return self._rows("SELECT data FROM effects WHERE source=? ORDER BY id", (subject.value,))

    def reads_of(self, subject):
        return [e for e in self.effects_of(subject) if e["kind"] in {"READ", "RECEIPT_READ"}]

    def writes_of(self, subject):
        return [e for e in self.effects_of(subject) if e["kind"].startswith("WRITE") or e["kind"] == "RECEIPT_WRITE"]

    def owners_of(self, subject):
        self._source_subject(subject)
        if isinstance(subject, SourceFileRef):
            file_id = subject.value
        else:
            file_id = (self.symbol(subject) if isinstance(subject, SymbolRef) else self.type(subject))["file"]
        owner = self.db.execute("SELECT owner FROM files WHERE id=?", (file_id,)).fetchone()[0]
        package = dict(self.db.execute("SELECT * FROM packages WHERE id=?", (owner,)).fetchone())
        return {"repository": package["repository"], "package": owner,
                "repository_path": next(p for p, r in metadata(self.db, "repository_roots").items() if r == package["repository"]),
                "manifest": package["manifest"], "package_name": package["name"]}

    def _source_subject(self, subject):
        table = {SymbolRef: "symbols", SourceFileRef: "files", TypeRef: "types"}.get(type(subject))
        if table is None or not self.db.execute(f"SELECT 1 FROM {table} WHERE id=?", (subject.value,)).fetchone():
            raise EvidenceError(Code.InvalidEvidence, "indexed SymbolRef, SourceFileRef or TypeRef required")

    def _traverse(self, refs, reverse, max_depth, max_nodes, max_edges):
        if not 0 <= max_depth <= self.limits.traversal_depth or not 1 <= max_nodes <= self.limits.result_size or not 1 <= max_edges <= self.limits.result_size:
            raise EvidenceError(Code.ResourceLimitExceeded, "traversal bounds")
        seen, edges, queue, omitted = set(), {}, deque((r, 0) for r in sorted(set(refs))), False
        while queue:
            node, depth = queue.popleft()
            if node in seen:
                continue
            if len(seen) >= max_nodes:
                omitted = True
                break
            seen.add(node)
            column = "target" if reverse else "source"
            for row in self.db.execute(f"SELECT data FROM edges WHERE {column}=? ORDER BY id", (node,)):
                edge = unpack(row[0])
                if len(edges) >= max_edges:
                    omitted = True
                    break
                edges[edge["id"]] = edge
                target = edge["source"] if reverse else edge["target"]
                if target and target not in seen:
                    if depth < max_depth:
                        queue.append((target, depth + 1))
                    else:
                        omitted = True
        return {"status": "Partial" if omitted else "Complete", "subjects": sorted(seen),
                "edges": sorted(edges.values(), key=lambda e: e["id"])}

    def transitive_dependencies(self, subject, max_depth=4, max_nodes=256, max_edges=1024):
        self._source_subject(subject)
        return self._traverse([subject.value], False, max_depth, max_nodes, max_edges)

    def transitive_dependents(self, subject, max_depth=4, max_nodes=256, max_edges=1024):
        self._source_subject(subject)
        return self._traverse([subject.value], True, max_depth, max_nodes, max_edges)

    def affected_by(self, changed_refs, max_depth=8, max_nodes=4096, max_edges=4096):
        return self._traverse([r.value for r in changed_refs], True, max_depth, max_nodes, max_edges)

    def evidence_revision(self, subject):
        symbol = self.source_evidence(subject)
        forward = self.transitive_dependencies(subject, max_depth=self.limits.traversal_depth,
                                               max_nodes=self.limits.result_size, max_edges=self.limits.result_size)
        reverse = self.dependents_of(subject)
        ids = sorted(set(forward["subjects"]) | {e["source"] for e in reverse})
        inputs = {}
        files = set()
        for identity in ids:
            for table in ["symbols", "types"]:
                row = self.db.execute(f"SELECT file,data FROM {table} WHERE id=?", (identity,)).fetchone()
                if row:
                    inputs[table + ":" + identity] = digest(unpack(row["data"]))
                    file = self.db.execute("SELECT * FROM files WHERE id=?", (row["file"],)).fetchone()
                    files.add(file["id"])
                    inputs["file:" + file["id"]] = file["digest"]
                    inputs["adapter:" + file["id"]] = digest(json.loads(file["adapter"]))
                    manifest = metadata(self.db, "packages")[file["owner"]]
                    if manifest:
                        inputs["manifest:" + file["owner"]] = self.inspect_file(manifest)["digest"]
                        for lock in ["Cargo.lock", "pnpm-lock.yaml", "package-lock.json"]:
                            lock_path = posixpath.join(posixpath.dirname(manifest), lock)
                            lock_row = self.db.execute("SELECT id,digest FROM files WHERE path=?", (lock_path,)).fetchone()
                            if lock_row:
                                inputs["lock:" + lock_row["id"]] = lock_row["digest"]
            if self.db.execute("SELECT 1 FROM files WHERE id=?", (identity,)).fetchone():
                files.add(identity)
        # Imports belong to files, not necessarily to the selected function.
        # Record their exact declarations and transitive module inputs so an
        # import/reexport edit cannot leave a reusable-looking stale packet.
        pending, seen = deque(sorted(files)), set()
        while pending:
            fid = pending.popleft()
            if fid in seen:
                continue
            if len(seen) >= self.limits.result_size:
                raise EvidenceError(Code.ResourceLimitExceeded, "revision module input set")
            seen.add(fid)
            file = self.db.execute("SELECT digest,adapter FROM files WHERE id=?", (fid,)).fetchone()
            inputs["file:"+fid] = file["digest"]
            inputs["adapter:"+fid] = digest(json.loads(file["adapter"]))
            declarations = self._rows("SELECT data FROM edges WHERE file=? AND kind IN ('Import','Module','Include') ORDER BY id", (fid,))
            inputs["module_edges:"+fid] = digest(declarations)
            for edge in declarations:
                if edge["target"] and self.db.execute("SELECT 1 FROM files WHERE id=?", (edge["target"],)).fetchone():
                    pending.append(edge["target"])
        return {"subject": subject.value, "inputs": inputs, "rules": digest(metadata(self.db, "rules")),
                "dependencies": digest(forward["edges"]), "reverse": digest(reverse),
                "effects": digest(self.effects_of(subject)) if isinstance(subject, SymbolRef) else digest({"resolution": "Unresolved", "source": symbol["body_digest"]}),
                "complete": forward["status"] == "Complete",
                "resolution_complete": not symbol["missing"] and all(e["resolution"] == "Resolved" for e in forward["edges"])}

    def evidence_digest(self, subject):
        return digest(self.evidence_revision(subject))

    def build_packet(self, subject, limits=PacketLimits(), continuation=None):
        from .packet import build_packet
        return build_packet(self, subject, limits, continuation)

    def request_evidence(self, request: EvidenceRequest, continuation=None):
        if not isinstance(request, EvidenceRequest):
            raise EvidenceError(Code.InvalidEvidence, "EvidenceRequest required")
        if any(not isinstance(r, Relation) for r in request.relations) or any(not isinstance(e, Effect) for e in request.effects):
            raise EvidenceError(Code.InvalidEvidence, "typed evidence selectors required")
        from .packet import build_packet
        return build_packet(self, request.subject, request.limits, continuation, request.relations, request.effects)

    def assess(self, subject, required_effects=(), required_targets=()):
        """Evidence availability, not classification policy or execution permission."""
        known = {e["kind"] for e in self.effects_of(subject) if e["kind"] != "UNKNOWN"}
        calls = self.dependencies_of(subject)
        resolved = {e["target"] for e in calls if e["resolution"] == "Resolved"}
        missing = ["effect:" + e for e in required_effects if e not in known]
        missing += ["target:" + t.value for t in required_targets if t.value not in resolved]
        return {"status": "NeedEvidence" if missing else "Observed", "missing": missing,
                "evidence_digest": self.evidence_digest(subject), "authority": False}

    def index_status(self):
        return {"format": FORMAT, "digest": metadata(self.db, "digest"),
                "repository": metadata(self.db, "repository"), "read_only": True}

    def stats(self):
        result = {t: self.db.execute(f"SELECT count(*) FROM {t}").fetchone()[0] for t in ["files", "symbols", "types", "edges", "effects"]}
        result.update(metadata(self.db, "measurements"))
        result["language_distribution"] = dict(self.db.execute("SELECT language,count(*) FROM files GROUP BY language"))
        result["edge_resolution"] = dict(self.db.execute("SELECT resolution,count(*) FROM edges GROUP BY resolution"))
        result["index_bytes"] = self.db.execute("PRAGMA page_count").fetchone()[0] * self.db.execute("PRAGMA page_size").fetchone()[0]
        return result

    def doctor(self):
        findings = list(metadata(self.db, "findings"))
        root = metadata(self.db, "root")
        current, unsafe = inventory(root, self.limits)
        findings.extend(unsafe)
        if repositories(root, current, metadata(self.db, "repository")) != metadata(self.db, "repository_roots"):
            findings.append({"code": "StaleIndex", "detail": "repository ownership mismatch"})
        stored = {r[0]: r[1] for r in self.db.execute("SELECT path,digest FROM files")}
        if set(stored) != {p for p, _ in current}:
            findings.append({"code": "StaleIndex", "detail": "inventory mismatch"})
        for path, lang in current:
            if observe(root, path, self.limits)[1] != stored.get(path):
                findings.append({"code": "StaleIndex", "path": path})
            adapter = self.db.execute("SELECT adapter FROM files WHERE path=?", (path,)).fetchone()
            if adapter and json.loads(adapter[0]) != provenance(lang):
                findings.append({"code": "StaleIndex", "path": path, "detail": "analyzer changed"})
        findings.append({"code": "UnsupportedDynamicResolution", "detail": "syntax adapters do not prove compiler dispatch"})
        rules = metadata(self.db, "rules")
        for tool, fields in {"rust_compiler": [("executable", "sha256")],
                             "typescript_compiler": [("module", "sha256"), ("node", "node_sha256")]}.items():
            config = rules.get(tool)
            if not config:
                continue
            for path_field, digest_field in fields:
                path = Path(config[path_field])
                if not path.is_file():
                    findings.append({"code": "AnalyzerUnavailable", "detail": tool+":"+path_field})
                elif digest(path.read_bytes()) != config[digest_field]:
                    findings.append({"code": "StaleIndex", "detail": tool+":artifact changed"})
        return findings

    def diff(self, previous, limit=128, continuation=None):
        if not 1 <= limit <= self.limits.result_size:
            raise EvidenceError(Code.ResourceLimitExceeded, "diff page size")
        baseline = [previous.index_status()["digest"], self.index_status()["digest"]]
        if continuation and continuation.get("baselines") != baseline:
            raise EvidenceError(Code.StaleIndex, "diff continuation")
        after = continuation.get("after", "") if continuation else ""
        if not isinstance(after, str):
            raise EvidenceError(Code.InvalidEvidence, "diff cursor")
        def merge(table, column, start=""):
            a = iter(previous.db.execute(f"SELECT id,{column} FROM {table} WHERE id>? ORDER BY id", (start,)))
            b = iter(self.db.execute(f"SELECT id,{column} FROM {table} WHERE id>? ORDER BY id", (start,)))
            x, y = next(a, None), next(b, None)
            while x is not None or y is not None:
                if y is None or (x is not None and x[0] < y[0]):
                    yield x[0], x[1], None
                    x = next(a, None)
                elif x is None or y[0] < x[0]:
                    yield y[0], None, y[1]
                    y = next(b, None)
                else:
                    yield x[0], x[1], y[1]
                    x, y = next(a, None), next(b, None)
        def differences(table):
            added = removed = 0
            for _, a, b in merge(table, "data"):
                if a != b:
                    added += b is not None
                    removed += a is not None
            return {"added": added, "removed": removed}
        result = {"added_symbols": [], "removed_symbols": [], "changed_symbols": [], "invalidated_packets": [],
                  "status": "Complete", "continuation": None}
        count, last = 0, after
        for identity, a, b in merge("symbols", "body_digest", after):
            if count == limit:
                result.update(status="Partial", continuation={"baselines": baseline, "after": last})
                break
            count, last = count+1, identity
            if a is None:
                result["added_symbols"].append(identity)
            elif b is None:
                result["removed_symbols"].append(identity)
            else:
                if a != b:
                    result["changed_symbols"].append(identity)
                if self.evidence_digest(SymbolRef(identity)) != previous.evidence_digest(SymbolRef(identity)):
                    result["invalidated_packets"].append(identity)
        result.update(changed_dependencies=differences("edges"), changed_effects=differences("effects"))
        return result
