"""Acceptance journeys assert content and identities, never just exit status."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from zixcel_source_evidence import Index, Limits, PacketLimits, SymbolRef, EvidenceError


class EvidenceJourney(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name, "source")
        self.root.mkdir()
        self.storage = Path(self.temp.name, "evidence.db")
        self.put("Cargo.toml", '[package]\nname="fixture"\nversion="0.10.0"\n')
        self.put("src/lib.rs", 'pub fn callee() -> u32 { 1 }\npub fn caller() -> u32 { callee() }\n')

    def put(self, name, text):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def build(self, **options):
        return Index.create(self.storage, self.root, "fixture", **options)

    def symbol(self, index, name):
        return SymbolRef(index.find_symbols(name)[0]["id"])

    def test_revision_restart_incremental_reverse_and_unrelated(self):
        first = self.build()
        caller, callee = self.symbol(first, "caller"), self.symbol(first, "callee")
        before = first.evidence_digest(caller)
        self.assertTrue(any(e["target"] == callee.value and e["resolution"] == "Resolved"
                            for e in first.dependencies_of(caller)))
        self.assertTrue(any(e["source"] == caller.value for e in first.dependents_of(callee)))
        reopened = Index.open_existing(self.storage)
        self.assertEqual(reopened.evidence_digest(caller), before)
        self.put("unrelated.rs", "fn other() {}")
        second = Index.update(self.storage)
        self.assertEqual(second.evidence_digest(caller), before)
        self.assertEqual(second.stats()["files_analyzed"], 1)
        self.put("src/lib.rs", 'pub fn callee() -> u32 { 2 }\npub fn caller() -> u32 { callee() }\n')
        third = Index.update(self.storage)
        self.assertNotEqual(third.evidence_digest(caller), before)
        self.assertEqual(first.evidence_digest(caller), before)  # reader pinned to old inode
        self.assertIn(caller.value, third.diff(second)["invalidated_packets"])
        self.assertIn(caller.value, third.affected_by([callee])["subjects"])

    def test_language_symbols_partial_dispatch_and_secrets(self):
        self.put("frontend.ts", 'export function run() { return target() }\nfunction target() { return 2 }\nclass Service { fetch() { return client.send() } }\n')
        self.put("page.vue", '<template><Child /></template><script setup lang="ts">import Child from "./Child.vue"; function refresh() { return store.read() }</script>')
        self.put("tool.py", 'def calculate():\n    return 1\n')
        self.put("run.sh", 'deploy() { curl https://example.invalid; }\n')
        self.put("secret.rs", 'fn secret() { let token = "super-private-credential"; unknown(token); }')
        self.put("migration.sql", 'CREATE TABLE events (id INTEGER);')
        self.put("contract.d.mts", 'export declare function connect(): void;')
        self.put("BUILD.bazel", 'def configure():\n    repository_rule(name="dependency")\n')
        self.put("page.html", '<html><script>function ready() { return 1 }</script></html>')
        self.put("default.nix", '{ x }: let configured = { token = "private-nix-token"; }; in configured')
        self.put("Makefile", 'check:\n\techo private-recipe-token\n')
        self.put("tool.ps1", 'function Invoke-Test {\nparam($x)\nWrite-Output "private-shell-token"\n}\n')
        self.put("sample.service", '[Service]\nExecStart=/private/command\n')
        self.put("launcher", '#!/bin/sh\nlaunch() { [ $((0$MODE & 0022)) -eq 0 ]; }\n')
        (self.root/"launcher").chmod(0o700)
        index = self.build()
        for name in ["run", "target", "refresh", "calculate", "deploy", "connect", "configure", "ready", "configured", "check", "Invoke-Test", "launch"]:
            self.assertTrue(index.find_symbols(name), name)
        for name in ["run", "refresh", "calculate", "Invoke-Test"]:
            self.assertEqual(index.find_symbols(name)[0]["kind"], "Function")
        for name, secret in [("configured", "private-nix-token"), ("check", "private-recipe-token"), ("Invoke-Test", "private-shell-token")]:
            self.assertNotIn(secret, json.dumps(index.build_packet(self.symbol(index, name))))
        self.assertEqual(index.inspect_file("sample.service")["language"], "ini")
        packet = index.build_packet(self.symbol(index, "secret"))
        self.assertNotIn("super-private-credential", json.dumps(packet))
        edges = index.dependencies_of(self.symbol(index, "refresh"))
        self.assertTrue(any(e["resolution"] == "Unresolved" for e in edges))
        self.assertTrue(any(e["kind"] == "UNKNOWN" for e in index.effects_of(self.symbol(index, "secret"))))

    def test_pure_reads_atomic_failure_corruption_and_stale(self):
        with self.assertRaises(EvidenceError) as missing:
            Index.open_existing(self.storage)
        self.assertEqual(missing.exception.code, "MissingIndex")
        self.assertFalse(self.storage.exists())
        index = self.build()
        baseline = index.index_status()["digest"]
        self.put("src/lib.rs", "fn broken( {")
        self.assertIn("StaleIndex", [f["code"] for f in index.doctor()])
        with self.assertRaises(EvidenceError):
            Index.update(self.storage)
        self.assertEqual(Index.open_existing(self.storage).index_status()["digest"], baseline)
        self.put("src/lib.rs", "fn valid() {}")
        with self.assertRaises(EvidenceError):
            Index.update(self.storage, failpoint="before_publish")
        self.assertEqual(Index.open_existing(self.storage).index_status()["digest"], baseline)
        import sqlite3
        with sqlite3.connect(self.storage) as db:
            db.execute("UPDATE symbols SET body_digest = 'corrupt'")
        with self.assertRaises(EvidenceError) as corrupt:
            Index.open_existing(self.storage)
        self.assertEqual(corrupt.exception.code, "CorruptIndex")

    def test_packet_bounds_continuation_and_path_limits(self):
        index = self.build()
        subject = self.symbol(index, "caller")
        result = index.build_packet(subject, PacketLimits(max_bytes=4096, max_source_bytes=0))
        self.assertEqual(result["status"], "Partial")
        self.assertTrue(result["omitted"])
        self.assertLessEqual(len(json.dumps(result, separators=(",", ":"), sort_keys=True).encode()), 4096)
        with self.assertRaises(EvidenceError):
            index.transitive_dependencies(subject, max_depth=100)
        outside = Path(self.temp.name, "outside.rs")
        outside.write_text("fn forbidden() {}")
        (self.root / "escape.rs").symlink_to(outside)
        with self.assertRaises(EvidenceError) as unsafe:
            Index.update(self.storage)
        self.assertEqual(unsafe.exception.code, "UnsafePath")

    def test_delete_move_rules_and_cli(self):
        first = self.build()
        old = self.symbol(first, "callee")
        (self.root / "src/lib.rs").rename(self.root / "src/moved.rs")
        second = Index.update(self.storage)
        with self.assertRaises(EvidenceError):
            second.symbol(old)
        self.assertIn(old.value, second.diff(first)["removed_symbols"])
        result = subprocess.run([sys.executable, "-m", "zixcel_source_evidence", "stats", str(self.storage)],
                                check=True, capture_output=True, text=True)
        self.assertEqual(json.loads(result.stdout)["symbols"], second.stats()["symbols"])
        third = Index.update(self.storage, rules={"version": "changed", "effects": []})
        self.assertNotEqual(second.index_status()["digest"], third.index_status()["digest"])

    def test_parameter_shadowing_is_not_resolved_to_same_name_function(self):
        self.put("src/lib.rs", "fn target() {} fn run(target: fn()) { target(); }")
        index = self.build()
        calls = [e for e in index.dependencies_of(self.symbol(index, "run")) if e["kind"] == "Call"]
        self.assertEqual(len(calls), 1)
        self.assertNotEqual(calls[0]["resolution"], "Resolved")

    def test_modules_aliases_type_contracts_and_package_rename(self):
        self.put("src/lib.rs", "mod child; pub trait Trait { fn call(&self); } struct Object; impl Trait for Object { fn call(&self) { self.call(); } }\n")
        self.put("src/child.rs", "pub fn value() -> u32 { 1 }")
        self.put("front.ts", 'import { target as alias } from "./service"; export function caller() { return alias() }')
        self.put("service.ts", "export function target(): number { return 1 }")
        first = self.build()
        caller = next(SymbolRef(s["id"]) for s in first.find_symbols("caller") if first.inspect_file("front.ts")["id"] == s["file"])
        edges = first.dependencies_of(caller)
        self.assertTrue(any(e["resolution"] == "CandidateTargets" and e["target"] for e in edges))
        before = first.evidence_digest(caller)
        self.put("service.ts", 'export function target(): string { return "one" }')
        second = Index.update(self.storage)
        self.assertNotEqual(second.evidence_digest(caller), before)
        owner = second.owners_of(caller)["package"]
        self.put("Cargo.toml", '[package]\nname="renamed"\nversion="0.10.0"\n')
        third = Index.update(self.storage)
        self.assertNotEqual(third.owners_of(caller)["package"], owner)

    def test_failure_stages_and_reader_during_candidate_build(self):
        from unittest.mock import patch
        from zixcel_source_evidence.worker import ParserWorker
        from concurrent.futures import ThreadPoolExecutor
        from threading import Event
        index = self.build()
        before = index.index_status()
        self.put("src/lib.rs", "fn changed() {}")
        for stage in ["parse", "resolution", "index", "persistence", "before_publish"]:
            with self.assertRaises(EvidenceError):
                Index.update(self.storage, failpoint=stage)
            with Index.open_existing(self.storage) as reader:
                self.assertEqual(reader.index_status(), before)
        entered, resume = Event(), Event()
        actual = ParserWorker.analyze
        def held(adapter, *args):
            entered.set()
            self.assertTrue(resume.wait(5))
            return actual(adapter, *args)
        with patch.object(ParserWorker, "analyze", held), ThreadPoolExecutor(max_workers=1) as pool:
            def update():
                with Index.update(self.storage) as replacement:
                    return replacement.index_status()
            future = pool.submit(update)
            self.assertTrue(entered.wait(5))
            with Index.open_existing(self.storage) as reader:
                self.assertEqual(reader.index_status(), before)
            resume.set()
            self.assertNotEqual(future.result()["digest"], before["digest"])
        self.assertEqual(index.index_status(), before)

    def test_effect_witnesses_and_negative_architecture(self):
        from zixcel_source_evidence.model import Effect
        first = self.build()
        target = self.symbol(first, "callee")
        body_digest = first.symbol(target)["body_digest"]
        for effect in Effect:
            current = Index.update(self.storage, rules={"version": "exact-witness", "effects": [
                {"symbol": target.value, "source_digest": body_digest, "kind": effect.value}]})
            self.assertEqual(current.effects_of(target)[0]["kind"], effect.value)
            current.close()
        with self.assertRaises(EvidenceError):
            Index.update(self.storage, rules={"version": "invalid", "effects": [
                {"symbol": target.value, "source_digest": "wrong", "kind": "WRITE_CANONICAL"}]})
        import zixcel_source_evidence
        modules = Path(zixcel_source_evidence.__file__).parent
        for source in modules.glob("*.py"):
            content = source.read_text()
            for forbidden in ["import openai", "import sem_lang", "import hatter", "import zixcel_graph"]:
                self.assertNotIn(forbidden, content)

    def test_incremental_matches_full_build_without_reanalyzing_other_package(self):
        self.put("other/Cargo.toml", '[package]\nname="other"\nversion="0.10.0"\n')
        self.put("other/src/lib.rs", "fn isolated() {}")
        first = self.build()
        isolated = self.symbol(first, "isolated")
        before = first.evidence_digest(isolated)
        self.put("src/lib.rs", "fn added() {} fn callee() -> u32 { 3 } fn caller() -> u32 { callee() }")
        incremental = Index.update(self.storage)
        self.assertEqual(incremental.stats()["files_analyzed"], 1)
        self.assertEqual(incremental.evidence_digest(isolated), before)
        self.assertLess(incremental.stats()["files_reresolved"], incremental.stats()["files"])
        with Index.create(Path(self.temp.name, "full.db"), self.root, "fixture") as full:
            self.assertEqual(full.index_status()["digest"], incremental.index_status()["digest"])
        self.put("src/lib.rs", "fn caller() { callee(); }")
        changed = Index.update(self.storage)
        self.assertTrue(any(e["resolution"] == "Unresolved" for e in changed.dependencies_of(self.symbol(changed, "caller"))))

    def test_macro_cfg_include_and_application_code_never_executed(self):
        self.put("build.rs", 'fn main() { panic!("must never run"); }')
        self.put("src/lib.rs", '#[cfg(test)] mod checks { fn test_only() {} }\ninclude!("generated.rs");\n#[custom_effect] fn opaque() {}\nfn drop_guard(_guard: Guard) {}\nfn empty() {}')
        self.put("src/generated.rs", "fn generated() {}")
        index = self.build()
        self.assertIn("#[cfg(test)]", index.symbol(self.symbol(index, "test_only"))["cfg"])
        self.assertEqual(index.effects_of(self.symbol(index, "opaque"))[0]["kind"], "UNKNOWN")
        guard = index.effects_of(self.symbol(index, "drop_guard"))[0]
        self.assertEqual(guard["kind"], "UNKNOWN")  # parameter destruction may perform effects
        self.assertEqual(guard["store_resolution"], "Unresolved")
        self.assertEqual(index.effects_of(self.symbol(index, "empty"))[0]["kind"], "PURE")
        self.assertTrue(index.find_symbols("generated"))
        records = index.db.execute("SELECT resolution FROM edges WHERE kind='Include'").fetchall()
        self.assertEqual([r[0] for r in records], ["Resolved"])
        import multiprocessing
        self.assertEqual(multiprocessing.active_children(), [])

    def test_narrow_requests_filter_before_budget_and_css_container(self):
        from zixcel_source_evidence.model import EvidenceRequest, Relation, Effect
        self.put("screen.css", "@container screen (width > 30px) { .x { color: red; } }")
        self.put("labels.yaml", "safe: secret-value\npackages:\n  nested:\n    version: secret-value\n")
        index = self.build()
        subject = self.symbol(index, "caller")
        result = index.request_evidence(EvidenceRequest(subject, (Relation.Call,), (Effect.UNKNOWN,),
            PacketLimits(max_dependencies=1, max_source_bytes=0)))
        self.assertEqual([e["kind"] for e in result["dependencies"]], ["Call"])
        self.assertEqual(result["effects"][0]["kind"], "UNKNOWN")
        self.assertEqual(index.inspect_file("screen.css")["language"], "css")
        self.assertNotIn("secret-value", json.dumps(index.find_symbols("safe")))
        self.assertFalse(index.find_symbols("nested"))
        self.assertFalse(index.effects_of(self.symbol(index, "safe")))
        with self.assertRaises(EvidenceError):
            index.build_packet(subject, continuation=result["continuation"])

    def test_rust_compiler_source_projection_process_and_artifact_identity(self):
        import os
        from zixcel_source_evidence.model import digest
        executable = os.environ.get("SOURCE_EVIDENCE_RUST_ANALYZER")
        if not executable:
            self.skipTest("SOURCE_EVIDENCE_RUST_ANALYZER artifact not configured")
        config = {"executable": executable, "sha256": digest(Path(executable).read_bytes())}
        self.put("Cargo.toml", '[package]\nname="fixture"\nversion="0.10.0"\nedition="2024"\n')
        self.put("src/lib.rs", 'mod part; struct Store; impl Store { fn read(&self) -> u32 { part::value() } }\nfn run() { let s = Store; s.read(); }')
        self.put("src/part.rs", 'pub fn value() -> u32 { 42 }')
        self.put("build.rs", 'fn main() { panic!("must not execute"); }')
        index = self.build(rules={"version": "0.10.0", "effects": [], "rust_compiler": config})
        edges = index.dependencies_of(self.symbol(index, "run"))
        self.assertTrue(any(e.get("compiler", {}).get("targets") for e in edges))
        self.assertTrue(all(e.get("compiler", {}).get("scope") == "source_only_projection" for e in edges if "compiler" in e))
        self.assertTrue(all(e["compiler"]["edition"] == "2024" for e in edges if "compiler" in e))
        self.assertGreater(index.stats()["rust_compiler"]["source_targets_observed"], 0)
        read = self.symbol(index, "read")
        run = self.symbol(index, "run")
        linked = [e for e in index.dependencies_of(run) if e["target"] == read.value]
        self.assertTrue(linked)
        self.assertTrue(all(e["resolution"] == "CandidateTargets" for e in linked))
        self.assertEqual({e["id"] for e in linked}, {e["id"] for e in index.dependents_of(read) if e["source"] == run.value})
        before = index.evidence_digest(run)
        self.put("src/part.rs", 'pub fn value() -> u32 { 43 }')
        with Index.update(self.storage) as changed:
            self.assertNotEqual(changed.evidence_digest(run), before)
            current_status = changed.index_status()
        config["sha256"] = "invalid"
        with self.assertRaises(EvidenceError):
            Index.update(self.storage, rules={"version": "0.10.0", "effects": [], "rust_compiler": config})
        with Index.open_existing(self.storage) as reopened:
            self.assertEqual(reopened.index_status(), current_status)

    def test_typescript_checker_alias_async_vue_and_dynamic(self):
        import os
        from zixcel_source_evidence.model import digest
        module, node = os.environ.get("SOURCE_EVIDENCE_TYPESCRIPT"), os.environ.get("SOURCE_EVIDENCE_NODE")
        if not module or not node:
            self.skipTest("TypeScript/Node compiler artifacts not configured")
        config = {"module": module, "node": node, "sha256": digest(Path(module).read_bytes()),
                  "node_sha256": digest(Path(node).read_bytes())}
        self.put("front.ts", 'import { value as alias } from "./service"; export async function run() { return alias() }\nfunction dynamic(x:any) { return x.anything() }')
        self.put("service.ts", "export function value(): number { return 1 }")
        self.put("view.vue", '<script setup lang="ts">import { value } from "./service"; function refresh() { value() }</script>')
        index = self.build(rules={"version": "0.10.0", "effects": [], "typescript_compiler": config})
        for name in ["run", "refresh"]:
            edges = index.dependencies_of(self.symbol(index, name))
            self.assertTrue(any(e.get("compiler", {}).get("resolution") == "Resolved" for e in edges), name)
            self.assertTrue(any(e["target"] == self.symbol(index, "value").value for e in edges))
        edges = index.dependencies_of(self.symbol(index, "dynamic"))
        self.assertFalse(any(e.get("compiler", {}).get("targets") for e in edges))

    def test_large_source_continuation_diff_pages_and_import_revisions(self):
        self.put("large.rs", "fn large() {\n"+" let local = 1;\n"*50+"}")
        self.put("front.ts", 'import { value } from "./types"; function use_value() { return value }')
        self.put("types.ts", "export const value = 1;")
        first = self.build()
        subject = self.symbol(first, "large")
        rebuilt, cursor, revision_inputs = "", None, {}
        for _ in range(100):
            packet = first.build_packet(subject, PacketLimits(max_source_bytes=90, max_revision_inputs=1), cursor)
            revision_inputs.update({v["ref"]: v["digest"] for v in packet["revision_inputs"]})
            for item in packet["sources"]:
                if item["symbol"] == subject.value:
                    self.assertEqual(item["offset_bytes"], len(rebuilt.encode()))
                    rebuilt += item["text"]
            cursor = packet["continuation"]
            if not cursor:
                break
        self.assertIsNone(cursor)
        self.assertEqual(rebuilt, first.symbol(subject)["source"])
        self.assertEqual(revision_inputs, first.evidence_revision(subject)["inputs"])
        from zixcel_source_evidence.model import digest
        self.assertEqual(digest(revision_inputs), packet["evidence_revision_set"]["inputs_digest"])
        command = [sys.executable, "-m", "zixcel_source_evidence", "packet", "build", str(self.storage), subject.value, "--max-source-bytes", "90"]
        first_page = json.loads(subprocess.run(command, check=True, capture_output=True, text=True).stdout)
        next_page = json.loads(subprocess.run(command+["--continuation", json.dumps(first_page["continuation"])],
                               check=True, capture_output=True, text=True).stdout)
        self.assertEqual(first_page["evidence_digest"], next_page["evidence_digest"])
        self.assertEqual(next_page["sources"][0]["offset_bytes"], 90)
        use_value = self.symbol(first, "use_value")
        before = first.evidence_digest(use_value)
        self.put("types.ts", "export const value = 2;")
        second = Index.update(self.storage)
        self.assertNotEqual(second.evidence_digest(use_value), before)
        invalidated, cursor = [], None
        for _ in range(30):
            result = second.diff(first, limit=1, continuation=cursor)
            invalidated.extend(result["invalidated_packets"])
            cursor = result["continuation"]
            if not cursor:
                break
        self.assertIsNone(cursor)
        self.assertIn(use_value.value, invalidated)

    def test_incremental_access_paths_and_bounded_compiler_retries(self):
        from zixcel_source_evidence.lsp import RustSession
        from unittest.mock import Mock
        index = self.build()
        import hashlib
        from zixcel_source_evidence.model import canonical, unpack
        from zixcel_source_evidence.index import state_digest
        reference = hashlib.sha256()
        for table in ["files", "symbols", "types", "edges", "effects", "packages"]:
            for row in index.db.execute(f"SELECT * FROM {table} ORDER BY id"):
                reference.update(canonical([table, [unpack(v) if isinstance(v, bytes) else v for v in row]]).encode())
        for row in index.db.execute("SELECT * FROM meta WHERE key NOT IN ('digest','measurements') ORDER BY key"):
            reference.update(canonical(list(row)).encode())
        self.assertEqual(state_digest(index.db), reference.hexdigest())
        for table in ["symbols", "types", "edges"]:
            plan = index.db.execute(f"EXPLAIN QUERY PLAN SELECT id FROM {table} WHERE file=?", ("file",)).fetchall()
            self.assertTrue(any("INDEX" in row[3] for row in plan), table)
        plan = index.db.execute("EXPLAIN QUERY PLAN SELECT file FROM edges WHERE target IN (?,?)", ("a","b")).fetchall()
        self.assertTrue(any("reverse" in row[3] for row in plan))
        session = object.__new__(RustSession)
        session.sequence, session.seconds = 0, 1
        session._send = Mock()
        session._receive = Mock(side_effect=[{"id":1,"error":{"code":-32801}}, {"id":2,"result":["resolved"]}])
        self.assertEqual(session.request("textDocument/definition", {}), ["resolved"])
        session.sequence = 0
        session._receive = Mock(side_effect=[{"id":i,"error":{"code":-32801}} for i in [1,2,3]])
        with self.assertRaises(EvidenceError):
            session.request("textDocument/definition", {})
        self.assertEqual(session._receive.call_count, 3)

    def test_nested_repository_ownership_and_typed_file_edges(self):
        from zixcel_source_evidence import SourceFileRef
        self.put("one/.git/HEAD", "ref: refs/heads/main\n")
        self.put("one/package.json", '{"name":"one"}')
        self.put("one/a.ts", 'import { value } from "./b"; export function run() { return value() }')
        self.put("one/b.ts", 'export function value() { return 1 }')
        self.put("two/.git/HEAD", "ref: refs/heads/main\n")
        self.put("two/src/lib.rs", 'fn external() {}')
        first = self.build()
        a, b = [SourceFileRef(first.inspect_file("one/"+p)["id"]) for p in ["a.ts", "b.ts"]]
        self.assertTrue(any(e["target"] == b.value for e in first.dependencies_of(a)))
        self.assertTrue(any(e["source"] == a.value for e in first.dependents_of(b)))
        one = first.owners_of(self.symbol(first, "run"))
        two = first.owners_of(self.symbol(first, "external"))
        self.assertNotEqual(one["repository"], two["repository"])
        self.assertEqual(one["repository_path"], "one")
        self.assertEqual(two["repository_path"], "two")
        self.assertIsNone(two["manifest"])  # Never inherit the outer repository's manifest.
        self.assertEqual(first.owners_of(a)["repository"], one["repository"])
        packet = first.build_packet(a)
        self.assertEqual(packet["subject_kind"], "SourceFile")
        self.assertIsNone(packet["symbol"])
        self.assertEqual(packet["source_unit"]["id"], a.value)
        self.assertTrue(any(e["kind"] == "Declaration" for e in packet["dependencies"]))
        self.assertIn("top_level_effect_inference", packet["missing"])
        command = [sys.executable, "-m", "zixcel_source_evidence", "packet", "build", str(self.storage), a.value, "--subject-kind", "file"]
        cli_packet = json.loads(subprocess.run(command, check=True, capture_output=True, text=True).stdout)
        self.assertEqual(cli_packet, packet)
        self.put("two/repository.toml", 'name="two"')
        with Index.update(self.storage) as changed:
            self.assertEqual(changed.owners_of(self.symbol(changed, "external"))["repository"], two["repository"])


if __name__ == "__main__":
    unittest.main()
