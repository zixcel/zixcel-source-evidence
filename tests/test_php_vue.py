"""Actual parser/index ABI: declarations never imply PHP or Vue runtime resolution."""
import json
from importlib.metadata import version
import tomllib
from pathlib import Path
import tempfile
import unittest
from zixcel_source_evidence import Code, EvidenceError, Index, Limits, SourceFileRef, SymbolRef


class PhpVueJourney(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name, "source")
        self.root.mkdir(mode=0o700)
        self.store = Path(self.temp.name, "evidence.db")

    def build(self):
        index = Index.create(self.store, self.root, "php-vue-fixture", limits=Limits(memory_bytes=536870912))
        self.addCleanup(index.close)
        return index

    def test_packaged_version_and_actual_grammar_provenance_match_the_owner_manifest(self):
        from zixcel_source_evidence.model import VERSION
        from zixcel_source_evidence.language import provenance
        declaration = tomllib.loads((Path(__file__).parents[1] / "pyproject.toml").read_text())["project"]
        self.assertEqual(version("zixcel-source-evidence"), declaration["version"])
        self.assertEqual(VERSION, declaration["version"])
        grammar = next(value.split("==")[1] for value in declaration["dependencies"] if value.startswith("tree-sitter-php=="))
        observed = provenance("php")
        self.assertEqual(observed["versions"]["tree-sitter-php"], grammar)
        self.assertEqual(observed["rule"], "source/ast/" + VERSION)

    def test_php_declarations_dispatch_provenance_and_literal_non_disclosure(self):
        marker = Path(self.temp.name, "must-not-exist")
        source = ('PRIVATE_HTML <?php namespace App\\Api; '
            'class Service { public function fetch(string $input): string { return helper($input); } } '
            'function helper(string $input): string { '
            f'file_put_contents("{marker}", "PRIVATE_CONTENT"); '
            '$token = <<<TOKEN\nPRIVATE_HEREDOC\nTOKEN; '
            'return "PRIVATE_LITERAL"; } ?>PRIVATE_TAIL')
        (self.root / "service.php").write_text(source)
        index = self.build()
        method = index.find_symbols("fetch")[0]
        self.assertEqual(method["kind"], "Method")
        self.assertEqual(method["qualified"], "Service::fetch")
        self.assertTrue(index.find_symbols("App\\Api"))
        calls = [edge for edge in index.dependencies_of(SymbolRef(method["id"])) if edge["kind"] == "Call"]
        self.assertTrue(calls)
        self.assertTrue(all(edge["resolution"] == "Unresolved" and not edge["target"] for edge in calls))
        file = index.inspect_file("service.php")
        self.assertEqual(file["language"], "php")
        packet = index.build_packet(SourceFileRef(file["id"]))
        encoded = json.dumps([packet, index.build_packet(SymbolRef(index.find_symbols("helper")[0]["id"]))])
        for secret in ["PRIVATE_HTML", "PRIVATE_CONTENT", "PRIVATE_HEREDOC", "PRIVATE_LITERAL", "PRIVATE_TAIL", str(marker)]:
            self.assertNotIn(secret, encoded)
        self.assertIn("php_namespace_resolution", packet["missing"])
        self.assertFalse(marker.exists(), "PHP code must never execute")
        reopened = Index.open_existing(self.store)
        self.addCleanup(reopened.close)
        self.assertEqual(reopened.evidence_digest(SourceFileRef(file["id"])), index.evidence_digest(SourceFileRef(file["id"])))

    def test_php_traits_interfaces_enums_and_methods_are_native_syntax_kinds(self):
        (self.root / "kinds.php").write_text('<?php trait Work { function run() { $this->send(); } } '
            'interface Port { public function send(): void; } enum Choice { case A; }')
        index = self.build()
        for name, kind in [("Work", "Trait"), ("Port", "Interface"), ("Choice", "Enum"), ("run", "Method"), ("send", "Method")]:
            self.assertEqual(index.find_symbols(name)[0]["kind"], kind)

    def test_invalid_php_is_refused_without_publishing_an_index(self):
        (self.root / "invalid.php").write_text('<?php function broken( { return "PRIVATE_LITERAL";')
        with self.assertRaises(EvidenceError) as raised:
            self.build()
        self.assertEqual(raised.exception.code, Code.ParseFailure)
        self.assertFalse(self.store.exists())

    def test_multiple_vue_scripts_keep_distinct_ids_and_explicit_sfc_residuals(self):
        (self.root / "page.vue").write_text('<template><Child /></template>'
            '<script lang="ts">function shared() { return "PRIVATE_ONE" }</script>'
            '<script setup lang="ts">function shared() { return "PRIVATE_TWO" } function refresh() { shared() }</script>')
        index = self.build()
        shared = index.find_symbols("shared")
        self.assertEqual(len(shared), 2)
        self.assertEqual(len({symbol["id"] for symbol in shared}), 2)
        refresh = index.find_symbols("refresh")[0]
        calls = [edge for edge in index.dependencies_of(SymbolRef(refresh["id"])) if edge["kind"] == "Call"]
        self.assertTrue(calls)
        self.assertTrue(all(edge["resolution"] == "Unresolved" and not edge["target"] for edge in calls))
        file = index.inspect_file("page.vue")
        packet = index.build_packet(SourceFileRef(file["id"]))
        self.assertIn("vue_sfc_compiler", packet["missing"])
        self.assertNotIn("PRIVATE_ONE", json.dumps(packet))
        self.assertNotIn("PRIVATE_TWO", json.dumps(packet))


if __name__ == '__main__':
    unittest.main()
