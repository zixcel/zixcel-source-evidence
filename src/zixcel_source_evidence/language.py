"""Syntax adapters normalize observations; dynamic resolution is never guessed.

Tree-sitter does not perform compiler type checking. Syntax type annotations are
explicitly labelled Declared; trait dispatch, macros and external packages retain
missing compiler evidence. Parser ASTs never leave this module.
"""
import importlib
from importlib.metadata import version, PackageNotFoundError
import json
import re
import tomllib
import configparser
from pathlib import Path
from .model import Code, EvidenceError, SymbolRef, TypeRef, ref, digest

GRAMMARS = {"rust": ("rust", "language"), "typescript": ("typescript", "language_typescript"),
            "tsx": ("typescript", "language_tsx"), "javascript": ("javascript", "language"),
            "python": ("python", "language"), "bash": ("bash", "language"), "vue": ("html", "language"),
            "yaml": ("yaml", "language"), "starlark": ("python", "language"), "html": ("html", "language")}
GRAMMARS.update({name: (name, "language") for name in ["nix", "make", "powershell"]})
DEFINITIONS = {"function_item", "function_signature_item", "struct_item", "enum_item", "trait_item",
               "type_item", "mod_item", "const_item", "static_item", "function_declaration",
               "function_expression", "arrow_function", "method_definition", "class_declaration",
               "interface_declaration", "type_alias_declaration", "function_definition", "class_definition",
               "function_signature", "method_signature", "abstract_method_signature"}
DEFINITIONS.update({"binding", "rule", "function_statement"})
SYMBOL_KINDS = {
    **{name: "Function" for name in ["function_item", "function_signature_item", "function_declaration",
        "function_expression", "arrow_function", "function_definition", "function_signature", "function_statement"]},
    **{name: "Method" for name in ["method_definition", "method_signature", "abstract_method_signature"]},
    "struct_item": "Struct", "enum_item": "Enum", "trait_item": "Trait", "type_item": "TypeAlias",
    "mod_item": "Module", "const_item": "Constant", "static_item": "Static",
    "class_declaration": "Class", "class_definition": "Class", "interface_declaration": "Interface",
    "type_alias_declaration": "TypeAlias", "binding": "Binding", "rule": "BuildRule"}
CALLS = {"call_expression", "call", "command", "apply_expression"}
TYPES = {"type_identifier", "primitive_type", "predefined_type", "generic_type", "type_annotation"}
IMPORTS = {"use_declaration", "import_statement", "import_from_statement", "export_statement"}
LITERALS = {"string", "string_literal", "raw_string_literal", "interpreted_string_literal",
            "char_literal", "template_string", "string_content", "string_fragment", "comment",
            "line_comment", "block_comment", "heredoc_body", "raw_text"}
LITERALS.update({"string_expression", "indented_string_expression", "uri_expression", "shell_text"})
def implementation_digest():
    return digest({p.name: digest(p.read_bytes()) for p in sorted(Path(__file__).parent.iterdir())
                   if p.suffix in {".py", ".mjs"}})


ANALYZER_DIGEST = implementation_digest()


def installed_version(name):
    try:
        return version(name)
    except PackageNotFoundError as error:
        raise EvidenceError(Code.AnalyzerUnavailable, name) from error


def provenance(language):
    packages = {"tree-sitter": installed_version("tree-sitter")}
    if language in GRAMMARS:
        g = GRAMMARS[language][0]
        packages["tree-sitter-" + g] = installed_version("tree-sitter-" + g)
        if language in {"vue", "html"}:
            embedded = "tree-sitter-typescript" if language == "vue" else "tree-sitter-javascript"
            packages[embedded] = installed_version(embedded)
    elif language == "sql":
        packages["sqlparse"] = installed_version("sqlparse")
    elif language == "css":
        packages["tinycss2"] = installed_version("tinycss2")
    return {"adapter": language, "versions": packages, "rule": "source/ast/0.10.0", "implementation": ANALYZER_DIGEST}


def parser(language):
    module, factory = GRAMMARS[language]
    try:
        from tree_sitter import Language, Parser
        grammar = importlib.import_module("tree_sitter_" + module)
        return Parser(Language(getattr(grammar, factory)()))
    except (ImportError, AttributeError, ValueError) as error:
        raise EvidenceError(Code.AnalyzerUnavailable, language) from error


def walk(root, maximum):
    stack, count = [root], 0
    while stack:
        node = stack.pop()
        count += 1
        if count > maximum:
            raise EvidenceError(Code.ResourceLimitExceeded, "AST nodes")
        yield node
        stack.extend(reversed(node.named_children))


def label(node, data):
    if node is None:
        return ""
    text = data[node.start_byte:node.end_byte].decode()
    # Labels may contain code identifiers/operators, never arbitrary literals.
    return text if len(text) <= 512 and re.fullmatch(r"[\w\s:.$<>,&*?!\[\]/()=+\-]+", text) else "<expression>"


def sanitize(root, raw, maximum):
    output = bytearray(raw)
    for node in walk(root, maximum):
        if node.type in LITERALS or "comment" in node.type or "string" in node.type:
            for i in range(node.start_byte, node.end_byte):
                if output[i] not in (10, 13):
                    output[i] = 32
    # Numeric/encoded credential literals are withheld too; exact hashes remain.
    return re.sub(rb"\b(?:0x[0-9a-fA-F]+|[0-9]{6,})\b", lambda m: b" " * len(m[0]), bytes(output))


class LanguageAdapter:
    def analyze(self, path, raw, file_id, owner, limits):
        raise NotImplementedError


class SyntaxAdapter(LanguageAdapter):
    def __init__(self, language):
        self.language = language

    def analyze(self, path, raw, file_id, owner, limits):
        language = self.language
        if language not in GRAMMARS or language in {"css", "yaml"}:
            return structured(language, path, raw, file_id, owner, limits)
        tree = parser(language).parse(raw)
        projections = []
        if language == "bash" and tree.root_node.has_error:
            # The pinned grammar rejects the valid shell arithmetic form
            # 0$MODE (an expanded octal numeral). Keep its original bytes and
            # revision, but omit only that numeral prefix from the syntax
            # projection. No arithmetic value or effect is inferred from it.
            projected = bytearray(raw)
            for error in walk(tree.root_node, limits.ast_nodes):
                if (error.type == "ERROR" and error.parent.type == "arithmetic_expansion"
                        and raw[error.start_byte:error.end_byte] == b"0"
                        and raw[error.end_byte:error.end_byte+1] == b"$"):
                    projected[error.start_byte:error.end_byte] = b" "
                    projections.append({"kind": "ArithmeticNumeralExpansion", "start": error.start_byte})
            if projections:
                tree = parser(language).parse(bytes(projected))
        if language in {"typescript", "tsx"} and tree.root_node.has_error:
            # The pinned grammar predates TS `export type *`. Erase only this
            # syntax modifier, preserving byte offsets and the original digest.
            # Never use this normalization to infer value-space availability.
            normalized = re.sub(rb"\bexport(\s+)type(\s+)(?=\*)", lambda m: b"export"+m[1]+b"    "+m[2], raw)
            tree = parser(language).parse(normalized)
        # Vue directive syntax may exceed HTML grammar. Script parses remain strict.
        if tree.root_node.has_error and language != "vue":
            raise EvidenceError(Code.ParseFailure, path)
        units = [(tree.root_node, raw, 0, language)]
        extra = []
        if language in {"vue", "html"}:
            units = []
            for node in walk(tree.root_node, limits.ast_nodes):
                if node.type == "script_element":
                    body = next((c for c in node.named_children if c.type == "raw_text"), None)
                    if body is None:
                        continue
                    code = raw[body.start_byte:body.end_byte]
                    embedded = "typescript" if language == "vue" else "javascript"
                    stree = parser(embedded).parse(code)
                    if stree.root_node.has_error:
                        raise EvidenceError(Code.ParseFailure, path + ":script")
                    units.append((stree.root_node, code, body.start_byte, embedded))
                if node.type == "tag_name":
                    name = label(node, raw)
                    if name and name[0].isupper():
                        extra.append({"kind": "Component", "name": name, "start": node.start_byte,
                                      "source": file_id, "resolution": "Unresolved", "targets": []})
        symbols, edges, types = [], extra, []
        module_source = bytearray(10 if b == 10 else 32 for b in raw)
        for syntax, data, offset, lang in units:
            clean = sanitize(syntax, data, limits.ast_nodes)
            module_source[offset:offset+len(data)] = clean
            # Keep byte offsets stable by only using original slice boundaries below.
            definitions, occurrences = [], {}
            nodes = list(walk(syntax, limits.ast_nodes))
            shadowed = set()
            for binding in nodes:
                if binding.type in {"parameter", "let_declaration", "variable_declarator", "required_parameter", "assignment"}:
                    pattern = binding.child_by_field_name("pattern") or binding.child_by_field_name("name") or binding.child_by_field_name("left")
                    if pattern:
                        shadowed.update(label(n, data) for n in walk(pattern, limits.ast_nodes) if n.type == "identifier")
            for node in nodes:
                if node.type not in DEFINITIONS:
                    continue
                name_node = node.child_by_field_name("name")
                if name_node is None:
                    name_node = (node.child_by_field_name("attrpath") or
                                 next((c for c in node.named_children if c.type in {"function_name", "targets"}), None))
                if name_node is None and node.parent and node.parent.type in {"variable_declarator", "assignment"}:
                    name_node = node.parent.child_by_field_name("name") or node.parent.child_by_field_name("left")
                name = label(name_node, data) or "<anonymous>"
                ancestors, attributes, scope, parent = [], [], [], node.parent
                method_context = False
                while parent:
                    if parent.type in {"impl_item", "trait_item", "class_definition", "class_declaration"}:
                        method_context = True
                    if parent.type in DEFINITIONS or parent.type == "impl_item":
                        item = parent.child_by_field_name("name") or parent.child_by_field_name("type")
                        scope.append(label(item, data) or parent.type)
                    # cfg evidence is syntax, not evaluation under a guessed target.
                    prev = parent.prev_named_sibling
                    while prev and prev.type == "attribute_item":
                        attributes.append(digest(data[prev.start_byte:prev.end_byte]))
                        ancestors.append(label(prev.child_by_field_name("attribute"), data)
                                         or data[prev.start_byte:prev.end_byte].decode()[:512])
                        prev = prev.prev_named_sibling
                    parent = parent.parent
                prev = node.prev_named_sibling
                while prev and prev.type == "attribute_item":
                    attributes.append(digest(data[prev.start_byte:prev.end_byte]))
                    ancestors.append(data[prev.start_byte:prev.end_byte].decode()[:512])
                    prev = prev.prev_named_sibling
                qualified = "::".join([*reversed(scope), name])
                key = (node.type, qualified)
                ordinal = occurrences.get(key, 0)
                occurrences[key] = ordinal + 1
                identity = ref(SymbolRef, file_id, node.type, qualified, ordinal).value
                start, end = node.start_byte + offset, node.end_byte + offset
                snippet = clean[node.start_byte:node.end_byte].decode()
                parameters = node.child_by_field_name("parameters")
                symbol_kind = SYMBOL_KINDS[node.type]
                if method_context and symbol_kind == "Function":
                    symbol_kind = "Method"
                entry = {"id": identity, "file": file_id, "owner": owner, "name": name,
                         "qualified": qualified, "kind": symbol_kind, "start": start, "end": end,
                         "line": raw[:start].count(b"\n") + 1,
                         "body_digest": digest(raw[start:end]), "source": snippet,
                         "attributes": sorted(set(attributes)),
                         "parameter_count": parameters.named_child_count if parameters else None,
                         "cfg": sorted(set(a for a in ancestors if a.startswith("#[cfg") and '"' not in a)),
                         "resolution": "PartiallyResolved", "missing": ["compiler_type_resolution", "dynamic_dispatch"] +
                             (["arithmetic_expansion_evaluation"] if projections else [])}
                symbols.append(entry)
                definitions.append((node.start_byte, node.end_byte, identity))
                edges.append({"kind": "Declaration", "source": file_id, "name": name,
                              "start": start, "resolution": "Resolved", "targets": [identity],
                              "syntax_digest": entry["body_digest"]})
                for at in range(start, end):
                    if module_source[at] != 10:
                        module_source[at] = 32
            definitions.sort(key=lambda v: (v[0], -v[1]))
            def containing(node):
                matches = [v for v in definitions if v[0] <= node.start_byte and node.end_byte <= v[1]]
                return min(matches, key=lambda v: v[1] - v[0])[2] if matches else file_id
            for node in nodes:
                kind, name = None, ""
                if node.type in CALLS:
                    fn = node.child_by_field_name("function") or node.child_by_field_name("name") or node.child_by_field_name("command_name")
                    kind, name = "Call", label(fn, data)
                elif node.type == "macro_invocation":
                    kind, name = "Macro", label(node.child_by_field_name("macro"), data)
                elif node.type in IMPORTS:
                    # Exported declarations are already symbols; preserve the import node digest.
                    kind, name = "Import", label(node, data)
                elif node.type == "mod_item" and node.child_by_field_name("body") is None:
                    kind, name = "Module", label(node.child_by_field_name("name"), data)
                elif node.type in TYPES:
                    kind, name = "TypeReference", label(node, data)
                elif node.type in {"member_expression", "field_expression", "attribute"}:
                    kind, name = "Property", label(node, data)
                if not kind:
                    continue
                source = containing(node)
                record = {"kind": kind, "source": source, "name": name or "<dynamic>",
                          "start": node.start_byte + offset, "resolution": "Unresolved", "targets": [],
                          "syntax_digest": digest(data[node.start_byte:node.end_byte]),
                          "shadowed": name in shadowed}
                if kind == "Import":
                    source_node = node.child_by_field_name("source")
                    argument = node.child_by_field_name("argument")
                    if source_node:
                        specifier = data[source_node.start_byte:source_node.end_byte].decode().strip("\"'")
                        if re.fullmatch(r"[\w./@-]{1,256}", specifier):
                            record["module"] = specifier
                    elif argument:
                        record["module"] = label(argument, data)
                    record["bindings"] = [label(n, data) for n in walk(node, limits.ast_nodes)
                                          if n.type in {"identifier", "type_identifier"}]
                    record["type_only"] = data[node.start_byte:node.end_byte].startswith(b"export type")
                    record["aliases"] = []
                    for n in walk(node, limits.ast_nodes):
                        if n.type in {"import_specifier", "use_as_clause"}:
                            original = n.child_by_field_name("name") or n.child_by_field_name("path")
                            alias = n.child_by_field_name("alias")
                            record["aliases"].append({"name": label(original, data),
                                                       "local": label(alias or original, data)})
                if kind == "Macro" and name == "include":
                    literals = [n for n in walk(node, limits.ast_nodes) if n.type == "string_literal"]
                    if len(literals) == 1:
                        include = data[literals[0].start_byte:literals[0].end_byte].decode().strip('"')
                        if re.fullmatch(r"[\w./-]{1,256}", include):
                            record["kind"], record["module"] = "Include", include
                if kind == "TypeReference":
                    tid = ref(TypeRef, file_id, name).value
                    types.append({"id": tid, "file": file_id, "name": name, "owner": owner,
                                  "resolution": "Declared", "digest": digest([name, file_id])})
                    record.update(resolution="Resolved", targets=[tid])
                edges.append(record)
        return {"symbols": symbols, "edges": edges, "types": list({t["id"]: t for t in types}.values()),
                "adapter": provenance(language), "coverage": "PartiallyResolved", "syntax_projections": projections,
                "module_source": module_source.decode(),
                "missing": ["compiler_type_resolution", "macro_expansion", "dynamic_dispatch"]}


def structured(language, path, raw, file_id, owner, limits):
    symbols = []
    try:
        if language in {"json", "toml"}:
            obj = json.loads(raw) if language == "json" else tomllib.loads(raw.decode())
            # Keys only. Values may be credentials; never put them in source packets.
            names = sorted(obj) if isinstance(obj, dict) else ["<array>"]
        elif language == "ini":
            configuration = configparser.ConfigParser(interpolation=None, strict=False)
            configuration.optionxform = str
            configuration.read_string(raw.decode())
            names = [section+":"+name for section in configuration.sections() for name in configuration[section]]
        elif language == "sql":
            import sqlparse
            names = ["statement:" + str(i) + ":" + s.get_type() for i, s in enumerate(sqlparse.parse(raw.decode()))]
        elif language == "css":
            import tinycss2
            rules = tinycss2.parse_stylesheet(raw.decode(), skip_comments=True, skip_whitespace=True)
            names, stack, count = [], list(rules), 0
            while stack:
                node = stack.pop()
                count += 1
                if count > limits.ast_nodes:
                    raise EvidenceError(Code.ResourceLimitExceeded, "CSS tokens")
                if node.type == "error":
                    raise EvidenceError(Code.ParseFailure, path)
                stack.extend(getattr(node, "content", None) or [])
                stack.extend(getattr(node, "arguments", None) or [])
                stack.extend(getattr(node, "prelude", None) or [])
            names = [r.type+":"+str(r.source_line)+":"+str(r.source_column) for r in rules]
        elif language == "yaml":
            tree = parser(language).parse(raw)
            if tree.root_node.has_error:
                raise EvidenceError(Code.ParseFailure, path)
            names = []
            for node in walk(tree.root_node, limits.ast_nodes):
                if node.type in {"block_mapping_pair", "flow_pair"}:
                    # Match JSON/TOML's top-level declaration contract. Nested
                    # package-lock keys are data, not executable symbols. All
                    # nested bytes remain covered by the file/body revision.
                    ancestor = node.parent.parent if node.parent else None
                    nested = False
                    while ancestor:
                        if ancestor.type in {"block_mapping_pair", "flow_pair", "block_sequence", "flow_sequence"}:
                            nested = True
                            break
                        ancestor = ancestor.parent
                    if nested:
                        continue
                    key = node.child_by_field_name("key")
                    if key:
                        names.append(label(key, raw))
        else:
            raise EvidenceError(Code.UnsupportedLanguage, language)
    except (ValueError, tomllib.TOMLDecodeError, configparser.Error) as error:
        raise EvidenceError(Code.ParseFailure, path) from error
    for i, name in enumerate(names):
        if i >= limits.symbols:
            raise EvidenceError(Code.ResourceLimitExceeded, "structured declarations")
        safe_name = name if re.fullmatch(r"[\w:./<>@-]{1,128}", name) else "<key>"
        symbols.append({"id": ref(SymbolRef, file_id, safe_name, i).value, "file": file_id,
                        "owner": owner, "name": safe_name, "qualified": safe_name,
                        "kind": "DataDeclaration", "start": 0, "end": 0, "line": 1,
                        "body_digest": digest(raw), "source": "", "cfg": [],
                        "resolution": "PartiallyResolved", "missing": ["runtime_semantics"]})
    return {"symbols": symbols, "edges": [], "types": [], "adapter": provenance(language),
            "module_source": "",
            "structure": "top_level_declarations", "nested_content": "revision_only",
            "coverage": "STRUCTURED_FILE_ADAPTER", "missing": ["runtime_semantics"]}
