"""All commands use the same library; machine-readable stdout, typed failures."""
import argparse
import json
import sys
from pathlib import Path
from . import Index, SymbolRef, SourceFileRef, TypeRef, EvidenceError, Limits, PacketLimits
from .model import canonical, Code


def main():
    parser = argparse.ArgumentParser(prog="zixcel-source-evidence")
    sub = parser.add_subparsers(dest="command", required=True)
    for command, operations in {"index": ["create", "update", "status", "verify", "rebuild"],
                                "inspect": ["symbol", "file", "type"],
                                "query": ["dependencies", "dependents", "effects", "symbols", "reads", "writes", "owners", "revision"],
                                "packet": ["build"]}.items():
        nested = sub.add_parser(command).add_subparsers(dest="operation", required=True)
        for operation in operations:
            p = nested.add_parser(operation)
            p.add_argument("index")
            if operation == "create":
                p.add_argument("root")
                p.add_argument("--repository", required=True)
                p.add_argument("--file-bytes", type=int, default=2*1024*1024)
                p.add_argument("--repository-bytes", type=int, default=256*1024*1024)
            if command == "index" and operation in {"create", "update", "rebuild"}:
                p.add_argument("--rules", help="Explicit trusted analysis configuration JSON (maximum 1 MiB)")
            if command in {"inspect", "query", "packet"}:
                p.add_argument("subject")
            if command == "query" and operation in {"dependencies", "dependents", "owners"}:
                p.add_argument("--subject-kind", choices=["symbol", "file", "type"], default="symbol")
            if command == "packet":
                p.add_argument("--subject-kind", choices=["symbol", "file"], default="symbol")
                p.add_argument("--max-bytes", type=int, default=65536)
                p.add_argument("--depth", type=int, default=1)
                p.add_argument("--max-source-bytes", type=int, default=8192)
                p.add_argument("--continuation", help="JSON continuation returned by the preceding page")
    for command in ["diff", "doctor", "stats"]:
        p = sub.add_parser(command)
        p.add_argument("index")
        if command == "diff":
            p.add_argument("previous")
            p.add_argument("--limit", type=int, default=128)
            p.add_argument("--continuation", help="JSON continuation returned by the preceding page")
    args = parser.parse_args()
    index = None
    try:
        cursor = None
        if getattr(args, "continuation", None):
            if len(args.continuation.encode()) > 65536:
                raise EvidenceError(Code.ResourceLimitExceeded, "continuation input bytes")
            try:
                cursor = json.loads(args.continuation)
                if not isinstance(cursor, dict):
                    raise ValueError()
            except ValueError as error:
                raise EvidenceError(Code.InvalidEvidence, "continuation JSON object required") from error
        rules = None
        if getattr(args, "rules", None):
            with Path(args.rules).open("rb") as file:
                raw = file.read(1024*1024+1)
            if len(raw) > 1024*1024:
                raise EvidenceError(Code.ResourceLimitExceeded, "analysis configuration bytes")
            rules = json.loads(raw)
            if not isinstance(rules, dict) or set(rules)-{"version", "effects", "rust_compiler", "typescript_compiler"}:
                raise EvidenceError(Code.InvalidEvidence, "analysis configuration keys")
        if args.command == "index" and args.operation == "create":
            index = Index.create(args.index, args.root, args.repository,
                                 Limits(file_bytes=args.file_bytes, repository_bytes=args.repository_bytes), rules=rules)
        elif args.command == "index" and args.operation in {"update", "rebuild"}:
            index = Index.update(args.index, rules=rules, rebuild=args.operation == "rebuild")
        else:
            index = Index.open_existing(args.index)
        if args.command == "index":
            value = index.index_status()
        elif args.command == "inspect":
            value = (index.symbol(SymbolRef(args.subject)) if args.operation == "symbol" else
                     index.type(TypeRef(args.subject)) if args.operation == "type" else index.inspect_file(args.subject))
        elif args.command == "query":
            operation = {"dependencies": index.dependencies_of, "dependents": index.dependents_of,
                         "effects": index.effects_of, "symbols": index.find_symbols, "reads": index.reads_of,
                         "writes": index.writes_of, "owners": index.owners_of, "revision": index.evidence_revision}[args.operation]
            kind = {"symbol": SymbolRef, "file": SourceFileRef, "type": TypeRef}[getattr(args, "subject_kind", "symbol")]
            value = operation(args.subject if args.operation == "symbols" else kind(args.subject))
        elif args.command == "packet":
            kind = SymbolRef if args.subject_kind == "symbol" else SourceFileRef
            value = index.build_packet(kind(args.subject), PacketLimits(max_bytes=args.max_bytes,
                max_depth=args.depth, max_source_bytes=args.max_source_bytes), cursor)
        elif args.command == "diff":
            with Index.open_existing(args.previous) as previous:
                value = index.diff(previous, args.limit, cursor)
        elif args.command == "doctor":
            value = {"findings": index.doctor()}
        else:
            value = index.stats()
        print(canonical(value))
        if args.command == "doctor" and value["findings"]:
            raise SystemExit(2)
    except EvidenceError as error:
        print(canonical(error.wire()))
        raise SystemExit(2) from None
    except (OSError, ValueError, KeyError) as error:
        print(canonical(EvidenceError(Code.InternalFailure, type(error).__name__).wire()))
        raise SystemExit(2) from None
    finally:
        if index:
            index.close()
