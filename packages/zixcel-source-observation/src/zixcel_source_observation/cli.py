from __future__ import annotations

import argparse
import json
import sys
from typing import Sequence

from .observe import ObservationError, observe_folder, observe_resource, observe_workbook


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="zixcel-source-observation")
    subcommands = parser.add_subparsers(dest="source_kind", required=True)

    for source_kind in ("folder", "workbook"):
        source_parser = subcommands.add_parser(source_kind)
        actions = source_parser.add_subparsers(dest="action", required=True)
        observe = actions.add_parser("observe")
        observe.add_argument("--root", required=True)
        observe.add_argument("--source", required=True)
        if source_kind == "folder":
            observe.add_argument("--maximum-entries", type=int, default=4096)
            observe.add_argument("--include-entry-paths", action="store_true")
        else:
            observe.add_argument("--maximum-rows", type=int, default=1_048_576)
            observe.add_argument("--maximum-columns", type=int, default=16_384)
            observe.add_argument("--maximum-sheets", type=int, default=1024)
            observe.add_argument("--include-labels", action="store_true")
    resource_parser = subcommands.add_parser("resource")
    resource_actions = resource_parser.add_subparsers(dest="action", required=True)
    resource_observe = resource_actions.add_parser("observe")
    resource_observe.add_argument("--configuration", required=True)
    resource_observe.add_argument("--resource-ref", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.source_kind == "folder":
            result = observe_folder(
                args.root,
                args.source,
                maximum_entries=args.maximum_entries,
                include_entry_paths=args.include_entry_paths,
            )
        elif args.source_kind == "workbook":
            result = observe_workbook(
                args.root,
                args.source,
                maximum_rows=args.maximum_rows,
                maximum_columns=args.maximum_columns,
                maximum_sheets=args.maximum_sheets,
                include_labels=args.include_labels,
            )
        else:
            result = observe_resource(args.configuration, args.resource_ref)
    except ObservationError as error:
        print(
            json.dumps(
                {
                    "schema_version": "0.10.0",
                    "kind": "source/observation/error",
                    "code": error.code,
                    "detail": error.detail,
                },
                ensure_ascii=False,
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 2
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
