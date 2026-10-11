from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import zipfile
from collections import Counter
from pathlib import Path, PurePosixPath
from typing import Any
from xml.etree import ElementTree


class ObservationError(ValueError):
    def __init__(self, code: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _sha256_file(path: Path, maximum_bytes: int) -> str:
    size = path.stat().st_size
    if size > maximum_bytes:
        raise ObservationError(
            "source-too-large", f"source is {size} bytes; limit is {maximum_bytes}"
        )
    hasher = hashlib.sha256()
    with path.open("rb") as source:
        while block := source.read(1024 * 1024):
            hasher.update(block)
    return hasher.hexdigest()


def _resolve_source(root: str | Path, source: str | Path) -> tuple[Path, Path, str]:
    root_path = Path(root)
    if not root_path.is_absolute() or not root_path.is_dir():
        raise ObservationError("invalid-root", "root must be an absolute directory")
    source_path = Path(source)
    if source_path.is_absolute() or ".." in source_path.parts:
        raise ObservationError(
            "source-outside-root", "source must be a relative path without '..'"
        )

    canonical_root = root_path.resolve(strict=True)
    candidate = canonical_root.joinpath(source_path)
    cursor = canonical_root
    for part in source_path.parts:
        cursor = cursor / part
        try:
            mode = cursor.lstat().st_mode
        except FileNotFoundError as error:
            raise ObservationError("source-not-found", "source does not exist") from error
        if stat.S_ISLNK(mode):
            raise ObservationError("symbolic-link-rejected", "symbolic links are not observed")

    resolved = candidate.resolve(strict=True)
    try:
        relative = resolved.relative_to(canonical_root).as_posix()
    except ValueError as error:
        raise ObservationError("source-outside-root", "source resolved outside root") from error
    return canonical_root, resolved, relative


def observe_folder(
    root: str | Path,
    source: str | Path,
    *,
    maximum_entries: int = 4096,
    maximum_file_bytes: int = 64 * 1024 * 1024,
    include_entry_paths: bool = False,
    excluded_directory_names: tuple[str, ...] = (),
) -> dict[str, Any]:
    if maximum_entries < 1 or maximum_entries > 65535:
        raise ObservationError("invalid-limit", "maximum_entries must be 1..65535")
    if (
        len(excluded_directory_names) > 32
        or len(set(excluded_directory_names)) != len(excluded_directory_names)
        or any(
            not name
            or len(name) > 128
            or name in {".", ".."}
            or "/" in name
            or "\\" in name
            or any(ord(character) < 32 or ord(character) == 127 for character in name)
            for name in excluded_directory_names
        )
    ):
        raise ObservationError(
            "invalid-exclusion", "excluded directory names must be 0..32 unique path components"
        )
    _, folder, relative = _resolve_source(root, source)
    if not folder.is_dir():
        raise ObservationError("source-not-directory", "folder source must be a directory")

    entries: list[dict[str, Any]] = []
    kinds: Counter[str] = Counter()
    total_bytes = 0
    excluded_directories = 0
    excluded = set(excluded_directory_names)
    for current_root, directory_names, file_names in os.walk(folder, followlinks=False):
        directory_names.sort()
        file_names.sort()
        excluded_directories += sum(name in excluded for name in directory_names)
        directory_names[:] = [name for name in directory_names if name not in excluded]
        current = Path(current_root)
        for name in [*directory_names, *file_names]:
            child = current / name
            child_relative = child.relative_to(folder).as_posix()
            child_stat = child.lstat()
            if stat.S_ISLNK(child_stat.st_mode):
                kind = "symbolic_link_rejected"
                size = 0
                content_digest = None
                directory_names[:] = [item for item in directory_names if item != name]
            elif stat.S_ISDIR(child_stat.st_mode):
                kind = "directory"
                size = 0
                content_digest = None
            elif stat.S_ISREG(child_stat.st_mode):
                kind = "file"
                size = child_stat.st_size
                total_bytes += size
                content_digest = (
                    _sha256_file(child, maximum_file_bytes)
                    if size <= maximum_file_bytes
                    else None
                )
            else:
                kind = "special_file_rejected"
                size = 0
                content_digest = None
            kinds[kind] += 1
            entry = {
                "path_digest_sha256": hashlib.sha256(
                    child_relative.encode("utf-8")
                ).hexdigest(),
                "kind": kind,
                "size_bytes": size,
                "content_digest_sha256": content_digest,
            }
            if include_entry_paths:
                entry["relative_path"] = child_relative
            entries.append(entry)
            if len(entries) > maximum_entries:
                raise ObservationError(
                    "entry-limit-exceeded",
                    f"folder exceeds maximum_entries={maximum_entries}",
                )

    body = {
        "schema_version": "0.10.0",
        "kind": "source/folder/observation",
        "source_ref": relative,
        "entry_count": len(entries),
        "entry_kinds": dict(sorted(kinds.items())),
        "total_regular_file_bytes": total_bytes,
        "excluded_directory_count": excluded_directories,
        "excluded_directory_names": sorted(excluded),
        "entries": entries,
        "content_included": False,
    }
    return {**body, "observation_digest_sha256": _digest(body)}


def _safe_xml(data: bytes, member: str) -> ElementTree.Element:
    upper = data[:4096].upper()
    if b"<!DOCTYPE" in upper or b"<!ENTITY" in upper:
        raise ObservationError("unsafe-xml", f"unsafe XML declaration in {member}")
    try:
        return ElementTree.fromstring(data)
    except ElementTree.ParseError as error:
        raise ObservationError("invalid-workbook-xml", f"invalid XML in {member}") from error


def _read_member(
    archive: zipfile.ZipFile, name: str, maximum_uncompressed_bytes: int
) -> bytes:
    try:
        info = archive.getinfo(name)
    except KeyError as error:
        raise ObservationError("missing-workbook-part", f"missing workbook part: {name}") from error
    if info.file_size > maximum_uncompressed_bytes:
        raise ObservationError("workbook-part-too-large", f"workbook part too large: {name}")
    with archive.open(info, "r") as member:
        data = member.read(maximum_uncompressed_bytes + 1)
    if len(data) > maximum_uncompressed_bytes:
        raise ObservationError("workbook-part-too-large", f"workbook part too large: {name}")
    return data


_CELL_REFERENCE = re.compile(r"^\$?([A-Z]+)\$?([1-9][0-9]*)$")


def _column_number(reference: str) -> int | None:
    match = _CELL_REFERENCE.match(reference.upper())
    if match is None:
        return None
    value = 0
    for character in match.group(1):
        value = value * 26 + ord(character) - ord("A") + 1
    return value


def observe_workbook(
    root: str | Path,
    source: str | Path,
    *,
    maximum_file_bytes: int = 64 * 1024 * 1024,
    maximum_members: int = 2048,
    maximum_uncompressed_bytes: int = 128 * 1024 * 1024,
    maximum_sheets: int = 1024,
    maximum_rows: int = 1_048_576,
    maximum_columns: int = 16_384,
    include_labels: bool = False,
) -> dict[str, Any]:
    _, workbook, relative = _resolve_source(root, source)
    if not workbook.is_file():
        raise ObservationError("source-not-file", "workbook source must be a file")
    if workbook.suffix.lower() not in {".xlsx", ".xlsm"}:
        raise ObservationError("unsupported-workbook", "only .xlsx and .xlsm are supported")
    source_digest = _sha256_file(workbook, maximum_file_bytes)

    try:
        archive = zipfile.ZipFile(workbook, "r")
    except (zipfile.BadZipFile, OSError) as error:
        raise ObservationError("invalid-workbook", "source is not a valid OOXML workbook") from error

    with archive:
        infos = archive.infolist()
        if len(infos) > maximum_members:
            raise ObservationError("member-limit-exceeded", "workbook has too many ZIP members")
        total_uncompressed = 0
        for info in infos:
            member_path = PurePosixPath(info.filename)
            if member_path.is_absolute() or ".." in member_path.parts:
                raise ObservationError("unsafe-archive-path", "workbook contains an unsafe path")
            total_uncompressed += info.file_size
            if total_uncompressed > maximum_uncompressed_bytes:
                raise ObservationError(
                    "workbook-too-large", "workbook uncompressed size exceeds limit"
                )

        workbook_root = _safe_xml(
            _read_member(archive, "xl/workbook.xml", maximum_uncompressed_bytes),
            "xl/workbook.xml",
        )
        relationships_root = _safe_xml(
            _read_member(
                archive, "xl/_rels/workbook.xml.rels", maximum_uncompressed_bytes
            ),
            "xl/_rels/workbook.xml.rels",
        )
        relationship_targets = {
            node.attrib.get("Id", ""): node.attrib.get("Target", "")
            for node in relationships_root
        }

        sheets: list[dict[str, Any]] = []
        for sheet in workbook_root.findall(
            ".//{http://schemas.openxmlformats.org/spreadsheetml/2006/main}sheet"
        ):
            relationship_id = sheet.attrib.get(
                "{http://schemas.openxmlformats.org/officeDocument/2006/relationships}id",
                "",
            )
            target = relationship_targets.get(relationship_id, "")
            target_path = PurePosixPath(target)
            if target_path.is_absolute() or ".." in target_path.parts:
                raise ObservationError("unsafe-workbook-reference", "unsafe worksheet target")
            member = str(PurePosixPath("xl") / PurePosixPath(target))
            normalized = str(PurePosixPath(member))
            worksheet = _safe_xml(
                _read_member(archive, normalized, maximum_uncompressed_bytes), normalized
            )
            namespace = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"
            rows = worksheet.findall(f".//{namespace}row")
            cells = worksheet.findall(f".//{namespace}c")
            row_count = len(rows)
            cell_count = len(cells)
            formula_count = len(worksheet.findall(f".//{namespace}f"))
            maximum_observed_row = max(
                (int(row.attrib["r"]) for row in rows if row.attrib.get("r", "").isdigit()),
                default=0,
            )
            maximum_observed_column = max(
                (
                    _column_number(cell.attrib.get("r", "")) or 0
                    for cell in cells
                ),
                default=0,
            )
            if maximum_observed_row > maximum_rows:
                raise ObservationError("row-limit-exceeded", "worksheet row limit exceeded")
            if maximum_observed_column > maximum_columns:
                raise ObservationError(
                    "column-limit-exceeded", "worksheet column limit exceeded"
                )
            dimension = worksheet.find(f".//{namespace}dimension")
            dimension_ref = dimension.attrib.get("ref") if dimension is not None else None
            name = sheet.attrib.get("name", "")
            item: dict[str, Any] = {
                "sheet_ref": hashlib.sha256(name.encode("utf-8")).hexdigest(),
                "label_available": bool(name),
                "row_count": row_count,
                "cell_count": cell_count,
                "formula_count": formula_count,
                "dimension": dimension_ref,
            }
            if include_labels:
                item["label"] = name
            sheets.append(item)

        if len(sheets) > maximum_sheets:
            raise ObservationError("sheet-limit-exceeded", "worksheet count exceeds limit")
        body = {
            "schema_version": "0.10.0",
            "kind": "source/workbook/observation",
            "source_ref": relative,
            "source_digest_sha256": source_digest,
            "format": workbook.suffix.lower().removeprefix("."),
            "sheet_count": len(sheets),
            "sheets": sheets,
            "contains_macros": "xl/vbaProject.bin" in archive.namelist(),
            "content_included": False,
            "formula_text_included": False,
        }
    return {**body, "observation_digest_sha256": _digest(body)}


def observe_resource(
    configuration: str | Path, resource_ref: str
) -> dict[str, Any]:
    configuration_path = Path(configuration)
    if not configuration_path.is_absolute() or not configuration_path.is_file():
        raise ObservationError(
            "invalid-configuration", "configuration must be an absolute file path"
        )
    if configuration_path.is_symlink():
        raise ObservationError(
            "symbolic-link-rejected", "configuration cannot be a symbolic link"
        )
    if configuration_path.stat().st_size > 64 * 1024:
        raise ObservationError("configuration-too-large", "configuration exceeds 64 KiB")
    try:
        document = json.loads(configuration_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ObservationError(
            "invalid-configuration", "configuration is not valid UTF-8 JSON"
        ) from error
    if not isinstance(document, dict) or set(document) != {
        "schema_version",
        "resources",
    }:
        raise ObservationError("invalid-configuration", "configuration fields are invalid")
    if document["schema_version"] != "0.10.0" or not isinstance(
        document["resources"], list
    ):
        raise ObservationError("invalid-configuration", "configuration schema is unsupported")
    matching = [
        item
        for item in document["resources"]
        if isinstance(item, dict) and item.get("resource_ref") == resource_ref
    ]
    if len(matching) != 1:
        raise ObservationError(
            "resource-not-selected", "resource_ref must select exactly one configured resource"
        )
    selected = matching[0]
    required_fields = {"resource_ref", "kind", "root", "source"}
    allowed_fields = required_fields | (
        {"maximum_entries", "excluded_directory_names"}
        if selected.get("kind") == "folder"
        else set()
    )
    if set(selected) < required_fields or set(selected) - allowed_fields or selected.get("kind") not in {"folder", "workbook"}:
        raise ObservationError("invalid-configuration", "resource fields are invalid")
    if not all(
        isinstance(selected.get(field), str)
        for field in ("resource_ref", "kind", "root", "source")
    ):
        raise ObservationError("invalid-configuration", "resource values must be strings")

    if selected["kind"] == "folder":
        maximum_entries = selected.get("maximum_entries", 4096)
        excluded_directory_names = selected.get("excluded_directory_names", [])
        if not isinstance(maximum_entries, int) or isinstance(maximum_entries, bool) or not isinstance(excluded_directory_names, list) or any(not isinstance(value, str) for value in excluded_directory_names):
            raise ObservationError("invalid-configuration", "folder observation limits are invalid")
        observed = observe_folder(
            selected["root"],
            selected["source"],
            maximum_entries=maximum_entries,
            excluded_directory_names=tuple(excluded_directory_names),
        )
    else:
        observed = observe_workbook(selected["root"], selected["source"])
    source_observation_digest = observed.pop("observation_digest_sha256")
    observed.pop("source_ref", None)
    body = {
        **observed,
        "resource_ref": resource_ref,
        "source_observation_digest_sha256": source_observation_digest,
    }
    return {**body, "observation_digest_sha256": _digest(body)}
