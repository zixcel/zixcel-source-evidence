from __future__ import annotations

import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from zixcel_source_observation import (
    ObservationError,
    observe_folder,
    observe_resource,
    observe_workbook,
)


WORKBOOK_XML = b'''<?xml version="1.0" encoding="UTF-8"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"
 xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
 <sheets><sheet name="Plan" sheetId="1" r:id="rId1"/></sheets>
</workbook>'''
RELATIONSHIPS_XML = b'''<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
 <Relationship Id="rId1" Type="worksheet" Target="worksheets/sheet1.xml"/>
</Relationships>'''
WORKSHEET_XML = b'''<?xml version="1.0" encoding="UTF-8"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
 <dimension ref="A1:B2"/><sheetData><row r="1"><c r="A1"><v>1</v></c></row>
 <row r="2"><c r="B2"><f>A1+1</f><v>2</v></c></row></sheetData>
</worksheet>'''


def write_workbook(path: Path) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("xl/workbook.xml", WORKBOOK_XML)
        archive.writestr("xl/_rels/workbook.xml.rels", RELATIONSHIPS_XML)
        archive.writestr("xl/worksheets/sheet1.xml", WORKSHEET_XML)


class ObservationTest(unittest.TestCase):
    def test_workbook_observation_excludes_cell_content_and_labels(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_workbook(root / "input.xlsx")
            result = observe_workbook(root, "input.xlsx")
            self.assertEqual(result["sheet_count"], 1)
            self.assertEqual(result["sheets"][0]["cell_count"], 2)
            self.assertEqual(result["sheets"][0]["formula_count"], 1)
            self.assertNotIn("label", result["sheets"][0])
            self.assertNotIn("Plan", str(result))

    def test_folder_observation_is_deterministic_and_content_free(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            folder = root / "source"
            folder.mkdir()
            (folder / "secret.txt").write_text("private value", encoding="utf-8")
            first = observe_folder(root, "source")
            second = observe_folder(root, "source")
            self.assertEqual(first, second)
            self.assertNotIn("secret.txt", str(first))
            self.assertNotIn("private value", str(first))

    def test_traversal_and_symbolic_links_are_rejected(self) -> None:
        with (
            tempfile.TemporaryDirectory() as directory,
            tempfile.TemporaryDirectory() as outside_directory,
        ):
            root = Path(directory)
            outside = Path(outside_directory) / "outside-source-observation"
            outside.write_text("outside", encoding="utf-8")
            with self.assertRaises(ObservationError):
                observe_workbook(root, "../outside-source-observation.xlsx")
            (root / "link").symlink_to(outside)
            with self.assertRaises(ObservationError):
                observe_workbook(root, "link")

    def test_bounded_folder_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            folder = root / "source"
            folder.mkdir()
            (folder / "one").write_text("1", encoding="utf-8")
            (folder / "two").write_text("2", encoding="utf-8")
            with self.assertRaises(ObservationError) as context:
                observe_folder(root, "source", maximum_entries=1)
            self.assertEqual(context.exception.code, "entry-limit-exceeded")

    def test_folder_observation_excludes_only_explicit_directory_names(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            folder = root / "source"
            (folder / "src").mkdir(parents=True)
            (folder / "generated").mkdir()
            (folder / "src" / "kept.txt").write_text("kept", encoding="utf-8")
            (folder / "generated" / "ignored.txt").write_text("ignored", encoding="utf-8")
            result = observe_folder(root, "source", excluded_directory_names=("generated",))
            self.assertEqual(result["entry_count"], 2)
            self.assertEqual(result["excluded_directory_count"], 1)
            self.assertEqual(result["excluded_directory_names"], ["generated"])

    def test_resource_folder_observation_accepts_bounded_exclusions(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            folder = root / "source"
            folder.mkdir()
            for name in ("one", "two", "three"):
                (folder / name).mkdir()
                (folder / name / "value.txt").write_text(name, encoding="utf-8")
            configuration = root / "configuration.json"
            configuration.write_text(json.dumps({
                "schema_version": "0.10.0",
                "resources": [{
                    "resource_ref": "resource/example/folder",
                    "kind": "folder",
                    "root": str(root),
                    "source": "source",
                    "maximum_entries": 4,
                    "excluded_directory_names": ["three"]
                }]
            }), encoding="utf-8")
            result = observe_resource(configuration, "resource/example/folder")
            self.assertEqual(result["entry_count"], 4)
            self.assertEqual(result["excluded_directory_count"], 1)
            self.assertNotIn(str(root), str(result))

    def test_resource_observation_hides_machine_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_workbook(root / "input.xlsx")
            configuration = root / "configuration.json"
            configuration.write_text(
                "{\"schema_version\":\"0.10.0\",\"resources\":[{"
                "\"resource_ref\":\"resource/example/workbook\","
                "\"kind\":\"workbook\","
                f"\"root\":{json.dumps(str(root))},"
                "\"source\":\"input.xlsx\"}]}",
                encoding="utf-8",
            )
            result = observe_resource(configuration, "resource/example/workbook")
            self.assertEqual(result["resource_ref"], "resource/example/workbook")
            self.assertNotIn(str(root), str(result))
            self.assertNotIn("input.xlsx", str(result))


if __name__ == "__main__":
    unittest.main()
