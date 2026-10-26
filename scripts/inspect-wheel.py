"""Inspect the standard wheel/RECORD against this owner's exact runtime source."""
import ast
import base64
import configparser
import csv
from email.parser import BytesParser
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import stat
import subprocess
import sys
import tomllib
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def require(value, message):
    if not value:
        raise ValueError(message)


def inspect(path):
    require(not subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=normal"], cwd=ROOT),
            "wheel receipt requires a clean committed source tree")
    declaration = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
    model = ast.parse((ROOT / "src/zixcel_source_evidence/model.py").read_text())
    version = next(node.value.value for node in model.body if isinstance(node, ast.Assign)
                   and any(isinstance(target, ast.Name) and target.id == "VERSION" for target in node.targets))
    require(version == declaration["version"], "package and native version differ")
    require(not path.is_symlink() and path.stat().st_size <= 2097152, "wheel boundary rejected")
    source = {"zixcel_source_evidence/" + item.name: item.read_bytes()
              for item in (ROOT / "src/zixcel_source_evidence").iterdir() if item.suffix in {".py", ".mts"}}
    prefix = "zixcel_source_evidence-" + version + ".dist-info/"
    metadata_names = {prefix + name for name in ["METADATA", "WHEEL", "entry_points.txt", "top_level.txt", "RECORD", "licenses/LICENSE"]}
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_size <= 2097152, "wheel file boundary rejected")
        with zipfile.ZipFile(stream) as wheel:
            entries = wheel.infolist()
            require(len(entries) <= 100 and sum(item.file_size for item in entries) <= 2097152, "wheel expansion boundary rejected")
            require(len({item.filename for item in entries}) == len(entries), "duplicate wheel member")
            for item in entries:
                relative = PurePosixPath(item.filename)
                require(len(item.filename) <= 240 and not relative.is_absolute() and ".." not in relative.parts
                        and "\\" not in item.filename and not stat.S_ISLNK(item.external_attr >> 16), "unsafe wheel member")
            require(set(wheel.namelist()) == set(source) | metadata_names, "wheel source coverage differs")
            files = {name: wheel.read(name) for name in wheel.namelist()}
        stream.seek(0)
        archive_hash, size = hashlib.sha256(), 0
        while chunk := stream.read(65536):
            size += len(chunk)
            require(size <= 2097152, "wheel changed beyond its boundary")
            archive_hash.update(chunk)
        after = os.fstat(stream.fileno())
        require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns), "wheel changed during inspection")
    for name, content in source.items():
        require(files[name] == content, "wheel runtime bytes differ from source")
    require(files[prefix + "licenses/LICENSE"] == (ROOT / "LICENSE").read_bytes(), "wheel license differs")
    metadata = BytesParser().parsebytes(files[prefix + "METADATA"])
    require(metadata["Name"] == declaration["name"] and metadata["Version"] == version, "wheel identity differs")
    require(metadata["Requires-Python"] == declaration["requires-python"], "wheel Python boundary differs")
    require(metadata["License-Expression"] == declaration["license"], "wheel license expression differs")
    require(sorted(metadata.get_all("Requires-Dist", [])) == sorted(declaration["dependencies"]), "wheel dependencies differ")
    properties = BytesParser().parsebytes(files[prefix + "WHEEL"])
    require(properties["Root-Is-Purelib"] == "true" and properties.get_all("Tag") == ["py3-none-any"], "unexpected wheel platform")
    entrypoints = configparser.ConfigParser(interpolation=None)
    entrypoints.read_string(files[prefix + "entry_points.txt"].decode())
    require(entrypoints.sections() == ["console_scripts"] and dict(entrypoints["console_scripts"]) == declaration["scripts"], "wheel entry points differ")
    seen = set()
    for row in csv.reader(io.StringIO(files[prefix + "RECORD"].decode())):
        require(len(row) == 3 and row[0] in files and row[0] not in seen, "invalid wheel RECORD")
        seen.add(row[0])
        if row[0] == prefix + "RECORD":
            require(row[1:] == ["", ""], "invalid RECORD self entry")
        else:
            expected = "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(files[row[0]]).digest()).decode().rstrip("=")
            require(row[1] == expected and row[2] == str(len(files[row[0]])), "wheel RECORD integrity differs")
    require(seen == set(files), "incomplete wheel RECORD")
    return {"schemaVersion": 1, "name": declaration["name"], "version": version,
            "source": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
            "sha256": archive_hash.hexdigest(), "runtimeFiles": len(source),
            "files": {name: hashlib.sha256(value).hexdigest() for name, value in sorted(files.items())}}


if __name__ == "__main__":
    require(len(sys.argv) == 3, "usage: inspect-wheel.py WHEEL RECEIPT")
    receipt = inspect(Path(sys.argv[1]))
    Path(sys.argv[2]).write_text(json.dumps(receipt, indent=2) + "\n")
    print(f"Verified {receipt['runtimeFiles']} runtime files, metadata, license and RECORD against owner source.")
