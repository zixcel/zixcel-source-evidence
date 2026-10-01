"""Descriptor-relative reads: never execute projects or follow source symlinks."""
import os
from pathlib import Path, PurePosixPath
import stat
from .model import Code, EvidenceError, Limits, digest, ref, RepositoryRef

LANGUAGES = {".rs": "rust", ".ts": "typescript", ".tsx": "tsx", ".js": "javascript",
             ".mts": "typescript", ".cts": "typescript", ".bazel": "starlark", ".bzl": "starlark", ".html": "html",
             ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript", ".vue": "vue",
             ".py": "python", ".sh": "bash", ".sql": "sql", ".json": "json", ".toml": "toml",
             ".css": "css", ".md": "documentation", ".yaml": "yaml", ".yml": "yaml"}
LANGUAGES.update({".nix": "nix", ".ps1": "powershell", ".service": "ini", ".timer": "ini"})
NAMES = {"Cargo.lock": "toml", "Makefile": "make", "GNUmakefile": "make"}
EXCLUDED = frozenset({".git", ".artifacts", ".venv", "node_modules", "target", "build", "dist", "vendor",
                      ".nuxt", ".output", "__pycache__", "protocol-snapshot"})


def directory(path):
    absolute = Path(os.path.abspath(path))
    for part in [*reversed(absolute.parents), absolute]:
        try:
            if not stat.S_ISDIR(part.lstat().st_mode):
                raise EvidenceError(Code.UnsafePath, "non-directory or symlink directory")
        except FileNotFoundError as error:
            raise EvidenceError(Code.UnsafePath, "missing directory") from error
    return absolute


def safe_read(root, relative, maximum):
    parts = PurePosixPath(relative).parts
    if not parts or PurePosixPath(relative).is_absolute() or any(p in {"..", "."} for p in parts):
        raise EvidenceError(Code.UnsafePath, "invalid relative path")
    fd = os.open(directory(root), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in parts[:-1]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        source = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        try:
            before = os.fstat(source)
            if not stat.S_ISREG(before.st_mode):
                raise EvidenceError(Code.UnsafePath, "not a regular file")
            if before.st_size > maximum:
                raise EvidenceError(Code.ResourceLimitExceeded, "file bytes")
            chunks, size = [], 0
            while chunk := os.read(source, min(65536, maximum + 1 - size)):
                size += len(chunk)
                if size > maximum:
                    raise EvidenceError(Code.ResourceLimitExceeded, "file bytes")
                chunks.append(chunk)
            after = os.fstat(source)
            if (before.st_dev, before.st_ino, before.st_mtime_ns, before.st_ctime_ns, before.st_size) != (
                    after.st_dev, after.st_ino, after.st_mtime_ns, after.st_ctime_ns, after.st_size):
                raise EvidenceError(Code.SourceChangedDuringAnalysis)
            return b"".join(chunks)
        finally:
            os.close(source)
    except OSError as error:
        raise EvidenceError(Code.UnsafePath, "source open rejected") from error
    finally:
        os.close(fd)


def inventory(root, limits=Limits()):
    limits.validate()
    root = directory(root)
    findings, files, total = [], [], 0
    def failed(error):
        raise EvidenceError(Code.UnsafePath, "unreadable inventory directory") from error
    for current, dirs, names in os.walk(root, followlinks=False, onerror=failed):
        dirs[:] = sorted(d for d in dirs if d not in EXCLUDED and not d.endswith(".egg-info"))
        for name in list(dirs):
            path = Path(current, name)
            if path.is_symlink():
                findings.append({"path": path.relative_to(root).as_posix(), "code": Code.UnsafePath.value})
                dirs.remove(name)
        for name in sorted(names):
            if len(files)+len(findings) >= limits.files:
                raise EvidenceError(Code.ResourceLimitExceeded, "inventory entries")
            path = Path(current, name)
            rel = path.relative_to(root).as_posix()
            if path.is_symlink() or not stat.S_ISREG(path.lstat().st_mode):
                findings.append({"path": rel, "code": Code.UnsafePath.value})
                continue
            language = NAMES.get(name, LANGUAGES.get(path.suffix))
            if language is None and not path.suffix and path.stat().st_mode & 0o111:
                # Inspect only executable, extensionless regular files. Secret
                # formats are never opened to guess a language.
                first = safe_read(root, rel, limits.file_bytes).split(b"\n", 1)[0]
                if first in {b"#!/bin/sh", b"#!/bin/bash", b"#!/usr/bin/env bash", b"#!/usr/bin/env sh"}:
                    language = "bash"
                elif first in {b"#!/usr/bin/python3", b"#!/usr/bin/env python3"}:
                    language = "python"
            if language is None:
                # Never claim unknown executable formats were analyzed.
                findings.append({"path": rel, "code": Code.UnsupportedLanguage.value})
                continue
            if language == "documentation":
                continue
            size = path.stat().st_size
            total += size
            if size > limits.file_bytes or total > limits.repository_bytes or len(files) >= limits.files:
                raise EvidenceError(Code.ResourceLimitExceeded, "source inventory")
            files.append((rel, language))
    return sorted(files), findings


def observe(root, path, limits):
    raw = safe_read(root, path, limits.file_bytes)
    try:
        raw.decode("utf-8")
    except UnicodeError as error:
        raise EvidenceError(Code.ParseFailure, "source is not UTF-8") from error
    return raw, digest(raw)


def repositories(root, paths, identity):
    """Discover local ownership boundaries without Git execution/config reads.

    A .git directory/worktree marker or repository.toml declares a boundary.
    Identity is the caller's observation namespace plus relative boundary, never
    a remote URL or unverified package name. A move deliberately changes refs.
    """
    parents = {"."}
    for path, _ in paths:
        parents.update(str(p) for p in PurePosixPath(path).parents)
    result = {".": ref(RepositoryRef, identity).value}
    for parent in sorted(parents):
        if parent == ".":
            continue
        for marker in [".git", "repository.toml"]:
            candidate = Path(root, parent, marker)
            try:
                mode = candidate.lstat().st_mode
            except FileNotFoundError:
                continue
            if stat.S_ISREG(mode) or (marker == ".git" and stat.S_ISDIR(mode)):
                result[parent] = ref(RepositoryRef, identity, parent).value
                break
    return result
