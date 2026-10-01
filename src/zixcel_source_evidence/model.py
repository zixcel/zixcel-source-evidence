"""Source-domain contracts. IDs never imply permission, meaning or causation."""
from dataclasses import dataclass, asdict
from enum import StrEnum
import hashlib
import json
import zlib

VERSION = "0.10.0"
FORMAT = "zixcel/source/evidence/1"


class Code(StrEnum):
    UnsupportedLanguage = "UnsupportedLanguage"
    ParseFailure = "ParseFailure"
    ResolutionFailure = "ResolutionFailure"
    SourceChangedDuringAnalysis = "SourceChangedDuringAnalysis"
    CorruptIndex = "CorruptIndex"
    StaleIndex = "StaleIndex"
    UnsafePath = "UnsafePath"
    ResourceLimitExceeded = "ResourceLimitExceeded"
    AnalyzerUnavailable = "AnalyzerUnavailable"
    InvalidEvidence = "InvalidEvidence"
    UnsupportedDynamicResolution = "UnsupportedDynamicResolution"
    InternalFailure = "InternalFailure"
    MissingIndex = "MissingIndex"
    PublicationConflict = "PublicationConflict"


class EvidenceError(Exception):
    def __init__(self, code: Code, detail: str = ""):
        self.code, self.detail = code, detail
        super().__init__(code.value)

    def wire(self):
        return {"error": self.code.value, "detail": self.detail}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def digest(value):
    return hashlib.sha256(value if isinstance(value, bytes) else canonical(value).encode()).hexdigest()


def pack(value):
    return zlib.compress(canonical(value).encode(), level=3)


def packed_canonical(value):
    try:
        decoder = zlib.decompressobj()
        raw = decoder.decompress(value, 64 * 1024 * 1024)
        if not decoder.eof or decoder.unused_data:
            raise EvidenceError(Code.CorruptIndex, "invalid or oversized compressed record")
        return raw
    except (zlib.error, ValueError, TypeError) as error:
        raise EvidenceError(Code.CorruptIndex, "invalid compressed record") from error


def unpack(value):
    try:
        return json.loads(packed_canonical(value))
    except (ValueError, TypeError) as error:
        raise EvidenceError(Code.CorruptIndex, "invalid record JSON") from error


@dataclass(frozen=True)
class RepositoryRef:
    value: str


@dataclass(frozen=True)
class PackageRef:
    value: str


@dataclass(frozen=True)
class SourceFileRef:
    value: str


@dataclass(frozen=True)
class SymbolRef:
    value: str


@dataclass(frozen=True)
class TypeRef:
    value: str


@dataclass(frozen=True)
class StoreRef:
    value: str


@dataclass(frozen=True)
class ExternalEffectRef:
    value: str


def ref(kind, *identity):
    return kind(digest([kind.__name__, *identity]))


class Relation(StrEnum):
    Import = "Import"
    Call = "Call"
    ReverseCall = "ReverseCall"  # query view, never a second canonical edge
    TraitDispatch = "TraitDispatch"
    TypeReference = "TypeReference"
    Callback = "Callback"
    Read = "Read"
    Write = "Write"
    ReceiptConsume = "ReceiptConsume"
    ExternalEffect = "ExternalEffect"
    RecoveryDependency = "RecoveryDependency"
    ProjectionDependency = "ProjectionDependency"
    Module = "Module"
    Include = "Include"
    Component = "Component"
    Macro = "Macro"
    Property = "Property"
    Declaration = "Declaration"


class Effect(StrEnum):
    READ = "READ"
    WRITE_CANONICAL = "WRITE_CANONICAL"
    WRITE_BACKEND = "WRITE_BACKEND"
    WRITE_RECOVERY = "WRITE_RECOVERY"
    EXTERNAL_EFFECT = "EXTERNAL_EFFECT"
    RECEIPT_READ = "RECEIPT_READ"
    RECEIPT_WRITE = "RECEIPT_WRITE"
    SECURITY_CONSUME = "SECURITY_CONSUME"
    DERIVED_PROJECTION = "DERIVED_PROJECTION"
    PURE = "PURE"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class Limits:
    file_bytes: int = 2 * 1024 * 1024
    repository_bytes: int = 256 * 1024 * 1024
    files: int = 30000
    symbols: int = 500000
    edges: int = 1000000
    ast_nodes: int = 500000
    memory_bytes: int = 1024 * 1024 * 1024
    queue_depth: int = 1
    parallel_parsers: int = 1
    parser_seconds: int = 60
    result_size: int = 4096
    traversal_depth: int = 16

    def validate(self):
        if any(type(v) is not int or v < 1 for v in asdict(self).values()):
            raise EvidenceError(Code.InvalidEvidence, "positive integer limits required")
        if self.parallel_parsers != 1 or self.queue_depth != 1:
            raise EvidenceError(Code.ResourceLimitExceeded, "this serial analyzer admits one parser and no queued work")


@dataclass(frozen=True)
class PacketLimits:
    max_bytes: int = 65536
    max_source_bytes: int = 8192
    max_dependencies: int = 64
    max_reverse_dependencies: int = 64
    max_types: int = 32
    max_effects: int = 32
    max_revision_inputs: int = 64
    max_depth: int = 1

    def validate(self):
        if any(type(v) is not int or v < 0 for v in asdict(self).values()) or self.max_bytes < 256:
            raise EvidenceError(Code.InvalidEvidence, "invalid packet limits")


@dataclass(frozen=True)
class EvidenceRequest:
    subject: SymbolRef | SourceFileRef
    relations: tuple[Relation, ...] = ()
    effects: tuple[Effect, ...] = ()
    limits: PacketLimits = PacketLimits()
