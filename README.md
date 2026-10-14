# zixcel-source-evidence

Index source observations and query evidence tied to a specific source revision.

## What you can do

- Create and inspect a local source index.
- Resolve bounded evidence queries to retained source references.

## Current scope

This is a source-evidence implementation. Complete semantic resolution and effect inference remain outside its current guarantees.

Package distribution is not activated by this documentation. Use the checked-in source and the declared dependency versions; published availability must be verified separately.

## Getting started

```sh
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -e .
```

## Examples and interface details

## API and identity

```python
from zixcel_source_evidence import Index, SymbolRef, PacketLimits

with Index.open_existing('/absolute/evidence.db') as index:
    symbol = SymbolRef(index.find_symbols('work')[0]['id'])
    packet = index.build_packet(symbol, PacketLimits(max_bytes=32768))
    upstream = index.dependencies_of(symbol)
    downstream = index.dependents_of(symbol)
```

RepositoryRef, PackageRef, SourceFileRef, SymbolRef, TypeRef, StoreRef and
ExternalEffectRef are distinct Python types. Wire references are carried in
typed fields; consumers must not interchange them. File identity includes the
explicit repository key and relative path. Symbol identity includes AST kind,
qualified declaration scope and same-name ordinal. Moving a file/symbol removes
its old identity and adds a new one; no heuristic rename alias is fabricated.
Package identity includes manifest location and declared package name.
Nested `.git` markers and `repository.toml` delimit independent repositories.
Their identities use the observation namespace plus relative boundary; remote
URLs and Git configuration are not read. A nested repository never inherits an
outer repository's package manifest. Forward/reverse/ownership queries accept
typed file and type references as well as symbols; file queries return the file's
direct declarations, not an implicit union of every contained function.
Packets also accept SourceFileRef (`packet build ... --subject-kind file`).
Top-level code is retained as a sanitized source slice; declarations have their
own SymbolRefs and indexed Declaration relations. This allows script entrypoints
without named functions to provide evidence. File packets explicitly withhold
top-level effect proof; an empty effect array never establishes purity.

Evidence revisions include relevant source/manifest digests, symbol/type records,
forward dependencies, direct reverse references, analyzer implementation digest,
grammar versions and rule digest. Collection ordering is canonical. A full
index digest includes its observation root; unrelated file changes may alter
that digest without changing an unrelated symbol packet's evidence digest.

## Resolution contract

`Resolved` means a structurally bound source reference; it does **not** mean a
compiler proved a program's runtime behavior. Type references point to declared
syntax types, labelled `Declared`. Same-file free calls may bind directly;
imports, method dispatch and shadowed targets retain `CandidateTargets` or
`Unresolved`. Rust cfg attributes are observations, not evaluation for a guessed
build target. Macro expansion is not executed. Cross-language execution remains
unresolved. Compiler diagnostics/type inference, fully qualified Rust trait
resolution across external crates is **not complete**. An optional, artifact-pinned
rust-analyzer observer and TypeScript checker are available through the same
index create/update API. Their normalized `compiler` observations include exact
tool/context digests, target sets and missing evidence. They do not overwrite
ordinary reference edges or claim full runtime/type resolution.
Additional observed compiler targets are persisted as scope-qualified candidate
edges, so reverse queries and invalidation see the same relationship. An exact
target in a projected compilation context is not promoted to runtime proof.

Compiler configuration is an explicit trusted `rules` object (CLI `--rules`):

```json
{
  "version": "0.10.0",
  "effects": [],
  "rust_compiler": {"executable": "/installed/bin/rust-analyzer", "sha256": "ARTIFACT_SHA256"},
  "typescript_compiler": {
    "module": "/installed/typescript/lib/typescript.js", "sha256": "ARTIFACT_SHA256",
    "node": "/installed/bin/node", "node_sha256": "ARTIFACT_SHA256"
  }
}
```

Rust uses a private, disposable source projection with literal contents made
inert, no sysroot/dependency discovery, no proc macros or Cargo, and no inherited
environment secrets. The declared edition (including observed workspace
inheritance) is used; absent inheritance is explicitly a projection default.
Empty cfg is a projection constraint, not an assertion of the project's build configuration. Its process group is
reaped on exit/failure; CPU/request time and observed RSS are bounded. TypeScript
uses only supplied in-memory files, no plugins/tsconfig/filesystem fallback or
emit. Standard library and external package types are absent, explicitly.
The trusted compiler artifacts are not downloaded or installed by this library.

Effect records default to UNKNOWN. Empty function bodies have a closed PURE
rule. Other effect categories can be recorded only by explicit rules pinned to
the exact symbol digest; their provenance is `explicit_source_rule`, not compiler
proof. Store identity remains Unresolved rather than manufacturing a StoreRef
from a function name. The package does not infer canonical authority from a method named
`commit`, `write`, `publish` or `recover`. `assess()` returns Observed/NeedEvidence,
never permission or a consumer-specific classification.

## Lifecycle, safety and bounds

Build a private candidate, validate all references/digests, recheck source bytes,
then compare-and-replace under a short publication lock. fsync precedes rename
and follows it on the parent directory. Existing reader connections retain the
old inode; a new reader sees the new baseline. Parse/resolve/write failures
leave the previous index unchanged. Only the private unpublished file owned by
that invocation is removed. No reader creates locks, indexes or repairs.

Incremental update reuses unchanged per-file parse products and index records.
It conservatively re-resolves changed packages and importers/reexports found in
the persisted reverse graph. Other packages' records are reused. Source bytes
are checked for staleness; SQLite backup prepares the next private snapshot.
Publication still checks the full index integrity and input byte digests.
Changing the analyzer invalidates its parse products and builds a fresh candidate
instead of copying/deleting all old rows. Physical file/reverse indexes support
incremental replacement; candidate SQLite cache is capped at one quarter of the
memory budget (maximum 256 MiB). Canonical bytes are hashed directly without a
redundant JSON decode/re-encode, preserving the exact digest representation.
Reader cache is bounded to one sixteenth of the configured budget (maximum
64 MiB). Publication returns the already validated immutable reader, avoiding a
redundant full scan or accidentally returning a subsequent writer's snapshot.

Default bounds: file 2 MiB, inventory 256 MiB/30,000 files, 500,000 symbols,
1,000,000 observed edges, 500,000 AST nodes per file, one supervised parser and no
queued parser jobs. The parser has an OS address-space ceiling of half the 1 GiB
memory budget and a 60-second request deadline. Its bounded IPC is closed and
the process is joined/terminated/killed on shutdown or failure. Parent RSS is
checked between files; a hard total parent-plus-parser ceiling remains distinct
from this parser bound. Query/traversal counts and depth are
bounded; overflow is typed. Packet limits cover total bytes, source bytes,
relation/type/effect counts and depth. Partial packets report omitted categories
and a revision-bound continuation. Large source slices are paged with explicit
byte offsets and exact source digests. Other indivisible records require a larger
budget. EvidenceRequest filters relations/effects before spending the packet
budget. Diff uses bounded symbol pages and baseline-bound continuation; global
edge/effect counts use streaming comparison rather than materializing whole sets.
The exact EvidenceRevisionSet remains available through the index API. Packets
carry its fixed descriptor/digest and page the potentially large `revision_inputs`
list. Reassembling those entries must match `inputs_digest`; the descriptor never
pretends that a partial list is the complete revision set. `page_start` and the
continuation explicitly identify the selected segment of every category.
CLI packet/diff commands accept the returned JSON with `--continuation`. When
only traversal depth is missing, the packet requests expanded bounds without a
non-advancing cursor. An indivisible item that cannot advance a page returns a
typed limit error. The parser is reaped before any compiler is started.

Symlinks and special files are rejected. Source reads use directory descriptors,
O_NOFOLLOW, byte caps and before/after stat checks. Generated/build dependency
directories are excluded. Raw strings/comments and long numeric literals are
masked before source slices are persisted. Structured-file values are never
included. Only source identifiers and digests leave the observer. This is not a
general DLP guarantee for secrets encoded as legal identifiers; deployments must
scope repositories and avoid credential stores.

## Documentation and source

[Interface reference](docs/interface-reference.md)

[Usage guide](docs/getting-started.md)

[Implementation and public interfaces](src) · [Verification cases](tests) · [Contributing](CONTRIBUTING.md) · [Security reporting](SECURITY.md) · [License](LICENSE) · [Attribution notices](NOTICE)

[OSS responsibility and source completion](docs/oss-source-contract.md) defines the supported package boundary and required acceptance. It does not declare unexecuted source, distribution or production checks complete.

Dependency updates: [repository policy](docs/dependency-updates.md).
