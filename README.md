# Zixcel Source Evidence

Version 0.10.0. A standalone Python library and JSON CLI for revision-pinned
source observations. This package is **not yet product-complete**: compiler
resolution and precise effect inference remain explicit limitations below.
Never interpret its tests passing as completion of a consumer's migration.

## Responsibility

Observe source without starting applications, build scripts, Cargo, project
hooks, tests or language-server plugins. Store symbols, declared types, observed
references and explicit unresolved relations. Query the immutable evidence
without rereading repositories. Callers own semantic admission and integration of the resulting evidence.

The package uses Python's SQLite and compression libraries, pinned Tree-sitter
grammars, sqlparse and tinycss2. Rust/JS/TS/Python/Shell and Starlark use syntax
trees; TS declaration modules (`.d.mts`/`.cts`) are included. Vue script blocks
use the TS adapter, HTML script blocks the JS adapter, with separate markup
component observations. JSON,
TOML and SQL are structured-file observations; CSS/YAML expose syntax-parsed
rule/key declarations, not evaluation of CSS or workflow execution. Unknown formats are
reported in inventory findings, not silently counted as analyzed.
Nix, Makefile and PowerShell have syntax adapters; systemd unit files have a
structured INI adapter. Executable extensionless shell/Python entrypoints are
recognized from explicit supported shebangs. Nothing is executed. Symbol kinds
are normalized (`Function`, `Method`, `Struct`, `BuildRule`, etc.), not parser
node names. Make recipes are withheld as opaque source; command execution and
Make expansion are not inferred from unparsed recipe text.
For the Bash grammar's unsupported `0$MODE` arithmetic numeral form, a
width-preserving syntax projection omits the numeral prefix only inside that
arithmetic node. Original source bytes/digests remain the evidence; arithmetic
evaluation is explicitly missing. Other parse errors still reject publication.
Structured data expose top-level declarations with nested content revision-pinned,
not one executable SymbolRef/effect per lockfile entry. Configuration keys do not
populate StoreEffectIndex. This is explicit structured coverage, not an assertion
that nested configuration values have runtime semantics.

## Install and use

Build/install the wheel with standard Python packaging. Python >=3.12 on Linux
is required (descriptor-relative paths, no-follow opens, advisory locks).
No application source is executed during installation or analysis.

```sh
zixcel-source-evidence index create /absolute/evidence.db /absolute/source --repository my-repository
zixcel-source-evidence index status /absolute/evidence.db
zixcel-source-evidence query symbols /absolute/evidence.db repair_pending_completion
zixcel-source-evidence inspect symbol /absolute/evidence.db SYMBOL_ID
zixcel-source-evidence packet build /absolute/evidence.db SYMBOL_ID --depth 2
zixcel-source-evidence index update /absolute/evidence.db
zixcel-source-evidence doctor /absolute/evidence.db
```

Create requires an existing storage parent and a missing index. Update/rebuild
require an existing valid index. A corrupt index is never repaired implicitly:
create a separate explicitly chosen index, verify it, then retire the corrupt
artifact. Every output is JSON; exit 2 means a typed failure or doctor findings.
`index verify` checks index integrity; `doctor` additionally observes current
source bytes and analyzer provenance. Index queries are pinned historical reads,
not an assertion that live source still matches.

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

## Validation

`python -m unittest discover -s tests -v` runs compound lifecycle, language,
dependency, corruption, path, failure-injection and concurrent-reader journeys.
Tests assert returned references, digests, state transitions and retained data.
Compiler journeys require `SOURCE_EVIDENCE_RUST_ANALYZER`,
`SOURCE_EVIDENCE_TYPESCRIPT`, and `SOURCE_EVIDENCE_NODE` artifact paths. Missing
tools produce an explicit skipped journey; a product acceptance run must count
skips as incomplete, not success. All three paths must refer to trusted installed
tools, never executable content from an inspected repository.
Full compiler/effect conformance and the complete C5 consumer run are separate
acceptance requirements, not implied by these tests.

Source-domain dependency kinds and StoreEffectIndex stay here. Future generic
revision-set/traversal primitives may be proposed separately; no generic Graph
API or runtime authority is added by this package.

## Package integration

The package is an independently consumable unit. Callers reference its documented
interface through a versioned dependency and own application-specific composition
and integration.
