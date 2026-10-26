# PHP and multi-block Vue syntax ABI (0.11.0)

The source owner reuses its existing supervised Tree-sitter adapter, index,
revision binding and packet API. PHP uses the declared `tree-sitter-php` 0.25.1
`language_php` grammar with core 0.26.0; it never invokes PHP, Composer, application
bootstrap, project plugins or included files. Grammar versions, the native
implementation digest and the rule derived from package VERSION bind observations.

PHP declares functions, classes, methods, interfaces, traits, enums and namespace
headers as native syntax symbols. `Namespace` is an additional symbol kind;
consumers with a closed kind catalog must handle it explicitly. Qualified scope
reflects only actual AST parents. Unbracketed namespace membership, Composer
PSR/autoload, include resolution, runtime dispatch and effects are not inferred.
Call/import observations retain their syntax fingerprints and unresolved status;
the generic same-file name binder cannot accidentally resolve PHP methods or
namespaced functions. Native compiler/semantic acceptance remains a separate
producer requirement. Parser errors refuse publication rather than publishing a
partially valid index.

PHP string/comment/heredoc/nowdoc and inline HTML text are withheld from sanitized
source, including file-level packets. Names and exact hashes remain observations;
the index itself and its selected references are private source-derived data.
Literal withholding is not a complete secret-detection guarantee.

Vue reuses the existing HTML plus embedded TypeScript adapters. Same-name ordinals
are now file-wide across script blocks, so normal/setup declarations cannot share
an identity. Multi-block call scopes remain unresolved until accepted SFC compiler
binding. Explicit residuals retain template/style/SFC compiler semantics for both
file and symbol packets. The adapter does not certify Vue template completeness,
component runtime behavior or generated application equivalence.

FORMAT remains `zixcel/source/evidence/1`. Package/rule and implementation revisions
change to 0.11.0. Existing readers are not silently rescanned; an explicit owner
update detects analyzer changes and rebuilds its candidate atomically before CAS
publication. Existing immutable readers remain pinned to their original snapshot.
Consumers must review this producer version and residual/kind handling before
changing their source/package pin; a new parser does not clear existing missing
semantic/effect proof.

`tests/test_php_vue.py` exercises actual parser workers, declarations, safe
unresolved dispatch, retained residuals, invalid-source refusal, literal
withholding, reopened packet identity and the absence of PHP execution. Full owner
CI also tests the installed Python distribution and existing compiler/observation
journeys. Local focused tests use unchanged 512 MiB operation limits and a fresh
owned test process; they do not resume held host/model/isolation trials.


Distribution verification uses a clean committed checkout. The retained standard
wheel is compared against every runtime Python/MTS source, its standard RECORD,
entry points/dependencies, README and all three declared license/notice files.
Unknown members (including retired JavaScript in stale build output) fail before
publication. Do not reuse an old `build/lib` snapshot as a package source. The
wheel wrapper is pure Python, but current observation/worker acceptance is Linux
with Python 3.12+; no Windows, macOS or resumed host trial is implied.
