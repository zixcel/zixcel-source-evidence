# Typed compiler guest

The explicitly selected and hash-pinned Node/TypeScript compiler guest is now
TypeScript source (`typescript.mts` and `typescript-request.mts`), executed by
the existing Node 24.15 runtime without emitting JavaScript. The Python core is
unchanged except for selecting that packaged entrypoint; this is not a claim
that the Python analyzer has migrated to Rust.

The guest validates its input envelope, admits only supplied in-memory source,
and never executes analyzed code, loads project plugins/configuration or emits.
The compiler artifact itself remains an explicit trusted input checked by the
caller. Byte limits, requested AST/result/memory budgets and caller deadlines
remain distinct; these are not a guarantee of a whole-host memory ceiling.
UTF-8 is decoded incrementally and invalid streams are refused.

The npm manifest contains development-only compiler/type-check dependencies;
Python consumers need the existing explicit Node/compiler artifacts, not npm
installation or a sibling checkout. Both `.mts` files are shipped in the wheel.
Owner CI checks strict types and real compiler refusals, then installs the built
Python distribution before running the existing source/observation journeys.
Daily Dependabot covers the new development manifest with a three-day cooldown.
Third-party parsed fixture languages remain inputs, not first-party runtime code.
