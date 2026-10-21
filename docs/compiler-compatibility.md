# Compiler API compatibility

Node and TypeScript are separate dependencies. Owner CI uses the patched Node 24.22.1 runtime. The optional compiler observation bridge is verified with the public TypeScript 5.9.3 CompilerHost/createProgram API. TypeScript 7.0.2 does not expose that API at the same package entrypoint, so its major upgrade is not accepted merely because it is newer. No private compiler checkout, compatibility decoder, unchecked type escape or silent syntax-only substitution is introduced.

The caller still supplies and pins the exact compiler/Node artifacts. The bridge checks required public compiler functions and constants before use; missing APIs yield the existing AnalyzerUnavailable state, not a successful empty result. These shape checks do not establish artifact trust or claim conformance of arbitrary future compiler versions. New major APIs require an explicit bridge migration and real independent-consumer tests. Compatible updates and security updates remain enabled; this source change adds no Dependabot ignore or alert dismissal.

Node type declarations follow the current Node 24 execution target. A types-only update to Node 26 is not a Node executable security fix. Reconsider that major when the execution target changes and the real compiler/consumer boundary has been validated.
