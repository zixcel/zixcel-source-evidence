// Trusted compiler host: only the supplied in-memory source exists. No tsconfig,
// plugins, module execution, filesystem fallback, emit, package hooks or network.
import { createRequire } from 'node:module'
import type * as TypeScript from 'typescript'
import { CompilerFailure, decodeRequest } from './typescript-request.mts'
const cap = 32 * 1024 * 1024
let raw = '', received = 0
try {
  const decoder = new TextDecoder('utf-8', { fatal: true })
  for await (const chunk of process.stdin) {
    const bytes: unknown = chunk
    if (!Buffer.isBuffer(bytes)) throw new CompilerFailure('ResolutionFailure')
    received += bytes.byteLength
    if (received > cap) throw new CompilerFailure('ResourceLimitExceeded')
    raw += decoder.decode(bytes, { stream: true })
  }
  raw += decoder.decode()
  const request = decodeRequest(JSON.parse(raw) as unknown)
  // The Python caller pins the explicit compiler and Node artifacts before invocation.
  const ts: typeof TypeScript = createRequire(import.meta.url)(request.module)
  const paths = Object.keys(request.files).sort()
  const options = { noEmit: true, noLib: true, allowJs: true, checkJs: true,
    target: ts.ScriptTarget.ESNext, module: ts.ModuleKind.ESNext,
    moduleResolution: ts.ModuleResolutionKind.Bundler, skipLibCheck: true }
  const host: TypeScript.CompilerHost = {
    fileExists: p => Object.hasOwn(request.files, p),
    readFile: p => request.files[p],
    getSourceFile: (p, version) => {
      const source = request.files[p]
      return source === undefined ? undefined : ts.createSourceFile(p, source, version, true)
    },
    getDefaultLibFileName: () => '/unavailable.d.ts',
    getCurrentDirectory: () => '/', getDirectories: () => [],
    directoryExists: p => paths.some(f => f.startsWith(p.endsWith('/') ? p : `${p}/`)),
    writeFile: () => { throw new Error('emit forbidden') },
    getCanonicalFileName: p => p, useCaseSensitiveFileNames: () => true,
    getNewLine: () => '\n'
  }
  const program = ts.createProgram(paths, options, host)
  const checker = program.getTypeChecker()
  const observedType = (node: TypeScript.Node) => {
    const type = checker.getTypeAtLocation(node)
    const categories = [['Unknown', ts.TypeFlags.Any | ts.TypeFlags.Unknown],
      ['String', ts.TypeFlags.StringLike], ['Number', ts.TypeFlags.NumberLike],
      ['Boolean', ts.TypeFlags.BooleanLike], ['Void', ts.TypeFlags.Void],
      ['Null', ts.TypeFlags.Null], ['Undefined', ts.TypeFlags.Undefined],
      ['Union', ts.TypeFlags.Union], ['Intersection', ts.TypeFlags.Intersection],
      ['Object', ts.TypeFlags.Object]] as const
    const kind = categories.find(([, mask]) => type.flags & mask)?.[0] ?? 'Other'
    return { kind, resolution: kind === 'Unknown' ? 'Unresolved' : 'InferredUnderProjection' }
  }
  interface Target { path: string; start: number; end: number }
  interface Observation { path: string; start: number; kind: 'Call' | 'Property'; type: ReturnType<typeof observedType>; targets: Target[] }
  const observations: Observation[] = []
  const location = (d: TypeScript.Node): Target | null => {
    const file = d.getSourceFile()
    if (!Object.hasOwn(request.files, file.fileName)) return null
    return { path: file.fileName, start: Buffer.byteLength(file.text.slice(0, d.getStart(file))),
      end: Buffer.byteLength(file.text.slice(0, d.end)) }
  }
  let nodes = 0
  for (const path of paths) {
    const file = program.getSourceFile(path)
    if (!file) continue
    const stack: TypeScript.Node[] = [file]
    while (stack.length) {
      const node = stack.pop()!
      if (++nodes > request.max_nodes) throw new CompilerFailure('ResourceLimitExceeded')
      if (ts.isCallExpression(node) || ts.isPropertyAccessExpression(node)) {
        let declarations: readonly TypeScript.Node[] = []
        if (ts.isCallExpression(node)) {
          const signature = checker.getResolvedSignature(node)
          if (signature?.declaration) declarations = [signature.declaration]
        } else {
          let symbol = checker.getSymbolAtLocation(node.name)
          if (symbol && (symbol.flags & ts.SymbolFlags.Alias)) symbol = checker.getAliasedSymbol(symbol)
          declarations = symbol?.declarations ?? []
        }
        observations.push({ path, start: Buffer.byteLength(file.text.slice(0, node.getStart(file))),
          kind: ts.isCallExpression(node) ? 'Call' : 'Property',
          type: observedType(node),
          targets: declarations.map(location).filter((target): target is Target => target !== null) })
        if (observations.length > request.max_results) throw new CompilerFailure('ResourceLimitExceeded')
      }
      ts.forEachChild(node, child => { stack.push(child) })
    }
    if (process.memoryUsage().rss > request.memory_bytes) throw new CompilerFailure('ResourceLimitExceeded')
  }
  const response = JSON.stringify({ version: ts.version, observations })
  if (Buffer.byteLength(response) > cap) throw new CompilerFailure('ResourceLimitExceeded')
  process.stdout.write(response)
} catch (error) {
  process.stdout.write(JSON.stringify({ error: error instanceof CompilerFailure ? error.code : 'ResolutionFailure', detail: 'TS compiler observation failed' }))
  process.exitCode = 2
}
