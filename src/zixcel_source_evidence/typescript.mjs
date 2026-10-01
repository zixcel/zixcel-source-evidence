// Trusted compiler host: only the supplied in-memory source exists. No tsconfig,
// plugins, module execution, filesystem fallback, emit, package hooks or network.
import { createRequire } from 'node:module'
const cap = 32 * 1024 * 1024
let raw = ''
for await (const chunk of process.stdin) {
  raw += chunk.toString('utf8')
  if (Buffer.byteLength(raw) > cap) {
    process.stdout.write(JSON.stringify({ error: 'ResourceLimitExceeded', detail: 'TS compiler input' }))
    process.exit(2)
  }
}
try {
  const request = JSON.parse(raw)
  const ts = createRequire(import.meta.url)(request.module)
  const paths = Object.keys(request.files).sort()
  const options = { noEmit: true, noLib: true, allowJs: true, checkJs: true,
    target: ts.ScriptTarget.ESNext, module: ts.ModuleKind.ESNext,
    moduleResolution: ts.ModuleResolutionKind.Bundler, skipLibCheck: true }
  const host = {
    fileExists: p => Object.hasOwn(request.files, p),
    readFile: p => request.files[p],
    getSourceFile: (p, version) => Object.hasOwn(request.files, p)
      ? ts.createSourceFile(p, request.files[p], version, true) : undefined,
    getDefaultLibFileName: () => '/unavailable.d.ts',
    getCurrentDirectory: () => '/', getDirectories: () => [],
    directoryExists: p => paths.some(f => f.startsWith(p.endsWith('/') ? p : `${p}/`)),
    writeFile: () => { throw new Error('emit forbidden') },
    getCanonicalFileName: p => p, useCaseSensitiveFileNames: () => true,
    getNewLine: () => '\n'
  }
  const program = ts.createProgram(paths, options, host)
  const checker = program.getTypeChecker()
  const observedType = node => {
    const type = checker.getTypeAtLocation(node)
    const categories = [['Unknown', ts.TypeFlags.Any | ts.TypeFlags.Unknown],
      ['String', ts.TypeFlags.StringLike], ['Number', ts.TypeFlags.NumberLike],
      ['Boolean', ts.TypeFlags.BooleanLike], ['Void', ts.TypeFlags.Void],
      ['Null', ts.TypeFlags.Null], ['Undefined', ts.TypeFlags.Undefined],
      ['Union', ts.TypeFlags.Union], ['Intersection', ts.TypeFlags.Intersection],
      ['Object', ts.TypeFlags.Object]]
    const kind = categories.find(([, mask]) => type.flags & mask)?.[0] ?? 'Other'
    return { kind, resolution: kind === 'Unknown' ? 'Unresolved' : 'InferredUnderProjection' }
  }
  const observations = []
  const location = d => {
    const file = d.getSourceFile()
    if (!Object.hasOwn(request.files, file.fileName)) return null
    return { path: file.fileName, start: Buffer.byteLength(file.text.slice(0, d.getStart(file))),
      end: Buffer.byteLength(file.text.slice(0, d.end)) }
  }
  let nodes = 0
  for (const path of paths) {
    const file = program.getSourceFile(path)
    if (!file) continue
    const stack = [file]
    while (stack.length) {
      const node = stack.pop()
      if (++nodes > request.max_nodes) throw { typed: 'ResourceLimitExceeded' }
      if (ts.isCallExpression(node) || ts.isPropertyAccessExpression(node)) {
        let declarations = []
        if (ts.isCallExpression(node)) {
          const signature = checker.getResolvedSignature(node)
          if (signature?.declaration) declarations = [signature.declaration]
        } else {
          let symbol = checker.getSymbolAtLocation(node.name)
          if (symbol?.flags & ts.SymbolFlags.Alias) symbol = checker.getAliasedSymbol(symbol)
          declarations = symbol?.declarations ?? []
        }
        observations.push({ path, start: Buffer.byteLength(file.text.slice(0, node.getStart(file))),
          kind: ts.isCallExpression(node) ? 'Call' : 'Property',
          type: observedType(node),
          targets: declarations.map(location).filter(Boolean) })
        if (observations.length > request.max_results) throw { typed: 'ResourceLimitExceeded' }
      }
      ts.forEachChild(node, child => { stack.push(child) })
    }
    if (process.memoryUsage().rss > request.memory_bytes) throw { typed: 'ResourceLimitExceeded' }
  }
  const response = JSON.stringify({ version: ts.version, observations })
  if (Buffer.byteLength(response) > cap) throw { typed: 'ResourceLimitExceeded' }
  process.stdout.write(response)
} catch (error) {
  process.stdout.write(JSON.stringify({ error: error.typed ?? 'ResolutionFailure', detail: 'TS compiler observation failed' }))
  process.exitCode = 2
}
