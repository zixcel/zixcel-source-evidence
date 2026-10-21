import assert from 'node:assert/strict'
import test from 'node:test'
import { createRequire } from 'node:module'
import { mkdtempSync, readdirSync, existsSync, rmSync } from 'node:fs'
import { spawnSync } from 'node:child_process'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { decodeRequest } from '../src/zixcel_source_evidence/typescript-request.mts'
const require = createRequire(import.meta.url)
const module = require.resolve('typescript')
const helper = new URL('../src/zixcel_source_evidence/typescript.mts', import.meta.url).pathname
const request = { module, files: { '/sample.ts': 'function café() { return 2 }; const value = café(); value.toString();' }, max_nodes: 10000, max_results: 100, memory_bytes: 536870912 }
function invoke(input: unknown) {
  const result = spawnSync(process.execPath, ['--max-old-space-size=128', helper], { input: JSON.stringify(input), encoding: 'utf8', timeout: 10000, maxBuffer: 1048576, cwd: '/', env: { PATH: '/usr/bin:/bin' } })
  assert.equal(result.signal, null)
  return { result, value: JSON.parse(result.stdout) as { error?: string; version?: string; observations?: { path: string; start: number; targets: { path: string }[] }[] } }
}
test('real compiler observes supplied Unicode source and refuses node/result/memory budgets', () => {
  const success = invoke(request)
  assert.equal(success.result.status, 0, success.result.stderr)
  assert.equal(success.value.version, '5.9.3')
  assert.ok(success.value.observations?.some(entry => entry.targets.some(target => target.path === '/sample.ts')))
  const start = request.files['/sample.ts'].indexOf('café();')
  assert.ok(success.value.observations?.some(entry => entry.start === Buffer.byteLength(request.files['/sample.ts'].slice(0, start))))
  for (const key of ['max_nodes', 'max_results', 'memory_bytes']) {
    const failure = invoke({ ...request, [key]: 1 })
    assert.equal(failure.result.status, 2)
    assert.equal(failure.value.error, 'ResourceLimitExceeded')
  }
})
test('untrusted request shapes reject before compiler loading', () => {
  for (const value of [null, [], { ...request, module: './untrusted.js' }, { ...request, files: { '/file.ts': 1 } }, { ...request, files: [] }, { ...request, max_nodes: Infinity }, { ...request, max_results: -1 }]) {
    assert.throws(() => decodeRequest(value))
    const rejected = invoke(value)
    assert.equal(rejected.result.status, 2)
    assert.equal(rejected.value.error, 'ResolutionFailure')
  }
})
test('supplied code is observed, never executed or resolved through filesystem fallback', () => {
  const directory = mkdtempSync(join(tmpdir(), 'source-compiler-'))
  try {
    const marker = join(directory, 'executed')
    const text = `import fs from 'node:fs'; fs.writeFileSync(${JSON.stringify(marker)}, 'unexpected');`
    const result = invoke({ ...request, files: { '/untrusted.ts': text } })
    assert.equal(result.result.status, 0, result.result.stderr)
    assert.equal(existsSync(marker), false)
    assert.ok(result.value.observations?.every(entry => entry.targets.every(target => target.path === '/untrusted.ts')))
  } finally { rmSync(directory, { recursive: true, force: true }) }
})
test('compiler guest contains only typed first-party entrypoints', () => {
  const names = readdirSync(new URL('../src/zixcel_source_evidence', import.meta.url))
  assert.deepEqual(names.filter(name => /\.(?:c|m)?js$/.test(name)), [])
  assert.ok(names.includes('typescript.mts') && names.includes('typescript-request.mts'))
})
