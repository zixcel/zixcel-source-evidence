import { isAbsolute } from 'node:path'
export interface CompilerRequest { module: string; files: Record<string, string>; max_nodes: number; max_results: number; memory_bytes: number }
export type FailureCode = 'ResourceLimitExceeded' | 'ResolutionFailure' | 'AnalyzerUnavailable'
export class CompilerFailure extends Error {
  readonly code: FailureCode
  constructor(code: FailureCode) { super(code); this.code = code }
}
function object(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new CompilerFailure('ResolutionFailure')
  return value as Record<string, unknown>
}
function positive(value: unknown): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 1) throw new CompilerFailure('ResolutionFailure')
  return value
}
export function decodeRequest(value: unknown): CompilerRequest {
  const request = object(value), fields = object(request.files), files: Record<string, string> = Object.create(null)
  if (typeof request.module !== 'string' || !isAbsolute(request.module)) throw new CompilerFailure('ResolutionFailure')
  for (const [path, source] of Object.entries(fields)) {
    if (!path.startsWith('/') || typeof source !== 'string') throw new CompilerFailure('ResolutionFailure')
    files[path] = source
  }
  return { module: request.module, files, max_nodes: positive(request.max_nodes),
    max_results: positive(request.max_results), memory_bytes: positive(request.memory_bytes) }
}
