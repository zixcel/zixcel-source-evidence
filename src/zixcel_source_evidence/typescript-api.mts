import type * as TypeScript from 'typescript'
import {CompilerFailure} from './typescript-request.mts'
// Artifact trust is established by the caller's exact digest, not by these API checks.
export function requireCompilerApi(value:unknown):typeof TypeScript {
 if(value===null||typeof value!=='object')throw new CompilerFailure('AnalyzerUnavailable')
 const compiler=value as Record<string,unknown>
 if(typeof compiler.version!=='string'||compiler.version.length>64)throw new CompilerFailure('AnalyzerUnavailable')
 for(const key of ['createSourceFile','createProgram','forEachChild','isCallExpression','isPropertyAccessExpression'])
  if(typeof compiler[key]!=='function')throw new CompilerFailure('AnalyzerUnavailable')
 const constants={ScriptTarget:['ESNext'],ModuleKind:['ESNext'],ModuleResolutionKind:['Bundler'],SymbolFlags:['Alias'],
  TypeFlags:['Any','Unknown','StringLike','NumberLike','BooleanLike','Void','Null','Undefined','Union','Intersection','Object']}
 for(const [group,keys]of Object.entries(constants)){
  const entries=compiler[group]
  if(entries===null||typeof entries!=='object')throw new CompilerFailure('AnalyzerUnavailable')
  for(const key of keys)if(!Number.isSafeInteger((entries as Record<string,unknown>)[key]))throw new CompilerFailure('AnalyzerUnavailable')
 }
 return compiler as unknown as typeof TypeScript
}
