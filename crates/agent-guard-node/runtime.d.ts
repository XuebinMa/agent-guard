export {
  Guard,
  TrustLevel,
  normalizePayload,
  verifyReceipt,
} from './index'
export type {
  Context,
  Decision,
  ExecuteOutcome,
  HandoffResult,
  RuntimeDecision,
  RuntimeOutcome,
  ExecutionReceipt,
  PolicyVerification,
  SandboxOutput,
} from './index'

import type { Decision, ExecuteOutcome, Guard, TrustLevel } from './index'

export type AdapterMode = 'check' | 'enforce' | 'auto'

export interface AdapterOptions<Input = unknown, Result = unknown> {
  mode?: AdapterMode
  tool?: string
  agentId?: string
  sessionId?: string
  actor?: string
  trustLevel?: TrustLevel | 'Untrusted' | 'Trusted' | 'Admin'
  workingDirectory?: string | (() => string | undefined)
  payloadMapper?: (input: Input) => string
  resultMapper?: (executeOutcome: ExecuteOutcome, originalInput: Input) => Result
}

export interface LangChainToolLike<Input = unknown, Output = unknown> {
  name?: string
  description?: string
  invoke?: (input: Input, ...args: any[]) => Output | Promise<Output>
  call?: (input: Input, ...args: any[]) => Output | Promise<Output>
  _call?: (input: Input, ...args: any[]) => Output | Promise<Output>
  [key: string]: any
}

export interface AgentGuardErrorShape {
  decision?: string
  policyVersion?: string
  sandboxType?: string
  receipt?: string
  status?: string
  code?: string
  matchedRule?: string
  askPrompt?: string
  decisionDetail?: Decision
}

export declare class AgentGuardAdapterError extends Error implements AgentGuardErrorShape {
  decision?: string
  policyVersion?: string
  sandboxType?: string
  receipt?: string
  status?: string
  code?: string
  matchedRule?: string
  askPrompt?: string
  decisionDetail?: Decision
}

export declare class AgentGuardDeniedError extends AgentGuardAdapterError {}
export declare class AgentGuardAskRequiredError extends AgentGuardAdapterError {}
export declare class AgentGuardExecutionError extends AgentGuardAdapterError {}

export declare function createGuardedExecutor<Input = unknown, Output = unknown, Result = unknown>(
  guard: Pick<Guard, 'check' | 'execute'>,
  options?: AdapterOptions<Input, Result>
): (
  handler: (input: Input, ...args: any[]) => Output | Promise<Output>
) => (input: Input, ...args: any[]) => Promise<Output | ExecuteOutcome | Result> | Output

export declare function wrapLangChainTool<Input = unknown, Output = unknown, Result = unknown>(
  guard: Pick<Guard, 'check' | 'execute'>,
  tool: LangChainToolLike<Input, Output>,
  options?: AdapterOptions<Input, Result>
): LangChainToolLike<Input, Output>

export declare function wrapOpenAITool<Input = unknown, Output = unknown, Result = unknown>(
  guard: Pick<Guard, 'check' | 'execute'>,
  handler: (input: Input, ...args: any[]) => Output | Promise<Output>,
  options: AdapterOptions<Input, Result>
): (input: Input, ...args: any[]) => Promise<Output | ExecuteOutcome | Result> | Output
