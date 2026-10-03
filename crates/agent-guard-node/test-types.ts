import {
  AgentGuardExecutionError,
  type ExecuteOutcome,
  Guard,
  wrapLangChainTool,
  type HandoffResult,
  type LangChainToolLike,
  type RuntimeOutcome,
} from './runtime.js'

declare const guard: Guard
declare const tool: LangChainToolLike<string, string>

const wrapped = wrapLangChainTool<string, string, string>(guard, tool, {
  mode: 'auto',
  tool: 'calculator',
})
const possibleOutcome:
  | string
  | ExecuteOutcome
  | RuntimeOutcome
  | Promise<string | ExecuteOutcome | RuntimeOutcome>
  | undefined = wrapped.invoke?.('2+2')

const error = new AgentGuardExecutionError('report failed')
const attemptedReport: HandoffResult | undefined = error.handoffReport

void possibleOutcome
void attemptedReport
