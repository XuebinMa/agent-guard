# Secure Shell Tools

| Field | Details |
| :--- | :--- |
| **Status** | 🟢 Operational Guide |
| **Audience** | AI Engineers, Agent Builders |
| **Version** | 1.0 |
| **Last Reviewed** | 2026-04-14 |
| **Related Docs** | [User Manual](user-manual.md), [Check vs Enforce](check-vs-enforce.md), [Node Quickstart](../../../crates/agent-guard-node/examples/quickstart/README.md) |

---

If you only protect one tool category first, protect your shell tools.

For most agent systems, `bash`, `terminal`, `shell`, or command-execution tools are the highest-risk boundary because they can touch the host filesystem, spawn processes, and pivot into networked actions.

This guide shows the shortest path to putting `agent-guard` in front of those tools.

---

## 1. Why Start Here

Shell tools are the best first use case for `agent-guard` because they combine:

- the clearest risk
- the clearest policy surface
- the strongest demo value
- the simplest “before vs after” story

Without a guard, the model output often flows directly into the OS.

With `agent-guard`, the shell tool call must first pass:

1. policy evaluation
2. optional anomaly checks and deny fuse
3. sandboxed execution for `enforce` mode

This guide is intentionally shell-first because shell is the strongest current `enforce` path in the project. Other tool types still benefit from policy checks, but should not be described as having identical sandbox coverage today.

---

## 2. The Minimum Safe Pattern

For shell-like tools, the recommended default is:

- start with `mode: "enforce"` for real command execution
- use a small allowlist
- add explicit `ask` or `deny` rules for risky operations
- set `workingDirectory` whenever the tool should stay within a workspace

Minimal policy:

```yaml
version: 1
default_mode: read_only

tools:
  bash:
    allow:
      - "echo"
      - "pwd"
      - "ls"
    ask:
      - prefix: "git push"
    deny:
      - "rm -rf /"
    mode: workspace_write
```

---

## 3. Node Example

The simplest production-shaped pattern in Node is to wrap the shell tool handler once and keep the rest of your app unchanged.

```js
const {
  Guard,
  wrapOpenAITool,
  AgentGuardDeniedError,
  AgentGuardAskRequiredError,
} = require('@agent-guard/node')

const guard = Guard.fromYamlFile('policy.yaml')

const guardedShell = wrapOpenAITool(
  guard,
  async (input) => {
    throw new Error('Original handler should not run in enforce mode')
  },
  {
    tool: 'bash',
    mode: 'enforce',
    trustLevel: 'Trusted',
    workingDirectory: () => process.cwd(),
    resultMapper: (outcome) => outcome.output?.stdout ?? '',
  }
)

async function run(command) {
  try {
    const result = await guardedShell({ command })
    console.log(result)
  } catch (error) {
    if (
      error instanceof AgentGuardDeniedError ||
      error instanceof AgentGuardAskRequiredError
    ) {
      console.error(error.name, error.decision, error.code)
      return
    }
    throw error
  }
}
```

---

## 4. Framework Entry Points

### OpenAI-style Handlers

Use `wrapOpenAITool()` when your tool looks like:

```js
async function execute(input) {
  return ...
}
```

This is the best match for OpenAI Agents style `tool({ execute })` definitions.

### LangChain-style Tools

Use `wrapLangChainTool()` when you already have a tool object with methods like:

- `invoke`
- `call`
- `_call`

This keeps the same object identity while guarding the execution path.

---

## 5. What To Allow, Ask, and Deny

Good starting policy shape for shell tools:

- `allow`: read-only and non-destructive commands such as `pwd`, `ls`, `echo`
- `ask`: risky-but-sometimes-legitimate actions such as `git push`
- `deny`: clearly dangerous actions such as `rm -rf /`

Do not start with a broad “let everything run and we will tighten later” approach for shell tools. The risk profile is too high.

---

## 6. Recommended Adoption Sequence

Use this order:

1. Start with one shell tool only.
2. Keep the policy allowlist intentionally small.
3. Run the tool in a development or staging environment.
4. Observe what gets blocked and what needs an `ask` rule.
5. Expand carefully.

If your team has multiple tools, it is usually better to protect `bash` first than to add shallow guards to five different low-risk tools.

---

## 7. Common Mistakes

### Mistake 1: Using `check` for a true shell executor

If the tool really executes shell commands on the host, prefer `enforce`, not `check`.

`check` still runs your original handler after approval. That is often the wrong boundary for shell execution.

### Mistake 2: Letting the shell tool default to broad input

Keep payloads structured as:

```json
{"command":"echo hello"}
```

Do not rely on ad hoc string munging in your application layer.

### Mistake 3: Forgetting `workingDirectory`

If the tool is meant to operate inside a workspace, pass the workspace path in the execution context.

### Mistake 4: Treating all platforms as equal

Linux, macOS, and Windows do not currently provide identical isolation strength. Always verify with:

```bash
cargo run --example demo_transparency
```

and:

```bash
cargo run -p guard-verify -- doctor --format text
```

### Mistake 5: Assuming fallback equals isolation

If your backend falls back to `NoopSandbox`, the policy gate still runs, but OS-level isolation is gone.

Treat `Fallback: Yes` in the doctor output as:

- acceptable for local experimentation
- not equivalent to real `enforce`
- a deployment blocker for environments that expect host isolation

---

## 8. Fastest Way To Try It

If you want a complete runnable example today, use:

```bash
npm ci --prefix crates/agent-guard-node
npm run build:debug --prefix crates/agent-guard-node
npm run demo:quickstart --prefix crates/agent-guard-node
```

The quickstart demonstrates:

- a safe shell command being allowed
- a risky shell command being blocked

---

## 9. Recommended Next Read

After you protect shell tools, the next document to read is [Check vs Enforce](check-vs-enforce.md). That guide helps you choose the right mode for API tools, shell tools, and mixed tool sets.
