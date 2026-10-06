# 🧱 Enforcement Layers (ADR)

| Field | Details |
| :--- | :--- |
| **Status** | ✅ Accepted (2026-06-12) |
| **Audience** | Contributors, Security Reviewers |
| **Version** | 1.1 |
| **Related Docs** | [Threat Model](threat-model.md), [Capability Parity](capability-parity.md) |
| **Tracking** | Decision record for [#57](https://github.com/XuebinMa/agent-guard/issues/57); informed by [#54](https://github.com/XuebinMa/agent-guard/issues/54), [#55](https://github.com/XuebinMa/agent-guard/issues/55) |

---

## Decision

`agent-guard` contains three enforcement mechanisms with different guarantees. This
record declares, once, which one is load-bearing in which deployment shape — so
that security claims, bypass-report triage, and engineering effort all follow the
same map instead of an implicit one.

1. The **policy engine** (rules, modes, trust levels) is **always load-bearing**:
   it is the decision integrity of the product. An incorrect `Allow` from a
   correctly authored policy is a security defect; severity depends on the
   reachable action, authority and deployment, not only the decision label.
2. The **static validators** (`agent-guard-validators`: bash command analysis,
   path checks) are an **intent gate, never a containment boundary**. They
   classify what a command *appears* to do and feed the decision layer. Denylist
   analysis of a Turing-complete shell structurally over- and under-matches;
   hardening it reduces friction and improves audit signal, but no validator fix
   ever upgrades it into a boundary.
3. The **OS sandbox** (`agent-guard-sandbox`: Landlock/seccomp, Seatbelt, Job
   Objects) restricts particular resources only when its platform feature is
   compiled in and the backend is active. Its capabilities are not a promise of
   global read, credential, network or arbitrary-program isolation. The Git
   broker is a separate, deliberately narrow outbound-change boundary, and a
   host/container deployment must keep its authority outside the agent runtime.
   See the Threat Model, Sharp Edge #1.

## Deployment shapes

| Shape | Example | What agent-guard provides | Containment responsibility |
| :--- | :--- | :--- | :--- |
| **Decision-only / advisory** | `guard-hook` on Claude Code PreToolUse; `Guard::check` / `decide` from any SDK | Policy decision + JSONL record. The hook is fail-open and the host runtime executes (or doesn't). | The **host runtime** (and whatever isolation it runs under). |
| **Guard-owned execution** | `Guard::execute` / runtime `run` path | Decision + execution inside the selected sandbox; optional signed receipt when a key is configured. | The **sandbox layer**, iff compiled in and active; otherwise the noop backend provides no OS containment. |
| **Broker-enforced Git push** | `agent-guard push` | Exact push URL and OID preview, one-use short-lived authorization, execution-time policy/remote-state revalidation, and an isolated temporary repository. The CLI creates an unsigned execution-stage `PushReceipt` and persists it only with `--receipt`. | A separate broker process and credential/config boundary the agent cannot read, modify or use. The CLI itself does not establish that separation. |

The easiest adoption wedge remains **decision-only and advisory**; the focused
product boundary is the brokered Git push path. In the hook shape there is no
sandbox in the path at all — which is precisely why the validator must not be
described as a boundary: it is the only mechanical check, and it is best-effort
by construction.

## Bounded shell analysis, not an execution-language promise

The static front-end is
[`tree-sitter-bash`](../../crates/agent-guard-validators/src/bash/ast.rs).
Guard-owned Unix runners execute `sh -c`; the Windows noop and Job Object
runners execute `cmd.exe /C`. A decision-only hook leaves shell selection and
execution to its host. The tool name `Bash` does not make these execution
dialects equivalent or turn the parser into Bash, POSIX sh, zsh, cmd or
PowerShell interpreters.

The supported contract is finite: model a static command/argument shape, apply
policy, and keep permanent regressions for it. Restricted modes reject known
unsupported syntax, computed command forms and opaque launchers. `ReadOnly`
has an explicit executable allowlist; **`WorkspaceWrite` does not reject every
unknown executable**. A program that looks ordinary can use configuration,
plugins, inherited environment or child processes in ways the parser cannot
predict. Recognition is therefore not a grant of new privileges, and path
classification alone is not runtime filesystem confinement.

Static classification does not sanitize the executing process's environment or
revoke authority already available to its programs. Do not pass write credentials
into an agent runtime and expect a command rule, `ReadOnly` or an HTTP policy to
make them unusable. Git's dedicated broker environment is a separate code path,
not a general environment guarantee for all Guard-owned or host-owned tools.

For workloads needing an enforced remote-write boundary, the planned first
profile puts the **whole** agent runtime, file tools, MCP servers and hooks in a
credential-free, unprivileged Linux container. The human invokes the broker
from the trusted host. This profile is not yet accepted as a deployed boundary;
see [Credential isolation](../guides/operations/credential-isolation.md) for
its asset permissions and outstanding acceptance checks. It narrows the first
deployment promise, not the existing public API or supported transport set.

## Triage rules for bypass reports

| Report | Severity | Rationale |
| :--- | :--- | :--- |
| Policy engine returns `Allow` where authored rules say deny/ask | **Security defect; assess impact** | Decision integrity is load-bearing; reachable authority determines severity. |
| Sandbox escape while the platform feature is active | **Security defect; assess broken capability** | Test the resource guarantee for that backend and mode, not an unconditional isolation claim. |
| Validator bypass (new wrapper, encoding or spawner) | **Security defect; assess downstream action** | Static analysis is bounded, but known bypasses still require repair or a safe refusal and a permanent regression. |
| "Escape" from a noop/passthrough sandbox in a default build | **Not a vulnerability** | Documented behavior (Threat Model, Sharp Edge #1); the diagnosis API reports it truthfully. |

## Consequences

- **Engineering effort**: repair confirmed parser/decision defects within the
  bounded supported grammar; do not extend an endless launcher denylist into a
  universal interpreter. Boundary-grade effort goes to broker authority
  separation, its exact transaction checks and the relevant OS capabilities.
  Guard-owned SDK execution can produce signed `ExecutionReceipt` values with
  an explicit key. The broker library also has an optional signing API, but the
  current push CLI supplies no key; these are different receipt paths.
- **Messaging**: no agent-guard surface (README, docs, release notes, outreach)
  may claim containment for the validator or for a default build. Claims about
  "blocking" in decision-only deployments must attribute enforcement to the host
  runtime honoring the decision. This extends the claim discipline already
  established for cross-runtime statements.
- **Known consequence we accept**: static text cannot establish arbitrary
  program effects. The required deployment boundary is resource/credential
  separation, not a claim that mode and path checks can fully interpret a
  program. A default build uses noop execution; a decision-only hook remains
  advisory. Neither becomes containment through more rules.

## Alternatives considered

- **Declare the validator the boundary and harden it indefinitely** — rejected:
  enumerate-badness over shell input cannot converge; it would commit the
  project to an unwinnable arms race and a false claim.
- **Declare the sandbox the boundary unconditionally** — rejected: it is
  off-by-default, platform-gated, and absent from the decision-only shape that
  most adopters actually run; claiming it unconditionally would be untrue for
  the primary wedge.
