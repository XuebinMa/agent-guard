# Accepted decision: broker-first security scope

- **Status:** Accepted by the user on 2026-10-06.
- **Purpose:** Durable project memory, not a claim of completed implementation.
- **User instruction:** “我同意你的建议，那么把上述目标写入记忆，并制定详细的开发计划”.
- **Operational guidance:** [CLAUDE.md](../../CLAUDE.md) remains the single source
  of contributor/agent instructions. This record preserves the product decision.
- **Implementation sequence:** [Active development plan](../plans/broker-first-development-plan.md).

## Objective

An agent can develop and test inside its authorized environment. It cannot
perform a protected remote Git mutation unless the trusted broker executes the
exact transaction approved by the human.

Authorization covers the repository, exact destination URL, target ref, old and
new object IDs, policy and execution conditions. Recognizing a familiar command
spelling is not equivalent to granting that operation.

The first deployment milestone is deliberately small: one Linux host, one
existing container runtime, one normal repository, one authenticated HTTPS
destination and one branch, with ordinary non-force push and approval from a
trusted host terminal. This is a planned deployment profile, not a new limit
silently imposed on the existing broker API.

## Why this is the decision

Shell syntax can be parsed reliably for a declared dialect and subset. Expansion
depends on runtime state, and arbitrary called-program effects cannot be fully
predicted from command text. Improving parsing remains useful but does not turn
a command classifier into a universal containment mechanism.

Use a small, protected authority path instead: arbitrary development computation
does not receive the credentials or access needed for remote mutation; the
broker receives structured data and owns the permitted side effect.

OS isolation and transaction authorization solve different problems. Resource
isolation does not identify the commit that should be published; a precise
approval does not isolate credentials on its own. Both are required for the
proposed hard boundary.

## Continue maintaining

- Confirmed defects, permanent regression locks and published advisory duties.
- Supported Shell syntax, safe display, compatibility and dependency maintenance.
- Decision integrity: known equivalent forms must not weaken an applicable deny.
- Existing SDK, binding and platform contracts and their current CI gates.
- Accurate limitations, including fail-open advisory hooks and default noop.

Known defects must be repaired or safely refused within an explicit support
contract. Changing scope is not permission to remove failing tests, abandon an
advisory obligation, or call a partial patch complete.

## Do not expand by default

- Universal Shell interpretation or simulation of arbitrary programs' effects.
- Unlimited launcher, tool-option, or Shell-dialect catalogues.
- New general agent frameworks, DLP, sandbox backends, governance/control planes,
  TPM/remote-attestation systems or generic privileged command services.
- New daemon/RPC, multi-tenant credential service or key-management platform for
  the first deployment milestone.

Reuse mature components where they fit. Their presence alone is not evidence of
a working policy or isolation boundary. Completing the milestone does not
automatically unfreeze this list; expansion requires a new explicit decision.

## Finite evidence, not unlimited review

The main acceptance criteria are broker invariants and an actual isolated
deployment: no unauthorized mutation, approval drift refusal, one-use grant
consumption, hostile-repository isolation, destination-scoped authentication,
and truthful outcomes checked against an independent remote.

Bounded Shell tests protect the declared subset and confirmed regressions.
Fuzzing and differential testing can improve that evidence; a quiet fuzzing run
does not prove all programs safe. Human approval is authorization, not a proof
of harmlessness. A receipt records an attempt and does not attest to deployment
isolation.

## Deployment and evidence limitations to preserve

- A same-user default installation is not credential isolation. Files,
  environment, authentication sockets, process access and privileged invocation
  paths must be considered, not just possession of a private-key file.
- Broker executables, PATH, HOME, trusted Git/transport configuration, credentials,
  grant storage and the approving terminal must be outside agent control.
- The repository is hostile data. Shared host inodes and writable configuration
  must not silently create access to broker-owned resources.
- The current CLI emits unsigned broker receipts and persists them only when
  requested. The SDK's `ExecutionReceipt` verifier is not a broker `PushReceipt`
  verification entry point. Do not promise otherwise.
- `guard-verify doctor` reports sandbox capabilities; it does not prove credential
  isolation or caller identity.
- Windows ambient handles and shared-hard-link limitations remain open until
  separately demonstrated repairs exist. A deployment restriction is not a code
  fix for those findings.

## Release authority remains separate

This acceptance authorizes recording the decision and planning development. It
does not answer the pending version/publication question, authorize a new release,
move an existing tag, or alter an advisory's affected range.

The [delivery record](../security-delivery-2026-10-04.md) owns changing release
facts. Keep `v0.2.7` immutable and honor its current publication hold. Consult
fresh repository, CI and registry state before any later delivery action; do not
turn this dated decision into an assumption of current availability.

## Research basis

These sources support the architecture, not a certification of Agent Guard:

- [Codex rules](https://learn.chatgpt.com/docs/agent-configuration/rules): limited
  interpretation of simple command chains, not universal Shell effect analysis.
- [Claude Code permissions](https://code.claude.com/docs/en/permissions) and
  [sandboxing](https://code.claude.com/docs/en/sandboxing): text decisions and
  runtime resource boundaries have different scopes.
- [Smoosh](https://arxiv.org/abs/1907.05308): mechanized POSIX Shell semantics are
  possible, without establishing arbitrary-program safety.
- [mvdan/sh interpreter API](https://pkg.go.dev/mvdan.cc/sh/v3/interp): execution
  and file-effect callbacks have explicit coverage limits.
- [ShellFuzzer paper](https://arxiv.org/html/2408.00433v1) and
  [prototype](https://github.com/user09021250/shellfuzzer): grammar-based shell
  testing exists; it is not a ready-made authorization verifier.
- [Git restricted shell](https://git-scm.com/docs/git-shell) and
  [OpenSSH restrictions](https://man.openbsd.org/sshd.8): finite privileged
  interfaces, rather than arbitrary client command execution.
- [Bubblewrap](https://github.com/containers/bubblewrap/blob/main/README.md#sandbox-security):
  sandbox mechanisms require a policy supplied by the trusted launcher.
- [Saltzer–Schroeder](https://web.mit.edu/Saltzer/www/publications/protection/Basic.html):
  economy of mechanism, complete mediation and least privilege.

The technical direction is justified by these sources. Customer demand and
commercial differentiation still require a real user workflow; neither is
proven by this research.
