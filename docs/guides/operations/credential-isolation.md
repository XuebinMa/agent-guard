# Credential isolation for the push broker

`agent-guard push` is a boundary only if the agent cannot push on its own.

The broker treats the working repository as hostile input. It copies the
regular refs and primary object database into a temporary bare repository,
loads no repository hooks or config there, and contacts the exact push URL the
human approved. That closes the repository-to-broker code-execution path, but
it cannot create the other half of the boundary: the credential must still be
unreachable from the agent process.

The broker reads credentials and transport settings only from a host-owned
config selected with `--git-config`, `AGENT_GUARD_BROKER_GIT_CONFIG`, or
`~/.agent-guard/broker.gitconfig`. It also inherits the host's SSH agent socket
when present. Those resources are part of the trusted broker environment;
nothing in this repository can prove that the agent cannot reach them.

The first strict deployment profile below is implemented and has
[passed the fixed synthetic native Linux acceptance](../../security-evidence/2026-10-06/native-linux/README.md)
at head `5f8e714`. The real container workflow and complementary broker suites
are separate from mere configuration tests. This does not certify arbitrary
images, all host services or real-user workflows. The default same-user setup
remains advisory.

## The default setup gives you none of it

Claude Code runs as your user, with your `~/.ssh`, your `~/.gitconfig`, and
your credential helper. `agent-guard push` runs as your user too. Both sides
hold the same credential, because they are the same principal.

The hook is fail-open and advisory. An agent that ignores it, or that reaches
`git push` through a tool call the hook does not recognise, pushes with your
key and nothing stops it.

The honest description of a default install is therefore: **the broker shows
you the effect and performs the push. It does not prevent the agent from
pushing.** That is worth having — a preview resolved from the remote is not
something `git push` gives you — but it is not containment, and calling it
containment would be the overclaim this project exists to avoid.

## The requirements

All of these must hold:

1. The agent cannot read, modify **or use** the push credential. An authentication
   socket or a callable credential-bearing program can grant use without
   exposing the credential bytes.
2. The broker Git config is outside the repository and cannot be written by
   the agent; secret-bearing config is also unreadable to it.
3. Broker binaries, `PATH`, `HOME`, helpers and host SSH configuration are
   trusted and outside agent write authority.
4. The broker uses its isolated execution path rather than a plain host-side
   `git push` in the agent-writable checkout.
5. The agent cannot create/approve grants, call the privileged broker on its
   own behalf, control the approving terminal, or reach the container manager.
6. The **whole** agent runtime, file tools, MCP servers and hooks run under the
   unprivileged boundary. A host-side handler with broader authority invalidates
   it even if shell commands alone run in a container.

Everything below is a way to satisfy that. Note what it rules out: same user,
same session, no container is **not** a boundary, because a POSIX process can
read its own user's files. No amount of configuration inside agent-guard
changes that.

## Deployment A — accepted fixed Linux container / host broker reference

The first acceptance target is one Linux host, one existing container runtime,
one normal repository, one authenticated HTTPS remote, and an ordinary
non-force branch push. The [fixed native Linux Docker launcher](../../../deploy/broker-first/README.md)
implements configuration checks and a host-terminal workflow. Authenticated
native acceptance passed for the fixed fixture and its I1–I8 coverage map. This
is a restricted **deployment profile**, not removal of existing
SSH/SCP transports or macOS/Windows APIs. Those remain separately supported;
they are not covered by this first strict profile's acceptance tests.

The reference profile runs the agent as an unprivileged container user, with only
the development workspace and explicitly required resources exposed. Give it
no way to authenticate to the protected remote:

- do **not** forward the SSH agent socket (no `-v $SSH_AUTH_SOCK`, no
  `--mount` of it)
- do **not** mount `~/.ssh`, `~/.gitconfig`, or `~/.config/gh`
- do **not** pass `GITHUB_TOKEN`, `GH_TOKEN`, or any other token the remote
  would accept — an inherited environment is the most common accidental grant
- do **not** mount broker config, grants, receipt storage, host home directories,
  container-management sockets or host sensitive files/inodes
- do **not** use privileged mode or expose host process namespaces; grant only
  the runtime capabilities, devices and network access the workload needs
- keep file tools, MCP servers and hook handlers inside the same boundary; do
  not proxy agent requests through privileged host handlers
- set `GIT_TERMINAL_PROMPT=0` to disable interactive prompts, **not** as an
  authentication boundary; it does not remove already reachable credentials

### Required asset permissions

"Use" includes invoking a helper, connecting to an authentication socket or
calling a program that performs a privileged action. A different filesystem
path alone does not remove that authority.

| Asset | Agent read | Agent write | Agent use/call | Trusted host authority |
| :--- | :--- | :--- | :--- | :--- |
| Development checkout and commits | Yes | Yes, inside its dedicated volume | Develop/test only; data is untrusted | Broker reads and validates a copied snapshot; never executes repository hooks/config |
| Remote-write credentials, tokens and accepted cookies | No | No | No | Trusted helper may use them for the scoped HTTPS destination |
| SSH/authentication sockets | No | No | No | Host owns them; SSH is outside the first HTTPS profile |
| Dedicated broker Git config | No secret-bearing contents | No | No helper invocation outside broker | Host creates/protects config and allowed scopes |
| Host-selected policy | An exported read-only copy may be provided | No host-policy changes | Cannot select/replace host policy | Host chooses policy and verifies it before granting/executing |
| Broker grant/approval store | No | No | Cannot issue, approve or consume authority on its own behalf | Host-only create/approve/consume |
| Broker/Git/helper binaries, executable `PATH` and host `HOME` | Only explicitly exposed non-secret copies | No host executable/config changes | No credential-bearing host CLI, including `--yes` | Host selects trusted binaries/config and invokes broker |
| Temporary broker repositories and receipt storage | No | No | No | Host owns snapshots and execution-stage records; exports copies deliberately |
| Approving terminal and its input stream | No | No | Cannot supply approval responses | Human on trusted host terminal; strict entry checks plus deployment/account separation, not TTY identity alone |
| Container runtime/management socket and host process control | No | No | No | Host launches/manages unprivileged runtime |
| File tools, MCP servers and hook handlers | Only container-authorized data | Only container-authorized paths | No higher-authority host proxy | Host ensures every execution path stays in the same runtime boundary |

Do not share writable hard-linked inodes with trusted host data. Use a dedicated
development volume or copy-based staging; a path allowlist alone is not alias
isolation. Newly added tool/runtime paths require this table and the acceptance
checks to be reviewed again.

### Trusted host configuration

On the host, create the dedicated config outside the checkout:

```bash
mkdir -p ~/.agent-guard
(umask 077; set -C; : > ~/.agent-guard/broker.gitconfig)
```

An empty file is sufficient for SSH authentication through `SSH_AUTH_SOCK`.
Creation refuses to overwrite an existing file; preserve an already configured
trusted file instead of rerunning initialization over it.
HTTPS users must scope nonempty credential helpers to an explicit destination:

```ini
[credential "https://github.com/your-org/your-repo.git"]
    helper = <trusted-host-helper>
    useHttpPath = true
```

Use your installed trusted helper in place of the placeholder. A host-root
scope (`https://github.com/`) deliberately authorizes all repository paths on
that host; prefer a repository path when that is the intended boundary. The
broker preserves the path in the helper context and rejects overrides that
disable it. Helpers remain trusted programs and must respect that context.
Required non-authentication `http.*` settings may also live in this file.
Includes, URL rewrites, remote definitions, protocol
overrides, hooks and arbitrary `core.*` commands are rejected.

If you authenticate with an `http.extraHeader` (for example a bearer token),
scope it to an explicit HTTPS destination rather than setting it unconditionally:

```ini
[http "https://github.com/"]
    extraHeader = Authorization: Basic <token>
```

The push URL is resolved from the repository, which the agent can edit, and the
preview contacts that URL before you approve. An unscoped helper that returns
the same credential for any context, or an unscoped `http.extraHeader`, can
send it to a repository-chosen destination. The broker therefore rejects every
nonempty unscoped helper, even when followed by an empty reset. Empty helper
resets remain supported. Helpers and headers require canonical HTTPS scopes
with an exact host/port and optional slash-bounded repository path, without
userinfo, wildcard, percent escapes, query, fragment or normalization aliases.
When these authentication settings exist, an HTTPS destination outside every
scope is refused before any network query. SSH/SCP and explicitly enabled
local test transports retain their separate trust/protocol boundary; they do
not use HTTPS helper/header settings. The broker also disables HTTP
redirects and rejects `http.followRedirects` overrides, including URL-scoped
ones: a custom credential header can otherwise follow a redirect even though
its original URL matched the scope. Configure the final URL directly when a
service uses redirects. These constraints apply to preview and push alike.

The [broker boundary tests](../../../crates/agent-guard-broker/tests/security_boundary.rs),
[transaction tests](../../../crates/agent-guard-broker/tests/transaction.rs),
and [sanitized-command regressions](../../../crates/agent-guard-broker/src/git/command.rs)
check the isolated execution path, exact remote-ref selection, authentication
scope refusal before connection, and redirect refusal. Real Git helper routing
is exercised locally with a fixed public canary, not a credential store or
network destination. Redirect tests use loopback and a public dummy header.

You then run `agent-guard push` on the host, against the same repository, where
your credential is. The repository supplies data only: the broker does not run
its hooks, use its credential helpers, honour its URL rewrites, or pass its
remote name to `git push`. The agent develops and commits inside its environment.
In the strict profile, the host launcher stops that whole container before
preview and execution, then the broker decides which exact object and URL may
leave. Resume development explicitly afterward; do not let a second runtime
keep writing the workspace.

The current CLI's confirmation reads stdin; it does **not** establish a trusted
TTY, a human principal, or that requestor and approver differ. `--yes` skips that
confirmation. The implemented strict host launch wrapper validates its terminal
and refuses piped input before stop or network; real PTY cancel/EOF/approve paths
ran in native acceptance. That check does not authenticate a human principal.
The agent must not be able to invoke the
credential-bearing host CLI; merely displaying a prompt does not prevent that.

The strict 0.2.4 slice deliberately rejects linked worktrees, partial clones,
object alternates, multiple push URLs and special Git transports. Convert to a
normal checkout rather than weakening these checks.

The acceptance target is a real remote authentication/authorization refusal
for an agent's direct mutation, alongside a successful authorized broker push.
That was demonstrated for the fixed native Linux fixture, not every possible
container image or host setup. The hook is advice in addition to that protected
deployment boundary, not the boundary itself.

## Deployment B — a hardware-backed key, one machine, no container

When a container is not practical, a key that requires a physical touch can
reduce unattended use, without establishing principal separation:

```bash
ssh-keygen -t ed25519-sk -C "agent-guard broker"
```

Do not add `no-touch-required`. Every push then needs someone to touch the
token.

**Be precise about what this buys.** The agent and you are still the same user,
so the agent can still *attempt* a push. What it cannot do is complete one
while nobody is at the keyboard. That turns silent pushes into pushes that need
a physical act — but the touch is not bound to the transaction you previewed,
so touching for the push you meant also satisfies a push you did not. It is a
real reduction, and it is not the property Deployment A gives you.

This is not a substitute for the fixed profile's credential/use boundary.

## Verify it, do not assume it

Configuration alone is not proof. A dry-run is a diagnostic, not the profile's
acceptance gate: it performs no ref mutation and cannot by itself establish
write authorization, caller identity, or absence of every credential route.
Use disposable local repositories and synthetic authentication for security
acceptance, never a production credential or third-party target.

**From the agent's environment** — inside the container, or in the shell the
agent runs in — attempt a push that changes nothing:

```bash
git push --dry-run origin HEAD:refs/heads/credential-isolation-probe
```

`--dry-run` contacts the remote but does not update a ref. It can still invoke
repository hooks and credential helpers, and absence of a ref update is not
absence of all side effects. Use this diagnostic only with a trusted disposable
fixture and public dummy authentication data.

**With no credential reachable**, plain Git in the agent environment fails
before it can push:

```
fatal: could not read Username for 'https://github.com': terminal prompts disabled
```

or, over SSH, `Permission denied (publickey)`. This is consistent with missing
credentials, but a network failure or an anonymous remote is not proof of
isolation. Confirm the same endpoint is reachable and accepts the trusted
broker's independently observed mutation.

**With a credential reachable**, git tells you exactly what it would have done:

```
To github.com:you/project.git
 * [new branch]      HEAD -> credential-isolation-probe
```

This output alone does not prove the agent has authenticated write authority.
If a direct mutation succeeds in the authenticated local fixture, the profile
fails its boundary regardless of the hook's decision.

Test the positive broker path too. A setup where both sides fail might simply
be an unreachable or unusable remote, not a demonstrated isolation boundary.

Finally run the broker itself. It must show the push URL rather than merely the
remote name. A repository `pre-push` hook or `remote.<name>.pushurl` is input to
the preview, never code or an implicit second destination in the broker. These
claims are executable, not just prose: the
[adversarial Broker boundary suite](../../../crates/agent-guard-broker/tests/security_boundary.rs)
pins the push URL, repository-hook and config isolation, refusal receipts,
protocol policy, and unsafe repository layouts.

### Whole-runtime acceptance evidence and limits

The [broker-first plan](../../plans/broker-first-development-plan.md) specifies
I1–I8 for a synthetic authenticated HTTPS fixture and independent remote-ref
observer: grantless execution has no helper/network activity; transaction and
policy drift refuses; hostile repository data cannot execute broker-side code;
scoped authentication and redirect refusal hold; an agent direct mutation is
rejected while an approved broker mutation succeeds; all assets above are
inaccessible through every tool path; receipts agree with consumed grants and
observed refs; and agent/piped input cannot impersonate a trusted approver.
These gates ran at head `5f8e714`: the
[native report and same-job broker/CLI logs](../../security-evidence/2026-10-06/native-linux/README.md)
map their separate evidence to I1–I8. The fixed reviewed image contains only the
synthetic agent workload; it is not a proof for every arbitrary tool path/image.
New runtime paths require fresh review and acceptance. Real human workflow
feedback remains P5 work. The dedicated Linux job must not skip a missing runtime or
silently downgrade to advisory/noop and report success. Missing local runtime
capabilities are reported as unrun, not passed.

`guard-verify doctor` reports capabilities available to its own process; it does
not test this authority matrix, credential isolation or approving-principal
identity.

## Operational cost

The isolated repository is a copy, not a shared object-store view: every
preview copies the source repository's primary objects, and an approved push
copies them again when it re-resolves the transaction. Plan for copy time and
temporary disk use proportional to the primary object store. Benchmark a
representative large repository on the broker host before rollout; do not
assume the cost measured on a small source checkout predicts production.

## What it still does not buy

Even with Deployment A, be careful what you claim:

- **The receipt is not proof of isolation.** It records what the broker
  witnessed. It cannot attest to how that process was launched, or to what else
  could reach the credential.
- **CLI receipts are unsigned, optional local records.** `agent-guard push`
  supplies no signing key and persists a `PushReceipt` only with `--receipt`.
  It creates one after entering execution, not for early policy refusal,
  preview failure or cancellation. The broker library's optional signing API
  does not configure a CLI signing key; SDK `ExecutionReceipt` verification is
  a different path. An unsigned record is not third-party-verifiable evidence.
- **A human still has to read the preview.** The broker refuses a transaction
  that moved after approval, but it cannot tell whether the change you approved
  is the change you wanted.
- **The repository remains hostile input.** The isolated snapshot prevents its
  hooks and config from executing, but malformed or racing repository data can
  still cause a safe refusal.
- **The broker's `PATH` is trusted.** It inherits `PATH` to locate `git` and
  programs Git deliberately invokes. If the agent can write any directory on
  that path, it can replace a trusted executable.
- **The broker's `HOME` is trusted.** Host SSH may read `~/.ssh/config`; if
  the agent can edit it, directives such as `ProxyCommand` can execute code
  in the credential-bearing process.
- **Same-user and doctor checks are not isolation.** Credential bytes need not
  be visible for an authentication socket or privileged callable program to
  authorize a push. Current stdin confirmation does not authenticate a human.
- **Helper/header scoping is not universal authentication isolation.** Other
  trusted transport settings (client certificates, cookies, proxies or
  integrated authentication), SSH configuration and helper behavior remain
  deployment responsibilities. The helper scope check does not audit programs
  or make those other mechanisms transaction-bound.
- **This covers `git push`.** Other ways code leaves a machine — a package
  publish, an HTTP upload, a copy to shared storage — are governed by policy
  where they are recognised, and by nothing where they are not.

## Related

- [Claude Code hook](claude-code-hook.md) — what the advisory layer does and does not do
- [Deployment guide](deployment-guide.md) — the general production checklist
- [`demos/push-broker/demo.sh`](../../../demos/push-broker/demo.sh) — the broker path end to end, against a throwaway repository
