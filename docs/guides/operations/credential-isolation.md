# Credential isolation for the push broker

`agent-guard push` is a boundary only if the agent cannot push on its own.

The broker now treats the working repository as hostile input. It copies the
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

So: how to actually get it, and how to prove to yourself that you did.

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

All four must hold:

1. The push credential is somewhere the agent process cannot read.
2. The broker Git config is outside the repository and cannot be written by
   the agent.
3. The Git binary and host SSH configuration are trusted.
4. The broker uses its isolated execution path rather than a plain host-side
   `git push` in the agent-writable checkout.

Everything below is a way to satisfy that. Note what it rules out: same user,
same session, no container is **not** a boundary, because a POSIX process can
read its own user's files. No amount of configuration inside agent-guard
changes that.

## Deployment A — agent container, isolated host broker

This is the preferred deployment when every prerequisite below is met.

Run the agent in a container with the repository bind-mounted, and give that
container no way to authenticate to the remote:

- do **not** forward the SSH agent socket (no `-v $SSH_AUTH_SOCK`, no
  `--mount` of it)
- do **not** mount `~/.ssh`, `~/.gitconfig`, or `~/.config/gh`
- do **not** pass `GITHUB_TOKEN`, `GH_TOKEN`, or any other token the remote
  would accept — an inherited environment is the most common accidental grant
- set `GIT_TERMINAL_PROMPT=0` so a push fails instead of hanging on a prompt

On the host, create the dedicated config outside the checkout:

```bash
install -m 600 /dev/null ~/.agent-guard/broker.gitconfig
```

An empty file is sufficient for SSH authentication through `SSH_AUTH_SOCK`.
HTTPS users may put an explicit `credential.helper` and required `http.*`
settings in this file. Includes, URL rewrites, remote definitions, protocol
overrides, hooks and arbitrary `core.*` commands are rejected.

You then run `agent-guard push` on the host, against the same repository, where
your credential is. The repository supplies data only: the broker does not run
its hooks, use its credential helpers, honour its URL rewrites, or pass its
remote name to `git push`. The agent can continue writing code and commits,
while the host broker decides which exact object and URL may leave.

The strict 0.2.4 slice deliberately rejects linked worktrees, partial clones,
object alternates, multiple push URLs and special Git transports. Convert to a
normal checkout rather than weakening these checks.

What the agent hits when it tries is a real authentication failure, not a
policy message — which is the point. The hook's refusal becomes advice on top
of a wall, rather than being the wall.

## Deployment B — a hardware-backed key, one machine, no container

When a container is not practical, a key that requires a physical touch is the
only same-machine measure that does anything:

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

If you can choose between the two, choose A.

## Verify it, do not assume it

Configuration you have not tested is a belief. This check is one command and it
separates the two states unambiguously.

**From the agent's environment** — inside the container, or in the shell the
agent runs in — attempt a push that changes nothing:

```bash
git push --dry-run origin HEAD:refs/heads/credential-isolation-probe
```

`--dry-run` contacts the remote and authenticates but never updates a ref, so
this is safe against a real repository. It creates nothing; confirm with
`git ls-remote --heads origin credential-isolation-probe` if you want to see
that for yourself.

**With no credential reachable**, plain Git in the agent environment fails
before it can push:

```
fatal: could not read Username for 'https://github.com': terminal prompts disabled
```

or, over SSH, `Permission denied (publickey)`. That is the result you want.

**With a credential reachable**, git tells you exactly what it would have done:

```
To github.com:you/project.git
 * [new branch]      HEAD -> credential-isolation-probe
```

If you see that from the agent's environment, **you do not have credential
isolation**, whatever else you configured. Fix the environment before treating
the broker as a boundary.

Run the same command from wherever you intend to run `agent-guard push`, and
expect the opposite result. A setup where both sides fail is not isolation
either — it is a broker that cannot do its job.

Finally run the broker itself. It must show the push URL rather than merely the
remote name. A repository `pre-push` hook or `remote.<name>.pushurl` is input to
the preview, never code or an implicit second destination in the broker. These
claims are executable, not just prose: the
[adversarial Broker boundary suite](../../../crates/agent-guard-broker/tests/security_boundary.rs)
pins the push URL, repository-hook and config isolation, refusal receipts,
protocol policy, and unsafe repository layouts.

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
- **An unsigned receipt is not evidence.** With no broker signing key
  configured a receipt is marked `unsigned`: a truthful record, and not
  something a third party can check.
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
- **This covers `git push`.** Other ways code leaves a machine — a package
  publish, an HTTP upload, a copy to shared storage — are governed by policy
  where they are recognised, and by nothing where they are not.

## Related

- [Claude Code hook](claude-code-hook.md) — what the advisory layer does and does not do
- [Deployment guide](deployment-guide.md) — the general production checklist
- [`demos/push-broker/demo.sh`](../../../demos/push-broker/demo.sh) — the broker path end to end, against a throwaway repository
