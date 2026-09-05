# Credential isolation for the push broker

`agent-guard push` is a boundary only if the agent cannot push on its own.

This page is about the half of that sentence the code cannot deliver. The
broker runs `git` as a subprocess and inherits its own process environment
([`crates/agent-guard-broker/src/git.rs`](../../../crates/agent-guard-broker/src/git.rs)),
so it pushes with whatever credential that process happens to hold. Nothing in
this repository creates the separation, and nothing in it can check whether you
have it. It is a property of how you run things.

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

## The requirement, in one sentence

> The push credential must live somewhere the agent's process cannot read.

Everything below is a way to satisfy that. Note what it rules out: same user,
same session, no container is **not** a boundary, because a POSIX process can
read its own user's files. No amount of configuration inside agent-guard
changes that.

## Deployment A — the agent in a container, the credential on the host

The one that actually holds, and the one to prefer.

Run the agent in a container with the repository bind-mounted, and give that
container no way to authenticate to the remote:

- do **not** forward the SSH agent socket (no `-v $SSH_AUTH_SOCK`, no
  `--mount` of it)
- do **not** mount `~/.ssh`, `~/.gitconfig`, or `~/.config/gh`
- do **not** pass `GITHUB_TOKEN`, `GH_TOKEN`, or any other token the remote
  would accept — an inherited environment is the most common accidental grant
- set `GIT_TERMINAL_PROMPT=0` so a push fails instead of hanging on a prompt

You then run `agent-guard push` on the host, in the same repository, where your
credential is. The agent can write code and run tests against the mounted
working tree; it cannot make anything leave the machine.

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

**With no credential reachable**, git fails before it can push:

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
- **This covers `git push`.** Other ways code leaves a machine — a package
  publish, an HTTP upload, a copy to shared storage — are governed by policy
  where they are recognised, and by nothing where they are not.

## Related

- [Claude Code hook](claude-code-hook.md) — what the advisory layer does and does not do
- [Deployment guide](deployment-guide.md) — the general production checklist
- [`demos/push-broker/demo.sh`](../../../demos/push-broker/demo.sh) — the broker path end to end, against a throwaway repository
