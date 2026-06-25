# `agent-guard-unwrap-v1` — shell command-body normalization annex

A normalization profile for the **`normalized command body`** field of the
crewAI governance contract (#5888 / PR #6030). It defines how a shell-executed
tool call is reduced to its *real executable + argv* before `params_hash` is
computed, so authorization binds what actually executes — not the surface
request a transparent wrapper or spawner can rewrite.

The core contract pins three things (per the #5888 discussion): `params_hash`
MUST be computed over the normalized executable form; the applied normalization
MUST be declared (`"normalization_id": "agent-guard-unwrap-v1"`); and an
execution-time recompute MUST fail closed on mismatch. This annex supplies the
shell profile for that scheme. It is transcribed from agent-guard's shipped gate
(`crates/agent-guard-validators/src/bash/wrappers.rs`); the conformance vectors
are derived from that gate, not authored for the spec.

## Scope

- **Input:** a pre-tokenized `argv` (a list of shell words). Tokenization is the
  runtime's responsibility, upstream of this profile.
- **Output:** `normalized_argv` (the real executable + argv) and a
  `target_unverifiable` flag.
- This profile covers the shell/command-body case only. Structured tool
  arguments use JCS-over-args; that is a different `normalization_id`.

## Normalization algorithm

Apply repeatedly until the leading token is the real command word:

1. **Strip `NAME=value` assignment prefixes.** A token is an assignment prefix
   iff it contains `=` and every byte before the first `=` is `[A-Za-z0-9_]`
   (an empty name — a leading `=` — also matches, mirroring the shipped gate).
   Drop all leading assignment prefixes. This handles bare (`FOO=1 cmd`) and
   post-wrapper (`env BAR=2 cmd`) assignments.

2. **`find … -exec`/`-execdir`:** if the leading token is `find`, locate the
   first `-exec` or `-execdir`; the sub-command is the tokens between it and the
   first `;` or `+` terminator. Continue normalizing that sub-command (so
   `find … -exec sudo rm …` reduces to `rm`). A `find` with no `-exec(dir)` is a
   plain traversal and is returned unchanged.

3. **Strip one transparent-wrapper layer** if the leading token is a known
   wrapper (table below): drop the wrapper name, its options, and its leading
   operands, then repeat from step 1 (handles nesting like `sudo env rm`).

4. Otherwise the leading token is the **real command word** — stop.

### Option/operand skipping (per wrapper)

Within a wrapper's arguments:

- `--` terminates option parsing (and is itself dropped).
- A lone `-`, or any token not starting with `-`, ends the option run.
- A `--long` token is dropped (boolean; this profile does not model `--long=val`
  splitting because the value is attached).
- For a short-option bundle, if an **argument-taking** flag (see table) is the
  **last char** of the bundle, the **next token** is its value and is consumed
  too (`-u root`, `-knu root`); otherwise the bundle is self-contained
  (`-uroot` attached value, or an all-boolean bundle `-kn`).
- After options, the wrapper's **leading operands** (e.g. `timeout`'s DURATION,
  `flock`'s lockfile) are dropped.

### Wrapper table (`agent-guard-unwrap-v1`)

| wrapper   | argument-taking short flags | leading operands | notes |
|-----------|-----------------------------|------------------|-------|
| `sudo`    | `C D g h p R r t T U u`     | 0 | |
| `doas`    | `u C`                       | 0 | |
| `env`     | `u C`                       | 0 | also passes `NAME=value` (step 1) |
| `nice`    | `n`                         | 0 | |
| `nohup`   | —                           | 0 | |
| `timeout` | `s k`                       | 1 | leading operand = DURATION |
| `strace`  | `o e p E s a`               | 0 | |
| `ltrace`  | `o e p s a u`               | 0 | |
| `nsenter` | `t S G`                     | 0 | rare `-r[dir]`/`-w[dir]` treated as boolean |
| `unshare` | —                           | 0 | all short flags boolean |
| `watch`   | `n`                         | 0 | |
| `flock`   | `w E`                       | 1 | leading operand = lockfile/fd |
| `xargs`   | `I i E e d n P s a L l`      | 0 | operands come from stdin — see below |

Any leading token not in this table (and not `find`/an assignment) is treated as
the real command word.

## Target-hiding spawners (`target_unverifiable`)

`xargs` and `find … -exec` supply the wrapped command's **operands** from
outside the visible request — stdin for `xargs`, the filesystem traversal (`{}`)
for `find -exec`. When such a spawner leads the command, the real write target
cannot be verified at authorization time, so `target_unverifiable = true` and the
runtime **MUST fail closed** rather than bind a digest over incomplete operands.
(The wrapper itself is still stripped for the executable form; the flag is an
additional, independent signal.)

## Conformance properties

The vectors in `vectors.json` exercise three properties:

- **test-3 (equivalence):** every surface form of an action normalizes to the
  same `normalized_argv` and the same digest
  (`"sha256:" + hex(SHA-256(JCS(normalized_argv)))`, RFC 8785).
- **test-2 (divergence):** a wrapper that changes the real executable or argv
  yields a different digest.
- **test-2 (fail-closed):** a target-hiding spawner is flagged
  `target_unverifiable`.

Two independent checks prove the profile:

1. `normalize_check.py` — a dependency-light **second implementation** of this
   algorithm (stdlib + `rfc8785`); recomputes the digests and asserts all three
   properties from the committed bytes.
2. `fidelity/` — a Rust harness that runs agent-guard's **real public gate**
   (`validate_bash_command`) and confirms every wrapped form tracks the bare
   canonical command's verdict (wrappers are transparent to the gate) and that
   target-hiding spawners block in `WorkspaceWrite`. This is what makes the
   profile *derived from the shipped gate* rather than authored for the spec.

The gate exposes an allow/block verdict, not the raw normalized argv, so the
fidelity harness witnesses equivalence at the verdict level; exact-digest
equivalence/divergence is the Python reference's job.

## Version

`agent-guard-unwrap-v1` — initial profile. Wrapper table + target-hiding set
transcribed from agent-guard `crates/agent-guard-validators/src/bash/wrappers.rs`
(audit lineage 2026-05-18 / 2026-06-08; PRs #75–#77). Irregular spawners beyond
this table are out of scope for v1.
