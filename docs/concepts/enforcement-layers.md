# 🧱 Enforcement Layers (ADR)

| Field | Details |
| :--- | :--- |
| **Status** | ✅ Accepted (2026-06-12) |
| **Audience** | Contributors, Security Reviewers |
| **Version** | 1.0 |
| **Related Docs** | [Threat Model](threat-model.md), [Capability Parity](capability-parity.md) |
| **Tracking** | Decision record for [#57](https://github.com/XuebinMa/agent-guard/issues/57); informed by [#54](https://github.com/XuebinMa/agent-guard/issues/54), [#55](https://github.com/XuebinMa/agent-guard/issues/55) |

---

## Decision

`agent-guard` contains two enforcement mechanisms with different guarantees. This
record declares, once, which one is load-bearing in which deployment shape — so
that security claims, bypass-report triage, and engineering effort all follow the
same map instead of an implicit one.

1. The **policy engine** (rules, modes, trust levels) is **always load-bearing**:
   it is the decision integrity of the product. A wrong `Allow` from a correctly
   authored policy is always a CRITICAL bug.
2. The **static validators** (`agent-guard-validators`: bash command analysis,
   path checks) are an **intent gate, never a containment boundary**. They
   classify what a command *appears* to do and feed the decision layer. Denylist
   analysis of a Turing-complete shell structurally over- and under-matches;
   hardening it reduces friction and improves audit signal, but no validator fix
   ever upgrades it into a boundary.
3. The **OS sandbox** (`agent-guard-sandbox`: Landlock/seccomp, Seatbelt, Job
   Objects) is the **only containment boundary** this project can offer — and
   only when the platform feature is compiled in and
   `Guard::default_sandbox_diagnosis()` confirms it is active (see Threat Model,
   Sharp Edge #1).

## The two deployment shapes

| Shape | Example | What agent-guard provides | Containment responsibility |
| :--- | :--- | :--- | :--- |
| **Decision-only** | `guard-hook` on Claude Code PreToolUse; `Guard::check` / `decide` from any SDK | Policy decision + signed evidence. The host runtime executes (or doesn't). | The **host runtime** (and whatever isolation it runs under). |
| **Guard-owned execution** | `Guard::execute` / runtime `run` path | Decision + execution inside the selected sandbox + signed receipt. | The **sandbox layer**, iff compiled in and active; otherwise falls back to decision-only posture (noop sandbox, truthfully diagnosed). |

The primary adoption wedge today is **decision-only**. In that shape there is no
sandbox in the path at all — which is precisely why the validator must not be
described as a boundary: in the most common deployment it is the only mechanical
check, and it is best-effort by construction.

## Triage rules for bypass reports

| Report | Severity | Rationale |
| :--- | :--- | :--- |
| Policy engine returns `Allow` where authored rules say deny/ask | **CRITICAL** | Decision integrity is always load-bearing. |
| Sandbox escape while the platform feature is compiled in and diagnosis reports active | **CRITICAL** | The one containment promise we make is broken. |
| Validator bypass (new laundering trick, wrapper, encoding, spawner) | **HIGH, routine backlog** | Expected arms race (e.g. #55); fix on cadence, never treat as a broken boundary because no boundary was promised. |
| "Escape" from a noop/passthrough sandbox in a default build | **Not a vulnerability** | Documented behavior (Threat Model, Sharp Edge #1); the diagnosis API reports it truthfully. |

## Consequences

- **Engineering effort**: validator hardening is scheduled work, not
  drop-everything work. Boundary-grade effort goes to the sandbox layer and to
  decision integrity (policy engine, decision plumbing, signed evidence).
- **Messaging**: no agent-guard surface (README, docs, release notes, outreach)
  may claim containment for the validator or for a default build. Claims about
  "blocking" in decision-only deployments must attribute enforcement to the host
  runtime honoring the decision. This extends the claim discipline already
  established for cross-runtime statements.
- **Known consequence we accept**: a sufficiently motivated payload can express
  a destructive action the validator cannot classify. The mitigation is the mode
  system + path confinement + (where compiled) the sandbox — not more denylist.

## Alternatives considered

- **Declare the validator the boundary and harden it indefinitely** — rejected:
  enumerate-badness over shell input cannot converge; it would commit the
  project to an unwinnable arms race and a false claim.
- **Declare the sandbox the boundary unconditionally** — rejected: it is
  off-by-default, platform-gated, and absent from the decision-only shape that
  most adopters actually run; claiming it unconditionally would be untrue for
  the primary wedge.
