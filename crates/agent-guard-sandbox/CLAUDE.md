# CLAUDE.md — agent-guard-sandbox

Scoped guidance for the OS-level sandbox crate. This **adds** to the root
[`CLAUDE.md`](../../CLAUDE.md); it does not repeat it. Read the
[Testing Strategy](../../docs/concepts/testing-strategy.md) before changing a
backend — the SDK's gate tests depend on this crate behaving truthfully.

## What this crate is

A single `Sandbox` trait (`name`, `sandbox_type`, `capabilities`, `execute`,
`is_available`) with one implementation per platform, selected at runtime:

| File | Backend | Feature flag | Default? |
| :--- | :--- | :--- | :---: |
| `linux.rs` | seccomp-bpf wrapper (prototype/fallback) | `seccomp` (needs libseccomp) | off |
| `landlock.rs` | Landlock FS isolation (kernel 5.13+) | `landlock` | off |
| `macos.rs` | Seatbelt via `sandbox-exec` (experimental) | `macos-sandbox` | off |
| `windows.rs` | Job Object (experimental) | `windows-sandbox` | off |
| `windows_appcontainer.rs` | AppContainer (experimental) | `windows-appcontainer` | off |
| `noop.rs` | no isolation, reports `"none"` | — | **yes** |

With no feature flags, a default build selects `noop` and `sandbox_type()`
returns `"none"`. That is intentional and must stay that way: the crate reports
the isolation it actually compiled in, never more.

## Invariants you must not break

These are locked by `GATE 2` and `GATE 3` in
[`agent-guard-sdk/tests/release_gate.rs`](../../crates/agent-guard-sdk/tests/release_gate.rs).
If you change backend selection or what a backend blocks, those tests must stay
green and stay honest.

1. **Truthful backend selection.** Priority is: Linux → `landlock` if its
   feature is on *and* available, else `seccomp` if compiled, else `"none"`;
   macOS → `macos-seatbelt` if available, else `"none"`; Windows →
   `windows-appcontainer`, else `windows-job-object` if available, else
   `"none"`. When nothing real is compiled in, the answer is `"none"` — do not
   make a backend claim isolation it does not enforce.
2. **`capabilities()` must match reality.** The `SandboxCapabilities` a backend
   returns is a promise about what it blocks. If `execute()` does not actually
   block global writes, the matching capability must be `true` (allowed/not
   blocked), not aspirationally `false`. The docs content-linter
   (`scripts/check_docs.py`) enforces the same honesty in the capability tables.
3. **The Linux baseline is a prototype wrapper, not shipped seccomp-bpf
   enforcement.** Do not relabel it as production-grade syscall filtering in
   code comments or docs — the linter rejects that phrasing and `GATE 2`
   reflects the truthful `"none"`/`"linux-seccomp"` split.

## Testing this crate

Per-OS integration tests only mean anything on the matching OS **with** the
matching feature flag — they cannot run cross-platform, and a plain
`cargo test -p agent-guard-sandbox` exercises only the noop path + unit tests.

```bash
# Linux (needs libseccomp-dev installed)
cargo test -p agent-guard-sandbox --features seccomp --test seccomp_integration -- --nocapture
# macOS
cargo test -p agent-guard-sandbox --features macos-sandbox --test macos_integration -- --nocapture
# Windows
cargo test -p agent-guard-sandbox --features windows-sandbox --test windows_job_integration -- --nocapture
```

CI runs each of these on a dedicated OS runner; locally you will only cover the
platform you are on. A green local `verify.sh` does **not** cover the other two
OS backends — see the local-vs-CI table in the testing strategy.

## See also

- [Capability Parity Matrix](../../docs/concepts/capability-parity.md) — what each OS backend blocks.
- Sandbox references: [Linux](../../docs/reference/sandbox-linux.md) · [macOS](../../docs/reference/sandbox-macos.md) · [Windows](../../docs/reference/sandbox-windows.md)
</content>
