# Bounded shell-maintenance closure, 2026-10-06

Baseline: `e1a0a0a5fd956186e67e9c235451cbfa2fb4b260` (the immutable
`v0.2.7` tag). This report describes the independent implementation checkout,
**not a released patch**. The [active progress record](broker-first-progress.md)
tracks later commits and exact-head CI separately.

The user authorized defensive repairs using safe unit/integration tests and
temporary local fixtures. Negative Shell strings below are classification
inputs only: no attack command, third-party mutation, live credential or
destructive payload was executed. This closes the four finite families in P1
of the [accepted plan](plans/broker-first-development-plan.md), not a universal
Shell safety claim. OS isolation and credential separation remain distinct.

## Findings and regression locks

### F45 — control-byte lexical disagreement

**Severity: High for a deployment relying on the command-policy gate.** The
Bash grammar treats VT/FF/CR as whitespace where an executing shell can treat
them as word bytes. A following comment delimiter can therefore hide a command
position from the classifier. On the baseline, harmless diagnostic text was
allowed by the real SDK and compiled hook rather than rejected as unmodelled.
The policy decision is defective even though no negative command was executed.

- Path: [`parse_shell`](../crates/agent-guard-validators/src/bash/ast.rs), then
  canonical subjects, validators, SDK and hook decisions.
- Conditions: attacker supplies command text; the host accepts the classified
  text for a shell with different lexical treatment. The hook is advisory and
  default SDK builds have no OS containment; a separate protected broker does
  not acquire credentials merely from this decision.
- Repair: raw ASCII controls other than tab/newline outside literal text return
  `TooComplex`. Restricted modes refuse them; known literal data stays usable.
- Locks: `unquoted_control_bytes_cannot_create_a_grammar_only_comment`, SDK
  `sec65`, actual hook JSON decisions, and shared Rust/Python/Node scenarios.

### F46 — computed command identity and empty assignment names

**Severity: High, conditional on the host's execution dialect and authority.**
The assignment-prefix guess accepted an empty name and discarded an `=`-leading
command word. In zsh such a word can be computed from command lookup. The
baseline SDK allowed the benign diagnostic instead of refusing unsupported
dynamic identity. The SDK's own Unix executor uses `sh`, not zsh: this is not
evidence that its executor performs zsh expansion.

- Paths: [`wrappers.rs`](../crates/agent-guard-validators/src/bash/wrappers.rs)
  and [`contains_dynamic_command_word`](../crates/agent-guard-validators/src/bash/tokenize.rs).
- Conditions: a host integration executes a dialect/form the Bash classifier
  cannot model, or an actual executable with that identity exists. Reachable
  credentials/privileges remain deployment conditions, not consequences proved
  by the test.
- Repair: `=`-leading command words are dynamic/unsupported in restricted
  modes; modelled environment operands require a nonempty assignment name.
- Locks: `computed_command_words_are_not_empty_environment_assignments`, SDK
  `sec66`, hook, parity; genuine assignments and supported wrappers remain
  positive controls.

### F47 — outer literal exemption crossing into executable regions

**Severity: Low as demonstrated; parser defense in depth.** The supplied
partial repair exempted quoted/heredoc data without reliably separating nested
executable regions. That leaves low-level canonical parsing inconsistent even
when a higher layer independently refuses substitutions.

- Path: the control-byte scanner in
  [`ast.rs`](../crates/agent-guard-validators/src/bash/ast.rs).
- Conditions: a substitution inside an outer quoted/heredoc region contains
  ambiguous control bytes outside its own literal nodes.
- Repair: literal ancestry stops at command/process substitution boundaries.
  Only literal nodes inside the current executable region can exempt a byte.
- Locks: `nested_executable_regions_do_not_inherit_outer_literal_exemptions`
  is red on baseline; SDK `sec67` is an entry-layer retention test. **It was
  already green before this repair**, so no SDK execution bypass is claimed.

### F48 — literal executable mistaken for a variable assignment

**Severity: Medium for read-only command authorization.** A string heuristic
removed assignment-looking command words after AST recovery. A quoted or
concatenated literal executable, or a command reached through `nice`, `timeout`
or `command`, could disappear and expose a benign argument as the command.
Baseline read-only SDK tests demonstrated Allow where refusal was required.

- Paths: AST command recovery and wrapper unwrapping in
  [`wrappers.rs`](../crates/agent-guard-validators/src/bash/wrappers.rs).
- Conditions: attacker supplies a literal executable identity; for execution
  impact that program must be reachable by the host. This is not a promise
  that WorkspaceWrite rejects all unknown programs.
- Repair: rely on real AST assignment-node identity before command recovery.
  Do not strip guessed assignment prefixes from recovered argv. Only explicitly
  modelled `env`/`sudo` operand grammar consumes assignment arguments.
- Locks: `literal_assignment_looking_command_words_are_never_discarded`, SDK
  `sec68`, hook and parity. Real assignments, `env --`, negation and ordinary
  data have positive compatibility controls.

## Reproducibility and results

[Preserved evidence](security-evidence/2026-10-06/README.md) includes the other
reviewer's original partial patch, five diagnostics, baseline failures and
green logs. The original checkout and reviewer checkout were not overwritten.

- Permanent parser suite on baseline: 4 failed / 1 positive-control pass.
- Baseline SDK: `sec65`, `sec66`, `sec68` failed; `sec67` and existing
  `sec60`–`sec64` passed. Real hook refusal test also failed with `allow` output.
- Patched validators: 319 unit, 5 new integration and 3 corpus passes.
- SDK security regression: 79/79; hook e2e: 13/13.
- `verify.sh full`: exit 0; Rust result summaries total 1,132 passed, 0 failed,
  2 ignored; Python with real LangChain 113 passed; Node tests and plugin 14/14
  passed. Matching-host macOS tests ran; other OS jobs require CI.
- Strict all-target workspace and Python-binding Clippy: exit 0.
- Independent comparator with rebuilt native bindings: 70 identical expected
  scenarios across Rust/Python/Node. Equality alone is not correctness; SDK
  assertions separately lock the intended decisions.

The first full invocation failed because a new deployment test existed before
its implementation module was written. It was not skipped; the frozen P3 tree
subsequently passed. One targeted SDK attempt encountered a sandbox-denied
loopback bind; a normally approved local-test rerun passed, preserving both logs.

## Deployment work is separate

The [fixed Linux reference](../deploy/broker-first/README.md) is new deployment
code, not a repair to default-hook credential isolation. Its configuration and
orchestration tests include refusal ordering and inspect drift. Six
[authenticated TLS host-composition tests](../tests/broker-first/README.md)
independently observe remote refs and unsigned attempt records, including
unauthenticated connectivity, scope refusal, cancellation and fixture cleanup.

Neither those host tests nor a successful configuration check establish native
container isolation. The dedicated job at head `5f8e714` now supplies
[actual native evidence](security-evidence/2026-10-06/native-linux/README.md),
plus 69 broker/23 CLI tests, zero failures or ignores; its 21-job matrix succeeded.
P3/P4's fixed synthetic Linux I1–I8 workflow is accepted, not arbitrary images,
all platforms or real user acceptance. Windows ambient handles and
general shared-hard-link limitations remain open. Publication is still held;
affected published-version ranges and any advisory updates require separate
verification and the outstanding version/disclosure decision.
