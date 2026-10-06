# Defensive security review, second pass — 2026-10-05

This continues the [first review](security-review-2026-10-04.md). That review
patched F1–F22 and left R1 and R2 open. This pass looked for what it did not
cover and for gaps inside the patches it added. Findings are numbered on from
it: F23–F40 are patched. Independent follow-up below closes four residuals
(F41–F44) in those patches; R3–R9 are open or need a decision.

## Scope and evidence boundary

Baseline: branch `codex/security-review-026` at `e6340c9`, which already
contains F1–F22. Everything below is **uncommitted and unreleased** in the
working tree. No commit, push, release, advisory or issue was created.

Reviewed: the Git push broker and its CLI, the shell front end (grammar walk,
wrapper unwrapping, command-word and write-target gates, read-only allowlist),
outbound Git recognition, HTTP request decisions, file path rules, policy
loading and signature handling, Guard-owned execution, the macOS sandbox
profile, the Claude Code hook and the plugin installer.

Every patched finding has a regression test that was run and seen to fail
before the fix and pass after it. Negative shell inputs are decision-only:
the validator or `Guard::check` is called and no command string is executed.
Where execution is what is under test (broker, sandbox, file writes), fixtures
are temporary directories, local bare repositories and loopback listeners. No
network destination, real credential or destructive payload was used.

Local execution is macOS. Code gated to Linux or Windows was read, not
compiled or run; that is stated per finding. Severity is contextual, not a
CVSS score: **high** bypasses an advertised decision boundary under a shipped
preset or a restricted mode, **medium** needs a non-default configuration or
affects what a person is shown or what evidence is kept, **low** is
robustness.

Reviewer subagents were used for independent passes and were cut off by a
usage limit twice. Their checkpoint notes were recovered and every item in
them was re-verified here with a failing test before being patched. Their
coverage is therefore partial; see "Not examined".

## Patched findings

### F23 — High: a wrapper option the table did not know moved the command word

- **Path:** `agent-guard-validators/src/bash/wrappers.rs::skip_wrapper_tokens`.
- **Condition/impact:** `env`, `sudo`, `nice`, `timeout`, `stdbuf`, `time`,
  `xargs` and the other modeled wrappers are unwrapped so the command they run
  reaches every gate. An option the table did not list was skipped as a flag
  with no value. `getopt_long` accepts any unambiguous prefix, and some
  value-taking options were missing, so the value was read as the command and
  the real command was not examined. In read-only mode
  `env --uns cat touch marker` was allowed; in workspace-write
  `env --uns x sh -c '…'` passed the inline-code gate and
  `nice --adj 5 touch /outside/x` passed the write-target gate. `env - cmd`,
  `flock FILE -c STRING` and `coproc cmd` hid the command the same way.
- **Patch:** every option a wrapper is unwrapped through is named, as
  value-taking or not. An option in neither list makes the invocation opaque,
  which restricted modes refuse. The initial exemption for attached long
  options was too broad; F41 below restricts it to named options too.
  `coproc`, `busybox`, `toybox` and `caffeinate`
  are modeled; `arch`, `script`, `chroot` and `setpriv` are listed as opaque.
- **Regression:** `sec52_wrapper_options_the_table_does_not_know_fail_closed`
  and the launcher cases in `sec57_…` in
  [security_regression.rs](../crates/agent-guard-sdk/tests/security_regression.rs),
  with fourteen ordinary wrapper invocations as positive controls.
- **Compatibility:** a rarely used wrapper option that is real but unlisted is
  now refused in restricted modes until it is added to the table.

### F24 — High: a Git global option's value hid the push

- **Path:** `bash/git_push.rs::parse_git_push`.
- **Condition/impact:** `--attr-source <tree>` and `--shallow-file <path>`
  take a separate value (checked against Git 2.49). The recognizer skipped the
  option as a flag, took the value as the subcommand and found no push.
  `git --attr-source HEAD push --force origin main` was allowed with no
  decision under a policy that denies force pushes. Residual gap in F16.
- **Patch:** both options consume their value. Global switches are split into
  known flags and everything else; after an unknown switch, a word followed by
  `push` or `send-pack` is treated as that switch's value and the push is kept
  as an unverified candidate.
- **Regression:** `sec41_git_global_option_values_cannot_hide_an_outbound_push`.

### F25 — High: a URL's spelling stepped around HTTP deny rules

- **Path:** SDK `guard.rs` / `guard_helpers.rs` canonical policy evaluation,
  core `policy.rs` URL subject matching, validator `http.rs`, and the outbound
  preset. Standalone core `PolicyEngine::check` does not add the SDK's canonical
  URL subjects itself.
- **Condition/impact:** rules match the URL text; a client connects to what
  that text parses to. Under the shipped preset `HTTP://169.254.169.254/…`,
  `http://2852039166/…`, `http://0xA9FEA9FE/…`,
  `http://[::ffff:169.254.169.254]/…`, `http://user@169.254.169.254/…`,
  `http://LOCALHOST:8080/`, `http://127.1/`, a leading space and backslashes
  were all allowed. `/%61dmin` did not match a rule naming `/admin`. A string
  that is not an absolute `http`/`https` URL matched no rule at all. Guard-owned
  mutations were still stopped by the executor's resolved-address check; the
  decision for a hand-off (`GET`) or a check-only host was not.
- **Patch:** a request must carry an absolute `http`/`https` URL. Rules are
  also matched against canonical spellings: the parsed URL, the URL without
  userinfo, an IPv4 address embedded in an IPv6 literal, and each with
  percent-escapes of unreserved characters decoded once. A deny or ask rule
  that matches any spelling applies. The form without userinfo is decided in
  full, so an allow-list still refuses `https://allowed@other/`; the other
  spellings do not un-match an allow rule written as `host:443/…`. The preset
  now covers `127.0.0.0/8`, `[::1]`, `[::]` and `169.254.0.0/16`.
- **Regression:** `sec45_url_spelling_cannot_bypass_an_http_deny_rule` (loads
  the shipped preset) and `sec55_percent_encoded_paths_match_and_allow_rules_keep_their_spelling`.

### F26 — High: options of read-only Git subcommands wrote files and ran programs

- **Path:** `bash/read_only.rs`; `bash/paths.rs`.
- **Condition/impact:** read-only mode allows `git log`, `diff`, `show`,
  `grep`, `ls-remote` and similar. `--output=<file>` writes a file,
  `git grep -O<program>` and `--open-files-in-pager` run a program,
  `git ls-remote --upload-pack=<program>` names the program run for a local
  repository, and `--ext-diff`, `--textconv`, `--filters` enable programs named
  in repository configuration. All were allowed. In workspace-write mode
  `git log --output=/outside/file` and `git archive -o` were not seen as writes.
- **Patch:** read-only refuses those options, including unambiguous prefixes
  and bundled short forms (`-nO…`). F42 below narrows the initial `--text` /
  `--filter` exceptions to subcommands defining those complete options and
  covers helper re-enabling. `--output` and `archive -o` are write targets.
- **Regression:** `sec51_read_only_git_subcommands_cannot_write_or_execute_through_options`
  and the Git cases in `sec43_…`.
- **Boundary:** programs a repository's own configuration runs by default
  (`diff.external`, a `textconv` driver, `core.fsmonitor`) are not visible in
  the command and remain outside this check.

### F27 — High: the shell computed a command word the gates never saw

- **Path:** `bash/ast.rs::argv_of`; `bash/tokenize.rs`.
- **Condition/impact:** in workspace-write mode each of these ran a command
  other than the one classified, writing outside the workspace in the probes:
  `tou\⏎ch /outside/x` (the grammar reads backslash-newline as blank space, the
  shell deletes it); `/usr/bin/t* /outside/x` and `tou{c,}h /outside/x`
  (pathname and brace expansion as the command word);
  `hash -p /usr/bin/touch ls; ls /outside/x`, `alias`, `enable -f`;
  `trap 'cmd' EXIT`; and `echo cmd | sh -h` or `sh -V`, which were treated as
  help and version queries but are `set` options for a shell.
- **Patch:** words separated by nothing but a line continuation are joined;
  a pattern or brace expansion as the command word is refused like a parameter
  expansion; `hash -p`, `alias NAME=VALUE`, `enable -f` and `trap ACTION` are
  refused; only `--version`/`--help` count as information queries for a shell.
- **Regression:** `sec53_line_continuations_globs_and_rebinding_cannot_rename_a_command`
  and `sec57_brace_words_traps_shell_flags_and_known_launchers_fail_closed`.

### F28 — High on Windows: the installer wrote a policy the hook could not parse

- **Path:** `packages/agent-guard-plugin/lib/init.js::policyWithFileAudit`.
- **Condition/impact:** the audit path was interpolated into a YAML
  double-quoted scalar. A Windows home directory (`C:\Users\…`) is an invalid
  `\U` escape, so the installed policy did not parse, and the hook approves
  every call when it cannot load its policy. A quote in the path broke it on
  any platform.
- **Patch:** the path is written with `JSON.stringify`, which is also a valid
  YAML double-quoted scalar, through a replacer function so `$&` in a path is
  text. The pattern no longer consumes the line break after the value.
- **Regression:** `policyWithFileAudit writes a path YAML reads back unchanged`
  in [init.test.js](../packages/agent-guard-plugin/test/init.test.js), and
  `outbound_preset_accepts_a_json_encoded_audit_path` in
  [preset_parse.rs](../crates/agent-guard-sdk/tests/preset_parse.rs), which
  loads the shipped preset with such a path through the real policy parser.
- **Evidence limit:** not run on a Windows host.

### F29 — Medium: the broker's own CLI was an unrecognized outbound push

- **Path:** `bash/git_push.rs`; `guard-hook/src/broker_hint.rs`.
- **Condition/impact:** the hook answers a refused `git push` by naming
  `agent-guard push --remote … --branch …`. That command matched no outbound
  rule, and `--yes` or piped input skips its confirmation, so an agent that
  ran it reached the remote with no question asked. This affects the
  decision-only hook deployment; it does not weaken credential isolation where
  the agent cannot run the broker.
- **Patch:** `agent-guard push` is recognized as an outbound push with its
  remote and branch, including through a path, `env`, or an unknown outer
  command. The hint is not attached to the broker command itself.
- **Regression:** `sec42_the_broker_cli_reaches_the_same_outbound_decision_as_git_push`
  and `the_broker_command_is_not_pointed_at_itself`.

### F30 — Medium: text chosen by an agent or a remote reached the approver raw

- **Path:** `agent-guard-sdk/src/guard_git_preview.rs`; `agent-guard-cli/src/main.rs`;
  `guard-hook/src/hook.rs`.
- **Condition/impact:** the remote and refspec from the command are restated
  in the approval sentence, stored in the approval ledger and printed by
  `agent-guard list` and `show`. A carriage return, escape sequence or
  bidirectional override there changes what the approver reads without
  changing what runs. A remote's refusal text was printed to the terminal the
  same way. Same class as F20, on the surfaces F20 did not cover.
- **Patch:** `agent_guard_core::display_safe` escapes control characters,
  invisible format characters and non-ASCII white space as `\u{…}`. It is
  applied where the sentence is built, to every ledger field the CLI prints,
  to the hook's reason and to Git error text.
- **Regression:** `sec44_…`, the unit tests in
  [display.rs](../crates/agent-guard-core/src/display.rs),
  [approval_display.rs](../crates/agent-guard-cli/tests/approval_display.rs)
  and [remote_text_display.rs](../crates/agent-guard-cli/tests/remote_text_display.rs),
  whose remote is a local bare repository with a refusing `pre-receive` hook.

### F31 — Medium: the remote tip was not checked to be an object id

- **Path:** `agent-guard-broker/src/transaction.rs`; `git/snapshot.rs`.
- **Condition/impact:** the first field of the selected `ls-remote` line was
  shown in the preview and passed to `cat-file`, `merge-base`, `rev-list` and
  the push lease. A remote that reports `HEAD` or other text there puts it on
  the approval surface and into local revision lookup. The push destination
  is unaffected. Source-traced; no hostile server was built.
- **Patch:** the tip must be 40 or 64 hex digits; `cat-file` must report the
  exact object asked for; the refusal does not repeat the remote's bytes.
- **Regression:** unit tests in `transaction.rs`.

### F32 — Medium: common write destinations were not write targets

- **Path:** `bash/paths.rs::write_targets_for_segment`.
- **Condition/impact:** workspace-write mode confines `cp`, `mv`, `tar -C`,
  `dd of=` and redirections. `unzip -d`, `rsync`/`scp` destinations,
  `curl -o`, `wget -O/-P`, `sort -o`, `git worktree add`, `git clone`,
  `git init` and `find … -delete`/`-fprint` outside the workspace were allowed.
- **Patch:** each has a destination grammar; Git destinations resolve against
  `git -C`.
- **Regression:** `sec43_archive_sync_download_and_git_checkout_destinations_are_confined`.
- **Boundary:** this list stays finite. See R5.

### F33 — Medium: read-only HTTP blocked four verbs and allowed the rest

- **Path:** `agent-guard-core/src/policy.rs::http_method_is_mutation`.
- **Patch/regression:** read-only allows `GET`, `HEAD`, `OPTIONS` and nothing
  else, matching the SDK's routing; `sec46_read_only_http_allows_only_safe_methods`.

### F34 — Medium: a `Host` header named a destination the URL did not

- **Path:** `agent-guard-validators/src/http.rs::validate_http_request`.
- **Condition/impact:** rules decide on the URL. A request to an allowed URL
  with `Host: other` is delivered to the URL's address and routed by the
  header, which shared front ends serve.
- **Patch/regression:** a `Host` header must equal the URL's host, with or
  without its port; `sec47_…`.

### F35 — Medium: the executed command inherited the host's standard input

- **Path:** `agent-guard-sandbox/src/process.rs::configure_process_group`.
- **Condition/impact:** a Guard-owned `cat` read the host's stdin. Under a
  stdio server that is the protocol stream.
- **Patch/regression:** stdin is the null device on every backend that uses
  the shared runner; `the_executed_command_does_not_read_the_hosts_standard_input`.
  The non-Unix variant was edited and not compiled here.

### F36 — Medium: the macOS sandbox granted workspace writes in read-only mode

- **Path:** `agent-guard-sandbox/src/macos.rs`.
- **Condition/impact:** the Seatbelt profile did not depend on the mode, so in
  read-only the OS layer stopped nothing the classifier had missed. Landlock
  already made this distinction.
- **Patch:** the workspace is writable in `WorkspaceWrite`/`FullAccess` only;
  `/dev/null` is writable in every mode.
- **Regression:** `m5_read_only_mode_blocks_workspace_writes`.
- **Cost, locked by `m6_…`:** macOS `sh` writes a here-document to a temporary
  file in the working directory, so `cmd <<EOF` no longer runs in read-only
  mode under this backend. [sandbox-macos.md](reference/sandbox-macos.md) says so.

### F37 — Medium: three ways a path rule did not match the path it named

- **Path:** `agent-guard-core/src/file_paths.rs::resolve_path_glob_pattern`;
  `policy.rs`.
- **Condition/impact:** (a) the literal text before a pattern's first wildcard
  was resolved whole and joined with a separator, so `.env*` became
  `<workspace>/.env/*` and `/var/log/app-*.log` became `/var/log/app-/*.log`:
  rules that load and match nothing. (b) On macOS and Windows a file that does
  not exist yet keeps the case it was asked for, so writing `.NPMRC` created
  the `.npmrc` a rule denies. (c) A path is resolved before matching, so
  `.env` as a symlink was readable under `**/.env`, including under the
  shipped preset.
- **Patch:** only whole directory components of a pattern are resolved;
  `deny_paths` ignore case where the filesystem does; deny rules are matched
  against the path as requested as well as the resolved file.
- **Regression:** `sec48_…`, `sec49_…`, `sec54_…`.
- **Behaviour change:** see R7.

### F38 — Medium: a policy whose signature failed still configured things

- **Path:** `agent-guard-sdk/src/guard.rs`, `guard_lifecycle.rs`.
- **Condition/impact:** such a Guard denies every tool call. It still applied
  the unverified policy's `audit` block — creating and appending to a file it
  named, posting records to a webhook it named, or disabling recording — and
  it still asked that policy whether to scan input, so removing
  `input_content` let a prompt carrying a secret through. A reload that failed
  verification was recorded as `success`.
- **Patch:** an unverified policy supplies no audit configuration; records go
  to the host's sink, or standard error until one is named. An unverified
  reload keeps the destination in force and is recorded as a failure that
  names the policy. `check_content` blocks. A later verified reload restores
  that policy's own destination.
- **Regression:** `sec50_…`, `sec56_…`, and
  `input_check_fails_closed_under_a_policy_whose_signature_failed` in
  [content_enforcement.rs](../crates/agent-guard-sdk/tests/content_enforcement.rs).

### F39 — Low: writing to a FIFO held the host thread indefinitely

- **Path:** `agent-guard-sdk/src/executors.rs`.
- **Patch/regression:** WriteFile opens without waiting and writes regular
  files only; `write_file_refuses_a_fifo_instead_of_waiting_on_it`.

### F40 — Low: `tools.custom` accepted sections that could never apply

- **Path:** `agent-guard-core/src/policy.rs`.
- **Condition/impact:** a repeated key replaced the rules under the first; a
  builtin's name or text outside the id grammar held rules no tool id could
  reach.
- **Patch/regression:** both fail at load;
  `custom_tool_sections_that_can_never_apply_cannot_construct_a_guard`.

## Open items and decisions

### R3 — Decision: unscoped `credential.helper` in the broker's trusted config

F21 requires a URL scope for `http.extraHeader` because the preview contacts
a repository-chosen URL before approval. `credential.helper` has no such
requirement. A helper keyed by host is unaffected. A helper that returns one
token for any host would give it to that URL at preview time. Not reproduced
and not changed: requiring `credential.<url>.helper` would be the equivalent
rule, and it changes what a deployment must configure.

### R4 — Documented limit: an agent can run `agent-guard approve`

The approval ledger is an unauthenticated same-user file. Recognizing
`agent-guard approve` in the outbound gate would not change that.

### R5 — Workspace-write confinement stays a finite list

Not covered: a state-changing Git subcommand under `git -C <outside>`,
`--git-dir` or `--work-tree`; `curl -D`/`-c`, `zip`, `patch -o`, `split`,
`openssl -out` and other sinks; any program not in the tables. The OS sandbox
is the layer for these.

### R6 — Not run on Windows or Linux

The non-Unix stdin change (F35) and the installer fix (F28) were verified at
source and string level only. R1 from the first review is unchanged.

### R7 — Behaviour change to review: `allow_paths` patterns

The pattern fix in F37 applies to `allow_paths` too. A pattern with a
wildcard inside its first non-directory component now means what it says:
`notes-*.md` matches, and `src*` matches `src-old/` as well as `src/`.
Previously such patterns matched a narrower, unintended set or nothing.

### R8 — Hand-off hosts must read a payload the way the Guard does

For a duplicated `url` key the validator and the policy engine take the last
value and the Guard's own executor rejects the payload. A host that executes a
hand-off itself and takes the first value would act on a URL no rule saw.

### R9 — Cross-language parity comparison not run locally

`tests/cross-language-parity/compare.py` needs a direct `python3` invocation,
which this repository's own hook refuses in an agent session. The Python and
Node binding suites were run through `scripts/verify.sh` and pass.

## Not examined

The shell front end outside the items above (here-document bodies, process
substitution, size and depth limits), the Linux and Windows sandbox backends
beyond reading them, `guard-verify`, the framework adapters, and SIEM export.
The reviewer assigned to command execution and privilege was cut off before
reporting; its probe file was recovered and re-run, which is where F25, F33,
F34, F35, F37, F38 and F39 began.

## Verification

The original author's macOS working-tree results, before the independent
follow-up below (not evidence for subsequent edits):

- `./scripts/verify.sh lint`, `rust`, `docs`, `node` and `python`: each exits
  0. The Rust leg (`--all-features`) reports 51 result groups, **1,106 passed,
  0 failed, 2 ignored**; the first review's combined tree reported 1,069.
  Python: 108 passed, 1 skipped (the real-framework module, which needs
  `AGENT_GUARD_PY_FRAMEWORKS`). Node binding tests pass; plugin tests 14 of 14.
  The docs gate scans 206 Markdown files.
- `cargo test -p agent-guard-sandbox --features macos-sandbox`: 19 unit tests
  and 7 Seatbelt integration tests pass.
- `cargo test -p agent-guard-sdk --features content --test content_enforcement`:
  11 pass.
- `crates/agent-guard-sdk/tests/security_regression.rs`: 68 pass, of which 19
  are new in this pass (`sec41`–`sec57`).

## Independent follow-up — residuals F41–F44

The original second-pass tree passed `verify.sh full` in an isolated temporary
snapshot. That is useful baseline evidence, but did not catch the following
decision gaps. Five new negative SDK tests were first observed failing with
`Allow`, then passed after the patches. These inputs are checked as strings:
no shell command, remote request, or helper program is executed by these tests.

### F41 — High: attached unknown wrapper options still hid command syntax

- **Path:** `bash/wrappers.rs::skip_wrapper_tokens`.
- **Condition/impact:** a restricted-mode caller can supply an unmodeled
  attached long option. Treating every `--NAME=VALUE` as self-contained let
  abbreviated `env` split-string syntax bypass the opaque-launcher check.
- **Patch:** require the exact long-option name to occur in the modeled
  value-taking or boolean list, with or without an attached value. Unknown
  names, including abbreviations, are opaque and refused in restricted modes.
- **Regression:** `sec58`, plus wrapper unit tests. Known `--unset=KEY` remains
  allowed; unknown attached options and a nested wrapper are denied.

### F42 — High: Git option exceptions were not subcommand-specific

- **Path:** `bash/read_only.rs::git_option_that_writes_or_executes`.
- **Condition/impact:** a read-only caller can enable repository-configured
  converters via cat-file option abbreviations. The blanket `--text` /
  `--filter` exception, two-letter minimum and ignored paired negation prefixes
  all produced `Allow` for helper-enabling forms.
- **Patch:** scope complete-option exceptions to the subcommands defining
  them, inspect even one-letter prefixes, and normalize paired `no-no-`
  prefixes that re-enable an option. Single disabling prefixes remain allowed.
- **Regression:** `sec59` and `sec62`; ordinary `diff --text`,
  `rev-list --filter` and disabling helper options remain allowed.
- **Reference:** Git's [cat-file option definitions](https://github.com/git/git/blob/v2.49.0/builtin/cat-file.c)
  and [option parser](https://github.com/git/git/blob/v2.49.0/parse-options.c).
  This remains command-text inspection, not isolation from all repository
  configuration that can execute programs by default.

### F43 — High: repeated continuations changed the command identity

- **Path:** `bash/ast.rs::argv_of`.
- **Condition/impact:** a caller can place multiple adjacent backslash-newline
  pairs inside an executable word. The shell removes every pair, but the
  reconstructed argv joined only one pair, missing executable-anchored gates.
- **Patch:** join adjacent words only when their entire nonempty source gap
  consists of continuation pairs; ordinary whitespace still separates words.
- **Regression:** `sec60` denies a reconstructed write and destructive Git
  intent, while a reconstructed read-only echo remains allowed.

### F44 — High: an attached copy-option value swallowed the destination

- **Path:** `bash/paths.rs::last_local_operand`.
- **Condition/impact:** in workspace-write mode, an attached short-option
  value ending in another value-taking flag letter made the parser consume
  the actual destination as a second option value, omitting the path check.
- **Patch:** stop interpreting the bundle at its first value-taking flag;
  consume the next argv only if that flag has no attached remainder.
- **Regression:** `sec61` and copy-destination unit tests cover outside
  destinations, ordinary workspace destinations and separate option values.

### Test-strengthening and remaining gate

The connected-reader FIFO regression tests the opened-file type refusal itself
in both write scopes and append/overwrite modes, asserting no bytes are sent.
The no-reader test alone primarily proved the nonblocking open behavior. It
passes locally after adding the required test-only `Read` import. Seatbelt
read-only/heredoc tests now use independent temporary workspaces; all seven
macOS integration tests pass with default parallel execution. The verified
policy-reload child test now asserts `Allow` as well as the restored audit sink.
The bounded OS-network parity probe now targets loopback rather than a public
IP, retaining the refusal assertion without contacting a third-party endpoint.

SDK security regressions: **73 passed** after F41–F44. Shared parity fixtures
now contain **52** scenarios, including 22 new decision-only positive/negative
cases. The comparator checks agreement rather than expected behavior; SDK
regressions independently enforce the latter. Final full/strict/parity results
and exact-head cross-platform CI belong in the
[delivery record](security-delivery-2026-10-04.md), not the older results above.
No claim here closes R1–R9 or establishes registry availability.
