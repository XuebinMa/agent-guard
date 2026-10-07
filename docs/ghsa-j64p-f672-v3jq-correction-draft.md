# GHSA-j64p-f672-v3jq correction draft

This is a draft for the existing public advisory, not a new advisory, CVE
assignment, or announcement that 0.2.8 is already available. Verify the actual
registry release before naming 0.2.8 as a patched version. The immutable 0.2.7
source tag contains the sed repair but its release was cancelled; it is not
an available registry remedy. New parser findings remain outside this advisory.

## Metadata to preserve and correct

Preserve the current advisory ID, summary, critical severity and CWE entries.
Do not rewrite its scope to cover all 22 findings in the defensive review.

| Ecosystem | Package | Correct affected range | Patched version |
| --- | --- | --- | --- |
| rust | agent-guard-validators | `<= 0.2.6` | none until release verification; then `0.2.8` |
| rust | agent-guard-sdk | `<= 0.2.6` | none until release verification; then `0.2.8` |
| rust | guard-hook | `<= 0.2.6` | none until release verification; then `0.2.8` |
| npm | agent-guard-plugin | `<= 0.2.6` | none until release verification; then `0.2.8` |
| pip | agent-guard-python | `<= 0.2.6` | none until release verification; then `0.2.8` |

The Python wheel embeds the SDK/validator implementation. The Node binding is
not published to npm; do not add it as a published vulnerable package. The
CLI's SDK dependency is covered transitively in Rust lockfiles; do not flag
unrelated core/offline verifier crates without evidence.

## Corrected public description before a repair release is available

Three independent Bash validation gaps in Agent Guard 0.2.5 and earlier could
let a tool call evade controls in the shipped restricted policy when it ran
with the default noop/advisory sandbox. Agent Guard 0.2.6 fixed the original
command-word normalization and unresolved/home-relative destination issues,
but its in-place sed destination fix was incomplete. The sed issue therefore
also affects 0.2.6; that version must not be presented as a complete fix.

1. Command-word normalization could differ from Bash execution for a line
   continuation, missing executable-anchored checks. The originally reported
   normalization case was addressed in 0.2.6.
2. Unresolved home-relative or variable-based write destinations could escape
   workspace checks. The originally reported unresolved-destination cases were
   addressed in 0.2.6.
3. In-place sed destinations were not extracted consistently. Follow-up review
   of 0.2.6 reproduced omitted forms involving attached backup suffixes and
   expressions/options after file operands. These forms can permit an existing
   outside-workspace file to be modified with the agent's current OS privileges.

Affected entry points include the Rust validators, SDK, guard-hook, the npm
plugin installing that hook, and Python wheels embedding the same native
implementation. A caller must be able to supply or influence a Bash tool
invocation evaluated under an affected restricted policy. This does not by
itself escape a correctly configured OS sandbox. The noop sandbox and default
advisory hook are not kernel containment boundaries.

The sed follow-up was merged in [PR #170](https://github.com/XuebinMa/agent-guard/pull/170)
with bounded parsing, conservative handling of unmodeled scripts/options,
and permanent negative and positive local regressions. Its 0.2.7 registry
release was cancelled. The successor 0.2.8 is being prepared in
[PR #171](https://github.com/XuebinMa/agent-guard/pull/171) but is not yet a
published remedy. Until a verified repair release is available,
disable the Bash tool or use independently configured OS confinement of the
intended workspace. Upgrading only to 0.2.6 does not close the complete sed issue.

## Description delta only after release verification

Replace the preceding final paragraph with:

> Version 0.2.8 completes the reproduced sed destination checks with bounded
> parsing, conservative refusal of unmodeled scripts/options and permanent
> negative/positive local regressions. Upgrade the affected Agent Guard
> components to 0.2.8 or later. If upgrading is not possible, disable the Bash
> tool or independently confine it to the intended workspace with a real OS
> sandbox. The hook remains advisory, and this fix does not make it a hostile
> agent containment boundary.

At that point set all five packages' patched version to `0.2.8`, retaining
`<= 0.2.6` as affected. Check the repository advisory API response after writing;
do not infer a CVE assignment or ecosystem notification propagation from a
successful update alone.
