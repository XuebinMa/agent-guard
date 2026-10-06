# Actual native Linux acceptance evidence

[CI run 37524417236](https://github.com/XuebinMa/agent-guard/actions/runs/37524417236)
completed with **21/21 job conclusions success**, including job
`112477665693`, `Broker Native Linux Acceptance`. Its PR head is
`5f8e714933049352950648ae5e08c30b9ce8fa91`.

GitHub checked out the PR test merge
`427cf1d13efbe06bed85bb51901e3ec0bd6624d2`, whose parents are baseline
`e1a0a0a5fd956186e67e9c235451cbfa2fb4b260` and that exact head. This is
**not** a merge into main. The native artifact is named after the test merge,
not the PR head: `broker-first-native-427cf1d13efbe06bed85bb51901e3ec0bd6624d2`,
artifact ID `11440789982`. The first lookup using the head-based name found no
artifact; it was not treated as an acceptance failure or as proof of success.

Files below preserve the downloaded bytes (no production secrets, synthetic
authentication values, private TLS key, raw headers or terminal transcript):

| File | SHA-256 |
| --- | --- |
| [native.json](native.json) | `aeaef58e856b20447795acc4a88d65e45508f453d5205eff879a30897d6c250c` |
| [broker-tests.log.b64](broker-tests.log.b64), decoded bytes | `921431a336f18d3855c5cc75fc6e1e8e151ddfd0fd673056c521b65e7ccacdc8` |
| [cli-tests.log.b64](cli-tests.log.b64), decoded bytes | `9bc22274550c753721e4c02306d85854149fcae455f2030fb5b7bbee5d082a5c` |
| [image.id](image.id) | `94a645f2ac4b39a0c060c475b2b177e6f87f2958838f3fe1fa233e476341f938` |
| [ci-conclusions.json](ci-conclusions.json) | `437594ee9a675336cba68533f36b5d0d47ae54a61aeea1a7dc1222b588ef3052` |

The raw logs end in blank lines, which fail the repository's Git whitespace
gate when added directly. They are stored losslessly as Base64 instead of
changing their evidence bytes or relaxing that gate. For example, decode to
stdout with `base64 --decode < broker-tests.log.b64`; do not execute log text.
The listed log hashes bind the decoded bytes. The original downloadable CI
artifact remains the source, including its trailing newlines.

The later [copy-cost.json](copy-cost.json) is **local performance evidence**, not
part of that CI artifact or isolation proof. SHA-256:
`3471940db23420be2944bde7bd77d4b4351f8233debd167e516d58ad597fbb59`.
Its method, dirty-source bindings, warm-cache limits and failed first attempt
are recorded in the [operations guide](../../../guides/operations/broker-first-operations.md).

## What actually ran

Native Ubuntu Linux kernel `6.17.0-1022-azure`, Docker Engine `28.0.4`, host
operator UID 1001 and agent UID 65532. The real container had one workspace
mount, read-only root, all capabilities dropped, no-new-privileges, private
namespaces and builtin seccomp. Public fixture connectivity was verified:
the agent reached the same private-bridge TLS endpoint with HTTP 401; its
unauthorized ordinary push failed with exit 128 and did not update the ref.

The agent built and ran the harmless workspace program and committed normally.
The named host config/home/grant/record files, authority directories, Docker
socket, host CLI and terminal were unavailable. A workspace approval lookalike
was only data. A piped approval was refused before stop/network; separate host
PTYs tested cancel and EOF with no mutation or execution receipt. The launcher
stopped the live complete container before preview and approved execution.

The successful host push used the exact private TLS URL and candidate OID
`0411adb0a64eed61e0e292671c92f2a81216ee0c`. The independent bare ref and unsigned
receipt matched; the receipt's grant existed in the spent store. The report
contains `accepted: true` and `cleanup_complete: true`.

The mandatory broker tests in this same job ran **69 passed, zero failed,
zero ignored**: actual execution authorization (5), drift (5), execute (6),
grant (10), receipt (4), security boundary (14), transaction (11), unit (14).
CLI tests ran **23 passed, zero failed, zero ignored**. Together with the
native driver these exercise I1–I8; see the
[coverage map](../../../../tests/broker-first/native/README.md).

## Limits

This accepts the **fixed synthetic native Linux profile**, not a universal
container escape proof, arbitrary image certification, real-human feedback,
production performance/capacity or another platform. PTY approval is synthetic.
I1–I4/I7 negatives use the complementary broker suites, not invented native
driver assertions. R1 Windows inherited handles and R2 general shared hard
links remain open. No release, tag movement or advisory change follows from
this evidence. Every later implementation head needs its own CI.
