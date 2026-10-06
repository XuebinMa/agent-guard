# Native broker-first acceptance

This is a required **native Linux Docker Engine** fixture, not a second deployment
launcher. It invokes [the fixed deployment profile](../../../deploy/broker-first/README.md)
and the newly built broker CLI. No daemon installation/start, remote Docker
context, Desktop VM, rootless/userns workaround, host networking, disabled network,
privileged agent or extra mount is supplied by this driver. Missing prerequisites
fail the job; they never produce a successful skip.

## Trusted test setup

Use a disposable Ubuntu runner whose non-root operator controls the existing
rootful local Docker Engine. That Docker authority stays outside the agent. The
runner must contain no production credentials, SSH agent or other agent workloads.
Its Git, Docker, Python, TLS tools, fixed launcher, Dockerfile and built CLI belong
to the trusted setup. Review the image inputs; this fixture does not scan an image
for hidden secrets. Native Linux is not available on the development Mac; the
dedicated job actually passed for head `5f8e714` in
[run 37524417236](https://github.com/XuebinMa/agent-guard/actions/runs/37524417236).
[Preserved evidence](../../../docs/security-evidence/2026-10-06/native-linux/README.md)
includes the real container result and complementary broker/CLI logs, not
substituted local metadata tests. Later heads need their own run.

CI must supply an approved digest-pinned Ubuntu base, build this directory as the
context, and retain the resulting exact local image ID. `BASE_IMAGE` deliberately
has no default mutable tag. The image contains Python, Git and a C compiler plus
only the fixed synthetic agent workload. It does **not** contain the broker,
credentials, host configuration or implicit volumes. The frozen profile overrides
the image's allowed environment and checks the real container before starting it.

```sh
docker build --build-arg BASE_IMAGE=ubuntu@sha256:<reviewed-real-digest> \
  --tag agent-guard-native-fixture tests/broker-first/native
docker image inspect --format '{{.Id}}' agent-guard-native-fixture
python3 tests/broker-first/native/acceptance.py \
  --image sha256:<actual-local-image-id> \
  --broker /absolute/fresh-build/agent-guard \
  --evidence /absolute/private-artifacts/native-acceptance.json
```

The placeholders are not executable values. The dedicated workflow must resolve
and record real pins; this document makes no assertion that a particular digest
exists. The output evidence file is exclusive, mode 0600 and outside the temporary
workspace; do not reuse an old evidence file for a fresh run.

The official [Ubuntu tag metadata](https://hub.docker.com/v2/repositories/library/ubuntu/tags/24.04)
was checked on 2026-10-06: its multi-platform OCI index was
`sha256:534baea6a22c03a63003dbc8dbe78fe34bc0d7e595d9a9dc9834884ff530eb55`
(Linux/amd64 child manifest
`sha256:f610ab94648195aa356059f5b41d6085c9d4d903c072430cdd1af7bdb646106b`).
That is a verified base pin, not a reproducible-build claim: package installation
still uses the Ubuntu repositories during trusted CI image setup, and the final
image ID plus broker binary SHA-256 and checkout SHA are recorded after the job.

## Actual network and authority checks

The agent remains on the production profile's `bridge` network. The driver obtains
the actual default bridge's RFC1918 IPv4 gateway from `docker network inspect`.
The shared TLS fixture additionally checks that exact address belongs to the
local Linux `docker0` interface, and binds **only that interface address**. The
certificate SAN and approved URL use the same IP and ephemeral port. Nothing
listens on all interfaces, uses a public address, or routes through a broker RPC.

The default bridge permits ordinary connectivity; it is not an egress firewall.
This fixture uses only its private synthetic endpoint. Docker's [bridge
documentation](https://docs.docker.com/engine/network/drivers/bridge/) describes
the network model; the profile intentionally supports just one topology and
does not claim to isolate unrelated workloads on the same bridge.

Only a public CA is copied into `/workspace`. A fresh synthetic authorization
header stays in the host-only, URL-scoped broker config. Its value, the TLS key,
config contents, request headers and raw PTY transcript never enter artifacts.

The actual container workload:

- creates a new ordinary Git repository and harmless commit, compiles a tiny C
  program and executes it under the writable workspace (not the `noexec` tmpfs);
- verifies the service certificate and receives HTTP 401, then tries a normal Git
  push without authorization; the host independently observes no ref change and
  only unauthenticated service events;
- checks that the named synthetic host config/home/grant/record resources cannot
  be opened, their authority directories are absent, the Docker socket cannot be
  connected, the actual host-only CLI cannot be executed, and no host terminal is
  attached; an agent-written workspace record remains only data;
- stays alive until the real host launcher stops the **whole container**, before
  broker preview or authorization. A naturally exited process is not accepted as
  evidence of requester quiescence.

Its bounded report is a probe result from this fixed, reviewed fixture image, not
an attestation supplied by an arbitrary hostile agent. The host independently
checks the real Docker profile, service authentication events and bare remote
ref; none of the product's decisions rely on accepting an agent's report.

The actual host workflow rejects `y` supplied through a pipe **before** container
stop or service access. Separate caller-owned mode-0600 PTYs then exercise cancel,
EOF, and approval through the existing broker's actual prompt. Cancellation/EOF
leave the remote unchanged and create no execution receipt. Approval changes
exactly `refs/heads/main` to the observed candidate OID; the independently read
bare-repository ref agrees with the receipt URL/OID and consumed grant ID.

PTY automation represents the test's trusted host caller. It does not establish a
human approver's identity, authenticate a real operator or complete the separate
P5 developer workflow acceptance. Host permissions remain prerequisites.

## Evidence map and limits

| Invariant | Evidence in this driver | Required complementary broker suite |
| --- | --- | --- |
| I1 | No host entry through agent file/CLI/socket/pipe | `authorization_boundary`: actual execution API refuses missing/expired/inconsistent/consumed records before any observed loopback contact; valid local transaction updates once, replay refuses. `grant` adds concurrent-spender/store checks. |
| I2 | Identical approved URL/OID across native workflow | `drift`, `security_boundary`, `execute` integration targets |
| I3 | Original repo remains hostile input to existing broker | `security_boundary` integration target |
| I4 | Agent has no auth; scoped host auth succeeds | `git::credentials`, `git::command::tests::sanitized_git_does_not_forward_a_scoped_header_to_a_redirect_target`, `security_boundary` scope tests |
| I5 | Verified TLS 401, failed direct push, unchanged actual ref | Actual native container job (cannot be replaced by metadata/unit tests) |
| I6 | Build/write/commit and named inaccessible host resources/socket | Actual native container job |
| I7 | Successful receipt + consumed grant + exact independent remote ref | `receipt`, `security_boundary` refusal/stale-lease tests |
| I8 | Agent entry absence; pipe denied; real PTY cancel/EOF/approve | Actual native job plus execution authorization tests |

The dedicated job must run the mandatory fresh-head broker suites as well as this
driver. The table does not claim every negative invariant is supplied by this
single workload. `test_driver.py` validates bounded evidence and rejects false
network/identity successes without Docker; it is only a driver unit test:

```sh
python3 -m unittest discover -s tests/broker-first/native -p 'test_*.py' -v
```

The five `authorization_boundary` tests use no credential helper, real secret,
or TLS payload: a positively reachable loopback listener counts any connection
and closes it immediately. This is direct execution ordering coverage, not a
claim of checking arbitrary authentication programs. Source inspection locates
the claim before any snapshot/Git/config operation; existing scoped-helper and
redirect tests supply the authentication-specific controls.

Every subprocess, connection, PTY and agent idle interval is bounded. Cleanup
checks the exact image, profile label, command, workspace bind and container ID;
only that synthetic container is stopped/removed. The fixed agent removes its own
two fixture trees before host cleanup, avoiding an unprivileged host pretending
it can remove UID-65532-owned directories. Failure retains a temporary synthetic
tree and makes the job fail; no global prune or unrelated resource is touched.

This does not close **R1 Windows ambient handles** or **R2 shared hard links**.
A fresh private-parent workspace is not equivalent to a dedicated filesystem.
There is no existing-repository import, linked-worktree support, partial clone,
general sandbox RPC, signed receipt/key lifecycle, daemon or plugin adapter here.
