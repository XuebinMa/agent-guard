# Broker-first: one Linux Docker reference

Status: the launcher and configuration tests are implemented. The fixed
synthetic native Linux container/HTTPS workflow has
[passed actual CI acceptance](../../docs/security-evidence/2026-10-06/native-linux/README.md)
at head `5f8e714`; unit/configuration tests alone are **not isolation proof**.
Do not call a successful configuration check an isolation certificate.
This is the small P3 reference in the
[development plan](../../docs/plans/broker-first-development-plan.md), not a new
sandbox backend, daemon, RPC, or privileged agent tool.

## Fixed profile and prerequisites

Use an existing native Linux Docker Engine, its local root-owned
`/var/run/docker.sock`, the builtin seccomp profile and `runc`. The launcher
does not install/start a daemon, build/pull an image, approve a request, or
publish anything. Docker Desktop, remote daemons, rootless/userns-remapped
daemon layouts and alternate runtimes are refused by this first profile; they
are not described as insecure, just not implemented or accepted here.

The approving human uses a dedicated non-root host account with access to the
trusted Docker Engine. Docker access is powerful host authority: **never give
it to the agent**, inside or outside a container. Protect that account, its
processes, terminal, Python interpreter, launcher, binaries and parent paths.
The launcher is ordinary host code, not setuid or a command exposed via MCP.

The host account must not be UID 65532. This is only one precaution, not a claim
that a different UID alone protects credentials. The boundary also relies on
private mount/PID namespaces, missing authentication/management sockets,
capability removal, host filesystem permissions and absence of privileged host
handlers. Trusted host administrators can still change Docker configuration.

The reviewed local image must contain the **entire** agent runtime, file tools,
MCP servers and hooks. It must contain no credentials accepted by the protected
Git destination, secret material, sensitive default environment or implicit
volumes. Pin its exact local `sha256:…` image ID. Metadata checks do not establish
that its layers contain no secrets; image review is a deployment prerequisite.
Do not proxy an in-container tool to a credential-bearing host handler.

| Asset/path | Agent access | Trusted host access |
| --- | --- | --- |
| Fresh `development/workspace` | Only host bind mount; read/write | Reads hostile repository after stopping container |
| Image and temporary `/tmp`, `/home/agent` | Agent programs; temporary writes | Image selected/reviewed by operator |
| `control/broker.gitconfig`, `credentials/`, `policy.yaml` | Not mounted; no helper/socket forwarded | Private operator-owned configuration |
| `control/home`, broker binary, fixed `/usr/bin` PATH | No host mount, host process or invocation handler | Protected executable/configuration sources |
| `control/grants`, `records`, ledger | Not mounted or accepted as agent input | Private one-use authorizations and unsigned records |
| Docker socket, approving host terminal | Not mounted/attached; no host API | Operator only |
| Network | Ordinary private bridge with egress | No broker service/listening API provided |

Container egress is deliberately not disabled. A reachable Git service still
requires credentials the agent lacks. This does not prevent general data
exfiltration, insecure host services, kernel/runtime bugs or credentials supplied
through an unregistered tool. No other container/user may access the workspace
or broker assets outside this workflow. All tool paths must remain in the
reviewed image; introducing a host handler requires fresh acceptance.

## Host setup

Provision `/srv/agent-guard-host` and `control/` as operator-owned mode `0700`,
under protected parents. Install the trusted launcher/interpreter and exact
tested broker binary outside the development workspace, without group/world
write permission or replaceable parent paths. `/usr/bin/git` and `/usr/bin` must
be host-protected. Do not run this launcher from agent-writable repository code.

Copy [profile.example.json](profile.example.json) to
`/srv/agent-guard-host/control/deployment.json`, owned by the operator, mode
`0600`. The zero image ID and `.invalid` URL are placeholders; replace them with
the reviewed **already-installed** image and one exact canonical HTTPS Git
destination. No credentials belong in this JSON. Unknown/duplicate keys are
errors, not Docker options passed through. The fixed profile has no environment,
mount, privilege, arbitrary CLI argument or `--yes` option.

Place private mode-`0600` ordinary files at `control/policy.yaml` and
`control/broker.gitconfig`. Configure policy/audit paths under protected state;
never reference agent-owned policy files. The Git config is validated again by
the existing broker: use destination-scoped HTTPS authentication, keep path
context, and do not disable certificate verification. One example for an
operator-managed credential file is:

```gitconfig
[credential "https://example.invalid/team/repo.git"]
    helper = store --file /srv/agent-guard-host/control/credentials/git-credentials
```

That file must be private operator-owned state, not imported into the image or
workspace. Provision the credential using the operator's normal secure method;
the reference does not generate tokens or manage secrets. Custom authentication
helpers, CA files and their executable/configuration dependencies are part of
the host trusted computing base, and must remain outside agent control.

From the protected host installation, initialize **once**:

```bash
/usr/bin/python3 /opt/agent-guard/deploy/broker-first/launch.py init-workspace \
  --config /srv/agent-guard-host/control/deployment.json
```

Initialization creates private host HOME, grants, records, credentials, scratch
and empty Docker CLI configuration directories. It creates a new, empty
`development/workspace`, records its device/inode in private state, and never
imports a pre-existing repository. The workspace has mode `01777` so the fixed
non-root container identity can develop there; its parent is mode `0700` and is
not mounted. No arbitrary host directory can be substituted later.
The container receives one fixed Git `safe.directory=/workspace` entry to permit
normal Git development in that host-owned directory. This does not trust
repository content in the broker; the host environment never carries that entry.

This is a fresh-directory bind mount, **not** a dedicated filesystem or a repair
for general shared-hard-link finding R2. Do not populate it using hard links or
mount pre-existing sensitive shared inodes. Repository content remains hostile
data, and the broker's isolated snapshot checks still apply. Windows ambient
handle finding R1 also remains open and outside this Linux reference.

## Develop, then approve from a separate terminal

```bash
/usr/bin/python3 /opt/agent-guard/deploy/broker-first/launch.py check \
  --config /srv/agent-guard-host/control/deployment.json
/usr/bin/python3 /opt/agent-guard/deploy/broker-first/launch.py start \
  --config /srv/agent-guard-host/control/deployment.json
```

`start` creates a container with readonly rootfs, all capabilities dropped,
no-new-privileges, private namespaces, builtin seccomp, bounded memory/processes,
only the workspace bind and two bounded temporary filesystems. It inspects the
created container **before starting the agent**. Image entrypoint/CMD are
replaced with the fixed argument vector. Host environment and Docker CLI proxy
configuration are not inherited. No host terminal is attached.

Inside its environment the agent may initialize a normal Git repository, create
files, build/test and make commits. Its remote must equal the configured URL.
Agent-side model/API integration is not automatically enabled; never introduce
protected Git tokens to make a runtime usable. The first reference has no
pre-existing repository import, interactive attachment, host tool bridge or
host-managed automation interface.

Use a **separate trusted host terminal** that has not displayed raw agent logs:

```bash
mesg n
/usr/bin/python3 /opt/agent-guard/deploy/broker-first/launch.py push \
  --config /srv/agent-guard-host/control/deployment.json
```

The launcher refuses redirected/piped stdin, stdout or stderr, requires the
same operator-owned non-group/world-writable terminal device, validates the
profile, and stops the complete agent container. It checks that it stopped
before reading repository configuration, and refuses multiple/missing/different
push URLs. The container stays stopped on cancellation/error/success; restart
development explicitly with `start`.

It then executes only the fixed existing `agent-guard push` entry point with
protected policy/config/grants and a unique protected receipt path, without
`--yes`, a shell, agent-supplied approvals or local-file-remote mode. The existing
CLI shows the resolved URL/OID/ref and asks for confirmation; grant consumption,
lease and transaction revalidation remain broker responsibilities.

TTY checks are **necessary preconditions, not approver identity proof**. A
same-permission process controlling this host account or terminal defeats the
deployment assumptions. Merely calling `isatty()` cannot separate that process
from the human. The image/agent must not obtain this account, terminal, Docker
socket or privileged invocation path. An agent-generated “approved” value is
never trusted.

Receipts remain unsigned broker attempt records, persisted only when execution
reaches the existing CLI receipt stage. Early refusal/cancel/preview failure
does not create one; neither a record nor `guard-verify doctor` proves isolation.

## Checks, evidence and known limits

```bash
python3 -m unittest discover -s scripts/tests -p test_broker_first_deployment.py -v
```

Tests exercise bad/unknown config, permission/link checks, workspace replacement,
fixed argv/environment, daemon/image metadata, terminal devices and local Git
config reading using public fixtures. Orchestration tests substitute only the
daemon/terminal/exec boundary to lock refusal ordering; they do not constitute
actual container acceptance. They do not contact a daemon, run a negative Shell
command or access real credentials. `check` reports `configuration_check: passed` separately from
`isolation_acceptance: not_run`. Failed capability/permission/metadata checks do
not fall back to advisory execution. Partial initialization is left visible;
inspect owned paths manually before recovery rather than reusing an old volume.

The required native Linux job runs the plan's authenticated HTTPS fixture,
positive workspace write/build/commit and host-approved push, plus independent
remote-state and denied credential/resource controls. A container unable to
reach the service is not a passing credential-isolation result. Do not mark P4
complete from these unit tests, or use Mac/Docker Desktop compilation as that
proof. The actual passing run and its complementary I1–I8 broker suites are
preserved in the evidence linked above; new heads require fresh CI.

The fixed scratch/resource sizes are reference defaults, not measured capacity
for a large repository. Workspace disk quotas, operational benchmarking,
user workflow and bounded broker/network execution remain separate work. The
launcher does not inspect every host service or prove absence of all shared
inodes; safe host administration remains a prerequisite.

## Why Docker and these mechanisms

Docker Engine fits the planned native Ubuntu acceptance environment and reuses
an existing runtime; no second runtime or daemon is introduced. Official
[run options](https://docs.docker.com/reference/cli/docker/container/run/)
document readonly rootfs, capabilities, seccomp and no-new-privileges.
[Bind-mount documentation](https://docs.docker.com/engine/storage/bind-mounts/)
explains why the source mount must be chosen by the trusted host.
[Engine security](https://docs.docker.com/engine/security/)
explains why daemon access belongs only to trusted users.
[User-namespace documentation](https://docs.docker.com/engine/security/userns-remap/)
documents host mount/ownership complexity; supporting remapping is intentionally
deferred rather than guessed. These references support configuration choices,
not a certification of this implementation.
