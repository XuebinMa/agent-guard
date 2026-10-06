# Local authenticated Git fixtures

This directory tests the actual broker CLI against the installed
[Git HTTP backend](https://git-scm.com/docs/git-http-backend), over TLS. This host
suite binds only to `127.0.0.1`. Repositories, identities, certificates and authentication values
are temporary synthetic fixtures. No third-party service, user credential store
or real repository is contacted. Python's HTTP server is a test adapter, not a
production deployment component.

Build the current CLI, then run the required suite explicitly:

```bash
cargo build -p agent-guard-cli --locked
AGENT_GUARD_TEST_CLI="$PWD/target/debug/agent-guard" \
  python3 -m unittest discover -s tests/broker-first -v
```

The suite fails, rather than skips, if the CLI is not supplied. `git` and an
OpenSSL CLI supporting `-addext` are required. Network and subprocess operations
have finite deadlines. Authentication headers are not logged.

Current six-test coverage: an independently observable authenticated push, destination
scope refusal before connection, cancellation/EOF with no execution receipt,
and a reachable unauthenticated client that cannot change the remote ref.
The actual ref is checked independently of the broker receipt. Two robustness
locks cover incomplete TLS handshake cleanup and an observer failure that must
not be misreported as an absent ref.

Three additional fixture-bind unit tests lock the native-only extension:
`docker_bridge_address` must be a canonical RFC1918 IPv4 address observed on
the Linux host's `docker0` interface; the native driver must also check the
daemon's default bridge gateway. Public/wildcard/link-local/other-interface
addresses are refused. The host suite uses mocked metadata for these checks,
not a real Docker daemon, and still binds only loopback.

These are **host composition tests**, not container-isolation acceptance. Running
the unauthenticated client on the same host does not prove an agent cannot find
host credentials. P4 still requires the native Linux container test and every
I1–I8 deployment invariant in the
[development plan](../../docs/plans/broker-first-development-plan.md).
