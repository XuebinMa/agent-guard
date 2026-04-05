"""
Python binding tests for agent-guard.

Run with (after `maturin develop`):
    pytest crates/agent-guard-python/tests/
"""

import json
import pytest

import agent_guard

# ── Fixtures ──────────────────────────────────────────────────────────────────

POLICY = """
version: 1
default_mode: workspace_write

tools:
  bash:
    deny:
      - prefix: "rm -rf"
      - prefix: "purge"
    ask:
      - prefix: "git push"
    allow:
      - prefix: "ls"

  read_file:
    deny_paths:
      - "/etc/**"
      - "**/.ssh/**"

  http_request:
    deny:
      - prefix: "http://169.254.169.254"
"""


@pytest.fixture(scope="module")
def guard():
    return agent_guard.Guard.from_yaml(POLICY)


# ── Basic construction ────────────────────────────────────────────────────────

def test_from_yaml_succeeds():
    g = agent_guard.Guard.from_yaml(POLICY)
    assert repr(g) == "Guard(<policy loaded>)"


def test_from_yaml_invalid_raises_guard_error():
    with pytest.raises(agent_guard.GuardError, match="policy"):
        agent_guard.Guard.from_yaml("version: 99\n")


def test_from_yaml_file_missing_raises(tmp_path):
    with pytest.raises(agent_guard.GuardError):
        agent_guard.Guard.from_yaml_file(str(tmp_path / "nonexistent.yaml"))


def test_version_attribute():
    assert isinstance(agent_guard.__version__, str)
    parts = agent_guard.__version__.split(".")
    assert len(parts) == 3


# ── Decision: allow ───────────────────────────────────────────────────────────

def test_allow_safe_bash(guard):
    d = guard.check("bash", "ls -la", trust_level="trusted")
    assert d.is_allow()
    assert d.outcome == "allow"
    assert d.code is None
    assert d.message is None
    assert d.matched_rule is None


# ── Decision: deny ────────────────────────────────────────────────────────────

def test_deny_rm_rf(guard):
    d = guard.check("bash", "rm -rf ./build", trust_level="trusted")
    assert d.is_deny()
    assert d.outcome == "deny"
    assert d.code is not None
    assert d.message is not None


def test_deny_has_matched_rule(guard):
    d = guard.check("bash", "purge --all", trust_level="trusted")
    assert d.is_deny()
    assert d.matched_rule is not None
    assert "bash" in d.matched_rule


def test_deny_read_etc_passwd(guard):
    payload = json.dumps({"path": "/etc/passwd"})
    d = guard.check("read_file", payload, trust_level="trusted")
    assert d.is_deny()


def test_deny_metadata_ssrf(guard):
    payload = json.dumps({"url": "http://169.254.169.254/latest"})
    d = guard.check("http_request", payload, trust_level="trusted")
    assert d.is_deny()


# ── Decision: ask_user ────────────────────────────────────────────────────────

def test_ask_user_git_push(guard):
    d = guard.check("bash", "git push origin main", trust_level="trusted")
    assert d.is_ask()
    assert d.outcome == "ask_user"
    assert d.ask_prompt is not None
    assert len(d.ask_prompt) > 0


# ── Invalid payload ───────────────────────────────────────────────────────────

def test_invalid_json_payload_denied(guard):
    # read_file requires JSON {"path":"..."}; a bare path string is rejected.
    d = guard.check("read_file", "/etc/passwd", trust_level="trusted")
    assert d.is_deny()
    assert "InvalidPayload" in (d.code or "")


def test_missing_field_denied(guard):
    payload = json.dumps({"file": "/etc/passwd"})  # "file" instead of "path"
    d = guard.check("read_file", payload, trust_level="trusted")
    assert d.is_deny()
    assert "MissingPayloadField" in (d.code or "")


# ── Trust level ───────────────────────────────────────────────────────────────

def test_untrusted_bash_write_denied(guard):
    # Untrusted → read_only → touch is a write command → Deny
    d = guard.check("bash", "touch /tmp/x", trust_level="untrusted")
    assert d.is_deny()


def test_invalid_trust_level_raises(guard):
    with pytest.raises(agent_guard.GuardError, match="trust_level"):
        guard.check("bash", "ls", trust_level="superuser")


# ── Invalid tool ──────────────────────────────────────────────────────────────

def test_invalid_tool_raises(guard):
    with pytest.raises(agent_guard.GuardError, match="invalid tool id"):
        guard.check("rm rf", "ls", trust_level="trusted")  # space in tool name


# ── Custom tool ───────────────────────────────────────────────────────────────

def test_custom_tool_default_allow(guard):
    # No policy for "acme.query" → default_mode workspace_write → Allow
    d = guard.check("acme.query", '{"sql":"SELECT 1"}', trust_level="trusted")
    assert d.is_allow()


# ── Decision predicates are mutually exclusive ────────────────────────────────

def test_decision_predicates_allow(guard):
    d = guard.check("bash", "ls", trust_level="trusted")
    assert d.is_allow() and not d.is_deny() and not d.is_ask()


def test_decision_predicates_deny(guard):
    d = guard.check("bash", "rm -rf ./x", trust_level="trusted")
    assert d.is_deny() and not d.is_allow() and not d.is_ask()


def test_decision_predicates_ask(guard):
    d = guard.check("bash", "git push origin main", trust_level="trusted")
    assert d.is_ask() and not d.is_allow() and not d.is_deny()


# ── repr ──────────────────────────────────────────────────────────────────────

def test_decision_repr_contains_outcome(guard):
    d = guard.check("bash", "ls", trust_level="trusted")
    r = repr(d)
    assert "allow" in r
