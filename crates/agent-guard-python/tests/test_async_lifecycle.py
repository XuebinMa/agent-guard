"""Real-binding regressions for asynchronous callback and execution lifecycles."""

import asyncio
import json
import os
import sys
import threading
import time

import pytest

from agent_guard import Guard, wrap_openai_tool
from agent_guard.adapters import dispatch_via_run_async


def audit_guard(audit_path):
    return Guard.from_yaml(f"""
version: 1
default_mode: full_access
tools:
  custom:
    calc: {{}}
audit:
  enabled: true
  output: file
  file_path: {json.dumps(str(audit_path))}
anomaly:
  enabled: false
""")


def reported_events(audit_path):
    if not audit_path.exists():
        return []
    return [
        event for event in map(json.loads, audit_path.read_text().splitlines())
        if event["type"] == "execution_reported"
    ]


async def wait_for_reported_events(audit_path, *, timeout=2):
    # Reporting enqueues the JSONL record; persistence is handled by the writer.
    deadline = time.monotonic() + timeout
    while True:
        reports = reported_events(audit_path)
        if reports:
            return reports
        remaining = deadline - time.monotonic()
        assert remaining > 0, "execution_reported was not persisted before the deadline"
        await asyncio.sleep(min(0.01, remaining))


@pytest.mark.skipif(os.name != "posix", reason="requires POSIX advisory file locks")
@pytest.mark.parametrize("fails", [False, True])
def test_completed_handoff_report_survives_delayed_file_visibility(tmp_path, fails):
    import fcntl

    audit_path = tmp_path / "audit.jsonl"
    with audit_path.open("a") as locked_file:
        fcntl.flock(locked_file, fcntl.LOCK_EX)
        guard = audit_guard(audit_path)

        async def action(value):
            if fails:
                raise ValueError("delayed audit callback failed")
            return value + 1

        async def scenario():
            wrapped = wrap_openai_tool(guard, action, tool="calc", mode="auto")
            if fails:
                with pytest.raises(ValueError, match="delayed audit callback failed"):
                    await asyncio.wait_for(wrapped(1), timeout=1)
            else:
                assert await asyncio.wait_for(wrapped(1), timeout=1) == 2
            assert reported_events(audit_path) == []

            waiter = asyncio.create_task(wait_for_reported_events(audit_path))
            try:
                await asyncio.sleep(0.03)
                assert not waiter.done(), "completion does not synchronously flush the audit file"
            finally:
                fcntl.flock(locked_file, fcntl.LOCK_UN)
            reports = await asyncio.wait_for(waiter, timeout=2)
            assert len(reports) == 1
            assert reports[0]["exit_code"] == (1 if fails else 0)

        asyncio.run(scenario())


def test_report_waiter_rejects_a_missing_report_within_its_budget(tmp_path):
    async def scenario():
        started = time.monotonic()
        with pytest.raises(AssertionError, match="execution_reported"):
            await wait_for_reported_events(tmp_path / "absent.jsonl", timeout=0.03)
        assert time.monotonic() - started < 0.5

    asyncio.run(scenario())


def test_report_waiter_rejects_malformed_json_instead_of_retrying(tmp_path):
    audit_path = tmp_path / "malformed.jsonl"
    audit_path.write_text("not JSON\n")

    async def scenario():
        with pytest.raises(json.JSONDecodeError):
            await wait_for_reported_events(audit_path, timeout=0.03)

    asyncio.run(scenario())


@pytest.mark.parametrize("returns_awaitable", [False, True])
@pytest.mark.parametrize("fails", [False, True])
def test_openai_async_handoff_reports_the_awaited_result(
    tmp_path, returns_awaitable, fails
):
    audit_path = tmp_path / "audit.jsonl"
    guard = audit_guard(audit_path)

    async def scenario():
        entered = asyncio.Event()
        release = asyncio.Event()

        async def action(value):
            entered.set()
            await release.wait()
            if fails:
                raise ValueError("asynchronous callback failed")
            return value + 1

        handler = (lambda value: action(value)) if returns_awaitable else action
        wrapped = wrap_openai_tool(guard, handler, tool="calc", mode="auto")
        task = asyncio.create_task(wrapped(1))
        try:
            await asyncio.wait_for(entered.wait(), timeout=2)
            assert reported_events(audit_path) == [], (
                "creating an awaitable is not completion of the host action"
            )
        finally:
            release.set()
            if fails:
                with pytest.raises(ValueError, match="asynchronous callback failed"):
                    await task
            else:
                assert await task == 2

        reports = await wait_for_reported_events(audit_path)
        assert len(reports) == 1
        assert reports[0]["exit_code"] == (1 if fails else 0)

    asyncio.run(scenario())


@pytest.mark.parametrize("fails", [False, True])
def test_cancelled_thread_handoff_reports_only_after_the_worker_finishes(tmp_path, fails):
    audit_path = tmp_path / "audit.jsonl"
    guard = audit_guard(audit_path)
    entered = threading.Event()
    release = threading.Event()
    finished = threading.Event()
    results = []

    def action():
        entered.set()
        assert release.wait(timeout=2)
        try:
            if fails:
                raise ValueError("worker callback failed")
            results.append("completed")
            return "completed"
        finally:
            finished.set()

    async def scenario():
        task = asyncio.create_task(dispatch_via_run_async(
            guard,
            tool="calc",
            payload="{}",
            guard_options={},
            handler=action,
        ))
        try:
            assert await asyncio.to_thread(entered.wait, 2)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            assert reported_events(audit_path) == [], (
                "cancelling the awaiting task does not stop a running worker"
            )
        finally:
            release.set()
            assert await asyncio.to_thread(finished.wait, 2)

        reports = await wait_for_reported_events(audit_path)
        assert len(reports) == 1
        assert reports[0]["exit_code"] == (1 if fails else 0)
        assert results == ([] if fails else ["completed"])

    asyncio.run(scenario())


@pytest.mark.skipif(os.name == "nt", reason="the harmless sleep command is POSIX-only")
@pytest.mark.parametrize("method_name", ["execute", "run"])
def test_native_execution_releases_the_gil_for_event_loop_progress(method_name):
    if hasattr(sys, "_is_gil_enabled") and not sys._is_gil_enabled():
        pytest.skip("this runtime has no global interpreter lock")
    guard = Guard.from_yaml("""
version: 1
default_mode: full_access
audit:
  enabled: false
anomaly:
  enabled: false
""")
    started = threading.Event()
    finished = threading.Event()

    def execute():
        started.set()
        try:
            return getattr(guard, method_name)(
                "bash", '{"command":"sleep 0.25"}', backend="none"
            )
        finally:
            finished.set()

    async def scenario():
        task = asyncio.create_task(asyncio.to_thread(execute))
        assert await asyncio.to_thread(started.wait, 2)
        ticks = 0
        deadline = time.monotonic() + 2
        while not finished.is_set() and time.monotonic() < deadline:
            await asyncio.sleep(0.01)
            if not finished.is_set():
                ticks += 1
        result = await task
        assert result.output.exit_code == 0
        assert ticks >= 3, "moving native execution to a thread must free the GIL"

    asyncio.run(scenario())
