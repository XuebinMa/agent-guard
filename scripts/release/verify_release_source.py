#!/usr/bin/env python3
"""Prove a release tag points at tested `main` before publishing anything."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any


class VerificationError(RuntimeError):
    pass


def git_output(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=repo,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "unknown git error"
        raise VerificationError(f"git {' '.join(args)} failed: {detail}")
    return result.stdout.strip()


def verify_git_source(repo: Path, expected_sha: str) -> str:
    head = git_output(repo, "rev-parse", "HEAD")
    main = git_output(repo, "rev-parse", "refs/remotes/origin/main")
    if head != expected_sha:
        raise VerificationError(
            f"checked-out commit {head} does not equal GITHUB_SHA {expected_sha}"
        )
    if head != main:
        raise VerificationError(
            f"release commit {head} is not current origin/main {main}"
        )
    return head


def parse_workflow_runs(payload: bytes) -> list[dict[str, Any]]:
    try:
        document = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise VerificationError(f"GitHub Actions API returned invalid JSON: {error}") from error
    if not isinstance(document, dict) or not isinstance(document.get("workflow_runs"), list):
        raise VerificationError("GitHub Actions API response is missing workflow_runs")
    if not all(isinstance(run, dict) for run in document["workflow_runs"]):
        raise VerificationError("GitHub Actions API returned a malformed workflow run")
    return document["workflow_runs"]


def require_successful_main_ci(runs: list[dict[str, Any]], expected_sha: str) -> None:
    matching = [
        run
        for run in runs
        if run.get("head_sha") == expected_sha
        and run.get("head_branch") == "main"
        and run.get("event") == "push"
        and run.get("status") == "completed"
    ]
    if any(run.get("conclusion") == "success" for run in matching):
        return
    if matching:
        conclusions = sorted({str(run.get("conclusion")) for run in matching})
        raise VerificationError(
            f"main push CI for {expected_sha} is not successful: {', '.join(conclusions)}"
        )
    raise VerificationError(
        f"no completed main push CI run exists for release commit {expected_sha}"
    )


def fetch_workflow_runs(
    *, api_url: str, repository: str, token: str, expected_sha: str
) -> list[dict[str, Any]]:
    query = urllib.parse.urlencode(
        {
            "branch": "main",
            "event": "push",
            "status": "completed",
            "head_sha": expected_sha,
            "per_page": "100",
        }
    )
    url = f"{api_url.rstrip('/')}/repos/{repository}/actions/workflows/ci.yml/runs?{query}"
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "agent-guard-release-source-verifier",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            if response.status != 200:
                raise VerificationError(
                    f"GitHub Actions API returned HTTP {response.status}"
                )
            payload = response.read(2 * 1024 * 1024 + 1)
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        raise VerificationError(f"GitHub Actions API query failed: {error}") from error
    if len(payload) > 2 * 1024 * 1024:
        raise VerificationError("GitHub Actions API response exceeded 2 MiB")
    return parse_workflow_runs(payload)


def main() -> int:
    repo = Path.cwd()
    expected_sha = os.environ.get("GITHUB_SHA", "")
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    token = os.environ.get("GITHUB_TOKEN", "")
    api_url = os.environ.get("GITHUB_API_URL", "https://api.github.com")
    if not expected_sha or not repository or not token:
        raise VerificationError(
            "GITHUB_SHA, GITHUB_REPOSITORY, and GITHUB_TOKEN are required"
        )
    release_sha = verify_git_source(repo, expected_sha)
    runs = fetch_workflow_runs(
        api_url=api_url,
        repository=repository,
        token=token,
        expected_sha=release_sha,
    )
    require_successful_main_ci(runs, release_sha)
    print(f"Release source verified: {release_sha} is tested origin/main.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except VerificationError as error:
        print(f"Release source verification failed: {error}", file=sys.stderr)
        raise SystemExit(1) from error
