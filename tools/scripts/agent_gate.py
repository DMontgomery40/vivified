#!/usr/bin/env python3
"""
Agent Gate: run local CI parity and (optionally) block until PR merges with green checks.

Usage:
  - Ensure local parity passes:
      python tools/scripts/agent_gate.py --local-only
  - Gate on a PR merge (requires env: GITHUB_TOKEN, REPO=owner/repo, PR_NUMBER):
      python tools/scripts/agent_gate.py --wait-merge

Notes:
  - Does not create PRs; use `gh pr create` or GitHub UI.
  - Uses GitHub REST API if credentials are present; otherwise, it exits after local checks.
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
from typing import Optional

try:
    import requests  # type: ignore
except Exception:  # pragma: no cover
    requests = None  # type: ignore


def run_local_checks() -> None:
    here = os.path.dirname(os.path.abspath(__file__))
    root = os.path.abspath(os.path.join(here, "..", ".."))
    env = os.environ.copy()
    print("[gate] Running make ci-local …")
    subprocess.run(["make", "ci-local"], cwd=root, check=True, env=env)
    # UI builds are optional locally; run if node is available
    try:
        subprocess.run(["node", "-v"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        print("[gate] Running make ui-ci-local …")
        subprocess.run(["make", "ui-ci-local"], cwd=root, check=True, env=env)
    except Exception:
        print("[gate] Skipping UI build (node not found).")


def get_env(name: str) -> Optional[str]:
    val = os.environ.get(name)
    return val.strip() if isinstance(val, str) else None


def wait_for_merge() -> int:
    if requests is None:
        print("[gate] requests not available; cannot poll GitHub. Exiting after local checks.")
        return 0

    token = get_env("GITHUB_TOKEN")
    repo = get_env("REPO")  # format: owner/repo
    pr_number = get_env("PR_NUMBER")
    if not (token and repo and pr_number):
        print("[gate] Missing env: GITHUB_TOKEN, REPO, PR_NUMBER. Exiting after local checks.")
        return 0

    session = requests.Session()
    session.headers.update({
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    })

    def pr_url() -> str:
        return f"https://api.github.com/repos/{repo}/pulls/{pr_number}"

    def checks_url(sha: str) -> str:
        return f"https://api.github.com/repos/{repo}/commits/{sha}/status"

    deadline = time.time() + 60 * 60  # 60 minutes
    head_sha = None

    print(f"[gate] Polling PR #{pr_number} in {repo} for green checks and merge …")
    while time.time() < deadline:
        r = session.get(pr_url(), timeout=30)
        if r.status_code >= 400:
            print(f"[gate] PR query failed: {r.status_code} {r.text}")
            time.sleep(10)
            continue
        data = r.json()
        merged = bool(data.get("merged"))
        head = data.get("head", {})
        head_sha = head.get("sha")
        if head_sha:
            cs = session.get(checks_url(head_sha), timeout=30)
            if cs.ok:
                state = cs.json().get("state")  # success | failure | pending
                print(f"[gate] checks state: {state} (sha={head_sha[:7]}) merged={merged}")
                if state == "failure":
                    print("[gate] checks failed; exiting non-zero.")
                    return 2
                if merged and state == "success":
                    print("[gate] PR merged with green checks. Done.")
                    return 0
            else:
                print(f"[gate] checks query failed: {cs.status_code} {cs.text}")
        time.sleep(10)

    print("[gate] timeout waiting for PR to merge.")
    return 3


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--local-only", action="store_true", help="Run local checks only and exit.")
    parser.add_argument("--wait-merge", action="store_true", help="After local checks, wait for PR to merge with green checks.")
    args = parser.parse_args()

    try:
        run_local_checks()
    except subprocess.CalledProcessError as e:
        return e.returncode

    if args.wait_merge:
        return wait_for_merge()

    return 0


if __name__ == "__main__":
    sys.exit(main())

