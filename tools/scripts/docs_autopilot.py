#!/usr/bin/env python3
"""
Lightweight Docs Autopilot (plan mode)

Generates a simple change plan based on the last commit diff. This is a
placeholder integration point for a fuller Docs-Autopilot tool.

Output: docs/_autopilot/plan.md
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from datetime import datetime


def git_diff_names() -> list[str]:
    try:
        out = subprocess.check_output(["git", "diff", "--name-only", "HEAD~1..HEAD"]).decode()
        return [line.strip() for line in out.splitlines() if line.strip()]
    except Exception:
        return []


def categorize(files: list[str]) -> dict[str, list[str]]:
    cats: dict[str, list[str]] = {
        "core": [],
        "plugins": [],
        "sdk": [],
        "docs": [],
        "other": [],
    }
    for f in files:
        if f.startswith("docs/") or f == "mkdocs.yml":
            cats["docs"].append(f)
        elif f.startswith("core/"):
            cats["core"].append(f)
        elif f.startswith("plugins/"):
            cats["plugins"].append(f)
        elif f.startswith("sdk/"):
            cats["sdk"].append(f)
        else:
            cats["other"].append(f)
    return cats


def generate_plan(cats: dict[str, list[str]]) -> str:
    ts = datetime.utcnow().isoformat()
    lines = ["# Docs Autopilot Plan", "", f"Generated: {ts}", ""]
    if any(cats.values()):
        lines += ["## Changes detected", ""]
        for k, v in cats.items():
            if not v:
                continue
            lines.append(f"- {k}: {len(v)} file(s)")
        lines.append("")

    suggestions = []
    if cats["core"]:
        suggestions.append("- Update Core overview and API references if endpoints or models changed.")
    if cats["plugins"]:
        suggestions.append("- Update Plugins overview or specific plugin docs for behavior/config changes.")
    if cats["sdk"]:
        suggestions.append("- Update SDK usage examples and version compatibility notes.")
    if cats["other"] and not cats["docs"]:
        suggestions.append("- Consider adding release notes or changelog entries.")

    if suggestions:
        lines += ["## Suggested documentation updates", "", *suggestions, ""]
    else:
        lines += ["No documentation updates suggested.", ""]

    return "\n".join(lines)


def main() -> None:
    files = git_diff_names()
    cats = categorize(files)
    plan = generate_plan(cats)
    out_dir = Path("docs/_autopilot")
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "plan.md").write_text(plan, encoding="utf-8")


if __name__ == "__main__":
    main()

