#!/usr/bin/env python3
"""
Docs smoke script (non-pytest) for mkdocs branch hygiene.
Runs the enhanced generator in offline scaffold mode and checks for
Material features in the output.
"""
from __future__ import annotations

import os
from pathlib import Path
import subprocess


def main() -> int:
    repo_root = Path(__file__).resolve().parents[2]
    env = dict(os.environ)
    env.pop("OPENAI_API_KEY", None)
    # Run generator offline
    subprocess.run([
        "python",
        str(repo_root / "tools" / "scripts" / "docs_autopilot_enhanced.py"),
        "--full-scan",
    ], check=True, env=env, cwd=str(repo_root))

    text = (repo_root / "docs" / "core" / "overview.md").read_text(encoding="utf-8")
    combined = text + "\n" + (repo_root / "docs" / "sdk" / "overview.md").read_text(encoding="utf-8")
    ok = all(s in combined for s in ["!!! warning", "```mermaid", "=== \"Python\""])
    print("Material features present" if ok else "Material features missing")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
