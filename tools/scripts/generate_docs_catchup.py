#!/usr/bin/env python3
"""
Catch-up generator for Vivified docs.

Runs the enhanced docs autopilot in full-scan mode to regenerate all docs
from the current repository state.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path


def main() -> int:
    repo_root = Path(__file__).resolve().parents[2]
    sys.path.insert(0, str(repo_root / "tools" / "scripts"))
    try:
        from docs_autopilot_enhanced import DocsAutopilotEnhanced  # type: ignore
    except Exception:
        # Fallback to path import if module name resolution differs
        import importlib.util

        spec = importlib.util.spec_from_file_location(
            "docs_autopilot_enhanced", str(repo_root / "tools" / "scripts" / "docs_autopilot_enhanced.py")
        )
        assert spec and spec.loader
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        DocsAutopilotEnhanced = getattr(mod, "DocsAutopilotEnhanced")

    output_dir = None  # write into docs/
    autopilot = DocsAutopilotEnhanced(repo_root)
    autopilot.run(full_scan=True, output_dir=output_dir)
    print("✅ Docs catch-up complete")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

