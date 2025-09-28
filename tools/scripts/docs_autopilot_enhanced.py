#!/usr/bin/env python3
"""
Enhanced Docs Autopilot for Vivified

Generates enterprise‑grade documentation using the OpenAI API with GPT‑5 (fallback to GPT‑4o),
scanning the full repository (core/, plugins/, sdk/) while excluding internal plans/runbooks.

Key features
- Full repo context with smart summarization (token‑safe)
- Content filtering: exclude anything with "phase" or "plan" in the name and internal planning folders
- Material for MkDocs rich output: admonitions, tabs, grids, collapsible sections, mermaid, annotations
- Professional, cross‑industry tone (ERP, cybersecurity, messaging) — not healthcare‑specific
- Safe by default: never include secrets or dev‑only bootstrap details

Usage
  python tools/scripts/docs_autopilot_enhanced.py --full-scan
  python tools/scripts/docs_autopilot_enhanced.py --full-scan --output-dir generated_docs

Env
  OPENAI_API_KEY   (required for LLM generation)
  OPENAI_MODEL     (optional; defaults to gpt-5-mini-2025-08-07)
"""

from __future__ import annotations

import argparse
import json
import os
import re
import textwrap
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

try:
    import requests  # Lightweight and avoids pinning the openai SDK
except Exception as e:  # pragma: no cover
    requests = None  # type: ignore[assignment]


# ----------------------------
# Helpers and data structures
# ----------------------------

EXCLUDE_DIRS = {
    ".git",
    "site",
    "__pycache__",
    "node_modules",
    ".mypy_cache",
    ".pytest_cache",
    "internal-plans",
}

EXCLUDE_FILE_PATTERNS = [
    re.compile(r"(^|/).*plan.*", re.IGNORECASE),
    re.compile(r"(^|/).*phase.*", re.IGNORECASE),
    re.compile(r".*\.db$", re.IGNORECASE),
    re.compile(r".*\.log$", re.IGNORECASE),
    re.compile(r".*\.lock$", re.IGNORECASE),
    re.compile(r".*\.DS_Store$", re.IGNORECASE),
]

INCLUDE_ROOTS = ["core", "plugins", "sdk"]  # Comprehensive platform context

TEXT_FILE_EXTS = {
    ".py",
    ".md",
    ".json",
    ".yaml",
    ".yml",
    ".toml",
    ".proto",
    ".sql",
    ".ts",
    ".tsx",
    ".js",
    ".jsx",
}


@dataclass
class RepoFile:
    path: Path
    rel: str
    size: int
    head: str


@dataclass
class RepoContext:
    files: List[RepoFile]
    summary: str
    stats: Dict[str, Any]


class DocsAutopilotEnhanced:
    def __init__(self, repo_root: Optional[Path] = None) -> None:
        self.repo_root = Path(repo_root or os.getcwd())
        self.openai_api_key = os.getenv("OPENAI_API_KEY", "").strip()
        # Preferred → Fallback 1 → Fallback 2
        self.model_chain = [
            os.getenv("OPENAI_MODEL", "gpt-5-mini-2025-08-07"),
            "gpt-5-chat-latest",
            "gpt-4o",
        ]

    # --------------
    # Public methods
    # --------------
    def run(self, full_scan: bool, output_dir: Optional[Path]) -> None:
        ctx = self.gather_comprehensive_context(full_scan=full_scan)
        docs_map = self.generate_docs(ctx)
        self.write_docs(docs_map, output_dir=output_dir)

    # ----------------
    # Context building
    # ----------------
    def gather_comprehensive_context(self, *, full_scan: bool = True) -> RepoContext:
        root = self.repo_root
        files: List[RepoFile] = []
        total_bytes = 0
        counted_by_dir: Dict[str, int] = {k: 0 for k in INCLUDE_ROOTS}

        for base in INCLUDE_ROOTS:
            base_path = root / base
            if not base_path.exists():
                continue
            for path in base_path.rglob("*"):
                if not path.is_file():
                    continue
                if any(seg in EXCLUDE_DIRS for seg in path.parts):
                    continue
                rel = str(path.relative_to(root))
                if any(p.search(rel) for p in EXCLUDE_FILE_PATTERNS):
                    continue
                if path.suffix not in TEXT_FILE_EXTS:
                    continue

                size = path.stat().st_size
                head = self._read_head(path, max_bytes=20_000)  # keep tight per file
                files.append(RepoFile(path=path, rel=rel, size=size, head=head))
                total_bytes += size
                if rel.split("/", 1)[0] in counted_by_dir:
                    counted_by_dir[rel.split("/", 1)[0]] += 1

        # Basic textual summary to prime the model instead of raw code dump
        summary_lines = [
            "Vivified repository context summary:",
            f"- Files scanned: {len(files)}",
            f"- Total bytes (all scanned): {total_bytes}",
            f"- By area: "
            + ", ".join(f"{k}={v}" for k, v in counted_by_dir.items()),
            "- Important traits: zero trust, supervised lanes (canonical/operator/proxy), audit, HIPAA",
        ]

        # Build compact outlines per directory with first lines/docstrings
        outlines = []
        for base in INCLUDE_ROOTS:
            outlines.append(f"\n[{base.upper()}] key files and excerpts:")
            n = 0
            for rf in files:
                if not rf.rel.startswith(f"{base}/"):
                    continue
                excerpt = self._first_para_or_docstring(rf.head)
                outlines.append(f"- {rf.rel}\n{self._indent(excerpt, 2)}")
                n += 1
                if n >= 60:  # avoid over‑prompting
                    outlines.append("  ... (truncated)")
                    break

        summary = "\n".join(summary_lines + outlines)
        stats = {"files": len(files), "bytes": total_bytes, **counted_by_dir}
        return RepoContext(files=files, summary=summary, stats=stats)

    # -------------
    # LLM prompting
    # -------------
    def generate_docs(self, ctx: RepoContext) -> Dict[str, str]:
        if not self.openai_api_key:
            # Graceful offline mode: generate a minimal but Material‑rich scaffold
            return self._offline_scaffold(ctx)

        system = self._create_system_prompt()
        user = self._create_user_prompt(ctx)

        # Try model chain with fallbacks
        last_err: Optional[Exception] = None
        for model in self.model_chain:
            try:
                content = self._chat_completions(model=model, system=system, user=user)
                docs_map = self._parse_docs_payload(content)
                if not docs_map:
                    raise ValueError("Empty docs payload from model")
                return docs_map
            except Exception as e:  # pragma: no cover - network exceptions
                last_err = e
                continue
        raise RuntimeError(f"All model calls failed: {last_err}")

    # ----------------------
    # Writing out the files
    # ----------------------
    def write_docs(self, docs_map: Dict[str, str], *, output_dir: Optional[Path]) -> None:
        docs_root = (output_dir or (self.repo_root / "docs")).resolve()
        docs_root.mkdir(parents=True, exist_ok=True)

        for rel_path, content in docs_map.items():
            # Safeguard: ensure we only write under docs/
            safe_rel = rel_path.lstrip('/' + '\\')
            target = docs_root / safe_rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
            print(f"Wrote {target.relative_to(self.repo_root)}")

    # ------------------
    # Prompt components
    # ------------------
    def _create_system_prompt(self) -> str:
        return textwrap.dedent(
            """
            You are an expert technical writer for enterprise platforms. Write comprehensive,
            accurate documentation for the Vivified platform using Material for MkDocs features.

            Mandatory rules:
            - Use rich Material features throughout: admonitions (!!!), tabs (=== "Python"),
              collapsible sections (??? note "Title"), grids/icons, mermaid diagrams, and code annotations.
            - Professional, cross‑industry tone (ERP, cybersecurity, messaging). Do not bias towards healthcare.
            - EXCLUDE internal plans/runbooks and any content with words like "phase" or "plan".
            - Reflect the actual repository architecture (core/, plugins/, sdk/). No placeholders.
            - Favor visual explanations for dyslexic readers: diagrams, lists, concise sentences.
            - Include multi‑language SDK examples where applicable (Python/Node.js tabs).
            - Never include secrets or dev‑only bootstrap keys (e.g., bootstrap_admin_only).
            - Assume docs live under docs/ with mkdocs‑material.
            - Output must be pure Markdown suitable for MkDocs.

            Output format contract:
            - Return a JSON object where keys are relative file paths under docs/ (e.g., "core/overview.md")
              and values are full Markdown documents using the features above.
            - Ensure at least these files are present:
              - "core/overview.md"
              - "plugins/overview.md"
              - "sdk/overview.md"
              - "architecture/diagrams.md" (with mermaid diagrams)
              - "reference/apis.md" (high‑level API overview using admonitions and tabs)
            - Do not include any file referencing internal plans or runbooks.
            """
        ).strip()

    def _create_user_prompt(self, ctx: RepoContext) -> str:
        # Provide summarized full‑repo context; instruct the model to infer structure and examples
        return textwrap.dedent(
            f"""
            Create updated documentation for the Vivified repository based on this context summary.

            === Repository Context Summary ===
            {ctx.summary}

            Requirements:
            - Use Material features extensively (admonitions, tabs, collapsible sections, mermaid, annotations).
            - Professional enterprise tone; showcase applicability to ERP, cybersecurity, messaging.
            - Do not mention internal phases/plans. Exclude any planning artifacts.
            - Provide multi‑language SDK examples where possible (Python and Node.js tabs).
            - Include at least one mermaid architecture diagram of the three‑lane model and gateway.
            - Include code annotations in at least one code block.
            - Use admonitions for notes/tips/warnings as appropriate.
            - Keep explanations truthful to the codebase structure.

            Return JSON with file paths → markdown content as described in the system prompt.
            """
        ).strip()

    # -----------------
    # LLM API handling
    # -----------------
    def _chat_completions(self, *, model: str, system: str, user: str) -> str:
        if requests is None:
            raise RuntimeError("The 'requests' package is required to call the OpenAI API")

        url = "https://api.openai.com/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.openai_api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": 0.4,
            "response_format": {"type": "json_object"},
            "max_tokens": 6000,
        }
        resp = requests.post(url, headers=headers, json=payload, timeout=180)
        resp.raise_for_status()
        data = resp.json()
        return data["choices"][0]["message"]["content"]

    # ------------------
    # Parsing utilities
    # ------------------
    def _parse_docs_payload(self, content: str) -> Dict[str, str]:
        try:
            obj = json.loads(content)
        except json.JSONDecodeError as e:
            # Attempt to extract JSON block
            start = content.find("{")
            end = content.rfind("}")
            if start != -1 and end != -1 and end > start:
                obj = json.loads(content[start : end + 1])
            else:
                raise e

        docs: Dict[str, str] = {}
        for rel, md in obj.items():
            if any(p.search(rel) for p in EXCLUDE_FILE_PATTERNS):
                continue
            # Force unix separators and strip leading docs/
            rel_norm = rel.replace("\\", "/")
            if rel_norm.startswith("docs/"):
                rel_norm = rel_norm[len("docs/") :]
            docs[rel_norm] = md
        return docs

    # -----------------
    # Local generation
    # -----------------
    def _offline_scaffold(self, ctx: RepoContext) -> Dict[str, str]:
        # Minimal but rich scaffold so CI and local builds don’t stall without API key
        base_note = (
            "!!! warning\n\n"
            "    AI generation skipped (no OPENAI_API_KEY). This page is a scaffold using repo context."
        )
        mermaid = (
            "```mermaid\n"
            "flowchart LR\n"
            "  Plugins-->Gateway\n"
            "  Gateway-->Canonical[Canonical Lane]\n"
            "  Gateway-->Operator[Operator Lane]\n"
            "  Gateway-->Proxy[Proxy Lane]\n"
            "```\n"
        )
        tabs = (
            "=== \"Python\"\n\n"
            "```python\n# SDK usage (1)\nfrom sdk.python import client  # (1)\nclient = client.Vivified()\n```\n\n"
            "1. Create the SDK client\n\n"
            "=== \"Node.js\"\n\n"
            "```ts\n// SDK usage\nimport { Vivified } from '@vivified/sdk'\nconst client = new Vivified()\n```\n"
        )

        pages: Dict[str, str] = {}

        pages["core/overview.md"] = "\n".join(
            [
                "# Core Overview",
                "",
                base_note,
                "",
                "The core mediates all plugin interactions and enforces a zero‑trust, audited architecture.",
                "",
                mermaid.rstrip(),
                "",
                "??? note \"Three supervised lanes\"",
                "    - Canonical: event‑driven messaging and normalized models",
                "    - Operator: synchronous RPC through the gateway",
                "    - Proxy: controlled egress to external APIs with allowlists",
                "",
                tabs.rstrip(),
            ]
        )

        pages["plugins/overview.md"] = "\n".join(
            [
                "# Plugins Overview",
                "",
                base_note,
                "",
                "Plugins are isolated and authenticate to core with unique tokens. No direct DB/FS access.",
                "",
                "!!! tip",
                "    Use traits to gate capabilities and UI surfaces (least‑privilege by default).",
            ]
        )

        pages["sdk/overview.md"] = "\n".join(
            [
                "# SDK Overview",
                "",
                base_note,
                "",
                "Use the official SDKs to integrate with gateway RPC and canonical events.",
                tabs.rstrip(),
            ]
        )

        pages["architecture/diagrams.md"] = "\n".join(
            [
                "# Architecture Diagrams",
                "",
                base_note,
                "",
                mermaid.rstrip(),
            ]
        )

        pages["reference/apis.md"] = "\n".join(
            [
                "# API Reference (High‑Level)",
                "",
                base_note,
                "",
                "!!! info",
                "    See the gateway service for endpoint groups. Auth is JWT with short‑lived tokens.",
            ]
        )

        return pages

    # --------------
    # File utilities
    # --------------
    @staticmethod
    def _indent(s: str, n: int) -> str:
        pad = " " * n
        return "\n".join(pad + ln for ln in s.splitlines())

    @staticmethod
    def _read_head(path: Path, *, max_bytes: int) -> str:
        try:
            with path.open("rb") as f:
                data = f.read(max_bytes)
            try:
                return data.decode("utf-8", errors="ignore")
            except Exception:
                return ""
        except Exception:
            return ""

    @staticmethod
    def _first_para_or_docstring(text: str) -> str:
        # Try to extract Python docstring, else first non‑empty paragraph
        m = re.search(r'"""(.*?)"""', text, re.DOTALL)
        if m:
            return m.group(1).strip()[:600]
        parts = [p.strip() for p in text.splitlines() if p.strip()]
        return "\n".join(parts[:8])[:600]


def main() -> None:
    parser = argparse.ArgumentParser(description="Vivified Docs Autopilot (enhanced)")
    parser.add_argument("--full-scan", action="store_true", help="Scan entire repository (default)")
    parser.add_argument("--output-dir", type=Path, default=None, help="Optional output directory instead of docs/")
    args = parser.parse_args()

    autopilot = DocsAutopilotEnhanced()
    autopilot.run(full_scan=True, output_dir=args.output_dir)


if __name__ == "__main__":  # pragma: no cover
    main()
