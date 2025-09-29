"""
AI services: lightweight Redis-backed RAG and stubs for agent/tool execution.

Design goals:
- No hard dependency on external LLM libs for tests to pass.
- Optional Redis vector-ish store; fall back to in-memory index.
- HIPAA-conscious: do not log PHI; return minimal metadata.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
import os
import re
import time
import logging

logger = logging.getLogger(__name__)


def _tokenize(text: str) -> List[str]:
    return re.findall(r"[a-zA-Z0-9_]+", text.lower())


@dataclass
class RAGStatus:
    docs_indexed: int
    last_trained_ts: Optional[float] = None


class RAGService:
    """Simple RAG indexer with Redis or in-memory fallback.

    Storage layout (Redis):
      - ai:rag:docs -> set of doc_ids
      - ai:rag:doc:{id}:title -> str
      - ai:rag:doc:{id}:path -> str
      - ai:rag:doc:{id}:content -> str (avoid PHI; only internal docs)
      - ai:rag:token:{tok} -> set of doc_ids
    """

    def __init__(self, redis_url: Optional[str] = None) -> None:
        self._redis_url = redis_url or os.getenv("REDIS_URL")
        self._rd = None
        self._docs: Dict[str, Tuple[str, str]] = {}
        self._tokens: Dict[str, set] = {}
        self._last_trained: Optional[float] = None

    async def _ensure_redis(self):
        if not self._redis_url:
            return None
        if self._rd is None:
            try:
                import redis.asyncio as redis  # type: ignore

                self._rd = redis.from_url(self._redis_url)
            except Exception:  # noqa: BLE001
                logger.debug("redis init failed; falling back to memory", exc_info=True)
                self._rd = None
        return self._rd

    async def status(self) -> RAGStatus:
        rd = await self._ensure_redis()
        if rd:
            try:
                docs = await rd.scard("ai:rag:docs")
            except Exception:  # noqa: BLE001
                docs = 0
        else:
            docs = len(self._docs)
        return RAGStatus(docs_indexed=int(docs), last_trained_ts=self._last_trained)

    async def clear(self) -> None:
        rd = await self._ensure_redis()
        if rd:
            try:
                ids = await rd.smembers("ai:rag:docs")
                pipe = rd.pipeline()
                for did in ids or []:
                    did_s = (
                        did.decode()
                        if isinstance(did, (bytes, bytearray))
                        else str(did)
                    )
                    pipe.delete(f"ai:rag:doc:{did_s}:title")
                    pipe.delete(f"ai:rag:doc:{did_s}:path")
                    pipe.delete(f"ai:rag:doc:{did_s}:content")
                pipe.delete("ai:rag:docs")
                await pipe.execute()
            except Exception:  # noqa: BLE001
                logger.debug("redis clear failed", exc_info=True)
        self._docs.clear()
        self._tokens.clear()
        self._last_trained = None

    async def train(self, sources: List[str]) -> int:
        """Train by indexing local text files from given directory roots.

        Only reads .md, .txt, .py, .ts, .tsx files as internal docs/code.
        """
        patterns = (".md", ".txt", ".py", ".ts", ".tsx")
        count = 0
        rd = await self._ensure_redis()

        for root in sources:
            root = os.path.abspath(root)
            if not os.path.exists(root):
                continue
            for dirpath, _dirnames, filenames in os.walk(root):
                for fn in filenames:
                    if not fn.lower().endswith(patterns):
                        continue
                    path = os.path.join(dirpath, fn)
                    try:
                        size = os.path.getsize(path)
                        if size > 512_000:  # Skip very large files (>512KB)
                            continue
                        with open(path, "r", encoding="utf-8", errors="ignore") as f:
                            content = f.read()
                        if not content:
                            continue
                        did = str(hash(path))
                        title = os.path.relpath(path, root)
                        toks = set(_tokenize(content))
                        if rd:
                            try:
                                pipe = rd.pipeline()
                                pipe.sadd("ai:rag:docs", did)
                                pipe.set(f"ai:rag:doc:{did}:title", title)
                                pipe.set(f"ai:rag:doc:{did}:path", path)
                                pipe.set(f"ai:rag:doc:{did}:content", content)
                                for t in toks:
                                    pipe.sadd(f"ai:rag:token:{t}", did)
                                await pipe.execute()
                            except Exception:  # noqa: BLE001
                                logger.debug("redis index failed", exc_info=True)
                                # Also maintain in-memory
                                self._docs[did] = (title, content)
                                for t in toks:
                                    self._tokens.setdefault(t, set()).add(did)
                        else:
                            self._docs[did] = (title, content)
                            for t in toks:
                                self._tokens.setdefault(t, set()).add(did)
                        count += 1
                    except Exception:  # noqa: BLE001
                        logger.debug("index error: %s", path, exc_info=True)

        self._last_trained = time.time()
        return count

    async def query(self, question: str, top_k: int = 3) -> List[Dict[str, str]]:
        toks = set(_tokenize(question))
        rd = await self._ensure_redis()
        scores: Dict[str, float] = {}
        if rd:
            try:
                cand_ids: set = set()
                for t in toks:
                    ids = await rd.smembers(f"ai:rag:token:{t}")
                    for did in ids or []:
                        cand_ids.add(
                            did.decode()
                            if isinstance(did, (bytes, bytearray))
                            else str(did)
                        )
                for did in cand_ids:
                    # Simple score: number of overlapping tokens
                    content = await rd.get(f"ai:rag:doc:{did}:content")
                    if content:
                        ct = (
                            content.decode()
                            if isinstance(content, (bytes, bytearray))
                            else str(content)
                        )
                        doc_toks = set(_tokenize(ct))
                        overlap = len(toks.intersection(doc_toks))
                        if overlap > 0:
                            scores[did] = float(overlap)
                ranked = sorted(scores.items(), key=lambda x: x[1], reverse=True)[
                    :top_k
                ]
                out: List[Dict[str, str]] = []
                for did, _sc in ranked:
                    title = await rd.get(f"ai:rag:doc:{did}:title")
                    path = await rd.get(f"ai:rag:doc:{did}:path")
                    out.append(
                        {
                            "id": str(did),
                            "title": (
                                title.decode()
                                if isinstance(title, (bytes, bytearray))
                                else str(title or "")
                            ),
                            "path": (
                                path.decode()
                                if isinstance(path, (bytes, bytearray))
                                else str(path or "")
                            ),
                        }
                    )
                return out
            except Exception:  # noqa: BLE001
                logger.debug("redis query failed", exc_info=True)

        # In-memory fallback
        for did, (_title, content) in self._docs.items():
            doc_toks = set(_tokenize(content))
            overlap = len(toks.intersection(doc_toks))
            if overlap > 0:
                scores[did] = float(overlap)
        ranked = sorted(scores.items(), key=lambda x: x[1], reverse=True)[:top_k]
        results: List[Dict[str, str]] = []
        for did, _sc in ranked:
            title, _content = self._docs.get(did, ("", ""))
            results.append({"id": did, "title": title, "path": title})
        return results


# Optional LangGraph-backed agent (stub if unavailable)
class AgentService:
    def __init__(self, rag: RAGService) -> None:
        self.rag = rag

    async def run(self, prompt: str) -> Dict[str, str]:
        # Attempt to use languages/graph libs if available (best effort)
        hits = await self.rag.query(prompt, top_k=3)
        context = "\n".join([f"- {h.get('title')}" for h in hits])

        # Try OpenAI if API key present; default model from env/config
        try:
            import httpx  # type: ignore
            model = os.getenv("AI_LLM_MODEL") or os.getenv("OPENAI_DEFAULT_MODEL") or "gpt-5-mini"
            api_key = os.getenv("OPENAI_API_KEY") or os.getenv("AI_OPENAI_API_KEY")
            base_url = os.getenv("OPENAI_BASE_URL", "https://api.openai.com")
            if api_key:
                payload = {
                    "model": model,
                    "messages": [
                        {"role": "system", "content": "You are a concise assistant."},
                        {
                            "role": "user",
                            "content": f"Context sources (internal):\n{context}\n\nQuestion: {prompt}",
                        },
                    ],
                    "temperature": 0.3,
                }
                url = f"{base_url.rstrip('/')}/v1/chat/completions"
                headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
                async with httpx.AsyncClient(timeout=30) as client:
                    resp = await client.post(url, json=payload, headers=headers)
                if resp.status_code < 300:
                    data = resp.json()
                    choice = ((data or {}).get("choices") or [{}])[0]
                    msg = (choice.get("message") or {}).get("content") or ""
                    if msg:
                        return {"result": msg}
                # Fallback to stub if non-2xx or empty
        except Exception:
            # Ignore; fall back to stub
            pass

        return {
            "result": f"Stubbed agent response. Context sources:\n{context}".strip()
        }
