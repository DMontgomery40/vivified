"""
AI services: lightweight Redis-backed RAG and stubs for agent/tool execution.

Design goals:
- No hard dependency on external LLM libs for tests to pass.
- Optional Redis vector-ish store; fall back to in-memory index.
- HIPAA-conscious: do not log PHI; return minimal metadata.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple, Iterable, Any
import os
import re
import time
import logging
import json
import fnmatch
import hashlib

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
        # Prefer Redis by default for persistence and performance. Fall back to memory if unreachable.
        self._redis_url = redis_url or os.getenv(
            "REDIS_URL", "redis://localhost:6379/0"
        )
        self._rd = None
        # In-memory fallback stores
        self._docs: Dict[str, Tuple[str, str]] = {}
        self._meta: Dict[str, Dict[str, List[str]]] = {}
        self._tokens: Dict[str, set] = {}
        self._vectors: Dict[str, List[float]] = {}
        self._last_trained: Optional[float] = None
        # Chunking params (can be overridden by ConfigService at train time)
        self._chunk_chars: int = int(os.getenv("RAG_CHUNK_CHARS", "4000") or 4000)
        self._overlap_chars: int = int(os.getenv("RAG_OVERLAP_CHARS", "400") or 400)
        # Optional plugin-backed storage (operator lane)
        self._backend: str = os.getenv("RAG_BACKEND", "redis").lower()
        self._backend_plugin_id: Optional[str] = os.getenv("RAG_PLUGIN_ID")

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
                    pipe.delete(f"ai:rag:doc:{did_s}:vec")
                pipe.delete("ai:rag:docs")
                await pipe.execute()
            except Exception:  # noqa: BLE001
                logger.debug("redis clear failed", exc_info=True)
        self._docs.clear()
        self._meta.clear()
        self._tokens.clear()
        self._vectors.clear()
        self._last_trained = None

    async def train(self, sources: List[str]) -> int:
        """Train by indexing local text files from given directory roots.

        Index all files not excluded by ignore patterns.
        """
        count = 0
        rd = await self._ensure_redis()
        root_base = os.path.abspath(os.getenv("RAG_ROOT", os.getcwd()))
        try:
            from ..config.service import get_config_service  # type: ignore

            cfg = get_config_service()
            cfg_root = await cfg.get("ai.rag.root")
            if isinstance(cfg_root, str) and cfg_root:
                root_base = os.path.abspath(cfg_root)
        except Exception:
            pass
        ignore_patterns = self._load_ignore_patterns(root_base)
        # Load ingestion rules (required traits/classification) and backend settings from ConfigService
        trait_rules: Dict[str, List[str]] = {}
        class_rules: Dict[str, List[str]] = {}
        try:
            from core.config.service import get_config_service  # type: ignore

            cfg = get_config_service()
            # Optional: override backend and plugin id
            try:
                be = await cfg.get("ai.rag.backend")
                if isinstance(be, str):
                    self._backend = be.lower()
                pid = await cfg.get("ai.rag.plugin_id")
                if isinstance(pid, str) and pid:
                    self._backend_plugin_id = pid
            except Exception:
                pass
            # Optional: override chunk sizes
            try:
                ch = await cfg.get("ai.rag.chunk_chars")
                if isinstance(ch, int) and ch > 0:
                    self._chunk_chars = ch
                ov = await cfg.get("ai.rag.overlap_chars")
                if isinstance(ov, int) and ov >= 0:
                    self._overlap_chars = ov
            except Exception:
                pass
            maybe_traits = await cfg.get("ai.rag.required_traits")
            if isinstance(maybe_traits, dict):
                trait_rules = {
                    str(k): [str(t) for t in (v or [])]
                    for k, v in maybe_traits.items()
                    if isinstance(v, (list, tuple))
                }
            maybe_class = await cfg.get("ai.rag.classification")
            if isinstance(maybe_class, dict):
                class_rules = {
                    str(k): [str(c) for c in (v or [])]
                    for k, v in maybe_class.items()
                    if isinstance(v, (list, tuple))
                }
        except Exception:
            pass

        for root in sources:
            root = os.path.abspath(root)
            if not os.path.exists(root):
                continue
            for dirpath, dirnames, filenames in os.walk(root):
                # Prune ignored directories early
                pruned: List[str] = []
                for d in list(dirnames):
                    dp = os.path.relpath(os.path.join(dirpath, d), root_base)
                    if self._is_ignored(dp, ignore_patterns, is_dir=True):
                        pruned.append(d)
                for d in pruned:
                    dirnames.remove(d)
                for fn in filenames:
                    path = os.path.join(dirpath, fn)
                    relp = os.path.relpath(path, root_base)
                    if self._is_ignored(relp, ignore_patterns, is_dir=False):
                        continue
                    try:
                        size = os.path.getsize(path)
                        max_bytes = int(os.getenv("RAG_MAX_BYTES", "2097152"))  # 2MB
                        if size > max_bytes:
                            continue
                        # Load as text; ignore undecodable bytes
                        with open(path, "rb") as f:
                            raw = f.read()
                        content = raw.decode("utf-8", errors="ignore")
                        if not content:
                            continue
                        # Deterministic doc base id using path, size, mtime
                        stat = os.stat(path)
                        base_id = hashlib.sha1(
                            f"{path}:{size}:{int(stat.st_mtime)}".encode()
                        ).hexdigest()[:16]
                        title = os.path.relpath(path, root_base)
                        required_traits: List[str] = self._traits_for_path(
                            relp, trait_rules
                        )
                        classification: List[str] = self._traits_for_path(
                            relp, class_rules
                        ) or ["internal"]
                        # Chunk content for embeddings
                        chunks = self._chunk_text(content)
                        for idx, chunk in enumerate(chunks):
                            did = f"{base_id}:{idx}"
                            toks = set(_tokenize(chunk))
                            # Compute embedding (best-effort)
                            vec = await self._embed_text(chunk)
                            # Plugin backend: forward to operator lane when configured
                            if self._backend == "plugin" and self._backend_plugin_id:
                                try:
                                    await self._plugin_index(
                                        plugin_id=self._backend_plugin_id,
                                        did=did,
                                        title=f"{title}#chunk{idx}",
                                        path=path,
                                        chunk=chunk,
                                        required_traits=required_traits,
                                        classification=classification,
                                        vector=vec,
                                    )
                                except Exception:
                                    logger.debug("plugin index failed", exc_info=True)
                            elif rd:
                                try:
                                    pipe = rd.pipeline()
                                    pipe.sadd("ai:rag:docs", did)
                                    pipe.set(
                                        f"ai:rag:doc:{did}:title", f"{title}#chunk{idx}"
                                    )
                                    pipe.set(f"ai:rag:doc:{did}:path", path)
                                    # Store small content excerpt for preview only (avoid large payloads)
                                    preview = chunk[:2000]
                                    pipe.set(f"ai:rag:doc:{did}:content", preview)
                                    pipe.set(
                                        f"ai:rag:doc:{did}:meta",
                                        json.dumps(
                                            {
                                                "required_traits": required_traits,
                                                "classification": classification,
                                            }
                                        ),
                                    )
                                    if vec is not None:
                                        pipe.set(
                                            f"ai:rag:doc:{did}:vec",
                                            json.dumps(vec),
                                        )
                                    for t in toks:
                                        pipe.sadd(f"ai:rag:token:{t}", did)
                                    await pipe.execute()
                                except Exception:  # noqa: BLE001
                                    logger.debug("redis index failed", exc_info=True)
                                    self._docs[did] = (f"{title}#chunk{idx}", chunk)
                                    self._meta[did] = {
                                        "required_traits": required_traits,
                                        "classification": classification,
                                    }
                                    if vec is not None:
                                        self._vectors[did] = vec
                                    for t in toks:
                                        self._tokens.setdefault(t, set()).add(did)
                            else:
                                self._docs[did] = (f"{title}#chunk{idx}", chunk)
                                self._meta[did] = {
                                    "required_traits": required_traits,
                                    "classification": classification,
                                }
                                if vec is not None:
                                    self._vectors[did] = vec
                                for t in toks:
                                    self._tokens.setdefault(t, set()).add(did)
                            count += 1
                    except Exception:  # noqa: BLE001
                        logger.debug("index error: %s", path, exc_info=True)

        self._last_trained = time.time()
        return count

    def _load_ignore_patterns(self, root_base: str) -> List[str]:
        # Built-in safe defaults to avoid noisy/bulky content
        patterns: List[str] = [
            "node_modules/",
            "dist/",
            "build/",
            "site/",
            ".git/",
            "__pycache__/",
            ".pytest_cache/",
            ".mypy_cache/",
        ]
        for candidate in [".ragignore", ".gitignore"]:
            p = os.path.join(root_base, candidate)
            try:
                if os.path.exists(p):
                    with open(p, "r", encoding="utf-8", errors="ignore") as f:
                        for line in f:
                            s = line.strip()
                            if not s or s.startswith("#"):
                                continue
                            patterns.append(s)
            except Exception:
                continue
        return patterns

    def _is_ignored(self, rel_path: str, patterns: List[str], *, is_dir: bool) -> bool:
        # Normalize to posix-like
        p = rel_path.replace(os.sep, "/").lstrip("./")
        base = os.path.basename(p)
        for pat in patterns:
            anchored = pat.startswith("/")
            is_dir_pat = pat.endswith("/")
            core = pat.strip("/")
            target = p if not anchored else "/" + p
            test_pat = core if not anchored else "/" + core
            # Directory pattern: match prefix
            if is_dir and is_dir_pat:
                if target.startswith(test_pat):
                    return True
                continue
            # File pattern: fnmatch path and basename
            if fnmatch.fnmatch(target, test_pat) or fnmatch.fnmatch(base, core):
                return True
        return False

    def _traits_for_path(self, rel_path: str, rules: Dict[str, List[str]]) -> List[str]:
        """Return merged list of values for matching glob patterns."""
        p = rel_path.replace(os.sep, "/").lstrip("./")
        vals: List[str] = []
        for pat, v in rules.items():
            core = pat.strip("/")
            if fnmatch.fnmatch(p, core) or fnmatch.fnmatch(os.path.basename(p), core):
                for item in v:
                    if item not in vals:
                        vals.append(item)
        return vals

    def _chunk_text(self, text: str) -> List[str]:
        """Chunk text into overlapping windows suitable for embeddings.

        Uses character windows to avoid tokenization dependency.
        """
        max_chars = int(self._chunk_chars or 4000)
        overlap = int(self._overlap_chars or 400)
        if max_chars <= 0:
            return [text]
        chunks: List[str] = []
        i = 0
        n = len(text)
        while i < n:
            j = min(i + max_chars, n)
            chunks.append(text[i:j])
            if j >= n:
                break
            i = max(0, j - overlap)
        return chunks

    async def _embed_text(self, text: str) -> Optional[List[float]]:
        """Compute embedding via configured provider (OpenAI by default).

        Returns None if embedding fails; query falls back to sparse token search.
        """
        text = text.strip()
        if not text:
            return None
        # Resolve connectors/config
        base_url = None
        api_key = None
        model = (
            os.getenv("EMBEDDING_MODEL")
            or os.getenv("OPENAI_EMBEDDING_MODEL")
            or "text-embedding-3-small"
        )
        try:
            from core.config.service import get_config_service  # type: ignore

            cfg = get_config_service()
            openai_cfg = await cfg.get("ai.connectors.openai") or {}
            base_url = (
                openai_cfg.get("base_url")
                or await cfg.get("ai.llm.base_url")
                or os.getenv("OPENAI_BASE_URL")
                or "https://api.openai.com"
            )
            secret = await cfg.get("secrets.ai.openai.api_key")
            api_key = secret or os.getenv("OPENAI_API_KEY")
            model_cfg = await cfg.get("ai.embeddings.model")
            if model_cfg:
                model = str(model_cfg)
        except Exception:
            base_url = os.getenv("OPENAI_BASE_URL") or "https://api.openai.com"
            api_key = os.getenv("OPENAI_API_KEY")
        # Construct request
        payload = {"model": model, "input": text}
        headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
        url = f"{str(base_url).rstrip('/')}/v1/embeddings"

        # Prefer proxy via core gateway for egress control
        try:
            import httpx  # type: ignore

            core_base = os.getenv("PUBLIC_API_URL", "http://localhost:8000").rstrip("/")
            if api_key and base_url:
                r = await httpx.AsyncClient(timeout=30).post(
                    f"{core_base}/gateway/proxy",
                    json={
                        "plugin_id": "ai-core",
                        "method": "POST",
                        "url": url,
                        "headers": {**headers, "Content-Type": "application/json"},
                        "json": payload,
                        "timeout": 30,
                    },
                )
                if r.status_code < 300:
                    data = r.json() or {}
                    emb = ((data.get("data") or [{}])[0] or {}).get("embedding")
                    if isinstance(emb, list) and all(
                        isinstance(x, (float, int)) for x in emb
                    ):
                        return [float(x) for x in emb]
        except Exception:
            logger.debug("proxy embedding failed", exc_info=True)

        # Direct call fallback
        try:
            import httpx  # type: ignore

            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.post(
                    url,
                    json=payload,
                    headers={**headers, "Content-Type": "application/json"},
                )
            if resp.status_code < 300:
                d = resp.json() or {}
                emb = ((d.get("data") or [{}])[0] or {}).get("embedding")
                if isinstance(emb, list) and all(
                    isinstance(x, (float, int)) for x in emb
                ):
                    return [float(x) for x in emb]
        except Exception:
            logger.debug("direct embedding failed", exc_info=True)
        return None

    async def _plugin_index(
        self,
        *,
        plugin_id: str,
        did: str,
        title: str,
        path: str,
        chunk: str,
        required_traits: List[str],
        classification: List[str],
        vector: Optional[List[float]] = None,
    ) -> None:
        try:
            import httpx  # type: ignore

            core_base = os.getenv("PUBLIC_API_URL", "http://localhost:8000").rstrip("/")
            body = {
                "caller_plugin": "ai-core",
                "payload": {
                    "id": did,
                    "title": title,
                    "path": path,
                    "content": chunk,
                    "required_traits": required_traits,
                    "classification": classification,
                    "vector": vector,
                },
                "timeout": 20,
            }
            await httpx.AsyncClient(timeout=20).post(
                f"{core_base}/gateway/{plugin_id}/rag_index", json=body
            )
        except Exception:
            raise

    async def query(
        self,
        question: str,
        top_k: int = 3,
        user_traits: Optional[Iterable[str]] = None,
    ) -> List[Dict[str, str]]:
        toks = set(_tokenize(question))
        rd = await self._ensure_redis()
        scores: Dict[str, float] = {}
        trait_set = set(user_traits or [])
        # Plugin backend delegation
        if self._backend == "plugin" and self._backend_plugin_id:
            try:
                import httpx  # type: ignore

                core_base = os.getenv("PUBLIC_API_URL", "http://localhost:8000").rstrip(
                    "/"
                )
                body = {
                    "caller_plugin": "ai-core",
                    "payload": {
                        "q": question,
                        "top_k": top_k,
                        "user_traits": list(trait_set),
                    },
                    "timeout": 30,
                }
                resp = await httpx.AsyncClient(timeout=30).post(
                    f"{core_base}/gateway/{self._backend_plugin_id}/rag_query",
                    json=body,
                )
                if resp.status_code < 300:
                    data = resp.json() or {}
                    items = data.get("items") or data.get("results") or []
                    out_items: List[Dict[str, str]] = []
                    for it in items:
                        if not isinstance(it, dict):
                            continue
                        title = str(it.get("title") or "")
                        path = str(it.get("path") or title)
                        did = str(
                            it.get("id") or hashlib.sha1(title.encode()).hexdigest()[:8]
                        )
                        out_items.append({"id": did, "title": title, "path": path})
                    return out_items[:top_k]
            except Exception:
                logger.debug("plugin query failed", exc_info=True)
        # Try semantic (vector) search first if we have vectors
        q_vec = await self._embed_text(question)
        used_vector = q_vec is not None
        if rd:
            try:
                cand_ids: List[str] = []
                # If vector available, scan all docs; else restrict by token overlap
                if used_vector:
                    ids = await rd.smembers("ai:rag:docs")
                    for did in ids or []:
                        cand_ids.append(
                            did.decode()
                            if isinstance(did, (bytes, bytearray))
                            else str(did)
                        )
                else:
                    seen: set = set()
                    for t in toks:
                        ids = await rd.smembers(f"ai:rag:token:{t}")
                        for did in ids or []:
                            key = (
                                did.decode()
                                if isinstance(did, (bytes, bytearray))
                                else str(did)
                            )
                            if key not in seen:
                                seen.add(key)
                                cand_ids.append(key)
                # Score
                if used_vector and q_vec is not None:
                    for did in cand_ids:
                        v_raw = await rd.get(f"ai:rag:doc:{did}:vec")
                        if not v_raw:
                            continue
                        try:
                            vec = json.loads(
                                v_raw.decode()
                                if isinstance(v_raw, (bytes, bytearray))
                                else str(v_raw)
                            )
                            if isinstance(vec, list) and vec:
                                scores[did] = float(
                                    self._cosine_sim(q_vec, [float(x) for x in vec])
                                )
                        except Exception:
                            continue
                else:
                    for did in cand_ids:
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
                # Filter by TBAC required_traits if metadata present
                allowed: List[Tuple[str, float]] = []
                for did, sc in scores.items():
                    req: List[str] = []
                    try:
                        meta_raw = await rd.get(f"ai:rag:doc:{did}:meta")
                        if meta_raw:
                            meta_obj = json.loads(
                                meta_raw.decode()
                                if isinstance(meta_raw, (bytes, bytearray))
                                else str(meta_raw)
                            )
                            req = list(meta_obj.get("required_traits") or [])
                    except Exception:
                        req = []
                    if set(req).issubset(trait_set):
                        allowed.append((did, sc))
                ranked = sorted(allowed, key=lambda x: x[1], reverse=True)[:top_k]
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
        if used_vector and q_vec is not None and self._vectors:
            for did, vec in self._vectors.items():
                try:
                    scores[did] = float(self._cosine_sim(q_vec, vec))
                except Exception:
                    continue
        else:
            for did, (_title, content) in self._docs.items():
                doc_toks = set(_tokenize(content))
                overlap = len(toks.intersection(doc_toks))
                if overlap > 0:
                    scores[did] = float(overlap)
        allowed2: List[Tuple[str, float]] = []
        for did, sc in scores.items():
            req = list(self._meta.get(did, {}).get("required_traits") or [])
            if set(req).issubset(trait_set):
                allowed2.append((did, sc))
        ranked = sorted(allowed2, key=lambda x: x[1], reverse=True)[:top_k]
        results: List[Dict[str, str]] = []
        for did, _sc in ranked:
            title, _content = self._docs.get(did, ("", ""))
            results.append({"id": did, "title": title, "path": title})
        return results

    @staticmethod
    def _cosine_sim(a: List[float], b: List[float]) -> float:
        # Handle mismatched lengths safely by truncation
        n = min(len(a), len(b))
        if n == 0:
            return 0.0
        dot = 0.0
        na = 0.0
        nb = 0.0
        for i in range(n):
            x = float(a[i])
            y = float(b[i])
            dot += x * y
            na += x * x
            nb += y * y
        denom = (na**0.5) * (nb**0.5)
        return (dot / denom) if denom > 0 else 0.0


# Optional LangGraph-backed agent (stub if unavailable)
class AgentService:
    def __init__(self, rag: RAGService) -> None:
        self.rag = rag

    async def run(
        self,
        prompt: str,
        *,
        user_traits: Optional[Iterable[str]] = None,
        opts: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        # Attempt tool-calling pipeline if enabled, else simple RAG-informed completion.
        hits = await self.rag.query(prompt, top_k=3, user_traits=user_traits)
        context = "\n".join([f"- {h.get('title')}" for h in hits])
        tools_log: List[Dict[str, Any]] = []

        # Try OpenAI via core proxy first (if configured), else direct
        try:
            import httpx  # type: ignore

            # Resolve connectors from ConfigService if available
            try:
                from ..config.service import get_config_service  # type: ignore

                cfgsvc = get_config_service()
                # Prefer explicit fields too
                openai_cfg = await cfgsvc.get("ai.connectors.openai") or {}
                anthropic_cfg = await cfgsvc.get("ai.connectors.anthropic") or {}
                llm_provider = (
                    (await cfgsvc.get("ai.llm.provider"))
                    or os.getenv("AI_LLM_PROVIDER")
                    or "openai"
                )
            except Exception:
                cfgsvc = None
                openai_cfg = {}
                anthropic_cfg = {}
                llm_provider = os.getenv("AI_LLM_PROVIDER") or "openai"
            # Determine provider and connection details
            provider = (opts or {}).get("provider") or llm_provider
            if provider.lower() == "anthropic":
                model = (opts or {}).get("model") or str(
                    (anthropic_cfg or {}).get("default_model")
                    or "claude-3-haiku-20240307"
                )
                api_key = (
                    (opts or {}).get("api_key")
                    or str((anthropic_cfg or {}).get("api_key") or "")
                    or os.getenv("ANTHROPIC_API_KEY")
                )
                base_url = (opts or {}).get("base_url") or str(
                    (anthropic_cfg or {}).get("base_url") or "https://api.anthropic.com"
                )
            else:
                model = (
                    (opts or {}).get("model")
                    or str((openai_cfg or {}).get("default_model") or "")
                    or os.getenv("AI_LLM_MODEL")
                    or os.getenv("OPENAI_DEFAULT_MODEL")
                    or "gpt-5-mini"
                )
                api_key = (
                    (opts or {}).get("api_key")
                    or str((openai_cfg or {}).get("api_key") or "")
                    or os.getenv("OPENAI_API_KEY")
                    or os.getenv("AI_OPENAI_API_KEY")
                )
                # Ensure base_url is always a string for type-checking
                base_url = str(
                    (opts or {}).get("base_url")
                    or (openai_cfg or {}).get("base_url")
                    or os.getenv("OPENAI_BASE_URL")
                    or "https://api.openai.com"
                )
            # Feature flag: enable tool-calling loop
            use_tools = False
            try:
                flag = os.getenv("AI_AGENT_TOOL_CALLING", "false").lower()
                env_flag = flag in {"1", "true", "yes"}
                use_tools = (opts or {}).get("tool_calling") == "true" or env_flag
                if cfgsvc is not None:
                    v = await cfgsvc.get("ai.agent.tool_calling")
                    if isinstance(v, bool):
                        use_tools = v
            except Exception:
                pass

            if api_key:
                if provider.lower() == "anthropic":
                    # Anthropic messages with optional tools; two-step tool_use → tool_result loop
                    try:
                        url = f"{(base_url or 'https://api.anthropic.com').rstrip('/')}/v1/messages"
                        headers = {
                            "x-api-key": api_key,
                            "anthropic-version": os.getenv(
                                "ANTHROPIC_VERSION", "2023-06-01"
                            ),
                            "Content-Type": "application/json",
                        }
                        messages_a = [
                            {
                                "role": "user",
                                "content": [
                                    {
                                        "type": "text",
                                        "text": f"Context sources (internal):\n{context}\n\nQuestion: {prompt}",
                                    }
                                ],
                            }
                        ]
                        tools_a = None
                        if use_tools:
                            tools_a = [
                                {
                                    "name": "rag_search",
                                    "description": "Search internal docs and return top matches.",
                                    "input_schema": {
                                        "type": "object",
                                        "properties": {"q": {"type": "string"}},
                                        "required": ["q"],
                                    },
                                },
                                {
                                    "name": "http_fetch",
                                    "description": "Fetch a URL via secure proxy (allowlisted domains only).",
                                    "input_schema": {
                                        "type": "object",
                                        "properties": {"url": {"type": "string"}},
                                        "required": ["url"],
                                    },
                                },
                            ]
                        body = {
                            "model": model,
                            "max_tokens": int(os.getenv("ANTHROPIC_MAX_TOKENS", "512")),
                            "messages": messages_a,
                        }
                        if tools_a:
                            body["tools"] = tools_a
                        tools_log = []  # type: ignore[var-annotated]
                        async with httpx.AsyncClient(timeout=30) as client:
                            resp = await client.post(url, json=body, headers=headers)
                        if resp.status_code < 300:
                            data = resp.json() or {}
                            content = data.get("content") or []
                            tool_uses = (
                                [
                                    c
                                    for c in content
                                    if isinstance(c, dict)
                                    and c.get("type") == "tool_use"
                                ]
                                if isinstance(content, list)
                                else []
                            )
                            if use_tools and tool_uses:
                                # Build tool_result blocks
                                tool_results = []
                                for tu in tool_uses:
                                    name = tu.get("name")
                                    tu_id = tu.get("id")
                                    inp = tu.get("input") or {}
                                    if name == "rag_search":
                                        q = str(inp.get("q") or prompt)
                                        tool_hits = await self.rag.query(
                                            q, top_k=5, user_traits=user_traits
                                        )
                                        tools_log.append(
                                            {
                                                "name": "rag_search",
                                                "args": {"q": q},
                                                "content": tool_hits,
                                            }
                                        )
                                        tool_results.append(
                                            {
                                                "type": "tool_result",
                                                "tool_use_id": tu_id,
                                                "content": [
                                                    {
                                                        "type": "text",
                                                        "text": json.dumps(
                                                            {"hits": tool_hits}
                                                        ),
                                                    }
                                                ],
                                            }
                                        )
                                    elif name == "http_fetch":
                                        f_url = str(inp.get("url") or "")
                                        fetched = ""
                                        if f_url:
                                            try:
                                                import httpx as _httpx  # type: ignore

                                                core_base = os.getenv(
                                                    "PUBLIC_API_URL",
                                                    "http://localhost:8000",
                                                ).rstrip("/")
                                                r2 = await _httpx.AsyncClient(
                                                    timeout=20
                                                ).post(
                                                    f"{core_base}/gateway/proxy",
                                                    json={
                                                        "plugin_id": "ai-core",
                                                        "method": "GET",
                                                        "url": f_url,
                                                        "headers": {},
                                                        "timeout": 20,
                                                    },
                                                )
                                                if r2.status_code < 300:
                                                    dj = r2.json()
                                                    fetched = (
                                                        dj.get("text")
                                                        or dj.get("body")
                                                        or ""
                                                    )
                                            except Exception:
                                                pass
                                        tools_log.append(
                                            {
                                                "name": "http_fetch",
                                                "args": {"url": f_url},
                                                "content": fetched[:200],
                                            }
                                        )
                                        tool_results.append(
                                            {
                                                "type": "tool_result",
                                                "tool_use_id": tu_id,
                                                "content": [
                                                    {
                                                        "type": "text",
                                                        "text": fetched[:4000],
                                                    }
                                                ],
                                            }
                                        )
                                # Second call with tool results
                                messages_a.append(
                                    {"role": "assistant", "content": content}
                                )
                                messages_a.append(
                                    {"role": "user", "content": tool_results}
                                )
                                body2 = {
                                    "model": model,
                                    "max_tokens": int(
                                        os.getenv("ANTHROPIC_MAX_TOKENS", "512")
                                    ),
                                    "messages": messages_a,
                                }
                                async with httpx.AsyncClient(timeout=30) as client3:
                                    r3 = await client3.post(
                                        url, json=body2, headers=headers
                                    )
                                if r3.status_code < 300:
                                    d3 = r3.json() or {}
                                    parts = d3.get("content") or []
                                    text3 = ""
                                    if isinstance(parts, list):
                                        texts = [
                                            p.get("text")
                                            for p in parts
                                            if isinstance(p, dict)
                                            and p.get("type") == "text"
                                        ]
                                        text3 = "\n".join([t for t in texts if t])
                                    if text3:
                                        out1: Dict[str, Any] = {"result": text3}
                                        if tools_log:
                                            out1["tools_used"] = tools_log
                                        return out1
                            # No tools or no tool_use: extract text
                            alt_parts: List[Dict[str, Any]] = (
                                content if isinstance(content, list) else []
                            )
                            text = ""
                            if alt_parts:
                                texts = [
                                    p.get("text")
                                    for p in alt_parts
                                    if isinstance(p, dict) and p.get("type") == "text"
                                ]
                                text = "\n".join([t for t in texts if t])
                            if text:
                                out2: Dict[str, Any] = {"result": text}
                                return out2
                    except Exception:
                        pass
                if use_tools:
                    tools_payload: List[Dict[str, Any]] = [
                        {
                            "type": "function",
                            "function": {
                                "name": "rag_search",
                                "description": "Search internal docs and return top matches.",
                                "parameters": {
                                    "type": "object",
                                    "properties": {"q": {"type": "string"}},
                                    "required": ["q"],
                                },
                            },
                        },
                        {
                            "type": "function",
                            "function": {
                                "name": "http_fetch",
                                "description": "Fetch a URL via secure proxy (allowlisted domains only).",
                                "parameters": {
                                    "type": "object",
                                    "properties": {"url": {"type": "string"}},
                                    "required": ["url"],
                                },
                            },
                        },
                    ]
                    messages: List[Dict[str, Any]] = [
                        {
                            "role": "system",
                            "content": "You are a concise assistant. Use tools when helpful.",
                        },
                        {
                            "role": "user",
                            "content": f"Context sources (internal):\n{context}\n\nQuestion: {prompt}",
                        },
                    ]
                    # First call with tools available
                    payload = {
                        "model": model,
                        "messages": messages,
                        "tools": tools_payload,
                        "tool_choice": "required",
                        "temperature": 0.2,
                    }
                else:
                    payload = {
                        "model": model,
                        "messages": [
                            {
                                "role": "system",
                                "content": "You are a concise assistant.",
                            },
                            {
                                "role": "user",
                                "content": f"Context sources (internal):\n{context}\n\nQuestion: {prompt}",
                            },
                        ],
                        "temperature": 0.3,
                    }
                # Prefer gateway proxy to enforce allowlists
                try:
                    core_base = os.getenv(
                        "PUBLIC_API_URL", "http://localhost:8000"
                    ).rstrip("/")
                    proxy_url = f"{core_base}/gateway/proxy"
                    target_url = f"{(base_url or 'https://api.openai.com').rstrip('/')}/v1/chat/completions"
                    headers = {
                        "Authorization": f"Bearer {api_key}",
                        "Content-Type": "application/json",
                    }
                    # Use JSON field; avoid assigning bytes to a reused variable name
                    async with httpx.AsyncClient(timeout=30) as client:
                        resp = await client.post(
                            proxy_url,
                            json={
                                "plugin_id": "ai-core",
                                "method": "POST",
                                "url": target_url,
                                "headers": headers,
                                "json": payload,
                                "timeout": 30,
                            },
                        )
                    if resp.status_code < 300:
                        data = resp.json()
                        # Proxy wraps response in { success, status_code, body/text }
                        prox = data or {}
                        if prox.get("success"):
                            # Body may be base64 or plain; try json parse of text
                            text = prox.get("text") or prox.get("body") or ""
                            try:
                                parsed = (
                                    json.loads(text) if isinstance(text, str) else {}
                                )
                            except Exception:
                                parsed = {}
                            choice = ((parsed or {}).get("choices") or [{}])[0]
                            message: Dict[str, Any] = choice.get("message") or {}
                            if use_tools and message.get("tool_calls"):
                                tool_calls: List[Dict[str, Any]] = (
                                    message.get("tool_calls") or []
                                )
                                # Execute tool calls sequentially (simple loop)
                                for tc in tool_calls:
                                    fn = tc.get("function") or {}
                                    name = fn.get("name")
                                    args_s = fn.get("arguments") or "{}"
                                    try:
                                        args = json.loads(args_s)
                                    except Exception:
                                        args = {}
                                    if name == "rag_search":
                                        q = str(args.get("q") or prompt)
                                        tool_hits = await self.rag.query(
                                            q, top_k=5, user_traits=user_traits
                                        )
                                        tools_log.append(
                                            {
                                                "name": "rag_search",
                                                "args": {"q": q},
                                                "content": tool_hits,
                                            }
                                        )
                                        messages.append(message)
                                        messages.append(
                                            {
                                                "role": "tool",
                                                "tool_call_id": tc.get("id") or "rag1",
                                                "name": name,
                                                "content": json.dumps(
                                                    {"hits": tool_hits}
                                                ),
                                            }
                                        )
                                    elif name == "http_fetch":
                                        url = str(args.get("url") or "")
                                        if url:
                                            try:
                                                async with httpx.AsyncClient(
                                                    timeout=20
                                                ) as client2:
                                                    r2 = await client2.post(
                                                        proxy_url,
                                                        json={
                                                            "plugin_id": "ai-core",
                                                            "method": "GET",
                                                            "url": url,
                                                            "headers": {},
                                                            "timeout": 20,
                                                        },
                                                    )
                                                fetched = ""
                                                if r2.status_code < 300:
                                                    dj = r2.json()
                                                    fetched = (
                                                        dj.get("text")
                                                        or dj.get("body")
                                                        or ""
                                                    )
                                                tools_log.append(
                                                    {
                                                        "name": "http_fetch",
                                                        "args": {"url": url},
                                                        "content": (
                                                            fetched[:200]
                                                            if isinstance(fetched, str)
                                                            else ""
                                                        ),
                                                    }
                                                )
                                                messages.append(message)
                                                messages.append(
                                                    {
                                                        "role": "tool",
                                                        "tool_call_id": tc.get("id")
                                                        or "http1",
                                                        "name": name,
                                                        "content": fetched[:4000],
                                                    }
                                                )
                                            except Exception:
                                                # ignore fetch errors
                                                pass
                                # Finalize
                                final_payload = {
                                    "model": model,
                                    "messages": messages,
                                    "temperature": 0.2,
                                }
                                async with httpx.AsyncClient(timeout=30) as client3:
                                    r3 = await client3.post(
                                        proxy_url,
                                        json={
                                            "plugin_id": "ai-core",
                                            "method": "POST",
                                            "url": target_url,
                                            "headers": headers,
                                            "json": final_payload,
                                            "timeout": 30,
                                        },
                                    )
                                if r3.status_code < 300:
                                    dj3 = r3.json() or {}
                                    text3_raw = dj3.get("text") or dj3.get("body") or ""
                                    try:
                                        parsed3 = (
                                            json.loads(text3_raw)
                                            if isinstance(text3_raw, str)
                                            else {}
                                        )
                                    except Exception:
                                        parsed3 = {}
                                    ch3 = ((parsed3 or {}).get("choices") or [{}])[0]
                                    msg3 = (ch3.get("message") or {}).get(
                                        "content"
                                    ) or ""
                                    if msg3:
                                        out3: Dict[str, Any] = {"result": msg3}
                                        if tools_log:
                                            out3["tools_used"] = tools_log
                                        return out3
                            # Non-tool flow
                            msg = (message or {}).get("content") or ""
                            if msg:
                                out: Dict[str, Any] = {"result": msg}
                                if tools_log:
                                    out["tools_used"] = tools_log
                                return out
                except Exception:
                    # Fall back to direct call
                    pass
                # Direct call fallback
                safe_base = (base_url or "https://api.openai.com").rstrip("/")
                url = f"{safe_base}/v1/chat/completions"
                headers = {
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                }
                async with httpx.AsyncClient(timeout=30) as client:
                    resp = await client.post(url, json=payload, headers=headers)
                if resp.status_code < 300:
                    data = resp.json()
                    choice = ((data or {}).get("choices") or [{}])[0]
                    resp_message: Dict[str, Any] = choice.get("message") or {}
                    # Handle tool-calls on direct path
                    if use_tools and resp_message.get("tool_calls"):
                        resp_tool_calls: List[Dict[str, Any]] = (
                            resp_message.get("tool_calls") or []
                        )
                        for tc in resp_tool_calls:
                            fn = tc.get("function") or {}
                            name = fn.get("name")
                            args_s = fn.get("arguments") or "{}"
                            try:
                                args = json.loads(args_s)
                            except Exception:
                                args = {}
                            if name == "rag_search":
                                q = str(args.get("q") or prompt)
                                tool_hits = await self.rag.query(
                                    q, top_k=5, user_traits=user_traits
                                )
                                messages.append(resp_message)
                                messages.append(
                                    {
                                        "role": "tool",
                                        "tool_call_id": tc.get("id") or "rag1",
                                        "name": name,
                                        "content": json.dumps({"hits": tool_hits}),
                                    }
                                )
                            elif name == "http_fetch":
                                fetch_url = str(args.get("url") or "")
                                if fetch_url:
                                    try:
                                        async with httpx.AsyncClient(
                                            timeout=20
                                        ) as client2:
                                            proxy_base = os.getenv(
                                                "PUBLIC_API_URL",
                                                "http://localhost:8000",
                                            ).rstrip("/")
                                            r2 = await client2.post(
                                                f"{proxy_base}/gateway/proxy",
                                                json={
                                                    "plugin_id": "ai-core",
                                                    "method": "GET",
                                                    "url": fetch_url,
                                                    "headers": {},
                                                    "timeout": 20,
                                                },
                                            )
                                        fetched = ""
                                        if r2.status_code < 300:
                                            dj = r2.json()
                                            fetched = (
                                                dj.get("text") or dj.get("body") or ""
                                            )
                                        messages.append(resp_message)
                                        messages.append(
                                            {
                                                "role": "tool",
                                                "tool_call_id": tc.get("id") or "http1",
                                                "name": name,
                                                "content": fetched[:4000],
                                            }
                                        )
                                    except Exception:
                                        pass
                        # Finalize direct call
                        final_payload = {
                            "model": model,
                            "messages": messages,
                            "temperature": 0.2,
                        }
                        async with httpx.AsyncClient(timeout=30) as client3:
                            r3 = await client3.post(
                                url, json=final_payload, headers=headers
                            )
                        if r3.status_code < 300:
                            data3 = r3.json() or {}
                            ch3 = ((data3 or {}).get("choices") or [{}])[0]
                            msg3 = (ch3.get("message") or {}).get("content") or ""
                            if msg3:
                                return {"result": msg3}
                    # Non-tool flow
                    msg = (resp_message or {}).get("content") or ""
                    if msg:
                        out4: Dict[str, Any] = {"result": msg}
                        if tools_log:
                            out4["tools_used"] = tools_log
                        return out4
                # Fallback to stub if non-2xx or empty
        except Exception:
            # Ignore; fall back to stub
            pass

        # Deterministic tool-calling fallback using internal RAG when enabled
        if locals().get("use_tools", False):
            tool_hits = await self.rag.query(prompt, top_k=5, user_traits=user_traits)
            items = "\n".join(
                [f"- {i+1}. {h.get('title')}" for i, h in enumerate(tool_hits)]
            )
            result = (
                "Tool-calling (simulated) via rag_search:\n" + items
                if items
                else "Tool-calling (simulated): no results"
            )
            out = {
                "result": result,
                "tools_used": [
                    {"name": "rag_search", "args": {"q": prompt}, "content": tool_hits}
                ],
            }
            return out

        return {
            "result": f"Stubbed agent response. Context sources:\n{context}".strip()
        }
