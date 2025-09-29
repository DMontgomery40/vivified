"""
Durable delivery backends for direct messages.

Current implementation: Redis Streams based durable queue with consumer group
and ack/retry. Enabled via env MESSAGE_DELIVERY_BACKEND=redis_streams.

Env variables:
  - MESSAGE_DELIVERY_BACKEND: memory (default) | redis_streams
  - MESSAGE_REDIS_URL: optional override; defaults to REDIS_URL
  - MESSAGE_STREAM_KEY: stream key, default 'msg:direct'
  - MESSAGE_GROUP: consumer group, default 'core'
  - MESSAGE_CONSUMER_ID: consumer name, default 'core-1'
  - MESSAGE_RETRY_IDLE_MS: claim pending after idle ms, default 60000
  - MESSAGE_STREAM_MAXLEN: approximate trim length, default 10000
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from typing import Any, Awaitable, Callable, Optional

logger = logging.getLogger(__name__)


class DurableBackend:
    async def start(self, deliver_cb: Callable[[Any, str], Awaitable[None]]) -> None:  # pragma: no cover - interface
        raise NotImplementedError

    async def stop(self) -> None:  # pragma: no cover - interface
        raise NotImplementedError

    async def enqueue(self, message: Any, source_plugin: str) -> None:  # pragma: no cover - interface
        raise NotImplementedError


class RedisStreamsDurable(DurableBackend):
    def __init__(self) -> None:
        self._url = os.getenv("MESSAGE_REDIS_URL") or os.getenv("REDIS_URL", "redis://127.0.0.1:6379/0")
        self._stream = os.getenv("MESSAGE_STREAM_KEY", "msg:direct")
        self._group = os.getenv("MESSAGE_GROUP", "core")
        self._consumer = os.getenv("MESSAGE_CONSUMER_ID", "core-1")
        self._retry_idle_ms = int(os.getenv("MESSAGE_RETRY_IDLE_MS", "60000") or 60000)
        self._maxlen = int(os.getenv("MESSAGE_STREAM_MAXLEN", "10000") or 10000)
        self._redis: Optional[Any] = None
        self._task: Optional[asyncio.Task] = None
        self._deliver_cb: Optional[Callable[[Any, str], Awaitable[None]]] = None

    async def start(self, deliver_cb: Callable[[Any, str], Awaitable[None]]) -> None:
        import redis.asyncio as redis  # type: ignore

        self._deliver_cb = deliver_cb
        self._redis = redis.from_url(self._url)
        try:
            # Create consumer group if not exists
            await self._redis.xgroup_create(name=self._stream, groupname=self._group, id="$", mkstream=True)  # type: ignore[attr-defined]
        except Exception:
            # Group probably exists
            pass

        async def _loop():
            assert self._redis is not None
            while True:
                try:
                    # First try new messages
                    msgs = await self._redis.xreadgroup(
                        groupname=self._group,
                        consumername=self._consumer,
                        streams={self._stream: ">"},
                        count=10,
                        block=2000,
                    )
                    if msgs:
                        for _stream_key, entries in msgs:
                            for mid, fields in entries:
                                await self._handle_entry(mid, fields)
                    else:
                        # No new messages; reclaim pending idle ones
                        await self._reclaim_pending()
                except asyncio.CancelledError:
                    break
                except Exception:
                    logger.debug("redis durable loop error", exc_info=True)
                    await asyncio.sleep(1.0)

        self._task = asyncio.create_task(_loop())

    async def stop(self) -> None:
        if self._task is not None:
            try:
                self._task.cancel()
                await self._task
            except Exception:
                pass
            self._task = None
        if self._redis is not None:
            try:
                await self._redis.close()
            except Exception:
                pass
            self._redis = None

    async def enqueue(self, message: Any, source_plugin: str) -> None:
        data = json.dumps({"message": message, "source_plugin": source_plugin})
        assert self._redis is not None, "durable backend not started"
        try:
            # XADD with approximate maxlen to bound memory
            await self._redis.xadd(name=self._stream, id="*", fields={"d": data}, maxlen=self._maxlen, approximate=True)  # type: ignore[attr-defined]
        except Exception:
            logger.debug("redis enqueue failed", exc_info=True)
            raise

    async def _handle_entry(self, mid: str, fields: Any) -> None:
        assert self._redis is not None
        if self._deliver_cb is None:
            return
        try:
            raw = fields.get("d")
            if isinstance(raw, bytes):
                raw = raw.decode("utf-8")
            obj = json.loads(raw or "{}")
            msg = obj.get("message") or {}
            src = obj.get("source_plugin") or "unknown"
            await self._deliver_cb(msg, str(src))
            # On success, ack and trim (optionally delete)
            await self._redis.xack(self._stream, self._group, mid)  # type: ignore[attr-defined]
            try:
                await self._redis.xdel(self._stream, mid)  # type: ignore[attr-defined]
            except Exception:
                pass
        except Exception:
            # Leave in PEL for retry via reclaim
            logger.debug("redis entry handle failed", exc_info=True)

    async def _reclaim_pending(self) -> None:
        assert self._redis is not None
        try:
            # Fetch some pending entries older than retry_idle_ms
            pend = await self._redis.xpending_range(
                name=self._stream,
                groupname=self._group,
                min="-",
                max="+",
                count=10,
                consumername=self._consumer,
            )
            # Claim if idle long enough
            claim_ids = []
            for p in pend or []:
                try:
                    idle = int(getattr(p, "idle", self._retry_idle_ms + 1))
                    mid = getattr(p, "message_id", None)
                    if mid and idle >= self._retry_idle_ms:
                        claim_ids.append(mid)
                except Exception:
                    continue
            if claim_ids:
                entries = await self._redis.xclaim(
                    name=self._stream,
                    groupname=self._group,
                    consumername=self._consumer,
                    min_idle_time=self._retry_idle_ms,
                    message_ids=claim_ids,
                )
                for mid, fields in entries or []:
                    await self._handle_entry(mid, fields)
        except Exception:
            logger.debug("redis reclaim failed", exc_info=True)


def select_durable_from_env() -> Optional[DurableBackend]:
    backend = (os.getenv("MESSAGE_DELIVERY_BACKEND") or "memory").lower()
    if backend == "redis_streams":
        try:
            return RedisStreamsDurable()
        except Exception:  # pragma: no cover - import/runtime errors
            logger.debug("failed to init RedisStreamsDurable", exc_info=True)
            return None
    # Future: nats_jetstream
    return None

