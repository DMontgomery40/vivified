from __future__ import annotations
from dataclasses import dataclass, field
from typing import Protocol, Any, Sequence, Mapping, Optional, runtime_checkable, Iterable

@dataclass
class ViviContext:
    env: Mapping[str, Optional[str]]
    traits: set[str] = field(default_factory=set)
    def log(self, *args: Any) -> None:
        print("[vivi]", *args)

@dataclass
class PluginInfo:
    name: str
    version: str
    capabilities: Sequence[str] = ()
    requires_traits: Iterable[str] = ()

@runtime_checkable
class ViviPlugin(Protocol):
    info: PluginInfo
    def init(self, ctx: ViviContext) -> None: ...
    def run(self, args: list[str], ctx: ViviContext) -> int | None: ...
