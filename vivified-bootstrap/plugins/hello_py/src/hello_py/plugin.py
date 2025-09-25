from __future__ import annotations
from vivified_core.types import ViviPlugin, ViviContext, PluginInfo

class _Hello(ViviPlugin):
    info = PluginInfo(name="hello", version="0.0.1", capabilities=("demo",), requires_traits=())
    def init(self, ctx: ViviContext) -> None:
        ctx.log("hello_py initialized")
    def run(self, args: list[str], ctx: ViviContext) -> int | None:
        who = args[0] if args else "world"
        ctx.log(f"hello from Python, {who}!")
        return 0

plugin = _Hello()
