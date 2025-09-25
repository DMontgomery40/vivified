from __future__ import annotations
from typing import Sequence
from vivified_core.types import ViviPlugin, ViviContext, PluginInfo
from vivified_core.state import load_state, save_state

class _Manage(ViviPlugin):
    info = PluginInfo(name="manage", version="0.0.1", capabilities=("admin",), requires_traits=())

    def init(self, ctx: ViviContext) -> None:
        ctx.log("manage plugin ready")

    def run(self, args: list[str], ctx: ViviContext) -> int | None:
        # Commands:
        # manage traits set a,b,c
        # manage traits add x
        # manage traits remove y
        # manage plugins disable hello
        # manage plugins enable hello
        # manage show
        state = load_state()
        if not args or args[0] in ("help", "-h", "--help"):
            ctx.log("usage: manage (traits|plugins|show) ...")
            return 0

        if args[0] == "show":
            ctx.log(f"traits={state['traits']}")
            ctx.log(f"disabled={state['disabled']}")
            return 0

        if args[0] == "traits":
            if len(args) < 2:
                ctx.log("traits commands: set <csv> | add <t> | remove <t>")
                return 1
            sub = args[1]
            if sub == "set":
                vals = args[2] if len(args) > 2 else ""
                traits = [t.strip() for t in vals.split(",") if t.strip()]
                state["traits"] = sorted(set(traits))
                save_state(state)
                ctx.log(f"traits set -> {state['traits']}")
                return 0
            if sub == "add":
                if len(args) < 3: 
                    ctx.log("missing trait to add"); 
                    return 1
                t = args[2].strip()
                if t and t not in state["traits"]:
                    state["traits"].append(t)
                    state["traits"] = sorted(set(state["traits"]))
                    save_state(state)
                ctx.log(f"traits -> {state['traits']}")
                return 0
            if sub == "remove":
                if len(args) < 3:
                    ctx.log("missing trait to remove")
                    return 1
                t = args[2].strip()
                state["traits"] = [x for x in state["traits"] if x != t]
                save_state(state)
                ctx.log(f"traits -> {state['traits']}")
                return 0
            ctx.log("unknown traits subcommand")
            return 1

        if args[0] == "plugins":
            if len(args) < 3:
                ctx.log("plugins commands: disable <name> | enable <name>")
                return 1
            sub, name = args[1], args[2]
            if sub == "disable":
                if name not in state["disabled"]:
                    state["disabled"].append(name)
                    state["disabled"] = sorted(set(state["disabled"]))
                    save_state(state)
                ctx.log(f"disabled -> {state['disabled']}")
                return 0
            if sub == "enable":
                state["disabled"] = [x for x in state["disabled"] if x != name]
                save_state(state)
                ctx.log(f"disabled -> {state['disabled']}")
                return 0
            ctx.log("unknown plugins subcommand")
            return 1

        ctx.log("unknown manage command")
        return 1

plugin = _Manage()

