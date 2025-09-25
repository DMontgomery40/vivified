from __future__ import annotations
import json, os, tempfile, shutil
from typing import Any, TypedDict

class ViviState(TypedDict):
    traits: list[str]
    disabled: list[str]

def _default_path() -> str:
    return os.getenv("VIVI_STATE", os.path.join(os.getcwd(), "state", "state.json"))

def load_state(path: str | None = None) -> ViviState:
    p = path or _default_path()
    try:
        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)
        traits = [t for t in data.get("traits", []) if isinstance(t, str)]
        disabled = [d for d in data.get("disabled", []) if isinstance(d, str)]
        return {"traits": sorted(set(traits)), "disabled": sorted(set(disabled))}
    except FileNotFoundError:
        return {"traits": [], "disabled": []}

def save_state(state: ViviState, path: str | None = None) -> None:
    p = path or _default_path()
    os.makedirs(os.path.dirname(p), exist_ok=True)
    tmp = p + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2, sort_keys=True)
    shutil.move(tmp, p)

