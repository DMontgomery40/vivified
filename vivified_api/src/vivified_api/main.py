from __future__ import annotations
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from vivified_core.kernel import Kernel, create_default_context
from vivified_core.state import load_state, save_state

app = FastAPI(title="Vivi API", version="0.0.1")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Load initial state and apply to context traits
_state = load_state()
_ctx = create_default_context()
# merge traits: env + persisted
_ctx.traits.update(_state.get("traits", []))
_kernel = Kernel(_ctx)

# Register built-in/native plugins
for modpath in ("hello_py.plugin", "manage_py.plugin"):
    try:
        mod = __import__(modpath, fromlist=["plugin"])
        _kernel.register(mod.plugin)  # type: ignore
    except Exception:
        pass

# Register externals listed in plugins.d (if any)
import os, glob, json
for cfg in glob.glob(os.path.join(os.getcwd(), "plugins.d", "*.json")):
    try:
        spec = json.load(open(cfg))
        for exe in spec.get("executables", []):
            try:
                _kernel.register_external(exe)
            except Exception:
                pass
    except Exception:
        pass

class RunReq(BaseModel):
    plugin: str
    args: list[str] = []

class StateUpdate(BaseModel):
    traits: list[str]
    disabled: list[str]

@app.get("/health")
def health():
    return {"ok": True, "traits": sorted(list(_ctx.traits))}

@app.get("/state")
def get_state():
    fresh = load_state()
    # reflect current env traits + persisted traits merged
    merged_traits = sorted(list(set(fresh.get("traits", [])) | set(_ctx.traits)))
    return {"traits": merged_traits, "disabled": fresh.get("disabled", [])}

@app.post("/state")
def set_state(req: StateUpdate):
    st = {"traits": sorted(set(req.traits)), "disabled": sorted(set(req.disabled))}
    save_state(st)
    # update live context traits
    _ctx.traits = set(st["traits"])
    return {"ok": True, "state": st}

@app.get("/plugins")
def list_plugins():
    disabled = set(load_state().get("disabled", []))
    allp = _kernel.list()
    visible = [p for p in allp if p not in disabled]
    return {"plugins": visible, "disabled": sorted(list(disabled))}

@app.post("/run")
def run(req: RunReq):
    disabled = set(load_state().get("disabled", []))
    if req.plugin in disabled:
        raise HTTPException(status_code=400, detail=f"plugin '{req.plugin}' is disabled")
    try:
        code = _kernel.run(req.plugin, req.args)
        return {"ok": True, "code": code}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

def run():
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8787)
