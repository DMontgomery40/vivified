from __future__ import annotations
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from vivified_core.kernel import Kernel, create_default_context

app = FastAPI(title="Vivi API", version="0.0.1")
_kernel = Kernel(create_default_context())

try:
    from hello_py.plugin import plugin as hello
    _kernel.register(hello)
except Exception:
    pass

class RunReq(BaseModel):
    plugin: str
    args: list[str] = []

@app.get("/health")
def health():
    return {"ok": True}

@app.get("/plugins")
def list_plugins():
    return {"plugins": _kernel.list()}

@app.post("/run")
def run(req: RunReq):
    try:
        code = _kernel.run(req.plugin, req.args)
        return {"ok": True, "code": code}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

def run():
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8787)
