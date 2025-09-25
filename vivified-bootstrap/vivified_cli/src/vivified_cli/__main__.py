from __future__ import annotations
import os, glob, json
import typer
from vivified_core.kernel import Kernel, create_default_context

app = typer.Typer(add_completion=False, help="Vivi CLI")

def _kernel():
    ctx = create_default_context()
    k = Kernel(ctx)
    try:
        from hello_py.plugin import plugin as hello
        k.register(hello)
    except Exception:
        pass
    for cfg in glob.glob(os.path.join(os.getcwd(), "plugins.d", "*.json")):
        spec = json.load(open(cfg))
        for exe in spec.get("executables", []):
            try:
                k.register_external(exe)
            except Exception as e:
                ctx.log(f"skip external '{exe}': {e}")
    return k

@app.command()
def plugins():
    k = _kernel()
    for name in k.list():
        typer.echo(name)

@app.command()
def run(plugin: str, args: list[str] = typer.Argument(default_factory=list)):
    k = _kernel()
    code = k.run(plugin, args)
    raise typer.Exit(code)
