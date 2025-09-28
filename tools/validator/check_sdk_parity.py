import json
import sys
from pathlib import Path


def main() -> int:
    root = Path(__file__).resolve().parents[2]
    spec_path = root / "tools" / "validator" / "sdk_parity.json"
    spec = json.loads(spec_path.read_text())
    methods = set(spec["methods"]) if isinstance(spec.get("methods"), list) else set()

    # Python SDK
    py_client = root / "sdk" / "python" / "src" / "vivified_sdk" / "client.py"
    py_text = py_client.read_text() if py_client.exists() else ""
    py_ok = all((f"def {m}" in py_text or f" {m}(" in py_text) for m in methods)

    # Node SDK
    node_client = root / "sdk" / "nodejs" / "src" / "index.ts"
    node_text = node_client.read_text() if node_client.exists() else ""
    node_ok = all((f" {m}(" in node_text) for m in methods)

    # Go SDK
    go_client = root / "sdk" / "go" / "client.go"
    go_text = go_client.read_text() if go_client.exists() else ""
    # Map method names from spec to Go exported names
    go_map = {
        "publish_event": "PublishEvent",
        "subscribe": "Subscribe",
        "call_plugin": "CallPlugin",
        "call_external": "CallExternal",
        "get_config": "GetConfig",
        "set_config": "SetConfig",
    }
    go_ok = all((go_map[m] in go_text) for m in methods)

    if py_ok and node_ok and go_ok:
        print("Parity OK")
        return 0
    else:
        if not py_ok:
            print("Python SDK missing methods", file=sys.stderr)
        if not node_ok:
            print("Node SDK missing methods", file=sys.stderr)
        if not go_ok:
            print("Go SDK missing methods", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())


