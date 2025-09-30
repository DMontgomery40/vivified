from pathlib import Path
import sys


def _ensure_sdk_python_on_path() -> None:
    repo_root = Path(__file__).resolve().parent
    sdk_python_src = repo_root / "sdk" / "python" / "src"
    sdk_path_str = str(sdk_python_src)
    if sdk_python_src.exists() and sdk_path_str not in sys.path:
        sys.path.insert(0, sdk_path_str)


_ensure_sdk_python_on_path()


