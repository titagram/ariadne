import sys
from pathlib import Path

_SRC = Path(__file__).parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))


def __getattr__(name: str):
    if name == "register":
        _root_shim = sys.modules.pop("ariadne", None)
        try:
            import importlib

            mod = importlib.import_module("ariadne.composition")
            return mod.register
        finally:
            if _root_shim is not None:
                sys.modules["ariadne"] = _root_shim
    raise AttributeError(f"module 'ariadne' has no attribute {name!r}")


__all__ = ["register"]
