from pathlib import Path
import sys

_SRC = Path(__file__).parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from ariadne.composition import register

__all__ = ["register"]
