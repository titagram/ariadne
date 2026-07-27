"""Profile-scoped paths and permission helpers for the append-only run store.

Path layout::

    ${HERMES_HOME:-~/.hermes}/ariadne/
      active-sessions.json
      challenges/
      runs/<engagement-id>/
        engagement.lock.yaml
        events.jsonl
        artifacts/
          <uuid>.<ext>
"""

from __future__ import annotations

import os
import stat
from pathlib import Path
from uuid import UUID


def ariadne_home(override: Path | None = None) -> Path:
    """Return the Ariadne data root.

    Defaults to ``${HERMES_HOME:-~/.hermes}/ariadne/``.
    Pass ``override`` to substitute a different root (used in tests).
    """
    if override is not None:
        return override
    hermes_home = Path(os.environ.get("HERMES_HOME", Path.home() / ".hermes"))
    return hermes_home / "ariadne"


def run_dir(engagement_id: UUID, base: Path | None = None) -> Path:
    """Return the run directory path for a given engagement.

    Creates the directory tree if it does not exist.
    """
    root = ariadne_home(override=base)
    path = root / "runs" / engagement_id.hex
    path.mkdir(parents=True, exist_ok=True)
    return path


def set_strict_permissions(path: Path, mode: int) -> None:
    """Set exact permission bits on *path*, regardless of umask.

    Args:
        path: File or directory to modify.
        mode: Unix permission mode (e.g. ``0o700``, ``0o600``).
    """
    current = stat.S_IMODE(path.stat().st_mode)
    desired = mode & 0o777
    if current != desired:
        path.chmod(desired)


def safe_artifact_path(run_path: Path, artifact_id: UUID, extension: str) -> Path:
    """Generate a safe, non-symlink artifact file path.

    The filename is derived from the UUID and a safe extension only —
    never from user-supplied input.  The path is resolved so that
    symlinks in ancestors are detected.
    """
    artifacts_dir = run_path / "artifacts"
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    # Resolve to catch any symlink in the tree
    artifacts_dir = artifacts_dir.resolve()
    filename = f"{artifact_id.hex}.{extension.strip('.').lower()}"
    path = artifacts_dir / filename
    return path.resolve()
