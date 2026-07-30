#!/usr/bin/env python3
"""Minimal OpenSSH askpass bridge for one protected Ariadne secret file."""

from __future__ import annotations

import os
import stat
from pathlib import Path


def main() -> int:
    raw_path = os.environ.get("ARIADNE_SECRET_FILE", "")
    if not raw_path:
        return 1
    path = Path(raw_path)
    try:
        mode = stat.S_IMODE(path.stat().st_mode)
        if not path.is_file() or mode & 0o077:
            return 1
        value = path.read_text(encoding="utf-8").rstrip("\r\n")
    except OSError:
        return 1
    if not value or "\n" in value or "\r" in value:
        return 1
    print(value)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
