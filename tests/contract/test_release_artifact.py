"""Contract tests for the Ariadne v1 release artifact.

Verifies that every required operator-facing file exists, the release
archive excludes runtime artefacts and secrets, and packaging metadata
is internally consistent.
"""

from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

# ── Helpers ────────────────────────────────────────────────────────────────────

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="module")
def release_archive() -> zipfile.ZipFile:
    """Build an in-memory archive of the tree as ``git archive`` would."""
    import io
    import subprocess as sp

    proc = sp.run(
        ["git", "archive", "--format", "zip", "--output", "/dev/stdout", "HEAD"],
        capture_output=True,
        cwd=ROOT,
    )
    data = io.BytesIO(proc.stdout)
    return zipfile.ZipFile(data, "r")


# ── Existence tests ────────────────────────────────────────────────────────────

REQUIRED_RELEASE_FILES = [
    "README.md",
    "SECURITY.md",
    "LICENSE",
    "docs/architecture.md",
    "docs/operator-guide.md",
    "docs/policy-reference.md",
    "docs/adapter-development.md",
]


def test_release_contains_operator_and_security_contracts() -> None:
    """Every operator-facing release file exists on disk."""
    missing = [p for p in REQUIRED_RELEASE_FILES if not (ROOT / p).is_file()]
    assert not missing, f"Missing release files: {missing}"


def test_release_archive_excludes_runs_secrets_and_caches(
    release_archive: zipfile.ZipFile,
) -> None:
    """The git archive must not contain runs/, .env, or __pycache__ paths."""
    names = set(release_archive.namelist()) | _parent_dir_names(release_archive)
    problems: list[str] = []

    for name in sorted(names):
        if name.startswith("runs/"):
            problems.append(f"should not contain runs/: {name}")
        if ".env" in name:
            problems.append(f"should not contain .env files: {name}")
        if "__pycache__" in name:
            problems.append(f"should not contain __pycache__: {name}")

    assert not problems, "\n".join(problems)


def _parent_dir_names(archive: zipfile.ZipFile) -> set[str]:
    """ZipFile.names includes files but not the implied parent dir entries."""
    parents: set[str] = set()
    for name in archive.namelist():
        parts = name.split("/")
        for i in range(1, len(parts)):
            parents.add("/".join(parts[:i]) + "/")
    return parents


# ── Metadata consistency ───────────────────────────────────────────────────────


def test_pyproject_version_matches_plugin_yaml() -> None:
    """Version in pyproject.toml and plugin.yaml must agree."""
    import tomllib

    with (ROOT / "pyproject.toml").open("rb") as fh:
        pyproject = tomllib.load(fh)
    pyproject_ver = pyproject["project"]["version"]

    import yaml

    manifest = yaml.safe_load((ROOT / "plugin.yaml").read_text())
    plugin_ver = manifest["version"]

    assert pyproject_ver == plugin_ver, (
        f"Version mismatch: pyproject.toml={pyproject_ver}, "
        f"plugin.yaml={plugin_ver}"
    )
