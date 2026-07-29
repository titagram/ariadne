"""Verified local index of the pinned official Nuclei template catalog."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path

import yaml

_CATALOG_DIR = Path(__file__).with_name("nuclei")
_LOCK_PATH = _CATALOG_DIR / "catalog.lock.yaml"
_TOKEN_RE = re.compile(r"[a-z0-9.]{3,}")
_GENERIC_TECHNOLOGY_TOKENS = frozenset(
    {
        "detect",
        "detection",
        "http",
        "https",
        "panel",
        "server",
        "service",
        "tech",
        "web",
        "version",
    }
)


class NucleiCatalogError(RuntimeError):
    """The pinned catalog is missing, corrupt, or cannot satisfy a request."""


@dataclass(frozen=True)
class NucleiTemplate:
    template_id: str
    path: str
    cves: tuple[str, ...]
    technologies: tuple[str, ...]
    provenance: str


class NucleiTemplateCatalog:
    """Load and select from a commit-pinned ProjectDiscovery index."""

    def __init__(
        self,
        *,
        revision: str,
        container_root: str,
        templates: tuple[NucleiTemplate, ...],
    ) -> None:
        self.revision = revision
        self.container_root = container_root.rstrip("/")
        self.templates = templates
        self._by_cve: dict[str, tuple[NucleiTemplate, ...]] = {}
        for template in templates:
            for cve in template.cves:
                self._by_cve.setdefault(cve.upper(), ())
                self._by_cve[cve.upper()] += (template,)

    @classmethod
    def load(
        cls,
        lock_path: Path = _LOCK_PATH,
    ) -> NucleiTemplateCatalog:
        lock = yaml.safe_load(lock_path.read_text())
        if not isinstance(lock, dict):
            raise NucleiCatalogError("Nuclei catalog lock is malformed")
        index = lock.get("index")
        if not isinstance(index, dict):
            raise NucleiCatalogError("Nuclei catalog lock has no index")
        index_path = lock_path.parent / str(index.get("path", ""))
        raw = index_path.read_bytes()
        actual = hashlib.sha256(raw).hexdigest()
        if actual != index.get("sha256"):
            raise NucleiCatalogError("Nuclei catalog index digest mismatch")
        payload = json.loads(raw)
        revision = str(lock.get("revision", ""))
        if payload.get("revision") != revision:
            raise NucleiCatalogError("Nuclei catalog revision mismatch")
        rows = payload.get("templates")
        if not isinstance(rows, list):
            raise NucleiCatalogError("Nuclei catalog templates are malformed")
        templates = tuple(
            NucleiTemplate(
                template_id=str(row["id"]),
                path=str(row["path"]),
                cves=tuple(str(item).upper() for item in row.get("cves", ())),
                technologies=tuple(str(item).casefold() for item in row.get("technologies", ())),
                provenance=str(row["provenance"]),
            )
            for row in rows
            if isinstance(row, dict)
        )
        return cls(
            revision=revision,
            container_root=str(lock.get("container_root", "")),
            templates=templates,
        )

    def select(
        self,
        *,
        cve_ids: tuple[str, ...],
        technologies: tuple[str, ...],
        maximum: int = 20,
    ) -> tuple[NucleiTemplate, ...]:
        """Select exact CVE templates, then narrowly matching tech detectors."""
        if maximum < 1:
            raise NucleiCatalogError("Template selection maximum must be positive")
        selected: dict[str, NucleiTemplate] = {}
        for cve in sorted({item.upper() for item in cve_ids if item}):
            for template in self._by_cve.get(cve, ()):
                selected.setdefault(template.path, template)
                if len(selected) >= maximum:
                    return tuple(selected.values())

        tokens = {
            token
            for value in technologies
            for token in _TOKEN_RE.findall(value.casefold())
            if token not in _GENERIC_TECHNOLOGY_TOKENS
        }
        if tokens:
            for template in self.templates:
                if not template.technologies:
                    continue
                template_tokens = set(template.technologies) - _GENERIC_TECHNOLOGY_TOKENS
                if template_tokens and template_tokens.issubset(tokens):
                    selected.setdefault(template.path, template)
                    if len(selected) >= maximum:
                        break
        return tuple(selected.values())

    def container_path(self, template: NucleiTemplate) -> str:
        path = Path(template.path)
        if path.is_absolute() or ".." in path.parts:
            raise NucleiCatalogError("Unsafe Nuclei template path")
        return f"{self.container_root}/{path.as_posix()}"
