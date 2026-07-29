"""Typed models for Ariadne's local Markdown knowledge base."""

from __future__ import annotations

import hashlib
import json
from enum import StrEnum
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class KnowledgeError(ValueError):
    """Raised when knowledge content is malformed or internally inconsistent."""


class ToolVerificationBlockedError(RuntimeError):
    """Raised when a tool card cannot be safely verified."""


class KnowledgeKind(StrEnum):
    """Canonical knowledge node kinds."""

    METHODOLOGY = "methodology"
    SERVICE = "service"
    TECHNIQUE = "technique"
    TOOL = "tool"
    SOURCE = "source"


class ToolDefinition(BaseModel):
    """Local commands and official fallback source declared by a tool node."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    executable: str = Field(min_length=1)
    version_args: tuple[str, ...] = ("--version",)
    help_args: tuple[str, ...] = ("--help",)
    official_source: str = Field(min_length=1)


class KnowledgeNode(BaseModel):
    """A canonical Markdown knowledge node."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: Literal[1]
    id: str = Field(pattern=r"^[a-z][a-z0-9_.-]+$")
    kind: KnowledgeKind
    title: str = Field(min_length=1)
    next: tuple[str, ...]
    requires: tuple[str, ...]
    policy: tuple[str, ...]
    provenance: tuple[str, ...]
    body: str = Field(min_length=1)
    source_path: Path
    url: str | None = None
    tool: ToolDefinition | None = None
    status: Literal["curated", "discovered", "runtime_verified"] | None = None
    version: str | None = None
    source_date: str | None = None
    documentation_source: str | None = None

    @model_validator(mode="after")
    def validate_kind_fields(self) -> KnowledgeNode:
        if self.kind == KnowledgeKind.TOOL and self.tool is None:
            raise ValueError("tool nodes require a tool definition")
        if self.kind == KnowledgeKind.TOOL and self.status is None:
            raise ValueError("tool nodes require a status")
        if self.kind != KnowledgeKind.TOOL and self.tool is not None:
            raise ValueError("only tool nodes may declare a tool definition")
        if self.kind == KnowledgeKind.SOURCE and not self.url:
            raise ValueError("source nodes require an official url")
        if self.kind == KnowledgeKind.SOURCE and self.url and not self.url.startswith(
            "https://"
        ):
            raise ValueError("official source URLs must use HTTPS")
        if self.kind != KnowledgeKind.SOURCE and self.url is not None:
            raise ValueError("only source nodes may declare a url")
        return self

    @property
    def digest(self) -> str:
        """Return a location-independent digest of canonical node content."""
        payload = self.model_dump(mode="json", exclude={"source_path"})
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class ToolCard(BaseModel):
    """JIT projection of one validated tool node."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str
    digest: str
    policy: frozenset[str]
    executable: str
    version_args: tuple[str, ...]
    help_args: tuple[str, ...]
    official_source_id: str
    official_source_url: str


class ToolDiscovery(BaseModel):
    """Curated metadata required to document a previously unknown tool."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    tool_id: str = Field(pattern=r"^tool\.[a-z][a-z0-9_.-]+$")
    title: str = Field(min_length=1, max_length=120)
    executable: str = Field(min_length=1, max_length=200)
    policy: tuple[str, ...]
    requires: tuple[str, ...] = ()
    official_source_id: str = Field(
        pattern=r"^source\.[a-z][a-z0-9_.-]+$"
    )
    official_source_url: str
    source_date: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}$")
    summary: str = Field(min_length=1, max_length=1000)
    version_args: tuple[str, ...] = ("--version",)
    help_args: tuple[str, ...] = ("--help",)

    @model_validator(mode="after")
    def validate_official_url(self) -> ToolDiscovery:
        if not self.official_source_url.startswith("https://"):
            raise ValueError("official source URLs must use HTTPS")
        return self


class RuntimeVerification(BaseModel):
    """Durable evidence that one immutable card worked in the local runtime."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: Literal[1] = 1
    tool_id: str
    card_digest: str
    status: Literal["documented", "runtime_verified"]
    executable_path: str
    version: str
    guidance: str
    guidance_source: Literal["local_help", "local_man", "official_provider"]
    verified_at: str
