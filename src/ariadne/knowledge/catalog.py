"""Strict Markdown/frontmatter loader and canonical index generator."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from uuid import uuid4

import yaml
from pydantic import ValidationError

from ariadne.knowledge.models import (
    KnowledgeError,
    KnowledgeKind,
    KnowledgeNode,
    ToolCard,
    ToolDiscovery,
)

_BASE_FIELDS = {
    "schema_version",
    "id",
    "kind",
    "title",
    "next",
    "requires",
    "policy",
    "provenance",
}
_KIND_FIELDS = {
    "url",
    "tool",
    "status",
    "version",
    "source_date",
    "documentation_source",
}


def _split_markdown(path: Path) -> tuple[dict[str, object], str]:
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        raise KnowledgeError(f"{path}: missing YAML frontmatter")
    try:
        closing = next(
            index
            for index, line in enumerate(lines[1:], start=1)
            if line.strip() == "---"
        )
    except StopIteration as exc:
        raise KnowledgeError(f"{path}: unterminated YAML frontmatter") from exc
    try:
        metadata = yaml.safe_load("\n".join(lines[1:closing]))
    except yaml.YAMLError as exc:
        raise KnowledgeError(f"{path}: invalid YAML frontmatter: {exc}") from exc
    if not isinstance(metadata, dict):
        raise KnowledgeError(f"{path}: frontmatter must be a mapping")
    body = "\n".join(lines[closing + 1 :]).strip()
    if not body:
        raise KnowledgeError(f"{path}: knowledge body must not be empty")
    return metadata, body


def _load_node(path: Path) -> KnowledgeNode:
    metadata, body = _split_markdown(path)
    unknown = set(metadata) - _BASE_FIELDS - _KIND_FIELDS
    if unknown:
        raise KnowledgeError(f"{path}: unknown frontmatter fields: {sorted(unknown)}")
    try:
        return KnowledgeNode.model_validate(
            {
                **metadata,
                "body": body,
                "source_path": path,
            }
        )
    except ValidationError as exc:
        raise KnowledgeError(f"{path}: invalid knowledge node: {exc}") from exc


class KnowledgeIndex:
    """Validated, deterministic index over a directory of knowledge nodes."""

    def __init__(self, root: Path, nodes: dict[str, KnowledgeNode]) -> None:
        self.root = root
        self.nodes = dict(nodes)
        self.digest = self._calculate_digest()

    @classmethod
    def load(cls, root: Path) -> KnowledgeIndex:
        """Load all Markdown nodes, reject duplicates and dangling references."""
        resolved_root = root.resolve()
        paths = sorted(resolved_root.rglob("*.md"))
        if not paths:
            raise KnowledgeError(f"{root}: no Markdown knowledge nodes found")

        nodes: dict[str, KnowledgeNode] = {}
        for path in paths:
            node = _load_node(path)
            if node.id in nodes:
                raise KnowledgeError(
                    f"duplicate knowledge id {node.id!r}: "
                    f"{nodes[node.id].source_path} and {path}"
                )
            nodes[node.id] = node

        for node in nodes.values():
            for relation, references in (
                ("next", node.next),
                ("requires", node.requires),
                ("provenance", node.provenance),
            ):
                for reference in references:
                    if reference not in nodes:
                        raise KnowledgeError(
                            f"{node.source_path}: {relation} references unknown id {reference!r}"
                        )
            for source_id in node.provenance:
                if nodes[source_id].kind != KnowledgeKind.SOURCE:
                    raise KnowledgeError(
                        f"{node.source_path}: provenance {source_id!r} is not a source node"
                    )
            if node.tool is not None:
                source = nodes.get(node.tool.official_source)
                if source is None or source.kind != KnowledgeKind.SOURCE:
                    raise KnowledgeError(
                        f"{node.source_path}: official_source "
                        f"{node.tool.official_source!r} is not a source node"
                    )

        return cls(resolved_root, nodes)

    def node(self, node_id: str) -> KnowledgeNode:
        try:
            return self.nodes[node_id]
        except KeyError as exc:
            raise KnowledgeError(f"unknown knowledge id {node_id!r}") from exc

    def tool_card(self, node_id: str) -> ToolCard:
        """Construct a tool card only when a caller requests that tool."""
        node = self.node(node_id)
        if node.kind != KnowledgeKind.TOOL or node.tool is None:
            raise KnowledgeError(f"{node_id!r} is not a tool node")
        source = self.node(node.tool.official_source)
        if source.url is None:
            raise KnowledgeError(f"{source.id!r} has no official URL")
        return ToolCard(
            id=node.id,
            digest=node.digest,
            policy=frozenset(node.policy),
            executable=node.tool.executable,
            version_args=node.tool.version_args,
            help_args=node.tool.help_args,
            official_source_id=source.id,
            official_source_url=source.url,
        )

    def discover_tool(self, discovery: ToolDiscovery) -> KnowledgeNode:
        """Create a concise canonical card for a previously unknown tool."""
        existing = self.nodes.get(discovery.tool_id)
        if existing is not None:
            if existing.kind != KnowledgeKind.TOOL:
                raise KnowledgeError(
                    f"{discovery.tool_id!r} already exists and is not a tool"
                )
            return existing
        for requirement in discovery.requires:
            if requirement not in self.nodes:
                raise KnowledgeError(
                    f"tool discovery requires unknown id {requirement!r}"
                )

        source = self.nodes.get(discovery.official_source_id)
        if source is not None and source.url != discovery.official_source_url:
            raise KnowledgeError(
                f"{discovery.official_source_id!r} has a different official URL"
            )
        if source is None:
            self._write_discovered_node(
                self.root / "sources" / f"{discovery.official_source_id[7:]}.md",
                {
                    "schema_version": 1,
                    "id": discovery.official_source_id,
                    "kind": "source",
                    "title": f"{discovery.title} official documentation",
                    "next": [],
                    "requires": [],
                    "policy": [],
                    "provenance": [],
                    "url": discovery.official_source_url,
                },
                f"Official upstream documentation for {discovery.title}.",
            )

        safe_name = discovery.tool_id[5:].replace(".", "-")
        self._write_discovered_node(
            self.root / "tools" / f"{safe_name}.md",
            {
                "schema_version": 1,
                "id": discovery.tool_id,
                "kind": "tool",
                "title": discovery.title,
                "next": [],
                "requires": list(discovery.requires),
                "policy": list(discovery.policy),
                "provenance": [discovery.official_source_id],
                "status": "discovered",
                "version": "runtime",
                "source_date": discovery.source_date,
                "documentation_source": "official",
                "tool": {
                    "executable": discovery.executable,
                    "version_args": list(discovery.version_args),
                    "help_args": list(discovery.help_args),
                    "official_source": discovery.official_source_id,
                },
            },
            discovery.summary,
        )
        refreshed = type(self).load(self.root)
        self.nodes = refreshed.nodes
        self.digest = refreshed.digest
        return self.node(discovery.tool_id)

    @staticmethod
    def _write_discovered_node(
        path: Path,
        metadata: dict[str, object],
        body: str,
    ) -> None:
        """Create one canonical Markdown node without overwriting existing data."""
        path.parent.mkdir(parents=True, exist_ok=True)
        rendered = (
            "---\n"
            + yaml.safe_dump(metadata, sort_keys=False).rstrip()
            + "\n---\n\n"
            + body.strip()
            + "\n"
        )
        temporary = path.with_name(f".{path.name}.{uuid4().hex}.tmp")
        try:
            with temporary.open("x", encoding="utf-8") as handle:
                handle.write(rendered)
                handle.flush()
                os.fsync(handle.fileno())
            try:
                os.link(temporary, path)
            except FileExistsError as exc:
                raise KnowledgeError(f"knowledge node already exists: {path}") from exc
        finally:
            temporary.unlink(missing_ok=True)

    def _calculate_digest(self) -> str:
        payload = [
            {"id": node_id, "digest": self.nodes[node_id].digest}
            for node_id in sorted(self.nodes)
        ]
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def write(self, output: Path) -> None:
        """Atomically write a compact, canonical JSON index."""
        payload = {
            "schema_version": 1,
            "digest": self.digest,
            "nodes": [
                {
                    "id": node_id,
                    "kind": self.nodes[node_id].kind.value,
                    "digest": self.nodes[node_id].digest,
                    "path": self.nodes[node_id].source_path.relative_to(self.root).as_posix(),
                }
                for node_id in sorted(self.nodes)
            ],
        }
        output.parent.mkdir(parents=True, exist_ok=True)
        temporary = output.with_name(f".{output.name}.{uuid4().hex}.tmp")
        try:
            with temporary.open("x", encoding="utf-8") as handle:
                json.dump(payload, handle, sort_keys=True, separators=(",", ":"))
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, output)
        finally:
            temporary.unlink(missing_ok=True)

    def promote_tool(self, record: object) -> KnowledgeNode:
        """Atomically promote a successfully used tool card in canonical Markdown."""
        from ariadne.knowledge.models import RuntimeVerification

        verification = RuntimeVerification.model_validate(record)
        if verification.status != "runtime_verified":
            raise KnowledgeError("Only successful runtime_verified records may promote")
        node = self.node(verification.tool_id)
        metadata, body = _split_markdown(node.source_path)
        metadata.update(
            {
                "status": "runtime_verified",
                "version": verification.version,
                "documentation_source": verification.guidance_source,
            }
        )
        temporary = node.source_path.with_name(
            f".{node.source_path.name}.{uuid4().hex}.tmp"
        )
        try:
            rendered = (
                "---\n"
                + yaml.safe_dump(metadata, sort_keys=False).rstrip()
                + "\n---\n\n"
                + body
                + "\n"
            )
            with temporary.open("x", encoding="utf-8") as handle:
                handle.write(rendered)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, node.source_path)
        finally:
            temporary.unlink(missing_ok=True)
        promoted = _load_node(node.source_path)
        self.nodes[promoted.id] = promoted
        self.digest = self._calculate_digest()
        return promoted
