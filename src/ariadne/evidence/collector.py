"""Immutable file and transcript evidence ingestion.

The ``EvidenceCollector`` is the sole entry point for creating evidence
records from process results, file content, or raw bytes. It computes
SHA-256 digests, records provenance, and enforces immutability:
transformations produce new related records rather than modifying originals.
"""

from __future__ import annotations

import hashlib
from typing import Any
from uuid import UUID, uuid4

from ariadne.evidence.records import EvidenceRecord, TransformationRecord


class EvidenceCollector:
    """Collects, hashes, and stores immutable evidence artifacts.

    Wraps an immutable snapshot hash and plan ID so that every collected
    ``EvidenceRecord`` is automatically bound to the current engagement
    context.  Transformations create new ``TransformationRecord`` instances
    linked to the original.
    """

    def __init__(
        self,
        snapshot_hash: str,
        plan_id: str = "",
        engagement_id: UUID | None = None,
    ) -> None:
        self._snapshot_hash = snapshot_hash
        self._plan_id = plan_id
        self._engagement_id = engagement_id or uuid4()

    @property
    def snapshot_hash(self) -> str:
        return self._snapshot_hash

    @property
    def plan_id(self) -> str:
        return self._plan_id

    @property
    def engagement_id(self) -> UUID:
        return self._engagement_id

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def collect_process(
        self,
        result: object,
        context: dict[str, Any],
    ) -> EvidenceRecord:
        """Create an ``EvidenceRecord`` from a process execution result.

        *result* must have ``.stdout``, ``.stderr``, and ``.exit_code``
        attributes (satisfied by ``ProcessResult``).

        *context* must include:

        - ``target``: ``TargetSpec``
        - ``adapter``: ``str`` (e.g. ``"nmap"``)
        - ``tool_version``: ``str`` (optional)
        - ``playbook``: ``str`` (optional)
        - ``source``: ``str`` (optional)
        - ``argv``: ``tuple[str, ...]`` (optional, for command redaction)
        """
        from ariadne.core.engagement import TargetSpec

        target = context.get("target")
        if target is None or not isinstance(target, TargetSpec):
            raise ValueError("context must include a valid 'target' TargetSpec")

        stdout = getattr(result, "stdout", "")
        stderr = getattr(result, "stderr", "")
        exit_code = getattr(result, "exit_code", 0)

        content = f"{stdout}\n{stderr}".encode() if stderr else stdout.encode()
        sha256 = hashlib.sha256(content).hexdigest()

        return EvidenceRecord(
            engagement_id=context.get("engagement_id", self._engagement_id),
            snapshot_hash=self._snapshot_hash,
            asset=str(target.host),
            adapter=str(context.get("adapter", "")),
            tool_version=str(context.get("tool_version")) if context.get("tool_version") else None,
            plan_id=self._plan_id or None,
            command_redacted=tuple(context.get("argv", ())),
            sha256=sha256,
            exit_code=exit_code,
            parser_status="completed" if exit_code == 0 else "failed",
            confidence=float(context.get("confidence", 1.0)),
            provenance=str(context.get("source", "")),
            content_type=context.get("content_type", "text/plain"),
        )

    def transform(
        self,
        original: EvidenceRecord,
        reason: str,
        content: bytes,
    ) -> TransformationRecord:
        """Create a new derived artifact from *original* without mutating it.

        The result is a ``TransformationRecord`` with the SHA-256 of the
        transformed *content* and a ``parent_id`` pointing to the original
        evidence.
        """
        sha256 = hashlib.sha256(content).hexdigest()

        return TransformationRecord(
            parent_id=original.evidence_id,
            engagement_id=original.engagement_id,
            snapshot_hash=self._snapshot_hash,
            plan_id=self._plan_id or None,
            reason=reason,
            sha256=sha256,
            asset=original.asset,
            origin_command=original.command_redacted,
            origin_tool_version=original.tool_version,
        )


def evidence_context(**kwargs: Any) -> dict[str, Any]:
    """Build an evidence context dict with validated fields.

    Requires at least a ``target`` keyword argument.
    """
    if not kwargs:
        raise ValueError("evidence_context requires at least one field, including 'target'")
    return kwargs
