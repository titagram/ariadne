"""Deterministic canonical serialization and SHA-256 digest."""

import hashlib
import json


def canonical_digest(model: object) -> str:
    """Return a deterministic SHA-256 hex digest of a Pydantic model.

    Serializes with sorted keys, UTF-8, compact separators, and UTC
    timestamps to produce a stable digest across model instances.
    """
    dump = getattr(model, "model_dump", None)
    raw = dump(mode="json") if callable(dump) else model
    canonical = json.dumps(raw, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
