"""Append-only, hash-chained JSONL writer and reader.

Each line is a JSON object with a cryptographic hash chain so that
tampering with any past event is detectable on re-read::

    {
      "sequence": 1,
      "previous_event_hash": "0000...0000",
      "event_hash": "abc123...",
      "event_type": "snapshot_locked",
      "payload": { ... },
      "timestamp": "2026-07-27T21:00:00+00:00"
    }

The ``event_hash`` is computed as::

    content_hash = sha256(seq + ":" + event_type + ":" + payload_json + ":" + timestamp)
    event_hash = sha256(prev_hash + ":" + content_hash)

Writing is atomic: content is written to a temporary file in the same
directory, flushed, fsynced, then ``os.replace``'d over the target.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any

# Sentinel for the first event in the chain.
_ZERO_HASH = "0" * 64


def _content_hash(sequence: int, event_type: str, payload: dict, timestamp: str) -> str:
    """Deterministic SHA-256 of the event body (excluding chain linkage)."""
    payload_canonical = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    body = f"{sequence}:{event_type}:{payload_canonical}:{timestamp}"
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def _event_hash(previous_event_hash: str, content_hash: str) -> str:
    """Chain hash: combine previous link with this event's content."""
    return hashlib.sha256(f"{previous_event_hash}:{content_hash}".encode()).hexdigest()


class JsonlEvent:
    """One hydrated event from a JSONL file."""

    __slots__ = (
        "sequence", "previous_event_hash", "event_hash",
        "event_type", "payload", "timestamp",
    )

    def __init__(
        self,
        sequence: int,
        previous_event_hash: str,
        event_hash: str,
        event_type: str,
        payload: dict,
        timestamp: str,
    ) -> None:
        self.sequence = sequence
        self.previous_event_hash = previous_event_hash
        self.event_hash = event_hash
        self.event_type = event_type
        self.payload = payload
        self.timestamp = timestamp

    def to_dict(self) -> dict[str, Any]:
        return {
            "sequence": self.sequence,
            "previous_event_hash": self.previous_event_hash,
            "event_hash": self.event_hash,
            "event_type": self.event_type,
            "payload": self.payload,
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, data: dict) -> JsonlEvent:
        return cls(
            sequence=data["sequence"],
            previous_event_hash=data["previous_event_hash"],
            event_hash=data["event_hash"],
            event_type=data["event_type"],
            payload=data.get("payload", {}),
            timestamp=data["timestamp"],
        )

    def verify_hash(self) -> bool:
        """Check that ``event_hash`` matches recomputation."""
        content = _content_hash(self.sequence, self.event_type, self.payload, self.timestamp)
        expected = _event_hash(self.previous_event_hash, content)
        return self.event_hash == expected


def build_event(
    sequence: int,
    previous_event_hash: str,
    event_type: str,
    payload: dict,
    timestamp: str,
) -> JsonlEvent:
    """Construct a JsonlEvent with the correct hash chain linkage."""
    content = _content_hash(sequence, event_type, payload, timestamp)
    evt_hash = _event_hash(previous_event_hash, content)
    return JsonlEvent(
        sequence=sequence,
        previous_event_hash=previous_event_hash,
        event_hash=evt_hash,
        event_type=event_type,
        payload=payload,
        timestamp=timestamp,
    )


def append_event(path: Path, event: JsonlEvent) -> None:
    """Atomically append one JSONL line to *path*.

    Reads existing content (if any), prepends it, and writes the new
    event line at the end.  Writes through a temporary file in the same
    directory, flushes, fsyncs, then ``os.replace`` for an atomic commit.
    """
    line = json.dumps(event.to_dict(), ensure_ascii=False, separators=(",", ":")) + "\n"
    dir_path = path.parent
    dir_path.mkdir(parents=True, exist_ok=True)

    # Read old content if the file already exists
    old_content = path.read_bytes() if path.exists() else b""

    fd, tmp_path = tempfile.mkstemp(dir=str(dir_path), prefix=".jsonl_tmp_")
    try:
        # Write old content first, then the new line
        os.write(fd, old_content)
        os.write(fd, line.encode("utf-8"))
        os.fsync(fd)
    finally:
        os.close(fd)

    os.replace(tmp_path, path)


def read_all(path: Path) -> list[JsonlEvent]:
    """Read *all* JSONL lines from *path*.

    Returns events in file order (oldest first).
    """
    if not path.is_file():
        return []
    events: list[JsonlEvent] = []
    for line in path.read_text().strip().split("\n"):
        line = line.strip()
        if not line:
            continue
        data = json.loads(line)
        events.append(JsonlEvent.from_dict(data))
    return events


def verify_chain(path: Path) -> tuple[bool, list[str]]:
    """Verify the hash chain integrity of a JSONL file.

    Returns ``(valid, errors)`` where *valid* is ``True`` iff every
    event's hash matches and the sequence is contiguous from 1.
    """
    events = read_all(path)
    if not events:
        return True, ["no events to verify"]

    errors: list[str] = []

    for i, evt in enumerate(events):
        expected_sequence = i + 1
        if evt.sequence != expected_sequence:
            errors.append(
                f"Sequence gap at index {i}: expected {expected_sequence}, got {evt.sequence}"
            )

        if i == 0 and evt.previous_event_hash != _ZERO_HASH:
            errors.append(
                f"First event has non-zero previous_event_hash: {evt.previous_event_hash}"
            )

        if i > 0:
            expected_prev = events[i - 1].event_hash
            if evt.previous_event_hash != expected_prev:
                errors.append(
                    f"Hash chain break at sequence {evt.sequence}: "
                    f"expected previous hash {expected_prev}, got {evt.previous_event_hash}"
                )

        # Always verify the event's own hash recomputes correctly
        if not evt.verify_hash():
            errors.append(f"Event at sequence {evt.sequence} has invalid event_hash")

    if not errors:
        return True, []

    return False, errors
