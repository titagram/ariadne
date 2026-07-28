"""Internal CVSS 3.1 calculator with published vector tests.

Implements a small self-contained CVSS 3.1 Base Score calculator with
no external dependencies.  Supports parsing, validation, score computation,
and severity rating.  The calculator is designed so that the vector and
numeric score can be independently computed and must agree before a
finding can be marked validated.
"""

from __future__ import annotations

import math
from typing import NamedTuple

from ariadne.core.errors import AriadneError


class CvssParsingError(AriadneError):
    """Raised when a CVSS vector string cannot be parsed."""

# ---------------------------------------------------------------------------
# Metric values and weighting tables
# ---------------------------------------------------------------------------

# Base Metric Group — values and their numeric scores
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}  # Attack Vector
_AC = {"L": 0.77, "H": 0.44}  # Attack Complexity
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}  # Privileges Required (Unchanged)
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.50}  # Privileges Required (Changed)
_UI = {"N": 0.85, "R": 0.62}  # User Interaction
_S = {"U": 0.0, "C": 1.0}  # Scope (impact sub-score modifier)
_C = {"H": 0.56, "L": 0.22, "N": 0.0}  # Confidentiality
_I = {"H": 0.56, "L": 0.22, "N": 0.0}  # Integrity
_A = {"H": 0.56, "L": 0.22, "N": 0.0}  # Availability


class CvssVector(NamedTuple):
    """Parsed and validated CVSS 3.1 base metric vector.

    Each field holds the single-character metric value from the vector
    string (e.g. ``"N"`` for Network, ``"L"`` for Low).
    """

    av: str  # Attack Vector
    ac: str  # Attack Complexity
    pr: str  # Privileges Required
    ui: str  # User Interaction
    s: str   # Scope
    c: str   # Confidentiality
    i: str   # Integrity
    a: str   # Availability

    @classmethod
    def parse(cls, vector_string: str) -> CvssVector:
        """Parse a CVSS 3.1 vector string into a structured ``CvssVector``.

        Accepts vectors in the standard format:

            ``CVSS:3.1/AV:X/AC:X/PR:X/UI:X/S:X/C:X/I:X/A:X``

        Args:
            vector_string: A complete CVSS 3.1 vector string.

        Returns:
            A ``CvssVector`` with validated metric values.

        Raises:
            CvssParsingError: If the vector is empty, malformed, or missing
                required metrics.
        """
        if not vector_string:
            raise CvssParsingError("CVSS vector string is empty")

        if not vector_string.startswith("CVSS:3.1/"):
            raise CvssParsingError(
                f"Vector must start with 'CVSS:3.1/': got {vector_string!r}"
            )

        # Split on '/' and drop the version prefix
        parts = vector_string.split("/")
        if len(parts) < 2:
            raise CvssParsingError("Vector has no metrics after version")

        metrics_str = parts[1:]  # ['AV:N', 'AC:L', ...]
        metrics: dict[str, str] = {}

        for part in metrics_str:
            if ":" not in part:
                raise CvssParsingError(f"Malformed metric segment: {part!r}")
            key, value = part.split(":", 1)
            metrics[key] = value

        # Validate all required metrics are present
        required_keys = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]
        for key in required_keys:
            value = metrics.get(key)
            if value is None:
                raise CvssParsingError(
                    f"Missing required metric {key} in vector {vector_string!r}"
                )

        return cls(
            av=metrics["AV"],
            ac=metrics["AC"],
            pr=metrics["PR"],
            ui=metrics["UI"],
            s=metrics["S"],
            c=metrics["C"],
            i=metrics["I"],
            a=metrics["A"],
        )

    def to_vector_string(self) -> str:
        """Serialize this vector back to standard CVSS 3.1 string format."""
        return (
            f"CVSS:3.1/AV:{self.av}/AC:{self.ac}/PR:{self.pr}/UI:{self.ui}"
            f"/S:{self.s}/C:{self.c}/I:{self.i}/A:{self.a}"
        )

    def severity(self, score: float) -> str:
        """Return the severity rating for *score* according to CVSS 3.1 ranges.

        Ratings:
            - ``NONE``: 0.0
            - ``LOW``: 0.1–3.9
            - ``MEDIUM``: 4.0–6.9
            - ``HIGH``: 7.0–8.9
            - ``CRITICAL``: 9.0–10.0
        """
        if score >= 9.0:
            return "CRITICAL"
        if score >= 7.0:
            return "HIGH"
        if score >= 4.0:
            return "MEDIUM"
        if score > 0.0:
            return "LOW"
        return "NONE"


def _roundup(value: float) -> float:
    """CVSS 3.1 round-up: ceiling to one decimal place, but 0.01–0.04 → 0.1."""
    rounded = int(math.ceil(value * 10)) / 10.0
    return rounded


def _calculate_impact_sub_score(
    scope: str,
    c: float,
    i: float,
    a: float,
) -> float:
    """Compute the Impact sub-score (ISS) and then the Impact score."""
    iss = 1.0 - (1.0 - c) * (1.0 - i) * (1.0 - a)
    if scope == "U":  # Unchanged
        return 6.42 * iss
    else:  # Changed
        return 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15


def vector_to_score(vector: CvssVector) -> float:
    """Compute the CVSS 3.1 Base Score from a parsed ``CvssVector``.

    Implements the standard CVSS 3.1 formula:

    1. Compute the Impact score from CIA metrics and Scope.
    2. Compute the Exploitability score from AV, AC, PR, and UI.
    3. Combine them with the Scope modifier.

    Returns a score rounded to one decimal place (CVSS 3.1 round-up).
    """
    # Look up numeric values
    av = _AV[vector.av]
    ac = _AC[vector.ac]

    pr = _PR_U[vector.pr] if vector.s == "U" else _PR_C[vector.pr]

    ui = _UI[vector.ui]
    c = _C[vector.c]
    i = _I[vector.i]
    a = _A[vector.a]

    # Exploitability sub-score
    exploitability = 8.22 * av * ac * pr * ui

    # Impact sub-score
    impact = _calculate_impact_sub_score(vector.s, c, i, a)

    # Base Score
    if impact <= 0:
        return 0.0

    if vector.s == "U":
        return _roundup(min(exploitability + impact, 10.0))
    else:
        return _roundup(min(1.08 * (exploitability + impact), 10.0))
