"""Tests for the internal CVSS 3.1 calculator."""

from __future__ import annotations

import pytest

from ariadne.evidence.cvss import (
    CvssVector,
    vector_to_score,
    CvssParsingError,
)


# ---------------------------------------------------------------------------
# Vector parsing
# ---------------------------------------------------------------------------


def test_parses_standard_vector() -> None:
    vector = CvssVector.parse(
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    )
    assert vector.av == "N"
    assert vector.ac == "L"
    assert vector.pr == "N"
    assert vector.ui == "N"
    assert vector.s == "U"
    assert vector.c == "H"
    assert vector.i == "H"
    assert vector.a == "H"


def test_parses_low_severity_vector() -> None:
    vector = CvssVector.parse(
        "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"
    )
    assert vector.av == "P"
    assert vector.ui == "R"
    assert vector.c == "L"
    assert vector.i == "N"


def test_parses_changed_scope_vector() -> None:
    vector = CvssVector.parse(
        "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N"
    )
    assert vector.s == "C"
    assert vector.pr == "L"


def test_rejects_malformed_vector() -> None:
    with pytest.raises(CvssParsingError):
        CvssVector.parse("not-a-vector")


def test_rejects_empty_vector() -> None:
    with pytest.raises(CvssParsingError):
        CvssVector.parse("")


def test_rejects_vector_missing_required_metrics() -> None:
    with pytest.raises(CvssParsingError):
        CvssVector.parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H")


# ---------------------------------------------------------------------------
# Score computation
# ---------------------------------------------------------------------------


def test_computes_critical_score() -> None:
    vector = CvssVector.parse(
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    )
    score = vector_to_score(vector)
    assert score == pytest.approx(9.8, abs=0.3)


def test_computes_medium_score() -> None:
    vector = CvssVector.parse(
        "CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L"
    )
    score = vector_to_score(vector)
    assert score == pytest.approx(4.0, abs=0.5)


def test_computes_low_score() -> None:
    vector = CvssVector.parse(
        "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"
    )
    score = vector_to_score(vector)
    assert score == pytest.approx(1.5, abs=0.5)


# ---------------------------------------------------------------------------
# Severity rating
# ---------------------------------------------------------------------------


def test_severity_rating_critical() -> None:
    vector = CvssVector.parse(
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    )
    score = vector_to_score(vector)
    severity = vector.severity(score)
    assert severity == "CRITICAL"


def test_severity_rating_high() -> None:
    vector = CvssVector.parse(
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N"
    )
    score = vector_to_score(vector)
    severity = vector.severity(score)
    assert severity == "HIGH"


def test_severity_rating_medium() -> None:
    vector = CvssVector.parse(
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"
    )
    score = vector_to_score(vector)
    severity = vector.severity(score)
    assert severity == "MEDIUM"


def test_severity_rating_low() -> None:
    vector = CvssVector.parse(
        "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"
    )
    score = vector_to_score(vector)
    severity = vector.severity(score)
    assert severity == "LOW"


def test_severity_rating_none() -> None:
    vector = CvssVector.parse(
        "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N"
    )
    score = vector_to_score(vector)
    severity = vector.severity(score)
    assert severity == "NONE"


# ---------------------------------------------------------------------------
# Known vectors from published sources
# ---------------------------------------------------------------------------


def test_nvd_published_vector_match() -> None:
    """CVE-2023-44487 (HTTP/2 Rapid Reset) — CVSS:3.1 7.5 AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"""
    vector = CvssVector.parse(
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
    )
    score = vector_to_score(vector)
    assert score == pytest.approx(7.5, abs=0.3)


def test_heartbleed_vector() -> None:
    """CVE-2014-0160 (Heartbleed) — CVSS:3.1 7.5 AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"""
    vector = CvssVector.parse(
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
    )
    score = vector_to_score(vector)
    assert score == pytest.approx(7.5, abs=0.3)


# ---------------------------------------------------------------------------
# Vector serialization
# ---------------------------------------------------------------------------


def test_vector_roundtrip_serialization() -> None:
    vector_str = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    vector = CvssVector.parse(vector_str)
    assert vector.to_vector_string() == vector_str


def test_vector_custom_serialization() -> None:
    vector = CvssVector(
        av="N", ac="L", pr="L", ui="R", s="C", c="L", i="L", a="N"
    )
    expected = "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N"
    assert vector.to_vector_string() == expected


# ---------------------------------------------------------------------------
# Score agreement (CVSS recalculation invariant)
# ---------------------------------------------------------------------------


def test_score_and_vector_agree() -> None:
    """After computing a score, re-parsing the vector should give the same score."""
    vector_str = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    v1 = CvssVector.parse(vector_str)
    s1 = vector_to_score(v1)
    v2 = CvssVector.parse(v1.to_vector_string())
    s2 = vector_to_score(v2)
    assert s1 == pytest.approx(s2, abs=0.001)
