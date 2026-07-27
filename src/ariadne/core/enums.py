"""Stable string enums for Ariadne's domain."""

from enum import StrEnum


class AutonomyMode(StrEnum):
    CONTROLLED = "controlled"
    FULL = "full"


class EnvironmentProfile(StrEnum):
    PRIVATE_LAB = "private-lab"
    HTB = "htb"


class AssetStatus(StrEnum):
    IN_SCOPE = "in_scope"
    OBSERVED_ONLY = "observed_only"


class FindingStatus(StrEnum):
    CANDIDATE = "candidate"
    VALIDATED = "validated"
    EXPLOITED = "exploited"
    FALSE_POSITIVE = "false_positive"
    INFORMATIONAL = "informational"
    POLICY_BLOCKED = "not_tested_due_to_policy"
