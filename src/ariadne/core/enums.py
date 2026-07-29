"""Stable string enums for Ariadne's domain."""

from enum import StrEnum


class AutonomyMode(StrEnum):
    CONTROLLED = "controlled"
    FULL = "full"


class EnvironmentProfile(StrEnum):
    PRIVATE_LAB = "private-lab"
    HTB = "htb"


class EngagementState(StrEnum):
    """Legal states in the Ariadne engagement state machine."""

    # Primary flow
    IDLE = "idle"
    ENGAGEMENT_DRAFT = "engagement_draft"
    AWAITING_CONFIRMATION = "awaiting_confirmation"
    SNAPSHOT_LOCKED = "snapshot_locked"
    ENVIRONMENT_PREFLIGHT = "environment_preflight"
    DISCOVERY = "discovery"
    ENUMERATION = "enumeration"
    HYPOTHESIS = "hypothesis"
    ACTION_PLANNING = "action_planning"
    AWAITING_APPROVAL = "awaiting_approval"
    AUTO_APPROVED = "auto_approved"
    EXECUTION = "execution"
    VALIDATION = "validation"
    FOOTHOLD = "foothold"
    POST_EXPLOITATION = "post_exploitation"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    OBJECTIVE_VALIDATION = "objective_validation"
    CLEANUP = "cleanup"
    REPORTING = "reporting"
    COMPLETE = "complete"

    # Side states
    SCOPE_AMENDMENT_REQUIRED = "scope_amendment_required"
    UNCURATED_POC_APPROVAL = "uncurated_poc_approval"
    HOST_INSTALLATION_APPROVAL = "host_installation_approval"
    PAUSED = "paused"
    BLOCKED = "blocked"
    FAILED = "failed"
    ABORTED = "aborted"


class AssetStatus(StrEnum):
    IN_SCOPE = "in_scope"
    SCOPE_CANDIDATE = "scope_candidate"
    OBSERVED_ONLY = "observed_only"


class FindingStatus(StrEnum):
    CANDIDATE = "candidate"
    VALIDATED = "validated"
    EXPLOITED = "exploited"
    FALSE_POSITIVE = "false_positive"
    INFORMATIONAL = "informational"
    POLICY_BLOCKED = "not_tested_due_to_policy"
