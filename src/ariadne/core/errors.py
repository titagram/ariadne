"""Typed domain exceptions for Ariadne."""


class AriadneError(Exception):
    """Base exception for all Ariadne-specific errors."""


class EngagementError(AriadneError):
    """Raised when an engagement operation is invalid."""


class PolicyError(AriadneError):
    """Raised when a policy constraint blocks an action."""


class SnapshotError(EngagementError):
    """Raised when a snapshot invariant is violated."""


class ConfirmationError(EngagementError):
    """Raised when an engagement confirmation is invalid."""


class ScopeError(EngagementError):
    """Raised when a scope operation is invalid."""


class PolicyConfigurationError(PolicyError):
    """Raised when a policy document is malformed or fails validation."""


class TransitionDeniedError(AriadneError):
    """Raised when an engagement state transition is not permitted."""
