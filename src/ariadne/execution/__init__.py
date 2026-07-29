"""Typed process-authorization boundary for live adapter execution."""

from ariadne.execution.contracts import (
    ExecutionContract,
    ExecutionContractRegistry,
    ExecutionEnvelope,
    GuardedRuntime,
    ProcessAuthorizationError,
)

__all__ = [
    "ExecutionContract",
    "ExecutionContractRegistry",
    "ExecutionEnvelope",
    "GuardedRuntime",
    "ProcessAuthorizationError",
]
