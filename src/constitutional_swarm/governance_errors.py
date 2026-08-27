"""Shared governance boundary exceptions without import cycles."""


class GovernanceBypassDenied(PermissionError):
    """Authority was requested outside the governed boundary."""
