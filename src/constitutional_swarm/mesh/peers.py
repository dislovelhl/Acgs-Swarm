"""Peer assignment and manifold-support types for the Constitutional Mesh."""

from __future__ import annotations

import math
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class PeerAssignment:
    """A validation assignment linking a producer's output to peer validators."""

    assignment_id: str
    producer_id: str
    artifact_id: str
    content: str
    content_hash: str
    peers: tuple[str, ...]
    constitutional_hash: str
    timestamp: float
    is_recovered: bool = False


@dataclass
class _AgentInfo:
    agent_id: str
    domain: str
    reputation: float = 1.0
    validations_performed: int = 0
    validations_received: int = 0


def _trust_variance(matrix: tuple[tuple[float, ...], ...]) -> float:
    """Variance of matrix entries around their mean."""
    values = [value for row in matrix for value in row]
    if not values:
        return 0.0
    mean = sum(values) / len(values)
    return sum((value - mean) ** 2 for value in values) / len(values)


def _matrix_spectral_norm(
    matrix: tuple[tuple[float, ...], ...],
    *,
    max_iterations: int = 20,
    tol: float = 1e-8,
) -> float:
    """Estimate the matrix spectral norm via power iteration on M^T M."""
    n = len(matrix)
    if n == 0:
        return 0.0
    vector = [1.0 / math.sqrt(n)] * n
    sigma = 0.0
    for _ in range(max_iterations):
        mv = [sum(matrix[i][j] * vector[j] for j in range(n)) for i in range(n)]
        mtmv = [sum(matrix[j][i] * mv[j] for j in range(n)) for i in range(n)]
        new_norm = math.sqrt(sum(value * value for value in mtmv))
        if new_norm < 1e-14:
            return 0.0
        new_sigma = math.sqrt(new_norm)
        vector = [value / new_norm for value in mtmv]
        if abs(new_sigma - sigma) / (sigma + 1e-12) < tol:
            return new_sigma
        sigma = new_sigma
    return sigma


def _summarize_metric(
    metrics: list[dict[str, float | str]],
    key: str,
) -> dict[str, float]:
    """Return mean/min/max for one recorded shadow metric."""
    values = [float(metric[key]) for metric in metrics]
    return {
        "mean": sum(values) / len(values),
        "min": min(values),
        "max": max(values),
    }
