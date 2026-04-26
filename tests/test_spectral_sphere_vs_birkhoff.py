"""Seeded MCFS regression comparison: SpectralSphere vs. Birkhoff collapse."""

from __future__ import annotations

import random

import pytest
from constitutional_swarm import GovernanceManifold, SpectralSphereManifold

SEEDS = (11, 29, 47)
N_AGENTS = 8
CYCLES = 25


def _seeded_updates(seed: int) -> list[tuple[int, int, float]]:
    rng = random.Random(seed)
    return [
        (i, j, rng.uniform(0.0, 1.0)) for i in range(N_AGENTS) for j in range(N_AGENTS) if i != j
    ]


def _trust_variance(matrix: tuple[tuple[float, ...], ...]) -> float:
    values = [value for row in matrix for value in row]
    mean = sum(values) / len(values)
    return sum((value - mean) ** 2 for value in values) / len(values)


def _numeric_rank(matrix: tuple[tuple[float, ...], ...], *, tol: float = 1e-5) -> int:
    rows = [list(row) for row in matrix]
    height = len(rows)
    width = len(rows[0])
    rank = 0

    for column in range(width):
        pivot = None
        pivot_abs = tol
        for row_idx in range(rank, height):
            candidate_abs = abs(rows[row_idx][column])
            if candidate_abs > pivot_abs:
                pivot = row_idx
                pivot_abs = candidate_abs
        if pivot is None:
            continue

        rows[rank], rows[pivot] = rows[pivot], rows[rank]
        pivot_value = rows[rank][column]
        rows[rank] = [value / pivot_value for value in rows[rank]]

        for row_idx in range(height):
            if row_idx == rank:
                continue
            factor = rows[row_idx][column]
            if abs(factor) <= tol:
                continue
            rows[row_idx] = [
                value - factor * rows[rank][idx] for idx, value in enumerate(rows[row_idx])
            ]
        rank += 1
        if rank == height:
            break

    return rank


@pytest.mark.parametrize("seed", SEEDS)
def test_spectral_sphere_preserves_rank_and_variance_vs_birkhoff(seed: int) -> None:
    updates = _seeded_updates(seed)
    spectral = SpectralSphereManifold(N_AGENTS, smoothing=0.0)
    birkhoff = GovernanceManifold(N_AGENTS)

    for from_agent, to_agent, delta in updates:
        spectral.update_trust(from_agent, to_agent, delta)
        birkhoff.update_trust(from_agent, to_agent, delta)

    spectral_initial_var = _trust_variance(spectral.trust_matrix)
    birkhoff_initial_var = _trust_variance(birkhoff.trust_matrix)
    assert spectral_initial_var > 0.0
    assert birkhoff_initial_var > 0.0

    spectral_current = spectral
    birkhoff_current = birkhoff
    for _ in range(CYCLES):
        spectral_current = spectral_current.compose(spectral, residual_alpha=0.1)
        birkhoff_current = birkhoff_current.compose(birkhoff)

    spectral_final = spectral_current.trust_matrix
    birkhoff_final = birkhoff_current.trust_matrix
    spectral_retention = _trust_variance(spectral_final) / spectral_initial_var
    birkhoff_retention = _trust_variance(birkhoff_final) / birkhoff_initial_var

    assert spectral_retention > 0.10
    assert _numeric_rank(spectral_final) == N_AGENTS
    assert birkhoff_retention <= 1e-12
    assert _numeric_rank(birkhoff_final) == 1
