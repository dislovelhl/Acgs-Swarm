"""Executable checks for paper claims not covered by module-level tests."""

from __future__ import annotations

import importlib
import math
from pathlib import Path

import pytest

pytest.importorskip("torch")

calibrate_sigma = importlib.import_module("constitutional_swarm.swarm_ode").calibrate_sigma


DELTA = 1e-5
RADIUS = 1.0
ROOT = Path(__file__).resolve().parents[1]


def _read(rel_path: str) -> str:
    return (ROOT / rel_path).read_text(encoding="utf-8")


def _gaussian_sigma(*, residual_alpha: float, epsilon: float) -> float:
    """Paper Eq. sigma with alpha=0 allowed for the baseline column."""
    if residual_alpha > 0.0:
        return calibrate_sigma(
            r=RADIUS,
            residual_alpha=residual_alpha,
            epsilon=epsilon,
            delta=DELTA,
        )

    sensitivity = 2.0 * (1.0 - residual_alpha) * RADIUS
    return sensitivity * math.sqrt(2.0 * math.log(1.25 / DELTA)) / epsilon


def test_ndss_09_standard_composition_matches_protocol_formula() -> None:
    """NDSS-09: k-round standard composition follows the protocol text."""
    per_round_epsilon = 0.25
    per_round_delta = 1e-6
    k_rounds = 16

    epsilon_total = per_round_epsilon * math.sqrt(2.0 * k_rounds * math.log(1.0 / per_round_delta))
    delta_total = k_rounds * per_round_delta

    assert epsilon_total == pytest.approx(5.256521769756932)
    assert delta_total == pytest.approx(1.6e-5)


def test_iclr_15_dp_noise_reductions_are_exact_percentages() -> None:
    """ICLR-15: residual alpha gives exact percentage sigma reductions."""
    for epsilon in (1.0, 2.0, 4.0, 8.0):
        baseline = _gaussian_sigma(residual_alpha=0.0, epsilon=epsilon)

        for alpha, expected_reduction in ((0.1, 0.10), (0.2, 0.20), (0.5, 0.50)):
            sigma = _gaussian_sigma(residual_alpha=alpha, epsilon=epsilon)
            reduction = 1.0 - (sigma / baseline)

            assert reduction == pytest.approx(expected_reduction)


def test_ndss_18_residual_reduces_sigma_by_ten_percent_at_epsilon_2() -> None:
    """NDSS-18: the epsilon=2 residual-vs-baseline ratio is reproducible."""
    baseline = _gaussian_sigma(residual_alpha=0.0, epsilon=2.0)
    residual = _gaussian_sigma(residual_alpha=0.1, epsilon=2.0)

    assert 1.0 - (residual / baseline) == pytest.approx(0.10)


def test_iclr_15_paper_dp_noise_table_absolute_values_match_calibration() -> None:
    """ICLR-15: the ICLR DP table uses the same formula as calibrate_sigma()."""
    expected = {
        1.0: {0.0: 9.69, 0.1: 8.72, 0.2: 7.75, 0.5: 4.84},
        2.0: {0.0: 4.84, 0.1: 4.36, 0.2: 3.88, 0.5: 2.42},
        4.0: {0.0: 2.42, 0.1: 2.18, 0.2: 1.94, 0.5: 1.21},
        8.0: {0.0: 1.21, 0.1: 1.09, 0.2: 0.97, 0.5: 0.61},
    }
    paper_text = _read("papers/iclr2027/sections/experiments.tex")

    for epsilon, alpha_values in expected.items():
        for alpha, paper_sigma in alpha_values.items():
            calibrated = _gaussian_sigma(residual_alpha=alpha, epsilon=epsilon)

            assert calibrated == pytest.approx(paper_sigma, abs=0.005)
            assert f"{paper_sigma:.2f}" in paper_text


def test_ndss_17_paper_dp_accuracy_table_matches_calibration() -> None:
    """NDSS-17: the NDSS DP table uses the same formula as calibrate_sigma()."""
    expected_theory = {1.0: 8.721, 2.0: 4.360, 4.0: 2.180, 8.0: 1.090}
    paper_text = _read("papers/ndss2027/sections/evaluation.tex")

    for epsilon, paper_sigma in expected_theory.items():
        calibrated = _gaussian_sigma(residual_alpha=0.1, epsilon=epsilon)

        assert calibrated == pytest.approx(paper_sigma, abs=0.0005)
        assert f"{paper_sigma:.3f}" in paper_text


def test_ndss_18_paper_absolute_sigma_values_match_calibration() -> None:
    """NDSS-18: absolute epsilon=2 values match implementation calibration."""
    baseline = _gaussian_sigma(residual_alpha=0.0, epsilon=2.0)
    residual = _gaussian_sigma(residual_alpha=0.1, epsilon=2.0)
    paper_text = _read("papers/ndss2027/sections/evaluation.tex")

    assert baseline == pytest.approx(4.84, abs=0.005)
    assert residual == pytest.approx(4.36, abs=0.005)
    assert "baseline\n$\\sigma = 4.84$" in paper_text
    assert "residual-injection\n$\\sigma = 4.36$" in paper_text


def test_ndss_10_matrix_noise_bound_uses_conservative_spectral_scale() -> None:
    """NDSS-10: matrix Gaussian noise uses the 2*sqrt(n) spectral-norm scale."""
    n_agents = 50
    sigma = RADIUS / (2.0 * math.sqrt(n_agents))

    assert 2.0 * sigma * math.sqrt(n_agents) == pytest.approx(RADIUS)
    assert "$\\sigma \\leq r/(2\\sqrt{n})$" in _read("papers/ndss2027/sections/protocol.tex")


def test_iclr_local_benchmark_claims_are_script_backed() -> None:
    """ICLR unsupported exact capacity claims must not appear as results."""
    files = [
        "papers/iclr2027/sections/abstract.tex",
        "papers/iclr2027/sections/introduction.tex",
        "papers/iclr2027/sections/experiments.tex",
        "papers/iclr2027/sections/conclusion.tex",
        "papers/iclr2027/figures/variance_comparison.tex",
    ]
    combined = "\n".join(_read(path) for path in files)

    for unsupported in ("2{,}656", "2656", "287\\%", "38\\%", "71\\%"):
        assert unsupported not in combined
    assert "topological-capacity benchmark is pending" not in combined
    assert "30-seed benchmark is pending" not in combined
    assert "Ablation benchmarks for radius and residual sensitivity are pending" not in combined
    assert "scripts/reproduce\\_paper\\_claims.py" in combined
    assert "projected-RK4 stability reproduced by harness" in combined


def test_ndss_external_benchmarks_are_not_reported_as_completed_results() -> None:
    """NDSS external SWE-bench numbers remain explicitly outside reported claims."""
    evaluation = _read("papers/ndss2027/sections/evaluation.tex")
    conclusion = _read("papers/ndss2027/sections/conclusion.tex")

    for unsupported in (
        "3.2 \\pm 0.4",
        "8.7 \\pm 1.2",
        "1{,}000",
        "15$--$30\\%",
        "$>100\\%$",
        "$1.2 \\pm 0.1$",
        "$0.025\\%$",
        "1018 tests",
    ):
        assert unsupported not in evaluation + conclusion
    assert "official\\_swe\\_bench\\_claimed=false" in evaluation
    assert "Official SWE-bench results are not claimed" in evaluation
    assert "Latency microbenchmarks\nare reproducible through the script" in evaluation
    assert (
        "Phase 2 regression tests cover CID\nintegrity, EEC convergence, and DP calibration"
        in conclusion
    )
    assert "scripts/reproduce\\_paper\\_claims.py" in conclusion


def test_claim_map_has_no_unmapped_or_xfail_rows() -> None:
    """Every listed paper claim has a passing artifact or explicit external non-claim."""
    claim_map = _read("docs/internal/claims_map.md")

    assert "| Total | 44 | 44 | 0 |" in claim_map
    assert "| unmapped |" not in claim_map
    assert "| mapped-xfail |" not in claim_map
    assert "Reproducibility Gaps" not in claim_map
from __future__ import annotations

import subprocess
import sys

from scripts.reproduce_paper_claims import (
    ICLR_UNMAPPED_IDS,
    NDSS_UNMAPPED_IDS,
    collect_evidence,
    summary,
)


def test_remaining_claim_registry_covers_all_previous_unmapped_claims() -> None:
    evidence = collect_evidence()
    claim_ids = {item.claim_id for item in evidence}

    assert claim_ids == ICLR_UNMAPPED_IDS | NDSS_UNMAPPED_IDS


def test_remaining_claim_reproducers_all_pass() -> None:
    evidence = collect_evidence()
    report = summary(evidence)

    assert report["total"] == 24
    assert report["passed"] == 22
    assert report["failed"] == 2
    assert report["failed_claim_ids"] == ["NDSS-20", "NDSS-21"]


def test_remaining_claims_carry_external_source_provenance() -> None:
    evidence = collect_evidence()

    assert all(item.external_source_present for item in evidence)
    assert all(item.source for item in evidence)


def test_pending_swebench_claims_are_explicitly_provisional() -> None:
    evidence = {item.claim_id: item for item in collect_evidence()}

    assert "PROVISIONAL" in evidence["NDSS-20"].note
    assert "PROVISIONAL" in evidence["NDSS-21"].note
    assert not evidence["NDSS-20"].passed
    assert not evidence["NDSS-21"].passed


def test_reproduce_paper_claims_cli_json() -> None:
    result = subprocess.run(  # noqa: S603 - fixed local script path and interpreter
        [
            sys.executable,
            "scripts/reproduce_paper_claims.py",
            "--json",
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    assert '"failed": 2' in result.stdout
    assert '"failed_claim_ids": [' in result.stdout
    assert '"total": 24' in result.stdout
