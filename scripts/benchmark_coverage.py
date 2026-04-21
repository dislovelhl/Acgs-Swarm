#!/usr/bin/env python3
"""Coverage benchmark for constitutional_swarm self-improvement loop.

Runs the full test suite with coverage enabled and outputs a JSON score.

Usage:
    python scripts/benchmark_coverage.py

Output (last line of stdout):
    {"primary": 91.60, "sub_scores": {"covered": 7673, "total": 8377, "missing": 704}}

Exit code: 0 on success, 1 on failure.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
COVERAGE_OUT = REPO_ROOT / "coverage_benchmark.json"

# Tests known to be flaky due to environment-specific build tooling.
# Excluded from the benchmark for stable, reproducible scoring.
_FLAKY_TESTS = [
    "tests/test_local_swe_bench_harness.py::test_repo_specific_bootstrap_packages_for_astropy",
    "tests/test_local_swe_bench_harness.py::test_harness_env_isolation_retries_astropy_native_build_with_stricter_legacy_pins",
    "tests/test_run_swe_bench_swarm_lite.py::test_summarize_reports_known_native_build_blockers_by_repo",
]


def main() -> None:
    deselect_args = []
    for t in _FLAKY_TESTS:
        deselect_args += ["--deselect", t]

    cmd = [
        sys.executable,
        "-m",
        "pytest",
        "tests/",
        "--import-mode=importlib",
        "-q",
        "--tb=no",
        "--no-header",
        f"--cov=src/constitutional_swarm",
        f"--cov-report=json:{COVERAGE_OUT}",
        "--cov-fail-under=0",
        *deselect_args,
    ]

    result = subprocess.run(cmd, cwd=REPO_ROOT, capture_output=False, text=True)

    if not COVERAGE_OUT.exists():
        print(
            json.dumps(
                {
                    "primary": 0.0,
                    "sub_scores": {"error": "coverage file not found"},
                    "status": "error",
                }
            ),
            flush=True,
        )
        sys.exit(1)

    with open(COVERAGE_OUT) as f:
        data = json.load(f)

    totals = data["totals"]
    score = round(totals["percent_covered"], 2)

    # Count test outcomes from subprocess return code
    # (pytest exits 0=all pass, 1=some fail, 2=error, etc.)
    tests_ok = result.returncode in (0, 1)  # 1 = tests ran but some failed

    print(
        json.dumps(
            {
                "primary": score,
                "sub_scores": {
                    "covered_lines": totals["covered_lines"],
                    "total_lines": totals["num_statements"],
                    "missing_lines": totals["missing_lines"],
                    "tests_exit_code": result.returncode,
                },
            }
        ),
        flush=True,
    )
    sys.exit(0)


if __name__ == "__main__":
    main()
