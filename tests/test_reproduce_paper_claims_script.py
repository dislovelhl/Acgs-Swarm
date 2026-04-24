from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

pytest.importorskip("torch")

_SCRIPT_PATH = Path(__file__).resolve().parent.parent / "scripts" / "reproduce_paper_claims.py"
_SPEC = importlib.util.spec_from_file_location("reproduce_paper_claims", _SCRIPT_PATH)
assert _SPEC is not None and _SPEC.loader is not None
_MODULE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_MODULE)


def _small_args(tmp_path: Path | None = None):
    parser = _MODULE.build_parser()
    argv = [
        "--seeds",
        "0",
        "--sizes",
        "10",
        "--cycles",
        "10",
        "--ablation-n",
        "5",
        "--ablation-cycles",
        "5",
        "--ablation-radii",
        "0.5,1.0",
        "--ablation-alphas",
        "0.0,0.1",
        "--ode-n",
        "5",
        "--ode-steps",
        "20",
        "--gossip-agents",
        "5",
        "--gossip-rounds",
        "4",
        "--gossip-artifacts",
        "1",
        "--gossip-partners",
        "2",
        "--swe-agents",
        "4",
        "--swe-tasks",
        "16",
        "--swe-warmup",
        "4",
        "--microbench-iterations",
        "1",
        "--microbench-n",
        "5",
    ]
    if tmp_path is not None:
        argv.extend(["--output", str(tmp_path / "claims.json")])
    return parser.parse_args(argv)


def test_reproducibility_suite_emits_claim_oriented_sections() -> None:
    payload = _MODULE.run_reproducibility_suite(_small_args())

    assert payload["pass"] is True
    assert payload["trust_variance"]["pass"] is True
    assert payload["ablation"]["pass"] is True
    assert payload["dp_calibration"]["pass"] is True
    assert payload["crdt_gossip"]["pass"] is True
    assert payload["byzantine_rejection"]["accepted_tampered"] == 0
    assert payload["synthetic_swe_bench"]["official_swe_bench_claimed"] is False
    assert payload["latency_microbenchmarks"]["ns_per_operation"]["cid_append"] > 0


def test_trust_variance_benchmark_keeps_birkhoff_and_residual_claims_separate() -> None:
    payload = _MODULE.trust_variance_benchmark(seeds=[0], sizes=[10], cycles=[10])
    rows = {(row["manifold"], row["n"]): row for row in payload["rows"]}

    assert rows[("birkhoff", 10)]["mean_retention"]["10"] < 0.01
    assert rows[("spectral", 10)]["mean_retention"]["10"] > 0.0
    assert rows[("spectral_residual", 10)]["mean_retention"]["10"] > 0.05


def test_cli_writes_json_output(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code = _MODULE.main(
        [
            "--seeds",
            "0",
            "--sizes",
            "10",
            "--cycles",
            "10",
            "--ablation-n",
            "5",
            "--ablation-cycles",
            "5",
            "--ablation-radii",
            "0.5,1.0",
            "--ablation-alphas",
            "0.0,0.1",
            "--ode-n",
            "5",
            "--ode-steps",
            "20",
            "--gossip-agents",
            "5",
            "--gossip-rounds",
            "4",
            "--gossip-artifacts",
            "1",
            "--gossip-partners",
            "2",
            "--swe-agents",
            "4",
            "--swe-tasks",
            "16",
            "--swe-warmup",
            "4",
            "--microbench-iterations",
            "1",
            "--microbench-n",
            "5",
            "--output",
            str(tmp_path / "claims.json"),
        ]
    )

    stdout_payload = json.loads(capsys.readouterr().out)
    file_payload = json.loads((tmp_path / "claims.json").read_text(encoding="utf-8"))
    assert code == 0
    assert stdout_payload == file_payload
    assert file_payload["pass"] is True
