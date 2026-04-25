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
    assert report["passed"] == 24
    assert report["failed"] == 0
    assert report["failed_claim_ids"] == []


def test_reproduce_paper_claims_cli_json() -> None:
    result = subprocess.run(  # noqa: S603 - fixed local script path and interpreter
        [
            sys.executable,
            "scripts/reproduce_paper_claims.py",
            "--json",
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    assert '"failed": 0' in result.stdout
    assert '"total": 24' in result.stdout
