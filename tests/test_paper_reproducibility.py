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
