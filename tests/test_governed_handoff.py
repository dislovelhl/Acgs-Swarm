from __future__ import annotations

import json
from pathlib import Path

import pytest

from constitutional_swarm.governed_handoff import (
    PolicyEngine,
    main,
    read_audit,
    run_task,
    verify_bundle,
)


def write_configs(root: Path) -> None:
    acgs = root / ".acgs"
    acgs.mkdir()
    (acgs / "constitution.yaml").write_text(
        r"""
schema_version: 1
policy:
  unknown_decisions: fail_closed
  protected_paths:
    - ".acgs/**"
    - "protected/**"
  secret_command_patterns:
    - '\b(cat|grep|rg)\b.*(\.env|secret|token)'
    - '\b(printenv|env)\b'
""",
        encoding="utf-8",
    )
    (acgs / "swarm.yaml").write_text(
        """
schema_version: 1
roles:
  proposer: {adapter: mock}
  executor: {adapter: mock}
  validator: {adapter: mock}
  observer: {adapter: mock}
adapters:
  mock: {}
""",
        encoding="utf-8",
    )


def test_task_cannot_execute_before_intake_policy_passes(tmp_path: Path) -> None:
    write_configs(tmp_path)
    task = tmp_path / "task.md"
    task.write_text("", encoding="utf-8")

    result = run_task(task, repo_root=tmp_path)

    assert result.final_state == "blocked"
    assert not (tmp_path / "output.txt").exists()
    bundle = json.loads(result.bundle_path.read_text(encoding="utf-8"))
    assert bundle["policy_decisions"][0]["gate"] == "intake"
    assert bundle["policy_decisions"][0]["outcome"] == "deny"


def test_unknown_policy_gate_fails_closed(tmp_path: Path) -> None:
    write_configs(tmp_path)
    engine = PolicyEngine(
        {"policy": {}},
        {"roles": {"executor": {}, "observer": {}, "proposer": {}, "validator": {}}},
        tmp_path,
    )

    decision = engine.decide("not_a_gate", "anything")

    assert decision.outcome == "deny"
    assert "fail closed" in decision.reason


def test_missing_role_assignments_fail_closed_at_intake(tmp_path: Path) -> None:
    write_configs(tmp_path)
    (tmp_path / ".acgs" / "swarm.yaml").write_text(
        "schema_version: 1\nroles:\n  executor: {adapter: mock}\n",
        encoding="utf-8",
    )
    task = tmp_path / "task.md"
    task.write_text(
        "task_id: missing-roles\nACGS_WRITE output.txt :: no", encoding="utf-8"
    )

    result = run_task(task, repo_root=tmp_path)

    bundle = json.loads(result.bundle_path.read_text(encoding="utf-8"))
    assert result.final_state == "blocked"
    assert bundle["policy_decisions"][0]["gate"] == "intake"
    assert bundle["policy_decisions"][0]["outcome"] == "deny"
    assert "missing role assignments" in bundle["policy_decisions"][0]["reason"]


def test_protected_path_edit_requires_human_review_after_test_proof(
    tmp_path: Path,
) -> None:
    write_configs(tmp_path)
    task = tmp_path / "task.md"
    task.write_text(
        "\n".join(
            [
                "task_id: protected-review",
                "ACGS_WRITE protected/config.txt :: changed",
                'ACGS_TEST python -c "print(1)"',
            ]
        ),
        encoding="utf-8",
    )

    result = run_task(task, repo_root=tmp_path)

    assert result.final_state == "human_review_required"
    assert not (tmp_path / "protected/config.txt").exists()
    bundle = json.loads(result.bundle_path.read_text(encoding="utf-8"))
    assert any(
        decision["gate"] == "file_write"
        and decision["outcome"] == "human_review_required"
        for decision in bundle["policy_decisions"]
    )
    assert bundle["tests_run"][0]["passed"] is True


def test_secret_reading_command_is_denied(tmp_path: Path) -> None:
    write_configs(tmp_path)
    (tmp_path / ".env").write_text("DUMMY_VALUE=[REDACTED]\n", encoding="utf-8")
    task = tmp_path / "task.md"
    task.write_text(
        "\n".join(
            [
                "task_id: secret-denied",
                "ACGS_TOOL cat .env",
                'ACGS_TEST python -c "print(1)"',
            ]
        ),
        encoding="utf-8",
    )

    result = run_task(task, repo_root=tmp_path)

    assert result.final_state == "blocked"
    bundle = json.loads(result.bundle_path.read_text(encoding="utf-8"))
    assert any(
        decision["gate"] == "tool_call" and decision["outcome"] == "deny"
        for decision in bundle["policy_decisions"]
    )


def test_write_directive_cannot_escape_repo_root(tmp_path: Path) -> None:
    write_configs(tmp_path)
    task = tmp_path / "task.md"
    task.write_text(
        "\n".join(
            [
                "task_id: outside-write-denied",
                "ACGS_WRITE ../outside.txt :: bad",
                'ACGS_TEST python -c "print(1)"',
            ]
        ),
        encoding="utf-8",
    )

    result = run_task(task, repo_root=tmp_path)

    assert result.final_state == "blocked"
    assert not (tmp_path.parent / "outside.txt").exists()
    bundle = json.loads(result.bundle_path.read_text(encoding="utf-8"))
    assert any(
        decision["gate"] == "file_write"
        and decision["outcome"] == "deny"
        and "escapes repository root" in decision["reason"]
        for decision in bundle["policy_decisions"]
    )
    assert bundle["file_changes"] == []


def test_test_proof_required_before_handoff(tmp_path: Path) -> None:
    write_configs(tmp_path)
    task = tmp_path / "task.md"
    task.write_text(
        "task_id: no-test\nACGS_WRITE output.txt :: changed", encoding="utf-8"
    )

    result = run_task(task, repo_root=tmp_path)

    assert result.final_state == "blocked"
    bundle = json.loads(result.bundle_path.read_text(encoding="utf-8"))
    assert any(
        decision["gate"] == "handoff"
        and decision["outcome"] == "deny"
        and "test proof" in decision["reason"]
        for decision in bundle["policy_decisions"]
    )


def test_one_passing_test_proof_allows_handoff(tmp_path: Path) -> None:
    write_configs(tmp_path)
    task = tmp_path / "task.md"
    task.write_text(
        "\n".join(
            [
                "task_id: happy-path",
                "ACGS_WRITE output/result.txt :: changed",
                'ACGS_TEST python -c "print(1)"',
            ]
        ),
        encoding="utf-8",
    )

    result = run_task(task, repo_root=tmp_path)

    assert result.final_state == "handoff_ready"
    bundle = json.loads(result.bundle_path.read_text(encoding="utf-8"))
    for key in [
        "constitution_hash",
        "workflow_hash",
        "task_metadata",
        "role_assignments",
        "policy_decisions",
        "tool_events",
        "file_changes",
        "tests_run",
        "final_state",
        "chain_hash",
    ]:
        assert key in bundle
    assert verify_bundle(result.bundle_path)["ok"] is True
    assert read_audit(result.audit_path)[-1]["event_hash"] == bundle["chain_hash"]


def test_bundle_verification_detects_broken_hash_chain(tmp_path: Path) -> None:
    write_configs(tmp_path)
    task = tmp_path / "task.md"
    task.write_text(
        'task_id: tamper-check\nACGS_WRITE output.txt :: ok\nACGS_TEST python -c "print(1)"',
        encoding="utf-8",
    )
    result = run_task(task, repo_root=tmp_path)
    bundle = json.loads(result.bundle_path.read_text(encoding="utf-8"))
    bundle["audit_path"] = str(tmp_path / "missing.audit.jsonl")
    bundle["audit_events"][1]["payload"]["task_hash"] = "tampered"
    tampered_bundle = tmp_path / "tampered.bundle.json"
    tampered_bundle.write_text(json.dumps(bundle, sort_keys=True), encoding="utf-8")

    verification = verify_bundle(tampered_bundle)

    assert verification["ok"] is False
    assert "event_hash mismatch" in verification["error"]


def test_cli_run_verify_and_pack(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    write_configs(tmp_path)
    task = tmp_path / "task.md"
    task.write_text(
        'task_id: cli-task\nACGS_WRITE output.txt :: ok\nACGS_TEST python -c "print(1)"',
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)

    assert main(["run", "--task", str(task)]) == 0
    assert main(["verify", "--bundle", ".acgs/evidence/cli-task.bundle.json"]) == 0
    assert main(["pack", "--task", "cli-task"]) == 0
