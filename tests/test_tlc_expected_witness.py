from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path
from typing import cast

import pytest
import yaml

import scripts.run_tlc_expected_witness as witness
from scripts.run_tlc_expected_witness import (
    Outcome,
    TLC_JAR_SHA256,
    classify_tlc_result,
    run_tlc_expected_witness,
)


ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "scripts" / "run_tlc_expected_witness.py"


def _state(number: int, action: str, body: str) -> str:
    return f"State {number}: <{action} line 1, col 1 to line 1, col 2 of module governed_commit>\n{body}\n"


def _valid_output(*, whitespace: bool = False) -> str:
    sep = "   " if whitespace else " "
    return "\n".join(
        [
            "TLC2 Version 2.19 of 08 August 2024 (rev: 5a47802)",
            f"Parsing{sep}file /checkout/specs/governed_commit.tla",
            "Semantic processing of module governed_commit",
            "Starting... (2026-08-27 08:03:56)",
            "Computing initial states...",
            "Finished computing initial states: 1 distinct state generated at 2026-08-27 08:03:56.",
            "Error: Invariant CoverageGoalNotReached is violated.",
            "Error: The behavior up to this point is:",
            _state(1, "Initial predicate", "/\\ accepted = {}"),
            _state(2, "Claim", "/\\ accepted = {}"),
            _state(3, "ProduceResult", "/\\ accepted = {}"),
            _state(
                4,
                "TryCommit",
                '/\\ accepted = {c1}\n/\\ decisions = (c1 :> "committed")\n'
                "/\\ nodeCommit = (w1 :> (root :> c1 @@ child :> none @@ leaf :> none) @@ w2 :> (root :> none @@ child :> none @@ leaf :> none))\n"
                '/\\ status = (w1 :> (root :> "governed_committed" @@ child :> "ready" @@ leaf :> "blocked") @@ w2 :> (root :> "ready" @@ child :> "blocked" @@ leaf :> "blocked"))\n'
                "/\\ nodeExecutor = (w1 :> (root :> e1 @@ child :> noexecutor @@ leaf :> noexecutor) @@ w2 :> (root :> noexecutor @@ child :> noexecutor @@ leaf :> noexecutor))\n"
                "/\\ nodeAttempt = (w1 :> (root :> a1 @@ child :> noattempt @@ leaf :> noattempt) @@ w2 :> (root :> noattempt @@ child :> noattempt @@ leaf :> noattempt))",
            ),
            _state(5, "Claim", "/\\ accepted = {c1}"),
            _state(6, "ProduceResult", "/\\ accepted = {c1}"),
            _state(
                7,
                "TryCommit",
                '/\\ accepted = {c1, c3}\n/\\ decisions = (c1 :> "committed" @@ c3 :> "committed")\n'
                "/\\ nodeCommit = (w1 :> (root :> c1 @@ child :> c3 @@ leaf :> none) @@ w2 :> (root :> none @@ child :> none @@ leaf :> none))\n"
                '/\\ status = (w1 :> (root :> "governed_committed" @@ child :> "governed_committed" @@ leaf :> "ready") @@ w2 :> (root :> "ready" @@ child :> "blocked" @@ leaf :> "blocked"))\n'
                "/\\ nodeExecutor = (w1 :> (root :> e1 @@ child :> e2 @@ leaf :> noexecutor) @@ w2 :> (root :> noexecutor @@ child :> noexecutor @@ leaf :> noexecutor))\n"
                "/\\ nodeAttempt = (w1 :> (root :> a1 @@ child :> a1 @@ leaf :> noattempt) @@ w2 :> (root :> noattempt @@ child :> noattempt @@ leaf :> noattempt))",
            ),
            _state(8, "Claim", "/\\ accepted = {c1, c3}"),
            _state(9, "ProduceResult", "/\\ accepted = {c1, c3}"),
            _state(
                10,
                "TryCommit",
                '/\\ accepted = {c1, c3, c4}\n/\\ decisions = (c1 :> "committed" @@ c3 :> "committed" @@ c4 :> "committed")\n'
                "/\\ nodeCommit = (w1 :> (root :> c1 @@ child :> c3 @@ leaf :> c4) @@ w2 :> (root :> none @@ child :> none @@ leaf :> none))\n"
                '/\\ status = (w1 :> (root :> "governed_committed" @@ child :> "governed_committed" @@ leaf :> "governed_committed") @@ w2 :> (root :> "ready" @@ child :> "blocked" @@ leaf :> "blocked"))\n'
                "/\\ nodeExecutor = (w1 :> (root :> e1 @@ child :> e2 @@ leaf :> e1) @@ w2 :> (root :> noexecutor @@ child :> noexecutor @@ leaf :> noexecutor))\n"
                "/\\ nodeAttempt = (w1 :> (root :> a1 @@ child :> a1 @@ leaf :> a2) @@ w2 :> (root :> noattempt @@ child :> noattempt @@ leaf :> noattempt))",
            ),
            _state(
                11,
                "RevokeExecutor",
                "/\\ executorEligible = (w1 :> (e1 :> TRUE @@ e2 :> FALSE) @@ w2 :> (e1 :> TRUE @@ e2 :> TRUE))\n"
                "/\\ agentRevocationEpoch = (w1 :> (e1 :> 0 @@ e2 :> 1) @@ w2 :> (e1 :> 0 @@ e2 :> 0))",
            ),
            _state(
                12,
                "RejectRevokedAttempt",
                '/\\ decisions = (c1 :> "committed" @@ c2 :> "denied" @@ c3 :> "committed" @@ c4 :> "committed")\n'
                "/\\ revocationDenied = {c2}",
            ),
            "997785 states generated, 152941 distinct states found, 75978 states left on queue.",
            "The depth of the complete state graph search is 13.",
            "Finished in 01s at (2026-08-27 08:03:57)",
        ]
    )


def _normal_success_output() -> str:
    return "\n".join(
        [
            "TLC2 Version 2.19 of 08 August 2024 (rev: 5a47802)",
            "Parsing file /checkout/specs/governed_commit.tla",
            "Semantic processing of module governed_commit",
            "Starting... (2026-08-27 08:03:56)",
            "Finished computing initial states: 1 distinct state generated at 2026-08-27 08:03:56.",
            "10 states generated, 10 distinct states found, 0 states left on queue.",
            "Finished in 01s at (2026-08-27 08:03:57)",
        ]
    )


def _classify(output: str, exit_code: int = 12, stderr: str = "") -> Outcome:
    return classify_tlc_result(exit_code, output, stderr).outcome


def test_exact_expected_witness_is_the_only_success() -> None:
    result = classify_tlc_result(12, _valid_output(), "")
    assert result.outcome is Outcome.EXPECTED_WITNESS
    assert result.wrapper_exit_code == 0


@pytest.mark.parametrize(
    ("exit_code", "output", "stderr", "expected"),
    [
        (
            0,
            _normal_success_output(),
            "",
            Outcome.WITNESS_NOT_REACHED,
        ),
        (
            12,
            _valid_output().replace("CoverageGoalNotReached", "TypeOK", 1),
            "",
            Outcome.UNEXPECTED_PROPERTY_VIOLATION,
        ),
        (
            12,
            _valid_output().replace(
                "Error: The behavior",
                "Error: Invariant TypeOK is violated.\nError: The behavior",
            ),
            "",
            Outcome.MULTIPLE_PROPERTY_VIOLATIONS,
        ),
        (
            12,
            _valid_output().replace(
                "Error: The behavior",
                "Error: Invariant TypeOK is violated.\nError: The behavior",
            ),
            "Safety failed",
            Outcome.TLC_RUNTIME_ERROR,
        ),
        (
            150,
            "TLC2 Version 2.19 of 08 August 2024\nError: The configuration file contains an error",
            "",
            Outcome.TLC_CONFIGURATION_ERROR,
        ),
        (
            150,
            "TLC2 Version 2.19 of 08 August 2024\nError: Parsing or semantic analysis failed.",
            "",
            Outcome.TLC_PARSE_ERROR,
        ),
        (
            1,
            "",
            "Error: Could not find or load main class tlc2.TLC",
            Outcome.TLC_RUNTIME_ERROR,
        ),
        (
            150,
            "TLC2 Version 2.19 of 08 August 2024\njava.lang.OutOfMemoryError",
            "",
            Outcome.TLC_RUNTIME_ERROR,
        ),
        (-9, _valid_output(), "", Outcome.TLC_RUNTIME_ERROR),
        (12, "", "", Outcome.TLC_OUTPUT_UNRECOGNIZED),
        (
            12,
            _valid_output().split("State 12:")[0],
            "",
            Outcome.TLC_OUTPUT_UNRECOGNIZED,
        ),
    ],
)
def test_fail_closed_outcome_taxonomy(
    exit_code: int, output: str, stderr: str, expected: Outcome
) -> None:
    assert _classify(output, exit_code, stderr) is expected


def test_timeout_has_distinct_fail_closed_outcome() -> None:
    result = classify_tlc_result(None, "partial", "", timed_out=True)
    assert result.outcome is Outcome.TLC_TIMEOUT
    assert result.wrapper_exit_code != 0


def test_malformed_exit_zero_is_not_witness_not_reached() -> None:
    assert _classify("truncated", 0) is Outcome.TLC_OUTPUT_UNRECOGNIZED


def test_exit_twelve_without_anchored_violation_is_unrecognized() -> None:
    output = _valid_output().replace(
        "Error: Invariant CoverageGoalNotReached is violated.\n", ""
    )
    assert _classify(output, 12) is Outcome.TLC_OUTPUT_UNRECOGNIZED


def test_any_nonempty_stderr_fails_closed() -> None:
    assert _classify(_valid_output(), 12, "warning") is Outcome.TLC_RUNTIME_ERROR


def test_indented_second_violation_is_detected() -> None:
    output = _valid_output().replace(
        "Error: The behavior",
        "  Error: Invariant TypeOK is violated.\nError: The behavior",
    )
    assert _classify(output) is Outcome.MULTIPLE_PROPERTY_VIOLATIONS


def test_wrong_trace_order_is_rejected() -> None:
    output = _valid_output()
    revoke = output[output.index("State 11:") : output.index("State 12:")]
    output = output.replace(revoke, "").replace("State 4:", revoke + "State 4:")
    assert _classify(output) is Outcome.TLC_OUTPUT_UNRECOGNIZED


def test_missing_intermediate_state_is_rejected() -> None:
    output = re.sub(r"State 5:.*?(?=State 6:)", "", _valid_output(), flags=re.S)
    assert _classify(output) is Outcome.TLC_OUTPUT_UNRECOGNIZED


@pytest.mark.parametrize("node", ["root", "child", "leaf"])
def test_cross_workflow_commit_substitution_is_rejected(node: str) -> None:
    original = _valid_output()
    commit = {"root": "c1", "child": "c3", "leaf": "c4"}[node]
    output = original.replace(
        f"w1 :> (root :> c1 @@ child :> {'c3' if node != 'root' else 'none'} @@ leaf :> {'c4' if node == 'leaf' else 'none'}) @@ w2 :> (root :> none @@ child :> none @@ leaf :> none)",
        f"w1 :> (root :> none @@ child :> none @@ leaf :> none) @@ w2 :> (root :> c1 @@ child :> c3 @@ leaf :> {commit})",
        1,
    )
    assert output != original
    assert _classify(output) is Outcome.TLC_OUTPUT_UNRECOGNIZED


def test_cross_workflow_revocation_substitution_is_rejected() -> None:
    output = _valid_output().replace(
        "w1 :> (e1 :> TRUE @@ e2 :> FALSE) @@ w2 :> (e1 :> TRUE @@ e2 :> TRUE)",
        "w1 :> (e1 :> TRUE @@ e2 :> TRUE) @@ w2 :> (e1 :> TRUE @@ e2 :> FALSE)",
    )
    assert _classify(output) is Outcome.TLC_OUTPUT_UNRECOGNIZED


@pytest.mark.parametrize(
    "needle",
    [
        "root :> c1",
        "child :> c3",
        "leaf :> c4",
        "e2 :> FALSE",
        "e2 :> 1",
        "revocationDenied = {c2}",
    ],
)
def test_each_required_semantic_milestone_is_mandatory(needle: str) -> None:
    assert (
        _classify(_valid_output().replace(needle, "missing", 1))
        is Outcome.TLC_OUTPUT_UNRECOGNIZED
    )


@pytest.mark.parametrize(
    ("old", "new"),
    [
        ('root :> "governed_committed"', 'root :> "ready"'),
        ("child :> e2", "child :> noexecutor"),
        ("leaf :> a2", "leaf :> noattempt"),
    ],
)
def test_w1_status_executor_and_attempt_bindings_are_mandatory(
    old: str, new: str
) -> None:
    original = _valid_output()
    output = original.replace(old, new, 1)
    assert output != original
    assert _classify(output) is Outcome.TLC_OUTPUT_UNRECOGNIZED


@pytest.mark.parametrize(
    ("old", "new"),
    [
        (
            'status = (w1 :> (root :> "governed_committed" @@ child :> "ready" @@ leaf :> "blocked") @@ w2 :> (root :> "ready" @@ child :> "blocked" @@ leaf :> "blocked"))',
            'status = (w1 :> (root :> "ready" @@ child :> "ready" @@ leaf :> "blocked") @@ w2 :> (root :> "governed_committed" @@ child :> "blocked" @@ leaf :> "blocked"))',
        ),
        (
            "nodeExecutor = (w1 :> (root :> e1 @@ child :> e2 @@ leaf :> noexecutor) @@ w2 :> (root :> noexecutor @@ child :> noexecutor @@ leaf :> noexecutor))",
            "nodeExecutor = (w1 :> (root :> e1 @@ child :> noexecutor @@ leaf :> noexecutor) @@ w2 :> (root :> noexecutor @@ child :> e2 @@ leaf :> noexecutor))",
        ),
        (
            "nodeAttempt = (w1 :> (root :> a1 @@ child :> a1 @@ leaf :> a2) @@ w2 :> (root :> noattempt @@ child :> noattempt @@ leaf :> noattempt))",
            "nodeAttempt = (w1 :> (root :> a1 @@ child :> a1 @@ leaf :> noattempt) @@ w2 :> (root :> noattempt @@ child :> noattempt @@ leaf :> a2))",
        ),
    ],
)
def test_literal_w1_to_w2_status_executor_and_attempt_substitutions_are_rejected(
    old: str, new: str
) -> None:
    original = _valid_output()
    output = original.replace(old, new, 1)
    assert output != original
    assert _classify(output) is Outcome.TLC_OUTPUT_UNRECOGNIZED


def test_property_name_in_configuration_echo_is_not_a_violation() -> None:
    output = _valid_output().replace(
        "Error: Invariant CoverageGoalNotReached is violated.\n", ""
    )
    output = "INVARIANT CoverageGoalNotReached\n" + output
    assert _classify(output, 12) is Outcome.TLC_OUTPUT_UNRECOGNIZED


def test_pinned_tlc_whitespace_variation_is_supported() -> None:
    assert _classify(_valid_output(whitespace=True)) is Outcome.EXPECTED_WITNESS


def test_wrapper_contract_is_pinned_and_shell_free() -> None:
    source = SCRIPT.read_text()
    assert 'EXPECTED_PROPERTY = "CoverageGoalNotReached"' in source
    assert "EXPECTED_TLC_EXIT = 12" in source
    assert (
        TLC_JAR_SHA256
        == "936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88"
    )
    assert "shell=True" not in source
    assert "subprocess.run(" in source


def _fake_jar(tmp_path: Path) -> Path:
    jar = tmp_path / "tla2tools.jar"
    jar.write_bytes(b"fixture")
    return jar


def test_runner_uses_explicit_argv_and_cleans_temp_state(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    jar = _fake_jar(tmp_path)
    observed: dict[str, object] = {}

    def fake_run(argv, **kwargs):
        observed.update(argv=argv, **kwargs)
        return subprocess.CompletedProcess(argv, 12, _valid_output(), "")

    monkeypatch.setattr(witness, "_sha256", lambda _path: TLC_JAR_SHA256)
    monkeypatch.setattr(witness.subprocess, "run", fake_run)
    log = tmp_path / "witness.log"
    result = run_tlc_expected_witness(tlc_jar=jar, log_path=log)

    assert result.outcome is Outcome.EXPECTED_WITNESS
    assert observed["shell"] is False
    assert observed["capture_output"] is True
    assert observed["text"] is True
    assert isinstance(observed["argv"], list)
    assert "governed_commit_coverage.cfg" in " ".join(observed["argv"])
    observed_cwd = cast(str | os.PathLike[str], observed["cwd"])
    assert not Path(observed_cwd).exists()
    assert "TLC_EXIT=12" in log.read_text()
    assert "STDOUT" in log.read_text() and "STDERR" in log.read_text()


@pytest.mark.parametrize(
    ("completed", "expected"),
    [
        (
            subprocess.CompletedProcess([], -9, _valid_output(), ""),
            Outcome.TLC_RUNTIME_ERROR,
        ),
        (subprocess.CompletedProcess([], 12, "", ""), Outcome.TLC_OUTPUT_UNRECOGNIZED),
        (
            subprocess.CompletedProcess(
                [], 12, _valid_output().split("State 12:")[0], ""
            ),
            Outcome.TLC_OUTPUT_UNRECOGNIZED,
        ),
        (
            subprocess.CompletedProcess(
                [], 150, "Error: The configuration file contains an error", ""
            ),
            Outcome.TLC_CONFIGURATION_ERROR,
        ),
        (
            subprocess.CompletedProcess(
                [], 150, "Error: Parsing or semantic analysis failed.", ""
            ),
            Outcome.TLC_PARSE_ERROR,
        ),
        (
            subprocess.CompletedProcess([], 1, "", "Java startup failed"),
            Outcome.TLC_RUNTIME_ERROR,
        ),
    ],
)
def test_runner_fail_closed_process_results(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    completed: subprocess.CompletedProcess[str],
    expected: Outcome,
) -> None:
    jar = _fake_jar(tmp_path)
    temp_directories: list[Path] = []

    def fake_run(*_args, **kwargs):
        temp_directories.append(Path(kwargs["cwd"]))
        return completed

    monkeypatch.setattr(witness, "_sha256", lambda _path: TLC_JAR_SHA256)
    monkeypatch.setattr(witness.subprocess, "run", fake_run)
    result = run_tlc_expected_witness(tlc_jar=jar, log_path=tmp_path / "run.log")
    assert result.outcome is expected
    assert temp_directories and all(not path.exists() for path in temp_directories)


def test_runner_timeout_and_java_start_failure_are_structured(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    jar = _fake_jar(tmp_path)
    timeout_cwds: list[Path] = []
    start_failure_cwds: list[Path] = []
    monkeypatch.setattr(witness, "_sha256", lambda _path: TLC_JAR_SHA256)

    def raise_timeout(*_args, **kwargs):
        timeout_cwds.append(Path(kwargs["cwd"]))
        raise subprocess.TimeoutExpired("java", 1, output="partial", stderr="")

    monkeypatch.setattr(
        witness.subprocess,
        "run",
        raise_timeout,
    )
    timeout_result = run_tlc_expected_witness(
        tlc_jar=jar, log_path=tmp_path / "timeout.log"
    )
    assert timeout_result.outcome is Outcome.TLC_TIMEOUT
    assert timeout_cwds and all(not path.exists() for path in timeout_cwds)

    def raise_start_failure(*_args, **kwargs):
        start_failure_cwds.append(Path(kwargs["cwd"]))
        raise OSError("java missing")

    monkeypatch.setattr(
        witness.subprocess,
        "run",
        raise_start_failure,
    )
    start_result = run_tlc_expected_witness(
        tlc_jar=jar, log_path=tmp_path / "start.log"
    )
    assert start_result.outcome is Outcome.TLC_RUNTIME_ERROR
    assert "java missing" in start_result.detail
    assert start_failure_cwds and all(not path.exists() for path in start_failure_cwds)


def test_checksum_and_invalid_timeout_fail_before_tlc_and_write_log(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    jar = _fake_jar(tmp_path)
    invoked = False

    def unexpected_run(*_args, **_kwargs):
        nonlocal invoked
        invoked = True

    monkeypatch.setattr(witness.subprocess, "run", unexpected_run)
    checksum_log = tmp_path / "checksum.log"
    checksum_result = run_tlc_expected_witness(tlc_jar=jar, log_path=checksum_log)
    assert checksum_result.outcome is Outcome.TLC_RUNTIME_ERROR
    assert checksum_log.exists()
    assert not invoked

    monkeypatch.setattr(witness, "_sha256", lambda _path: TLC_JAR_SHA256)
    timeout_log = tmp_path / "invalid-timeout.log"
    timeout_result = run_tlc_expected_witness(
        tlc_jar=jar, timeout_seconds=0, log_path=timeout_log
    )
    assert timeout_result.outcome is Outcome.TLC_CONFIGURATION_ERROR
    assert timeout_log.exists()
    assert not invoked


def test_log_write_failure_is_fail_closed_without_exception(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    jar = _fake_jar(tmp_path)
    monkeypatch.setattr(witness, "_sha256", lambda _path: TLC_JAR_SHA256)
    monkeypatch.setattr(
        witness.subprocess,
        "run",
        lambda argv, **_kwargs: subprocess.CompletedProcess(
            argv, 12, _valid_output(), ""
        ),
    )
    monkeypatch.setattr(
        Path,
        "write_text",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("disk full")),
    )
    result = run_tlc_expected_witness(tlc_jar=jar, log_path=tmp_path / "blocked.log")
    assert result.outcome is Outcome.TLC_RUNTIME_ERROR
    assert "diagnostic log" in result.detail


def test_cli_log_write_failure_prints_structured_failure_without_traceback(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    jar = _fake_jar(tmp_path)
    monkeypatch.setattr(witness, "_sha256", lambda _path: TLC_JAR_SHA256)
    monkeypatch.setattr(
        witness.subprocess,
        "run",
        lambda argv, **_kwargs: subprocess.CompletedProcess(
            argv, 12, _valid_output(), ""
        ),
    )
    monkeypatch.setattr(
        Path,
        "write_text",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("disk full")),
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [str(SCRIPT), "--tlc-jar", str(jar), "--log", str(tmp_path / "blocked.log")],
    )

    assert witness.main() == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "FAIL: TLC_RUNTIME_ERROR" in captured.err
    assert "diagnostic log write failed" in captured.err
    assert f"Diagnostic log target: {tmp_path / 'blocked.log'}" in captured.err
    assert "Diagnostic log:" not in captured.err
    assert "Traceback" not in captured.err


def test_workflow_is_yaml_valid_and_fail_closed() -> None:
    workflow_path = ROOT / ".github" / "workflows" / "tla-check.yml"
    source = workflow_path.read_text()
    workflow = yaml.safe_load(source)
    assert isinstance(workflow, dict)
    assert "run_tlc_expected_witness.py" in source
    assert "continue-on-error" not in source
    assert "|| true" not in source
    assert "set +e" not in source
    assert "set -euo pipefail" in source
    assert "sha256sum -c -" in source
    assert "tla2tools-${{ env.TLC_VERSION }}-${{ env.TLC_SHA256 }}" in source
    assert "governed_commit.cfg" in source
    assert "governed_commit_coverage.cfg" not in source  # wrapper pins it
    assert "CoverageGoalNotReached" not in source  # wrapper pins it
    assert TLC_JAR_SHA256 in source
    assert "scripts/run_tlc_expected_witness.py" in source
    assert "tests/test_tlc_expected_witness.py" in source
    assert "Makefile" in source
    jobs = workflow["jobs"]
    assert set(jobs) == {"safety", "gcb-witness"}
    safety_configs = {
        entry["config"] for entry in jobs["safety"]["strategy"]["matrix"]["spec"]
    }
    assert safety_configs == {
        "MeshMC.cfg",
        "constitution_reconfig.cfg",
        "governed_commit.cfg",
    }
    witness_steps = jobs["gcb-witness"]["steps"]
    assert any(
        step.get("if") == "always()" and "upload-artifact" in step.get("uses", "")
        for step in witness_steps
    )


@pytest.mark.integration
def test_real_pinned_tlc_witness(tmp_path: Path) -> None:
    jar = os.environ.get("TLA2TOOLS_JAR")
    if not jar:
        pytest.skip("TLA2TOOLS_JAR is required for the real formal integration")
    log = tmp_path / "witness.log"
    completed = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--tlc-jar",
            jar,
            "--timeout",
            "120",
            "--log",
            str(log),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=150,
        check=False,
    )
    assert completed.returncode == 0, (
        completed.stdout + completed.stderr + log.read_text()
    )
    assert "PASS: EXPECTED_WITNESS" in completed.stdout
    assert "CoverageGoalNotReached" in log.read_text()
    assert not list(ROOT.glob("states/**"))
    assert not list(ROOT.glob("TTrace*"))
