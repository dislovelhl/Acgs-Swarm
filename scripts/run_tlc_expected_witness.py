#!/usr/bin/env python3
"""Run the pinned GCB non-vacuity model and validate its exact witness."""

from __future__ import annotations

import argparse
import hashlib
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from enum import Enum
from pathlib import Path


EXPECTED_TLC_EXIT = 12
EXPECTED_PROPERTY = "CoverageGoalNotReached"
TLC_VERSION_LINE = "TLC2 Version 2.19 of 08 August 2024"
TLC_JAR_SHA256 = "936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88"
DEFAULT_TIMEOUT_SECONDS = 180


class Outcome(str, Enum):
    EXPECTED_WITNESS = "EXPECTED_WITNESS"
    WITNESS_NOT_REACHED = "WITNESS_NOT_REACHED"
    UNEXPECTED_PROPERTY_VIOLATION = "UNEXPECTED_PROPERTY_VIOLATION"
    MULTIPLE_PROPERTY_VIOLATIONS = "MULTIPLE_PROPERTY_VIOLATIONS"
    TLC_CONFIGURATION_ERROR = "TLC_CONFIGURATION_ERROR"
    TLC_PARSE_ERROR = "TLC_PARSE_ERROR"
    TLC_RUNTIME_ERROR = "TLC_RUNTIME_ERROR"
    TLC_TIMEOUT = "TLC_TIMEOUT"
    TLC_OUTPUT_UNRECOGNIZED = "TLC_OUTPUT_UNRECOGNIZED"


@dataclass(frozen=True)
class WitnessResult:
    outcome: Outcome
    detail: str
    process_exit_code: int | None
    stdout: str = ""
    stderr: str = ""

    @property
    def wrapper_exit_code(self) -> int:
        return 0 if self.outcome is Outcome.EXPECTED_WITNESS else 1


_VIOLATION_RE = re.compile(
    r"^\s*Error:\s+Invariant\s+([A-Za-z_][A-Za-z0-9_]*)\s+is violated\.\s*$",
    re.MULTILINE,
)
_STATE_RE = re.compile(
    r"^State\s+(\d+):\s*<([^>]+)>\s*$\n(.*?)(?=^State\s+\d+:|^\d+\s+states generated,|\Z)",
    re.MULTILINE | re.DOTALL,
)


def _normalized(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def _strip_outer_parentheses(value: str) -> str:
    value = value.strip()
    while value.startswith("(") and value.endswith(")"):
        depth = 0
        closes_at_end = False
        for index, character in enumerate(value):
            if character == "(":
                depth += 1
            elif character == ")":
                depth -= 1
                if depth == 0:
                    closes_at_end = index == len(value) - 1
                    break
        if not closes_at_end:
            break
        value = value[1:-1].strip()
    return value


def _split_top_level(value: str, separator: str) -> list[str]:
    parts: list[str] = []
    start = 0
    parentheses = 0
    braces = 0
    tuples = 0
    quoted = False
    index = 0
    while index < len(value):
        character = value[index]
        if character == '"' and (index == 0 or value[index - 1] != "\\"):
            quoted = not quoted
        elif not quoted:
            if value.startswith("<<", index):
                tuples += 1
                index += 2
                continue
            if value.startswith(">>", index):
                tuples -= 1
                index += 2
                continue
            if character == "(":
                parentheses += 1
            elif character == ")":
                parentheses -= 1
            elif character == "{":
                braces += 1
            elif character == "}":
                braces -= 1
            elif (
                parentheses == 0
                and braces == 0
                and tuples == 0
                and value.startswith(separator, index)
            ):
                parts.append(value[start:index].strip())
                index += len(separator)
                start = index
                continue
        index += 1
    parts.append(value[start:].strip())
    return parts


def _parse_tla_value(value: str) -> object:
    value = _strip_outer_parentheses(_normalized(value))
    if value.startswith("{") and value.endswith("}"):
        members = _split_top_level(value[1:-1], ",")
        return {member for member in members if member}
    entries = _split_top_level(value, "@@")
    if len(entries) > 1 or ":>" in value:
        mapping: dict[str, object] = {}
        for entry in entries:
            pair = _split_top_level(entry, ":>")
            if len(pair) != 2 or pair[0] in mapping:
                return value
            mapping[pair[0]] = _parse_tla_value(pair[1])
        return mapping
    if value.startswith('"') and value.endswith('"'):
        return value[1:-1]
    return value


def _parse_assignments(body: str) -> dict[str, object]:
    assignment_re = re.compile(
        r"^\s*/\\\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*", re.MULTILINE
    )
    matches = list(assignment_re.finditer(body))
    assignments: dict[str, object] = {}
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(body)
        name = match.group(1)
        if name in assignments:
            return {}
        assignments[name] = _parse_tla_value(body[match.end() : end])
    return assignments


def _value_at(assignments: dict[str, object], name: str, *keys: str) -> object | None:
    value = assignments.get(name)
    for key in keys:
        if not isinstance(value, dict):
            return None
        value = value.get(key)
    return value


def _trace_is_complete_and_ordered(output: str) -> bool:
    states = [
        (
            int(number),
            header.split(" line ", 1)[0].strip(),
            _parse_assignments(body),
        )
        for number, header, body in _STATE_RE.findall(output)
    ]
    if [number for number, _, _ in states] != list(range(1, len(states) + 1)):
        return False
    if not states or states[0][1] != "Initial predicate":
        return False

    commit_milestones = (
        ("root", "c1", "e1", "a1"),
        ("child", "c3", "e2", "a1"),
        ("leaf", "c4", "e1", "a2"),
    )
    cursor = 1
    for node, commit, executor, attempt in commit_milestones:
        for index in range(cursor, len(states)):
            _, action, assignments = states[index]
            accepted = assignments.get("accepted")
            if (
                action == "TryCommit"
                and isinstance(accepted, set)
                and commit in accepted
                and _value_at(assignments, "nodeCommit", "w1", node) == commit
                and _value_at(assignments, "status", "w1", node) == "governed_committed"
                and _value_at(assignments, "decisions", commit) == "committed"
                and _value_at(assignments, "nodeExecutor", "w1", node) == executor
                and _value_at(assignments, "nodeAttempt", "w1", node) == attempt
            ):
                cursor = index + 1
                break
        else:
            return False

    for index in range(cursor, len(states)):
        _, action, assignments = states[index]
        if (
            action == "RevokeExecutor"
            and _value_at(assignments, "executorEligible", "w1", "e2") == "FALSE"
            and _value_at(assignments, "agentRevocationEpoch", "w1", "e2") == "1"
        ):
            cursor = index + 1
            break
    else:
        return False

    for _, action, assignments in states[cursor:]:
        revocation_denied = assignments.get("revocationDenied")
        if (
            action == "RejectRevokedAttempt"
            and _value_at(assignments, "decisions", "c2") == "denied"
            and isinstance(revocation_denied, set)
            and "c2" in revocation_denied
        ):
            return True
    return False


def _normal_success_envelope(output: str) -> bool:
    required = (
        TLC_VERSION_LINE in output,
        re.search(
            r"^\s*Parsing\s+file\s+.*governed_commit\.tla\s*$", output, re.MULTILINE
        )
        is not None,
        "Semantic processing of module governed_commit" in output,
        re.search(r"^\s*Starting\.\.\.", output, re.MULTILINE) is not None,
        "Finished computing initial states:" in output,
        re.search(
            r"^\s*\d+\s+states generated,\s+\d+\s+distinct states found,\s+0\s+states left on queue\.",
            output,
            re.MULTILINE,
        )
        is not None,
        re.search(r"^\s*Finished in\s+", output, re.MULTILINE) is not None,
    )
    forbidden = re.search(
        r"(?im)^\s*(?:Error:|Fatal\b|Exception\b)|\bis violated\.\s*$", output
    )
    return all(required) and forbidden is None


def classify_tlc_result(
    process_exit_code: int | None,
    stdout: str,
    stderr: str,
    *,
    timed_out: bool = False,
) -> WitnessResult:
    """Classify TLC output. Only the exact, complete coverage witness succeeds."""

    combined = "\n".join(part for part in (stdout, stderr) if part)
    if timed_out:
        return WitnessResult(
            Outcome.TLC_TIMEOUT,
            "TLC exceeded the bounded timeout",
            process_exit_code,
            stdout,
            stderr,
        )
    if process_exit_code is not None and process_exit_code < 0:
        return WitnessResult(
            Outcome.TLC_RUNTIME_ERROR,
            "TLC was terminated by signal",
            process_exit_code,
            stdout,
            stderr,
        )
    if stderr:
        return WitnessResult(
            Outcome.TLC_RUNTIME_ERROR,
            "pinned TLC emitted unexpected stderr",
            process_exit_code,
            stdout,
            stderr,
        )

    configuration_markers = (
        "configuration file contains an error",
        "Error: The configuration file",
        "TLC found an error in the configuration file",
    )
    if any(marker.lower() in combined.lower() for marker in configuration_markers):
        return WitnessResult(
            Outcome.TLC_CONFIGURATION_ERROR,
            "TLC configuration failed",
            process_exit_code,
            stdout,
            stderr,
        )

    parse_markers = (
        "Parsing or semantic analysis failed",
        "Fatal errors while parsing TLA+ spec",
        "Cannot find source file for module",
        "Semantic errors:",
    )
    if any(marker.lower() in combined.lower() for marker in parse_markers):
        return WitnessResult(
            Outcome.TLC_PARSE_ERROR,
            "TLA+ parse or semantic processing failed",
            process_exit_code,
            stdout,
            stderr,
        )

    runtime_markers = (
        "Could not find or load main class",
        "java.lang.",
        "Exception in thread",
        "TLC threw an unexpected exception",
        "OutOfMemoryError",
        "No space left on device",
        "DiskStateQueueException",
    )
    if any(marker.lower() in combined.lower() for marker in runtime_markers):
        return WitnessResult(
            Outcome.TLC_RUNTIME_ERROR,
            "Java or TLC runtime failed",
            process_exit_code,
            stdout,
            stderr,
        )

    if process_exit_code == 0 and _normal_success_envelope(stdout):
        return WitnessResult(
            Outcome.WITNESS_NOT_REACHED,
            "coverage witness was not reached",
            process_exit_code,
            stdout,
            stderr,
        )
    if process_exit_code == 0:
        return WitnessResult(
            Outcome.TLC_OUTPUT_UNRECOGNIZED,
            "exit-zero TLC output did not contain a complete normal-success envelope",
            process_exit_code,
            stdout,
            stderr,
        )
    if process_exit_code != EXPECTED_TLC_EXIT:
        return WitnessResult(
            Outcome.TLC_RUNTIME_ERROR,
            f"unexpected TLC exit code {process_exit_code}",
            process_exit_code,
            stdout,
            stderr,
        )
    if not combined.strip():
        return WitnessResult(
            Outcome.TLC_OUTPUT_UNRECOGNIZED,
            "TLC output was empty",
            process_exit_code,
            stdout,
            stderr,
        )

    violations = _VIOLATION_RE.findall(combined)
    if len(violations) > 1:
        return WitnessResult(
            Outcome.MULTIPLE_PROPERTY_VIOLATIONS,
            f"violated properties: {violations}",
            process_exit_code,
            stdout,
            stderr,
        )
    if not violations:
        return WitnessResult(
            Outcome.TLC_OUTPUT_UNRECOGNIZED,
            "expected anchored invariant violation was absent",
            process_exit_code,
            stdout,
            stderr,
        )
    if violations != [EXPECTED_PROPERTY]:
        return WitnessResult(
            Outcome.UNEXPECTED_PROPERTY_VIOLATION,
            f"violated properties: {violations}",
            process_exit_code,
            stdout,
            stderr,
        )

    violation_lines = re.findall(r"(?im)^\s*.*\bis violated\.\s*$", combined)
    if [line.strip() for line in violation_lines] != [
        f"Error: Invariant {EXPECTED_PROPERTY} is violated."
    ]:
        return WitnessResult(
            Outcome.TLC_RUNTIME_ERROR,
            "unexpected violation marker accompanied the witness",
            process_exit_code,
            stdout,
            stderr,
        )

    error_lines = re.findall(r"^\s*Error:.*$", combined, re.MULTILINE)
    allowed_errors = {
        f"Error: Invariant {EXPECTED_PROPERTY} is violated.",
        "Error: The behavior up to this point is:",
    }
    if any(line.strip() not in allowed_errors for line in error_lines) or re.search(
        r"(?im)^\s*(?:Fatal\b|Exception\b)", combined
    ):
        return WitnessResult(
            Outcome.TLC_RUNTIME_ERROR,
            "unexpected TLC error accompanied the witness",
            process_exit_code,
            stdout,
            stderr,
        )

    required_envelope = (
        TLC_VERSION_LINE in combined,
        re.search(
            r"^\s*Parsing\s+file\s+.*governed_commit\.tla\s*$",
            combined,
            re.MULTILINE,
        )
        is not None,
        "Semantic processing of module governed_commit" in combined,
        re.search(r"^\s*Starting\.\.\.", combined, re.MULTILINE) is not None,
        "Finished computing initial states:" in combined,
        "Error: The behavior up to this point is:" in combined,
        re.search(
            r"^\s*\d+\s+states generated,\s+\d+\s+distinct states found,",
            combined,
            re.MULTILINE,
        )
        is not None,
        re.search(r"^\s*Finished in\s+", combined, re.MULTILINE) is not None,
    )
    if not all(required_envelope) or not _trace_is_complete_and_ordered(combined):
        return WitnessResult(
            Outcome.TLC_OUTPUT_UNRECOGNIZED,
            "counterexample envelope or ordered semantic trace was incomplete",
            process_exit_code,
            stdout,
            stderr,
        )
    return WitnessResult(
        Outcome.EXPECTED_WITNESS,
        "exact GCB non-vacuity witness established",
        process_exit_code,
        stdout,
        stderr,
    )


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _write_log(path: Path, argv: list[str], result: WitnessResult) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "COMMAND\n"
        + "\n".join(argv)
        + "\n\nSTDOUT\n"
        + result.stdout
        + "\n\nSTDERR\n"
        + result.stderr
        + f"\n\nRESULT\n{result.outcome.value}: {result.detail}\n"
        + f"TLC_EXIT={result.process_exit_code}\n",
        encoding="utf-8",
    )


def _record_result(path: Path, argv: list[str], result: WitnessResult) -> WitnessResult:
    try:
        _write_log(path, argv, result)
    except OSError as exc:
        return WitnessResult(
            Outcome.TLC_RUNTIME_ERROR,
            f"{result.outcome.value} occurred but diagnostic log write failed: {exc}",
            result.process_exit_code,
            result.stdout,
            result.stderr,
        )
    return result


def run_tlc_expected_witness(
    *,
    tlc_jar: Path,
    java_command: str = "java",
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    log_path: Path,
) -> WitnessResult:
    repo_root = Path(__file__).resolve().parents[1]
    if timeout_seconds <= 0:
        result = WitnessResult(
            Outcome.TLC_CONFIGURATION_ERROR,
            "timeout must be positive",
            None,
        )
        return _record_result(log_path, [], result)
    try:
        jar_valid = tlc_jar.is_file() and _sha256(tlc_jar) == TLC_JAR_SHA256
    except OSError:
        jar_valid = False
    if not jar_valid:
        result = WitnessResult(
            Outcome.TLC_RUNTIME_ERROR,
            "TLC jar is missing or its SHA-256 is not the pinned v1.7.4 digest",
            None,
        )
        return _record_result(log_path, [], result)

    with tempfile.TemporaryDirectory(prefix="gcb-tlc-witness-") as temp_name:
        temp_root = Path(temp_name)
        java_tmp = temp_root / "java"
        metadir = temp_root / "states"
        java_tmp.mkdir()
        metadir.mkdir()
        argv = [
            java_command,
            f"-Djava.io.tmpdir={java_tmp}",
            "-XX:+UseParallelGC",
            "-Xmx4g",
            "-cp",
            str(tlc_jar.resolve()),
            "tlc2.TLC",
            "-deadlock",
            "-workers",
            "auto",
            "-metadir",
            str(metadir),
            "-config",
            str((repo_root / "specs" / "governed_commit_coverage.cfg").resolve()),
            str((repo_root / "specs" / "governed_commit.tla").resolve()),
        ]
        try:
            completed = subprocess.run(
                argv,
                cwd=temp_root,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                check=False,
                shell=False,
            )
            result = classify_tlc_result(
                completed.returncode, completed.stdout, completed.stderr
            )
        except subprocess.TimeoutExpired as exc:
            stdout = (
                exc.stdout.decode()
                if isinstance(exc.stdout, bytes)
                else (exc.stdout or "")
            )
            stderr = (
                exc.stderr.decode()
                if isinstance(exc.stderr, bytes)
                else (exc.stderr or "")
            )
            result = classify_tlc_result(None, stdout, stderr, timed_out=True)
        except OSError as exc:
            result = WitnessResult(
                Outcome.TLC_RUNTIME_ERROR,
                f"failed to start Java: {exc}",
                None,
                "",
                str(exc),
            )
        return _record_result(log_path, argv, result)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--tlc-jar", required=True, type=Path, help="path to the pinned TLC v1.7.4 jar"
    )
    parser.add_argument(
        "--java", default="java", help="Java executable (default: java)"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT_SECONDS,
        help="finite TLC timeout in seconds",
    )
    parser.add_argument(
        "--log",
        type=Path,
        default=Path("tlc-gcb-witness.log"),
        help="diagnostic log path",
    )
    return parser


def main() -> int:
    args = _parser().parse_args()
    result = run_tlc_expected_witness(
        tlc_jar=args.tlc_jar,
        java_command=args.java,
        timeout_seconds=args.timeout,
        log_path=args.log,
    )
    stream = sys.stdout if result.wrapper_exit_code == 0 else sys.stderr
    print(
        f"{'PASS' if result.wrapper_exit_code == 0 else 'FAIL'}: {result.outcome.value}: {result.detail}",
        file=stream,
    )
    print(f"Diagnostic log target: {args.log}", file=stream)
    if result.wrapper_exit_code != 0:
        if result.stdout:
            print("--- TLC stdout ---", result.stdout, sep="\n", file=sys.stderr)
        if result.stderr:
            print("--- TLC stderr ---", result.stderr, sep="\n", file=sys.stderr)
    return result.wrapper_exit_code


if __name__ == "__main__":
    raise SystemExit(main())
