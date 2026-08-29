"""Run every bounded APCC model with the pinned TLC distribution."""

from __future__ import annotations
import argparse
import hashlib
import re
import subprocess
import sys
from pathlib import Path

TLC_JAR_SHA256 = "936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88"
TLC_VERSION_LINE = "TLC2 Version 2.19 of 08 August 2024"
DEFAULT_CONFIGS = (
    "apcc_safety.cfg",
    "apcc_liveness.cfg",
    "apcc_witness_valid_chain.cfg",
    "apcc_witness_exact_replay.cfg",
    "apcc_witness_stale_rejection.cfg",
    "apcc_witness_revocation.cfg",
    "apcc_witness_recovery.cfg",
    "apcc_ablation_guard_reread.cfg",
    "apcc_ablation_supersession.cfg",
    "apcc_ablation_status_window.cfg",
    "apcc_ablation_attempt_guard.cfg",
    "apcc_ablation_revocation_closure.cfg",
    "apcc_ablation_propagation_fence.cfg",
    "apcc_ablation_recovery_authority.cfg",
    "apcc_ablation_supersession_nonretroactivity.cfg",
    "apcc_witness_invalid_authorization.cfg",
    "apcc_witness_invalid_receipt.cfg",
    "apcc_witness_status_binding.cfg",
    "apcc_ablation_authorization_evidence.cfg",
    "apcc_ablation_receipt_evidence.cfg",
    "apcc_ablation_status_binding.cfg",
    "apcc_witness_legacy_status.cfg",
    "apcc_ablation_legacy_status.cfg",
    "apcc_causal_safety.cfg",
    "apcc_causal_witness.cfg",
    "apcc_causal_ablation.cfg",
    "apcc_multitenant_safety.cfg",
    "apcc_multitenant_witness.cfg",
    "apcc_multitenant_nonce_ablation.cfg",
    "apcc_multitenant_actor_ablation.cfg",
    "apcc_multitenant_target_witness.cfg",
    "apcc_multitenant_target_ablation.cfg",
)
_VIOLATION = re.compile(r"Error: Invariant ([A-Za-z]+) is violated\.")
EXPECTED_WITNESS = {
    "apcc_witness_valid_chain.cfg": "WitnessValidChainNotReached",
    "apcc_witness_exact_replay.cfg": "WitnessExactReplayNotReached",
    "apcc_witness_stale_rejection.cfg": "WitnessStaleRejectionNotReached",
    "apcc_witness_revocation.cfg": "WitnessRevocationBlockedNotReached",
    "apcc_witness_recovery.cfg": "WitnessRecoveryNotReached",
    "apcc_ablation_guard_reread.cfg": "NoRevokedActorCommit",
    "apcc_ablation_supersession.cfg": "AtomicSupersession",
    "apcc_ablation_status_window.cfg": "IssuedStatusHasBoundedResidualValidity",
    "apcc_ablation_attempt_guard.cfg": "NoCrossAttemptReplay",
    "apcc_ablation_revocation_closure.cfg": "EffectiveRevocationClosure",
    "apcc_ablation_propagation_fence.cfg": "RevocationPropagationIsRecoverable",
    "apcc_ablation_recovery_authority.cfg": "NoAuthorityFromRecovery",
    "apcc_ablation_supersession_nonretroactivity.cfg": "SupersessionNonretroactivity",
    "apcc_witness_invalid_authorization.cfg": "WitnessInvalidAuthorizationRejectedNotReached",
    "apcc_witness_invalid_receipt.cfg": "WitnessInvalidReceiptRejectedNotReached",
    "apcc_witness_status_binding.cfg": "WitnessStatusBindingNotReached",
    "apcc_ablation_authorization_evidence.cfg": "NoUnauthorizedCommit",
    "apcc_ablation_receipt_evidence.cfg": "NoInvalidReceiptCommit",
    "apcc_ablation_status_binding.cfg": "DownstreamAuthorityConsistency",
    "apcc_witness_legacy_status.cfg": "WitnessLegacyStatusBlockedNotReached",
    "apcc_ablation_legacy_status.cfg": "NoAuthorityFromLegacyStatus",
    "apcc_causal_witness.cfg": "WitnessCausalCoverageNotReached",
    "apcc_causal_ablation.cfg": "BoundedIndependentCausalVerification",
    "apcc_multitenant_witness.cfg": "WitnessMultitenantIsolationNotReached",
    "apcc_multitenant_nonce_ablation.cfg": "NonceUniqueness",
    "apcc_multitenant_actor_ablation.cfg": "ActorRevocationWorkflowScope",
    "apcc_multitenant_target_witness.cfg": "WitnessRevocationTargetsNotReached",
    "apcc_multitenant_target_ablation.cfg": "RevocationTargetSeparation",
}
CONFIG_MODULE = {
    config: (
        "apcc_causal"
        if config.startswith("apcc_causal_")
        else "apcc_multitenant"
        if config.startswith("apcc_multitenant_")
        else "apcc"
    )
    for config in DEFAULT_CONFIGS
}


def classify_result(exit_code: int, output: str, expected_witness: str | None) -> bool:
    """Accept only normal success or one intentional named witness violation."""
    violations = _VIOLATION.findall(output)
    errors = [
        line.strip()
        for line in output.splitlines()
        if line.lstrip().startswith("Error:")
    ]
    if expected_witness is not None:
        allowed_errors = {
            f"Error: Invariant {expected_witness} is violated.",
            "Error: The behavior up to this point is:",
        }
        return (
            exit_code == 12
            and violations == [expected_witness]
            and bool(errors)
            and all(error in allowed_errors for error in errors)
            and "behavior up to this point" in output
        )
    return (
        exit_code == 0
        and not violations
        and not errors
        and "No error has been found" in output
    )


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _stats(output: str) -> str:
    lines = [
        line.strip()
        for line in output.splitlines()
        if "states generated" in line or "depth of the complete state graph" in line
    ]
    return " | ".join(lines) if lines else "state statistics unavailable"


def run_config(jar: Path, specs: Path, config: str, timeout: int) -> bool:
    module = CONFIG_MODULE[config]
    completed = subprocess.run(
        [
            "java",
            "-cp",
            str(jar),
            "tlc2.TLC",
            "-cleanup",
            "-config",
            config,
            module,
        ],
        cwd=specs,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    output = completed.stdout + completed.stderr
    expected_witness = EXPECTED_WITNESS.get(config)
    ok = TLC_VERSION_LINE in output and classify_result(
        completed.returncode, output, expected_witness
    )
    print(
        f"{'PASS' if ok else 'FAIL'} {config}: exit={completed.returncode}; {_stats(output)}"
    )
    if not ok:
        print(output, file=sys.stderr)
    return ok


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tlc-jar", required=True, type=Path)
    parser.add_argument(
        "--specs", type=Path, default=Path(__file__).resolve().parents[1] / "specs"
    )
    parser.add_argument("--config", action="append", choices=DEFAULT_CONFIGS)
    parser.add_argument("--timeout", type=int, default=360)
    args = parser.parse_args(argv)
    if not args.tlc_jar.is_file() or _sha256(args.tlc_jar) != TLC_JAR_SHA256:
        print(
            "FAIL: TLC jar is missing or does not match pinned v1.7.4 SHA-256",
            file=sys.stderr,
        )
        return 2
    try:
        results = [
            run_config(args.tlc_jar, args.specs, config, args.timeout)
            for config in tuple(args.config or DEFAULT_CONFIGS)
        ]
    except subprocess.TimeoutExpired as exc:
        print(f"FAIL: TLC timeout after {exc.timeout}s", file=sys.stderr)
        return 2
    return 0 if all(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
