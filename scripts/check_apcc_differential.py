#!/usr/bin/env python3
"""Compare the independent Python and Go APCC verifiers on hashed vectors."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from constitutional_swarm.apcc.verifier import (  # noqa: E402
    ScopedTrust,
    TrustBinding,
    TrustRole,
    verify_current,
    verify_historical,
)


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--go-binary",
        type=Path,
        default=ROOT / "verifiers/apcc-go/apcc-verify",
    )
    parser.add_argument(
        "--fixtures",
        type=Path,
        default=ROOT / "tests/fixtures/apcc/v1",
    )
    return parser.parse_args()


def _b64u(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _trust(raw: bytes) -> ScopedTrust:
    value = json.loads(raw)
    if set(value) != {"bindings", "protocol_version"}:
        raise ValueError("unexpected trust manifest fields")
    return ScopedTrust(
        tuple(
            TrustBinding(
                TrustRole(binding["role"]),
                tuple(binding["scope"]),
                binding["key_id"],
                _b64u(binding["public_key_b64u"]),
            )
            for binding in value["bindings"]
        )
    )


def _artifact(fixtures: Path, reference: str) -> bytes:
    path = fixtures / reference
    raw = path.read_bytes()
    expected = path.stem
    actual = hashlib.sha256(raw).hexdigest()
    if expected != actual:
        raise ValueError(f"content address mismatch: {reference}")
    return raw


def _python_code(fixtures: Path, vector: dict[str, Any]) -> str:
    envelope = _artifact(fixtures, vector["certificate"])
    trust = _trust(_artifact(fixtures, vector["trust"]))
    if vector["mode"] == "historical":
        result = verify_historical(envelope, trust=trust)
    else:
        inputs = vector["current_inputs"]
        result = verify_current(
            envelope,
            trust=trust,
            authority_status=(
                _artifact(fixtures, vector["authority_status"])
                if vector.get("authority_status")
                else None
            ),
            request_nonce=inputs["request_nonce"],
            now_ms=inputs["now_ms"],
            highest_trust_log_sequence=inputs["highest_trust_log_sequence"],
            highest_trust_log_head=inputs["highest_trust_log_head"],
            maximum_staleness_ms=inputs["maximum_staleness_ms"],
        )
    return "OK" if result.ok else result.code.value


def _go_code(binary: Path, fixtures: Path, vector: dict[str, Any]) -> str:
    command = [
        str(binary),
        vector["mode"],
        "--certificate",
        str(fixtures / vector["certificate"]),
        "--trust",
        str(fixtures / vector["trust"]),
    ]
    if vector["mode"] == "current":
        inputs = vector["current_inputs"]
        command.extend(
            [
                "--request-nonce",
                inputs["request_nonce"],
                "--now-ms",
                inputs["now_ms"],
                "--highest-trust-log-sequence",
                inputs["highest_trust_log_sequence"],
                "--highest-trust-log-head",
                inputs["highest_trust_log_head"],
                "--maximum-staleness-ms",
                inputs["maximum_staleness_ms"],
            ]
        )
        if vector.get("authority_status"):
            command.extend(
                ["--authority-status", str(fixtures / vector["authority_status"])]
            )
    completed = subprocess.run(command, check=False, capture_output=True, text=True)
    if completed.returncode not in {0, 1}:
        raise RuntimeError(f"Go verifier operational failure: {completed.stderr}")
    output = json.loads(completed.stdout)
    if set(output) != {
        "certificate_digest",
        "code",
        "mode",
        "ok",
        "protocol_version",
    }:
        raise ValueError("unstable Go verifier output schema")
    return output["code"]


def main() -> int:
    arguments = _arguments()
    manifest = json.loads((arguments.fixtures / "manifest.json").read_bytes())
    failures: list[str] = []
    for vector in manifest["vectors"]:
        expected = vector["expected_code"]
        python_code = _python_code(arguments.fixtures, vector)
        go_code = _go_code(arguments.go_binary, arguments.fixtures, vector)
        if python_code != expected or go_code != expected:
            failures.append(
                f"{vector['name']}: expected={expected} python={python_code} go={go_code}"
            )
    if failures:
        print("\n".join(failures), file=sys.stderr)
        return 1
    print(f"APCC differential PASS ({len(manifest['vectors'])} vectors)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
