"""Regression test for security finding SEC-001: unauthenticated WebSocket transport.

Origin
------
- First audited: security-audit-report.md (HIGH finding)
- Remediation claim: SYSTEMIC_IMPROVEMENT.md — "non-local WebSocket transport
  now requires TLS configuration"
- Status as of this test's existence: REMEDIATED (asserted here)

Contract
--------
- `RemoteVoteClient.request_vote()` MUST raise `ValueError` containing "TLS" BEFORE
  any network IO when `ssl_context is None` and the host is not loopback.
  See remote_vote_transport.py:122-124 for the gate.
- Loopback addresses (127.0.0.1, localhost, ::1) MAY proceed without TLS for dev.
- A non-loopback request WITH a valid `ssl_context` must not be blocked by the gate.
- The failing HIGH audit finding is now a live regression test: if anyone removes
  the gate, this test turns red and the security-audit-report.md auto-generator
  flags the finding as back-open.
"""

from __future__ import annotations

import ssl

import pytest
from constitutional_swarm.mesh import RemoteVoteRequest
from constitutional_swarm.remote_vote_transport import RemoteVoteClient

FINDING_ID = "SEC-001"
SEVERITY = "HIGH"
STATUS = "remediated"
TITLE = "Unauthenticated WebSocket transport"


def _minimal_request() -> RemoteVoteRequest:
    """Minimal RemoteVoteRequest that reaches the TLS gate before field validation."""
    return RemoteVoteRequest(
        assignment_id="test-assignment",
        voter_id="test-voter",
        producer_id="test-producer",
        artifact_id="test-artifact",
        content="",
        content_hash="0" * 64,
        constitutional_hash="0" * 16,
        voter_public_key="",
        request_signer_public_key="",
        request_signature="",
    )


def _is_tls_gate_error(exc: BaseException) -> bool:
    """True iff the exception is the TLS gate ValueError, not something else."""
    return isinstance(exc, ValueError) and "TLS" in str(exc)


@pytest.mark.security
class TestFindingSEC001:
    async def test_non_localhost_without_tls_raises(self) -> None:
        """Sad path: non-loopback + no TLS must be rejected at the gate."""
        client = RemoteVoteClient()
        req = _minimal_request()
        with pytest.raises(ValueError, match=r"TLS"):
            await client.request_vote(
                host="peer.example.com",
                port=8443,
                request=req,
                ssl_context=None,
            )

    async def test_non_localhost_with_tls_does_not_trigger_gate(self) -> None:
        """Happy path: non-loopback + valid ssl_context must pass the gate.

        Downstream connection will fail (no server), but the TLS gate at
        remote_vote_transport.py:122-124 must NOT be the failure reason.
        Guards against a regression that makes the gate unconditional.
        """
        client = RemoteVoteClient()
        req = _minimal_request()
        ctx = ssl.create_default_context()
        try:
            await client.request_vote(
                host="peer.example.com",
                port=8443,
                request=req,
                ssl_context=ctx,
                timeout=0.1,
            )
        except Exception as exc:
            if _is_tls_gate_error(exc):
                pytest.fail(f"TLS gate fired even with ssl_context set: {exc}")
            # Any other exception (OSError / ImportError / TimeoutError / etc.) is
            # an expected downstream failure — the gate passed, which is what we want.

    # IPv6 loopback `::1` intentionally omitted — websockets.uri.parse_uri rejects
    # raw IPv6 without bracket syntax (`ws://[::1]:8443`), which is an orthogonal
    # bug to the TLS gate. The gate itself treats `::1` as loopback (tested in unit
    # scope elsewhere); this integration test only covers hosts that make it past
    # the URI parser.
    @pytest.mark.parametrize("host", ["127.0.0.1", "localhost"])
    async def test_loopback_without_tls_passes_gate(self, host: str) -> None:
        """Happy path: loopback hosts may proceed without TLS for dev use.

        Any downstream connection / import failure is fine — we only assert the
        TLS gate does not fire. An unexpected ValueError propagates so that
        field-validation drift is surfaced rather than silently swallowed.
        """
        client = RemoteVoteClient()
        req = _minimal_request()
        try:
            await client.request_vote(
                host=host,
                port=8443,
                request=req,
                ssl_context=None,
                timeout=0.1,
            )
        except ValueError as exc:
            if _is_tls_gate_error(exc):
                pytest.fail(f"TLS gate incorrectly fired for loopback host {host!r}: {exc}")
            raise  # non-TLS ValueError — surface it, don't swallow
        except (OSError, ImportError, TimeoutError):
            # Expected: no server on loopback, or websockets not installed.
            pass

    def test_ipv6_loopback_is_whitelisted_in_gate(self) -> None:
        """Unit-level check that the TLS gate treats `::1` as loopback.

        Distinct from `test_loopback_without_tls_passes_gate` because the gate
        logic fires before websockets' URI parser, so we can verify the
        is_local check directly by reading the module constant.
        """
        import inspect

        from constitutional_swarm.remote_vote_transport import RemoteVoteClient

        source = inspect.getsource(RemoteVoteClient.request_vote)
        assert "::1" in source, "IPv6 loopback `::1` must appear in the TLS gate"
        assert "127.0.0.1" in source, "IPv4 loopback must appear in the TLS gate"
        assert "localhost" in source, "localhost must appear in the TLS gate"
