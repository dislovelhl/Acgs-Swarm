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
- The failing HIGH audit finding is now a live regression test: if anyone removes
  the gate, this test turns red and the security-audit-report.md auto-generator
  flags the finding as back-open.
"""

from __future__ import annotations

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


@pytest.mark.security
@pytest.mark.asyncio
class TestFindingSEC001:
    async def test_non_localhost_without_tls_raises(self) -> None:
        client = RemoteVoteClient()
        req = _minimal_request()
        with pytest.raises(ValueError, match=r"TLS"):
            await client.request_vote(
                host="peer.example.com",
                port=8443,
                request=req,
                ssl_context=None,
            )

    @pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "::1"])
    async def test_loopback_without_tls_passes_gate(self, host: str) -> None:
        """Loopback must pass the TLS gate. Downstream IO/import failures are fine —
        what matters is the gate at lines 122-124 does not fire here."""
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
        except ValueError as e:
            if "TLS" in str(e):
                pytest.fail(f"TLS gate incorrectly fired for loopback host {host!r}: {e}")
        except (TimeoutError, OSError, ImportError, Exception):
            pass
