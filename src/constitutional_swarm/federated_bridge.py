"""Federated Constitution Bridge — cross-organisational FCHP layer.

Implements the Federated Constitutional Hybrid Protocol (FCHP) for
cross-organisational constitutional rule propagation.

Architecture:
    - AgentCredential  — verifiable identity for a cross-org AI agent
    - FederatedConstitutionBridge — enforces fail-closed cross-org rule gates

Security contract:
    - Unknown credentials → REJECT (fail-closed, never fail-open)
    - Constitutional hash mismatch → REJECT
    - Revoked credentials → REJECT
    - All decisions are logged for audit

Research basis:
    - Constitutional Evolution (arXiv:2602.00755): cross-org constitutions
      68% better than human-designed when evolved with minimal inter-agent comm
    - Linux Foundation Agentic AI Foundation (Dec 2025): MCP+A2A+AGENTS.md
      as vendor-neutral connectivity substrate
    - EU AI Act Articles 9/12/13: cross-org accountability chain
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from constitutional_swarm.constants import CONSTITUTIONAL_HASH as _CONSTITUTIONAL_HASH


class CredentialStatus(Enum):
    """Lifecycle state of an AgentCredential."""

    ACTIVE = "active"
    REVOKED = "revoked"
    EXPIRED = "expired"
    PENDING = "pending"  # awaiting org-level approval


@dataclass(frozen=True, slots=True)
class AgentCredential:
    """Verifiable identity for a cross-organisational AI agent.

    Attributes:
        agent_id:           Unique agent identifier (UUID-like string).
        org_id:             Organisation that issued this credential.
        pubkey_fingerprint: Hex fingerprint of the agent's public key.
        constitutional_hash: Hash of the constitution this agent operates under.
        issued_at:          Unix timestamp of issuance.
        expires_at:         Unix timestamp of expiry (0 = never expires).
        domains:            Governance domains this agent is authorised for.
        metadata:           Arbitrary issuer metadata.

    Example::

        cred = AgentCredential(
            agent_id="agent-finance-42",
            org_id="acme-corp",
            pubkey_fingerprint="deadbeef1234",
            constitutional_hash="608508a9bd224290",
            issued_at=int(time.time()),
        )
    """

    agent_id: str
    org_id: str
    pubkey_fingerprint: str
    constitutional_hash: str
    issued_at: float
    expires_at: float = 0.0
    domains: tuple[str, ...] = ()
    status: CredentialStatus = CredentialStatus.ACTIVE
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def fingerprint(self) -> str:
        """Stable credential fingerprint (sha256 of key fields)."""
        raw = f"{self.agent_id}:{self.org_id}:{self.pubkey_fingerprint}:{self.constitutional_hash}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def is_expired(self, now: float | None = None) -> bool:
        """True if the credential has passed its expiry timestamp."""
        if self.expires_at == 0.0:
            return False
        _now = time.time() if now is None else now
        return _now > self.expires_at

    def authorised_for(self, domain: str) -> bool:
        """True if this credential covers the requested domain."""
        return not self.domains or domain in self.domains


@dataclass
class FederationDecision:
    """Record of a single bridge access decision.

    Attributes:
        agent_id:   Agent that attempted access.
        org_id:     Organisation of the agent.
        domain:     Requested governance domain.
        allowed:    True if access was granted.
        reason:     Human-readable decision rationale.
        timestamp:  Unix timestamp of decision.
        rule_hash:  Constitutional hash validated against.
    """

    agent_id: str
    org_id: str
    domain: str
    allowed: bool
    reason: str
    timestamp: float = field(default_factory=time.time)
    rule_hash: str = _CONSTITUTIONAL_HASH

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "org_id": self.org_id,
            "domain": self.domain,
            "allowed": self.allowed,
            "reason": self.reason,
            "timestamp": self.timestamp,
            "rule_hash": self.rule_hash,
        }


class FederatedConstitutionBridge:
    """Enforces cross-organisational constitutional rule gates.

    Implements fail-closed semantics: any unknown, revoked, expired, or
    hash-mismatched credential is rejected.  No silent failures.

    Usage::

        bridge = FederatedConstitutionBridge(
            local_constitutional_hash="608508a9bd224290",
        )

        cred = AgentCredential(
            agent_id="agent-42",
            org_id="partner-corp",
            pubkey_fingerprint="abcdef",
            constitutional_hash="608509bd224290",  # WRONG HASH
            issued_at=time.time(),
        )
        bridge.register_credential(cred)

        decision = bridge.gate(cred.agent_id, domain="privacy")
        assert not decision.allowed   # hash mismatch → fail-closed

    Args:
        local_constitutional_hash: The constitutional hash this bridge enforces.
        require_hash_match: If True (default), cross-org agents must present
            the same constitutional hash (strict federation mode).
        audit_log_size: Maximum decision audit log entries.
    """

    def __init__(
        self,
        local_constitutional_hash: str = _CONSTITUTIONAL_HASH,
        *,
        require_hash_match: bool = True,
        audit_log_size: int = 1000,
    ) -> None:
        self._local_hash = local_constitutional_hash
        self._require_hash = require_hash_match
        self._audit_log_size = audit_log_size

        self._credentials: dict[str, AgentCredential] = {}
        self._revoked: set[str] = set()
        self._audit_log: list[FederationDecision] = []

    # ── Credential management ────────────────────────────────────────────

    def register_credential(self, cred: AgentCredential) -> None:
        """Register a cross-org agent credential.

        Registration does not grant access — the credential is vetted
        at gate() time.

        Args:
            cred: Agent credential issued by a federated organisation.
        """
        self._credentials[cred.agent_id] = cred

    def revoke(self, agent_id: str) -> bool:
        """Revoke a credential immediately.

        Returns True if the credential was known, False otherwise.
        """
        self._revoked.add(agent_id)
        return agent_id in self._credentials

    def registered_agents(self) -> list[str]:
        """List all registered agent IDs (including revoked)."""
        return list(self._credentials)

    # ── Gate ─────────────────────────────────────────────────────────────

    def gate(
        self,
        agent_id: str,
        *,
        domain: str = "",
        now: float | None = None,
    ) -> FederationDecision:
        """Evaluate cross-org access for an agent.

        Fail-closed: returns allowed=False for any rejection reason.

        Rejection conditions:
            1. Credential not registered → UNKNOWN
            2. Credential revoked → REVOKED
            3. Credential expired → EXPIRED
            4. Constitutional hash mismatch (if require_hash_match) → HASH_MISMATCH
            5. Domain not authorised → DOMAIN_DENIED

        Args:
            agent_id: Agent requesting cross-org access.
            domain:   Governance domain for the operation.
            now:      Override current time (for testing).

        Returns:
            FederationDecision with allowed flag and reason.
        """
        _now = time.time() if now is None else now
        cred = self._credentials.get(agent_id)

        # 1. Unknown credential
        if cred is None:
            return self._deny(agent_id, "", domain, "UNKNOWN_CREDENTIAL", _now)

        # 2. Pending (awaiting approval) — fail-closed
        if cred.status == CredentialStatus.PENDING:
            return self._deny(agent_id, cred.org_id, domain, "CREDENTIAL_PENDING", _now)

        # 3. Revoked
        if agent_id in self._revoked:
            return self._deny(agent_id, cred.org_id, domain, "REVOKED", _now)

        # 4. Expired
        if cred.is_expired(now=_now):
            return self._deny(agent_id, cred.org_id, domain, "EXPIRED", _now)

        # 5. Constitutional hash mismatch
        if self._require_hash and cred.constitutional_hash != self._local_hash:
            return self._deny(agent_id, cred.org_id, domain, "HASH_MISMATCH", _now)

        # 6. Domain authorisation
        if domain and not cred.authorised_for(domain):
            return self._deny(agent_id, cred.org_id, domain, "DOMAIN_DENIED", _now)

        return self._allow(agent_id, cred.org_id, domain, _now)

    # ── Audit ─────────────────────────────────────────────────────────────

    def audit_log(self) -> list[dict[str, Any]]:
        """Full decision audit log (most recent last)."""
        return [d.to_dict() for d in self._audit_log]

    def denied_count(self) -> int:
        """Number of denied gate decisions."""
        return sum(1 for d in self._audit_log if not d.allowed)

    def allowed_count(self) -> int:
        """Number of allowed gate decisions."""
        return sum(1 for d in self._audit_log if d.allowed)

    def summary(self) -> dict[str, Any]:
        """Bridge status summary."""
        return {
            "local_constitutional_hash": self._local_hash,
            "registered_credentials": len(self._credentials),
            "revoked_credentials": len(self._revoked),
            "total_decisions": len(self._audit_log),
            "allowed": self.allowed_count(),
            "denied": self.denied_count(),
            "require_hash_match": self._require_hash,
        }

    # ── Internal ──────────────────────────────────────────────────────────

    def _allow(
        self, agent_id: str, org_id: str, domain: str, now: float
    ) -> FederationDecision:
        decision = FederationDecision(
            agent_id=agent_id,
            org_id=org_id,
            domain=domain,
            allowed=True,
            reason="ALLOWED",
            timestamp=now,
            rule_hash=self._local_hash,
        )
        self._record(decision)
        return decision

    def _deny(
        self, agent_id: str, org_id: str, domain: str, reason: str, now: float
    ) -> FederationDecision:
        decision = FederationDecision(
            agent_id=agent_id,
            org_id=org_id,
            domain=domain,
            allowed=False,
            reason=reason,
            timestamp=now,
            rule_hash=self._local_hash,
        )
        self._record(decision)
        return decision

    def _record(self, decision: FederationDecision) -> None:
        """Append decision to audit log, pruning when over capacity."""
        self._audit_log.append(decision)
        if len(self._audit_log) > self._audit_log_size:
            self._audit_log = self._audit_log[-self._audit_log_size :]

    def __repr__(self) -> str:
        return (
            f"FederatedConstitutionBridge("
            f"credentials={len(self._credentials)}, "
            f"decisions={len(self._audit_log)})"
        )
