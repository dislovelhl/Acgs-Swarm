"""Peer-side validation and signing for remote vote requests."""

from __future__ import annotations

import hashlib
from collections import OrderedDict

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from acgs_lite import Constitution
from constitutional_swarm.dna import AgentDNA
from constitutional_swarm.mesh import ConstitutionalMesh, RemoteVoteRequest
from constitutional_swarm.remote_vote_transport.protocol import RemoteVoteResponse


class LocalRemotePeer:
    """Runtime for a public-key-only remote peer that validates/signs votes."""

    def __init__(
        self,
        *,
        agent_id: str,
        constitution: Constitution,
        vote_private_key: Ed25519PrivateKey | bytes | str | None = None,
        strict: bool = False,
        trusted_request_signers: set[str] | None = None,
        allow_untrusted_request_signers: bool = False,
        replay_window_seconds: float = 300.0,
    ) -> None:
        self.agent_id = agent_id
        self.constitution = constitution
        self.strict = strict
        self._dna = AgentDNA(
            constitution=constitution,
            agent_id=agent_id,
            strict=strict,
        )
        self._private_key = self._coerce_private_key(vote_private_key)
        self._public_key = self._private_key.public_key()
        self._trusted_request_signers = set(trusted_request_signers or set())
        self._allow_untrusted_request_signers = allow_untrusted_request_signers
        self._replay_window_seconds = replay_window_seconds
        self._request_nonce_cache: OrderedDict[str, float] = OrderedDict()

    @property
    def public_key_hex(self) -> str:
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        ).hex()

    def handle_vote_request(self, request: RemoteVoteRequest) -> RemoteVoteResponse:
        if request.voter_id != self.agent_id:
            raise ValueError(
                f"Vote request intended for {request.voter_id}, but peer is {self.agent_id}"
            )
        if request.voter_public_key != self.public_key_hex:
            raise ValueError("Vote request public key does not match remote peer identity")
        ConstitutionalMesh.verify_remote_vote_request(
            request,
            replay_window_seconds=self._replay_window_seconds,
            nonce_cache=self._request_nonce_cache,
        )
        if (
            not self._allow_untrusted_request_signers
            and request.request_signer_public_key not in self._trusted_request_signers
        ):
            raise ValueError("Remote vote request signer is not trusted")
        if hashlib.sha256(request.content.encode("utf-8")).hexdigest()[:32] != request.content_hash:
            raise ValueError("Remote vote request content does not match content hash")

        result = self._dna.validate(request.content)
        approved = result.valid
        reason = "constitutional check passed" if result.valid else "; ".join(result.violations)
        signature = self._private_key.sign(
            ConstitutionalMesh.build_vote_payload(
                assignment_id=request.assignment_id,
                voter_id=request.voter_id,
                approved=approved,
                reason=reason,
                constitutional_hash=request.constitutional_hash,
                content_hash=request.content_hash,
            )
        ).hex()
        return RemoteVoteResponse(
            assignment_id=request.assignment_id,
            voter_id=request.voter_id,
            approved=approved,
            reason=reason,
            constitutional_hash=request.constitutional_hash,
            content_hash=request.content_hash,
            signature=signature,
        )

    @staticmethod
    def _coerce_private_key(
        value: Ed25519PrivateKey | bytes | str | None,
    ) -> Ed25519PrivateKey:
        if value is None:
            return Ed25519PrivateKey.generate()
        if isinstance(value, Ed25519PrivateKey):
            return value
        raw = bytes.fromhex(value) if isinstance(value, str) else value
        return Ed25519PrivateKey.from_private_bytes(raw)


__all__ = ["LocalRemotePeer"]
