"""Deterministic typed APCC authority support for GCB tests."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import socket
import threading
import time
from collections.abc import Iterable, Mapping
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from constitutional_swarm.apcc.crypto import sha256_digest
from constitutional_swarm.apcc.model import Signature
from constitutional_swarm.apcc.ports import (
    APCCAuthorityConfig,
    AuthorityRuntime,
    AuthoritySigningRole,
    StatusFreshnessPolicy,
)
from constitutional_swarm.apcc.verifier import TrustBinding, TrustRole
from constitutional_swarm.governed_commit import (
    TrustedGovernanceBootstrap,
    TrustedGovernanceAdmin,
    _GCBFaultCheckpoint,
)
from constitutional_swarm.authority_child import (
    AuthorityChildConfig,
    KeySourceRef,
    OutboxSinkRef,
)


def _seed(label: str) -> bytes:
    return hashlib.sha256(f"gcb-apcc-test:{label}".encode()).digest()


def producer_key(label: str = "agent") -> Ed25519PrivateKey:
    """Return a stable test producer key without sharing production key material."""
    return Ed25519PrivateKey.from_private_bytes(_seed(f"producer:{label}"))


def canonical_nonce(label: str) -> str:
    """Return deterministic hexadecimal input representing exactly 16 bytes."""
    return _seed(f"nonce:{label}")[:16].hex()


def _public_bytes(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


class DetachedSigner:
    def __init__(self, label: str) -> None:
        self._key = Ed25519PrivateKey.from_private_bytes(_seed(label))

    def public_key_bytes(self) -> bytes:
        return _public_bytes(self._key)

    def sign(self, domain: bytes, canonical_body: bytes) -> bytes:
        return self._key.sign(domain + b"\x00" + canonical_body)


class PolicySigner:
    """Route test policy signatures to the key bound to the exact version."""

    def __init__(self, versions: Iterable[tuple[str, int]]) -> None:
        self._keys = {
            version: Ed25519PrivateKey.from_private_bytes(_seed(f"policy:{version}"))
            for version, _epoch in versions
        }

    def public_key_bytes(self, version: str | None = None) -> bytes:
        selected = version or next(iter(self._keys))
        return _public_bytes(self._keys[selected])

    def sign(self, domain: bytes, canonical_body: bytes) -> bytes:
        statement = json.loads(canonical_body)
        version = str(statement.get("policy_version", next(iter(self._keys))))
        return self._keys[version].sign(domain + b"\x00" + canonical_body)


class _KeyProvider:
    def __init__(self) -> None:
        self._keys = {
            AuthoritySigningRole.COMMIT: Ed25519PrivateKey.from_private_bytes(
                _seed("commit")
            ),
            AuthoritySigningRole.STATUS: Ed25519PrivateKey.from_private_bytes(
                _seed("status")
            ),
        }

    def public_key(self, role: AuthoritySigningRole, key_id: str) -> bytes:
        del key_id
        return _public_bytes(self._keys[role])

    def sign(
        self,
        role: AuthoritySigningRole,
        key_id: str,
        domain: bytes,
        canonical_body: bytes,
    ) -> Signature:
        signature = self._keys[role].sign(domain + b"\x00" + canonical_body)
        encoded = base64.urlsafe_b64encode(signature).rstrip(b"=").decode()
        return Signature("Ed25519", key_id, encoded)


class _Clock:
    def now_ms(self) -> int:
        return int(time.time() * 1000)


class _OutboxSink:
    def deliver(self, event_id: str, payload: bytes) -> None:
        del event_id, payload


class InProcessExecutionClientHarness:
    """Test-only adapter for the restricted executor API.

    This in-process adapter is convenience plumbing, not security evidence for
    process isolation or authority-capability unreachability.  It intentionally
    exposes only the complete runtime allowlist accepted by ``SwarmExecutor``.
    """

    def __new__(cls, admin: object):
        """Return an exact client backed by a test-only signed socketpair server."""
        from constitutional_swarm.authority_ipc import (
            digest,
            recv_frame,
            send_frame,
            signed_response,
        )
        from constitutional_swarm.authority_service import (
            _AuthorityExecutionChannel,
            _bind_verified_child_channel,
            _handle_execution_request,
        )

        client_socket, server_socket = socket.socketpair(socket.AF_UNIX)
        signing_key = Ed25519PrivateKey.generate()
        session = base64.urlsafe_b64encode(os.urandom(24)).rstrip(b"=").decode()

        def serve() -> None:
            sequence = 0
            with server_socket:
                while True:
                    try:
                        request = recv_frame(server_socket, 1_048_576)
                    except (ConnectionError, OSError, ValueError):
                        return
                    sequence += 1
                    request_digest = digest(request)
                    try:
                        result = _handle_execution_request(admin, request)
                    except Exception as exc:
                        response = signed_response(
                            key=signing_key,
                            session=session,
                            channel="execution",
                            sequence=sequence,
                            authority_pid=os.getpid(),
                            request_digest=request_digest,
                            error={"code": type(exc).__name__, "message": str(exc)},
                        )
                    else:
                        response = signed_response(
                            key=signing_key,
                            session=session,
                            channel="execution",
                            sequence=sequence,
                            authority_pid=os.getpid(),
                            request_digest=request_digest,
                            result=result,
                        )
                    try:
                        send_frame(server_socket, response, 1_048_576)
                    except (ConnectionError, OSError, ValueError):
                        return

        threading.Thread(target=serve, daemon=True).start()
        return _bind_verified_child_channel(
            _AuthorityExecutionChannel,
            client_socket,
            channel_role="execution",
            session=session,
            authority_pid=os.getpid(),
            ipc_public_key=signing_key.public_key(),
            max_frame_bytes=1_048_576,
        )


def compose_test_executor(
    registry: object,
    store: object,
    execution_client: object,
    *,
    policy_version: str,
):
    """Compose an in-process executor for tests; never security evidence."""
    from constitutional_swarm.swarm import SwarmExecutor

    executor = SwarmExecutor(registry, store, policy_version=policy_version)  # type: ignore[arg-type]
    executor._execution_client = execution_client
    return executor


class TrustedAuthorityLifecycleHarness:
    """Test-only stand-in for privileged authority-child lifecycle work."""

    __slots__ = ("__admin", "__projection")

    def __init__(self, admin: object, workflow_id: str, store: object) -> None:
        self.__admin = admin
        self.__projection = admin.bind_projection(  # type: ignore[attr-defined]
            workflow_id, store
        )

    def dispatch_after_commit(self) -> int:
        """Dispatch compatibility projection events outside the executor."""
        return self.__admin.dispatch_outbox(  # type: ignore[attr-defined]
            self.__projection
        )

    def complete_control_transition(self) -> tuple[int, int]:
        """Materialize and dispatch a trusted revocation control transition."""
        propagated = self.__admin.resume_revocation_propagation()  # type: ignore[attr-defined]
        dispatched = self.__admin.dispatch_revocation_outbox(  # type: ignore[attr-defined]
            self.__projection
        )
        return propagated, dispatched

    def recover_on_startup(self) -> tuple[int, int, int]:
        """Run the privileged durable lifecycle work performed after reopen."""
        commits = self.dispatch_after_commit()
        propagated, revocations = self.complete_control_transition()
        return commits, propagated, revocations


def provision_executor_workflow(
    admin: object, dag: object, *, policy_version: str
) -> None:
    """Provision exact executor bindings through the trusted test admin."""
    nodes = dag.nodes  # type: ignore[attr-defined]
    topology = {node_id: node.depends_on for node_id, node in nodes.items()}
    capabilities = {
        node_id: node.required_capabilities for node_id, node in nodes.items()
    }
    input_digests = {
        node_id: hashlib.sha256(
            json.dumps(
                {
                    "title": node.title,
                    "description": node.description,
                    "domain": node.domain,
                    "required_capabilities": node.required_capabilities,
                    "depends_on": node.depends_on,
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        ).hexdigest()
        for node_id, node in nodes.items()
    }
    admin.create_workflow(  # type: ignore[attr-defined]
        workflow_id=dag.dag_id,  # type: ignore[attr-defined]
        nodes=topology,
        policy_version=policy_version,
        required_capabilities=capabilities,
        input_digests=input_digests,
    )


def typed_bootstrap(
    *,
    policy_id: str = "gcb-test-policy",
    policy_versions: Iterable[tuple[str, int]] = (("policy-v1", 1),),
    producers: Mapping[str, Ed25519PrivateKey] | None = None,
    authority_store_id: str = "gcb-test-store",
    outbox_sink: object | None = None,
) -> TrustedGovernanceBootstrap:
    """Build the exact caller-explicit APCC bootstrap used by GCB tests."""
    authority_root = sha256_digest(b"gcb-test-authority-root")
    actor_authority = "authority:gcb-test:actor-authority"
    declared_producers = producers or {
        "agent": producer_key("agent"),
        "other": producer_key("other"),
    }
    declared_policy_versions = tuple(policy_versions)
    policy_signer = PolicySigner(declared_policy_versions)
    registry_signer = DetachedSigner("registry")
    control_signer = DetachedSigner("control")
    commit_key = Ed25519PrivateKey.from_private_bytes(_seed("commit"))
    status_key = Ed25519PrivateKey.from_private_bytes(_seed("status"))
    config = APCCAuthorityConfig(
        authority_store_id=authority_store_id,
        producer_trust=tuple(
            TrustBinding(
                TrustRole.PRODUCER,
                (agent_id, actor_authority, authority_root),
                f"gcb-producer-{agent_id}",
                _public_bytes(key),
            )
            for agent_id, key in declared_producers.items()
        ),
        policy_trust=tuple(
            TrustBinding(
                TrustRole.POLICY,
                (policy_id, version, str(epoch)),
                f"gcb-policy-key-{version}",
                policy_signer.public_key_bytes(version),
            )
            for version, epoch in declared_policy_versions
        ),
        registry_trust=(
            TrustBinding(
                TrustRole.REGISTRY,
                (authority_root, "1"),
                "gcb-registry-key",
                registry_signer.public_key_bytes(),
            ),
        ),
        commit_trust=TrustBinding(
            TrustRole.COMMIT,
            (authority_store_id,),
            "gcb-commit-key",
            _public_bytes(commit_key),
        ),
        status_trust=TrustBinding(
            TrustRole.STATUS,
            (authority_store_id,),
            "gcb-status-key",
            _public_bytes(status_key),
        ),
        freshness=StatusFreshnessPolicy("5000", "1000"),
    )
    return TrustedGovernanceBootstrap(
        config=config,
        runtime=AuthorityRuntime(
            _KeyProvider(),
            _Clock(),
            outbox_sink or _OutboxSink(),  # type: ignore[arg-type]
        ),
        policy_signer=policy_signer,
        registry_signer=registry_signer,
        control_signer=control_signer,
    )


def authority_child_config(
    database_path: str | Path,
    key_bundle_path: str | Path,
    *,
    policy_versions: Iterable[tuple[str, int]] = (("1", 1),),
    producers: Mapping[str, Ed25519PrivateKey] | None = None,
    provision: bool = True,
) -> AuthorityChildConfig:
    """Write a secure deterministic test key bundle and return public child config."""
    declared_versions = tuple(policy_versions)
    bootstrap = typed_bootstrap(
        policy_versions=declared_versions,
        producers=producers,
    )
    identity = Ed25519PrivateKey.from_private_bytes(_seed("authority-identity"))

    def private_seed(label: str) -> str:
        return base64.urlsafe_b64encode(_seed(label)).rstrip(b"=").decode()

    bundle = {
        "policy": {
            version: private_seed(f"policy:{version}")
            for version, _epoch in declared_versions
        },
        "registry": private_seed("registry"),
        "control": private_seed("control"),
        "commit": private_seed("commit"),
        "status": private_seed("status"),
        "identity": private_seed("authority-identity"),
    }
    path = Path(key_bundle_path)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(
            descriptor,
            json.dumps(bundle, sort_keys=True, separators=(",", ":")).encode(),
        )
    finally:
        os.close(descriptor)
    return AuthorityChildConfig(
        database_path=str(database_path),
        authority=bootstrap.config,
        key_source=KeySourceRef("file", str(path), _public_bytes(identity)),
        outbox_sink=OutboxSinkRef(),
        provision=provision,
    )


def configure_test_seams(
    admin: TrustedGovernanceAdmin,
    *,
    fault_checkpoint: _GCBFaultCheckpoint | None = None,
    busy_timeout_ms: int = 5_000,
) -> TrustedGovernanceAdmin:
    """Configure runtime fault seams without widening the public bootstrap API."""
    port = admin.commit_port
    if fault_checkpoint is not None and not isinstance(
        fault_checkpoint, _GCBFaultCheckpoint
    ):
        raise TypeError("GCB fault must be a fixed checkpoint")
    port._fault_checkpoint = fault_checkpoint
    port._fault_checkpoint_fired = False
    port._busy_timeout_ms = busy_timeout_ms
    return admin


def open_typed_admin(
    bootstrap: TrustedGovernanceBootstrap,
    path: str | Path,
    *,
    fault_checkpoint: _GCBFaultCheckpoint | None = None,
    busy_timeout_ms: int = 5_000,
):
    return configure_test_seams(
        bootstrap.open_admin(path),
        fault_checkpoint=fault_checkpoint,
        busy_timeout_ms=busy_timeout_ms,
    )
