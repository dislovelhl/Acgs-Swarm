"""Artifact Store — stigmergic coordination medium.

Agents interact through artifacts, not messages. The store IS the
coordination mechanism. Like how ants coordinate through pheromones,
agents coordinate through published artifacts.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any

from constitutional_swarm.governance_errors import GovernanceBypassDenied


def _freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType(
            {str(key): _freeze(item) for key, item in value.items()}
        )
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(item) for item in value)
    if isinstance(value, set):
        return tuple(sorted((_freeze(item) for item in value), key=repr))
    return value


def _thaw(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _thaw(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw(item) for item in value]
    return value


@dataclass(frozen=True, slots=True)
class Artifact:
    """An immutable, content-addressed work product.

    Artifacts are the outputs of agent work. They are stored in the
    artifact store and can be referenced by downstream tasks.
    Content-addressed via SHA-256 for integrity verification.
    """

    artifact_id: str
    task_id: str
    agent_id: str
    content_type: str
    content: str
    domain: str = ""
    tags: tuple[str, ...] = ()
    timestamp: float = field(default_factory=time.time)
    constitutional_hash: str = ""
    parent_artifacts: tuple[str, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "tags", tuple(self.tags))
        object.__setattr__(self, "parent_artifacts", tuple(self.parent_artifacts))
        object.__setattr__(self, "metadata", _freeze(self.metadata))

    def canonical_dict(self) -> dict[str, Any]:
        return {
            "artifact_id": self.artifact_id,
            "task_id": self.task_id,
            "agent_id": self.agent_id,
            "content_type": self.content_type,
            "content": self.content,
            "domain": self.domain,
            "tags": list(self.tags),
            "timestamp": self.timestamp,
            "constitutional_hash": self.constitutional_hash,
            "parent_artifacts": list(self.parent_artifacts),
            "metadata": _thaw(self.metadata),
        }

    @property
    def content_hash(self) -> str:
        """SHA-256 hash of the content for integrity verification."""
        return hashlib.sha256(
            json.dumps(
                self.canonical_dict(), sort_keys=True, separators=(",", ":")
            ).encode()
        ).hexdigest()[:32]

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "artifact_id": self.artifact_id,
            "task_id": self.task_id,
            "agent_id": self.agent_id,
            "content_type": self.content_type,
            "content_hash": self.content_hash,
            "domain": self.domain,
            "tags": list(self.tags),
            "timestamp": self.timestamp,
            "constitutional_hash": self.constitutional_hash,
            "parent_artifacts": list(self.parent_artifacts),
        }


@dataclass(frozen=True, slots=True)
class ArtifactEvent:
    """Workflow-scoped immutable watcher notification."""

    workflow_id: str
    artifact: Artifact


class ArtifactStore:
    """In-memory artifact store for stigmergic coordination.

    Agents publish artifacts. Other agents discover and consume them.
    No direct messaging — all coordination through the store.

    In production, this would be backed by git, a database, or
    object storage. The in-memory version is for prototyping.
    """

    def __init__(self) -> None:
        self._artifacts: dict[tuple[str, str], Artifact] = {}
        self._revoked: set[tuple[str, str]] = set()
        self._by_task: dict[tuple[str, str], list[tuple[str, str]]] = {}
        self._by_domain: dict[tuple[str, str], list[tuple[str, str]]] = {}
        self._by_agent: dict[tuple[str, str], list[tuple[str, str]]] = {}
        self._watchers: dict[tuple[str, str], list[Any]] = {}
        self._governed_guards: dict[str, tuple[object, Callable[[str], bool]]] = {}
        self._governed_seal_ids: dict[str, str] = {}
        self._lock = threading.Lock()

    def set_visibility_guard(self, guard: Callable[[str], bool] | None) -> None:
        del guard
        raise GovernanceBypassDenied("governed_projection_is_monotonic")

    def _bind_governed(
        self,
        *,
        workflow_id: str,
        seal_id: str,
        guard: Callable[[str], bool],
    ) -> _GovernedProjectionPort:
        with self._lock:
            prior = self._governed_seal_ids.get(workflow_id)
            if prior is not None and prior != seal_id:
                raise GovernanceBypassDenied("governed_projection_seal_conflict")
            if prior is None:
                capability = object()
                self._governed_seal_ids[workflow_id] = seal_id
                self._governed_guards[workflow_id] = (capability, guard)
            else:
                capability, _prior_guard = self._governed_guards[workflow_id]
        return _GovernedProjectionPort(self, workflow_id, seal_id, capability)

    def _is_visible(self, key: tuple[str, str]) -> bool:
        with self._lock:
            if key in self._revoked or key not in self._artifacts:
                return False
            guarded = self._governed_guards.get(key[0])
        if guarded is None:
            return True
        try:
            return bool(guarded[1](key[1]))
        except BaseException:
            return False

    def publish(self, artifact: Artifact) -> str:
        """Publish an artifact to the store.

        Returns the artifact ID. Notifies watchers of the artifact's
        task_id and domain. Rejects duplicates.

        Thread-safe: duplicate check and index mutations are atomically
        protected by the store lock.  Watcher callbacks are fired
        *outside* the lock so they can safely call back into the store
        without deadlocking.
        """
        with self._lock:
            if self._governed_guards:
                raise GovernanceBypassDenied("governed_projection_is_sealed")
        callbacks = self.publish_deferred(artifact)
        self._dispatch_callbacks("", Artifact(**artifact.canonical_dict()), callbacks)
        return artifact.artifact_id

    def publish_deferred(self, artifact: Artifact) -> tuple[Any, ...]:
        """Store an artifact and return callbacks for deferred dispatch.

        This keeps direct ``publish()`` behavior unchanged while allowing
        executor code to release its own locks before firing watcher callbacks.
        """
        with self._lock:
            if self._governed_guards:
                raise GovernanceBypassDenied("governed_projection_is_sealed")
        return self._publish_deferred("", artifact, capability=None)

    def _publish_deferred(
        self, workflow_id: str, artifact: Artifact, *, capability: object | None
    ) -> tuple[Any, ...]:
        key = (workflow_id, artifact.artifact_id)
        with self._lock:
            if workflow_id:
                guarded = self._governed_guards.get(workflow_id)
                if guarded is None or guarded[0] is not capability:
                    raise GovernanceBypassDenied("invalid_projection_capability")
                try:
                    authoritative = bool(guarded[1](artifact.artifact_id))
                except BaseException:
                    authoritative = False
                if not authoritative:
                    raise GovernanceBypassDenied(
                        "projection_artifact_not_authoritative"
                    )
            if key in self._artifacts:
                raise ValueError(f"Artifact {artifact.artifact_id} already exists")
            immutable = Artifact(**artifact.canonical_dict())
            self._artifacts[key] = immutable
            self._by_task.setdefault((workflow_id, immutable.task_id), []).append(key)
            self._by_domain.setdefault((workflow_id, immutable.domain), []).append(key)
            self._by_agent.setdefault((workflow_id, immutable.agent_id), []).append(key)
            return self._collect_callbacks_unlocked(workflow_id, immutable)

    def _dispatch_callbacks(
        self, workflow_id: str, artifact: Artifact, callbacks: tuple[Any, ...]
    ) -> None:
        """Dispatch pre-collected watcher callbacks outside store locks."""
        event: Artifact | ArtifactEvent = (
            ArtifactEvent(workflow_id, artifact) if workflow_id else artifact
        )
        for callback in callbacks:
            callback(event)

    def redispatch_callbacks(self, artifact: Artifact) -> None:
        """Retry watcher publication for an already stored artifact.

        Transactional-outbox retries are at-least-once: callbacks must be
        idempotent because a process can lose its response after delivery.
        """
        with self._lock:
            stored = self._artifacts.get(("", artifact.artifact_id))
            if stored != artifact:
                raise ValueError(
                    f"Artifact {artifact.artifact_id} is missing or conflicts"
                )
            callbacks = self._collect_callbacks_unlocked("", artifact)
        self._dispatch_callbacks("", artifact, callbacks)

    def get(
        self, artifact_id: str, *, workflow_id: str | None = None
    ) -> Artifact | None:
        """Retrieve an artifact by ID."""
        with self._lock:
            if workflow_id is not None:
                key = (workflow_id, artifact_id)
            else:
                matches = [key for key in self._artifacts if key[1] == artifact_id]
                if any(key[0] in self._governed_guards for key in matches):
                    raise GovernanceBypassDenied(
                        "workflow_id_required_for_governed_read"
                    )
                if len(matches) != 1:
                    return None
                key = matches[0]
            artifact = self._artifacts.get(key)
        if artifact is None or not self._is_visible(key):
            return None
        return Artifact(**artifact.canonical_dict())

    def revoke(self, artifact_id: str) -> None:
        """Make a projected artifact non-consumable, idempotently."""
        with self._lock:
            if self._governed_guards:
                raise GovernanceBypassDenied("governed_projection_is_sealed")
            self._revoked.add(("", artifact_id))

    def _revoke_governed(
        self, workflow_id: str, artifact_id: str, *, capability: object
    ) -> None:
        with self._lock:
            guarded = self._governed_guards.get(workflow_id)
            if guarded is None or guarded[0] is not capability:
                raise GovernanceBypassDenied("invalid_projection_capability")
            self._revoked.add((workflow_id, artifact_id))

    def get_by_task(self, task_id: str, *, workflow_id: str = "") -> list[Artifact]:
        """Get all artifacts for a task."""
        with self._lock:
            ids = list(self._by_task.get((workflow_id, task_id), []))
            artifacts = {key: self._artifacts.get(key) for key in ids}
        return [
            artifact
            for key, artifact in artifacts.items()
            if artifact is not None and self._is_visible(key)
        ]

    def get_by_domain(self, domain: str, *, workflow_id: str = "") -> list[Artifact]:
        """Get all artifacts in a domain."""
        with self._lock:
            ids = list(self._by_domain.get((workflow_id, domain), []))
            artifacts = {key: self._artifacts.get(key) for key in ids}
        return [
            artifact
            for key, artifact in artifacts.items()
            if artifact is not None and self._is_visible(key)
        ]

    def get_by_agent(self, agent_id: str, *, workflow_id: str = "") -> list[Artifact]:
        """Get all artifacts produced by an agent."""
        with self._lock:
            ids = list(self._by_agent.get((workflow_id, agent_id), []))
            artifacts = {key: self._artifacts.get(key) for key in ids}
        return [
            artifact
            for key, artifact in artifacts.items()
            if artifact is not None and self._is_visible(key)
        ]

    def watch(self, key: str, callback: Any, *, workflow_id: str | None = None) -> None:
        """Register a watcher for a task_id or domain.

        Callback is called when a matching artifact is published.
        """
        with self._lock:
            if workflow_id is None:
                if self._governed_guards:
                    raise GovernanceBypassDenied(
                        "workflow_id_required_for_governed_watch"
                    )
                workflow_id = ""
            self._watchers.setdefault((workflow_id, key), []).append(callback)

    def _collect_callbacks_unlocked(
        self, workflow_id: str, artifact: Artifact
    ) -> tuple[Any, ...]:
        """Collect callbacks for an artifact while the store lock is held."""
        return tuple(
            cb
            for key in (artifact.task_id, artifact.domain)
            for cb in self._watchers.get((workflow_id, key), [])
        )

    def verify_integrity(self, artifact_id: str, *, workflow_id: str = "") -> bool:
        """Verify an artifact's content hash hasn't been tampered with."""
        with self._lock:
            key = (workflow_id, artifact_id)
            artifact = self._artifacts.get(key)
        if artifact is None or not self._is_visible(key):
            return False
        expected = Artifact(**artifact.canonical_dict()).content_hash
        return artifact.content_hash == expected

    @property
    def count(self) -> int:
        """Number of currently visible artifacts."""
        with self._lock:
            keys = list(self._artifacts)
        return sum(self._is_visible(key) for key in keys)

    def summary(self) -> dict[str, Any]:
        """Store summary statistics."""
        with self._lock:
            keys = list(self._artifacts)
            artifacts = dict(self._artifacts)
        visible_keys = [key for key in keys if self._is_visible(key)]
        visible = [artifacts[key] for key in visible_keys]
        return {
            "total_artifacts": len(visible),
            "domains": len({artifact.domain for artifact in visible}),
            "agents": len({artifact.agent_id for artifact in visible}),
            "tasks": len({artifact.task_id for artifact in visible}),
        }


class _GovernedProjectionPort:
    """Capability-bearing projector; deliberately absent from public exports."""

    def __init__(
        self,
        store: ArtifactStore,
        workflow_id: str,
        seal_id: str,
        capability: object,
    ) -> None:
        self._store = store
        self.workflow_id = workflow_id
        self.seal_id = seal_id
        self._capability = capability

    def get(self, artifact_id: str) -> Artifact | None:
        return self._store.get(artifact_id, workflow_id=self.workflow_id)

    def watch(self, key: str, callback: Any) -> None:
        self._store.watch(key, callback, workflow_id=self.workflow_id)

    def publish(self, artifact: Artifact) -> tuple[Any, ...]:
        return self._store._publish_deferred(
            self.workflow_id, artifact, capability=self._capability
        )

    def dispatch(self, artifact_id: str, callbacks: tuple[Any, ...]) -> None:
        artifact = self.get(artifact_id)
        if artifact is None:
            raise GovernanceBypassDenied("projection_artifact_not_authoritative")
        self._store._dispatch_callbacks(self.workflow_id, artifact, callbacks)

    def redispatch(self, artifact: Artifact) -> None:
        existing = self.get(artifact.artifact_id)
        if existing != artifact:
            raise GovernanceBypassDenied("projection_artifact_conflict")
        with self._store._lock:
            callbacks = self._store._collect_callbacks_unlocked(
                self.workflow_id, existing
            )
        self._store._dispatch_callbacks(self.workflow_id, existing, callbacks)

    def revoke(self, artifact_id: str) -> None:
        self._store._revoke_governed(
            self.workflow_id, artifact_id, capability=self._capability
        )
