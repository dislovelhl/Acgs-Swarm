"""Stigmergic Swarm — orchestrator-free task execution via compiled DAGs.

Goals are compiled into task DAGs. Agents self-select tasks based on
capability. Completed artifacts unlock downstream tasks. No orchestrator,
no coordination messages. Works identically for 8 or 800 agents.
"""

from __future__ import annotations

import hashlib
import json
import threading
import uuid
from dataclasses import dataclass, field, replace
from typing import Any

from constitutional_swarm.artifact import Artifact, ArtifactStore
from constitutional_swarm.capability import CapabilityRegistry
from constitutional_swarm.execution import (
    ContractStatus,
    ExecutionStatus,
    WorkReceipt,
    contract_status_from_execution,
)
from constitutional_swarm.governed_commit import (
    AttemptAuthorizationPayload,
    CommitDecision,
    CommitOutcome,
    CommitRequest,
    GovernanceBypassDenied,
    GovernedReceiptPayload,
    SignedAttemptAuthorization,
)

NodeStatus = ExecutionStatus
_UNSET = object()
_AUTHORITY_TRANSPORT_ERRORS = (ConnectionError, EOFError, OSError, TimeoutError)
_MAX_WORKFLOW_NODES = 1000


def _neg_priority(node: TaskNode) -> int:
    return -node.priority


def _with_status(
    node: TaskNode,
    status: ExecutionStatus,
    *,
    claimed_by: str | object | None = _UNSET,
    artifact_id: str | object | None = _UNSET,
) -> TaskNode:
    """Clone a TaskNode while updating lifecycle fields."""
    updates: dict[str, Any] = {
        "status": status,
        "metadata": dict(node.metadata),
    }
    if claimed_by is not _UNSET:
        updates["claimed_by"] = claimed_by
    if artifact_id is not _UNSET:
        updates["artifact_id"] = artifact_id
    return replace(node, **updates)


def _node_snapshot(node: TaskNode) -> TaskNode:
    return replace(node, metadata=dict(node.metadata))


@dataclass
class TaskNode:
    """A node in the task DAG.

    Each node represents a unit of work with typed inputs/outputs,
    dependencies on parent nodes, and capability requirements.
    """

    node_id: str = field(default_factory=lambda: uuid.uuid4().hex[:16])
    title: str = ""
    description: str = ""
    domain: str = ""
    required_capabilities: tuple[str, ...] = ()
    depends_on: tuple[str, ...] = ()
    priority: int = 0
    max_budget_tokens: int = 0
    status: ExecutionStatus = ExecutionStatus.BLOCKED
    claimed_by: str | None = None
    artifact_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class TaskDAG:
    """A directed acyclic graph of tasks compiled from a goal.

    The DAG defines the execution plan. Agents claim and execute nodes
    whose dependencies are satisfied. No orchestrator needed — the DAG
    structure IS the coordination.
    """

    dag_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    goal: str = ""
    nodes: dict[str, TaskNode] = field(default_factory=dict)

    def _dependencies_completed(self, node: TaskNode) -> bool:
        """Check whether a node's dependencies exist and are completed."""
        missing = tuple(dep for dep in node.depends_on if dep not in self.nodes)
        if missing:
            raise KeyError(
                f"Node {node.node_id} depends on missing node(s): {', '.join(missing)}"
            )
        return all(
            self.nodes[dep].status == ExecutionStatus.GOVERNED_COMMITTED
            for dep in node.depends_on
        )

    def add_node(self, node: TaskNode) -> TaskDAG:
        """Add a node to the DAG. Returns new DAG (immutable pattern)."""
        new_nodes = dict(self.nodes)
        existing = new_nodes.get(node.node_id)
        if existing is not None:
            raise ValueError(
                f"Node ID collision for {node.node_id}:"
                f" {existing.title!r} conflicts with {node.title!r}"
            )
        new_nodes[node.node_id] = node
        return TaskDAG(dag_id=self.dag_id, goal=self.goal, nodes=new_nodes)

    def ready_nodes(self) -> list[TaskNode]:
        """Get all nodes whose dependencies are satisfied and unclaimed.

        A node is ready when all its parents are COMPLETED.
        """
        ready = []
        for node in self.nodes.values():
            if node.status != ExecutionStatus.BLOCKED:
                continue
            if self._dependencies_completed(node):
                ready.append(node)
        return ready

    def mark_ready(self) -> TaskDAG:
        """Update all blocked nodes with satisfied dependencies to READY."""
        new_nodes = dict(self.nodes)
        for nid, node in new_nodes.items():
            if node.status != ExecutionStatus.BLOCKED:
                continue
            if self._dependencies_completed(node):
                new_nodes[nid] = _with_status(node, ExecutionStatus.READY)
        return TaskDAG(dag_id=self.dag_id, goal=self.goal, nodes=new_nodes)

    def claim_node(self, node_id: str, agent_id: str) -> TaskDAG:
        """Claim a ready node for execution."""
        node = self.nodes.get(node_id)
        if node is None:
            raise KeyError(f"Node {node_id} not found")
        if node.status != ExecutionStatus.READY:
            raise ValueError(f"Node {node_id} is {node.status.value}, not ready")
        new_nodes = dict(self.nodes)
        new_nodes[node_id] = _with_status(
            node,
            ExecutionStatus.CLAIMED,
            claimed_by=agent_id,
        )
        return TaskDAG(dag_id=self.dag_id, goal=self.goal, nodes=new_nodes)

    def complete_node(self, node_id: str, artifact_id: str) -> TaskDAG:
        """Reject the legacy authority bypass.

        Execution completion is not an authoritative transition.  Callers must
        stage a result and submit a signed receipt to ``SwarmExecutor.commit``.
        """
        del node_id, artifact_id
        raise GovernanceBypassDenied("TaskDAG.complete_node cannot create authority")

    @property
    def is_complete(self) -> bool:
        """Check if all nodes in the DAG are completed."""
        return all(
            n.status == ExecutionStatus.GOVERNED_COMMITTED for n in self.nodes.values()
        )

    @property
    def progress(self) -> dict[str, int]:
        """Count nodes by status."""
        counts: dict[str, int] = {}
        for node in self.nodes.values():
            counts[node.status.value] = counts.get(node.status.value, 0) + 1
        return counts

    def to_contracts(self, constitutional_hash: str = "") -> list[WorkReceipt]:
        """Convert DAG nodes to immutable work receipts for the swarm."""
        return [
            WorkReceipt(
                task_id=node.node_id,
                title=node.title,
                description=node.description,
                domain=node.domain,
                required_capabilities=node.required_capabilities,
                priority=node.priority,
                max_budget_tokens=node.max_budget_tokens,
                status=contract_status_from_execution(node.status),
                constitutional_hash=constitutional_hash,
            )
            for node in self.nodes.values()
        ]


class SwarmExecutor:
    """Executes a task DAG using a swarm of agents.

    Agents self-select tasks based on capabilities. No orchestrator.
    The executor just manages the DAG state and artifact store.

    In production, this runs as a lightweight event loop. Agents
    poll for ready tasks or subscribe to notifications.
    """

    def __init__(
        self,
        registry: CapabilityRegistry,
        store: ArtifactStore,
        boundary: object = _UNSET,
        *,
        policy_version: str = "",
        trusted_admin: object = _UNSET,
    ) -> None:
        if boundary is not _UNSET or trusted_admin is not _UNSET:
            raise TypeError(
                "legacy boundary/admin access is forbidden; execution_client is "
                "injected only by AuthorityServiceHandle.spawn_executor()"
            )
        self._registry = registry
        self._store = store
        self._execution_client: object | None = None
        self._policy_version = policy_version
        self._dag: TaskDAG | None = None
        self._lock = threading.Lock()
        self._ready_ids: set[str] = set()
        # Parallel list of TaskNode refs for O(1) snapshot-ready output.
        # Membership in this list equals membership in _ready_ids. Append on
        # submit (child newly-ready); swap-remove on claim.
        self._ready_list: list[TaskNode] = []
        self._ready_index: dict[str, int] = {}  # node_id -> position in _ready_list
        self._caps_cache: dict[str, tuple[frozenset[str], frozenset[str]]] = {}
        self._pending_deps: dict[str, int] = {}
        self._children: dict[str, list[str]] = {}
        self._completed_count: int = 0
        self._total_count: int = 0
        # Track whether every ready node has empty required_capabilities.
        # When True (typical for benchmark DAGs), skip per-task cap filtering.
        self._all_ready_unconstrained: bool = True
        # Whether the DAG has any constrained nodes at all. Set once at load.
        self._dag_has_constrained: bool = False

    def _authority_call(self, operation: str, /, *args: Any, **kwargs: Any) -> Any:
        client = self._execution_client
        if client is None:
            raise GovernanceBypassDenied("governed boundary is not configured")
        try:
            method = getattr(client, operation)
            return method(*args, **kwargs)
        except GovernanceBypassDenied:
            raise
        except _AUTHORITY_TRANSPORT_ERRORS as exc:
            raise GovernanceBypassDenied("authority_unavailable") from exc

    def _rebuild_ready_index(self) -> None:
        self._ready_ids = set()
        self._ready_list = []
        self._ready_index = {}
        if self._dag is None:
            return
        for nid, node in self._dag.nodes.items():
            if node.status == ExecutionStatus.READY:
                self._ready_index[nid] = len(self._ready_list)
                self._ready_list.append(node)
                self._ready_ids.add(nid)

    def _build_dep_index(self) -> None:
        self._pending_deps = {}
        self._children = {}
        self._completed_count = 0
        if self._dag is None:
            self._total_count = 0
            return
        nodes = self._dag.nodes
        self._total_count = len(nodes)
        for nid, node in nodes.items():
            pending = 0
            for dep in node.depends_on:
                if dep not in nodes:
                    raise KeyError(f"Node {nid} depends on missing node {dep}")
                self._children.setdefault(dep, []).append(nid)
                if nodes[dep].status != ExecutionStatus.GOVERNED_COMMITTED:
                    pending += 1
            self._pending_deps[nid] = pending
            if node.status == ExecutionStatus.GOVERNED_COMMITTED:
                self._completed_count += 1

    def load_dag(self, dag: TaskDAG) -> None:
        """Load a task DAG for execution."""
        with self._lock:
            if len(dag.nodes) > _MAX_WORKFLOW_NODES:
                raise GovernanceBypassDenied("node_status_batch_too_large")
            if self._dag is not None and self._dag.dag_id != dag.dag_id:
                raise GovernanceBypassDenied("executor_workflow_identity_mismatch")
            authoritative_states = None
            if self._execution_client is not None:
                if not self._policy_version:
                    raise GovernanceBypassDenied(
                        "policy_version is required for governed execution"
                    )
                topology = {
                    node.node_id: node.depends_on for node in dag.nodes.values()
                }
                capabilities = {
                    node.node_id: node.required_capabilities
                    for node in dag.nodes.values()
                }
                input_digests = {
                    node.node_id: hashlib.sha256(
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
                    for node in dag.nodes.values()
                }
                try:
                    authoritative_states = self._authority_call(
                        "attach_workflow",
                        workflow_id=dag.dag_id,
                        nodes=topology,
                        policy_version=self._policy_version,
                        required_capabilities=capabilities,
                        input_digests=input_digests,
                    )
                except KeyError:
                    raise GovernanceBypassDenied(
                        "workflow_requires_signed_trusted_provisioning"
                    ) from None
            normalized_nodes: dict[str, TaskNode] = {}
            for node_id, source_node in dag.nodes.items():
                normalized = _with_status(
                    source_node,
                    ExecutionStatus.BLOCKED,
                    claimed_by=None,
                    artifact_id=None,
                )
                normalized.metadata.pop("attempt_id", None)
                normalized_nodes[node_id] = normalized
            self._dag = TaskDAG(
                dag_id=dag.dag_id, goal=dag.goal, nodes=normalized_nodes
            ).mark_ready()
            if authoritative_states is not None:
                for node_id, state in authoritative_states.items():
                    node = self._dag.nodes[node_id]
                    node.status = ExecutionStatus(state.status)
                    node.claimed_by = state.claimed_by
                    node.artifact_id = state.artifact_id
                    if state.attempt_id is not None:
                        node.metadata["attempt_id"] = state.attempt_id
            self._rebuild_ready_index()
            self._build_dep_index()
            self._dag_has_constrained = any(
                node.required_capabilities for node in self._dag.nodes.values()
            )
            if self._dag_has_constrained:
                self._all_ready_unconstrained = not any(
                    self._dag.nodes[nid].required_capabilities
                    for nid in self._ready_ids
                )
            else:
                self._all_ready_unconstrained = True

    def _synchronize_authoritative_states(self) -> None:
        """Refresh the in-memory projection from the SQLite authority."""
        if self._dag is None or self._execution_client is None:
            return
        node_ids = tuple(self._dag.nodes)
        states = self._authority_call(
            "workflow_node_states", self._dag.dag_id, node_ids
        )
        if len(states) != len(node_ids):
            raise GovernanceBypassDenied("authority_status_batch_length_mismatch")
        for node_id, state in zip(node_ids, states, strict=True):
            node = self._dag.nodes[node_id]
            node.status = ExecutionStatus(state.status)
            node.claimed_by = state.claimed_by
            node.artifact_id = state.artifact_id
            if state.attempt_id is None:
                node.metadata.pop("attempt_id", None)
            else:
                node.metadata["attempt_id"] = state.attempt_id
        self._rebuild_ready_index()
        self._build_dep_index()

    def authoritative_artifact(self, artifact_id: str) -> Artifact | None:
        """Read only an artifact backed by a currently valid governed commit."""
        with self._lock:
            if self._dag is None:
                raise RuntimeError("No DAG loaded")
            if self._execution_client is None:
                raise GovernanceBypassDenied("governed boundary is not configured")
            workflow_id = self._dag.dag_id
        return self._authority_call("authoritative_artifact", workflow_id, artifact_id)

    def available_tasks(self, agent_id: str) -> list[TaskNode]:
        """Get tasks an agent can claim based on its capabilities.

        Matches agent capabilities against task requirements.
        Returns only READY (unclaimed) tasks.

        The DAG snapshot is taken inside the lock; the (potentially
        slow) capability lookup and filtering happen outside the lock
        so concurrent callers are not serialised on registry I/O.
        """
        with self._lock:
            self._synchronize_authoritative_states()
            if self._dag is None or not self._ready_ids:
                return []
            cached = self._caps_cache.get(agent_id)
            if cached is None:
                agent_caps = self._registry.get_agent_capabilities(agent_id)
                cap_names = frozenset(c.name.lower() for c in agent_caps)
                cap_domains = frozenset(c.domain for c in agent_caps)
                self._caps_cache[agent_id] = (cap_names, cap_domains)
            else:
                cap_names, cap_domains = cached

            # INVARIANT: _ready_list mirrors _ready_ids and holds live
            # TaskNode refs (maintained in-place by claim/submit). When every
            # ready task is unconstrained, return a copy directly — no dict
            # lookup, no cap filtering.
            if self._all_ready_unconstrained:
                available = list(self._ready_list)
            else:
                available = []
                for node in self._ready_list:
                    caps = node.required_capabilities
                    if not caps:
                        available.append(node)
                        continue
                    if node.domain in cap_domains:
                        available.append(node)
                        continue
                    for rc in caps:
                        if rc.lower() in cap_names:
                            available.append(node)
                            break

        if len(available) > 1:
            first_priority = available[0].priority
            for node in available:
                if node.priority != first_priority:
                    available.sort(key=_neg_priority)
                    break
        return [_node_snapshot(node) for node in available]

    def prepare_claim(self, node_id: str, agent_id: str) -> AttemptAuthorizationPayload:
        """Create a fresh, context-bound claim payload for the agent to sign."""
        with self._lock:
            if self._dag is None:
                raise RuntimeError("No DAG loaded")
            if self._execution_client is None:
                raise GovernanceBypassDenied("claim requires a governed boundary")
            node = self._dag.nodes.get(node_id)
            if node is None:
                raise KeyError(f"Node {node_id} not found")
            if node.status != ExecutionStatus.READY:
                raise ValueError(f"Node {node_id} is {node.status.value}, not ready")
            payload = self._authority_call(
                "prepare_attempt_authorization",
                workflow_id=self._dag.dag_id,
                node_id=node_id,
                attempt_id=uuid.uuid4().hex,
                agent_id=agent_id,
                nonce=uuid.uuid4().hex,
            )
            return payload

    def claim(
        self,
        node_id: str,
        agent_id: str,
        authorization: SignedAttemptAuthorization | None = None,
    ) -> WorkReceipt:
        """Agent claims a task. Returns the immutable work receipt."""
        with self._lock:
            if self._dag is None:
                raise RuntimeError("No DAG loaded")
            nodes = self._dag.nodes
            node = nodes.get(node_id)
            if node is None:
                raise KeyError(f"Node {node_id} not found")
            if node.status != ExecutionStatus.READY:
                raise ValueError(f"Node {node_id} is {node.status.value}, not ready")
            if not isinstance(authorization, SignedAttemptAuthorization):
                raise GovernanceBypassDenied("signed_attempt_authorization_required")
            attempt_id = authorization.payload.attempt_id
            if self._execution_client is None:
                raise GovernanceBypassDenied("claim requires a governed boundary")
            self._authority_call(
                "claim",
                workflow_id=self._dag.dag_id,
                node_id=node_id,
                attempt_id=attempt_id,
                agent_id=agent_id,
                authorization=authorization,
                required_capabilities=node.required_capabilities,
            )
            node.status = ExecutionStatus.CLAIMED
            node.claimed_by = agent_id
            node.metadata["attempt_id"] = attempt_id
            node.metadata["attempt_authorization"] = authorization
            self._ready_ids.discard(node_id)
            idx = self._ready_index.pop(node_id, -1)
            if idx >= 0:
                last = len(self._ready_list) - 1
                if idx != last:
                    moved = self._ready_list[last]
                    self._ready_list[idx] = moved
                    self._ready_index[moved.node_id] = idx
                self._ready_list.pop()
            return WorkReceipt(
                task_id=node.node_id,
                title=node.title,
                description=node.description,
                domain=node.domain,
                required_capabilities=node.required_capabilities,
                status=ContractStatus.CLAIMED,
                claimed_by=agent_id,
                priority=node.priority,
            )

    def submit(self, node_id: str, artifact: Artifact) -> None:
        """Reject the legacy publish-and-complete bypass."""
        del node_id, artifact
        raise GovernanceBypassDenied(
            "submit cannot create authority; stage and commit a receipt"
        )

    def produce_result(
        self,
        node_id: str,
        artifact: Artifact,
        *,
        authorization: SignedAttemptAuthorization | None = None,
    ) -> GovernedReceiptPayload:
        """Stage a result using the retained signed attempt capability."""
        with self._lock:
            if self._dag is None:
                raise RuntimeError("No DAG loaded")
            if self._execution_client is None:
                raise GovernanceBypassDenied("governed boundary is not configured")
            node = self._dag.nodes.get(node_id)
            if node is None:
                raise KeyError(node_id)
            attempt_id = str(node.metadata.get("attempt_id", ""))
            if authorization is None:
                authorization = node.metadata.get("attempt_authorization")
            if not isinstance(authorization, SignedAttemptAuthorization):
                raise GovernanceBypassDenied("signed_attempt_authorization_required")
            self._authority_call(
                "stage_result",
                workflow_id=self._dag.dag_id,
                node_id=node_id,
                attempt_id=attempt_id,
                artifact=artifact,
                authorization=authorization,
            )
            node.status = ExecutionStatus.RESULT_PRODUCED
            node.artifact_id = artifact.artifact_id
            return self._authority_call(
                "prepare_receipt_payload",
                workflow_id=self._dag.dag_id,
                node_id=node_id,
                attempt_id=attempt_id,
                agent_id=artifact.agent_id,
                commit_id=uuid.uuid4().hex,
                nonce=uuid.uuid4().hex,
            )

    def commit(self, request: CommitRequest) -> CommitDecision:
        """Commit through GCB and then refresh non-authoritative projections."""
        with self._lock:
            if self._dag is None:
                raise RuntimeError("No DAG loaded")
            if self._execution_client is None:
                raise GovernanceBypassDenied("governed boundary is not configured")
            if request.receipt.payload.workflow_id != self._dag.dag_id:
                raise GovernanceBypassDenied("executor_workflow_identity_mismatch")
            decision = self._authority_call("commit", request)
            if decision.outcome is not CommitOutcome.COMMITTED:
                return decision
            node = self._dag.nodes[decision.node_id]
            refreshed_ids = (
                decision.node_id,
                *self._children.get(decision.node_id, ()),
            )
            refreshed_states = self._authority_call(
                "workflow_node_states", self._dag.dag_id, refreshed_ids
            )
            if len(refreshed_states) != len(refreshed_ids):
                raise GovernanceBypassDenied("authority_status_batch_length_mismatch")
            authority_state = refreshed_states[0]
            if authority_state.status != "governed_committed":
                raise GovernanceBypassDenied("commit_projection_authority_mismatch")
            if node.status is not ExecutionStatus.GOVERNED_COMMITTED:
                node.status = ExecutionStatus(authority_state.status)
                self._completed_count += 1
            for child_id, state in zip(
                refreshed_ids[1:], refreshed_states[1:], strict=True
            ):
                child = self._dag.nodes[child_id]
                if state.status == "ready" and child.status == ExecutionStatus.BLOCKED:
                    child.status = ExecutionStatus.READY
                    self._ready_ids.add(child_id)
                    self._ready_index[child_id] = len(self._ready_list)
                    self._ready_list.append(child)
        return decision

    @property
    def is_complete(self) -> bool:
        """Check if the entire DAG is done."""
        with self._lock:
            self._synchronize_authoritative_states()
            if self._dag is None:
                return False
            if self._total_count > 0:
                return self._completed_count >= self._total_count
            return self._dag.is_complete

    @property
    def progress(self) -> dict[str, int]:
        """Current DAG progress by status."""
        with self._lock:
            self._synchronize_authoritative_states()
            if self._dag is None:
                return {}
            return self._dag.progress

    @property
    def dag(self) -> TaskDAG | None:
        """Return a defensive, non-authoritative DAG projection."""
        with self._lock:
            self._synchronize_authoritative_states()
            if self._dag is None:
                return None
            return TaskDAG(
                dag_id=self._dag.dag_id,
                goal=self._dag.goal,
                nodes={
                    node_id: _node_snapshot(node)
                    for node_id, node in self._dag.nodes.items()
                },
            )
