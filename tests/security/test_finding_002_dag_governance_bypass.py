from __future__ import annotations

import pytest

from constitutional_swarm.artifact import Artifact, ArtifactStore
from constitutional_swarm.capability import CapabilityRegistry
from constitutional_swarm.governed_commit import GovernanceBypassDenied
from constitutional_swarm.swarm import SwarmExecutor, TaskDAG, TaskNode


@pytest.mark.security
def test_legacy_completion_and_submit_cannot_create_authority() -> None:
    dag = TaskDAG(goal="deny bypass").add_node(TaskNode(node_id="root"))
    dag = dag.mark_ready().claim_node("root", "agent")
    with pytest.raises(GovernanceBypassDenied):
        dag.complete_node("root", "artifact")

    executor = SwarmExecutor(CapabilityRegistry(), ArtifactStore())
    executor.load_dag(TaskDAG(goal="deny bypass").add_node(TaskNode(node_id="root")))
    with pytest.raises(GovernanceBypassDenied):
        executor.claim("root", "agent")
    with pytest.raises(GovernanceBypassDenied):
        executor.submit(
            "root",
            Artifact(
                artifact_id="artifact",
                task_id="root",
                agent_id="agent",
                content_type="text",
                content="unverified",
            ),
        )
