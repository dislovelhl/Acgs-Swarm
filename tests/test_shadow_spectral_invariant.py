"""Shadow spectral invariant tests.

Shadow spectral tracking is allowed to collect metrics, but it must never
change the live peer-routing decisions made by the Birkhoff path.
"""

from __future__ import annotations

from typing import Any

from constitutional_swarm import ConstitutionalMesh, ValidationVote

from acgs_lite import Constitution


def _signed_vote(
    mesh: ConstitutionalMesh,
    assignment_id: str,
    voter_id: str,
    *,
    approved: bool,
    reason: str = "",
) -> ValidationVote:
    return mesh.submit_vote(
        assignment_id,
        voter_id,
        approved=approved,
        reason=reason,
        signature=mesh.sign_vote(
            assignment_id,
            voter_id,
            approved=approved,
            reason=reason,
        ),
    )


def _build_mesh(*, seed: int, shadow_spectral: bool) -> ConstitutionalMesh:
    mesh = ConstitutionalMesh(
        Constitution.default(),
        seed=seed,
        use_manifold=True,
        shadow_spectral=shadow_spectral,
    )
    for index in range(8):
        mesh.register_local_signer(f"agent-{index:02d}", domain=f"domain-{index % 3}")
    return mesh


def test_shadow_spectral_tracking_never_changes_live_peer_assignment() -> None:
    live = _build_mesh(seed=123, shadow_spectral=False)
    shadow = _build_mesh(seed=123, shadow_spectral=True)

    divergence_count = 0
    total_assignments = 100

    for index in range(total_assignments):
        producer = f"agent-{index % 8:02d}"
        assignment_live = live.request_validation(
            producer,
            f"shadow-invariant-content-{index}",
            f"shadow-live-{index}",
        )
        assignment_shadow = shadow.request_validation(
            producer,
            f"shadow-invariant-content-{index}",
            f"shadow-shadow-{index}",
        )

        if assignment_live.peers != assignment_shadow.peers:
            divergence_count += 1

        for peer in assignment_live.peers[:2]:
            _signed_vote(live, assignment_live.assignment_id, peer, approved=True)
        for peer in assignment_shadow.peers[:2]:
            _signed_vote(shadow, assignment_shadow.assignment_id, peer, approved=True)

    shadow_summary: dict[str, Any] | None = shadow.shadow_metrics_summary()

    assert divergence_count == 0
    assert not hasattr(live, "_shadow_manifold")
    assert shadow_summary is not None
    assert shadow_summary["count"] == total_assignments
