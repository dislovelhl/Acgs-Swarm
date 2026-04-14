"""Focused tests for the swarm_ode -> MerkleCRDT bridge."""

from __future__ import annotations

import json

import pytest

torch = pytest.importorskip("torch")


def test_integrate_records_ode_snapshots_to_crdt() -> None:
    """record_every points and final state should be appended to the CRDT."""
    from constitutional_swarm.merkle_crdt import MerkleCRDT
    from constitutional_swarm.swarm_ode import StationaryField, integrate

    n = 4
    H0 = torch.eye(n) * 0.5
    crdt = MerkleCRDT(agent_id="ode-agent")
    result = integrate(
        StationaryField(torch.zeros(n, n)),
        H0,
        n_steps=10,
        record_every=5,
        crdt=crdt,
    )

    assert result["n_steps"] == 10
    assert crdt.size == 3

    nodes = crdt.topological_order()
    assert [node.payload_type for node in nodes] == ["ode_snapshot"] * 3
    assert all(node.bodes_passed for node in nodes)
    assert all(node.constitutional_hash == "608508a9bd224290" for node in nodes)
    assert all(node.verify_cid() for node in nodes)

    payloads = [json.loads(node.payload) for node in nodes]
    trajectory = result["trajectory"]
    assert [payload["step"] for payload in payloads] == [0, 5, 10]
    for payload, (t, _H, variance) in zip(payloads, trajectory, strict=True):
        assert payload["t"] == pytest.approx(t)
        assert payload["variance"] == pytest.approx(variance)


def test_integrate_does_not_write_crdt_when_recording_disabled() -> None:
    """Providing a CRDT should still be a no-op when record_every=0."""
    from constitutional_swarm.merkle_crdt import MerkleCRDT
    from constitutional_swarm.swarm_ode import StationaryField, integrate

    n = 3
    H0 = torch.eye(n)
    crdt = MerkleCRDT(agent_id="ode-agent")
    result = integrate(
        StationaryField(torch.zeros(n, n)),
        H0,
        n_steps=10,
        record_every=0,
        crdt=crdt,
    )

    assert result["trajectory"] == []
    assert crdt.size == 0
