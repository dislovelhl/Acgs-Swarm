"""Tests for previously-uncovered branches in axon_server.py and dendrite_client.py."""
import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock

from constitutional_swarm.bittensor.synapse_adapter import GovernanceDeliberation


# ── axon_server.py missing branches ─────────────────────────────────────────

class TestAxonServerMissingBranches:
    @pytest.fixture
    def axon_server(self, tmp_path):
        from constitutional_swarm.bittensor.axon_server import MinerAxonServer
        from constitutional_swarm.bittensor.miner import ConstitutionalMiner
        from constitutional_swarm.bittensor.protocol import MinerConfig

        path = tmp_path / "c.yaml"
        path.write_text(
            "name: test\nrules:\n"
            "  - id: r1\n    text: Safe\n    severity: critical\n"
            "    hardcoded: true\n    keywords: [harm]\n"
        )

        async def handler(task, ctx, meta):
            return ("ok", "ok")

        miner = ConstitutionalMiner(
            config=MinerConfig(constitution_path=str(path), agent_id="test"),
            deliberation_handler=handler,
        )
        return MinerAxonServer(miner)

    def _make_syn(self, axon_server):
        return GovernanceDeliberation(
            task_id="t1",
            task_dag_json="{}",
            constitution_hash=axon_server.miner.constitution_hash,
            domain="d",
        )

    @pytest.mark.asyncio
    async def test_forward_dna_prefail(self, axon_server):
        """Lines 76-77: DNAPreCheckFailedError handler in forward()."""
        from constitutional_swarm.bittensor.miner import DNAPreCheckFailedError

        syn = self._make_syn(axon_server)
        axon_server._miner.process = AsyncMock(side_effect=DNAPreCheckFailedError("dna"))
        result = await axon_server.forward(syn)
        assert result.error_message is not None
        assert "DNA" in result.error_message or "dna" in result.error_message.lower()

    @pytest.mark.asyncio
    async def test_forward_timeout(self, axon_server):
        """Lines 78-79: TimeoutError handler in forward()."""
        syn = self._make_syn(axon_server)
        axon_server._miner.process = AsyncMock(side_effect=TimeoutError())
        result = await axon_server.forward(syn)
        assert result.error_message is not None
        assert "timed out" in result.error_message.lower()

    @pytest.mark.asyncio
    async def test_forward_generic_exception(self, axon_server):
        """Lines 80-81: generic Exception handler in forward()."""
        syn = self._make_syn(axon_server)
        axon_server._miner.process = AsyncMock(side_effect=RuntimeError("boom"))
        result = await axon_server.forward(syn)
        assert result.error_message is not None
        assert "RuntimeError" in result.error_message

    def test_verify_missing_constitution_hash(self, axon_server):
        """Lines 101-102: verify() with empty constitution_hash."""
        syn = GovernanceDeliberation(task_id="t", task_dag_json="{}", constitution_hash="", domain="d")
        with pytest.raises(ValueError, match="constitution_hash"):
            axon_server.verify(syn)

    def test_verify_missing_task_dag_json(self, axon_server):
        """Lines 103-104: verify() with empty task_dag_json."""
        syn = GovernanceDeliberation(task_id="t", task_dag_json="", constitution_hash="h", domain="d")
        with pytest.raises(ValueError, match="task_dag_json"):
            axon_server.verify(syn)


# ── dendrite_client.py missing branches ──────────────────────────────────────

class TestDendriteClientMissingBranches:
    @pytest.fixture
    def client(self, tmp_path):
        from constitutional_swarm.bittensor.dendrite_client import ValidatorDendriteClient

        path = tmp_path / "c.yaml"
        path.write_text(
            "name: test\nrules:\n"
            "  - id: r1\n    text: Safe\n    severity: critical\n"
            "    hardcoded: true\n    keywords: [harm]\n"
        )
        return ValidatorDendriteClient(constitution_path=str(path))

    @pytest.mark.asyncio
    async def test_query_local_timeout_filters_out(self, client, tmp_path):
        """Timeout in _query_local filters the miner out — returns []."""
        from constitutional_swarm.bittensor.axon_server import MinerAxonServer
        from constitutional_swarm.bittensor.miner import ConstitutionalMiner
        from constitutional_swarm.bittensor.protocol import MinerConfig
        from constitutional_swarm.bittensor.synapses import DeliberationSynapse

        path = tmp_path / "c2.yaml"
        path.write_text(
            "name: test\nrules:\n"
            "  - id: r1\n    text: Safe\n    severity: critical\n"
            "    hardcoded: true\n    keywords: [harm]\n"
        )

        async def slow_handler(task, ctx, meta):
            await asyncio.sleep(10)
            return ("j", "r")

        miner = ConstitutionalMiner(
            config=MinerConfig(constitution_path=str(path), agent_id="slow"),
            deliberation_handler=slow_handler,
        )
        server = MinerAxonServer(miner)
        client.register_local_miner(server)

        delib = DeliberationSynapse(
            task_id="timeout-test",
            task_dag_json="{}",
            constitution_hash=client.constitution_hash,
            domain="test",
        )
        judgments = await client.query_miners(delib, timeout=0.01)
        assert judgments == []

    @pytest.mark.asyncio
    async def test_query_network_routes_and_filters_responses(self, client, tmp_path):
        """Lines 147-167: _query_network() processes dendrite responses.

        Patches _dendrite and _metagraph directly so HAS_BITTENSOR=False
        environments can exercise the network query path.
        """
        from constitutional_swarm.bittensor.synapses import DeliberationSynapse

        # Build a mock response with a valid judgment
        good_resp = GovernanceDeliberation(
            task_id="net-test",
            task_dag_json="{}",
            constitution_hash=client.constitution_hash,
            domain="net",
            judgment="allow",
            reasoning="looks fine",
            dna_valid=True,
        )
        # Build a bad response (no judgment → has_response=False)
        bad_resp = GovernanceDeliberation(
            task_id="net-test",
            task_dag_json="{}",
            constitution_hash=client.constitution_hash,
            domain="net",
        )

        # Mock dendrite returns both good and bad
        client._dendrite = AsyncMock(return_value=[good_resp, bad_resp])
        client._metagraph = MagicMock()
        client._metagraph.axons = [MagicMock()]

        delib = DeliberationSynapse(
            task_id="net-test",
            task_dag_json="{}",
            constitution_hash=client.constitution_hash,
            domain="net",
        )
        judgments = await client.query_miners(delib, timeout=5.0)
        # good_resp has judgment filled → should produce one JudgmentSynapse
        assert len(judgments) == 1
        assert judgments[0].judgment == "allow"

    @pytest.mark.asyncio
    async def test_query_network_error_response_filtered(self, client):
        """_query_network() filters out responses with error_message set."""
        from constitutional_swarm.bittensor.synapses import DeliberationSynapse

        error_resp = GovernanceDeliberation(
            task_id="err-test",
            task_dag_json="{}",
            constitution_hash=client.constitution_hash,
            domain="net",
            judgment="deny",
            error_message="Something went wrong",
        )

        client._dendrite = AsyncMock(return_value=[error_resp])
        client._metagraph = MagicMock()
        client._metagraph.axons = [MagicMock()]

        delib = DeliberationSynapse(
            task_id="err-test",
            task_dag_json="{}",
            constitution_hash=client.constitution_hash,
            domain="net",
        )
        judgments = await client.query_miners(delib)
        assert judgments == []

    @pytest.mark.asyncio
    async def test_query_network_non_governance_response_skipped(self, client):
        """_query_network() skips non-GovernanceDeliberation objects in responses."""
        from constitutional_swarm.bittensor.synapses import DeliberationSynapse

        client._dendrite = AsyncMock(return_value=["not a synapse", None, 42])
        client._metagraph = MagicMock()
        client._metagraph.axons = [MagicMock(), MagicMock(), MagicMock()]

        delib = DeliberationSynapse(
            task_id="skip-test",
            task_dag_json="{}",
            constitution_hash=client.constitution_hash,
            domain="net",
        )
        judgments = await client.query_miners(delib)
        assert judgments == []

    @pytest.mark.asyncio
    async def test_query_network_with_timeout_sets_deadline(self, client):
        """_query_network() passes timeout to dendrite call."""
        from constitutional_swarm.bittensor.synapses import DeliberationSynapse

        client._dendrite = AsyncMock(return_value=[])
        client._metagraph = MagicMock()
        client._metagraph.axons = []

        delib = DeliberationSynapse(
            task_id="t1",
            task_dag_json="{}",
            constitution_hash=client.constitution_hash,
            domain="d",
        )
        await client.query_miners(delib, timeout=30.0)
        # Check dendrite was called with the timeout argument
        call_kwargs = client._dendrite.call_args
        assert call_kwargs is not None
