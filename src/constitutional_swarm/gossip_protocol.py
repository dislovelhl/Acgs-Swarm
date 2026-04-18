"""
WebSocket Gossip Transport — MCFS Phase 5.

Replaces in-process MerkleCRDT.merge() with a real network layer.
Each SwarmNode runs a WebSocket server and gossips DAGNode batches
to random peers. Integration point: MerkleCRDT.merge_nodes() already
accepts raw DAGNode lists — this module wires it to the network.

Architecture:
    GossipPeerRegistry  — registry of known peer addresses (host:port)
    GossipServer        — WebSocket server; receives batches, calls merge_nodes()
    GossipClient        — sends DAGNode batches to a single peer
    SwarmNode           — combines MerkleCRDT + server + periodic gossip loop

Wire format (JSON):
    Each message is a JSON array of node objects:
    [
        {
            "cid": "<sha256-hex>",
            "agent_id": "...",
            "payload": "...",
            "payload_type": "artifact",
            "parent_cids": ["..."],
            "bodes_passed": false,
            "constitutional_hash": ""
        },
        ...
    ]

Optional dependency: websockets>=12.0
Install: pip install 'constitutional-swarm[transport]'

    from constitutional_swarm.gossip_protocol import SwarmNode

    async with SwarmNode("agent-0", host="127.0.0.1", port=8765) as node:
        node.registry.add("127.0.0.1", 8766)
        node.crdt.append(payload="hello from agent-0")
        await node.gossip_round(n_peers=2)
"""

from __future__ import annotations

import asyncio
import json
import logging
import random
import threading
from dataclasses import dataclass, field
from typing import Any

from constitutional_swarm.merkle_crdt import DAGNode, MerkleCRDT

log = logging.getLogger(__name__)

# Maximum bytes allowed in a single node's metadata field.
# Prevents memory exhaustion via oversized gossip payloads (DoS defence).
MAX_METADATA_BYTES = 65_536  # 64 KiB

# ---------------------------------------------------------------------------
# Wire serialization helpers
# ---------------------------------------------------------------------------


def _node_to_wire(node: DAGNode) -> dict[str, Any]:
    """Serialize a DAGNode to a wire-format dict (includes CID)."""
    return {
        "cid": node.cid,
        "agent_id": node.agent_id,
        "payload": node.payload,
        "payload_type": node.payload_type,
        "parent_cids": list(node.parent_cids),
        "bodes_passed": node.bodes_passed,
        "constitutional_hash": node.constitutional_hash,
    }


def _wire_to_node(data: dict[str, Any]) -> DAGNode:
    """Deserialize a wire-format dict to a DAGNode.

    The node's CID is taken from the wire — verify_cid() on the receiver
    ensures integrity before insertion into the replica.

    Raises ValueError if the metadata field exceeds MAX_METADATA_BYTES to
    prevent memory exhaustion via oversized gossip payloads.
    """
    raw_metadata = data.get("metadata", {})
    if isinstance(raw_metadata, dict):
        metadata_size = len(json.dumps(raw_metadata).encode())
        if metadata_size > MAX_METADATA_BYTES:
            raise ValueError(
                f"Gossip node metadata exceeds {MAX_METADATA_BYTES} bytes "
                f"({metadata_size} bytes from agent '{data.get('agent_id', '?')}')"
            )
    else:
        raw_metadata = {}

    return DAGNode(
        cid=data["cid"],
        agent_id=data["agent_id"],
        payload=data["payload"],
        payload_type=data.get("payload_type", "artifact"),
        parent_cids=tuple(data.get("parent_cids", [])),
        bodes_passed=data.get("bodes_passed", False),
        constitutional_hash=data.get("constitutional_hash", ""),
        metadata=raw_metadata,
    )


def encode_batch(nodes: list[DAGNode]) -> str:
    """Encode a batch of nodes to a JSON string for transmission."""
    return json.dumps([_node_to_wire(n) for n in nodes])


def decode_batch(message: str) -> list[DAGNode]:
    """Decode a JSON string to a list of DAGNodes."""
    try:
        items = json.loads(message)
        if not isinstance(items, list):
            raise ValueError(f"Expected JSON array, got {type(items)}")
        return [_wire_to_node(item) for item in items]
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        raise ValueError(f"Malformed gossip batch: {exc}") from exc


# ---------------------------------------------------------------------------
# Peer registry
# ---------------------------------------------------------------------------


@dataclass
class GossipPeerRegistry:
    """Thread-safe registry of known peer addresses.

    Each entry is a (host, port) tuple. The local node's own address
    is stored in `self_addr` and is always excluded from gossip targets.
    """

    self_addr: tuple[str, int] | None = None
    _peers: list[tuple[str, int]] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def add(self, host: str, port: int) -> None:
        """Register a peer. Silently ignores the local node's own address."""
        addr = (host, port)
        if addr == self.self_addr:
            return
        with self._lock:
            if addr not in self._peers:
                self._peers.append(addr)

    def remove(self, host: str, port: int) -> None:
        """Unregister a peer."""
        addr = (host, port)
        with self._lock:
            self._peers = [p for p in self._peers if p != addr]

    def sample(self, n: int, *, rng: random.Random | None = None) -> list[tuple[str, int]]:
        """Return up to n random peers."""
        rng = rng or random.SystemRandom()
        with self._lock:
            pool = list(self._peers)
        return rng.sample(pool, min(n, len(pool)))

    @property
    def all_peers(self) -> list[tuple[str, int]]:
        """Snapshot of all registered peers."""
        with self._lock:
            return list(self._peers)

    def __len__(self) -> int:
        with self._lock:
            return len(self._peers)


# ---------------------------------------------------------------------------
# Gossip server (WebSocket)
# ---------------------------------------------------------------------------


class GossipServer:
    """WebSocket server that receives DAGNode batches and merges them.

    Each incoming message is a JSON-encoded batch of nodes. The server
    deserializes them and calls `crdt.merge_nodes()`. CID verification
    is delegated to MerkleCRDT (reject_unverified=True by default).

    Args:
        crdt: The local MerkleCRDT replica to receive gossip into.
        host: Bind address.
        port: Bind port.
    """

    def __init__(self, crdt: MerkleCRDT, host: str = "127.0.0.1", port: int = 0) -> None:
        self.crdt = crdt
        self.host = host
        self.port = port
        self._server: Any = None  # websockets.Server
        self._actual_port: int = port

    async def start(self) -> None:
        """Start the WebSocket server. Raises ImportError if websockets not installed."""
        try:
            import websockets  # type: ignore[import]
        except ImportError as exc:
            raise ImportError(
                "WebSocket transport requires 'websockets>=12.0'. "
                "Install with: pip install 'constitutional-swarm[transport]'"
            ) from exc

        self._server = await websockets.serve(
            self._handle_connection,
            self.host,
            self.port,
        )
        # Record actual bound port (useful when port=0 for OS-assigned)
        sockets = self._server.sockets
        if sockets:
            self._actual_port = sockets[0].getsockname()[1]
        log.debug("GossipServer listening at %s:%d", self.host, self._actual_port)

    async def stop(self) -> None:
        """Gracefully shut down the server."""
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

    @property
    def actual_port(self) -> int:
        """The port the server is actually bound to (after start())."""
        return self._actual_port

    async def _handle_connection(self, websocket: Any) -> None:
        """Handle one WebSocket connection. Reads batches until disconnect."""
        try:
            import websockets  # type: ignore[import]
        except ImportError:
            connection_closed_error = RuntimeError
        else:
            connection_closed_error = websockets.exceptions.ConnectionClosed

        peer = websocket.remote_address
        log.debug("Gossip connection from %s", peer)
        try:
            async for message in websocket:
                try:
                    nodes = decode_batch(message)
                    added = self.crdt.merge_nodes(nodes)
                    log.debug("Merged %d/%d nodes from %s", added, len(nodes), peer)
                except ValueError as exc:
                    log.warning("Rejected malformed batch from %s: %s", peer, exc)
        except (connection_closed_error, OSError) as exc:
            log.debug("Connection from %s closed: %s", peer, type(exc).__name__)


# ---------------------------------------------------------------------------
# Gossip client (WebSocket)
# ---------------------------------------------------------------------------


class GossipClient:
    """Sends DAGNode batches to a single peer over WebSocket.

    Usage (fire-and-forget, one connection per send):

        client = GossipClient()
        await client.send_batch("127.0.0.1", 8766, nodes)

    The client is stateless — it opens, sends, closes. For long-running
    agents, SwarmNode reuses GossipClient across rounds.
    """

    async def send_batch(
        self,
        host: str,
        port: int,
        nodes: list[DAGNode],
        *,
        timeout: float = 5.0,
    ) -> bool:
        """Send nodes to a peer. Returns True on success, False on failure.

        Failures are logged at DEBUG level and swallowed — gossip is
        best-effort and partial delivery is acceptable for convergence.
        """
        if not nodes:
            return True

        try:
            import websockets  # type: ignore[import]
        except ImportError as exc:
            raise ImportError(
                "WebSocket transport requires 'websockets>=12.0'. "
                "Install with: pip install 'constitutional-swarm[transport]'"
            ) from exc

        uri = f"ws://{host}:{port}"
        try:
            async with asyncio.timeout(timeout):
                async with websockets.connect(uri) as ws:
                    await ws.send(encode_batch(nodes))
            log.debug("Sent %d nodes to %s:%d", len(nodes), host, port)
            return True
        except (TimeoutError, OSError, websockets.exceptions.WebSocketException) as exc:
            log.debug("Failed to reach %s:%d: %s", host, port, type(exc).__name__)
            return False


# ---------------------------------------------------------------------------
# SwarmNode: CRDT + server + gossip loop
# ---------------------------------------------------------------------------


class SwarmNode:
    """Self-contained swarm participant: local CRDT replica + gossip transport.

    Each SwarmNode runs a WebSocket gossip server and maintains a peer
    registry. Call gossip_round() to push current DAG heads to random peers.

    Args:
        agent_id: Unique identifier for this node in the swarm.
        host: WebSocket server bind address.
        port: WebSocket server port. 0 = OS-assigned (use actual_port after start).
        reject_unverified: If True (default), reject nodes with invalid CIDs.
        gossip_batch_size: Max nodes per gossip batch. 0 = send all heads.

    Usage as async context manager:

        async with SwarmNode("agent-0", port=8765) as node:
            node.registry.add("127.0.0.1", 8766)
            node.crdt.append(payload="hello")
            await node.gossip_round(n_peers=2)
    """

    def __init__(
        self,
        agent_id: str,
        *,
        host: str = "127.0.0.1",
        port: int = 0,
        reject_unverified: bool = True,
        gossip_batch_size: int = 0,
    ) -> None:
        self.agent_id = agent_id
        self.crdt = MerkleCRDT(agent_id, reject_unverified=reject_unverified)
        self.registry = GossipPeerRegistry()
        self.client = GossipClient()
        self._server = GossipServer(self.crdt, host=host, port=port)
        self._gossip_batch_size = gossip_batch_size
        self._running = False

    async def start(self) -> None:
        """Start the WebSocket gossip server."""
        await self._server.start()
        self.registry.self_addr = (self._server.host, self._server.actual_port)
        self._running = True
        log.info(
            "SwarmNode %s started at %s:%d",
            self.agent_id,
            self._server.host,
            self._server.actual_port,
        )

    async def stop(self) -> None:
        """Shut down the gossip server."""
        await self._server.stop()
        self._running = False

    async def __aenter__(self) -> SwarmNode:
        await self.start()
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.stop()

    @property
    def actual_port(self) -> int:
        """The port the server is bound to (after start())."""
        return self._server.actual_port

    @property
    def host(self) -> str:
        return self._server.host

    def _select_nodes_for_gossip(self) -> list[DAGNode]:
        """Select nodes to send in a gossip batch.

        If gossip_batch_size == 0, sends all nodes (full state gossip).
        Otherwise sends up to gossip_batch_size most recent nodes.
        Full state gossip is correct but expensive at scale; batching
        trades completeness per round for lower message size.
        """
        all_nodes = [self.crdt.get(cid) for cid in self.crdt.all_cids()]
        nodes = [n for n in all_nodes if n is not None]
        if self._gossip_batch_size > 0:
            # Sort by CID for determinism, take last N
            nodes.sort(key=lambda n: n.cid)
            nodes = nodes[-self._gossip_batch_size:]
        return nodes

    async def gossip_round(
        self,
        n_peers: int = 2,
        *,
        rng: random.Random | None = None,
    ) -> dict[str, Any]:
        """Gossip current DAG state to n_peers random peers.

        Returns a summary dict with peer count and send results.
        """
        peers = self.registry.sample(n_peers, rng=rng)
        if not peers:
            return {"peers_contacted": 0, "successes": 0, "nodes_sent": 0}

        nodes = self._select_nodes_for_gossip()
        if not nodes:
            return {"peers_contacted": 0, "successes": 0, "nodes_sent": 0}

        results = await asyncio.gather(
            *[self.client.send_batch(host, port, nodes) for host, port in peers],
            return_exceptions=True,
        )
        successes = sum(1 for r in results if r is True)
        return {
            "peers_contacted": len(peers),
            "successes": successes,
            "nodes_sent": len(nodes),
        }

    async def run_gossip_loop(
        self,
        *,
        interval_s: float = 1.0,
        n_peers: int = 2,
        max_rounds: int | None = None,
        rng: random.Random | None = None,
    ) -> None:
        """Run continuous gossip loop until cancelled or max_rounds reached.

        Typically run as a background task:

            task = asyncio.create_task(node.run_gossip_loop(interval_s=0.5))
            # ... do work ...
            task.cancel()
        """
        rounds = 0
        while True:
            if max_rounds is not None and rounds >= max_rounds:
                break
            await self.gossip_round(n_peers=n_peers, rng=rng)
            rounds += 1
            if max_rounds is None or rounds < max_rounds:
                await asyncio.sleep(interval_s)


# ---------------------------------------------------------------------------
# Multi-node convergence helper (for testing and benchmarks)
# ---------------------------------------------------------------------------


async def spin_up_swarm(
    n_nodes: int,
    *,
    host: str = "127.0.0.1",
    reject_unverified: bool = True,
) -> list[SwarmNode]:
    """Spin up n_nodes SwarmNodes on localhost with OS-assigned ports.

    All nodes are registered with each other in a full mesh.
    Returns the started nodes. Caller is responsible for stopping them.

    Example:
        nodes = await spin_up_swarm(5)
        try:
            nodes[0].crdt.append(payload="hello")
            await nodes[0].gossip_round(n_peers=2)
        finally:
            await asyncio.gather(*[n.stop() for n in nodes])
    """
    nodes = [
        SwarmNode(f"agent-{i}", host=host, reject_unverified=reject_unverified)
        for i in range(n_nodes)
    ]
    # Start all servers
    await asyncio.gather(*[node.start() for node in nodes])

    # Register full mesh (every node knows every other)
    for node in nodes:
        for other in nodes:
            if other is not node:
                node.registry.add(other.host, other.actual_port)

    return nodes


async def simulate_ws_gossip_convergence(
    n_nodes: int = 5,
    n_rounds: int = 10,
    artifacts_per_round: int = 2,
    n_peers: int = 2,
    *,
    seed: int = 42,
    host: str = "127.0.0.1",
) -> dict[str, Any]:
    """Simulate convergence over real WebSocket connections.

    Analogous to merkle_crdt.simulate_gossip_convergence() but uses
    actual network I/O instead of in-process merge().

    Returns:
        dict with convergence result, per-node sizes, total artifacts.
    """
    rng = random.Random(seed)  # noqa: S311 - deterministic simulation seed
    nodes = await spin_up_swarm(n_nodes, host=host)

    try:
        for round_idx in range(n_rounds):
            # Each node appends artifacts
            for node in nodes:
                for art_idx in range(artifacts_per_round):
                    node.crdt.append(
                        payload=f"round={round_idx} art={art_idx} by={node.agent_id}",
                        payload_type="task_output",
                        bodes_passed=True,
                        constitutional_hash="608508a9bd224290",
                    )

            # Gossip round (all nodes push to n_peers)
            await asyncio.gather(
                *[node.gossip_round(n_peers=n_peers, rng=rng) for node in nodes]
            )
            # Small pause to let receivers process
            await asyncio.sleep(0.02)

        # Final full-mesh convergence round
        for node in nodes:
            await node.gossip_round(n_peers=len(nodes), rng=rng)
        await asyncio.sleep(0.1)

    finally:
        await asyncio.gather(*[node.stop() for node in nodes])

    cid_sets = [node.crdt.all_cids() for node in nodes]
    converged = all(s == cid_sets[0] for s in cid_sets)
    sizes = {node.agent_id: node.crdt.size for node in nodes}
    total_artifacts = n_nodes * n_rounds * artifacts_per_round

    return {
        "converged": converged,
        "n_nodes": n_nodes,
        "n_rounds": n_rounds,
        "total_artifacts": total_artifacts,
        "sizes": sizes,
        "unique_cids": len(cid_sets[0]) if converged else -1,
    }

# Backwards-compatible alias — CI smoke test imports this name
GossipNode = SwarmNode
