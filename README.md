# constitutional-swarm

[![PyPI](https://img.shields.io/pypi/v/constitutional-swarm)](https://pypi.org/project/constitutional-swarm/)
[![Python](https://img.shields.io/pypi/pyversions/constitutional-swarm)](https://pypi.org/project/constitutional-swarm/)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)

**Orchestrator-free multi-agent governance via embedded Agent DNA, stigmergic task coordination, constitutional peer validation, and manifold-constrained trust.**

`constitutional-swarm` provides five composable patterns for governed multi-agent systems. Core constitutional checks stay local (443 ns/check), while remote/public-key peer validation remains available when you install the transport runtime. The core package depends on `acgs-lite` and `cryptography`, with optional extras for WebSocket transport and the MCFS research stack.

## Installation

```bash
# Core install — no torch required
pip install constitutional-swarm

# With MCFS research stack (latent DNA steering, swarm ODE dynamics)
pip install "constitutional-swarm[research]"

# With WebSocket gossip transport
pip install "constitutional-swarm[transport]"
```

Requires Python 3.11+.

## Quick Start

### Pattern A — Agent DNA (embedded validation)

Every agent carries an immutable constitutional validator. Governance is O(1) and local.

```python
from constitutional_swarm import AgentDNA
from acgs_lite import Rule, Severity

dna = AgentDNA.from_rules([
    Rule(id="no-pii", pattern="SSN|date of birth", severity=Severity.CRITICAL,
         description="Block PII"),
])

result = dna.validate("summarize patient notes")
print(result.valid, result.latency_ns)  # True, ~443

# Use as a decorator
@dna.govern
def my_agent(text: str) -> str:
    return f"processed: {text}"
```

Load from YAML or use defaults:

```python
dna = AgentDNA.from_yaml("constitution.yaml")
dna = AgentDNA.default(agent_id="worker-1")  # permissive defaults
```

### Pattern B — Stigmergic Swarm (DAG-compiled task execution)

Compile a goal into a `TaskDAG`. Agents self-select ready tasks by capability — no orchestrator.

```python
from constitutional_swarm import (
    DAGCompiler, GoalSpec, SwarmExecutor, CapabilityRegistry, ArtifactStore, Artifact,
)
import uuid, time

spec = GoalSpec(
    goal="Analyse and summarise quarterly reports",
    domains=["data", "analytics", "writing"],
    steps=[
        {"title": "fetch-reports", "domain": "data",      "required_capabilities": ["fetch"]},
        {"title": "analyse",       "domain": "analytics", "required_capabilities": ["analyse"],
         "depends_on": ["fetch-reports"]},
        {"title": "summarise",     "domain": "writing",   "required_capabilities": ["write"],
         "depends_on": ["analyse"]},
    ],
)

dag = DAGCompiler().compile(spec)
registry = CapabilityRegistry()
store = ArtifactStore()
executor = SwarmExecutor(registry, store)
executor.load_dag(dag)

# Agents self-select and execute tasks
agent_id = "worker-1"
for task in executor.available_tasks(agent_id):
    receipt = executor.claim(task.node_id, agent_id)
    artifact = Artifact(
        artifact_id=uuid.uuid4().hex,
        task_id=receipt.task_id,
        agent_id=agent_id,
        content_type="text/plain",
        content=f"completed: {receipt.title}",
        domain=receipt.domain,
    )
    executor.submit(receipt.task_id, artifact)
```

### Pattern C — Constitutional Mesh (Byzantine-tolerant peer validation)

Every output is validated by randomly assigned peers. Quorum acceptance produces a cryptographic `MeshProof`.

```python
from constitutional_swarm import ConstitutionalMesh
from acgs_lite import Constitution

constitution = Constitution.from_yaml("constitution.yaml")

mesh = ConstitutionalMesh(
    constitution,
    peers_per_validation=3,  # peers assigned per output
    quorum=2,                 # votes needed to accept
)

mesh.register_local_signer("agent-a", domain="writing")
mesh.register_local_signer("agent-b", domain="writing")
mesh.register_local_signer("agent-c", domain="writing")

# Assign peers and collect votes
assignment = mesh.request_validation("agent-a", content="Draft report…", artifact_id="doc-1")
mesh.validate_and_vote(assignment.assignment_id, "agent-b")
mesh.validate_and_vote(assignment.assignment_id, "agent-c")

result = mesh.get_result(assignment.assignment_id)
assert result.settled is True
assert result.proof is not None
print(result.accepted, result.quorum_met, result.proof.verify())
```

Remote/public-key-only peers:

```python
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

remote_key = Ed25519PrivateKey.generate()
mesh.register_remote_agent("agent-d", domain="writing", vote_public_key=remote_key.public_key())

request = mesh.prepare_remote_vote(assignment.assignment_id, "agent-d")
signature = remote_key.sign(
    ConstitutionalMesh.build_vote_payload(
        assignment_id=request.assignment_id,
        voter_id=request.voter_id,
        approved=True,
        reason="remote constitutional check passed",
        constitutional_hash=request.constitutional_hash,
        content_hash=request.content_hash,
    )
).hex()

mesh.submit_vote(
    request.assignment_id,
    request.voter_id,
    approved=True,
    reason="remote constitutional check passed",
    signature=signature,
)
```

Built-in runtime path:

```python
from constitutional_swarm import ConstitutionalMesh, LocalRemotePeer, RemoteVoteServer

mesh = ConstitutionalMesh(constitution)
mesh.register_local_signer("producer", domain="writing")
remote_peer = LocalRemotePeer(agent_id="agent-d", constitution=constitution)
mesh.register_remote_agent("agent-d", domain="writing", vote_public_key=remote_peer.public_key_hex)

async with RemoteVoteServer(remote_peer.handle_vote_request, host="127.0.0.1", port=0) as server:
    result = await mesh.full_validation_remote(
        "producer",
        "safe distributed review content",
        "art-remote",
        peer_routes={"agent-d": ("127.0.0.1", server.actual_port)},
    )
```

Security notes:
- remote peers verify a signed request envelope before validating content
- remote peers reject requests when `sha256(content) != content_hash`
- plain `ws://` transport is allowed only on localhost; non-local use requires TLS via `ssl_context`
- production remote peers should set `trusted_request_signers={mesh.get_request_signing_public_key()}`

Registration modes:
- `register_local_signer(...)` — the mesh may sign for this peer in-process
- `register_remote_agent(...)` — public-key-only peer; signing happens outside the process
- `register_agent(...)` — compatibility wrapper that now requires explicit mode selection

Settlement semantics:

- quorum does not just mark a result as "currently accepted"
- it freezes a `MeshResult` / `MeshProof` snapshot with stable finality
- late votes are rejected after settlement so the proof root cannot drift
- optional settlement stores can persist finalized proofs across restarts

Choosing a settlement backend:

```python
from constitutional_swarm import ConstitutionalMesh, JSONLSettlementStore, SQLiteSettlementStore
from acgs_lite import Constitution

constitution = Constitution.default()

# Append-only local file
jsonl_mesh = ConstitutionalMesh(
    constitution,
    settlement_store=JSONLSettlementStore("artifacts/mesh-settlements.jsonl"),
)

# Stdlib SQLite
sqlite_mesh = ConstitutionalMesh(
    constitution,
    settlement_store=SQLiteSettlementStore("artifacts/mesh-settlements.db"),
)

print(jsonl_mesh.summary()["settlement_storage"])
print(sqlite_mesh.summary()["settlement_storage"])
```

### Pattern D — Governance Manifold (bounded trust propagation)

Projects raw agent interaction matrices onto the Birkhoff polytope (doubly stochastic) via Sinkhorn-Knopp, guaranteeing bounded influence at any scale.

```python
from constitutional_swarm import GovernanceManifold, sinkhorn_knopp

# Raw trust matrix (3 agents)
raw = [[1.0, 0.5, 0.2],
       [0.3, 1.0, 0.7],
       [0.1, 0.4, 1.0]]

result = sinkhorn_knopp(raw, max_iterations=20, epsilon=1e-6)
print(result.converged, result.spectral_bound)  # True, ≤1.0

# Or use the stateful GovernanceManifold (tracks interaction history)
manifold = GovernanceManifold(num_agents=3)
manifold.update_trust(from_agent=0, to_agent=1, delta=0.8)
projection = manifold.project()
```

### Pattern E — Evolution Log (declarative metric invariants)

Enforces five structural invariants at write time: strict monotonicity, strict acceleration, contiguous history, uniqueness, and minimum evidence. No loops, no conditionals — declare the contract and the database rejects violations.

```python
from constitutional_swarm import EvolutionLog, NonIncreasingValueError, DecelerationBlockedError

with EvolutionLog(":memory:") as log:
    # Seed data — accelerating capability curve
    for epoch, value in [(1, 10.0), (2, 12.0), (3, 16.0), (4, 22.0), (5, 30.0)]:
        log.record(epoch, "capability", value)

    # Write-time enforcement
    try:
        log.record(6, "capability", 38.0)   # delta=8, prior delta=8 → rejected
    except DecelerationBlockedError:
        pass  # constant rate is not acceleration

    log.record(6, "capability", 40.0)  # delta=10 > prior delta=8 → accepted

    # Query the contract
    dashboard = {r.metric: r for r in log.dashboard()}
    assert dashboard["capability"].strictly_accelerating == "YES"

    # Generative search: what is the minimum valid next value?
    assert log.admissible_min("capability", 7) == 51.0  # 40 + 10 + 1

    # Dry-run admission check (mirrors Prolog admit/3)
    assert log.admit("capability", 7, 55.0) is True
    assert log.admit("capability", 7, 50.0) is False  # delta=10, prior=10 → not strict

    # Validate an entire trajectory
    assert log.valid_trajectory("capability", 1, 6) is True
```

The log is append-only: `UPDATE` and `DELETE` are blocked by triggers. Single-epoch metrics report `"INSUFFICIENT DATA"` rather than a misleading answer.

## Key Features

- **Agent DNA** — `AgentDNA` embeds a constitutional co-processor in every agent; 443 ns/validation via the ACGS Rust engine
- **Stigmergic DAGs** — `DAGCompiler` + `SwarmExecutor` for orchestrator-free task execution; agents claim `ready_nodes()` by capability
- **Constitutional Mesh** — `ConstitutionalMesh` provides Byzantine-tolerant peer validation with cryptographic `MeshProof` chains; MACI prevents self-validation
- **Sinkhorn-Knopp manifold** — `GovernanceManifold` and `sinkhorn_knopp()` project trust matrices onto the Birkhoff polytope; spectral norm ≤ 1
- **Evolution Log** — `EvolutionLog` enforces strict monotonicity + acceleration as structural database invariants; regressions and decelerations are rejected at write time
- **Artifact store** — `ArtifactStore` tracks task outputs (`Artifact`) by ID
- **Capability registry** — `CapabilityRegistry` maps agents to `Capability` sets for task claiming
- **Benchmarking** — `SwarmBenchmark` for measuring validation throughput at scale

## API Reference

| Symbol | Description |
|--------|-------------|
| `EvolutionLog` | Append-only SQLite log; `.record(epoch, metric, value)`, `.dashboard()`, `.admit()`, `.admissible_min()`, `.valid_trajectory()`, `.detect_regression()`, `.detect_deceleration()`, `.detect_gaps()` |
| `DashboardRow` | Per-metric summary: `baseline`, `current_best`, `epoch_count`, `total_gain`, `avg_rate`, `strictly_increasing`, `strictly_accelerating` |
| `EvolutionViolationError` | Base exception for all write-time invariant violations |
| `MissingPriorEpochError` | Raised when epoch N is inserted without epoch N-1 |
| `NonIncreasingValueError` | Raised when value does not strictly exceed prior value |
| `DecelerationBlockedError` | Raised when delta does not strictly exceed prior delta |
| `MutationBlockedError` | Raised when UPDATE or DELETE is attempted on the append-only table |
| `RegressionRecord` | `(metric, epoch, delta)` — result of `detect_regression()` |
| `DecelerationRecord` | `(metric, epoch, accel)` — result of `detect_deceleration()` |
| `GapRecord` | `(metric, epoch)` — result of `detect_gaps()` |
| `AgentDNA` | Constitutional co-processor; `.from_rules()`, `.from_yaml()`, `.default(agent_id=...)`, `.validate(action)`, `.govern` decorator |
| `DNAValidationResult` | `valid`, `action`, `violations`, `latency_ns`, `constitutional_hash`, `risk_score` |
| `DNADisabledError` | Raised when validate() is called on a disabled `AgentDNA` |
| `constitutional_dna` | Decorator factory for inline DNA governance |
| `ConstitutionalMesh` | `ConstitutionalMesh(constitution, peers_per_validation=3, quorum=2)` |
| `MeshProof` | Cryptographic proof of a settled peer validation; `accepted`, `vote_hashes`, `root_hash`, `verify()` |
| `MeshResult` | Current or settled result view; includes `accepted`, `quorum_met`, `pending_votes`, `proof`, `settled`, `settled_at` |
| `MeshHaltedError` | Raised when mesh is halted and a new operation is attempted |
| `AssignmentSettledError` | Raised when a vote is submitted after quorum has already finalized an assignment |
| `PeerAssignment` | Immutable assignment linking a producer's output to peer validators |
| `ValidationVote` | A peer's Ed25519-signed vote on a producer's output |
| `SettlementStore` | Minimal append/load protocol for durable settled-proof snapshots |
| `JSONLSettlementStore` | Append-only local settlement adapter for single-node use |
| `SQLiteSettlementStore` | SQLite-backed settlement adapter using the Python standard library |
| `SwarmExecutor` | Runs a `TaskDAG`; agents self-select tasks by capability |
| `TaskDAG` | DAG of `TaskNode`s compiled from a `GoalSpec` |
| `TaskNode` | Single unit of work: `title`, `required_capabilities`, `depends_on`, `status` |
| `DAGCompiler` | `.compile(GoalSpec)` → `TaskDAG`; `.compile_from_yaml(path)` |
| `GoalSpec` | Goal description with subtask list |
| `GovernanceManifold` | Tracks agent interactions; `.project()` → `ManifoldProjectionResult` |
| `ManifoldProjectionResult` | `matrix`, `iterations`, `converged`, `max_deviation`, `spectral_bound` |
| `sinkhorn_knopp` | Projects any non-negative matrix onto the Birkhoff polytope |
| `Artifact` | Task output record |
| `ArtifactStore` | Stores and retrieves `Artifact`s by ID |
| `Capability` | Named capability (string + metadata) |
| `CapabilityRegistry` | Maps agent IDs to their `Capability` sets |
| `TaskContract` | Records the agreement between a task and a claiming agent |
| `ContractStatus` | Enum: `PENDING`, `ACTIVE`, `COMPLETED`, `FAILED` |
| `WorkReceipt` | Receipt issued when an agent completes a task node |
| `ExecutionStatus` | Enum: `BLOCKED`, `READY`, `ACTIVE`, `COMPLETED`, `FAILED` |
| `SwarmBenchmark` | Measures DNA validation throughput at scale |
| `BenchmarkResult` | Benchmark output: `agents`, `validations_per_second`, `p99_ns` |

## Bittensor Integration

Run constitutional governance miners and validators on a Bittensor subnet.

```bash
pip install "constitutional-swarm[bittensor]"
```

**Register a subnet on testnet:**
```bash
python scripts/testnet_deploy.py register \
  --wallet-name my-wallet \
  --wallet-hotkey default
# prints: netuid=<id>
```

**Start a miner:**
```bash
python scripts/testnet_deploy.py miner \
  --netuid <id> \
  --constitution examples/constitution.yaml \
  --wallet-name my-wallet
```

**Start a validator:**
```bash
python scripts/testnet_deploy.py validator \
  --netuid <id> \
  --constitution examples/constitution.yaml \
  --wallet-name my-wallet
```

Testnet TAO faucet: https://test.taostats.io/faucet

## Runtime dependencies

- `acgs-lite>=2.7.2`

## License

AGPL-3.0-or-later.

## Links

- [Homepage](https://acgs.ai)
- [PyPI](https://pypi.org/project/constitutional-swarm/)
- [Issues](https://github.com/dislovelhl/Acgs-Swarm/issues)

## Project Docs

- [Changelog](CHANGELOG.md)
- [Contributor notes](CLAUDE.md)
- [Paper draft index](paper/README.md)
- [MACI + differential privacy protocol draft](docs/maci_dp_protocol.md)
