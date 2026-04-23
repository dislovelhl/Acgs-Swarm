# constitutional-swarm
[![PyPI](https://img.shields.io/pypi/v/constitutional-swarm)](https://pypi.org/project/constitutional-swarm/)
[![Python](https://img.shields.io/pypi/pyversions/constitutional-swarm)](https://pypi.org/project/constitutional-swarm/)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
<img width="1280" height="640" alt="acgswarm" src="https://github.com/user-attachments/assets/dbc67c5d-2d46-4125-81ea-cfd5457b1c5a" />

**Orchestrator-free constitutional governance for multi-agent systems.**

## What this package is

`constitutional-swarm` is a governed multi-agent runtime built on [`acgs-lite`](https://pypi.org/project/acgs-lite/). It embeds governance per agent, supports orchestrator-free execution, adds peer validation and durable settlement, and ships advanced trust and governance research modules. Core constitutional checks stay local (sub-10 µs per check; see [performance notes](#performance-notes)); remote/public-key peer validation is available via the optional transport runtime.

## Installation

```bash
# Core runtime
pip install constitutional-swarm

# Optional transport runtime (websockets)
pip install "constitutional-swarm[transport]"

# Optional research stack (torch + transformers)
pip install "constitutional-swarm[research]"

# Optional Bittensor subnet integration
pip install "constitutional-swarm[bittensor]"
```

Requires Python 3.11+.

## Positioning

constitutional-swarm extends ACGS from governing single actions to governing agent societies. It combines local constitutional enforcement, orchestrator-free execution, peer-validated settlement, bounded trust dynamics, and a path toward decentralized constitutional evolution. The package includes both deployable governance primitives and frontier research modules; this README distinguishes them explicitly so users can adopt the stable core without absorbing the full research stack.

> ACGS-lite governs an action. constitutional-swarm governs a society of agents.

## Status

- **Stable core** — `AgentDNA`, DAG execution, `ConstitutionalMesh`, settlement durability, `EvolutionLog`
- **Production-direction trust model** — `SpectralSphereManifold`
- **Research baseline** — `GovernanceManifold` (Birkhoff/Sinkhorn); retained as a research control
- **Frontier modules** — `latent_dna`, `swarm_ode`, `merkle_crdt`, `swe_bench`

### What's new in 1.0

- Narrowed top-level public API: `AgentDNA`, `ConstitutionalMesh`, `GovernanceManifold`, `SwarmExecutor`, and `TaskDAG` are the canonical import surface
- Remote votes now use envelope-signed requests with replay protection
- Mesh startup now reconciles pending settlements on boot instead of leaving recovery to manual follow-up
- Settlement persistence now carries a `schema_version` for forward-compatible replay/recovery
- `SpectralSphereManifold` is the production-direction trust model; `GovernanceManifold` remains the research-control baseline

## Architecture in one view

| Layer | Purpose |
|-------|---------|
| **AgentDNA** | Local constitutional co-processor embedded in every agent |
| **DAG execution** | Orchestrator-free task execution via `DAGCompiler` + `SwarmExecutor` |
| **ConstitutionalMesh** | Peer validation with proof-bearing settlement |
| **Trust dynamics** | Bounded influence propagation (`SpectralSphereManifold` / `GovernanceManifold`) |
| **Constitutional evolution** | `EvolutionLog`, precedent formation, constitution sync |
| **Research modules** | `latent_dna`, `swarm_ode`, `merkle_crdt`, MCFS evaluation scaffolds |

## Quick starts by maturity tier

### A. Core runtime

The deployable surface. Start here.

#### Pattern A — Agent DNA (embedded validation)

Every agent carries an immutable constitutional validator. Governance is O(1) and local.

```python
from constitutional_swarm import AgentDNA
from acgs_lite import Rule, Severity

dna = AgentDNA.from_rules([
    Rule(id="no-pii", text="Block PII", patterns=["SSN", "date of birth"], severity=Severity.CRITICAL),
])

result = dna.validate("summarize patient notes")
print(result.valid, result.latency_ns)  # True, sub-10 µs typical

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

#### Pattern B — Stigmergic Swarm (DAG-compiled task execution)

Compile a goal into a `TaskDAG`. Agents self-select ready tasks by capability — no orchestrator.

```python
from constitutional_swarm import SwarmExecutor, TaskDAG
from constitutional_swarm.artifact import Artifact, ArtifactStore
from constitutional_swarm.capability import Capability, CapabilityRegistry
from constitutional_swarm.compiler import DAGCompiler, GoalSpec
import uuid

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
assert isinstance(dag, TaskDAG)
registry = CapabilityRegistry()
store = ArtifactStore()
executor = SwarmExecutor(registry, store)
executor.load_dag(dag)

# Register agent capabilities — without this, available_tasks() returns nothing.
agent_id = "worker-1"
registry.register(agent_id, [
    Capability(name="fetch",   domain="data"),
    Capability(name="analyse", domain="analytics"),
    Capability(name="write",   domain="writing"),
])

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

#### Pattern C — Constitutional Mesh (Byzantine-tolerant peer validation)

Every output is validated by randomly assigned peers. Quorum acceptance produces a cryptographic `MeshProof`.
`ConstitutionalMesh` requires Ed25519-signed votes: use `register_local_signer(...)` for in-process signers, `register_remote_agent(...)` for public-key-only peers, and pass a signature to every `submit_vote(...)`.

```python
from constitutional_swarm import ConstitutionalMesh
from acgs_lite import Constitution

constitution = Constitution.from_yaml("constitution.yaml")

mesh = ConstitutionalMesh(
    constitution,
    peers_per_validation=3,
    quorum=2,
)

mesh.register_local_signer("agent-a", domain="writing")
mesh.register_local_signer("agent-b", domain="writing")
mesh.register_local_signer("agent-c", domain="writing")

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

Built-in runtime path (requires `[transport]` extra):

```python
import asyncio
from constitutional_swarm import ConstitutionalMesh
from constitutional_swarm.remote_vote_transport import LocalRemotePeer, RemoteVoteServer

async def main():
    mesh = ConstitutionalMesh(constitution)
    mesh.register_local_signer("producer", domain="writing")
    remote_peer = LocalRemotePeer(agent_id="agent-d", constitution=constitution)
    mesh.register_remote_agent("agent-d", domain="writing", vote_public_key=remote_peer.public_key_hex)

    async with RemoteVoteServer(
        remote_peer.handle_vote_request,
        host="127.0.0.1",
        port=0,
        transport_security="auto",
    ) as server:
        result = await mesh.full_validation_remote(
            "producer",
            "safe distributed review content",
            "art-remote",
            peer_routes={"agent-d": ("127.0.0.1", server.actual_port)},
        )

asyncio.run(main())
```

Security notes:
- remote peers verify an envelope-signed request before validating content and reject replays outside the nonce/timestamp window
- remote peers reject requests when `sha256(content) != content_hash`
- `transport_security="auto"` defaults to `tls` unless the host is loopback
- `transport_security="tls"` forces TLS transport
- `transport_security="plaintext"` forces plain WebSocket transport
- production remote peers should set `trusted_request_signers={mesh.get_request_signing_public_key()}`
- **persist the mesh request-signing key across restarts.** It is generated per-process by default; without persistence, peers that pinned `trusted_request_signers` will reject requests after a restart and trust silently breaks
- **never set `allow_untrusted_request_signers=True` in production.** It exists for tests only and disables the signer-pinning check — leaving it on in prod erases the main transport trust boundary

Registration modes:
- `register_local_signer(...)` — the mesh may sign for this peer in-process
- `register_remote_agent(...)` — public-key-only peer; signing happens outside the process
- ~~`register_agent(...)`~~ — **REMOVED in v0.3.0**. See [MIGRATION.md](MIGRATION.md)

Settlement semantics:

- quorum does not just mark a result as "currently accepted"
- it freezes a `MeshResult` / `MeshProof` snapshot with stable finality
- late votes are rejected after settlement so the proof root cannot drift
- optional settlement stores persist finalized proofs across restarts

Choosing a settlement backend:

```python
from constitutional_swarm import ConstitutionalMesh
from constitutional_swarm.settlement_store import JSONLSettlementStore, SQLiteSettlementStore
from acgs_lite import Constitution

constitution = Constitution.default()

jsonl_mesh = ConstitutionalMesh(
    constitution,
    settlement_store=JSONLSettlementStore("artifacts/mesh-settlements.jsonl"),
)

sqlite_mesh = ConstitutionalMesh(
    constitution,
    settlement_store=SQLiteSettlementStore("artifacts/mesh-settlements.db"),
)
```

#### Pattern D — Evolution Log (declarative metric invariants)

Enforces five structural invariants at write time: strict monotonicity, strict acceleration, contiguous history, uniqueness, and minimum evidence. No loops, no conditionals — declare the contract and the database rejects violations.

```python
from constitutional_swarm.evolution_log import EvolutionLog, DecelerationBlockedError

with EvolutionLog(":memory:") as log:
    for epoch, value in [(1, 10.0), (2, 12.0), (3, 16.0), (4, 22.0), (5, 30.0)]:
        log.record(epoch, "capability", value)

    try:
        log.record(6, "capability", 38.0)   # delta=8, prior delta=8 → rejected
    except DecelerationBlockedError:
        pass

    log.record(6, "capability", 40.0)  # delta=10 > prior delta=8 → accepted

    dashboard = {r.metric: r for r in log.dashboard()}
    assert dashboard["capability"].strictly_accelerating == "YES"

    assert log.admissible_min("capability", 7) == 51.0  # 40 + 10 + 1
    assert log.admit("capability", 7, 55.0) is True
    assert log.admit("capability", 7, 50.0) is False
    assert log.valid_trajectory("capability", 1, 6) is True
```

The log is append-only: `UPDATE` and `DELETE` are blocked by triggers. Single-epoch metrics report `"INSUFFICIENT DATA"` rather than a misleading answer.

### B. Advanced runtime — trust dynamics

#### Pattern E — SpectralSphereManifold (production-direction trust model)

Bounded spectral norm with negative trust allowed and residual identity injection. This is the current production-direction trust model; it preserves boundedness while retaining specialization under repeated swarm composition.

```python
from constitutional_swarm.spectral_sphere import SpectralSphereManifold

manifold = SpectralSphereManifold(num_agents=3, r=1.0)
manifold.update_trust(from_agent=0, to_agent=1, delta=0.8)
manifold.update_trust(from_agent=1, to_agent=2, delta=-0.3)  # negative trust permitted
projection = manifold.project()
```

### C. Research stack

MCFS-style modules and evaluation scaffolds. APIs may change.

- `latent_dna` — BODES hook + `LatentDNAWrapper.generate_governed()` for LLM residual steering (requires `[research]`)
- `swarm_ode` — projected RK4 continuous-time trust dynamics
- `merkle_crdt` — content-addressed DAG artifact store (SHA-256 CIDs, set-union merge)
- `gossip_protocol` — WebSocket gossip transport for `MerkleCRDT` (requires `[transport]`)
- `swe_bench/` — evaluation scaffold: `SWEBenchAgent`, `SWEBenchHarness`, `SwarmCoordinator`

## Trust dynamics: baseline and current direction

`constitutional-swarm` ships two trust models. Which you use is an architectural choice, and this section is deliberately explicit.

**Baseline: `GovernanceManifold` (Birkhoff / Sinkhorn-Knopp)**

Projects raw agent interaction matrices onto the Birkhoff polytope (doubly stochastic) via Sinkhorn-Knopp, guaranteeing bounded influence at any scale. It gave us a rigorous first trust geometry with spectral norm ≤ 1, compositional closure, and trust conservation.

```python
from constitutional_swarm import GovernanceManifold
from constitutional_swarm.manifold import sinkhorn_knopp

raw = [[1.0, 0.5, 0.2],
       [0.3, 1.0, 0.7],
       [0.1, 0.4, 1.0]]

result = sinkhorn_knopp(raw, max_iterations=20, epsilon=1e-6)
print(result.converged, result.spectral_bound)  # True, ≤1.0

manifold = GovernanceManifold(num_agents=3)
manifold.update_trust(from_agent=0, to_agent=1, delta=0.8)
projection = manifold.project()
```

**Failure mode we observed.** Repeated real swarm composition revealed that Birkhoff/Sinkhorn projection drives the swarm toward uniformity — specialization collapses under iterated application. The regression is encoded empirically as an `xfail` test in [`tests/test_manifold_degeneration.py`](tests/test_manifold_degeneration.py); we kept the baseline as a research control.

**Current production direction: `SpectralSphereManifold`.** Bounded spectral norm, negative trust allowed, residual identity injection. Preserves boundedness without forcing uniformity. This is theory informing product, not theory being discarded.

See the `spectral_sphere` reference (Anonymous, 2026) and the `manifold` reference (Xie et al., 2025) for mathematical background.

## Key Features

- **Agent DNA** — `AgentDNA` embeds a constitutional co-processor in every agent; validation is routed through the ACGS Rust engine (sub-10 µs typical; see [performance notes](#performance-notes))
- **Stigmergic DAGs** — `DAGCompiler` + `SwarmExecutor` for orchestrator-free task execution; agents claim ready tasks via `executor.available_tasks(agent_id)` filtered by registered capability
- **Constitutional Mesh** — `ConstitutionalMesh` provides Byzantine-tolerant peer validation with cryptographic `MeshProof` chains; MACI prevents self-validation
- **Spectral-sphere manifold** — `SpectralSphereManifold` is the production-direction trust model; `GovernanceManifold` and `sinkhorn_knopp()` remain as the Birkhoff baseline
- **Evolution Log** — `EvolutionLog` enforces strict monotonicity + acceleration as structural database invariants
- **Artifact store** — `ArtifactStore` tracks task outputs (`Artifact`) by ID
- **Capability registry** — `CapabilityRegistry` maps agents to `Capability` sets for task claiming
- **Benchmarking** — `SwarmBenchmark` for measuring validation throughput at scale

## Public API

For 1.0, the canonical top-level import surface is intentionally small:

```python
from constitutional_swarm import (
    AgentDNA,
    ConstitutionalMesh,
    GovernanceManifold,
    SwarmExecutor,
    TaskDAG,
)
```

| Symbol | Description |
|--------|-------------|
| `AgentDNA` | Stable entry point for embedded constitutional validation |
| `ConstitutionalMesh` | Stable entry point for peer validation, settlement, and signed voting flows |
| `GovernanceManifold` | Stable top-level access to the Birkhoff/Sinkhorn research baseline |
| `SwarmExecutor` | Stable top-level executor for orchestrator-free task execution |
| `TaskDAG` | Stable DAG type produced by the compiler/runtime pipeline |

Everything else remains importable, but 1.0 documents it as advanced surface. New code should prefer explicit module imports for transport, persistence, compiler helpers, and research modules.

### Advanced Modules and Extras

| Module | Use for |
|--------|---------|
| `constitutional_swarm.mesh` | Peer-validation internals, proofs, results, reconciliation, and settlement-facing types |
| `constitutional_swarm.remote_vote_transport` | `RemoteVoteServer`, `RemoteVoteClient`, `LocalRemotePeer`, and transport-security configuration |
| `constitutional_swarm.compiler` | `DAGCompiler`, `GoalSpec`, `GoalStep`, and compilation helpers |
| `constitutional_swarm.settlement_store` | `SettlementStore`, `SettlementRecord`, `JSONLSettlementStore`, `SQLiteSettlementStore` |
| `constitutional_swarm.spectral_sphere` | `SpectralSphereManifold` and spectral projection helpers |

Compatibility re-exports may still work for some advanced symbols, but the 1.0 documentation contract is: top-level for the five stable names above, explicit submodules for advanced usage.

## Advanced: Bittensor subnet integration

Run constitutional governance miners and validators on a Bittensor subnet. This is a decentralized validator network layer, not part of the stable core.

```bash
pip install "constitutional-swarm[bittensor]"
```

**Local no-network quickstart:**
```bash
python scripts/testnet_deploy.py --constitution examples/constitution.yaml
```

Expected output snippet:
```text
Running local Constitutional Swarm testnet simulation...
  Mode: local (no Bittensor SDK, wallet, RPC, axon, or external network)
  Agents registered: 5
  local-case-0: accepted=True votes_for=2 votes_against=0 quorum_met=True
MEASUREMENT agents_registered=5 validations=4 votes_cast=8 accepted=4 rejected=0 final_spectral_bound=1.00000 stable=True
```

Measurable local outcome: 5 agents registered, 4 validations settled, 8 votes cast,
4 accepted decisions, and a stable final trust manifold.

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

## Performance notes

The `AgentDNA.validate()` hot path routes through the ACGS Rust engine. The repository's regression test asserts an average below 10 µs per validation (`tests/test_constitutional_swarm.py::...avg_ns < 10_000`). Reference benchmarks on a modern x86 laptop have observed ~443 ns/call, but that figure depends on hardware, rule count, pattern complexity, and the Rust engine build. Do not treat 443 ns as a product guarantee — treat the sub-10 µs bound as the contract and benchmark your own workload before quoting numbers externally.

## Runtime dependencies

- `acgs-lite>=2.8.1`
- `cryptography>=44.0.2`

## License

AGPL-3.0-or-later.

## Links

- [Homepage](https://acgs.ai)
- [PyPI](https://pypi.org/project/constitutional-swarm/)
- [Issues](https://github.com/dislovelhl/Acgs-Swarm/issues)

## Project Docs

- [Changelog](CHANGELOG.md)
- [Contributor notes](CLAUDE.md)
- [Security policy](SECURITY.md)
- [Paper draft index](paper/README.md)
- [MACI + differential privacy protocol draft](docs/maci_dp_protocol.md)

## References

Core papers cited in this codebase and accompanying manuscripts. The full BibTeX file is [`references.bib`](references.bib).

| Citation | Reference |
|----------|-----------|
| Xie et al., 2025 | [Manifold-Constrained Hyper-Connections (mHC)](https://arxiv.org/abs/2512.24880) — mathematical foundation for Birkhoff-polytope governance projection |
| Anonymous, 2026 | [Spectral-Sphere-Constrained Hyper-Connections (sHC)](https://arxiv.org/abs/2603.20896) — spectral-norm-ball alternative to Birkhoff projection |
| Zhu et al., 2024 | [Hyper-Connections](https://arxiv.org/abs/2409.19606) — expanded residual streams in transformers |
| Bai et al., 2022 | [Constitutional AI: Harmlessness from AI Feedback](https://arxiv.org/abs/2212.08073) |
| Wu et al., 2023 | [AutoGen: Enabling Next-Gen LLM Applications](https://arxiv.org/abs/2308.08155) |
| Sinkhorn, 1964 | A Relationship Between Arbitrary Positive Matrices and Doubly Stochastic Matrices. *Ann. Math. Stat.* 35(2):876–879. [doi:10.1214/aoms/1177703591](https://doi.org/10.1214/aoms/1177703591) |
| Sinkhorn & Knopp, 1967 | Concerning Nonnegative Matrices and Doubly Stochastic Matrices. *Pacific J. Math.* 21(2):343–348. [doi:10.2140/pjm.1967.21.343](https://doi.org/10.2140/pjm.1967.21.343) |
| Castro & Liskov, 1999 | Practical Byzantine Fault Tolerance. *USENIX OSDI*, pp. 173–186 |
| Dwork et al., 2006 | [Calibrating Noise to Sensitivity in Private Data Analysis](https://doi.org/10.1007/11681878_14). *TCC* |
| Dwork & Roth, 2014 | [The Algorithmic Foundations of Differential Privacy](https://doi.org/10.1561/0400000042). *Found. Trends TCS* 9(3–4):211–407 |
| Kleppmann & Beresford, 2022 | [Merkle-CRDTs: Merkle-DAGs Meet CRDTs](https://arxiv.org/abs/2004.00107) |
| Anonymous, 2025 | [Federated Sinkhorn (arXiv:2502.07021)](https://arxiv.org/abs/2502.07021) |
| Jimenez et al., 2024 | [SWE-bench](https://arxiv.org/abs/2310.06770) — software engineering benchmark used for swarm evaluation |
| Buterin et al., 2023 | [MACI: Minimal Anti-Collusion Infrastructure](https://privacy-scaling-explorations.github.io/maci/) |
