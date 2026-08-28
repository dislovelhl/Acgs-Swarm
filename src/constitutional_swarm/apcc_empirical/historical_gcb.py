"""Isolated executor for the pinned pre-APCC GCB-1 implementation."""

from __future__ import annotations

import base64
import ast
import fcntl
import hashlib
import hmac
import json
import os
import select
import secrets
import shutil
import stat
import subprocess
import tarfile
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlsplit

from constitutional_swarm.apcc_empirical.adapters import (
    AuthorityObservation,
    BaselineBlocked,
    Capability,
    DurableSnapshot,
    ScenarioExecutionError,
    TrialStimulus,
    variant_id_for_native_evidence,
)

GCB1_COMMIT_SHA = "6e65db3e478fa315119038b616d78f4f171422db"
GCB1_TREE_SHA = "18cf41945e9cd2e40b208d2f4cd4dbf8788bb6f0"
GCB1_LOCK_SHA256 = "e111811f919150018e43af151f66590c5097feb9695bdf4aaafa2f8725d3f3b5"
ADAPTER_VERSION = "gcb1-subprocess-v1"
FROZEN_PYTHON_VERSION = "3.13.13"
FROZEN_CRYPTOGRAPHY_VERSION = "47.0.0"
_MAX_FRAME_BYTES = 1_048_576
_RPC_TIMEOUT_SECONDS = 5.0
_STATE_LOCK_TIMEOUT_SECONDS = 0.5
JOURNAL_COVERAGE_LIMITATION = (
    "Pinned GCB-1 has no public workflow-enumeration API; an authority commit that "
    "survives while the authenticated journal index does not cannot be rediscovered."
)
JOURNAL_ROLLBACK_SCOPE = (
    "Detects authenticated journal-only rollback against its paired durable head; "
    "paired journal-and-head rollback and same-UID storage compromise are outside "
    "the declared trusted-host/store TCB."
)
SQLITE_PATH_SCOPE = (
    "Pinned GCB-1 SQLite accepts a pathname, not a supervisor-held database FD; "
    "B5 therefore relies on lstat identity checks, its mode-0700 state root, and "
    "the lifetime ownership lock under the trusted same-UID host TCB, without an "
    "open-FD no-follow guarantee."
)
_ENVIRONMENT_IDENTITY_SCRIPT = r"""
import hashlib, importlib.metadata, json, sys
from pathlib import Path
import cryptography

snapshot = Path(sys.argv[1]).resolve()
module = snapshot / "src/constitutional_swarm/governed_commit.py"
cryptography_root = Path(cryptography.__file__).resolve().parent
def hash_tree(root):
    digest = hashlib.sha256()
    for path in sorted(
        item for item in root.rglob("*")
        if item.is_file() and "__pycache__" not in item.parts and item.suffix != ".pyc"
    ):
        digest.update(path.relative_to(root).as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
    return digest.hexdigest()
material = {
    "python_version": sys.version.split()[0],
    "python_binary_sha256": hashlib.sha256(
        Path(sys.executable).resolve().read_bytes()
    ).hexdigest(),
    "cryptography_version": cryptography.__version__,
    "cryptography_content_sha256": hash_tree(cryptography_root),
    "environment_content_sha256": hash_tree(Path(sys.prefix).resolve()),
    "distributions": sorted(
        (dist.metadata["Name"].lower(), dist.version)
        for dist in importlib.metadata.distributions()
        if dist.metadata["Name"]
    ),
    "lock_sha256": hashlib.sha256((snapshot / "uv.lock").read_bytes()).hexdigest(),
    "module_sha256": hashlib.sha256(module.read_bytes()).hexdigest(),
}
encoded = json.dumps(material, sort_keys=True, separators=(",", ":")).encode()
print(json.dumps({"material": material, "digest": hashlib.sha256(encoded).hexdigest()}))
"""

_UNSUPPORTED_VARIANTS = frozenset(
    {
        "predecessor-replacement-race:supersession-current",
        "predecessor-replacement-race:supersession-stale",
    }
)


class HistoricalSnapshotError(RuntimeError):
    """The historical source or authenticated worker boundary is invalid."""


@dataclass(frozen=True, slots=True)
class HistoricalSnapshotIdentity:
    commit_sha: str
    tree_sha: str
    lock_sha256: str
    python_version: str
    cryptography_version: str
    environment_digest: str
    module_sha256: str
    adapter_version: str
    snapshot_root: Path
    module_path: str

    def as_manifest_record(self) -> dict[str, str]:
        return {
            "commit_sha": self.commit_sha,
            "tree_sha": self.tree_sha,
            "lock_sha256": self.lock_sha256,
            "python_version": self.python_version,
            "cryptography_version": self.cryptography_version,
            "environment_digest": self.environment_digest,
            "module_sha256": self.module_sha256,
            "adapter_version": self.adapter_version,
            "module_path": self.module_path,
            "journal_coverage_limitation": JOURNAL_COVERAGE_LIMITATION,
            "journal_rollback_scope": JOURNAL_ROLLBACK_SCOPE,
            "sqlite_path_scope": SQLITE_PATH_SCOPE,
        }


_WORKER = r"""
import base64, hashlib, hmac, importlib.metadata, json, os, secrets, sys, time, types
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path

snapshot = Path(sys.argv[1]).resolve()
database = Path(sys.argv[2])
if not database.is_absolute() or database.is_symlink():
    raise SystemExit("unsafe historical database pathname")
os.umask(0o077)
bootstrap_line = sys.stdin.readline(1_048_577)
if not bootstrap_line or len(bootstrap_line.encode("utf-8")) > 1_048_576:
    raise SystemExit("invalid bootstrap frame")
bootstrap_frame = json.loads(bootstrap_line)
secret = base64.b64decode(bootstrap_frame["secret"], validate=True)
seeds = [
    base64.b64decode(bootstrap_frame[name], validate=True)
    for name in ("verifier", "admin", "agent")
]
sys.path.insert(0, str(snapshot / "src"))
package = types.ModuleType("constitutional_swarm")
package.__path__ = [str(snapshot / "src" / "constitutional_swarm")]
package.__package__ = "constitutional_swarm"
sys.modules["constitutional_swarm"] = package

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import cryptography
from constitutional_swarm.artifact import Artifact, ArtifactStore
from constitutional_swarm.governed_commit import (
    GovernedCommitBoundary, PredecessorBinding, TrustedGovernanceBootstrap,
    sign_attempt_authorization, sign_governed_receipt,
)
import constitutional_swarm.governed_commit as historical_module

module_path = str(Path(historical_module.__file__).resolve())
if not module_path.startswith(str(snapshot)):
    raise SystemExit("current-module import contamination")
if any(name.startswith("constitutional_swarm.apcc") for name in sys.modules):
    raise SystemExit("current APCC module contamination")

def hash_tree(root):
    digest = hashlib.sha256()
    for path in sorted(
        item for item in root.rglob("*")
        if item.is_file() and "__pycache__" not in item.parts and item.suffix != ".pyc"
    ):
        digest.update(path.relative_to(root).as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
    return digest.hexdigest()

def environment_identity():
    cryptography_root = Path(cryptography.__file__).resolve().parent
    distributions = sorted(
        (dist.metadata["Name"].lower(), dist.version)
        for dist in importlib.metadata.distributions()
        if dist.metadata["Name"]
    )
    material = {
        "python_version": sys.version.split()[0],
        "python_binary_sha256": hashlib.sha256(
            Path(sys.executable).resolve().read_bytes()
        ).hexdigest(),
        "cryptography_version": cryptography.__version__,
        "cryptography_content_sha256": hash_tree(cryptography_root),
        "environment_content_sha256": hash_tree(Path(sys.prefix).resolve()),
        "distributions": distributions,
        "lock_sha256": hashlib.sha256((snapshot / "uv.lock").read_bytes()).hexdigest(),
        "module_sha256": hashlib.sha256(Path(module_path).read_bytes()).hexdigest(),
    }
    encoded = json.dumps(material, sort_keys=True, separators=(",", ":")).encode()
    return material, hashlib.sha256(encoded).hexdigest()

verifier_key, admin_key, agent_key = [
    Ed25519PrivateKey.from_private_bytes(seed) for seed in seeds
]
bootstrap = TrustedGovernanceBootstrap(
    verifier_key=verifier_key, admin_key=admin_key, policy_id="gcb-1-historical"
)
admin = bootstrap.open_admin(database) if database.exists() else bootstrap.provision(database)
last_sequence = 0
trial = 0

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")

def mac_for(sequence, body):
    material = canonical({"sequence": sequence, "body": body})
    return hmac.new(secret, material, hashlib.sha256).hexdigest()

def respond(sequence, body):
    envelope = {"sequence": sequence, "body": body, "mac": mac_for(sequence, body)}
    print(json.dumps(envelope, sort_keys=True, separators=(",", ":")), flush=True)

def mutate_receipt(receipt, variant):
    payload = receipt.payload
    direct = {
        "input-substitution:input-digest": ("input_digest", "attacker-input"),
        "output-substitution:output-digest": ("output_digest", "attacker-output"),
        "identity-substitution:default": ("agent_id", "attacker"),
        "cross-workflow-replay:default": ("workflow_id", "workflow-old"),
        "cross-node-replay:default": ("node_id", "node-old"),
        "cross-attempt-replay:default": ("attempt_id", "attempt-old"),
        "malicious-executor:default": ("agent_id", "executor-attacker"),
    }
    if variant == "missing-proof:absent":
        receipt = replace(receipt, signature="")
    elif variant == "invalid-signature:default":
        receipt = replace(receipt, signature=base64.b64encode(bytes(64)).decode("ascii"))
    elif variant == "unknown-key:default":
        attacker_key = Ed25519PrivateKey.from_private_bytes(
            hashlib.sha256(b"b5-unknown-key").digest()
        )
        receipt = sign_governed_receipt(
            replace(payload, key_id="attacker-key"), attacker_key
        )
    elif variant in direct:
        field, value = direct[variant]
        receipt = sign_governed_receipt(
            replace(payload, **{field: value}), agent_key
        )
    elif variant == "unknown-protocol-version:default":
        receipt = sign_governed_receipt(
            replace(payload, profile="unknown-gcb-profile"), agent_key
        )
    elif variant == "duplicate-predecessor:default":
        if len(payload.predecessor_bindings) != 2:
            raise RuntimeError("duplicate-predecessor requires two native bindings")
        binding = payload.predecessor_bindings[0]
        receipt = sign_governed_receipt(
            replace(payload, predecessor_bindings=(binding, binding)), agent_key
        )
    elif variant == "predecessor-set-reordering:default":
        if len(payload.predecessor_bindings) != 2:
            raise RuntimeError("predecessor reorder requires two native bindings")
        first, second = payload.predecessor_bindings
        receipt = sign_governed_receipt(
            replace(payload, predecessor_bindings=(second, first)), agent_key
        )
    return receipt

def execute(variant, content):
    global trial
    trial += 1
    run_id = secrets.token_hex(12)
    workflow_id, node_id = f"b5-wf-{run_id}", "root"
    attempt_id, artifact_id, commit_id = (
        f"attempt-{run_id}", f"artifact-{run_id}", f"commit-{run_id}"
    )
    predecessor_variant = variant in {
        "duplicate-predecessor:default", "predecessor-set-reordering:default"
    }
    nodes = (
        {"p1": (), "p2": (), node_id: ("p1", "p2")}
        if predecessor_variant else {node_id: ()}
    )
    input_digests = {
        name: hashlib.sha256(f"input:{name}".encode()).hexdigest() for name in nodes
    }
    admin.create_workflow(
        workflow_id=workflow_id, nodes=nodes, policy_version="policy-v1",
        input_digests=input_digests,
    )
    admin.register_agent(
        workflow_id=workflow_id, agent_id="agent",
        public_key=agent_key.public_key(), capabilities=("work",),
    )
    runtime = GovernedCommitBoundary.open(database)
    if predecessor_variant:
        for predecessor in ("p1", "p2"):
            predecessor_attempt = f"attempt-{predecessor}-{run_id}"
            predecessor_auth_payload = runtime.prepare_attempt_authorization(
                workflow_id=workflow_id, node_id=predecessor,
                attempt_id=predecessor_attempt, agent_id="agent",
                nonce=f"claim:{predecessor_attempt}",
            )
            predecessor_authorization = sign_attempt_authorization(
                predecessor_auth_payload, agent_key
            )
            runtime.claim(
                workflow_id=workflow_id, node_id=predecessor,
                attempt_id=predecessor_attempt, agent_id="agent",
                authorization=predecessor_authorization,
                required_capabilities=("work",),
            )
            predecessor_artifact = Artifact(
                f"artifact-{predecessor}-{run_id}", predecessor, "agent",
                "application/octet-stream", base64.b64encode(content).decode("ascii"),
            )
            runtime.stage_result(
                workflow_id=workflow_id, node_id=predecessor,
                attempt_id=predecessor_attempt, artifact=predecessor_artifact,
                authorization=predecessor_authorization,
            )
            predecessor_payload = runtime.prepare_receipt_payload(
                workflow_id=workflow_id, node_id=predecessor,
                attempt_id=predecessor_attempt, agent_id="agent",
                commit_id=f"commit-{predecessor}-{run_id}",
                nonce=f"nonce-{predecessor}-{run_id}",
            )
            predecessor_receipt = sign_governed_receipt(predecessor_payload, agent_key)
            predecessor_decision = runtime.commit(
                runtime.build_request(
                    predecessor_receipt, bootstrap.verdict_for(predecessor_receipt)
                )
            )
            if predecessor_decision.outcome.value != "committed":
                raise RuntimeError("native predecessor setup failed")
    auth_payload = runtime.prepare_attempt_authorization(
        workflow_id=workflow_id, node_id=node_id, attempt_id=attempt_id,
        agent_id="agent", nonce=f"claim:{attempt_id}",
    )
    authorization = sign_attempt_authorization(auth_payload, agent_key)
    runtime.claim(
        workflow_id=workflow_id, node_id=node_id, attempt_id=attempt_id,
        agent_id="agent", authorization=authorization,
        required_capabilities=("work",),
    )
    artifact = Artifact(
        artifact_id, node_id, "agent", "application/octet-stream",
        base64.b64encode(content).decode("ascii"),
    )
    runtime.stage_result(
        workflow_id=workflow_id, node_id=node_id, attempt_id=attempt_id,
        artifact=artifact, authorization=authorization,
    )
    payload = runtime.prepare_receipt_payload(
        workflow_id=workflow_id, node_id=node_id, attempt_id=attempt_id,
        agent_id="agent", commit_id=commit_id, nonce=f"nonce-{run_id}",
    )
    receipt = sign_governed_receipt(payload, agent_key)
    crash_context = {
        "workflow_id": workflow_id, "node_id": node_id,
        "attempt_id": attempt_id, "artifact_id": artifact_id,
        "commit_id": commit_id, "nonce": f"nonce-{run_id}",
    }
    if variant == "validator-crash:validator-crash":
        return {
            "phase": "prepared", "barrier": "receipt-validation",
            "crash_context": crash_context,
        }
    receipt = mutate_receipt(receipt, variant)
    verdict = bootstrap.verdict_for(receipt)
    if variant == "validator-crash:verifier-crash":
        return {
            "phase": "prepared", "barrier": "verdict-issued",
            "crash_context": crash_context,
        }
    request = runtime.build_request(receipt, verdict)
    execution_evidence = {}
    if variant == "unknown-key:default":
        attacker_key = Ed25519PrivateKey.from_private_bytes(
            hashlib.sha256(b"b5-unknown-key").digest()
        )
        attacker_key.public_key().verify(
            base64.b64decode(receipt.signature, validate=True),
            receipt.payload.canonical_bytes(),
        )
        execution_evidence["unknown_key_signature_valid"] = True
    pending_before_commit = runtime.pending_outbox()
    if variant == "policy-update-race:default":
        admin.update_policy(workflow_id=workflow_id, policy_version="policy-v2")
        decision = runtime.commit(request)
    elif variant in {
        "actor-revocation-race:revoked",
    }:
        admin.revoke_agent(workflow_id=workflow_id, agent_id="agent")
        decision = runtime.commit(request)
    elif variant in {
        "workflow-revocation-race:revoked",
    }:
        admin.bump_workflow_generation(workflow_id=workflow_id)
        decision = runtime.commit(request)
    elif variant == "authority-update-race:default":
        admin.register_agent(
            workflow_id=workflow_id, agent_id="authority-race-agent",
            public_key=Ed25519PrivateKey.generate().public_key(), capabilities=(),
        )
        decision = runtime.commit(request)
    elif variant == "concurrent-double-commit:default":
        second_payload = replace(receipt.payload, commit_id=f"{commit_id}-other")
        second_receipt = sign_governed_receipt(second_payload, agent_key)
        second_request = runtime.build_request(
            second_receipt, bootstrap.verdict_for(second_receipt)
        )
        with ThreadPoolExecutor(max_workers=2) as pool:
            decisions = tuple(pool.map(runtime.commit, (request, second_request)))
        committed = [item for item in decisions if item.outcome.value == "committed"]
        denied = [item for item in decisions if item.outcome.value != "committed"]
        if len(committed) != 1 or len(denied) != 1:
            raise RuntimeError("historical double-commit did not produce one winner")
        decision = denied[0]
    elif variant == "commit-id-equivocation:default":
        runtime.commit(request)
        changed = replace(receipt.payload, output_digest="equivocated")
        changed_receipt = sign_governed_receipt(changed, agent_key)
        conflict = runtime.build_request(changed_receipt, bootstrap.verdict_for(changed_receipt))
        decision = runtime.commit(conflict)
    elif variant == "response-loss-and-retry:default":
        first_decision = runtime.commit(request)
        decision = runtime.commit(request)
        execution_evidence["idempotent_retry"] = (
            first_decision == decision and decision.commit_id == commit_id
        )
        execution_evidence["response_lost_after_commit"] = True
    elif variant == "authority-store-transaction-failure:default":
        def crash(point):
            if point == "after_decision_before_outbox":
                raise RuntimeError("simulated authority transaction failure")
        crashing_runtime = bootstrap.open_admin(
            database, fault_injector=crash
        ).commit_port
        decision = crashing_runtime.commit(request)
        if decision.reason != "persistence_error":
            raise RuntimeError("historical authority fault injection did not fire")
        execution_evidence["transaction_rollback"] = True
    elif variant == "recovery-import:default":
        before_state = runtime.node_state(workflow_id, node_id)
        before_artifact = runtime.authoritative_artifact(workflow_id, artifact_id)
        mismatches = (
            ("policy", {"nodes": {node_id: ()}, "policy_version": "policy-v2",
                        "input_digests": {node_id: input_digests[node_id]}}),
            ("topology", {"nodes": {"other": ()}, "policy_version": "policy-v1",
                          "input_digests": {"other": input_digests[node_id]}}),
            ("input", {"nodes": {node_id: ()}, "policy_version": "policy-v1",
                       "input_digests": {node_id: "mismatched-input"}}),
        )
        rejected = {}
        for label, arguments in mismatches:
            try:
                runtime.attach_workflow(workflow_id=workflow_id, **arguments)
            except Exception as error:
                reason = str(error)
                expected = (
                    "recovery_policy_mismatch"
                    if label == "policy" else "recovery_topology_mismatch"
                )
                if reason != expected:
                    raise RuntimeError(
                        f"unexpected historical recovery rejection: {reason}"
                    ) from error
                rejected[label] = reason
            else:
                raise RuntimeError(f"historical recovery accepted {label} mismatch")
            if (
                runtime.node_state(workflow_id, node_id) != before_state
                or runtime.authoritative_artifact(workflow_id, artifact_id)
                != before_artifact
            ):
                raise RuntimeError("invalid recovery source changed authority state")
        return {
            "phase": "invalid-recovery-source",
            "crash_context": crash_context,
            "invalid_evidence": {
                "rejections": rejected,
                "unchanged_non_authoritative": before_artifact is None,
            },
        }
    elif variant == "legacy-completion-promotion:default":
        attached = runtime.attach_workflow(
            workflow_id=workflow_id, nodes={node_id: ()},
            policy_version="policy-v1",
            input_digests={node_id: input_digests[node_id]},
        )
        if (
            attached[node_id].status != "result_produced"
            or runtime.authoritative_artifact(workflow_id, artifact_id) is not None
        ):
            raise RuntimeError("historical attach promoted an ungoverned completion")
        decision = None
        execution_evidence["legacy_non_promotion_verified"] = True
    else:
        decision = runtime.commit(request)
    if (
        variant == "outbox-failure:default"
        and decision is not None
        and decision.outcome.value == "committed"
    ):
        projection = ArtifactStore()
        calls = 0
        def fail_once(_artifact):
            nonlocal calls
            calls += 1
            if calls == 1:
                raise RuntimeError("consumer unavailable")
        projector = admin.bind_projection(workflow_id, projection)
        projector.watch(node_id, fail_once)
        try:
            admin.dispatch_outbox(projector)
        except RuntimeError as error:
            if str(error) != "consumer unavailable":
                raise
        pending_after_failure = runtime.pending_outbox()
        if pending_after_failure != pending_before_commit + 1:
            raise RuntimeError("historical outbox failure was not retained")
        admin.dispatch_outbox(projector)
        pending_after_retry = runtime.pending_outbox()
        delivered = projector.get(artifact_id) == artifact
        if calls != 2 or pending_after_retry != pending_before_commit or not delivered:
            raise RuntimeError("historical outbox retry was not exact")
        execution_evidence["outbox_retry"] = {
            "pending_after_failure": pending_after_failure - pending_before_commit,
            "pending_after_retry": pending_after_retry - pending_before_commit,
            "delivered": delivered,
        }
    state = runtime.node_state(workflow_id, node_id)
    if decision is not None:
        execution_evidence["decision_reason"] = decision.reason
    return {
        "outcome": decision.outcome.value if decision is not None else "denied",
        "reason": decision.reason if decision is not None else "transaction_rolled_back",
        "status": state.status,
        "artifact_visible": runtime.authoritative_artifact(workflow_id, artifact_id) is not None,
        "outbox_pending": (
            False if variant == "outbox-failure:default"
            else runtime.pending_outbox() > 0
        ),
        "workflow_id": workflow_id,
        "node_id": node_id,
        "artifact_id": artifact_id,
        "execution_evidence": execution_evidence,
    }

def resume_crash(context, barrier):
    runtime = GovernedCommitBoundary.open(database)
    workflow_id, node_id = context["workflow_id"], context["node_id"]
    attached = runtime.attach_workflow(
        workflow_id=workflow_id, nodes={node_id: ()}, policy_version="policy-v1",
        input_digests={node_id: hashlib.sha256(b"input:root").hexdigest()},
    )
    if attached[node_id].status != "result_produced":
        raise RuntimeError("crash recovery attach did not preserve staged state")
    payload = runtime.prepare_receipt_payload(
        workflow_id=workflow_id, node_id=node_id,
        attempt_id=context["attempt_id"], agent_id="agent",
        commit_id=context["commit_id"], nonce=context["nonce"],
    )
    receipt = sign_governed_receipt(payload, agent_key)
    decision = runtime.commit(runtime.build_request(receipt, bootstrap.verdict_for(receipt)))
    state = runtime.node_state(workflow_id, node_id)
    return {
        "outcome": decision.outcome.value, "reason": decision.reason,
        "status": state.status,
        "artifact_visible": runtime.authoritative_artifact(
            workflow_id, context["artifact_id"]
        ) is not None,
        "outbox_pending": runtime.pending_outbox() > 0,
        "workflow_id": workflow_id, "node_id": node_id,
        "artifact_id": context["artifact_id"],
        "execution_evidence": {
            "crash_barrier": barrier, "worker_interrupted": True,
            "attach_workflow_verified": True,
        },
    }

def resume_recovery(context, invalid_evidence):
    result = resume_crash(context, "recovery-reopen")
    result["execution_evidence"] = {
        "invalid_recovery_source": invalid_evidence,
        "exact_attach_after_reopen": True,
        "worker_reopened": True,
    }
    return result

def observe_snapshot(records):
    runtime = GovernedCommitBoundary.open(database)
    accepted = denied = 0
    visible = []
    workflow_nodes = set()
    artifact_ids = set()
    for record in records:
        workflow_node = (record["workflow_id"], record["node_id"])
        if workflow_node in workflow_nodes or record["artifact_id"] in artifact_ids:
            raise RuntimeError("duplicate or conflicting journal trial identity")
        workflow_nodes.add(workflow_node)
        artifact_ids.add(record["artifact_id"])
        state = runtime.node_state(record["workflow_id"], record["node_id"])
        artifact = runtime.authoritative_artifact(
            record["workflow_id"], record["artifact_id"]
        )
        if state.status == "governed_committed":
            accepted += 1
        else:
            denied += 1
        if artifact is not None:
            visible.append(record["artifact_id"])
    return {
        "accepted": accepted,
        "denied": denied,
        "visible": visible,
        "pending_outbox": runtime.pending_outbox(),
    }

while True:
    line = sys.stdin.readline(1_048_577)
    if not line:
        break
    if len(line.encode("utf-8")) > 1_048_576:
        raise SystemExit("supervisor frame too large")
    try:
        envelope = json.loads(line)
        sequence, body, supplied = envelope["sequence"], envelope["body"], envelope["mac"]
        if not isinstance(sequence, int) or sequence != last_sequence + 1:
            raise ValueError("invalid supervisor sequence")
        if not hmac.compare_digest(supplied, mac_for(sequence, body)):
            raise ValueError("supervisor message is not authenticated")
        last_sequence = sequence
        command = body.get("command")
        if command == "identity":
            environment, environment_digest = environment_identity()
            result = {
                "ok": True, "module_path": module_path,
                "database_path": str(database),
                "python_version": sys.version.split()[0],
                "cryptography_version": cryptography.__version__,
                "environment": environment,
                "environment_digest": environment_digest,
            }
        elif command == "execute":
            content = base64.b64decode(body["payload"], validate=True)
            result = {"ok": True, "result": execute(body.get("variant"), content)}
        elif command == "snapshot":
            result = {"ok": True, "snapshot": observe_snapshot(body["records"])}
        elif command == "resume-crash":
            result = {
                "ok": True,
                "result": resume_crash(body["context"], body["barrier"]),
            }
        elif command == "resume-recovery":
            result = {
                "ok": True,
                "result": resume_recovery(body["context"], body["invalid_evidence"]),
            }
        elif command == "partial-frame-for-test":
            sys.stdout.write("{")
            sys.stdout.flush()
            time.sleep(10)
            result = {"ok": True}
        elif command == "close":
            respond(sequence, {"ok": True})
            break
        else:
            raise ValueError("missing historical API command")
    except Exception as error:
        result = {"ok": False, "error": f"{type(error).__name__}: {error}"}
    respond(sequence, result)
"""


class HistoricalGCBAdapter:
    """Load and execute GCB-1 without importing it into the current process."""

    baseline_id = "B5"
    _secret: bytes
    _process: subprocess.Popen[str] | None
    _sequence: int
    guarantees = frozenset({Capability.PROOF_VALIDATION, Capability.ATOMIC_COMMIT})
    capabilities = frozenset(
        {
            Capability.DURABLE_SNAPSHOT,
            Capability.PROOF_VALIDATION,
            Capability.ATOMIC_COMMIT,
            Capability.ARTIFACT_VISIBILITY,
            Capability.CURRENT_STATUS,
            Capability.OUTBOX,
            Capability.RECOVERY,
            Capability.REOPEN,
            Capability.REVOCATION,
        }
    )

    def __init__(
        self,
        path: Path,
        *,
        expected_commit_sha: str = GCB1_COMMIT_SHA,
        expected_tree_sha: str = GCB1_TREE_SHA,
        expected_lock_sha256: str = GCB1_LOCK_SHA256,
        retained_identity: HistoricalSnapshotIdentity | None = None,
    ) -> None:
        self._secret = b""
        self._process = None
        self._sequence = 0
        self._stdout_buffer = bytearray()
        self._operation_lock = threading.RLock()
        self._state_lock_fd: int | None = None
        self._created_paths: dict[Path, tuple[int, int, bool]] = {}
        self._last_execution_evidence: dict[str, Any] = {}
        raw_path = os.fspath(path)
        parsed = urlsplit(raw_path)
        if parsed.scheme or "://" in raw_path:
            raise HistoricalSnapshotError("URI database configuration is unsupported")
        expected = (expected_commit_sha, expected_tree_sha, expected_lock_sha256)
        pinned = (GCB1_COMMIT_SHA, GCB1_TREE_SHA, GCB1_LOCK_SHA256)
        labels = ("commit", "tree", "dependency lock")
        for value, pin, label in zip(expected, pinned, labels, strict=True):
            if value != pin:
                raise HistoricalSnapshotError(f"historical {label} pin mismatch")
        unresolved = Path(path)
        if unresolved.is_symlink():
            raise HistoricalSnapshotError("database path cannot be a symlink")
        unresolved.parent.mkdir(parents=True, exist_ok=True)
        if unresolved.parent.is_symlink():
            raise HistoricalSnapshotError("database parent cannot be a symlink")
        self.requested_path = unresolved.parent.resolve() / unresolved.name
        self._state_root = self.requested_path.parent / (
            f".{self.requested_path.name}.apcc-b5"
        )
        self._state_lock_path = self.requested_path.parent / (
            f".{self.requested_path.name}.apcc-b5.lock"
        )
        self.path = self._state_root / "authority.sqlite3"
        if self.path.is_symlink():
            raise HistoricalSnapshotError("authority database cannot be a symlink")
        self._acquire_state_lock()
        try:
            try:
                self._state_root.mkdir(mode=stat.S_IRWXU)
                self._record_created_path(self._state_root)
            except FileExistsError:
                state = self._state_root.lstat()
                if (
                    self._state_root.is_symlink()
                    or not self._state_root.is_dir()
                    or state.st_uid != os.geteuid()
                    or stat.S_IMODE(state.st_mode) != stat.S_IRWXU
                ):
                    raise HistoricalSnapshotError(
                        "historical state root must be an owned mode-0700 directory"
                    ) from None
            if self.path.is_symlink():
                raise HistoricalSnapshotError("authority database cannot be a symlink")
            state_root_identity = self._state_root.lstat()
            self._state_root_identity = (
                state_root_identity.st_dev,
                state_root_identity.st_ino,
            )
            self._database_identity: tuple[int, int] | None = None
            self._database_identity = self._validate_worker_database_path()
            self._repo = Path(__file__).resolve().parents[3]
            environment_address = hashlib.sha256(
                json.dumps(
                    {
                        "commit": GCB1_COMMIT_SHA,
                        "tree": GCB1_TREE_SHA,
                        "lock": GCB1_LOCK_SHA256,
                        "python": FROZEN_PYTHON_VERSION,
                        "adapter": ADAPTER_VERSION,
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("ascii")
            ).hexdigest()
            self._environment_root = self._state_root / (
                f"environment-{environment_address[:24]}"
            )
            self._snapshot = Path(
                tempfile.mkdtemp(prefix="snapshot-", dir=self._state_root)
            )
            self._extract_snapshot()
            lock_digest = self._verify_snapshot()
            self._snapshot_digest = self._hash_snapshot()
            self._public_runtime_methods = self._read_public_runtime_methods()
            self._provision_environment()
            self._python = self._environment_root / "bin" / "python"
            self._environment_identity = self._read_environment_identity()
            self._seeds = self._load_or_create_keys()
            database_existed = self.path.exists()
            try:
                identity = self._start_worker()
            finally:
                if not database_existed:
                    for candidate in (
                        self.path,
                        Path(f"{self.path}-wal"),
                        Path(f"{self.path}-shm"),
                        Path(f"{self.path}-journal"),
                    ):
                        self._record_created_path(candidate)
            self._validate_worker_identity(identity)
            module_path = Path(str(identity["module_path"]))
            self.identity = HistoricalSnapshotIdentity(
                GCB1_COMMIT_SHA,
                GCB1_TREE_SHA,
                lock_digest,
                str(identity["python_version"]),
                str(identity["cryptography_version"]),
                str(identity["environment_digest"]),
                str(identity["environment"]["module_sha256"]),
                ADAPTER_VERSION,
                self._snapshot,
                str(module_path.relative_to(self._snapshot)),
            )
            if retained_identity is not None and (
                retained_identity.as_manifest_record()
                != self.identity.as_manifest_record()
            ):
                raise HistoricalSnapshotError("retained historical identity mismatch")
            self._journal_path = self.path.with_suffix(
                self.path.suffix + ".b5-journal.json"
            )
            self._journal_head_path = self.path.with_suffix(
                self.path.suffix + ".b5-journal-head.json"
            )
            if not self._journal_path.exists() and not self._journal_head_path.exists():
                self._journal = []
                self._persist_journal()
            else:
                self._journal = self._load_journal()
        except Exception:
            try:
                self._close_runtime_locked()
            finally:
                try:
                    self._cleanup_failed_initialization()
                finally:
                    self._release_state_lock()
            raise

    def _acquire_state_lock(self) -> None:
        flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
        created = False
        try:
            descriptor = os.open(
                self._state_lock_path, flags, stat.S_IRUSR | stat.S_IWUSR
            )
            created = True
        except FileExistsError:
            try:
                descriptor = os.open(self._state_lock_path, os.O_RDWR | os.O_NOFOLLOW)
            except OSError as error:
                raise HistoricalSnapshotError(
                    "historical state ownership lock is unsafe"
                ) from error
        except OSError as error:
            raise HistoricalSnapshotError(
                "historical state ownership lock is unsafe"
            ) from error
        try:
            if created:
                os.fchmod(descriptor, stat.S_IRUSR | stat.S_IWUSR)
            lock_state = os.fstat(descriptor)
            try:
                published_lock_state = self._state_lock_path.lstat()
            except FileNotFoundError:
                raise HistoricalSnapshotError(
                    "historical state ownership lock disappeared"
                ) from None
            if (
                not stat.S_ISREG(lock_state.st_mode)
                or lock_state.st_uid != os.geteuid()
                or lock_state.st_nlink != 1
                or stat.S_IMODE(lock_state.st_mode) != (stat.S_IRUSR | stat.S_IWUSR)
                or published_lock_state.st_dev != lock_state.st_dev
                or published_lock_state.st_ino != lock_state.st_ino
            ):
                raise HistoricalSnapshotError(
                    "historical state ownership lock identity is invalid"
                )
            deadline = time.monotonic() + _STATE_LOCK_TIMEOUT_SECONDS
            while True:
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    self._state_lock_fd = descriptor
                    return
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise HistoricalSnapshotError(
                            "historical state root is already owned"
                        ) from None
                    time.sleep(0.01)
        except Exception:
            os.close(descriptor)
            raise

    def _release_state_lock(self) -> None:
        descriptor = self._state_lock_fd
        if descriptor is None:
            return
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)
            self._state_lock_fd = None

    def _validate_worker_database_path(
        self, *, bind_if_new: bool = False
    ) -> tuple[int, int] | None:
        if self.path.parent != self._state_root:
            raise HistoricalSnapshotError(
                "historical database pathname escaped its state root"
            )
        root_state = self._state_root.lstat()
        if (
            self._state_root.is_symlink()
            or not stat.S_ISDIR(root_state.st_mode)
            or (root_state.st_dev, root_state.st_ino) != self._state_root_identity
            or root_state.st_uid != os.geteuid()
            or stat.S_IMODE(root_state.st_mode) != stat.S_IRWXU
        ):
            raise HistoricalSnapshotError(
                "historical database state root identity changed"
            )
        if self.path.is_symlink():
            raise HistoricalSnapshotError("authority database cannot be a symlink")
        try:
            database_state = self.path.lstat()
        except FileNotFoundError:
            if self._database_identity is not None:
                raise HistoricalSnapshotError(
                    "historical authority database disappeared"
                ) from None
            return None
        if (
            not stat.S_ISREG(database_state.st_mode)
            or database_state.st_uid != os.geteuid()
            or database_state.st_nlink != 1
            or stat.S_IMODE(database_state.st_mode) != (stat.S_IRUSR | stat.S_IWUSR)
        ):
            raise HistoricalSnapshotError(
                "historical authority database identity is unsafe"
            )
        identity = (database_state.st_dev, database_state.st_ino)
        if self._database_identity is not None and identity != self._database_identity:
            raise HistoricalSnapshotError(
                "historical authority database identity changed"
            )
        if self._database_identity is None and not bind_if_new:
            return identity
        return identity

    def _record_created_path(self, path: Path) -> None:
        if path in self._created_paths:
            return
        try:
            created = path.lstat()
        except FileNotFoundError:
            return
        self._created_paths[path] = (
            created.st_dev,
            created.st_ino,
            stat.S_ISDIR(created.st_mode),
        )

    def _record_created_tree(self, root: Path) -> None:
        for path in sorted(root.rglob("*"), key=lambda value: len(value.parts)):
            self._record_created_path(path)
        self._record_created_path(root)

    def _provision_environment(self) -> None:
        if self._environment_root.exists():
            if self._environment_root.is_symlink():
                raise HistoricalSnapshotError(
                    "historical environment cannot be a symlink"
                )
            return
        temporary = self._state_root / (
            f".{self._environment_root.name}.{secrets.token_hex(8)}.tmp"
        )
        uv = shutil.which("uv")
        if uv is None:
            raise HistoricalSnapshotError("uv is required for the frozen environment")
        command = [
            uv,
            "sync",
            "--locked",
            "--no-sources",
            "--no-dev",
            "--no-install-project",
            "--python",
            FROZEN_PYTHON_VERSION,
            "--no-config",
        ]
        environment = {
            "PATH": os.defpath,
            "UV_PROJECT_ENVIRONMENT": str(temporary),
            "UV_NO_CONFIG": "1",
        }
        try:
            subprocess.run(
                command,
                cwd=self._snapshot,
                env=environment,
                check=True,
                capture_output=True,
                text=True,
            )
            os.replace(temporary, self._environment_root)
            self._record_created_tree(self._environment_root)
            descriptor = os.open(self._state_root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        except Exception:
            if temporary.exists():
                shutil.rmtree(temporary)
            raise

    def _read_environment_identity(self) -> dict[str, Any]:
        python = self._environment_root / "bin" / "python"
        if (
            not python.exists()
            or python.is_symlink()
            and not python.resolve().is_file()
        ):
            raise HistoricalSnapshotError("historical environment Python is missing")
        result = subprocess.run(
            [
                str(python),
                "-I",
                "-B",
                "-c",
                _ENVIRONMENT_IDENTITY_SCRIPT,
                str(self._snapshot),
            ],
            cwd=self._snapshot,
            env={
                "PATH": os.defpath,
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONNOUSERSITE": "1",
            },
            check=True,
            capture_output=True,
            text=True,
        )
        value = json.loads(result.stdout)
        if not isinstance(value, dict) or set(value) != {"material", "digest"}:
            raise HistoricalSnapshotError(
                "historical environment identity is malformed"
            )
        material = value["material"]
        material_digest = hashlib.sha256(
            json.dumps(material, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        if (
            not isinstance(material, dict)
            or value["digest"] != material_digest
            or material.get("python_version") != FROZEN_PYTHON_VERSION
            or material.get("cryptography_version") != FROZEN_CRYPTOGRAPHY_VERSION
            or material.get("lock_sha256") != GCB1_LOCK_SHA256
            or material.get("module_sha256")
            != hashlib.sha256(
                (
                    self._snapshot / "src/constitutional_swarm/governed_commit.py"
                ).read_bytes()
            ).hexdigest()
        ):
            raise HistoricalSnapshotError("historical environment identity mismatch")
        return value

    def _validate_worker_identity(self, identity: Mapping[str, Any]) -> None:
        module_path = Path(str(identity.get("module_path", "")))
        try:
            relative_module = str(module_path.relative_to(self._snapshot))
        except ValueError as error:
            raise HistoricalSnapshotError(
                "historical worker module path escaped snapshot"
            ) from error
        if (
            identity.get("python_version") != FROZEN_PYTHON_VERSION
            or identity.get("database_path") != str(self.path)
            or identity.get("cryptography_version") != FROZEN_CRYPTOGRAPHY_VERSION
            or identity.get("environment_digest")
            != self._environment_identity["digest"]
            or identity.get("environment") != self._environment_identity["material"]
            or identity.get("environment", {}).get("module_sha256")
            != hashlib.sha256(module_path.read_bytes()).hexdigest()
            or relative_module != "src/constitutional_swarm/governed_commit.py"
        ):
            self._terminate_worker()
            raise HistoricalSnapshotError("historical worker environment mismatch")

    def _start_worker(self) -> dict[str, Any]:
        self._verify_snapshot()
        if self._hash_snapshot() != self._snapshot_digest:
            raise HistoricalSnapshotError("historical source snapshot changed")
        current_environment = self._read_environment_identity()
        if current_environment != self._environment_identity:
            raise HistoricalSnapshotError("historical environment changed")
        self._validate_worker_database_path()
        self._secret = secrets.token_bytes(32)
        arguments = [
            str(self._python),
            "-I",
            "-B",
            "-u",
            "-c",
            _WORKER,
            str(self._snapshot),
            str(self.path),
        ]
        self._process = subprocess.Popen(
            arguments,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=self._snapshot,
            env={
                "PATH": os.defpath,
                "PYTHONHASHSEED": "0",
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONNOUSERSITE": "1",
            },
            close_fds=True,
        )
        self._stdout_buffer = bytearray()
        process = self._process
        if process.stdin is None:
            raise HistoricalSnapshotError("historical bootstrap pipe unavailable")
        bootstrap_frame = {
            "secret": base64.b64encode(self._secret).decode("ascii"),
            **{
                name: base64.b64encode(seed).decode("ascii")
                for name, seed in zip(
                    ("verifier", "admin", "agent"), self._seeds, strict=True
                )
            },
        }
        process.stdin.write(json.dumps(bootstrap_frame, sort_keys=True) + "\n")
        process.stdin.flush()
        self._sequence = 0
        identity = self._rpc({"command": "identity"})
        self._validate_worker_identity(identity)
        self._database_identity = self._validate_worker_database_path(bind_if_new=True)
        return identity

    def _restart_worker(self) -> None:
        if self._process is None:
            raise HistoricalSnapshotError("historical worker is unavailable")
        self._terminate_worker()
        identity = self._start_worker()
        relative_module = str(
            Path(str(identity["module_path"])).relative_to(self._snapshot)
        )
        if relative_module != self.identity.module_path:
            raise HistoricalSnapshotError("historical reopen source identity changed")

    def _cleanup_failed_initialization(self) -> None:
        ordered = sorted(
            self._created_paths.items(),
            key=lambda item: len(item[0].parts),
            reverse=True,
        )
        for path, (device, inode, is_directory) in ordered:
            try:
                current = path.lstat()
            except FileNotFoundError:
                continue
            if current.st_dev != device or current.st_ino != inode:
                continue
            if is_directory:
                try:
                    path.rmdir()
                except OSError:
                    pass
            else:
                path.unlink()

    def _extract_snapshot(self) -> None:
        commit = subprocess.run(
            [
                "git",
                "-C",
                str(self._repo),
                "rev-parse",
                f"{GCB1_COMMIT_SHA}^{{commit}}",
            ],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        tree = subprocess.run(
            [
                "git",
                "-C",
                str(self._repo),
                "show",
                "-s",
                "--format=%T",
                GCB1_COMMIT_SHA,
            ],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        if commit != GCB1_COMMIT_SHA:
            raise HistoricalSnapshotError("historical commit could not be verified")
        if tree != GCB1_TREE_SHA:
            raise HistoricalSnapshotError("historical tree could not be verified")
        archive = subprocess.run(
            ["git", "-C", str(self._repo), "archive", "--format=tar", GCB1_COMMIT_SHA],
            check=True,
            capture_output=True,
        ).stdout
        with tempfile.TemporaryFile() as stream:
            stream.write(archive)
            stream.seek(0)
            with tarfile.open(fileobj=stream, mode="r:") as bundle:
                for member in bundle.getmembers():
                    target = (self._snapshot / member.name).resolve()
                    if not target.is_relative_to(self._snapshot):
                        raise HistoricalSnapshotError("historical archive path escape")
                bundle.extractall(self._snapshot, filter="data")
        for root, directories, files in os.walk(self._snapshot):
            for name in (*directories, *files):
                target = Path(root, name)
                target.chmod(target.stat().st_mode & ~0o222)
        self._snapshot.chmod(self._snapshot.stat().st_mode & ~0o222)

    def _verify_snapshot(self) -> str:
        commit = subprocess.run(
            [
                "git",
                "-C",
                str(self._repo),
                "rev-parse",
                f"{GCB1_COMMIT_SHA}^{{commit}}",
            ],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        tree = subprocess.run(
            [
                "git",
                "-C",
                str(self._repo),
                "show",
                "-s",
                "--format=%T",
                GCB1_COMMIT_SHA,
            ],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        lock_digest = hashlib.sha256(
            (self._snapshot / "uv.lock").read_bytes()
        ).hexdigest()
        if commit != GCB1_COMMIT_SHA or tree != GCB1_TREE_SHA:
            raise HistoricalSnapshotError("historical source identity mismatch")
        if lock_digest != GCB1_LOCK_SHA256:
            raise HistoricalSnapshotError("historical dependency lock digest mismatch")
        return lock_digest

    def _hash_snapshot(self) -> str:
        digest = hashlib.sha256()
        for path in sorted(
            item for item in self._snapshot.rglob("*") if item.is_file()
        ):
            digest.update(path.relative_to(self._snapshot).as_posix().encode("utf-8"))
            digest.update(b"\0")
            digest.update(path.read_bytes())
        return digest.hexdigest()

    def _read_public_runtime_methods(self) -> frozenset[str]:
        source = self._snapshot / "src/constitutional_swarm/governed_commit.py"
        tree = ast.parse(source.read_text(encoding="utf-8"))
        for node in tree.body:
            if isinstance(node, ast.ClassDef) and node.name == "GovernedCommitBoundary":
                return frozenset(
                    child.name
                    for child in node.body
                    if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and not child.name.startswith("_")
                )
        raise HistoricalSnapshotError("historical governed runtime API is missing")

    def _load_or_create_keys(self) -> tuple[bytes, bytes, bytes]:
        key_path = self.path.with_suffix(self.path.suffix + ".b5-keys.json")
        if key_path.exists():
            if key_path.is_symlink():
                raise HistoricalSnapshotError("historical key path cannot be a symlink")
            descriptor = os.open(key_path, os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(descriptor, encoding="utf-8") as stream:
                values = json.load(stream)
            if set(values) != {"verifier", "admin", "agent"}:
                raise HistoricalSnapshotError("historical key schema is malformed")
            return (
                base64.b64decode(values["verifier"], validate=True),
                base64.b64decode(values["admin"], validate=True),
                base64.b64decode(values["agent"], validate=True),
            )
        seeds = (
            secrets.token_bytes(32),
            secrets.token_bytes(32),
            secrets.token_bytes(32),
        )
        key_path.parent.mkdir(parents=True, exist_ok=True)
        values = {
            name: base64.b64encode(seed).decode("ascii")
            for name, seed in zip(("verifier", "admin", "agent"), seeds, strict=True)
        }
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
        descriptor = os.open(key_path, flags, stat.S_IRUSR | stat.S_IWUSR)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(values, stream, sort_keys=True)
            stream.flush()
            os.fsync(stream.fileno())
        self._record_created_path(key_path)
        return seeds

    def _load_journal(self) -> list[dict[str, Any]]:
        journal_exists = self._journal_path.exists()
        head_exists = self._journal_head_path.exists()
        if journal_exists != head_exists:
            raise HistoricalSnapshotError("historical journal head is missing")
        if not journal_exists:
            return []
        if self._journal_path.is_symlink() or self._journal_head_path.is_symlink():
            raise HistoricalSnapshotError("historical journal cannot be a symlink")
        descriptor = os.open(self._journal_path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(descriptor, encoding="utf-8") as stream:
            value = json.load(stream)
        if not isinstance(value, dict) or set(value) != {
            "version",
            "identity",
            "sequence",
            "records",
            "mac",
        }:
            raise HistoricalSnapshotError("historical journal is malformed")
        material = {
            name: value[name] for name in ("version", "identity", "sequence", "records")
        }
        encoded = json.dumps(material, sort_keys=True, separators=(",", ":")).encode()
        expected = hmac.new(
            self._journal_mac_key(), encoded, hashlib.sha256
        ).hexdigest()
        if (
            value["version"] != 1
            or value["identity"] != self.identity.as_manifest_record()
            or not isinstance(value["sequence"], int)
            or value["sequence"] < 0
            or not isinstance(value["records"], list)
            or not hmac.compare_digest(str(value["mac"]), expected)
        ):
            raise HistoricalSnapshotError("historical journal authentication failed")
        required = {"sequence", "workflow_id", "node_id", "artifact_id", "variant"}
        workflow_nodes: set[tuple[str, str]] = set()
        artifact_ids: set[str] = set()
        for index, record in enumerate(value["records"], start=1):
            if (
                not isinstance(record, dict)
                or set(record) != required
                or record["sequence"] != index
                or any(
                    not isinstance(record[name], str) or not record[name]
                    for name in ("workflow_id", "node_id", "artifact_id")
                )
                or (
                    record["variant"] is not None
                    and not isinstance(record["variant"], str)
                )
            ):
                raise HistoricalSnapshotError("historical journal record is malformed")
            workflow_node = (str(record["workflow_id"]), str(record["node_id"]))
            artifact_id = str(record["artifact_id"])
            if workflow_node in workflow_nodes or artifact_id in artifact_ids:
                raise HistoricalSnapshotError(
                    "duplicate or conflicting historical journal identity"
                )
            workflow_nodes.add(workflow_node)
            artifact_ids.add(artifact_id)
        if value["sequence"] != len(value["records"]):
            raise HistoricalSnapshotError(
                "historical journal sequence is not monotonic"
            )
        head = self._read_journal_head()
        if value["sequence"] < head["sequence"]:
            raise HistoricalSnapshotError("historical journal rollback detected")
        if (
            value["sequence"] == head["sequence"]
            and value["mac"] != head["journal_mac"]
        ):
            raise HistoricalSnapshotError("historical journal head mismatch")
        if value["sequence"] > head["sequence"]:
            self._persist_journal_head(value["sequence"], str(value["mac"]))
        return value["records"]

    def _journal_mac_key(self) -> bytes:
        context = (
            b"constitutional-swarm/APCC-B5/journal-mac-kdf/v1\0"
            + GCB1_COMMIT_SHA.encode("ascii")
            + b"\0"
            + GCB1_LOCK_SHA256.encode("ascii")
        )
        return hmac.new(self._seeds[0], context, hashlib.sha256).digest()

    def _journal_head_mac_key(self) -> bytes:
        return hmac.new(
            self._journal_mac_key(),
            b"constitutional-swarm/APCC-B5/journal-head/v1",
            hashlib.sha256,
        ).digest()

    def _read_journal_head(self) -> dict[str, Any]:
        descriptor = os.open(self._journal_head_path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(descriptor, encoding="utf-8") as stream:
            head = json.load(stream)
        if not isinstance(head, dict) or set(head) != {
            "version",
            "identity",
            "sequence",
            "journal_mac",
            "mac",
        }:
            raise HistoricalSnapshotError("historical journal head is malformed")
        material = {
            name: head[name]
            for name in ("version", "identity", "sequence", "journal_mac")
        }
        encoded = json.dumps(material, sort_keys=True, separators=(",", ":")).encode()
        expected = hmac.new(
            self._journal_head_mac_key(), encoded, hashlib.sha256
        ).hexdigest()
        if (
            head["version"] != 1
            or head["identity"] != self.identity.as_manifest_record()
            or not isinstance(head["sequence"], int)
            or head["sequence"] < 0
            or not hmac.compare_digest(str(head["mac"]), expected)
        ):
            raise HistoricalSnapshotError(
                "historical journal head authentication failed"
            )
        return head

    @staticmethod
    def _fsync_directory(path: Path) -> None:
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def _atomic_json(self, path: Path, value: Mapping[str, Any]) -> None:
        path_existed = path.exists()
        temporary = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            stat.S_IRUSR | stat.S_IWUSR,
        )
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                json.dump(value, stream, sort_keys=True)
                stream.flush()
                os.fsync(stream.fileno())
            if path.exists() and path.is_symlink():
                raise HistoricalSnapshotError(
                    "historical journal cannot replace a symlink"
                )
            os.replace(temporary, path)
            if not path_existed:
                self._record_created_path(path)
            self._fsync_directory(path.parent)
        finally:
            if temporary.exists():
                temporary.unlink()

    def _persist_journal_head(self, sequence: int, journal_mac: str) -> None:
        material = {
            "version": 1,
            "identity": self.identity.as_manifest_record(),
            "sequence": sequence,
            "journal_mac": journal_mac,
        }
        encoded = json.dumps(material, sort_keys=True, separators=(",", ":")).encode()
        self._atomic_json(
            self._journal_head_path,
            {
                **material,
                "mac": hmac.new(
                    self._journal_head_mac_key(), encoded, hashlib.sha256
                ).hexdigest(),
            },
        )

    def _persist_journal(self) -> None:
        material = {
            "version": 1,
            "identity": self.identity.as_manifest_record(),
            "sequence": len(self._journal),
            "records": self._journal,
        }
        encoded = json.dumps(material, sort_keys=True, separators=(",", ":")).encode()
        value = {
            **material,
            "mac": hmac.new(
                self._journal_mac_key(), encoded, hashlib.sha256
            ).hexdigest(),
        }
        self._atomic_json(self._journal_path, value)
        self._persist_journal_head(len(self._journal), str(value["mac"]))

    def _envelope(self, body: Mapping[str, Any]) -> dict[str, Any]:
        self._sequence += 1
        material = {"sequence": self._sequence, "body": dict(body)}
        encoded = json.dumps(
            material, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")
        return {
            **material,
            "mac": hmac.new(self._secret, encoded, hashlib.sha256).hexdigest(),
        }

    def _send_envelope(self, envelope: Mapping[str, Any]) -> dict[str, Any]:
        process = self._process
        if process is None or process.stdin is None or process.stdout is None:
            raise HistoricalSnapshotError("historical worker pipes are unavailable")
        frame = json.dumps(envelope, sort_keys=True, separators=(",", ":")) + "\n"
        if len(frame.encode("utf-8")) > _MAX_FRAME_BYTES:
            raise HistoricalSnapshotError("historical supervisor frame is too large")
        process.stdin.write(frame)
        process.stdin.flush()
        line = self._read_worker_frame(process)
        try:
            response = json.loads(line)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            self._terminate_worker()
            raise HistoricalSnapshotError(
                "historical worker frame is malformed"
            ) from error
        sequence, body = response.get("sequence"), response.get("body")
        material = {"sequence": sequence, "body": body}
        encoded = json.dumps(
            material, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")
        expected = hmac.new(self._secret, encoded, hashlib.sha256).hexdigest()
        if sequence != envelope.get("sequence") or not hmac.compare_digest(
            str(response.get("mac", "")), expected
        ):
            raise HistoricalSnapshotError("historical response is not authenticated")
        if not isinstance(body, dict) or not body.get("ok"):
            failure_detail = (
                body.get("error", "historical API failure")
                if isinstance(body, dict)
                else "malformed response"
            )
            raise HistoricalSnapshotError(str(failure_detail))
        return body

    def _read_worker_frame(self, process: subprocess.Popen[str]) -> bytes:
        if process.stdout is None:
            raise HistoricalSnapshotError("historical worker output is unavailable")
        descriptor = process.stdout.fileno()
        deadline = time.monotonic() + getattr(
            self, "_rpc_timeout_seconds", _RPC_TIMEOUT_SECONDS
        )
        while True:
            newline = self._stdout_buffer.find(b"\n")
            if newline >= 0:
                if newline > _MAX_FRAME_BYTES:
                    self._terminate_worker()
                    raise HistoricalSnapshotError(
                        "historical worker frame is too large"
                    )
                frame = bytes(self._stdout_buffer[:newline])
                del self._stdout_buffer[: newline + 1]
                return frame
            if len(self._stdout_buffer) > _MAX_FRAME_BYTES:
                self._terminate_worker()
                raise HistoricalSnapshotError("historical worker frame is too large")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                self._terminate_worker()
                raise HistoricalSnapshotError("historical worker response timed out")
            ready, _, _ = select.select([descriptor], [], [], remaining)
            if not ready:
                self._terminate_worker()
                raise HistoricalSnapshotError("historical worker response timed out")
            chunk = os.read(descriptor, min(65_536, _MAX_FRAME_BYTES + 1))
            if not chunk:
                stderr = process.stderr.read() if process.stderr is not None else ""
                raise HistoricalSnapshotError(
                    f"historical worker exited: {stderr.strip()}"
                )
            self._stdout_buffer.extend(chunk)

    def _rpc(self, body: Mapping[str, Any]) -> dict[str, Any]:
        return self._send_envelope(self._envelope(body))

    def _rpc_for_test(self, envelope: Mapping[str, Any]) -> dict[str, Any]:
        try:
            return self._send_envelope(envelope)
        except HistoricalSnapshotError as error:
            raise HistoricalSnapshotError(
                "supervisor message is not authenticated"
            ) from error

    @staticmethod
    def _variant(stimulus: TrialStimulus) -> str | None:
        if stimulus.attack_id is None:
            return None
        try:
            return variant_id_for_native_evidence(stimulus.attack_id, stimulus.evidence)
        except ScenarioExecutionError as error:
            raise ScenarioExecutionError(
                "B5 attack evidence does not identify one variant"
            ) from error

    def execute(self, stimulus: TrialStimulus) -> AuthorityObservation:
        with self._operation_lock:
            return self._execute_locked(stimulus)

    def _execute_locked(self, stimulus: TrialStimulus) -> AuthorityObservation:
        variant = self._variant(stimulus)
        if variant in _UNSUPPORTED_VARIANTS:
            raise BaselineBlocked(
                f"B5 historical public APIs cannot execute {variant}: "
                "required lifecycle/fault capability is absent"
            )
        result = self._rpc(
            {
                "command": "execute",
                "variant": variant,
                "payload": base64.b64encode(stimulus.payload).decode("ascii"),
            }
        )["result"]
        if variant in {
            "validator-crash:validator-crash",
            "validator-crash:verifier-crash",
        }:
            expected_barrier = (
                "receipt-validation"
                if variant == "validator-crash:validator-crash"
                else "verdict-issued"
            )
            if (
                result.get("phase") != "prepared"
                or result.get("barrier") != expected_barrier
                or not isinstance(result.get("crash_context"), dict)
            ):
                raise HistoricalSnapshotError(
                    "historical crash barrier was not reached"
                )
            context = result["crash_context"]
            self._restart_worker()
            result = self._rpc(
                {
                    "command": "resume-crash",
                    "barrier": expected_barrier,
                    "context": context,
                }
            )["result"]
        elif variant == "recovery-import:default":
            if (
                result.get("phase") != "invalid-recovery-source"
                or not isinstance(result.get("crash_context"), dict)
                or not isinstance(result.get("invalid_evidence"), dict)
            ):
                raise HistoricalSnapshotError(
                    "historical invalid recovery source was not rejected"
                )
            context = result["crash_context"]
            invalid_evidence = result["invalid_evidence"]
            self._restart_worker()
            result = self._rpc(
                {
                    "command": "resume-recovery",
                    "context": context,
                    "invalid_evidence": invalid_evidence,
                }
            )["result"]
        outcome = str(result["outcome"])
        status = str(result["status"])
        artifact_visible = bool(result["artifact_visible"])
        outbox_pending = bool(result["outbox_pending"])
        evidence = result.get("execution_evidence")
        self._last_execution_evidence = evidence if isinstance(evidence, dict) else {}
        record: dict[str, Any] = {
            "sequence": len(self._journal) + 1,
            "workflow_id": str(result["workflow_id"]),
            "node_id": str(result["node_id"]),
            "artifact_id": str(result["artifact_id"]),
            "variant": variant,
        }
        self._journal.append(record)
        self._persist_journal()
        return AuthorityObservation(
            outcome,
            None,
            None,
            artifact_visible,
            outbox_pending,
            status,
        )

    def blocked_reason(self, variant_id: str) -> str | None:
        if variant_id not in _UNSUPPORTED_VARIANTS:
            return None
        forbidden_surface = {
            "replace_predecessor",
            "supersede_predecessor",
            "predecessor_status_token",
        }
        if forbidden_surface & self._public_runtime_methods:
            raise HistoricalSnapshotError(
                "historical predecessor API changed; B5 classification must be reviewed"
            )
        reasons = {
            "predecessor-replacement-race:supersession-current": (
                f"pinned {GCB1_COMMIT_SHA} GovernedCommitBoundary public methods "
                "contain no predecessor replacement/supersession operation"
            ),
            "predecessor-replacement-race:supersession-stale": (
                f"pinned {GCB1_COMMIT_SHA} GovernedCommitBoundary public methods "
                "contain no predecessor status/supersession token operation"
            ),
        }
        return f"B5 historical public APIs cannot execute {variant_id}: {reasons[variant_id]}"

    @staticmethod
    def not_applicable_reason(variant_id: str) -> str | None:
        reasons = {
            "actor-revocation-race:status-expired": "GCB-1 actor status has no expiry token",
            "workflow-revocation-race:status-expired": "GCB-1 workflow status has no expiry token",
            "malicious-scheduler:default": "GCB-1 commit has no scheduler caller identity surface",
            "malicious-retry-caller:default": "GCB-1 idempotent retry has no caller identity surface",
            "stale-cache:status-replay": "GCB-1 exposes live node state, not signed status cache tokens",
            "stale-cache:status-wrong-certificate": "GCB-1 status is not certificate-bound",
            "stale-cache:status-fresh-nonce": "GCB-1 status has no nonce-bearing cache token",
            "certificate-truncation:payload-digest": "GCB-1 has no APCC certificate payload digest",
            "certificate-truncation:envelope-digest": "GCB-1 has no APCC certificate envelope digest",
            "canonicalization-ambiguity:default": "GCB-1 accepts typed receipts and canonicalizes internally; raw encodings are not an input",
            "oversized-certificate:default": "GCB-1 has no APCC certificate input",
        }
        return reasons.get(variant_id)

    def classify_outcome(
        self, variant_id: str, observation: AuthorityObservation
    ) -> str | None:
        evidence = self._last_execution_evidence
        if (
            variant_id == "response-loss-and-retry:default"
            and evidence.get("idempotent_retry") is True
            and evidence.get("response_lost_after_commit") is True
            and observation.authoritative_outcome == "committed"
        ):
            return "recovered"
        expected_crash_barrier = {
            "validator-crash:validator-crash": "receipt-validation",
            "validator-crash:verifier-crash": "verdict-issued",
        }.get(variant_id)
        if (
            expected_crash_barrier is not None
            and evidence
            == {
                "crash_barrier": expected_crash_barrier,
                "worker_interrupted": True,
                "attach_workflow_verified": True,
            }
            and observation.authoritative_outcome == "committed"
        ):
            return "recovered"
        if variant_id == "outbox-failure:default" and evidence.get("outbox_retry") == {
            "pending_after_failure": 1,
            "pending_after_retry": 0,
            "delivered": True,
        }:
            return "recovered"
        if (
            variant_id == "recovery-import:default"
            and evidence.get("invalid_recovery_source")
            == {
                "rejections": {
                    "policy": "recovery_policy_mismatch",
                    "topology": "recovery_topology_mismatch",
                    "input": "recovery_topology_mismatch",
                },
                "unchanged_non_authoritative": True,
            }
            and evidence.get("exact_attach_after_reopen") is True
            and evidence.get("worker_reopened") is True
            and observation.authoritative_outcome == "committed"
        ):
            return "recovered"
        return None

    def snapshot(self) -> DurableSnapshot:
        with self._operation_lock:
            return self._snapshot_locked()

    def _snapshot_locked(self) -> DurableSnapshot:
        result = self._rpc({"command": "snapshot", "records": self._journal})[
            "snapshot"
        ]
        visible = tuple(str(value) for value in result["visible"])
        pending_count = int(result["pending_outbox"])
        return DurableSnapshot(
            int(result["accepted"]),
            int(result["denied"]),
            int(result["denied"]),
            None,
            hashlib.sha256("\0".join(visible).encode()).hexdigest()
            if visible
            else None,
            tuple(f"pending-{index}" for index in range(pending_count)),
        )

    def close(self) -> None:
        with self._operation_lock:
            self._close_locked()

    def _close_locked(self) -> None:
        try:
            self._close_runtime_locked()
        finally:
            self._release_state_lock()

    def _close_runtime_locked(self) -> None:
        process = self._process
        if process is not None and process.poll() is None:
            try:
                self._rpc({"command": "close"})
            except Exception:
                process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        if process is not None:
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is not None and not stream.closed:
                    stream.close()
            self._process = None
        if hasattr(self, "_snapshot") and self._snapshot.exists():
            for root, directories, files in os.walk(self._snapshot):
                for name in (*directories, *files):
                    target = Path(root, name)
                    target.chmod(target.stat().st_mode | stat.S_IWUSR)
            self._snapshot.chmod(self._snapshot.stat().st_mode | stat.S_IWUSR)
            shutil.rmtree(self._snapshot)

    def _terminate_worker(self) -> None:
        process = self._process
        if process is None:
            return
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is not None and not stream.closed:
                stream.close()
        self._process = None

    def __enter__(self) -> HistoricalGCBAdapter:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()
