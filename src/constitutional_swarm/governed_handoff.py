"""Governed coding-agent handoff CLI for constitutional_swarm.

This module is intentionally lightweight: it turns a local task file into
governed tool, file-write, test, and handoff events, then writes tamper-evident
JSONL audit evidence plus a bundle under the caller repository's ``.acgs`` dir.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shlex
import subprocess
from dataclasses import dataclass
from fnmatch import fnmatch
from pathlib import Path
from time import time
from typing import Any, Protocol

ALLOW = "allow"
DENY = "deny"
REVIEW = "human_review_required"
ZERO_HASH = "0" * 64


@dataclass(frozen=True)
class Action:
    kind: str
    value: str
    content: str | None = None


@dataclass
class AuditLogger:
    path: Path
    task_id: str
    previous_hash: str = ZERO_HASH
    event_index: int = 0

    def __post_init__(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def emit(
        self, role: str, event_type: str, payload: dict[str, Any]
    ) -> dict[str, Any]:
        base = {
            "event_index": self.event_index,
            "timestamp": time(),
            "task_id": self.task_id,
            "role": role,
            "event_type": event_type,
            "payload": payload,
            "prev_hash": self.previous_hash,
        }
        event_hash = sha256_text(canonical_json(base))
        event = {**base, "event_hash": event_hash}
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(canonical_json(event) + "\n")
        self.previous_hash = event_hash
        self.event_index += 1
        return event


class ExecutorAdapter(Protocol):
    name: str

    def propose_actions(self, task: "TaskSpec") -> list[Action]:
        """Return requested actions; policy gates decide what can run."""


@dataclass(frozen=True)
class PolicyDecision:
    gate: str
    subject: str
    outcome: str
    reason: str

    def as_dict(self) -> dict[str, str]:
        return {
            "gate": self.gate,
            "subject": self.subject,
            "outcome": self.outcome,
            "reason": self.reason,
        }


class PolicyEngine:
    def __init__(
        self, constitution: dict[str, Any], swarm: dict[str, Any], repo_root: Path
    ) -> None:
        self.constitution = constitution
        self.swarm = swarm
        self.repo_root = repo_root.resolve()
        policy = (
            constitution.get("policy", {}) if isinstance(constitution, dict) else {}
        )
        self.protected_paths = list(
            policy.get("protected_paths", [".acgs/**", ".env", "secrets/**"])
        )
        self.secret_patterns = [
            re.compile(str(pattern), re.IGNORECASE)
            for pattern in policy.get(
                "secret_command_patterns",
                [
                    r"\b(cat|less|more|head|tail|sed|awk|grep|rg)\b.*"
                    r"(\.env|secret|credential|id_rsa|token)",
                    r"\b(printenv|env)\b",
                    r"\b(git\s+config\s+--get|gh\s+auth\s+token)\b",
                ],
            )
        ]

    def decide(self, gate: str, subject: str, **context: Any) -> PolicyDecision:
        if gate == "intake":
            return self._intake(subject, context)
        if gate == "tool_call":
            return self._tool_call(subject)
        if gate == "file_write":
            return self._file_write(subject)
        if gate == "state_transition":
            return self._state_transition(subject)
        if gate == "handoff":
            return self._handoff(subject, context)
        return PolicyDecision(gate, subject, DENY, "unknown policy gate; fail closed")

    def _intake(self, subject: str, context: dict[str, Any]) -> PolicyDecision:
        required_roles = {"executor", "observer", "proposer", "validator"}
        roles = set((self.swarm.get("roles") or {}).keys())
        if not context.get("task_exists"):
            return PolicyDecision("intake", subject, DENY, "task file does not exist")
        if not context.get("task_content"):
            return PolicyDecision("intake", subject, DENY, "task file is empty")
        if not required_roles.issubset(roles):
            missing = ", ".join(sorted(required_roles - roles))
            return PolicyDecision(
                "intake", subject, DENY, f"missing role assignments: {missing}"
            )
        return PolicyDecision("intake", subject, ALLOW, "task intake policy passed")

    def _tool_call(self, command: str) -> PolicyDecision:
        if not command:
            return PolicyDecision("tool_call", command, DENY, "empty tool command")
        if any(pattern.search(command) for pattern in self.secret_patterns):
            return PolicyDecision(
                "tool_call", command, DENY, "secret-reading command denied"
            )
        if re.search(r"[;&|`$<>]", command):
            return PolicyDecision(
                "tool_call", command, DENY, "shell metacharacters are not allowed"
            )
        return PolicyDecision("tool_call", command, ALLOW, "tool command allowed")

    def _file_write(self, raw_path: str) -> PolicyDecision:
        resolved = (self.repo_root / raw_path).resolve()
        if not resolved.is_relative_to(self.repo_root):
            return PolicyDecision(
                "file_write", raw_path, DENY, "path escapes repository root"
            )
        normalized = resolved.relative_to(self.repo_root).as_posix()
        if any(fnmatch(normalized, pattern) for pattern in self.protected_paths):
            return PolicyDecision(
                "file_write", normalized, REVIEW, "protected path requires human review"
            )
        return PolicyDecision("file_write", normalized, ALLOW, "file write allowed")

    def _state_transition(self, transition: str) -> PolicyDecision:
        allowed = {
            "executing->validating",
            "intake_pending->planned",
            "planned->executing",
            "validating->blocked",
            "validating->handoff_ready",
            "validating->human_review_required",
        }
        if transition not in allowed:
            return PolicyDecision(
                "state_transition", transition, DENY, "unknown transition; fail closed"
            )
        return PolicyDecision(
            "state_transition", transition, ALLOW, "state transition allowed"
        )

    def _handoff(self, subject: str, context: dict[str, Any]) -> PolicyDecision:
        tests_run = context.get("tests_run") or []
        if not tests_run:
            return PolicyDecision(
                "handoff", subject, DENY, "test proof is required before handoff"
            )
        if not any(test.get("passed") for test in tests_run):
            return PolicyDecision(
                "handoff", subject, DENY, "at least one passing test proof is required"
            )
        return PolicyDecision(
            "handoff", subject, ALLOW, "handoff gate passed with test proof"
        )


@dataclass(frozen=True)
class RunResult:
    task_id: str
    final_state: str
    audit_path: Path
    bundle_path: Path
    chain_hash: str


@dataclass(frozen=True)
class TaskSpec:
    task_id: str
    path: Path
    content: str
    metadata: dict[str, Any]


class MockAdapter:
    """Deterministic local adapter for CLI smoke runs and tests.

    Supported task directives:
    - ``ACGS_WRITE path :: content``
    - ``ACGS_TOOL command``
    - ``ACGS_TEST command``
    """

    name = "mock"

    def propose_actions(self, task: TaskSpec) -> list[Action]:
        actions: list[Action] = []
        for raw_line in task.content.splitlines():
            line = raw_line.strip()
            if line.startswith("ACGS_WRITE "):
                target, sep, content = line.removeprefix("ACGS_WRITE ").partition(
                    " :: "
                )
                if sep:
                    actions.append(
                        Action(kind="write", value=target.strip(), content=content)
                    )
            elif line.startswith("ACGS_TOOL "):
                actions.append(
                    Action(kind="tool", value=line.removeprefix("ACGS_TOOL ").strip())
                )
            elif line.startswith("ACGS_TEST "):
                actions.append(
                    Action(kind="test", value=line.removeprefix("ACGS_TEST ").strip())
                )
        return actions


class LocalShellAdapter(MockAdapter):
    """Alias for local shell-backed mock directives."""

    name = "local-shell"


class ExternalAgentAdapter:
    """Boundary for Codex/Claude-style agents invoked by a local command."""

    def __init__(self, *, name: str, command: str | None) -> None:
        self.name = name
        self._command = command

    def propose_actions(self, task: TaskSpec) -> list[Action]:
        if not self._command:
            raise RuntimeError(f"{self.name} adapter is not configured")
        argv = [*shlex.split(self._command), str(task.path)]
        completed = subprocess.run(  # noqa: S603 - local adapter command from .acgs config
            argv, check=False, capture_output=True, text=True, timeout=120
        )
        if completed.returncode != 0:
            raise RuntimeError(
                completed.stderr.strip() or f"{self.name} adapter failed"
            )
        synthetic = TaskSpec(task.task_id, task.path, completed.stdout, task.metadata)
        return MockAdapter().propose_actions(synthetic)


def build_adapter(name: str, config: dict[str, Any] | None = None) -> ExecutorAdapter:
    config = config or {}
    if name == "mock":
        return MockAdapter()
    if name in {"local-shell", "shell"}:
        return LocalShellAdapter()
    if name in {"claude", "codex"}:
        command = config.get("command")
        return ExternalAgentAdapter(
            name=name, command=str(command) if command else None
        )
    raise ValueError(f"unknown executor adapter: {name}")


def build_bundle(
    *,
    audit_path: Path,
    bundle_path: Path,
    constitution_hash: str,
    workflow_hash: str,
) -> dict[str, Any]:
    events = read_audit(audit_path)
    chain_hash = replay_hashes(events)
    bundle = {
        "schema_version": 1,
        "audit_path": str(audit_path),
        "constitution_hash": constitution_hash,
        "workflow_hash": workflow_hash,
        "task_metadata": _latest_payload(events, "task_metadata"),
        "role_assignments": _latest_payload(events, "role_assignments"),
        "policy_decisions": _payloads(events, "policy_decision"),
        "tool_events": _payloads(events, "tool_event"),
        "file_changes": _payloads(events, "file_change"),
        "tests_run": _payloads(events, "test_run"),
        "final_state": _latest_payload(events, "final_state"),
        "chain_hash": chain_hash,
        "audit_events": [
            {k: v for k, v in event.items() if k != "_line"} for event in events
        ],
    }
    bundle_path.parent.mkdir(parents=True, exist_ok=True)
    bundle_path.write_text(
        json.dumps(bundle, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return bundle


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="acgs-swarm")
    subparsers = parser.add_subparsers(dest="command", required=True)

    run = subparsers.add_parser("run", help="Run a task through governed handoff gates")
    run.add_argument("--task", required=True, type=Path)

    verify = subparsers.add_parser("verify", help="Verify an evidence bundle")
    verify.add_argument("--bundle", required=True, type=Path)

    pack = subparsers.add_parser(
        "pack", help="Rebuild a bundle from an audit JSONL task id"
    )
    pack.add_argument("--task", required=True)

    return parser


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def hash_file(path: Path) -> str | None:
    if not path.exists() or not path.is_file():
        return None
    return hashlib.sha256(path.read_bytes()).hexdigest()


def hash_yaml_payload(payload: dict[str, Any]) -> str:
    return sha256_text(canonical_json(payload))


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "run":
        result = run_task(args.task)
        print(
            json.dumps(
                {
                    "task_id": result.task_id,
                    "final_state": result.final_state,
                    "audit_path": str(result.audit_path),
                    "bundle_path": str(result.bundle_path),
                    "chain_hash": result.chain_hash,
                },
                sort_keys=True,
            )
        )
        return (
            0 if result.final_state in {"handoff_ready", "human_review_required"} else 1
        )
    if args.command == "verify":
        result = verify_bundle(args.bundle)
        print(json.dumps(result, sort_keys=True))
        return 0 if result["ok"] else 1
    if args.command == "pack":
        bundle = pack_task(args.task)
        print(
            json.dumps(
                {
                    "bundle_path": f".acgs/evidence/{args.task}.bundle.json",
                    "chain_hash": bundle["chain_hash"],
                },
                sort_keys=True,
            )
        )
        return 0
    raise AssertionError(args.command)


def pack_task(task_id: str, *, acgs_dir: Path = Path(".acgs")) -> dict[str, Any]:
    evidence_dir = acgs_dir / "evidence"
    audit_path = evidence_dir / f"{task_id}.audit.jsonl"
    if not audit_path.exists():
        raise FileNotFoundError(audit_path)
    run_metadata = _latest_payload(read_audit(audit_path), "run_metadata")
    return build_bundle(
        audit_path=audit_path,
        bundle_path=evidence_dir / f"{task_id}.bundle.json",
        constitution_hash=run_metadata["constitution_hash"],
        workflow_hash=run_metadata["workflow_hash"],
    )


def read_audit(path: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, start=1):
            if line.strip():
                event = json.loads(line)
                event["_line"] = line_no
                events.append(event)
    return events


def replay_hashes(events: list[dict[str, Any]]) -> str:
    previous = ZERO_HASH
    for index, event in enumerate(events):
        if event.get("event_index") != index:
            raise ValueError(
                f"audit event index mismatch at line {event.get('_line', index + 1)}"
            )
        if event.get("prev_hash") != previous:
            raise ValueError(f"audit prev_hash mismatch at event {index}")
        observed_hash = event.get("event_hash")
        payload = {k: v for k, v in event.items() if k not in {"event_hash", "_line"}}
        expected_hash = sha256_text(canonical_json(payload))
        if observed_hash != expected_hash:
            raise ValueError(f"audit event_hash mismatch at event {index}")
        previous = observed_hash
    return previous


def run_local_command(command: str, *, cwd: Path) -> dict[str, Any]:
    argv = shlex.split(command)
    completed = subprocess.run(  # noqa: S603 - command already passed the policy gate
        argv, cwd=cwd, check=False, capture_output=True, text=True, timeout=120
    )
    return {
        "command": command,
        "argv": argv,
        "returncode": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
        "passed": completed.returncode == 0,
    }


def run_task(task_path: Path, *, repo_root: Path = Path(".")) -> RunResult:
    repo_root = repo_root.resolve()
    acgs_dir = repo_root / ".acgs"
    constitution_path = acgs_dir / "constitution.yaml"
    swarm_path = acgs_dir / "swarm.yaml"
    constitution = _load_yaml(constitution_path)
    swarm = _load_yaml(swarm_path)
    task = _load_task(task_path.resolve())
    evidence_dir = acgs_dir / "evidence"
    audit_path = evidence_dir / f"{task.task_id}.audit.jsonl"
    bundle_path = evidence_dir / f"{task.task_id}.bundle.json"
    if audit_path.exists():
        audit_path.unlink()

    constitution_hash = hash_yaml_payload(constitution)
    workflow_hash = hash_yaml_payload(swarm)
    logger = AuditLogger(audit_path, task.task_id)
    policy = PolicyEngine(constitution, swarm, repo_root)

    logger.emit(
        "observer",
        "run_metadata",
        {
            "constitution_path": str(constitution_path),
            "constitution_hash": constitution_hash,
            "workflow_path": str(swarm_path),
            "workflow_hash": workflow_hash,
        },
    )
    logger.emit("observer", "task_metadata", task.metadata)
    logger.emit("observer", "role_assignments", swarm.get("roles", {}))

    intake = policy.decide(
        "intake",
        str(task.path),
        task_exists=task.path.exists(),
        task_content=task.content.strip(),
    )
    _record_decision(logger, intake)
    if intake.outcome != ALLOW:
        return _finish(logger, bundle_path, constitution_hash, workflow_hash, "blocked")

    _transition(policy, logger, "intake_pending->planned")
    logger.emit(
        "proposer",
        "plan",
        {
            "summary": "Run task through proposer, executor, validator, observer governance gates.",
            "adapter": _executor_adapter_name(swarm),
            "actions": [
                "intake",
                "tool_call",
                "file_write",
                "state_transition",
                "handoff",
            ],
        },
    )

    _transition(policy, logger, "planned->executing")
    file_changes: list[dict[str, Any]] = []
    tests_run: list[dict[str, Any]] = []
    blocked = False
    human_review_required = False
    for action in _load_actions(swarm, task):
        if action.kind == "tool":
            blocked = _handle_tool_action(policy, logger, action, repo_root) or blocked
        elif action.kind == "test":
            blocked = (
                _handle_test_action(policy, logger, action, repo_root, tests_run)
                or blocked
            )
        elif action.kind == "write":
            result = _handle_write_action(
                policy, logger, action, repo_root, file_changes
            )
            blocked = result["blocked"] or blocked
            human_review_required = (
                result["human_review_required"] or human_review_required
            )

    _transition(policy, logger, "executing->validating")
    handoff = policy.decide("handoff", "human-review", tests_run=tests_run)
    _record_decision(logger, handoff)
    logger.emit(
        "validator",
        "validation",
        {
            "policy_compliant": not blocked and handoff.outcome == ALLOW,
            "human_review_required": human_review_required,
            "file_changes": file_changes,
            "tests_run": tests_run,
        },
    )

    if blocked or handoff.outcome == DENY:
        final_state = "blocked"
    elif human_review_required:
        final_state = "human_review_required"
    else:
        final_state = "handoff_ready"
    _transition(policy, logger, f"validating->{final_state}")
    return _finish(logger, bundle_path, constitution_hash, workflow_hash, final_state)


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def verify_bundle(bundle_path: Path) -> dict[str, Any]:
    bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    audit_path = Path(bundle["audit_path"])
    events = (
        read_audit(audit_path)
        if audit_path.exists()
        else bundle.get("audit_events", [])
    )
    try:
        chain_hash = replay_hashes(events)
    except ValueError as exc:
        return {
            "ok": False,
            "chain_hash": None,
            "expected_chain_hash": bundle.get("chain_hash"),
            "event_count": len(events),
            "error": str(exc),
        }
    ok = chain_hash == bundle.get("chain_hash")
    return {
        "ok": ok,
        "chain_hash": chain_hash,
        "expected_chain_hash": bundle.get("chain_hash"),
        "event_count": len(events),
    }


def _executor_adapter_name(swarm: dict[str, Any]) -> str:
    executor = (swarm.get("roles") or {}).get("executor") or {}
    return str(executor.get("adapter", "mock"))


def _finish(
    logger: AuditLogger,
    bundle_path: Path,
    constitution_hash: str,
    workflow_hash: str,
    final_state: str,
) -> RunResult:
    logger.emit("observer", "final_state", {"state": final_state})
    bundle = build_bundle(
        audit_path=logger.path,
        bundle_path=bundle_path,
        constitution_hash=constitution_hash,
        workflow_hash=workflow_hash,
    )
    return RunResult(
        task_id=logger.task_id,
        final_state=final_state,
        audit_path=logger.path,
        bundle_path=bundle_path,
        chain_hash=bundle["chain_hash"],
    )


def _handle_test_action(
    policy: PolicyEngine,
    logger: AuditLogger,
    action: Action,
    repo_root: Path,
    tests_run: list[dict[str, Any]],
) -> bool:
    decision = policy.decide("tool_call", action.value)
    _record_decision(logger, decision)
    if decision.outcome != ALLOW:
        return True
    event = run_local_command(action.value, cwd=repo_root)
    tests_run.append(event)
    logger.emit("validator", "test_run", event)
    return not event["passed"]


def _handle_tool_action(
    policy: PolicyEngine, logger: AuditLogger, action: Action, repo_root: Path
) -> bool:
    decision = policy.decide("tool_call", action.value)
    _record_decision(logger, decision)
    if decision.outcome != ALLOW:
        return True
    event = run_local_command(action.value, cwd=repo_root)
    logger.emit("executor", "tool_event", event)
    return event["returncode"] != 0


def _handle_write_action(
    policy: PolicyEngine,
    logger: AuditLogger,
    action: Action,
    repo_root: Path,
    file_changes: list[dict[str, Any]],
) -> dict[str, bool]:
    decision = policy.decide("file_write", action.value)
    _record_decision(logger, decision)
    if decision.outcome == REVIEW:
        return {"blocked": False, "human_review_required": True}
    if decision.outcome != ALLOW:
        return {"blocked": True, "human_review_required": False}
    change = _write_file(repo_root, action)
    file_changes.append(change)
    logger.emit("executor", "file_change", change)
    return {"blocked": False, "human_review_required": False}


def _latest_payload(events: list[dict[str, Any]], event_type: str) -> dict[str, Any]:
    for event in reversed(events):
        if event.get("event_type") == event_type:
            payload = event.get("payload")
            return payload if isinstance(payload, dict) else {"value": payload}
    return {}


def _load_actions(swarm: dict[str, Any], task: TaskSpec) -> list[Action]:
    adapters = swarm.get("adapters") if isinstance(swarm.get("adapters"), dict) else {}
    adapter_name = _executor_adapter_name(swarm)
    adapter_config = (
        adapters.get(adapter_name)
        if isinstance(adapters.get(adapter_name), dict)
        else {}
    )
    return build_adapter(adapter_name, adapter_config).propose_actions(task)


def _load_task(path: Path) -> TaskSpec:
    content = path.read_text(encoding="utf-8") if path.exists() else ""
    metadata = {
        "task_id": _task_id(path, content),
        "task_path": str(path),
        "task_hash": sha256_text(content),
    }
    return TaskSpec(
        task_id=metadata["task_id"], path=path, content=content, metadata=metadata
    )


def _load_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(path)
    text = path.read_text(encoding="utf-8")
    try:
        import yaml  # type: ignore[import-untyped]
    except ImportError:
        payload = _parse_simple_yaml(text)
    else:
        payload = yaml.safe_load(text)
    if not isinstance(payload, dict):
        raise ValueError(f"{path} must contain a YAML mapping")
    return payload


def _parse_inline_mapping(value: str) -> dict[str, Any]:
    inner = value.strip()[1:-1].strip()
    if not inner:
        return {}
    result: dict[str, Any] = {}
    for part in inner.split(","):
        key, sep, raw_value = part.partition(":")
        if not sep:
            raise ValueError(f"unsupported inline YAML mapping: {value}")
        result[key.strip()] = _parse_scalar(raw_value.strip())
    return result


def _parse_scalar(value: str) -> Any:
    value = value.strip()
    if value.startswith("{") and value.endswith("}"):
        return _parse_inline_mapping(value)
    if (value.startswith('"') and value.endswith('"')) or (
        value.startswith("'") and value.endswith("'")
    ):
        return value[1:-1]
    if value in {"true", "false"}:
        return value == "true"
    if re.fullmatch(r"-?\d+", value):
        return int(value)
    return value


def _parse_simple_yaml(text: str) -> dict[str, Any]:
    lines = [
        line.rstrip()
        for line in text.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    root: dict[str, Any] = {}
    stack: list[tuple[int, dict[str, Any] | list[Any]]] = [(-1, root)]
    pending: tuple[int, dict[str, Any], str] | None = None
    for line in lines:
        indent = len(line) - len(line.lstrip(" "))
        stripped = line.strip()
        while stack and indent <= stack[-1][0]:
            stack.pop()
        if pending and indent > pending[0]:
            parent = pending[1]
            key = pending[2]
            container: dict[str, Any] | list[Any] = (
                [] if stripped.startswith("- ") else {}
            )
            parent[key] = container
            stack.append((indent - 1, container))
            pending = None
        container = stack[-1][1]
        if stripped.startswith("- "):
            if not isinstance(container, list):
                raise ValueError("unsupported YAML list placement")
            container.append(_parse_scalar(stripped[2:].strip()))
            continue
        key, sep, value = stripped.partition(":")
        if not sep or not isinstance(container, dict):
            raise ValueError(f"unsupported YAML line: {line}")
        if value.strip():
            container[key.strip()] = _parse_scalar(value.strip())
        else:
            pending = (indent, container, key.strip())
    return root


def _payloads(events: list[dict[str, Any]], event_type: str) -> list[dict[str, Any]]:
    return [
        event["payload"] for event in events if event.get("event_type") == event_type
    ]


def _record_decision(logger: AuditLogger, decision: PolicyDecision) -> None:
    logger.emit("validator", "policy_decision", decision.as_dict())


def _task_id(path: Path, content: str) -> str:
    match = re.search(r"(?m)^task_id:\s*([A-Za-z0-9_.-]+)\s*$", content)
    if match:
        return match.group(1)
    safe_stem = re.sub(r"[^A-Za-z0-9_.-]+", "-", path.stem).strip("-") or "task"
    return f"{safe_stem}-{sha256_text(content)[:10]}"


def _transition(policy: PolicyEngine, logger: AuditLogger, transition: str) -> None:
    decision = policy.decide("state_transition", transition)
    _record_decision(logger, decision)
    if decision.outcome != ALLOW:
        raise RuntimeError(f"state transition denied: {transition}")
    logger.emit("observer", "state_transition", {"transition": transition})


def _write_file(repo_root: Path, action: Action) -> dict[str, Any]:
    repo_root = repo_root.resolve()
    target = (repo_root / action.value).resolve()
    if not target.is_relative_to(repo_root):
        raise ValueError("file write target escapes repository root")
    before_hash = hash_file(target)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(action.content or "", encoding="utf-8")
    return {
        "path": target.relative_to(repo_root).as_posix(),
        "before_hash": before_hash,
        "after_hash": hash_file(target),
        "action": "write",
    }


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
