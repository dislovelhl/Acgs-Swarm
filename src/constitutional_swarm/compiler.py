"""DAG Compiler — converts structured goal specifications into TaskDAGs.

Goals are expressed as GoalSpecs with titled steps and title-based dependencies.
The compiler resolves titles to deterministic node IDs, validates the dependency
graph (no cycles, no missing deps), and produces a TaskDAG ready for SwarmExecutor.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from constitutional_swarm.swarm import TaskDAG, TaskNode


@dataclass(frozen=True, slots=True)
class GoalStep(Mapping[str, Any]):
    """Structured goal step with backward-compatible mapping access."""

    title: str
    domain: str = ""
    depends_on: tuple[str, ...] = ()
    description: str = ""
    required_capabilities: tuple[str, ...] = ()
    priority: int = 0
    max_budget_tokens: int = 0
    extra: dict[str, Any] = field(default_factory=dict, repr=False)

    @classmethod
    def from_input(cls, step: GoalStep | Mapping[str, Any]) -> GoalStep:
        """Normalize a mapping-like step payload into a GoalStep."""
        if isinstance(step, cls):
            return step
        if not isinstance(step, Mapping):
            raise TypeError(f"Goal step must be a mapping, got {type(step).__name__}")

        known_keys = {
            "title",
            "domain",
            "depends_on",
            "description",
            "required_capabilities",
            "priority",
            "max_budget_tokens",
        }
        return cls(
            title=str(step.get("title", "")),
            domain=str(step.get("domain", "")),
            depends_on=_coerce_str_tuple(step.get("depends_on", ())),
            description=str(step.get("description", "")),
            required_capabilities=_coerce_str_tuple(step.get("required_capabilities", ())),
            priority=int(step.get("priority", 0)),
            max_budget_tokens=int(step.get("max_budget_tokens", 0)),
            extra={key: value for key, value in step.items() if key not in known_keys},
        )

    def __getitem__(self, key: str) -> Any:
        if key == "title":
            return self.title
        if key == "domain":
            return self.domain
        if key == "depends_on":
            return self.depends_on
        if key == "description":
            return self.description
        if key == "required_capabilities":
            return self.required_capabilities
        if key == "priority":
            return self.priority
        if key == "max_budget_tokens":
            return self.max_budget_tokens
        return self.extra[key]

    def __iter__(self) -> Iterator[str]:
        yield "title"
        if self.domain:
            yield "domain"
        yield "depends_on"
        if self.description:
            yield "description"
        if self.required_capabilities:
            yield "required_capabilities"
        if self.priority:
            yield "priority"
        if self.max_budget_tokens:
            yield "max_budget_tokens"
        yield from self.extra

    def __len__(self) -> int:
        return sum(1 for _ in self)


def _coerce_str_tuple(values: object) -> tuple[str, ...]:
    if values is None:
        return ()
    if isinstance(values, str):
        return (values,)
    if not isinstance(values, Iterable):
        raise TypeError(f"Expected an iterable of strings, got {type(values).__name__}")
    return tuple(str(value) for value in values)


@dataclass(frozen=True, slots=True)
class GoalSpec:
    """Structured specification of a goal to compile into a TaskDAG."""

    goal: str
    domains: tuple[str, ...] | list[str]
    steps: tuple[GoalStep | Mapping[str, Any], ...] | list[GoalStep | Mapping[str, Any]]

    def __post_init__(self) -> None:
        object.__setattr__(self, "domains", tuple(self.domains))
        object.__setattr__(
            self,
            "steps",
            tuple(GoalStep.from_input(step) for step in self.steps),
        )


def _deterministic_node_id(title: str) -> str:
    """Generate a deterministic node ID from a title hash."""
    return hashlib.sha256(title.encode("utf-8")).hexdigest()[:16]


def _detect_cycle(
    adjacency: dict[str, list[str]],
    all_nodes: set[str],
) -> list[str] | None:
    """Detect a cycle in the dependency graph using DFS.

    Returns the cycle path if found, None otherwise.
    """
    WHITE, GRAY, BLACK = 0, 1, 2
    color: dict[str, int] = {node: WHITE for node in all_nodes}
    parent: dict[str, str | None] = {node: None for node in all_nodes}

    def _dfs(node: str) -> list[str] | None:
        color[node] = GRAY
        for neighbor in adjacency.get(node, []):
            if color[neighbor] == GRAY:
                # Reconstruct cycle
                cycle = [neighbor, node]
                current = node
                while parent[current] is not None and parent[current] != neighbor:
                    current = parent[current]  # type: ignore[assignment]
                    cycle.append(current)
                cycle.reverse()
                return cycle
            if color[neighbor] == WHITE:
                parent[neighbor] = node
                result = _dfs(neighbor)
                if result is not None:
                    return result
        color[node] = BLACK
        return None

    for node in all_nodes:
        if color[node] == WHITE:
            result = _dfs(node)
            if result is not None:
                return result
    return None


class DAGCompiler:
    """Compiles GoalSpec descriptions into executable TaskDAGs.

    Usage:
        compiler = DAGCompiler()
        dag = compiler.compile(spec)
        dag = compiler.compile_from_yaml("goal.yaml")
    """

    def compile(self, spec: GoalSpec) -> TaskDAG:
        """Compile a GoalSpec into a TaskDAG.

        Validates:
        - All domains are non-empty strings
        - All dependency titles reference existing steps
        - No cycles in the dependency graph
        - No duplicate step titles

        Raises:
            ValueError: On validation failure (cycles, missing deps, etc.)
        """
        steps = spec.steps
        domains = spec.domains

        # Validate domains
        for domain in domains:
            if not domain or not domain.strip():
                raise ValueError("Domain names must be non-empty strings")

        # Validate no duplicate titles
        titles = [step.title for step in steps]
        seen_titles: set[str] = set()
        for title in titles:
            if title in seen_titles:
                raise ValueError(f"Duplicate step title: {title!r}")
            seen_titles.add(title)

        # Build title -> node_id mapping
        title_to_id: dict[str, str] = {
            step.title: _deterministic_node_id(step.title) for step in steps
        }
        if len(set(title_to_id.values())) != len(title_to_id):
            raise ValueError("Deterministic node ID collision detected; revise step titles")

        # Validate all dependency titles exist
        for step in steps:
            for dep_title in step.depends_on:
                if dep_title not in title_to_id:
                    raise ValueError(
                        f"Step {step.title!r} depends on {dep_title!r}, which does not exist"
                    )

        # Validate step domains are in the declared domains list
        for step in steps:
            step_domain = step.domain
            if step_domain and domains and step_domain not in domains:
                raise ValueError(
                    f"Step {step.title!r} has domain {step_domain!r}, "
                    f"which is not in the declared domains: {domains}"
                )

        # Build adjacency list for cycle detection (node -> dependencies)
        adjacency: dict[str, list[str]] = {}
        all_node_ids: set[str] = set()
        for step in steps:
            node_id = title_to_id[step.title]
            all_node_ids.add(node_id)
            dep_ids = [title_to_id[dt] for dt in step.depends_on]
            adjacency[node_id] = dep_ids

        # Detect cycles
        cycle = _detect_cycle(adjacency, all_node_ids)
        if cycle is not None:
            # Map IDs back to titles for a useful error message
            id_to_title = {v: k for k, v in title_to_id.items()}
            cycle_titles = [id_to_title.get(nid, nid) for nid in cycle]
            raise ValueError(f"Cycle detected in dependency graph: {cycle_titles}")

        # Build TaskDAG
        dag = TaskDAG(goal=spec.goal)
        for step in steps:
            node_id = title_to_id[step.title]
            dep_ids = tuple(title_to_id[dt] for dt in step.depends_on)
            node = TaskNode(
                node_id=node_id,
                title=step.title,
                description=step.description,
                domain=step.domain,
                required_capabilities=step.required_capabilities,
                depends_on=dep_ids,
                priority=step.priority,
                max_budget_tokens=step.max_budget_tokens,
            )
            dag = dag.add_node(node)

        return dag

    def compile_from_yaml(self, path: str | Path) -> TaskDAG:
        """Load a GoalSpec from a YAML file and compile it.

        Expected YAML structure:
            goal: "..."
            domains: [...]
            steps:
              - title: "..."
                domain: "..."
                depends_on: [...]

        Raises:
            FileNotFoundError: If the YAML file does not exist.
            ValueError: On invalid spec or compilation failure.
        """
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"YAML file not found: {path}")

        with open(path) as f:
            data = yaml.safe_load(f)

        if not isinstance(data, dict):
            raise ValueError(f"YAML file must contain a mapping, got {type(data).__name__}")

        spec = GoalSpec(
            goal=data.get("goal", ""),
            domains=data.get("domains", []),
            steps=data.get("steps", []),
        )
        return self.compile(spec)
