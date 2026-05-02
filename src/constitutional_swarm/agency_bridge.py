"""Agency Bridge — wraps ACGS-agency-agents Markdown definitions in constitutional governance.

Parses each agent's YAML frontmatter (name, description, domain, emoji), instantiates
an AgentDNA from the shared ACGS constitution, and registers a Capability in the
CapabilityRegistry.  No extra dependencies beyond what constitutional_swarm already carries.

Typical usage::

    from constitutional_swarm.agency_bridge import AgencyAgentRegistry

    registry = AgencyAgentRegistry.from_path("packages/agency-agents/")
    matches  = registry.find("machine learning")       # list[GovernedAgencyAgent]
    agent    = registry.get("ai-engineer")             # GovernedAgencyAgent | None
    result   = agent.dna.validate("deploy model")      # DNAValidationResult
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import yaml  # PyYAML — available transitively via acgs-lite
except ImportError:
    yaml = None  # type: ignore[assignment]

log = logging.getLogger(__name__)

from acgs_lite import Constitution, MACIRole, Rule
from constitutional_swarm.capability import Capability, CapabilityRegistry
from constitutional_swarm.dna import AgentDNA

_FRONTMATTER_RE = re.compile(r"^---\s*\n(.*?)\n---\s*\n", re.DOTALL)
_SLUG_RE = re.compile(r"[^a-z0-9]+")


def _slugify(name: str) -> str:
    return _SLUG_RE.sub("-", name.lower()).strip("-")


def _parse_frontmatter(text: str) -> tuple[dict[str, Any], str]:
    """Return (frontmatter_dict, body_text) for a Markdown file.

    body_text is everything after the closing ``---`` delimiter.
    """
    m = _FRONTMATTER_RE.match(text)
    if not m:
        return {}, text
    raw = m.group(1)
    body = text[m.end() :]
    if yaml is not None:
        try:
            return yaml.safe_load(raw) or {}, body
        except yaml.YAMLError:
            log.debug("PyYAML failed to parse frontmatter; falling back to naive parser")
    # Fallback: naive key: value parser (no nested structures needed)
    result: dict[str, Any] = {}
    for line in raw.splitlines():
        if ":" in line:
            k, _, v = line.partition(":")
            result[k.strip()] = v.strip()
    return result, body


def _default_constitution() -> Constitution:
    """Load the swarm package's bundled example constitution."""
    yaml_path = Path(__file__).parent.parent.parent / "examples" / "constitution.yaml"
    if yaml_path.exists():
        return Constitution.from_yaml(str(yaml_path))
    return Constitution.from_rules(
        [
            Rule(id="safety", text="Do not take actions that cause irreversible harm."),
            Rule(id="transparency", text="Decisions must be explainable and auditable."),
            Rule(id="proportionality", text="Interventions must be proportional to severity."),
        ]
    )


@dataclass(frozen=True, slots=True)
class AgencyAgentDef:
    """Parsed metadata from an agency agent Markdown file."""

    name: str
    description: str
    domain: str
    body: str = ""
    emoji: str = ""
    vibe: str = ""
    color: str = ""
    source_path: Path = field(default_factory=Path)


@dataclass
class GovernedAgencyAgent:
    """An agency agent definition wrapped in constitutional governance.

    Attributes:
        definition:  Parsed frontmatter from the agent's Markdown file.
        dna:         Constitutional co-processor (AgentDNA) — call
                     ``dna.validate(action)`` or use ``@dna.govern``.
        capability:  Declared capability registered in the CapabilityRegistry.
    """

    definition: AgencyAgentDef
    dna: AgentDNA
    capability: Capability

    @property
    def agent_id(self) -> str:
        return self.dna.agent_id


def _make_dna(defn: AgencyAgentDef, constitution: Constitution, agent_id: str) -> AgentDNA:
    return AgentDNA(
        constitution=constitution,
        agent_id=agent_id,
        maci_role=MACIRole.EXECUTOR,
        strict=True,
        validate_output=True,
    )


def _make_capability(defn: AgencyAgentDef) -> Capability:
    # Extract keyword tags from description (longest alpha words, capped at 8)
    tags = tuple(
        sorted(
            {w for w in defn.description.lower().split() if len(w) > 4 and w.isalpha()},
            key=len,
            reverse=True,
        )[:8]
    )
    return Capability(
        name=defn.name,
        domain=defn.domain,
        description=defn.description,
        tags=tags,
    )


def load_agency_agents(
    path: Path | str,
    *,
    constitution: Constitution | None = None,
) -> list[GovernedAgencyAgent]:
    """Load all agency agent ``.md`` files under *path* and wrap each in AgentDNA governance.

    Args:
        path:         Path to a directory tree (e.g. ``packages/agency-agents/``) or a
                      single ``.md`` file.
        constitution: ACGS constitution to embed in each agent's DNA.  Defaults to the
                      swarm's bundled ``examples/constitution.yaml``.

    Returns:
        List of :class:`GovernedAgencyAgent` instances ordered by domain then name.
        Files whose frontmatter lacks ``name`` or ``description`` are silently skipped
        (they are README/index files, not agent definitions).
    """
    root = Path(path)
    const = constitution or _default_constitution()

    md_files: list[Path] = [root] if root.is_file() else sorted(root.rglob("*.md"))

    agents: list[GovernedAgencyAgent] = []
    seen_ids: dict[str, str] = {}  # slug -> first domain that claimed it
    for md_path in md_files:
        try:
            text = md_path.read_text(encoding="utf-8")
        except OSError:
            log.debug("agency_bridge: could not read %s, skipping", md_path)
            continue
        fm, body = _parse_frontmatter(text)
        name = fm.get("name", "")
        description = fm.get("description", "")
        if not name or not description:
            log.debug("agency_bridge: skipping %s (no name/description in frontmatter)", md_path)
            continue
        domain = md_path.parent.name if not root.is_file() else "general"
        slug = _slugify(name)
        if slug in seen_ids:
            # Prefix with domain to resolve collision (e.g. "engineering-analyst")
            log.debug(
                "agency_bridge: slug '%s' collision between domain '%s' and '%s'; "
                "prefixing with domain",
                slug,
                seen_ids[slug],
                domain,
            )
            slug = f"{domain}-{slug}"
        seen_ids[slug] = domain
        defn = AgencyAgentDef(
            name=name,
            description=description,
            domain=domain,
            body=body,
            emoji=fm.get("emoji", ""),
            vibe=fm.get("vibe", ""),
            color=fm.get("color", ""),
            source_path=md_path,
        )
        agents.append(
            GovernedAgencyAgent(
                definition=defn,
                dna=_make_dna(defn, const, slug),
                capability=_make_capability(defn),
            )
        )
    return agents


class AgencyAgentRegistry:
    """Load and govern a directory of ACGS-agency-agents Markdown definitions.

    Wraps :class:`~constitutional_swarm.capability.CapabilityRegistry` with a loader
    for the agency-agents Markdown format.

    Example::

        registry = AgencyAgentRegistry.from_path("packages/agency-agents/")

        # Find agents by free-text requirement
        matches = registry.find("machine learning")

        # Find agents in a specific domain
        engineers = registry.find_by_domain("engineering")

        # Get a specific agent and validate an action through its DNA
        agent = registry.get("ai-engineer")
        if agent:
            result = agent.dna.validate("deploy ML model to production")
            assert result.valid
    """

    def __init__(self, agents: list[GovernedAgencyAgent]) -> None:
        self._agents: dict[str, GovernedAgencyAgent] = {a.agent_id: a for a in agents}
        self._capability_registry = CapabilityRegistry()
        for agent in agents:
            self._capability_registry.register(agent.agent_id, [agent.capability])

    @classmethod
    def from_path(
        cls,
        path: Path | str,
        *,
        constitution: Constitution | None = None,
    ) -> AgencyAgentRegistry:
        """Build a registry from a directory of agency agent Markdown files."""
        return cls(load_agency_agents(path, constitution=constitution))

    def get(self, agent_id: str) -> GovernedAgencyAgent | None:
        """Return a governed agent by its slugified ID (e.g. ``"ai-engineer"``)."""
        return self._agents.get(agent_id)

    def find(self, requirement: str) -> list[GovernedAgencyAgent]:
        """Return all agents whose capability matches a free-text requirement."""
        return [a for a in self._agents.values() if a.capability.matches(requirement)]

    def find_by_domain(self, domain: str) -> list[GovernedAgencyAgent]:
        """Return all agents in a domain (e.g. ``"engineering"``, ``"design"``)."""
        pairs = self._capability_registry.find_by_domain(domain)
        return [self._agents[aid] for aid, _ in pairs if aid in self._agents]

    def best_for(
        self, requirement: str, *, domain: str | None = None
    ) -> GovernedAgencyAgent | None:
        """Return the single best-matched agent for a requirement."""
        match = self._capability_registry.find_best(requirement, domain=domain)
        if match is None:
            return None
        agent_id, _ = match
        return self._agents.get(agent_id)

    def all(self) -> list[GovernedAgencyAgent]:
        """Return all loaded governed agents."""
        return list(self._agents.values())

    def __len__(self) -> int:
        return len(self._agents)

    def __repr__(self) -> str:
        domains = sorted({a.definition.domain for a in self._agents.values()})
        return f"AgencyAgentRegistry({len(self)} agents, domains={domains})"
