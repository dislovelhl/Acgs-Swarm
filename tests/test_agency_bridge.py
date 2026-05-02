"""Tests for agency_bridge — governed agency agent loader."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest
from constitutional_swarm.agency_bridge import (
    AgencyAgentDef,
    AgencyAgentRegistry,
    load_agency_agents,
)
from constitutional_swarm.dna import AgentDNA

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SAMPLE_AGENT_MD = textwrap.dedent(
    """\
    ---
    name: Test Engineer
    description: Expert test engineer specializing in automated testing and quality assurance.
    color: green
    emoji: 🧪
    vibe: Tests everything, trusts nothing.
    ---

    # Test Engineer Agent

    You are a **Test Engineer**, an expert in automated testing.
    """
)

SAMPLE_AGENT_NO_FM = textwrap.dedent(
    """\
    # README

    This is a README file with no frontmatter.
    """
)


@pytest.fixture()
def agent_dir(tmp_path: Path) -> Path:
    """Create a minimal agency-agents directory tree."""
    (tmp_path / "engineering").mkdir()
    (tmp_path / "engineering" / "test-engineer.md").write_text(SAMPLE_AGENT_MD)
    (tmp_path / "engineering" / "README.md").write_text(SAMPLE_AGENT_NO_FM)

    (tmp_path / "design").mkdir()
    (tmp_path / "design" / "ui-designer.md").write_text(
        textwrap.dedent(
            """\
            ---
            name: UI Designer
            description: Expert UI designer specializing in visual design systems and component libraries.
            color: purple
            emoji: 🎨
            ---

            # UI Designer Agent
            """
        )
    )
    return tmp_path


# ---------------------------------------------------------------------------
# load_agency_agents
# ---------------------------------------------------------------------------


def test_load_skips_non_agent_markdown(agent_dir: Path) -> None:
    agents = load_agency_agents(agent_dir)
    names = [a.definition.name for a in agents]
    assert "Test Engineer" in names
    assert "UI Designer" in names
    # README.md has no frontmatter name/description — must be skipped
    assert len(agents) == 2


def test_load_single_file(tmp_path: Path) -> None:
    md = tmp_path / "test-engineer.md"
    md.write_text(SAMPLE_AGENT_MD)
    agents = load_agency_agents(md)
    assert len(agents) == 1
    assert agents[0].definition.name == "Test Engineer"
    assert agents[0].definition.domain == "general"


def test_load_domain_derived_from_directory(agent_dir: Path) -> None:
    agents = load_agency_agents(agent_dir)
    by_name = {a.definition.name: a for a in agents}
    assert by_name["Test Engineer"].definition.domain == "engineering"
    assert by_name["UI Designer"].definition.domain == "design"


def test_load_emoji_and_vibe_parsed(agent_dir: Path) -> None:
    agents = load_agency_agents(agent_dir)
    te = next(a for a in agents if a.definition.name == "Test Engineer")
    assert te.definition.emoji == "🧪"
    assert te.definition.vibe == "Tests everything, trusts nothing."


# ---------------------------------------------------------------------------
# GovernedAgencyAgent
# ---------------------------------------------------------------------------


def test_governed_agent_has_dna(agent_dir: Path) -> None:
    agents = load_agency_agents(agent_dir)
    for agent in agents:
        assert isinstance(agent.dna, AgentDNA)
        assert agent.dna.agent_id == agent.agent_id


def test_agent_id_is_slugified(agent_dir: Path) -> None:
    agents = load_agency_agents(agent_dir)
    by_name = {a.definition.name: a for a in agents}
    assert by_name["Test Engineer"].agent_id == "test-engineer"
    assert by_name["UI Designer"].agent_id == "ui-designer"


def test_dna_validate_safe_action(agent_dir: Path) -> None:
    agents = load_agency_agents(agent_dir)
    agent = agents[0]
    result = agent.dna.validate("write a unit test")
    assert result.valid


def test_capability_matches_description_keyword(agent_dir: Path) -> None:
    agents = load_agency_agents(agent_dir)
    te = next(a for a in agents if a.definition.name == "Test Engineer")
    assert te.capability.matches("testing")
    assert te.capability.domain == "engineering"


# ---------------------------------------------------------------------------
# AgencyAgentRegistry
# ---------------------------------------------------------------------------


def test_registry_len(agent_dir: Path) -> None:
    registry = AgencyAgentRegistry.from_path(agent_dir)
    assert len(registry) == 2


def test_registry_get(agent_dir: Path) -> None:
    registry = AgencyAgentRegistry.from_path(agent_dir)
    agent = registry.get("test-engineer")
    assert agent is not None
    assert agent.definition.name == "Test Engineer"


def test_registry_get_missing(agent_dir: Path) -> None:
    registry = AgencyAgentRegistry.from_path(agent_dir)
    assert registry.get("nonexistent") is None


def test_registry_find(agent_dir: Path) -> None:
    registry = AgencyAgentRegistry.from_path(agent_dir)
    matches = registry.find("design")
    assert any(a.definition.name == "UI Designer" for a in matches)


def test_registry_find_by_domain(agent_dir: Path) -> None:
    registry = AgencyAgentRegistry.from_path(agent_dir)
    engineers = registry.find_by_domain("engineering")
    assert len(engineers) == 1
    assert engineers[0].definition.name == "Test Engineer"


def test_registry_best_for(agent_dir: Path) -> None:
    registry = AgencyAgentRegistry.from_path(agent_dir)
    best = registry.best_for("visual design")
    assert best is not None
    assert best.definition.name == "UI Designer"


def test_registry_all(agent_dir: Path) -> None:
    registry = AgencyAgentRegistry.from_path(agent_dir)
    all_agents = registry.all()
    assert len(all_agents) == 2
    names = {a.definition.name for a in all_agents}
    assert names == {"Test Engineer", "UI Designer"}


def test_registry_repr(agent_dir: Path) -> None:
    registry = AgencyAgentRegistry.from_path(agent_dir)
    r = repr(registry)
    assert "2 agents" in r
    assert "design" in r
    assert "engineering" in r


# ---------------------------------------------------------------------------
# Integration: top-level constitutional_swarm import
# ---------------------------------------------------------------------------


def test_top_level_import() -> None:
    from constitutional_swarm import (
        AgencyAgentDef,
        AgencyAgentRegistry,
        GovernedAgencyAgent,
        load_agency_agents,
    )

    assert AgencyAgentDef is not None
    assert AgencyAgentRegistry is not None
    assert GovernedAgencyAgent is not None
    assert load_agency_agents is not None


# ---------------------------------------------------------------------------
# Body capture (Gemini finding #1)
# ---------------------------------------------------------------------------


def test_body_captured(agent_dir: Path) -> None:
    agents = load_agency_agents(agent_dir)
    te = next(a for a in agents if a.definition.name == "Test Engineer")
    assert "Test Engineer Agent" in te.definition.body
    assert "automated testing" in te.definition.body


def test_body_field_exists_on_dataclass() -> None:
    defn = AgencyAgentDef(name="X", description="Y", domain="test", body="hello")
    assert defn.body == "hello"


# ---------------------------------------------------------------------------
# ID collision detection (Gemini finding #2)
# ---------------------------------------------------------------------------


def test_id_collision_prefixed_with_domain(tmp_path: Path) -> None:
    analyst_md = textwrap.dedent(
        """\
        ---
        name: Analyst
        description: Expert analyst specializing in data analysis and reporting.
        ---
        # Analyst
        """
    )
    (tmp_path / "engineering").mkdir()
    (tmp_path / "finance").mkdir()
    (tmp_path / "engineering" / "analyst.md").write_text(analyst_md)
    (tmp_path / "finance" / "analyst.md").write_text(analyst_md)

    agents = load_agency_agents(tmp_path)
    assert len(agents) == 2
    ids = {a.agent_id for a in agents}
    # One keeps "analyst", the other gets prefixed with its domain
    assert "analyst" in ids
    assert any("-analyst" in aid for aid in ids)


# ---------------------------------------------------------------------------
# YAML defensive parsing (Codex finding #3)
# ---------------------------------------------------------------------------


def test_yaml_colon_in_value(tmp_path: Path) -> None:
    md = tmp_path / "colon-agent.md"
    md.write_text(
        textwrap.dedent(
            """\
            ---
            name: Colon Agent
            description: "Expert: specializing in multi-domain: analysis and reporting."
            ---
            # Colon Agent
            """
        )
    )
    agents = load_agency_agents(md)
    assert len(agents) == 1
    assert agents[0].definition.name == "Colon Agent"
    assert "analysis" in agents[0].definition.description
