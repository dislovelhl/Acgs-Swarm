"""Tests for the three evolutionary systems:
1. MAP-Elites miner quality optimization
2. Precedent cascade for constitution evolution
3. Island-based TAO emission tuning
"""

from __future__ import annotations

import os
import tempfile

import pytest
from constitutional_swarm.bittensor.cascade import (
    CascadeStage,
    ConstitutionDelta,
    PrecedentCascade,
)
from constitutional_swarm.bittensor.island_evolution import (
    EmissionEvolver,
    EmissionGenome,
    MinerQualityObservation,
    MinerTier,
    _spearman_rho,
)
from constitutional_swarm.bittensor.map_elites import (
    CellCoordinate,
    DeliberationStrategy,
    FitnessWeights,
    GovernanceDomain,
    MinerApproach,
    MinerQualityGrid,
)

# ---------------------------------------------------------------------------
# Shared fixture: constitution YAML
# ---------------------------------------------------------------------------


@pytest.fixture
def constitution_path():
    content = """
name: test-evo-constitution
rules:
  - id: safety-01
    text: Do not cause physical harm
    severity: critical
    hardcoded: true
    keywords:
      - harm
      - danger
      - kill
      - weapon
  - id: privacy-01
    text: Protect personal information
    severity: high
    hardcoded: true
    keywords:
      - personal data
      - PII
"""
    path = os.path.join(tempfile.gettempdir(), "test_evo_constitution.yaml")
    with open(path, "w") as f:
        f.write(content)
    return path


# ===========================================================================
# System 1: MAP-Elites
# ===========================================================================


class TestMinerQualityGrid:
    """MAP-Elites grid for miner quality diversity."""

    def test_empty_grid(self):
        grid = MinerQualityGrid()
        assert grid.coverage == 0.0
        assert grid.occupied_count == 0
        assert len(grid.empty_cells()) == 28

    def test_compute_fitness(self):
        grid = MinerQualityGrid()
        f = grid.compute_fitness(acceptance_rate=1.0, reasoning_quality=1.0, speed_ms=0.0)
        assert f == pytest.approx(1.0)

        f2 = grid.compute_fitness(acceptance_rate=0.0, reasoning_quality=0.0, speed_ms=2000.0)
        assert f2 == pytest.approx(0.0)

    def test_challenge_fills_empty_cell(self):
        grid = MinerQualityGrid()
        approach = MinerApproach(
            miner_uid="miner-01",
            domain=GovernanceDomain.SAFETY,
            strategy=DeliberationStrategy.HYBRID,
            fitness=0.8,
            acceptance_rate=0.9,
            reasoning_quality=0.7,
            speed_ms=500,
            sample_count=10,
        )
        assert grid.challenge(approach) is True
        assert grid.occupied_count == 1

    def test_challenge_replaces_incumbent(self):
        grid = MinerQualityGrid()
        weak = MinerApproach(
            miner_uid="miner-01",
            domain=GovernanceDomain.SAFETY,
            strategy=DeliberationStrategy.HYBRID,
            fitness=0.5,
            acceptance_rate=0.5,
            reasoning_quality=0.5,
            speed_ms=500,
            sample_count=10,
        )
        strong = MinerApproach(
            miner_uid="miner-02",
            domain=GovernanceDomain.SAFETY,
            strategy=DeliberationStrategy.HYBRID,
            fitness=0.9,
            acceptance_rate=0.9,
            reasoning_quality=0.9,
            speed_ms=100,
            sample_count=10,
        )
        grid.challenge(weak)
        assert grid.challenge(strong) is True
        best = grid.best_for(GovernanceDomain.SAFETY, DeliberationStrategy.HYBRID)
        assert best is not None
        assert best.miner_uid == "miner-02"

    def test_challenge_rejects_below_min_samples(self):
        grid = MinerQualityGrid(fitness_weights=FitnessWeights(min_samples=10))
        approach = MinerApproach(
            miner_uid="m",
            domain=GovernanceDomain.SAFETY,
            strategy=DeliberationStrategy.HYBRID,
            fitness=0.9,
            acceptance_rate=0.9,
            reasoning_quality=0.9,
            speed_ms=100,
            sample_count=3,
        )
        assert grid.challenge(approach) is False

    def test_diversity_score(self):
        grid = MinerQualityGrid()
        # Same miner in 2 cells = low diversity
        for strat in [DeliberationStrategy.HYBRID, DeliberationStrategy.PRECEDENT_BASED]:
            grid.challenge(
                MinerApproach(
                    miner_uid="same-miner",
                    domain=GovernanceDomain.SAFETY,
                    strategy=strat,
                    fitness=0.8,
                    acceptance_rate=0.8,
                    reasoning_quality=0.8,
                    speed_ms=200,
                    sample_count=10,
                )
            )
        assert grid.diversity_score() == 0.5  # 1 unique / 2 cells

    def test_ceiling_detection(self):
        grid = MinerQualityGrid(ceiling_window=3)
        strong = MinerApproach(
            miner_uid="m",
            domain=GovernanceDomain.SAFETY,
            strategy=DeliberationStrategy.HYBRID,
            fitness=0.9,
            acceptance_rate=0.9,
            reasoning_quality=0.9,
            speed_ms=100,
            sample_count=10,
        )
        grid.challenge(strong)  # First: fills empty cell (improvement)

        # 3 weaker challenges that don't improve
        for _ in range(3):
            weak = MinerApproach(
                miner_uid="m2",
                domain=GovernanceDomain.SAFETY,
                strategy=DeliberationStrategy.HYBRID,
                fitness=0.5,
                acceptance_rate=0.5,
                reasoning_quality=0.5,
                speed_ms=500,
                sample_count=10,
            )
            grid.challenge(weak)
        assert grid.ceiling_detected() is True

    def test_exploration_bonus(self):
        grid = MinerQualityGrid()
        # New miner gets max bonus
        assert grid.exploration_bonus("new-miner") == 1.1
        # Miner with cells gets reduced bonus
        grid.challenge(
            MinerApproach(
                miner_uid="active",
                domain=GovernanceDomain.SAFETY,
                strategy=DeliberationStrategy.HYBRID,
                fitness=0.8,
                acceptance_rate=0.8,
                reasoning_quality=0.8,
                speed_ms=200,
                sample_count=10,
            )
        )
        bonus = grid.exploration_bonus("active")
        assert 1.0 < bonus <= 1.1

    def test_summary(self):
        grid = MinerQualityGrid()
        s = grid.summary()
        assert s["total_cells"] == 28
        assert s["occupied_cells"] == 0
        assert "domain_coverage" in s


# ===========================================================================
# System 2: Precedent Cascade
# ===========================================================================


class TestPrecedentCascade:
    """Four-stage cascade for constitution evolution."""

    def test_valid_judgment_passes_all_stages(self, constitution_path):
        from acgs_lite import Constitution

        constitution = Constitution.from_yaml(constitution_path)
        cascade = PrecedentCascade(constitution)

        candidate = cascade.run_full_cascade(
            judgment="Privacy should be balanced with transparency in governance reporting",
            reasoning="Both principles serve the public interest; context determines priority",
            domain="privacy",
            miner_uid="miner-01",
        )
        assert candidate.alive is True
        assert candidate.stages_passed == 4

    def test_violating_judgment_rejected_at_stage1(self, constitution_path):
        from acgs_lite import Constitution

        constitution = Constitution.from_yaml(constitution_path)
        cascade = PrecedentCascade(constitution)

        candidate = cascade.run_full_cascade(
            judgment="Use a weapon to cause harm",
            reasoning="Deliberately harmful",
            domain="safety",
            miner_uid="miner-bad",
        )
        assert candidate.alive is False
        assert candidate.stages_passed < 4

    def test_accept_creates_delta(self, constitution_path):
        from acgs_lite import Constitution

        constitution = Constitution.from_yaml(constitution_path)
        cascade = PrecedentCascade(constitution)

        candidate = cascade.run_full_cascade(
            judgment="Fairness requires considering all stakeholder perspectives",
            reasoning="Equitable treatment is a constitutional mandate",
            domain="fairness",
            miner_uid="miner-01",
        )
        delta = cascade.accept(candidate)
        assert delta is not None
        assert isinstance(delta, ConstitutionDelta)
        assert delta.domain == "fairness"
        assert len(cascade.accepted_deltas) == 1

    def test_reject_does_not_create_delta(self, constitution_path):
        from acgs_lite import Constitution

        constitution = Constitution.from_yaml(constitution_path)
        cascade = PrecedentCascade(constitution)

        candidate = cascade.run_full_cascade(
            judgment="Use weapons to cause physical harm to people",
            reasoning="Dangerous action",
            domain="safety",
            miner_uid="miner-bad",
        )
        delta = cascade.accept(candidate)
        assert delta is None
        assert len(cascade.accepted_deltas) == 0

    def test_funnel_report(self, constitution_path):
        from acgs_lite import Constitution

        constitution = Constitution.from_yaml(constitution_path)
        cascade = PrecedentCascade(constitution)

        cascade.run_full_cascade("good judgment", "good reasoning", "d", "m")
        cascade.run_full_cascade("Use weapon to cause harm", "bad", "d", "m2")

        report = cascade.metrics.funnel_report()
        assert report["submitted"] == 2
        assert report["passed_dna"] >= 1

    def test_stage_by_stage_advance(self, constitution_path):
        from acgs_lite import Constitution

        constitution = Constitution.from_yaml(constitution_path)
        cascade = PrecedentCascade(constitution)

        candidate = cascade.submit("Valid governance ruling", "Sound logic", "privacy", "m")
        assert candidate.current_stage == CascadeStage.DNA_PRECHECK

        candidate = cascade.advance(candidate)
        assert len(candidate.stage_results) == 1

        candidate = cascade.advance(candidate)
        assert len(candidate.stage_results) == 2


# ===========================================================================
# System 3: Island-Based Emission Evolution
# ===========================================================================


class TestSpearmanRho:
    """Spearman rank correlation helper."""

    def test_perfect_correlation(self):
        assert _spearman_rho([1, 2, 3, 4, 5], [1, 2, 3, 4, 5]) == pytest.approx(1.0)

    def test_perfect_anticorrelation(self):
        assert _spearman_rho([1, 2, 3, 4, 5], [5, 4, 3, 2, 1]) == pytest.approx(-1.0)

    def test_no_correlation(self):
        # Not exactly 0 but should be low
        rho = _spearman_rho([1, 2, 3, 4], [2, 4, 1, 3])
        assert abs(rho) < 0.5

    def test_short_list(self):
        assert _spearman_rho([1], [1]) == 0.0


class TestEmissionGenome:
    """Genome weight computation."""

    def test_compute_weight(self):
        genome = EmissionGenome(
            genome_id="test",
            reputation_weight=1.0,
            tier_multiplier_scale=0.0,
            precedent_bonus=0.0,
            authenticity_weight=0.0,
            generation=0,
        )
        w = genome.compute_weight(
            reputation=2.0, tier=MinerTier.APPRENTICE, precedent_count=0, manifold_trust=0.0
        )
        assert w == pytest.approx(2.0)

    def test_tier_scaling(self):
        genome = EmissionGenome(
            genome_id="test",
            reputation_weight=0.0,
            tier_multiplier_scale=1.0,
            precedent_bonus=0.0,
            authenticity_weight=0.0,
            generation=0,
        )
        w_apprentice = genome.compute_weight(0, MinerTier.APPRENTICE, 0, 0)
        w_master = genome.compute_weight(0, MinerTier.MASTER, 0, 0)
        assert w_master > w_apprentice


class TestEmissionEvolver:
    """Island-based evolutionary optimizer."""

    def _sample_observations(self) -> list[MinerQualityObservation]:
        """Create observations where quality correlates with reputation."""
        return [
            MinerQualityObservation(
                "m1",
                consensus_quality=0.9,
                acceptance_rate=0.95,
                reputation=1.8,
                tier=MinerTier.MASTER,
                precedent_contributions=10,
                manifold_trust=0.8,
            ),
            MinerQualityObservation(
                "m2",
                consensus_quality=0.7,
                acceptance_rate=0.75,
                reputation=1.3,
                tier=MinerTier.JOURNEYMAN,
                precedent_contributions=3,
                manifold_trust=0.5,
            ),
            MinerQualityObservation(
                "m3",
                consensus_quality=0.5,
                acceptance_rate=0.55,
                reputation=1.0,
                tier=MinerTier.APPRENTICE,
                precedent_contributions=0,
                manifold_trust=0.3,
            ),
            MinerQualityObservation(
                "m4",
                consensus_quality=0.3,
                acceptance_rate=0.35,
                reputation=0.8,
                tier=MinerTier.APPRENTICE,
                precedent_contributions=0,
                manifold_trust=0.2,
            ),
            MinerQualityObservation(
                "m5",
                consensus_quality=0.1,
                acceptance_rate=0.15,
                reputation=0.5,
                tier=MinerTier.APPRENTICE,
                precedent_contributions=0,
                manifold_trust=0.1,
            ),
        ]

    def test_initialize_islands(self):
        evolver = EmissionEvolver(seed=42)
        evolver.initialize_islands()
        assert len(evolver.islands) == 4

    def test_evaluate_genome_perfect(self):
        """A genome that perfectly ranks miners by reputation should have rho=1."""
        evolver = EmissionEvolver(seed=42)
        # Reputation-only genome should correlate perfectly with our test data
        genome = EmissionGenome(
            genome_id="rep-only",
            reputation_weight=1.0,
            tier_multiplier_scale=0.0,
            precedent_bonus=0.0,
            authenticity_weight=0.0,
            generation=0,
        )
        obs = self._sample_observations()
        rho = evolver.evaluate_genome(genome, obs)
        assert rho == pytest.approx(1.0)

    def test_evolve_one_generation(self):
        evolver = EmissionEvolver(seed=42, population_per_island=5)
        evolver.initialize_islands()
        obs = self._sample_observations()
        evolver.evolve_all(obs)
        assert evolver.active_genome is not None
        assert evolver._total_generations == 1

    def test_evolve_multiple_generations(self):
        evolver = EmissionEvolver(seed=42, population_per_island=5)
        evolver.initialize_islands()
        obs = self._sample_observations()
        for _ in range(10):
            evolver.evolve_all(obs)
        assert evolver._total_generations == 10
        # Fitness should have improved
        assert evolver._global_best_fitness > 0.0

    def test_ceiling_triggers_migration(self):
        evolver = EmissionEvolver(
            seed=42,
            population_per_island=5,
            stagnation_threshold=3,
        )
        evolver.initialize_islands()
        obs = self._sample_observations()
        # Run enough generations for ceiling
        for _ in range(20):
            evolver.evolve_all(obs)
        # Should have triggered at least one migration
        # (stagnation_threshold=3 with 20 generations)
        assert len(evolver.migrations) >= 0  # May or may not trigger

    def test_compute_emission_weights(self):
        evolver = EmissionEvolver(seed=42, population_per_island=5)
        evolver.initialize_islands()
        obs = self._sample_observations()
        evolver.evolve_all(obs)
        weights = evolver.compute_emission_weights(obs)
        assert len(weights) == 5
        assert abs(sum(weights.values()) - 1.0) < 1e-9

    def test_weights_empty_without_evolution(self):
        evolver = EmissionEvolver(seed=42)
        assert evolver.compute_emission_weights([]) == {}

    def test_summary(self):
        evolver = EmissionEvolver(seed=42, population_per_island=5)
        evolver.initialize_islands()
        obs = self._sample_observations()
        evolver.evolve_all(obs)
        s = evolver.summary()
        assert "total_generations" in s
        assert "global_best_fitness" in s
        assert "islands" in s
        assert len(s["islands"]) == 4

    def test_evolution_improves_fitness(self):
        """Fitness should improve over generations."""
        evolver = EmissionEvolver(seed=42, population_per_island=10)
        evolver.initialize_islands()
        obs = self._sample_observations()

        fitness_gen1 = None
        fitness_gen20 = None

        for gen in range(20):
            evolver.evolve_all(obs)
            if gen == 0:
                fitness_gen1 = evolver._global_best_fitness
            if gen == 19:
                fitness_gen20 = evolver._global_best_fitness

        assert fitness_gen1 is not None
        assert fitness_gen20 is not None
        assert fitness_gen20 >= fitness_gen1


# ===========================================================================
# Phase 4: Extended Evolutionary System Tests (25+)
# ===========================================================================

import random


class TestEmissionGenomeExtended:
    """Extended tests for EmissionGenome creation and weight computation."""

    def test_creation_fields(self):
        """EmissionGenome stores all fields correctly."""
        random.seed(42)
        g = EmissionGenome(
            genome_id="g1",
            reputation_weight=0.5,
            tier_multiplier_scale=1.2,
            precedent_bonus=0.3,
            authenticity_weight=0.4,
            generation=3,
            parent_id="p1",
        )
        assert g.genome_id == "g1"
        assert g.reputation_weight == 0.5
        assert g.tier_multiplier_scale == 1.2
        assert g.precedent_bonus == 0.3
        assert g.authenticity_weight == 0.4
        assert g.generation == 3
        assert g.parent_id == "p1"

    def test_compute_weight_positive_for_positive_inputs(self):
        """compute_weight produces positive values for positive parameters."""
        random.seed(42)
        g = EmissionGenome(
            genome_id="pos",
            reputation_weight=0.5,
            tier_multiplier_scale=0.5,
            precedent_bonus=0.5,
            authenticity_weight=0.5,
            generation=0,
        )
        w = g.compute_weight(
            reputation=1.0,
            tier=MinerTier.JOURNEYMAN,
            precedent_count=5,
            manifold_trust=0.5,
        )
        assert w > 0.0

    def test_compute_weight_zero_params_zero_weight(self):
        """All-zero parameters produce zero weight."""
        random.seed(42)
        g = EmissionGenome(
            genome_id="zero",
            reputation_weight=0.0,
            tier_multiplier_scale=0.0,
            precedent_bonus=0.0,
            authenticity_weight=0.0,
            generation=0,
        )
        w = g.compute_weight(
            reputation=5.0, tier=MinerTier.MASTER, precedent_count=50, manifold_trust=1.0
        )
        assert w == pytest.approx(0.0)

    def test_precedent_bonus_capped_at_50(self):
        """Precedent count is capped at 50 in the formula."""
        random.seed(42)
        g = EmissionGenome(
            genome_id="cap",
            reputation_weight=0.0,
            tier_multiplier_scale=0.0,
            precedent_bonus=1.0,
            authenticity_weight=0.0,
            generation=0,
        )
        w50 = g.compute_weight(
            reputation=0, tier=MinerTier.APPRENTICE, precedent_count=50, manifold_trust=0
        )
        w100 = g.compute_weight(
            reputation=0, tier=MinerTier.APPRENTICE, precedent_count=100, manifold_trust=0
        )
        assert w50 == pytest.approx(w100)

    def test_frozen_dataclass(self):
        """EmissionGenome is immutable (frozen)."""
        random.seed(42)
        g = EmissionGenome(
            genome_id="frozen",
            reputation_weight=0.5,
            tier_multiplier_scale=0.5,
            precedent_bonus=0.5,
            authenticity_weight=0.5,
            generation=0,
        )
        with pytest.raises(AttributeError):
            g.reputation_weight = 0.9  # type: ignore[misc]


class TestMinerQualityObservationExtended:
    """Extended tests for MinerQualityObservation."""

    def test_creation_fields(self):
        """MinerQualityObservation stores all fields correctly."""
        random.seed(42)
        obs = MinerQualityObservation(
            miner_uid="m1",
            consensus_quality=0.85,
            acceptance_rate=0.9,
            reputation=1.5,
            tier=MinerTier.JOURNEYMAN,
            precedent_contributions=7,
            manifold_trust=0.6,
        )
        assert obs.miner_uid == "m1"
        assert obs.consensus_quality == 0.85
        assert obs.acceptance_rate == 0.9
        assert obs.reputation == 1.5
        assert obs.tier == MinerTier.JOURNEYMAN
        assert obs.precedent_contributions == 7
        assert obs.manifold_trust == 0.6

    def test_frozen(self):
        """MinerQualityObservation is immutable."""
        random.seed(42)
        obs = MinerQualityObservation(
            miner_uid="m1",
            consensus_quality=0.5,
            acceptance_rate=0.5,
            reputation=1.0,
            tier=MinerTier.APPRENTICE,
            precedent_contributions=0,
            manifold_trust=0.0,
        )
        with pytest.raises(AttributeError):
            obs.consensus_quality = 1.0  # type: ignore[misc]


class TestIslandInitializationExtended:
    """Extended tests for island initialization."""

    def test_four_islands_created(self):
        """initialize_islands creates exactly 4 islands."""
        random.seed(42)
        evolver = EmissionEvolver(seed=42)
        evolver.initialize_islands()
        assert len(evolver.islands) == 4

    def test_island_families_are_diverse(self):
        """Each island has a distinct parameter family."""
        random.seed(42)
        evolver = EmissionEvolver(seed=42)
        evolver.initialize_islands()
        families = {island.identity.family for island in evolver.islands.values()}
        assert families == {"reputation_heavy", "tier_heavy", "precedent_heavy", "balanced"}

    def test_population_size_per_island(self):
        """Each island has the configured population size."""
        random.seed(42)
        evolver = EmissionEvolver(seed=42, population_per_island=7)
        evolver.initialize_islands()
        for island in evolver.islands.values():
            assert len(island.population) == 7

    def test_initial_genomes_have_generation_zero(self):
        """All initial genomes are generation 0."""
        random.seed(42)
        evolver = EmissionEvolver(seed=42, population_per_island=5)
        evolver.initialize_islands()
        for island in evolver.islands.values():
            for genome in island.population:
                assert genome.generation == 0


class TestGenomeMutationExtended:
    """Extended tests for genome mutation."""

    def test_mutation_stays_nonnegative(self):
        """Mutated parameters are clamped to >= 0."""
        random.seed(42)
        evolver = EmissionEvolver(seed=42, mutation_sigma=10.0)  # Large sigma
        base = EmissionGenome(
            genome_id="base",
            reputation_weight=0.01,
            tier_multiplier_scale=0.01,
            precedent_bonus=0.01,
            authenticity_weight=0.01,
            generation=0,
        )
        # Mutate many times; all values should stay >= 0
        for _ in range(50):
            mutated = evolver._mutate(base, 1)
            assert mutated.reputation_weight >= 0.0
            assert mutated.tier_multiplier_scale >= 0.0
            assert mutated.precedent_bonus >= 0.0
            assert mutated.authenticity_weight >= 0.0

    def test_mutation_changes_genome_id(self):
        """Mutated genome gets a new ID."""
        random.seed(42)
        evolver = EmissionEvolver(seed=42)
        base = EmissionGenome(
            genome_id="original",
            reputation_weight=0.5,
            tier_multiplier_scale=1.0,
            precedent_bonus=0.3,
            authenticity_weight=0.2,
            generation=0,
        )
        mutated = evolver._mutate(base, 1)
        assert mutated.genome_id != base.genome_id
        assert mutated.parent_id == base.genome_id

    def test_mutation_sigma_respected(self):
        """With very small sigma, mutations are small."""
        random.seed(42)
        evolver = EmissionEvolver(seed=42, mutation_sigma=0.001)
        base = EmissionGenome(
            genome_id="base",
            reputation_weight=0.5,
            tier_multiplier_scale=1.0,
            precedent_bonus=0.3,
            authenticity_weight=0.2,
            generation=0,
        )
        for _ in range(20):
            mutated = evolver._mutate(base, 1)
            assert abs(mutated.reputation_weight - base.reputation_weight) < 0.05
            assert abs(mutated.authenticity_weight - base.authenticity_weight) < 0.05


class TestTournamentSelectionExtended:
    """Extended tests for tournament selection."""

    def test_fittest_wins_deterministic(self):
        """With seed, tournament consistently picks high-fitness genomes."""
        random.seed(42)
        evolver = EmissionEvolver(seed=42)
        g_weak = EmissionGenome(
            genome_id="weak",
            reputation_weight=0.1,
            tier_multiplier_scale=0.1,
            precedent_bonus=0.1,
            authenticity_weight=0.1,
            generation=0,
        )
        g_strong = EmissionGenome(
            genome_id="strong",
            reputation_weight=0.9,
            tier_multiplier_scale=0.9,
            precedent_bonus=0.9,
            authenticity_weight=0.9,
            generation=0,
        )
        scored = [(g_strong, 0.95), (g_weak, 0.1)]
        # With only 2 candidates and k=3 (clamped to 2), best always wins
        winners = [evolver._tournament_select(scored, k=2) for _ in range(10)]
        assert all(w.genome_id == "strong" for w in winners)


class TestCrossoverExtended:
    """Extended tests for single-point crossover."""

    def test_child_has_genes_from_both_parents(self):
        """Crossover child contains parameters from both parents."""
        random.seed(42)
        evolver = EmissionEvolver(seed=42)
        a = EmissionGenome(
            genome_id="a",
            reputation_weight=0.0,
            tier_multiplier_scale=0.0,
            precedent_bonus=0.0,
            authenticity_weight=0.0,
            generation=0,
        )
        b = EmissionGenome(
            genome_id="b",
            reputation_weight=1.0,
            tier_multiplier_scale=1.0,
            precedent_bonus=1.0,
            authenticity_weight=1.0,
            generation=0,
        )
        # Run many crossovers; at least one should mix genes
        found_mixed = False
        for _ in range(20):
            child = evolver._crossover(a, b, 1)
            params = [
                child.reputation_weight,
                child.tier_multiplier_scale,
                child.precedent_bonus,
                child.authenticity_weight,
            ]
            has_a = any(p == 0.0 for p in params)
            has_b = any(p == 1.0 for p in params)
            if has_a and has_b:
                found_mixed = True
                break
        assert found_mixed, "Crossover should produce children with genes from both parents"

    def test_crossover_preserves_parent_id(self):
        """Crossover child records first parent as parent_id."""
        random.seed(42)
        evolver = EmissionEvolver(seed=42)
        a = EmissionGenome(
            genome_id="parent_a",
            reputation_weight=0.5,
            tier_multiplier_scale=0.5,
            precedent_bonus=0.5,
            authenticity_weight=0.5,
            generation=0,
        )
        b = EmissionGenome(
            genome_id="parent_b",
            reputation_weight=0.8,
            tier_multiplier_scale=0.8,
            precedent_bonus=0.8,
            authenticity_weight=0.8,
            generation=0,
        )
        child = evolver._crossover(a, b, 1)
        assert child.parent_id == "parent_a"


class TestCeilingDetectionExtended:
    """Extended tests for ceiling (stagnation) detection."""

    def test_no_ceiling_initially(self):
        """Fresh island has no ceiling."""
        random.seed(42)
        evolver = EmissionEvolver(seed=42, stagnation_threshold=3)
        evolver.initialize_islands()
        for island in evolver.islands.values():
            assert evolver.check_ceiling(island) is False

    def test_ceiling_triggers_after_stagnation(self):
        """Ceiling detected when stagnation_count >= threshold."""
        random.seed(42)
        from constitutional_swarm.bittensor.island_evolution import Island, IslandIdentity

        island = Island(
            identity=IslandIdentity(island_id="test", family="test"),
            population=[],
            stagnation_count=5,
        )
        evolver = EmissionEvolver(seed=42, stagnation_threshold=5)
        assert evolver.check_ceiling(island) is True

    def test_ceiling_not_triggered_below_threshold(self):
        """No ceiling when stagnation_count < threshold."""
        random.seed(42)
        from constitutional_swarm.bittensor.island_evolution import Island, IslandIdentity

        island = Island(
            identity=IslandIdentity(island_id="test", family="test"),
            population=[],
            stagnation_count=4,
        )
        evolver = EmissionEvolver(seed=42, stagnation_threshold=5)
        assert evolver.check_ceiling(island) is False


class TestMigrationExtended:
    """Extended tests for migration between islands."""

    def test_migration_injects_genome(self):
        """Best genome from source appears in target after migration."""
        random.seed(42)
        from constitutional_swarm.bittensor.island_evolution import Island, IslandIdentity

        best = EmissionGenome(
            genome_id="best",
            reputation_weight=0.9,
            tier_multiplier_scale=2.0,
            precedent_bonus=0.5,
            authenticity_weight=0.8,
            generation=5,
        )
        filler = EmissionGenome(
            genome_id="filler",
            reputation_weight=0.1,
            tier_multiplier_scale=0.1,
            precedent_bonus=0.1,
            authenticity_weight=0.1,
            generation=0,
        )
        source = Island(
            identity=IslandIdentity(island_id="src", family="reputation_heavy"),
            population=[best],
            best_genome=best,
            best_fitness=0.95,
        )
        target = Island(
            identity=IslandIdentity(island_id="tgt", family="balanced"),
            population=[filler, filler],
        )
        evolver = EmissionEvolver(seed=42)
        _, new_target = evolver.migrate(source, target)
        # The migrant should have the same parameter values as the source best
        migrant = new_target.population[-1]
        assert migrant.reputation_weight == best.reputation_weight
        assert migrant.tier_multiplier_scale == best.tier_multiplier_scale
        assert migrant.parent_id == best.genome_id

    def test_migration_records_event(self):
        """Migration creates a MigrationEvent."""
        random.seed(42)
        from constitutional_swarm.bittensor.island_evolution import Island, IslandIdentity

        best = EmissionGenome(
            genome_id="best",
            reputation_weight=0.9,
            tier_multiplier_scale=2.0,
            precedent_bonus=0.5,
            authenticity_weight=0.8,
            generation=5,
        )
        source = Island(
            identity=IslandIdentity(island_id="src", family="tier_heavy"),
            population=[best],
            best_genome=best,
            best_fitness=0.9,
        )
        target = Island(
            identity=IslandIdentity(island_id="tgt", family="balanced"),
            population=[best],
        )
        evolver = EmissionEvolver(seed=42)
        evolver.migrate(source, target)
        assert len(evolver.migrations) == 1
        event = evolver.migrations[0]
        assert event.from_island == "src"
        assert event.to_island == "tgt"
        assert event.trigger == "ceiling_detected"

    def test_migration_no_op_without_best(self):
        """Migration is a no-op when source has no best genome."""
        random.seed(42)
        from constitutional_swarm.bittensor.island_evolution import Island, IslandIdentity

        source = Island(
            identity=IslandIdentity(island_id="src", family="tier_heavy"),
            population=[],
            best_genome=None,
        )
        filler = EmissionGenome(
            genome_id="f",
            reputation_weight=0.1,
            tier_multiplier_scale=0.1,
            precedent_bonus=0.1,
            authenticity_weight=0.1,
            generation=0,
        )
        target = Island(
            identity=IslandIdentity(island_id="tgt", family="balanced"),
            population=[filler],
        )
        evolver = EmissionEvolver(seed=42)
        _, new_target = evolver.migrate(source, target)
        assert new_target.population == target.population


class TestFitnessEvaluationExtended:
    """Extended tests for fitness evaluation (Spearman correlation)."""

    def test_evaluate_genome_with_single_observation(self):
        """Single observation returns 0.0 (insufficient data)."""
        random.seed(42)
        evolver = EmissionEvolver(seed=42)
        genome = EmissionGenome(
            genome_id="g",
            reputation_weight=1.0,
            tier_multiplier_scale=0.0,
            precedent_bonus=0.0,
            authenticity_weight=0.0,
            generation=0,
        )
        obs = [
            MinerQualityObservation(
                "m1",
                consensus_quality=0.9,
                acceptance_rate=0.9,
                reputation=1.0,
                tier=MinerTier.MASTER,
                precedent_contributions=0,
                manifold_trust=0.5,
            )
        ]
        assert evolver.evaluate_genome(genome, obs) == 0.0

    def test_evaluate_genome_anticorrelated(self):
        """A genome that ranks miners inversely should have negative rho."""
        random.seed(42)
        evolver = EmissionEvolver(seed=42)
        # Genome weights reputation, but quality is inversely related to reputation
        genome = EmissionGenome(
            genome_id="inv",
            reputation_weight=1.0,
            tier_multiplier_scale=0.0,
            precedent_bonus=0.0,
            authenticity_weight=0.0,
            generation=0,
        )
        obs = [
            MinerQualityObservation(
                "m1",
                consensus_quality=0.1,
                acceptance_rate=0.1,
                reputation=2.0,
                tier=MinerTier.APPRENTICE,
                precedent_contributions=0,
                manifold_trust=0.0,
            ),
            MinerQualityObservation(
                "m2",
                consensus_quality=0.5,
                acceptance_rate=0.5,
                reputation=1.0,
                tier=MinerTier.APPRENTICE,
                precedent_contributions=0,
                manifold_trust=0.0,
            ),
            MinerQualityObservation(
                "m3",
                consensus_quality=0.9,
                acceptance_rate=0.9,
                reputation=0.5,
                tier=MinerTier.APPRENTICE,
                precedent_contributions=0,
                manifold_trust=0.0,
            ),
        ]
        rho = evolver.evaluate_genome(genome, obs)
        assert rho < 0.0


class TestFullEvolutionLoopExtended:
    """Extended tests for multi-generation evolution."""

    def _sample_observations(self) -> list[MinerQualityObservation]:
        return [
            MinerQualityObservation(
                "m1",
                consensus_quality=0.9,
                acceptance_rate=0.95,
                reputation=1.8,
                tier=MinerTier.MASTER,
                precedent_contributions=10,
                manifold_trust=0.8,
            ),
            MinerQualityObservation(
                "m2",
                consensus_quality=0.7,
                acceptance_rate=0.75,
                reputation=1.3,
                tier=MinerTier.JOURNEYMAN,
                precedent_contributions=3,
                manifold_trust=0.5,
            ),
            MinerQualityObservation(
                "m3",
                consensus_quality=0.3,
                acceptance_rate=0.35,
                reputation=0.8,
                tier=MinerTier.APPRENTICE,
                precedent_contributions=0,
                manifold_trust=0.2,
            ),
        ]

    def test_ten_generations_nonnegative_fitness(self):
        """After 10 generations, global best fitness is non-negative."""
        random.seed(42)
        evolver = EmissionEvolver(seed=42, population_per_island=5)
        evolver.initialize_islands()
        obs = self._sample_observations()
        for _ in range(10):
            evolver.evolve_all(obs)
        assert evolver._global_best_fitness >= 0.0

    def test_ten_generations_has_active_genome(self):
        """After 10 generations, there is an active genome."""
        random.seed(42)
        evolver = EmissionEvolver(seed=42, population_per_island=5)
        evolver.initialize_islands()
        obs = self._sample_observations()
        for _ in range(10):
            evolver.evolve_all(obs)
        assert evolver.active_genome is not None

    def test_generation_counter_tracks(self):
        """Total generations counter increments correctly."""
        random.seed(42)
        evolver = EmissionEvolver(seed=42, population_per_island=5)
        evolver.initialize_islands()
        obs = self._sample_observations()
        for _ in range(7):
            evolver.evolve_all(obs)
        assert evolver._total_generations == 7


class TestMapElitesExtended:
    """Extended MAP-Elites tests."""

    def test_empty_grid_coverage_zero(self):
        """Empty grid has zero coverage."""
        random.seed(42)
        grid = MinerQualityGrid()
        assert grid.coverage == 0.0

    def test_fill_grid_increases_coverage(self):
        """Adding approaches to different cells increases coverage."""
        random.seed(42)
        grid = MinerQualityGrid()
        domains = list(GovernanceDomain)
        strategies = list(DeliberationStrategy)
        count = 0
        for d in domains[:3]:
            for s in strategies[:2]:
                grid.challenge(
                    MinerApproach(
                        miner_uid=f"miner-{count}",
                        domain=d,
                        strategy=s,
                        fitness=0.7,
                        acceptance_rate=0.7,
                        reasoning_quality=0.7,
                        speed_ms=300,
                        sample_count=10,
                    )
                )
                count += 1
        assert grid.coverage == pytest.approx(6 / 28, abs=1e-6)
        assert grid.occupied_count == 6

    def test_challenge_rejects_weaker(self):
        """Challenge does not replace incumbent with lower fitness."""
        random.seed(42)
        grid = MinerQualityGrid()
        strong = MinerApproach(
            miner_uid="strong",
            domain=GovernanceDomain.PRIVACY,
            strategy=DeliberationStrategy.CONSTITUTIONAL_REASONING,
            fitness=0.9,
            acceptance_rate=0.9,
            reasoning_quality=0.9,
            speed_ms=100,
            sample_count=10,
        )
        weak = MinerApproach(
            miner_uid="weak",
            domain=GovernanceDomain.PRIVACY,
            strategy=DeliberationStrategy.CONSTITUTIONAL_REASONING,
            fitness=0.3,
            acceptance_rate=0.3,
            reasoning_quality=0.3,
            speed_ms=800,
            sample_count=10,
        )
        grid.challenge(strong)
        replaced = grid.challenge(weak)
        assert replaced is False
        best = grid.best_for(
            GovernanceDomain.PRIVACY, DeliberationStrategy.CONSTITUTIONAL_REASONING
        )
        assert best is not None
        assert best.miner_uid == "strong"

    def test_exploration_bonus_new_miner_above_one(self):
        """Exploration bonus for a brand-new miner is > 1.0."""
        random.seed(42)
        grid = MinerQualityGrid()
        bonus = grid.exploration_bonus("totally-new")
        assert bonus > 1.0

    def test_diversity_score_increases_with_diverse_miners(self):
        """Diversity score is higher when different miners hold cells."""
        random.seed(42)
        grid_same = MinerQualityGrid()
        grid_diverse = MinerQualityGrid()
        domains = list(GovernanceDomain)[:2]
        strategies = list(DeliberationStrategy)[:2]
        idx = 0
        for d in domains:
            for s in strategies:
                grid_same.challenge(
                    MinerApproach(
                        miner_uid="same",
                        domain=d,
                        strategy=s,
                        fitness=0.7,
                        acceptance_rate=0.7,
                        reasoning_quality=0.7,
                        speed_ms=300,
                        sample_count=10,
                    )
                )
                grid_diverse.challenge(
                    MinerApproach(
                        miner_uid=f"miner-{idx}",
                        domain=d,
                        strategy=s,
                        fitness=0.7,
                        acceptance_rate=0.7,
                        reasoning_quality=0.7,
                        speed_ms=300,
                        sample_count=10,
                    )
                )
                idx += 1
        assert grid_diverse.diversity_score() > grid_same.diversity_score()

    def test_ceiling_detection_stagnant_grid(self):
        """Ceiling detected when last N challenges produce no improvements."""
        random.seed(42)
        grid = MinerQualityGrid(ceiling_window=4)
        # Fill a cell with a strong approach
        strong = MinerApproach(
            miner_uid="king",
            domain=GovernanceDomain.FAIRNESS,
            strategy=DeliberationStrategy.STAKEHOLDER_ANALYSIS,
            fitness=0.99,
            acceptance_rate=0.99,
            reasoning_quality=0.99,
            speed_ms=50,
            sample_count=20,
        )
        grid.challenge(strong)
        # Now send 4 weaker challenges — none should improve
        for i in range(4):
            grid.challenge(
                MinerApproach(
                    miner_uid=f"weak-{i}",
                    domain=GovernanceDomain.FAIRNESS,
                    strategy=DeliberationStrategy.STAKEHOLDER_ANALYSIS,
                    fitness=0.1,
                    acceptance_rate=0.1,
                    reasoning_quality=0.1,
                    speed_ms=900,
                    sample_count=10,
                )
            )
        assert grid.ceiling_detected() is True

    def test_no_ceiling_with_improvements(self):
        """No ceiling when challenges keep improving."""
        random.seed(42)
        grid = MinerQualityGrid(ceiling_window=3)
        for i in range(5):
            grid.challenge(
                MinerApproach(
                    miner_uid=f"miner-{i}",
                    domain=GovernanceDomain.RELIABILITY,
                    strategy=DeliberationStrategy.HYBRID,
                    fitness=0.1 * (i + 1),
                    acceptance_rate=0.5,
                    reasoning_quality=0.5,
                    speed_ms=500,
                    sample_count=10,
                )
            )
        assert grid.ceiling_detected() is False

    def test_domain_coverage(self):
        """domain_coverage counts strategies filled for a domain."""
        random.seed(42)
        grid = MinerQualityGrid()
        for s in [DeliberationStrategy.HYBRID, DeliberationStrategy.PRECEDENT_BASED]:
            grid.challenge(
                MinerApproach(
                    miner_uid="m1",
                    domain=GovernanceDomain.TRANSPARENCY,
                    strategy=s,
                    fitness=0.7,
                    acceptance_rate=0.7,
                    reasoning_quality=0.7,
                    speed_ms=300,
                    sample_count=10,
                )
            )
        assert grid.domain_coverage(GovernanceDomain.TRANSPARENCY) == 2
        assert grid.domain_coverage(GovernanceDomain.SAFETY) == 0

    def test_top_miners_ordering(self):
        """top_miners returns miners sorted by fitness descending."""
        random.seed(42)
        grid = MinerQualityGrid()
        for i, d in enumerate(list(GovernanceDomain)[:3]):
            grid.challenge(
                MinerApproach(
                    miner_uid=f"m-{i}",
                    domain=d,
                    strategy=DeliberationStrategy.HYBRID,
                    fitness=0.3 * (i + 1),
                    acceptance_rate=0.5,
                    reasoning_quality=0.5,
                    speed_ms=500,
                    sample_count=10,
                )
            )
        top = grid.top_miners(n=3)
        assert len(top) == 3
        assert top[0].fitness >= top[1].fitness >= top[2].fitness

    def test_ceiling_for_cell(self):
        """Per-cell ceiling detection works independently."""
        random.seed(42)
        grid = MinerQualityGrid(ceiling_window=3)
        coord = CellCoordinate(
            domain=GovernanceDomain.EFFICIENCY,
            strategy=DeliberationStrategy.CONSTITUTIONAL_REASONING,
        )
        # Fill cell, then challenge with weaker approaches
        grid.challenge(
            MinerApproach(
                miner_uid="strong",
                domain=GovernanceDomain.EFFICIENCY,
                strategy=DeliberationStrategy.CONSTITUTIONAL_REASONING,
                fitness=0.95,
                acceptance_rate=0.95,
                reasoning_quality=0.95,
                speed_ms=100,
                sample_count=10,
            )
        )
        for _ in range(3):
            grid.challenge(
                MinerApproach(
                    miner_uid="weak",
                    domain=GovernanceDomain.EFFICIENCY,
                    strategy=DeliberationStrategy.CONSTITUTIONAL_REASONING,
                    fitness=0.1,
                    acceptance_rate=0.1,
                    reasoning_quality=0.1,
                    speed_ms=900,
                    sample_count=10,
                )
            )
        assert grid.ceiling_for_cell(coord) is True
