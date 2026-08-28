from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from constitutional_swarm.apcc_empirical.adapters import (
    AuthorityObservation,
    BaselineBlocked,
    Capability,
    DurableSnapshot,
    ScenarioExecutionError,
    TrialStimulus,
    create_baseline_adapter,
    native_evidence_for_variant,
)
from constitutional_swarm.apcc_empirical.scenarios import (
    BASELINE_IDS,
    REQUIRED_VARIANTS,
    ScenarioCatalogError,
    ScenarioOutcome,
    ScenarioRunner,
    default_scenario_catalog,
    validate_scenario_catalog,
)


def test_catalog_covers_exact_source_attacks_and_mandatory_subvariants() -> None:
    catalog = default_scenario_catalog()
    assert len({item.attack_id for item in catalog}) == 32
    assert {item.variant_id for item in catalog}.issuperset(REQUIRED_VARIANTS)
    assert all(item.capabilities for item in catalog)
    assert all(set(item.expected) == set(BASELINE_IDS) for item in catalog)
    assert all(item.expected["B5"] is ScenarioOutcome.BLOCKED for item in catalog)


def test_catalog_rejects_duplicate_unknown_and_vacuous_mappings() -> None:
    catalog = list(default_scenario_catalog())
    with pytest.raises(ScenarioCatalogError, match="duplicate"):
        validate_scenario_catalog((*catalog, catalog[0]))
    with pytest.raises(ScenarioCatalogError, match="unknown attack"):
        validate_scenario_catalog(
            (replace(catalog[0], attack_id="invented"), *catalog[1:])
        )
    with pytest.raises(ScenarioCatalogError, match="unknown scenario variant"):
        validate_scenario_catalog(
            (replace(catalog[0], variant_id="missing-proof:invented"), *catalog[1:])
        )
    vacuous = replace(
        catalog[0],
        expected={baseline: ScenarioOutcome.FAIL_CLOSED for baseline in BASELINE_IDS},
    )
    with pytest.raises(ScenarioCatalogError, match="vacuous"):
        validate_scenario_catalog((vacuous, *catalog[1:]))


def test_runner_executes_matched_control_first_and_proves_attack_differs(
    tmp_path: Path,
) -> None:
    spec = next(
        item
        for item in default_scenario_catalog()
        if item.variant_id == "missing-proof:absent"
    )
    adapter = create_baseline_adapter("B0", tmp_path / "b0.db")
    result = ScenarioRunner().run(
        spec,
        adapter,
        control=TrialStimulus.control(b"signed-proof"),
        attack=TrialStimulus.attack(
            b"no-proof",
            attack_id=spec.attack_id,
            capabilities=spec.capabilities,
            evidence=native_evidence_for_variant(spec.variant_id),
        ),
    )
    assert result.control is not None
    assert result.before_attack is not None
    assert result.after_attack is not None
    assert result.control.authoritative_outcome == "committed"
    assert result.attack_payload_differs
    assert result.before_attack.accepted_count == 1
    assert result.after_attack.accepted_count == 2
    assert result.outcome is ScenarioOutcome.COMPROMISED
    assert spec.expected["B0"] is ScenarioOutcome.COMPROMISED


def test_runner_reports_payload_and_evidence_mutation_truth_independently(
    tmp_path: Path,
) -> None:
    spec = next(
        item
        for item in default_scenario_catalog()
        if item.variant_id == "policy-update-race:default"
    )
    adapter = create_baseline_adapter("B0", tmp_path / "same-payload.db")
    result = ScenarioRunner().run(
        spec,
        adapter,
        control=TrialStimulus.control(b"same-bytes"),
        attack=TrialStimulus.attack(
            b"same-bytes",
            attack_id=spec.attack_id,
            capabilities=spec.capabilities,
            evidence=native_evidence_for_variant(spec.variant_id),
        ),
    )
    assert result.attack_payload_differs is False
    assert result.attack_evidence_differs is True


def test_runner_rejects_attack_capabilities_that_do_not_match_spec(
    tmp_path: Path,
) -> None:
    spec = next(iter(default_scenario_catalog()))
    adapter = create_baseline_adapter("B0", tmp_path / "capability.db")
    with pytest.raises(ScenarioCatalogError, match="attack capabilities"):
        ScenarioRunner().run(
            spec,
            adapter,
            control=TrialStimulus.control(b"control"),
            attack=TrialStimulus.attack(
                b"attack",
                attack_id=spec.attack_id,
                capabilities=frozenset(Capability),
                evidence=native_evidence_for_variant(spec.variant_id),
            ),
        )


def test_runner_reports_missing_capability_as_blocked_not_passed(
    tmp_path: Path,
) -> None:
    spec = next(
        item
        for item in default_scenario_catalog()
        if Capability.REVOCATION in item.capabilities
    )
    adapter = create_baseline_adapter("B0", tmp_path / "blocked.db")
    result = ScenarioRunner().run(
        spec,
        adapter,
        control=TrialStimulus.control(b"control"),
        attack=TrialStimulus.attack(
            b"attack",
            attack_id=spec.attack_id,
            capabilities=spec.capabilities,
            evidence=native_evidence_for_variant(spec.variant_id),
        ),
    )
    assert result.outcome is ScenarioOutcome.BLOCKED
    assert result.blocked_capabilities == frozenset(
        {Capability.REVOCATION, Capability.CURRENT_STATUS}
    )
    assert result.before_attack == result.after_attack


def test_b6_cells_are_blocked_without_public_durable_observation_boundary() -> None:
    catalog = default_scenario_catalog()
    assert all(spec.expected["B6"] is ScenarioOutcome.BLOCKED for spec in catalog)
    assert all(Capability.DURABLE_SNAPSHOT in spec.capabilities for spec in catalog)


def test_runner_does_not_downgrade_execution_failures_to_blocked() -> None:
    spec = next(iter(default_scenario_catalog()))

    class FailingAdapter:
        baseline_id = "B0"
        capabilities = spec.capabilities

        def execute(self, stimulus: TrialStimulus) -> AuthorityObservation:
            del stimulus
            raise BaselineBlocked("unexpected runtime failure")

        def snapshot(self) -> DurableSnapshot:
            raise AssertionError("not reached")

    with pytest.raises(BaselineBlocked, match="unexpected runtime failure"):
        ScenarioRunner().run(
            spec,
            FailingAdapter(),
            control=TrialStimulus.control(b"control"),
            attack=TrialStimulus.attack(
                b"attack",
                attack_id=spec.attack_id,
                capabilities=spec.capabilities,
                evidence=native_evidence_for_variant(spec.variant_id),
            ),
        )


def test_runner_retains_control_and_before_evidence_on_harness_error() -> None:
    spec = next(iter(default_scenario_catalog()))
    committed = AuthorityObservation("committed", None, None, True, None, None)
    before = DurableSnapshot(1, 0, 0, None, None, None, 0)

    class FailingAdapter:
        baseline_id = "B0"
        capabilities = spec.capabilities
        calls = 0

        def execute(self, stimulus: TrialStimulus) -> AuthorityObservation:
            del stimulus
            self.calls += 1
            if self.calls == 1:
                return committed
            raise ScenarioExecutionError("fault injection failed")

        def snapshot(self) -> DurableSnapshot:
            return before

    with pytest.raises(
        ScenarioExecutionError, match="fault injection failed"
    ) as caught:
        ScenarioRunner().run(
            spec,
            FailingAdapter(),
            control=TrialStimulus.control(b"control"),
            attack=TrialStimulus.attack(
                b"attack",
                attack_id=spec.attack_id,
                capabilities=spec.capabilities,
                evidence=native_evidence_for_variant(spec.variant_id),
            ),
        )
    assert caught.value.control == committed
    assert caught.value.before_attack == before


def test_catalog_contains_no_expected_defense_execution_oracle() -> None:
    catalog = default_scenario_catalog()
    assert not hasattr(catalog[0], "defenses")
    assert "defenses" not in TrialStimulus.__dataclass_fields__


def test_expected_outcome_labels_never_enter_baseline_execution(tmp_path: Path) -> None:
    spec = next(
        item
        for item in default_scenario_catalog()
        if item.variant_id == "invalid-signature:default"
    )
    relabeled = replace(
        spec,
        expected={baseline: ScenarioOutcome.RECOVERED for baseline in BASELINE_IDS},
    )
    outcomes = []
    for index, candidate in enumerate((spec, relabeled)):
        result = ScenarioRunner().run(
            candidate,
            create_baseline_adapter("B4", tmp_path / f"labels-{index}.db"),
            control=TrialStimulus.control(b"control"),
            attack=TrialStimulus.attack(
                b"attack",
                attack_id=candidate.attack_id,
                capabilities=candidate.capabilities,
                evidence=native_evidence_for_variant(candidate.variant_id),
            ),
        )
        outcomes.append(result.outcome)
    assert outcomes == [ScenarioOutcome.FAIL_CLOSED, ScenarioOutcome.FAIL_CLOSED]


def test_every_executable_baseline_result_matches_actual_named_mechanism(
    tmp_path: Path,
) -> None:
    for scenario_index, spec in enumerate(default_scenario_catalog()):
        for baseline_id in BASELINE_IDS[:5]:
            adapter = create_baseline_adapter(
                baseline_id,
                tmp_path / f"{scenario_index}-{baseline_id}.db",
            )
            result = ScenarioRunner().run(
                spec,
                adapter,
                control=TrialStimulus.control(b"control"),
                attack=TrialStimulus.attack(
                    b"attack",
                    attack_id=spec.attack_id,
                    capabilities=spec.capabilities,
                    evidence=native_evidence_for_variant(spec.variant_id),
                ),
            )
            assert result.outcome is spec.expected[baseline_id], (
                spec.variant_id,
                baseline_id,
                result.outcome,
            )
