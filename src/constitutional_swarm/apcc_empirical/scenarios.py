"""Typed APCC-1 empirical attack catalog and anti-vacuous runner."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Mapping, Protocol

from constitutional_swarm.apcc_empirical.adapters import (
    AuthorityObservation,
    Capability,
    DurableSnapshot,
    ScenarioExecutionError,
    TrialStimulus,
    native_evidence_for_variant,
)
from constitutional_swarm.apcc_empirical.contract import ATTACK_IDS


BASELINE_IDS = tuple(f"B{index}" for index in range(7))


class ScenarioOutcome(StrEnum):
    COMPROMISED = "compromised"
    FAIL_CLOSED = "fail-closed"
    RECOVERED = "recovered"
    BLOCKED = "blocked"


class ScenarioCatalogError(ValueError):
    """Raised for an ambiguous, incomplete, or vacuous scenario catalog."""


@dataclass(frozen=True, slots=True)
class ScenarioSpec:
    attack_id: str
    variant_id: str
    capabilities: frozenset[Capability]
    expected: Mapping[str, ScenarioOutcome]

    def __post_init__(self) -> None:
        object.__setattr__(self, "capabilities", frozenset(self.capabilities))
        object.__setattr__(self, "expected", MappingProxyType(dict(self.expected)))


class ScenarioAdapter(Protocol):
    baseline_id: str
    capabilities: frozenset[Capability]

    def execute(self, stimulus: TrialStimulus) -> AuthorityObservation: ...

    def snapshot(self) -> DurableSnapshot: ...


@dataclass(frozen=True, slots=True)
class ScenarioResult:
    outcome: ScenarioOutcome
    control: AuthorityObservation | None
    attack: AuthorityObservation | None
    before_attack: DurableSnapshot | None
    after_attack: DurableSnapshot | None
    attack_payload_differs: bool
    attack_evidence_differs: bool
    blocked_capabilities: frozenset[Capability]


_VARIANTS: dict[str, tuple[str, ...]] = {
    attack_id: (f"{attack_id}:default",) for attack_id in ATTACK_IDS
}
_VARIANTS.update(
    {
        "validator-crash": (
            "validator-crash:validator-crash",
            "validator-crash:verifier-crash",
        ),
        "stale-cache": (
            "stale-cache:status-replay",
            "stale-cache:status-wrong-certificate",
            "stale-cache:status-fresh-nonce",
        ),
        "predecessor-replacement-race": (
            "predecessor-replacement-race:supersession-current",
            "predecessor-replacement-race:supersession-stale",
        ),
        "actor-revocation-race": (
            "actor-revocation-race:revoked",
            "actor-revocation-race:status-expired",
        ),
        "workflow-revocation-race": (
            "workflow-revocation-race:revoked",
            "workflow-revocation-race:status-expired",
        ),
        "input-substitution": ("input-substitution:input-digest",),
        "output-substitution": ("output-substitution:output-digest",),
        "certificate-truncation": (
            "certificate-truncation:payload-digest",
            "certificate-truncation:envelope-digest",
        ),
        "missing-proof": ("missing-proof:absent",),
    }
)
REQUIRED_VARIANTS = frozenset(
    variant for variants in _VARIANTS.values() for variant in variants
)


_OPERATIONAL_CAPABILITIES: dict[str, frozenset[Capability]] = {
    "actor-revocation-race": frozenset(
        {Capability.DURABLE_SNAPSHOT, Capability.REVOCATION, Capability.CURRENT_STATUS}
    ),
    "workflow-revocation-race": frozenset(
        {Capability.DURABLE_SNAPSHOT, Capability.REVOCATION, Capability.CURRENT_STATUS}
    ),
    "predecessor-replacement-race": frozenset(
        {
            Capability.DURABLE_SNAPSHOT,
            Capability.SUPERSESSION,
            Capability.CURRENT_STATUS,
        }
    ),
    "response-loss-and-retry": frozenset(
        {Capability.DURABLE_SNAPSHOT, Capability.RECOVERY}
    ),
    "validator-crash": frozenset(
        {Capability.DURABLE_SNAPSHOT, Capability.REOPEN, Capability.RECOVERY}
    ),
    "authority-store-transaction-failure": frozenset(
        {Capability.DURABLE_SNAPSHOT, Capability.RECOVERY}
    ),
    "outbox-failure": frozenset(
        {Capability.DURABLE_SNAPSHOT, Capability.OUTBOX, Capability.RECOVERY}
    ),
    "recovery-import": frozenset({Capability.DURABLE_SNAPSHOT, Capability.RECOVERY}),
    "legacy-completion-promotion": frozenset(
        {Capability.DURABLE_SNAPSHOT, Capability.ARTIFACT_VISIBILITY}
    ),
    "stale-cache": frozenset({Capability.DURABLE_SNAPSHOT, Capability.CURRENT_STATUS}),
}


def _capabilities_for(attack_id: str) -> frozenset[Capability]:
    return _OPERATIONAL_CAPABILITIES.get(
        attack_id, frozenset({Capability.DURABLE_SNAPSHOT})
    )


_B2_DENIES = {"malicious-scheduler", "policy-update-race"}
_B4_COMPROMISES = {"concurrent-double-commit"}


def _expected_for(attack_id: str) -> Mapping[str, ScenarioOutcome]:
    required = _capabilities_for(attack_id)
    operational = required != frozenset({Capability.DURABLE_SNAPSHOT})
    result: dict[str, ScenarioOutcome] = {}
    for baseline in ("B0", "B1", "B2", "B3", "B4"):
        if operational:
            result[baseline] = ScenarioOutcome.BLOCKED
        elif baseline in {"B0", "B1"}:
            result[baseline] = ScenarioOutcome.COMPROMISED
        elif baseline == "B2":
            result[baseline] = (
                ScenarioOutcome.FAIL_CLOSED
                if attack_id in _B2_DENIES
                else ScenarioOutcome.COMPROMISED
            )
        elif baseline == "B3":
            result[baseline] = ScenarioOutcome.COMPROMISED
        else:
            result[baseline] = (
                ScenarioOutcome.COMPROMISED
                if attack_id in _B4_COMPROMISES
                else ScenarioOutcome.FAIL_CLOSED
            )
    result["B5"] = ScenarioOutcome.BLOCKED
    result["B6"] = ScenarioOutcome.BLOCKED
    return result


def default_scenario_catalog() -> tuple[ScenarioSpec, ...]:
    catalog = tuple(
        ScenarioSpec(
            attack_id,
            variant_id,
            _capabilities_for(attack_id),
            _expected_for(attack_id),
        )
        for attack_id in ATTACK_IDS
        for variant_id in _VARIANTS[attack_id]
    )
    validate_scenario_catalog(catalog)
    return catalog


def validate_scenario_catalog(catalog: tuple[ScenarioSpec, ...]) -> None:
    seen: set[str] = set()
    attacks: set[str] = set()
    for spec in catalog:
        if spec.attack_id not in ATTACK_IDS:
            raise ScenarioCatalogError(f"unknown attack {spec.attack_id!r}")
        if spec.variant_id in seen:
            raise ScenarioCatalogError(f"duplicate scenario {spec.variant_id!r}")
        if spec.variant_id not in REQUIRED_VARIANTS:
            raise ScenarioCatalogError(f"unknown scenario variant {spec.variant_id!r}")
        seen.add(spec.variant_id)
        attacks.add(spec.attack_id)
        if not spec.capabilities:
            raise ScenarioCatalogError("scenario capability mapping cannot be vacuous")
        if set(spec.expected) != set(BASELINE_IDS):
            raise ScenarioCatalogError("scenario must declare every B0-B6 outcome")
        if (
            len(set(spec.expected.values())) == 1
            and next(iter(spec.expected.values())) is not ScenarioOutcome.BLOCKED
        ):
            raise ScenarioCatalogError("scenario outcome mapping cannot be vacuous")
        if spec.capabilities != _capabilities_for(spec.attack_id):
            raise ScenarioCatalogError("scenario capability mapping is not canonical")
        if dict(spec.expected) != dict(_expected_for(spec.attack_id)):
            raise ScenarioCatalogError("scenario outcome mapping is not canonical")
        if spec.expected["B5"] is not ScenarioOutcome.BLOCKED:
            raise ScenarioCatalogError("B5 must remain BLOCKED")
        native_evidence_for_variant(spec.variant_id)
    if attacks != set(ATTACK_IDS):
        raise ScenarioCatalogError("catalog must cover exactly the 32 source attacks")
    if seen != set(REQUIRED_VARIANTS):
        raise ScenarioCatalogError("catalog must cover exactly the mandatory variants")


class ScenarioRunner:
    """Run a matched valid control first when the adapter can observe the case."""

    def run(
        self,
        spec: ScenarioSpec,
        adapter: ScenarioAdapter,
        *,
        control: TrialStimulus,
        attack: TrialStimulus,
    ) -> ScenarioResult:
        if control.attack_id is not None or attack.attack_id != spec.attack_id:
            raise ScenarioCatalogError("control/attack identity mismatch")
        expected_attack = native_evidence_for_variant(spec.variant_id)
        if attack.evidence != expected_attack:
            raise ScenarioCatalogError(
                "attack native evidence mutation is not canonical"
            )
        evidence_differs = attack.evidence != control.evidence
        payload_differs = attack.payload != control.payload
        if not evidence_differs:
            raise ScenarioCatalogError("attack mutation is vacuous")
        if attack.capabilities != spec.capabilities:
            raise ScenarioCatalogError("attack capabilities do not match scenario spec")
        missing = spec.capabilities - adapter.capabilities
        if missing:
            return ScenarioResult(
                ScenarioOutcome.BLOCKED,
                None,
                None,
                None,
                None,
                payload_differs,
                evidence_differs,
                frozenset(missing),
            )
        control_observation: AuthorityObservation | None = None
        before: DurableSnapshot | None = None
        try:
            control_observation = adapter.execute(control)
            if control_observation.authoritative_outcome != "committed":
                raise ScenarioCatalogError("matched valid control did not commit")
            before = adapter.snapshot()
            attack_observation = adapter.execute(attack)
            after = adapter.snapshot()
        except ScenarioExecutionError as error:
            error.control = control_observation
            error.before_attack = before
            try:
                error.after_attack = adapter.snapshot()
            except Exception:
                error.after_attack = None
            raise
        outcome = (
            ScenarioOutcome.COMPROMISED
            if attack_observation.authoritative_outcome == "committed"
            else ScenarioOutcome.FAIL_CLOSED
        )
        return ScenarioResult(
            outcome,
            control_observation,
            attack_observation,
            before,
            after,
            payload_differs,
            evidence_differs,
            frozenset(),
        )
