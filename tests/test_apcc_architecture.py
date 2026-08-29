from __future__ import annotations

import ast
import inspect
from dataclasses import FrozenInstanceError, replace
from types import ModuleType
from typing import get_args, get_type_hints

import pytest

from constitutional_swarm.apcc import codec, crypto, model, ports, verifier
from constitutional_swarm.apcc.ports import AuthorityReader, AuthorityStore
from constitutional_swarm.apcc.verifier import TrustRole
from tests.test_apcc_verifier import valid_vector


FORBIDDEN_IMPORTS = (
    "sqlite3",
    "psycopg",
    "sqlalchemy",
    "constitutional_swarm.artifact",
    "constitutional_swarm.compiler",
    "constitutional_swarm.execution",
    "constitutional_swarm.governed_commit",
    "constitutional_swarm.swarm",
)


def test_controlled_boot_result_rejects_impossible_publishable_state() -> None:
    from constitutional_swarm.authority_isolation import (
        CONTROLLED_BOOT_POSITIVE_ASSUMPTIONS,
        CONTROLLED_BOOT_RESIDUAL_EXCLUSIONS,
        ControlledBootEvidence,
        ControlledBootPhase,
        ControlledBootResult,
    )

    with pytest.raises(ValueError, match="phase/evidence mismatch"):
        ControlledBootResult(
            profile="linux-controlled-boot-v1",
            phase=ControlledBootPhase.SCHEDULER_STARTED_PUBLISHABLE,
            evidence=ControlledBootEvidence.NONPUBLISHABLE,
            authority_source_consumed=True,
            controller_source_consumed=True,
            observer_ready=True,
            positive_assumptions=CONTROLLED_BOOT_POSITIVE_ASSUMPTIONS,
            residual_exclusions=CONTROLLED_BOOT_RESIDUAL_EXCLUSIONS,
        )


def _imports(module: ModuleType) -> set[str]:
    tree = ast.parse(inspect.getsource(module))
    return {
        name
        for node in ast.walk(tree)
        for name in (
            [alias.name for alias in node.names]
            if isinstance(node, ast.Import)
            else [node.module]
            if isinstance(node, ast.ImportFrom) and node.module
            else []
        )
    }


def test_apcc_core_is_pure_and_has_no_scheduler_artifact_or_store_imports() -> None:
    for module in (model, codec, crypto, verifier, ports):
        assert not any(
            imported == forbidden or imported.startswith(f"{forbidden}.")
            for imported in _imports(module)
            for forbidden in FORBIDDEN_IMPORTS
        ), module.__name__


def test_authority_store_is_abstract_and_commit_id_lookup_is_store_global() -> None:
    assert getattr(AuthorityStore, "_is_protocol", False)
    authority_operations = {
        name
        for protocol in (AuthorityReader, AuthorityStore)
        for name, member in protocol.__dict__.items()
        if not name.startswith("_") and callable(member)
    }
    assert authority_operations == {
        "stage_result",
        "assemble_evidence",
        "propose_commit",
        "read_commit_context",
        "atomic_commit",
        "replay_commit",
        "get_certificate",
        "current_status",
        "current_status_batch",
        "logical_node_status_batch",
        "revoke",
        "supersede",
        "recover",
        "recover_outbox",
        "get_outbox_event",
        "read_logical_node",
    }
    assert get_type_hints(AuthorityStore)["authority_store_id"] is str
    assert "commit" not in authority_operations
    assert list(inspect.signature(AuthorityStore.get_certificate).parameters) == [
        "self",
        "commit_id",
    ]
    assert list(inspect.signature(AuthorityStore.atomic_commit).parameters) == [
        "self",
        "request",
    ]


def test_revoke_returns_typed_revocation_result_not_an_arbitrary_node_state() -> None:
    result_type = getattr(ports, "RevocationResult", None)
    assert result_type is not None
    assert set(inspect.get_annotations(result_type)) == {
        "scope",
        "target_id",
        "resulting_generation",
        "audit_event_id",
    }
    assert "node_state" not in inspect.get_annotations(result_type)
    assert get_type_hints(AuthorityStore.revoke)["return"] is result_type
    assert "workflow-scoped key" in (inspect.getdoc(ports.RevocationRequest) or "")
    assert set(ports.RevocationScope) == {
        ports.RevocationScope.CERTIFICATE,
        ports.RevocationScope.ACTOR,
        ports.RevocationScope.WORKFLOW,
    }


def test_revocation_scopes_have_non_overlapping_target_semantics() -> None:
    digest = "A" * 43
    certificate = ports.RevocationRequest(
        ports.RevocationScope.CERTIFICATE, "workflow-1", digest, "1", "reason"
    )
    actor = ports.RevocationRequest(
        ports.RevocationScope.ACTOR, "workflow-1", "agent-1", "1", "reason"
    )
    workflow = ports.RevocationRequest(
        ports.RevocationScope.WORKFLOW,
        "workflow-1",
        "workflow-1",
        "1",
        "reason",
    )
    assert certificate.target_id == digest
    assert actor.target_id == "agent-1"
    assert workflow.target_id == workflow.workflow_id
    with pytest.raises(ValueError, match="SHA-256 digest"):
        ports.RevocationRequest(
            ports.RevocationScope.CERTIFICATE,
            "workflow-1",
            "workflow-1",
            "1",
            "reason",
        )
    with pytest.raises(ValueError, match="must equal workflow_id"):
        ports.RevocationRequest(
            ports.RevocationScope.WORKFLOW,
            "workflow-1",
            digest,
            "1",
            "reason",
        )


def test_commit_request_declares_store_global_idempotency_namespaces() -> None:
    request_contract = inspect.getdoc(ports.AtomicCommitRequest) or ""
    assert "authority-store-global" in request_contract
    assert "commit_id" in request_contract
    assert "nonce" in request_contract


def test_exact_replay_result_has_no_second_authority_identity() -> None:
    """The replay port returns the original authoritative tuple verbatim."""
    annotation = get_type_hints(AuthorityStore.replay_commit)["return"]
    assert annotation is ports.CommitResult
    authoritative_fields = {
        "decision",
        "certificate_payload_bytes",
        "certificate_envelope_bytes",
        "certificate_digest",
        "audit_event_id",
    }
    assert authoritative_fields <= set(inspect.get_annotations(ports.CommitResult))


def test_get_certificate_is_explicitly_the_exact_envelope_bytes_port() -> None:
    assert get_type_hints(AuthorityStore.get_certificate)["return"] == bytes | None
    assert (
        "envelope bytes"
        in (inspect.getdoc(AuthorityStore.get_certificate) or "").lower()
    )


def test_supersession_port_has_three_statically_discriminated_branches() -> None:
    assert set(inspect.get_annotations(ports.SupersessionRequest)) == {
        "old_certificate_digest",
        "new_proposal",
    }
    assert (
        get_type_hints(ports.SupersessionRequest)["new_proposal"]
        is ports.AtomicCommitRequest
    )
    branches = set(get_args(ports.SupersessionResult))
    assert branches == {
        ports.SupersessionCommitted,
        ports.SupersessionDenied,
        ports.SupersessionConflicted,
    }
    assert set(inspect.get_annotations(ports.SupersessionCommitted)) == {
        "commit_result",
        "old_certificate_digest",
        "new_certificate_digest",
        "replacement_edge_id",
        "outbox_event_id",
        "kind",
    }
    for branch in (ports.SupersessionDenied, ports.SupersessionConflicted):
        assert set(inspect.get_annotations(branch)) == {
            "commit_result",
            "old_certificate_digest",
            "kind",
        }
        assert not {
            "new_certificate_digest",
            "replacement_edge_id",
            "outbox_event_id",
            "audit_event_id",
        } & set(inspect.get_annotations(branch))


def test_runtime_and_public_bootstrap_configuration_are_portable_and_separate() -> None:
    assert set(ports.AuthoritySigningRole) == {
        ports.AuthoritySigningRole.COMMIT,
        ports.AuthoritySigningRole.STATUS,
    }
    assert getattr(ports.AuthorityKeyProvider, "_is_protocol", False)
    assert getattr(ports.AuthorityClock, "_is_protocol", False)
    assert getattr(ports.AuthorityOutboxSink, "_is_protocol", False)
    assert set(inspect.get_annotations(ports.AuthorityRuntime)) == {
        "key_provider",
        "clock",
        "outbox_sink",
    }
    config_fields = set(inspect.get_annotations(ports.APCCAuthorityConfig))
    assert config_fields == {
        "authority_store_id",
        "producer_trust",
        "policy_trust",
        "registry_trust",
        "commit_trust",
        "status_trust",
        "freshness",
    }
    assert not any(
        forbidden in name.lower()
        for name in config_fields
        for forbidden in ("private", "seed", "signer", "runtime", "clock", "sink")
    )


def test_signer_free_reader_exposes_only_read_operations() -> None:
    reader_operations = {
        name
        for name, member in AuthorityReader.__dict__.items()
        if not name.startswith("_") and callable(member)
    }
    assert reader_operations == {
        "read_commit_context",
        "read_logical_node",
        "replay_commit",
        "get_certificate",
        "get_outbox_event",
    }
    assert not reader_operations & {
        "stage_result",
        "assemble_evidence",
        "propose_commit",
        "atomic_commit",
        "current_status",
        "revoke",
        "supersede",
        "recover",
        "recover_outbox",
    }


def _authority_config() -> ports.APCCAuthorityConfig:
    bindings = valid_vector().trust.bindings
    by_role = {
        role: tuple(binding for binding in bindings if binding.role is role)
        for role in TrustRole
    }
    return ports.APCCAuthorityConfig(
        "store-1",
        by_role[TrustRole.PRODUCER],
        by_role[TrustRole.POLICY],
        by_role[TrustRole.REGISTRY],
        by_role[TrustRole.COMMIT][0],
        by_role[TrustRole.STATUS][0],
        ports.StatusFreshnessPolicy("5000", "1000"),
    )


def test_public_authority_config_requires_five_distinct_exactly_scoped_roles() -> None:
    config = _authority_config()
    assert tuple(binding.role for binding in config.trust_bindings) == tuple(TrustRole)
    assert len({binding.public_key for binding in config.trust_bindings}) == 5
    with pytest.raises(FrozenInstanceError):
        setattr(config, "authority_store_id", "other")
    with pytest.raises(ValueError, match="producer"):
        replace(config, producer_trust=())
    with pytest.raises(ValueError, match="authority_store_id"):
        replace(config, commit_trust=replace(config.commit_trust, scope=("other",)))
    with pytest.raises(ValueError, match="reused"):
        replace(
            config,
            status_trust=replace(
                config.status_trust,
                key_id=config.commit_trust.key_id,
                public_key=config.commit_trust.public_key,
            ),
        )


@pytest.mark.parametrize(
    ("maximum", "lifetime"),
    (("0", "1"), ("1", "0"), ("01", "1"), ("1", "2"), ("-1", "1")),
)
def test_status_freshness_policy_is_positive_canonical_and_bounds_issuance(
    maximum: str, lifetime: str
) -> None:
    with pytest.raises(ValueError):
        ports.StatusFreshnessPolicy(maximum, lifetime)


def test_ports_do_not_leak_runtime_rows_callbacks_or_repository_artifacts() -> None:
    source = inspect.getsource(ports).lower()
    for forbidden in ("sqlite", "postgres", "scheduler", "artifact", "callback"):
        assert forbidden not in source


def test_protocol_surface_exposes_only_models_codec_crypto_verifier_and_ports() -> None:
    assert hasattr(crypto, "domain_preimage")
    assert hasattr(crypto, "predecessor_root")
    assert hasattr(codec, "encode_payload")
    assert hasattr(verifier, "verify_historical")
    assert hasattr(verifier, "verify_causal_closure")
    assert hasattr(verifier, "verify_current")


def test_core_has_no_backend_specific_linearization_primitives() -> None:
    source = "\n".join(
        inspect.getsource(module).lower()
        for module in (model, codec, crypto, verifier, ports)
    )
    for backend_detail in (
        "begin immediate",
        "select for update",
        "unique index",
        "sqlite",
        "postgres",
    ):
        assert backend_detail not in source


def test_removed_ambiguous_state_aliases_are_not_public() -> None:
    assert not hasattr(model, "NodeLifecycle")
    assert not hasattr(model, "NodeState")


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("profile", 1),
        ("phase", "authority_ready"),
        ("evidence", "nonpublishable"),
        ("authority_source_consumed", 1),
        ("controller_source_consumed", 0),
        ("observer_ready", 0),
        ("positive_assumptions", ["assumption"]),
        ("residual_exclusions", ("valid", 1)),
    ],
)
def test_controlled_boot_result_enforces_exact_runtime_types(field, value) -> None:
    from constitutional_swarm.authority_isolation import (
        CONTROLLED_BOOT_POSITIVE_ASSUMPTIONS,
        CONTROLLED_BOOT_RESIDUAL_EXCLUSIONS,
        ControlledBootEvidence,
        ControlledBootPhase,
        ControlledBootResult,
    )

    values = {
        "profile": "linux-controlled-boot-v1",
        "phase": ControlledBootPhase.AUTHORITY_READY,
        "evidence": ControlledBootEvidence.NONPUBLISHABLE,
        "authority_source_consumed": True,
        "controller_source_consumed": False,
        "observer_ready": False,
        "positive_assumptions": CONTROLLED_BOOT_POSITIVE_ASSUMPTIONS,
        "residual_exclusions": CONTROLLED_BOOT_RESIDUAL_EXCLUSIONS,
    }
    values[field] = value
    with pytest.raises((TypeError, ValueError)):
        ControlledBootResult(**values)
