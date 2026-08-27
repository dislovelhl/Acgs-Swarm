from __future__ import annotations

import ast
import inspect
from typing import Protocol, get_type_hints

from constitutional_swarm.apcc import codec, crypto, model, ports, verifier
from constitutional_swarm.apcc.ports import AuthorityStore


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


def _imports(module: object) -> set[str]:
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
    assert issubclass(AuthorityStore, Protocol)
    authority_operations = {
        name
        for name, member in AuthorityStore.__dict__.items()
        if not name.startswith("_") and callable(member)
    }
    assert authority_operations == {
        "stage_result",
        "read_commit_context",
        "atomic_commit",
        "replay_commit",
        "get_certificate",
        "current_status",
        "revoke",
        "supersede",
        "recover",
        "recover_outbox",
    }
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


def test_supersession_port_carries_a_new_atomic_proposal_and_replay_identity() -> None:
    assert set(inspect.get_annotations(ports.SupersessionRequest)) == {
        "old_certificate_digest",
        "new_proposal",
    }
    assert (
        get_type_hints(ports.SupersessionRequest)["new_proposal"]
        is ports.AtomicCommitRequest
    )
    assert {
        "commit_result",
        "old_certificate_digest",
        "new_certificate_digest",
        "outbox_event_id",
        "audit_event_id",
    } <= set(inspect.get_annotations(ports.SupersessionResult))
    assert (
        get_type_hints(ports.SupersessionResult)["commit_result"] is ports.CommitResult
    )


def test_ports_do_not_leak_runtime_rows_callbacks_or_repository_artifacts() -> None:
    source = inspect.getsource(ports).lower()
    for forbidden in ("sqlite", "postgres", "scheduler", "artifact", "callback"):
        assert forbidden not in source


def test_protocol_surface_exposes_only_models_codec_crypto_verifier_and_ports() -> None:
    assert hasattr(crypto, "domain_preimage")
    assert hasattr(crypto, "predecessor_root")
    assert hasattr(codec, "encode_payload")
    assert hasattr(verifier, "verify_historical")
    assert hasattr(verifier, "verify_current")
