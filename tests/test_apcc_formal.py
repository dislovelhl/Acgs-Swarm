from __future__ import annotations

import importlib.util
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / "specs" / "apcc.tla"
CAUSAL_SPEC = ROOT / "specs" / "apcc_causal.tla"
MULTITENANT_SPEC = ROOT / "specs" / "apcc_multitenant.tla"
CONFIGS = (
    "apcc_safety.cfg",
    "apcc_liveness.cfg",
    "apcc_witness_valid_chain.cfg",
    "apcc_witness_exact_replay.cfg",
    "apcc_witness_stale_rejection.cfg",
    "apcc_witness_revocation.cfg",
    "apcc_witness_recovery.cfg",
    "apcc_ablation_guard_reread.cfg",
    "apcc_ablation_supersession.cfg",
    "apcc_ablation_status_window.cfg",
    "apcc_ablation_attempt_guard.cfg",
    "apcc_ablation_revocation_closure.cfg",
    "apcc_ablation_propagation_fence.cfg",
    "apcc_ablation_recovery_authority.cfg",
    "apcc_ablation_supersession_nonretroactivity.cfg",
    "apcc_witness_invalid_authorization.cfg",
    "apcc_witness_invalid_receipt.cfg",
    "apcc_witness_status_binding.cfg",
    "apcc_ablation_authorization_evidence.cfg",
    "apcc_ablation_receipt_evidence.cfg",
    "apcc_ablation_status_binding.cfg",
    "apcc_witness_legacy_status.cfg",
    "apcc_ablation_legacy_status.cfg",
    "apcc_causal_safety.cfg",
    "apcc_causal_witness.cfg",
    "apcc_causal_ablation.cfg",
    "apcc_multitenant_safety.cfg",
    "apcc_multitenant_witness.cfg",
    "apcc_multitenant_nonce_ablation.cfg",
    "apcc_multitenant_actor_ablation.cfg",
    "apcc_multitenant_target_witness.cfg",
    "apcc_multitenant_target_ablation.cfg",
)


def _runner_module():
    path = ROOT / "scripts" / "run_apcc_tlc.py"
    spec = importlib.util.spec_from_file_location("run_apcc_tlc", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_apcc_spec_contains_frozen_state_dimensions_actions_and_properties() -> None:
    source = SPEC.read_text()
    for token in (
        '"UNSEEN"',
        '"RESULT_STAGED"',
        '"EVIDENCE_ASSEMBLED"',
        '"COMMIT_PENDING"',
        'Nodes == {"n1", "n2", "n3"}',
        'Agents == {"agent1", "agent2"}',
        'c = "p3" -> "p2"',
        "Parent2(c)",
        "Ancestors(c)",
        "Snapshot(c)",
        "CommitContextValid(c)",
        "LinRecord(c)",
        "SupRequest(old, new, id)",
        "CanonicalSupRequest",
        "ConflictingSupRequest",
        "supHistory",
        "replayHistory",
        "recoveryHistory",
        "revocationHistory",
        "dispHistory",
        "StatusExpiry(c)",
        "MaxStaleness",
        "ExactReplay",
        "Equivocation",
        "AtomicCommit",
        "SupersessionEdge",
        "EffectiveRevoked",
        "RecoverLostResponse",
        "ValidStableProposalEventuallyCommits",
        "NoUnauthorizedCommit",
        "NoInvalidReceiptCommit",
        "NoStalePolicyCommit",
        "NoStaleAuthorityCommit",
        "NoRevokedActorCommit",
        "NoStaleWorkflowCommit",
        "NoInvalidPredecessorCommit",
        "NoCrossAttemptReplay",
        "NoCrossWorkflowReplay",
        "NoCrossNodeReplay",
        "NoAuthorityFromRecovery",
        "NoAuthorityFromStaging",
        "NoAuthorityFromOutbox",
        "NoAuthorityFromLegacyStatus",
        "EffectiveRevocationClosure",
        "DownstreamAuthorityConsistency",
        "AtomicSupersession",
        "RevocationPropagationIsRecoverable",
        "IssuedStatusHasBoundedResidualValidity",
        "authorizationValid",
        "receiptValid",
        "certAuthorized",
        "certReceiptValid",
        "StatusView",
        "StatusAccepts",
        "statusChecks",
        '"PREVALIDATED_CURRENT", "PREDECESSOR_SUPERSEDED",',
        '"GUARDED_REJECT_PREDECESSOR_REPLACED">>',
    ):
        assert token in source
    for forbidden_alias in (
        "AtomicVisibility ==",
        "ReplayIdentity ==",
        "ConflictRecording ==",
        "NoManufacturedRecoveryAuthority ==",
    ):
        assert forbidden_alias not in source
    assert "PolicyEpoch(c) == 1" in source
    assert 'Attempt(c) == IF c \\in {"p1r", "denied"}' in source
    assert 'c \\in {"p1r", "stale"} -> "p1"' in source
    assert 's.life["stale"] = "COMMIT_PENDING"' in source
    assert "StaleRejectionIsolation ==" not in source
    predecessor_start = source.index("NoInvalidPredecessorCommit ==")
    predecessor_end = source.index("NoCrossAttemptReplay ==", predecessor_start)
    predecessor_definition = source[predecessor_start:predecessor_end]
    assert 's.outcome["stale"] = "DENIED"' in predecessor_definition
    assert 's.rejectReason["stale"] = "PREDECESSOR_REPLACED"' in predecessor_definition
    assert (
        'Attempt("stale") = s.attempt[CandidateNode("stale")]' in predecessor_definition
    )
    assert 'CandidateLifecycle == {"EXECUTING", "RESULT_STAGED",' in source
    assert 'RequestOutcomes == {"NONE", "COMMITTED", "DENIED", "CONFLICTED"}' in source
    assert "! .life" not in source
    for terminal_outcome in (
        '!.life[c] = "COMMITTED"',
        '!.life[c] = "DENIED"',
        '!.life[c] = "CONFLICTED"',
    ):
        assert terminal_outcome not in source
    for token in (
        "decisionRecord",
        "certificateRecord",
        "OutputDigest(c)",
        "certificateSequence",
        "statusCertificateSequence",
        "statusActorGeneration",
        "statusWorkflowGeneration",
        "statusTrustGeneration",
        "statusSignerRole",
        "legacyCompletion",
        "legacyStatus",
        "legacyAuth",
        "AttemptLegacyAuthority",
        "WitnessLegacyStatusBlockedNotReached",
    ):
        assert token in source


def test_companion_models_cover_causal_and_multitenant_obligations() -> None:
    causal = CAUSAL_SPEC.read_text()
    for token in (
        "BoundedIndependentCausalVerification",
        "MalformedResolver",
        "EdgeFieldMismatch",
        "DigestMismatch",
        "CycleOrAlias",
        "DepthExceeded",
        "CountExceeded",
        "BytesExceeded",
        "WitnessCausalCoverageNotReached",
        "worklist",
        "visited",
        "activePath",
        "resolvedEnvelope",
        "sixFieldsMatch",
        "depthUsed",
        "certificateCount",
        "totalBytes",
        "ResolverMissing",
        "ResolverError",
        "InvalidReturnedValue",
    ):
        assert token in causal
    assert "IndependentValid" not in causal
    assert 'result[x] = "ACCEPT" => IndependentValid(x)' not in causal
    multitenant = MULTITENANT_SPEC.read_text()
    for token in (
        'Workflows == {"shared-id", "workflow2"}',
        'Actors == {"shared-id"}',
        "NonceUniqueness",
        "ActorRevocationWorkflowScope",
        "actorRevoked",
        "globalNonceOwner",
        "WitnessMultitenantIsolationNotReached",
        "RevocationTargetSeparation",
        'RevocationScopes == {"CERTIFICATE", "ACTOR", "WORKFLOW"}',
        "WitnessRevocationTargetsNotReached",
    ):
        assert token in multitenant


def test_named_obligations_use_independent_history_and_snapshot_semantics() -> None:
    source = SPEC.read_text()
    required_fragments = {
        "NoCrossAttemptReplay": ("s.linHistory", "r[10] = r[11]"),
        "EffectiveRevocationClosure": (
            "s.revocationHistory",
            "ExpectedRevocationSet(r)",
        ),
        "SupersessionNonretroactivity": (
            "s.supHistory",
            "s.certpred[c] = r.certpredBefore[c]",
        ),
        "NoAuthorityFromRecovery": ("s.recoveryHistory", "r[2] = r[3]"),
        "RecoveryDoesNotPromoteUnverifiedState": ("s.recovered", "s.supDecision"),
        "RevocationPropagationIsRecoverable": (
            "s.revocationHistory",
            "s.propagationDone",
        ),
    }
    for name, fragments in required_fragments.items():
        start = source.index(f"{name} ==")
        end = source.find("\n\n", start)
        definition = source[start : end if end != -1 else len(source)]
        assert all(fragment in definition for fragment in fragments), name
    assert "EffectiveRevocationClosure == EffectiveRevoked" not in source
    assert (
        "NoAuthorityFromRecovery == RecoveryDoesNotPromoteUnverifiedState" not in source
    )


def test_apcc_configs_separate_safety_liveness_and_each_nonvacuity_witness() -> None:
    runner = _runner_module()
    for name in CONFIGS:
        assert (ROOT / "specs" / name).is_file()
    assert (
        "PROPERTY ValidStableProposalEventuallyCommits"
        in (ROOT / "specs" / "apcc_liveness.cfg").read_text()
    )
    assert (
        "PROPERTY RevocationEventuallyPropagates"
        in (ROOT / "specs" / "apcc_liveness.cfg").read_text()
    )
    for name, expected in runner.EXPECTED_WITNESS.items():
        source = (ROOT / "specs" / name).read_text()
        assert "Expected result: TLC exit 12" in source
        assert f"INVARIANT {expected}" in source
    for name in CONFIGS:
        assert "CHECK_DEADLOCK FALSE" not in (ROOT / "specs" / name).read_text()
        assert "CONSTANT Ablation" in (ROOT / "specs" / name).read_text()
    liveness = (ROOT / "specs" / "apcc_liveness.cfg").read_text()
    formal_source = SPEC.read_text()
    for predicate_name in ("StableProposal(c)", "DenialReady(c)", "ConflictReady(c)"):
        assert predicate_name in formal_source
    for property_name in (
        "DeniedProposalEventuallyReturnsDenial",
        "ConflictingProposalEventuallyReturnsConflict",
        "OutboxIntentEventuallyDelivered",
        "ResponseLossEventuallyRecovers",
    ):
        assert f"PROPERTY {property_name}" in liveness


def test_each_witness_config_is_bound_to_its_exact_expected_invariant() -> None:
    runner = _runner_module()
    assert set(runner.EXPECTED_WITNESS) < set(CONFIGS)
    for config, expected in runner.EXPECTED_WITNESS.items():
        source = (ROOT / "specs" / config).read_text()
        assert f"INVARIANT {expected}" in source
        others = set(runner.EXPECTED_WITNESS.values()) - {expected}
        for other in others:
            assert f"INVARIANT {other}" not in source
        wrong = next(iter(others))
        wrong_output = (
            f"Error: Invariant {wrong} is violated.\n"
            "The behavior up to this point is:\nState 1: <Initial predicate>"
        )
        assert not runner.classify_result(12, wrong_output, expected)
    assert set(runner.CONFIG_MODULE) == set(CONFIGS)
    assert runner.CONFIG_MODULE["apcc_causal_safety.cfg"] == "apcc_causal"
    assert runner.CONFIG_MODULE["apcc_multitenant_safety.cfg"] == "apcc_multitenant"
    assert runner.EXPECTED_WITNESS["apcc_witness_legacy_status.cfg"] == (
        "WitnessLegacyStatusBlockedNotReached"
    )
    assert runner.EXPECTED_WITNESS["apcc_ablation_legacy_status.cfg"] == (
        "NoAuthorityFromLegacyStatus"
    )


def test_apcc_runner_pins_tlc_and_classifies_safety_and_witness_results() -> None:
    runner = _runner_module()
    assert runner.TLC_JAR_SHA256 == (
        "936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88"
    )
    assert runner.TLC_VERSION_LINE == "TLC2 Version 2.19 of 08 August 2024"
    assert runner.classify_result(
        0, "Model checking completed. No error has been found.", None
    )
    assert runner.classify_result(
        12,
        "Error: Invariant WitnessRecoveryNotReached is violated.\n"
        "The behavior up to this point is:\nState 1: <Initial predicate>",
        "WitnessRecoveryNotReached",
    )
    mismatched = (
        "Error: Invariant WitnessRecoveryNotReached is violated.\n"
        "The behavior up to this point is:\nState 1: <Initial predicate>"
    )
    assert not runner.classify_result(12, mismatched, "WitnessExactReplayNotReached")
    unexpected_deadlock = (
        "Error: Invariant WitnessRecoveryNotReached is violated.\n"
        "Error: The behavior up to this point is:\n"
        "Error: Deadlock reached.\nState 1: <Initial predicate>"
    )
    assert not runner.classify_result(
        12, unexpected_deadlock, "WitnessRecoveryNotReached"
    )
    unexpected_temporal = (
        "Error: Invariant WitnessRecoveryNotReached is violated.\n"
        "Error: The behavior up to this point is:\n"
        "Error: Temporal properties were violated.\nState 1: <Initial predicate>"
    )
    assert not runner.classify_result(
        12, unexpected_temporal, "WitnessRecoveryNotReached"
    )
    indented_unexpected_error = (
        "Error: Invariant WitnessRecoveryNotReached is violated.\n"
        "Error: The behavior up to this point is:\n"
        "  Error: Deadlock reached.\nState 1: <Initial predicate>"
    )
    assert not runner.classify_result(
        12, indented_unexpected_error, "WitnessRecoveryNotReached"
    )
    assert "-deadlock" not in Path(runner.__file__).read_text()
