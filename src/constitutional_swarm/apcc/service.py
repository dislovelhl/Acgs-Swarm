"""The sole typed entry point for APCC authority-producing operations.

The service deliberately contains no persistence policy.  It validates that the
ephemeral authority keys match the public configuration and delegates each state
transition exactly once. Request-dependent validation remains inside the store's
guarded transaction so replay and equivocation precedence cannot be bypassed.
"""

from __future__ import annotations

from .ports import (
    APCCAuthorityConfig,
    AssembleEvidenceRequest,
    AssembleEvidenceResult,
    AtomicCommitRequest,
    AuthorityExecutionStore,
    AuthorityRuntime,
    AuthoritySigningRole,
    CommitResult,
    ProposeCommitRequest,
    ProposeCommitResult,
    StageResultRequest,
    StageResultResult,
)


class APCCCommitService:
    """Validate authority identity and delegate through execution capability."""

    def __init__(
        self,
        *,
        store: AuthorityExecutionStore,
        config: APCCAuthorityConfig,
        runtime: AuthorityRuntime,
    ) -> None:
        if store.authority_store_id != config.authority_store_id:
            raise ValueError("authority store ID does not match APCC configuration")
        self._store = store
        self._config = config
        self._runtime = runtime
        self._validate_runtime_authority_keys()

    def _validate_runtime_authority_keys(self) -> None:
        pairs = (
            (AuthoritySigningRole.COMMIT, self._config.commit_trust),
            (AuthoritySigningRole.STATUS, self._config.status_trust),
        )
        for role, binding in pairs:
            try:
                public_key = self._runtime.key_provider.public_key(role, binding.key_id)
            except Exception as error:
                raise ValueError("authority signer is unavailable") from error
            if bytes(public_key) != binding.public_key:
                raise ValueError("authority signer does not match configured trust")

    def stage_result(self, request: StageResultRequest) -> StageResultResult:
        return self._store.stage_result(request)

    def assemble_evidence(
        self, request: AssembleEvidenceRequest
    ) -> AssembleEvidenceResult:
        return self._store.assemble_evidence(request)

    def propose_commit(self, request: ProposeCommitRequest) -> ProposeCommitResult:
        return self._store.propose_commit(request)

    def commit(self, request: AtomicCommitRequest) -> CommitResult:
        return self._store.atomic_commit(request)
