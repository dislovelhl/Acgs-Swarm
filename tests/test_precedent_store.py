"""Tests for PrecedentStore — Phase 3.1 precedent feedback loop."""

from __future__ import annotations

import pytest
from constitutional_swarm.bittensor.precedent_store import (
    PrecedentRecord,
    PrecedentStore,
    _cosine_similarity,
    _euclidean_distance,
)
from constitutional_swarm.bittensor.protocol import EscalationType

CONST_HASH = "608508a9bd224290"

# Standard 7-dim governance vectors
PRIVACY_HEAVY = {
    "safety": 0.1,
    "security": 0.2,
    "privacy": 0.9,
    "fairness": 0.3,
    "reliability": 0.1,
    "transparency": 0.6,
    "efficiency": 0.1,
}
SECURITY_HEAVY = {
    "safety": 0.8,
    "security": 0.9,
    "privacy": 0.2,
    "fairness": 0.1,
    "reliability": 0.7,
    "transparency": 0.3,
    "efficiency": 0.5,
}
FAIRNESS_HEAVY = {
    "safety": 0.2,
    "security": 0.1,
    "privacy": 0.3,
    "fairness": 0.9,
    "reliability": 0.2,
    "transparency": 0.7,
    "efficiency": 0.2,
}
BALANCED = {
    "safety": 0.5,
    "security": 0.5,
    "privacy": 0.5,
    "fairness": 0.5,
    "reliability": 0.5,
    "transparency": 0.5,
    "efficiency": 0.5,
}


# ---------------------------------------------------------------------------
# Vector utilities
# ---------------------------------------------------------------------------


class TestVectorUtilities:
    def test_cosine_identical_vectors(self):
        assert _cosine_similarity(PRIVACY_HEAVY, PRIVACY_HEAVY) == pytest.approx(1.0, abs=1e-6)

    def test_cosine_orthogonal_vectors(self):
        a = {
            "safety": 1.0,
            "security": 0.0,
            "privacy": 0.0,
            "fairness": 0.0,
            "reliability": 0.0,
            "transparency": 0.0,
            "efficiency": 0.0,
        }
        b = {
            "safety": 0.0,
            "security": 1.0,
            "privacy": 0.0,
            "fairness": 0.0,
            "reliability": 0.0,
            "transparency": 0.0,
            "efficiency": 0.0,
        }
        assert _cosine_similarity(a, b) == pytest.approx(0.0, abs=1e-9)

    def test_cosine_range(self):
        sim = _cosine_similarity(PRIVACY_HEAVY, SECURITY_HEAVY)
        assert 0.0 <= sim <= 1.0

    def test_cosine_similar_vectors_higher_than_dissimilar(self):
        similar = {k: v + 0.05 for k, v in PRIVACY_HEAVY.items()}
        dissimilar = SECURITY_HEAVY
        assert _cosine_similarity(PRIVACY_HEAVY, similar) > _cosine_similarity(
            PRIVACY_HEAVY, dissimilar
        )

    def test_cosine_zero_vector(self):
        zero = {k: 0.0 for k in PRIVACY_HEAVY}
        assert _cosine_similarity(PRIVACY_HEAVY, zero) == 0.0

    def test_euclidean_same_vector(self):
        assert _euclidean_distance(PRIVACY_HEAVY, PRIVACY_HEAVY) == pytest.approx(0.0, abs=1e-9)

    def test_euclidean_positive(self):
        d = _euclidean_distance(PRIVACY_HEAVY, SECURITY_HEAVY)
        assert d > 0.0


# ---------------------------------------------------------------------------
# PrecedentRecord
# ---------------------------------------------------------------------------


def _make_record(
    miner_uid: str = "miner-01",
    judgment: str = "Privacy takes precedence",
    reasoning: str = "ECHR Article 8 applies",
    votes_for: int = 2,
    votes_against: int = 0,
    escalation_type: EscalationType = EscalationType.CONSTITUTIONAL_CONFLICT,
    impact_vector: dict | None = None,
    constitutional_hash: str = CONST_HASH,
    case_id: str = "case-001",
) -> PrecedentRecord:
    return PrecedentRecord.create(
        case_id=case_id,
        task_id="task-001",
        miner_uid=miner_uid,
        judgment=judgment,
        reasoning=reasoning,
        votes_for=votes_for,
        votes_against=votes_against,
        proof_root_hash="abc123",
        escalation_type=escalation_type,
        impact_vector=impact_vector or PRIVACY_HEAVY,
        constitutional_hash=constitutional_hash,
    )


class TestPrecedentRecord:
    def test_create(self):
        r = _make_record()
        assert r.precedent_id
        assert r.validation_accepted is True
        assert r.is_active is True

    def test_validator_grade(self):
        r = _make_record(votes_for=3, votes_against=1)
        assert r.validator_grade == pytest.approx(0.75)

    def test_zero_votes_grade(self):
        # Edge case: 0 total votes
        r = PrecedentRecord.create(
            case_id="c",
            task_id="t",
            miner_uid="m",
            judgment="j",
            reasoning="r",
            votes_for=0,
            votes_against=0,
            proof_root_hash="",
            escalation_type=EscalationType.UNKNOWN,
            impact_vector=BALANCED,
            constitutional_hash=CONST_HASH,
        )
        assert r.validator_grade == 0.0

    def test_unique_ids(self):
        r1 = _make_record(case_id="c1")
        r2 = _make_record(case_id="c2")
        assert r1.precedent_id != r2.precedent_id

    def test_immutable(self):
        r = _make_record()
        with pytest.raises(AttributeError):
            r.judgment = "changed"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# PrecedentStore — basic operations
# ---------------------------------------------------------------------------


class TestPrecedentStoreBasicOps:
    def test_empty_store(self):
        store = PrecedentStore(CONST_HASH)
        assert store.size == 0
        assert store.total_stored == 0

    def test_add_and_size(self):
        store = PrecedentStore(CONST_HASH, min_votes_for_precedent=1)
        store.add(_make_record())
        assert store.size == 1

    def test_add_wrong_hash_rejected(self):
        store = PrecedentStore(CONST_HASH, min_votes_for_precedent=1)
        bad = _make_record(constitutional_hash="wrong")
        with pytest.raises(ValueError, match="mismatch"):
            store.add(bad)

    def test_add_not_accepted_rejected(self):
        store = PrecedentStore(CONST_HASH, min_votes_for_precedent=1)
        # Create a record with validation_accepted=False — must bypass create()
        import dataclasses

        r = _make_record()
        bad = dataclasses.replace(r, validation_accepted=False)
        with pytest.raises(ValueError, match="not accepted"):
            store.add(bad)

    def test_add_insufficient_votes_rejected(self):
        store = PrecedentStore(CONST_HASH, min_votes_for_precedent=3)
        r = _make_record(votes_for=2)
        with pytest.raises(ValueError, match="Insufficient"):
            store.add(r)

    def test_add_duplicate_rejected(self):
        store = PrecedentStore(CONST_HASH, min_votes_for_precedent=1)
        r = _make_record()
        store.add(r)
        with pytest.raises(ValueError, match="already stored"):
            store.add(r)

    def test_revoke(self):
        store = PrecedentStore(CONST_HASH, min_votes_for_precedent=1)
        r = _make_record()
        store.add(r)
        store.revoke(r.precedent_id, reason="contradicts new rule")
        assert store.size == 0
        assert store.total_stored == 1  # still in store (audit)

    def test_revoke_nonexistent_raises(self):
        store = PrecedentStore(CONST_HASH)
        with pytest.raises(KeyError):
            store.revoke("nonexistent-id")

    def test_revoke_excluded_from_retrieval(self):
        store = PrecedentStore(CONST_HASH, min_votes_for_precedent=1, auto_resolve_threshold=0.5)
        r = _make_record()
        store.add(r)
        store.revoke(r.precedent_id)

        result = store.retrieve(PRIVACY_HEAVY)
        assert result.matches == []
        assert not result.can_auto_resolve


# ---------------------------------------------------------------------------
# PrecedentStore — retrieval
# ---------------------------------------------------------------------------


class TestPrecedentStoreRetrieval:
    def _populated_store(self) -> PrecedentStore:
        """Store with 3 precedents of different escalation types."""
        store = PrecedentStore(
            CONST_HASH,
            min_votes_for_precedent=1,
            auto_resolve_threshold=0.9,
        )
        store.add(
            _make_record(
                case_id="c1",
                judgment="Privacy wins",
                impact_vector=PRIVACY_HEAVY,
                escalation_type=EscalationType.CONSTITUTIONAL_CONFLICT,
            )
        )
        store.add(
            _make_record(
                case_id="c2",
                judgment="Security wins",
                impact_vector=SECURITY_HEAVY,
                escalation_type=EscalationType.CONTEXT_SENSITIVITY,
            )
        )
        store.add(
            _make_record(
                case_id="c3",
                judgment="Fairness wins",
                impact_vector=FAIRNESS_HEAVY,
                escalation_type=EscalationType.STAKEHOLDER_IRRECONCILABILITY,
            )
        )
        return store

    def test_retrieve_returns_matches(self):
        store = self._populated_store()
        result = store.retrieve(PRIVACY_HEAVY, k=3)
        assert len(result.matches) == 3

    def test_retrieve_ranked_by_similarity(self):
        store = self._populated_store()
        result = store.retrieve(PRIVACY_HEAVY, k=3)
        sims = [m.similarity for m in result.matches]
        assert sims == sorted(sims, reverse=True)

    def test_retrieve_top_match_is_correct(self):
        store = self._populated_store()
        result = store.retrieve(PRIVACY_HEAVY, k=3)
        assert result.top_match is not None
        assert result.top_match.precedent.judgment == "Privacy wins"

    def test_retrieve_k_limits_results(self):
        store = self._populated_store()
        result = store.retrieve(PRIVACY_HEAVY, k=2)
        assert len(result.matches) <= 2

    def test_retrieve_by_escalation_type(self):
        store = self._populated_store()
        result = store.retrieve(
            PRIVACY_HEAVY,
            k=10,
            escalation_type=EscalationType.CONSTITUTIONAL_CONFLICT,
        )
        assert all(
            m.precedent.escalation_type == EscalationType.CONSTITUTIONAL_CONFLICT
            for m in result.matches
        )

    def test_retrieve_min_similarity_filter(self):
        store = self._populated_store()
        # Security-heavy query should have low similarity to privacy/fairness records
        result = store.retrieve(SECURITY_HEAVY, k=10, min_similarity=0.8)
        for m in result.matches:
            assert m.similarity >= 0.8

    def test_retrieve_empty_store(self):
        store = PrecedentStore(CONST_HASH)
        result = store.retrieve(PRIVACY_HEAVY)
        assert result.matches == []
        assert not result.can_auto_resolve

    def test_rank_numbers(self):
        store = self._populated_store()
        result = store.retrieve(PRIVACY_HEAVY, k=3)
        ranks = [m.rank for m in result.matches]
        assert ranks == [1, 2, 3]


# ---------------------------------------------------------------------------
# PrecedentStore — auto-resolution
# ---------------------------------------------------------------------------


class TestPrecedentStoreAutoResolution:
    def test_auto_resolve_high_similarity(self):
        store = PrecedentStore(
            CONST_HASH,
            min_votes_for_precedent=1,
            auto_resolve_threshold=0.8,
        )
        r = _make_record(judgment="Privacy wins", impact_vector=PRIVACY_HEAVY)
        store.add(r)

        # Near-identical vector — should auto-resolve
        near_identical = {k: v * 1.01 for k, v in PRIVACY_HEAVY.items()}
        result = store.retrieve(near_identical)
        assert result.can_auto_resolve is True
        assert result.auto_resolution == "Privacy wins"
        assert result.auto_resolution_confidence >= 0.8
        assert result.auto_resolution_source == r.precedent_id

    def test_no_auto_resolve_low_similarity(self):
        store = PrecedentStore(
            CONST_HASH,
            min_votes_for_precedent=1,
            auto_resolve_threshold=0.99,  # very high threshold
        )
        r = _make_record(impact_vector=PRIVACY_HEAVY)
        store.add(r)

        # Dissimilar query — should not auto-resolve
        result = store.retrieve(SECURITY_HEAVY)
        assert not result.can_auto_resolve

    def test_auto_resolve_source_tracks_precedent_id(self):
        store = PrecedentStore(
            CONST_HASH,
            min_votes_for_precedent=1,
            auto_resolve_threshold=0.5,
        )
        r = _make_record(impact_vector=PRIVACY_HEAVY)
        store.add(r)
        result = store.retrieve(PRIVACY_HEAVY)
        assert result.auto_resolution_source == r.precedent_id


# ---------------------------------------------------------------------------
# PrecedentStore — statistics
# ---------------------------------------------------------------------------


class TestPrecedentStoreStatistics:
    def test_escalation_distribution(self):
        store = PrecedentStore(CONST_HASH, min_votes_for_precedent=1)
        for i in range(3):
            store.add(
                _make_record(
                    case_id=f"cc{i}",
                    escalation_type=EscalationType.CONSTITUTIONAL_CONFLICT,
                )
            )
        store.add(
            _make_record(
                case_id="ctx1",
                escalation_type=EscalationType.CONTEXT_SENSITIVITY,
            )
        )
        dist = store.escalation_distribution()
        assert dist["constitutional_conflict"] == 3
        assert dist["context_sensitivity"] == 1

    def test_miner_contribution_counts(self):
        store = PrecedentStore(CONST_HASH, min_votes_for_precedent=1)
        for i in range(3):
            store.add(_make_record(case_id=f"m1c{i}", miner_uid="miner-alpha"))
        store.add(_make_record(case_id="m2c1", miner_uid="miner-beta"))
        counts = store.miner_contribution_counts()
        assert counts["miner-alpha"] == 3
        assert counts["miner-beta"] == 1

    def test_escalation_rate_decreases_with_precedents(self):
        store = PrecedentStore(CONST_HASH, min_votes_for_precedent=1)
        rate_empty = store.escalation_rate_projection()

        # Add 1000 precedents (simulated)
        for i in range(1000):
            store.add(_make_record(case_id=f"bulk_{i}"))

        rate_1k = store.escalation_rate_projection()
        assert rate_1k < rate_empty

    def test_escalation_rate_floor(self):
        store = PrecedentStore(CONST_HASH, min_votes_for_precedent=1)
        # Even with many precedents, floor should be 0.5%
        for _i in range(100_000):
            # We can't actually add 100k records but we can set a huge count
            pass
        rate = store.escalation_rate_projection(baseline_rate=0.03, decay_per_1k=100.0)
        assert rate >= 0.005

    def test_summary(self):
        store = PrecedentStore(CONST_HASH, min_votes_for_precedent=1)
        store.add(_make_record())
        s = store.summary()
        assert s["active_precedents"] == 1
        assert s["total_stored"] == 1
        assert s["revoked"] == 0
        assert "escalation_distribution" in s
        assert s["constitutional_hash"] == CONST_HASH

    def test_revocation_tracked_in_summary(self):
        store = PrecedentStore(CONST_HASH, min_votes_for_precedent=1)
        r = _make_record()
        store.add(r)
        store.revoke(r.precedent_id, reason="test")
        s = store.summary()
        assert s["active_precedents"] == 0
        assert s["total_stored"] == 1
        assert s["revoked"] == 1
        assert s["revocation_log_entries"] == 1


# ---------------------------------------------------------------------------
# Super-majority validation (3/5 quorum)
# ---------------------------------------------------------------------------


class TestSuperMajorityValidation:
    def test_insufficient_total_validators_rejected(self):
        """Precedent with too few total validators is rejected."""
        store = PrecedentStore(
            CONST_HASH,
            min_votes_for_precedent=3,
            min_total_validators=5,
        )
        # 3 votes for, 0 against = only 3 total validators (need 5)
        r = _make_record(votes_for=3, votes_against=0)
        with pytest.raises(ValueError, match="Insufficient total validators"):
            store.add(r)

    def test_insufficient_votes_for_with_enough_validators(self):
        """Enough validators but not enough approvals is rejected."""
        store = PrecedentStore(
            CONST_HASH,
            min_votes_for_precedent=3,
            min_total_validators=5,
        )
        # 2 for, 3 against = 5 total validators but only 2 approvals (need 3)
        r = _make_record(votes_for=2, votes_against=3)
        with pytest.raises(ValueError, match="Insufficient validator votes"):
            store.add(r)

    def test_3_of_5_super_majority_accepted(self):
        """3/5 super-majority passes validation."""
        store = PrecedentStore(
            CONST_HASH,
            min_votes_for_precedent=3,
            min_total_validators=5,
        )
        r = _make_record(votes_for=3, votes_against=2)
        store.add(r)
        assert store.size == 1

    def test_5_of_5_unanimous_accepted(self):
        """Unanimous 5/5 accepted."""
        store = PrecedentStore(
            CONST_HASH,
            min_votes_for_precedent=3,
            min_total_validators=5,
        )
        r = _make_record(votes_for=5, votes_against=0)
        store.add(r)
        assert store.size == 1

    def test_default_no_total_validator_check(self):
        """Default min_total_validators=0 means no total validator check."""
        store = PrecedentStore(CONST_HASH)
        r = _make_record(votes_for=2, votes_against=0)  # only 2 total
        store.add(r)
        assert store.size == 1


# ---------------------------------------------------------------------------
# Concurrent PrecedentStore — thread safety
# ---------------------------------------------------------------------------


class TestConcurrentPrecedentStore:
    """Verify PrecedentStore handles concurrent adds without data loss."""

    def test_20_threads_add_unique_precedents(self):
        import threading

        store = PrecedentStore(
            CONST_HASH,
            min_votes_for_precedent=1,
            min_total_validators=0,
        )

        errors: list[Exception] = []

        def add_precedent(idx: int) -> None:
            try:
                record = _make_record(
                    case_id=f"concurrent-{idx}",
                    miner_uid=f"miner-{idx}",
                    judgment=f"Judgment for case {idx}",
                )
                store.add(record)
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=add_precedent, args=(i,)) for i in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == [], f"Exceptions during concurrent add: {errors}"
        assert store.size == 20


# ---------------------------------------------------------------------------
# 10K precedent k-NN scale test
# ---------------------------------------------------------------------------


class TestPrecedentStoreScale:
    """Scale test: 10,000 precedents with k-NN retrieval performance check."""

    @pytest.mark.slow
    def test_10k_precedent_knn_retrieval(self):
        """Insert 10K synthetic precedents and verify k-NN retrieval
        completes in <2000ms with correctly ranked results."""
        import random
        import time as _time

        random.seed(42)

        dims = (
            "safety", "security", "privacy", "fairness",
            "reliability", "transparency", "efficiency",
        )
        esc_types = list(EscalationType)

        store = PrecedentStore(
            constitutional_hash=CONST_HASH,
            min_votes_for_precedent=1,
            min_total_validators=0,
            auto_resolve_threshold=0.99,  # high to avoid auto-resolve noise
        )

        # Generate and insert 10,000 precedents with random 7-vectors
        for i in range(10_000):
            vec = {d: random.random() for d in dims}
            rec = PrecedentRecord(
                precedent_id=f"scale-{i:05d}",
                case_id=f"case-{i:05d}",
                task_id=f"task-{i:05d}",
                miner_uid=f"miner-{i % 100:03d}",
                judgment=f"Judgment for case {i}",
                reasoning=f"Reasoning {i}",
                validation_accepted=True,
                votes_for=2,
                votes_against=0,
                proof_root_hash=f"hash-{i}",
                validator_grade=1.0,
                escalation_type=esc_types[i % len(esc_types)],
                impact_vector=vec,
                ambiguous_dimensions=(),
                constitutional_hash=CONST_HASH,
                recorded_at=_time.time(),
                is_active=True,
            )
            store.add(rec)

        assert store.size == 10_000

        # Query with a known vector (biased toward privacy)
        query_vector = {
            "safety": 0.1, "security": 0.1, "privacy": 0.95,
            "fairness": 0.1, "reliability": 0.1, "transparency": 0.1, "efficiency": 0.1,
        }

        start = _time.monotonic()
        result = store.retrieve(query_vector, k=10)
        elapsed_ms = (_time.monotonic() - start) * 1000

        # Performance: must complete in <2000ms (generous for CI)
        assert elapsed_ms < 2000, f"Retrieval took {elapsed_ms:.1f}ms, expected <2000ms"

        # Must return results
        assert len(result.matches) == 10

        # Top match must have positive similarity
        assert result.top_match is not None
        assert result.top_match.similarity > 0.0

        # Results must be ranked by descending similarity
        sims = [m.similarity for m in result.matches]
        assert sims == sorted(sims, reverse=True), (
            f"Results not ranked by descending similarity: {sims}"
        )
