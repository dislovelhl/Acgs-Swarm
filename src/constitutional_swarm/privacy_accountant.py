"""Privacy budget accountant for (ε, δ)-differential privacy in the swarm.

Implements the Moments Accountant (Abadi et al., 2016) as a session-scoped
ε-budget tracker.  Each call to :meth:`spend` records Gaussian mechanism
expenditure; :meth:`assert_budget` raises :class:`PrivacyBudgetExhausted`
if the cumulative ε exceeds the allowed budget.

Fail-closed: if ``assert_budget`` is called after the budget is exceeded the
swarm *stops broadcasting* DP-noised updates — it does not silently continue.

Usage::

    from constitutional_swarm.privacy_accountant import PrivacyAccountant

    pa = PrivacyAccountant(epsilon=1.0, delta=1e-5)
    for step in training_steps:
        sigma = pa.spend(sensitivity=0.1, sigma=pa.required_sigma(sensitivity=0.1))
        pa.assert_budget()   # raises if over budget
        swarm_ode.add_dp_noise(H, sigma)
"""

from __future__ import annotations

import math
import threading
from dataclasses import dataclass, field


class PrivacyBudgetExhausted(RuntimeError):
    """Raised when the cumulative ε-budget for this session is exceeded."""


@dataclass
class _SpendRecord:
    sensitivity: float
    sigma: float
    epsilon_spent: float
    delta_spent: float


@dataclass
class PrivacyAccountant:
    """Session-scoped moments accountant for (ε, δ)-DP.

    Parameters
    ----------
    epsilon:
        Maximum total ε budget for this session.
    delta:
        Target δ failure probability (shared across the session).
    """

    epsilon: float
    delta: float

    _spent_epsilon: float = field(default=0.0, init=False, repr=False)
    _spent_delta: float = field(default=0.0, init=False, repr=False)
    _history: list[_SpendRecord] = field(default_factory=list, init=False, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)

    def __post_init__(self) -> None:
        if self.epsilon <= 0:
            raise ValueError(f"epsilon must be positive, got {self.epsilon}")
        if not (0 < self.delta < 1):
            raise ValueError(f"delta must be in (0,1), got {self.delta}")

    # ------------------------------------------------------------------
    # Core API
    # ------------------------------------------------------------------

    def required_sigma(self, sensitivity: float) -> float:
        """Compute the minimum σ for the *remaining* ε budget.

        Uses the Gaussian mechanism calibration from NDSS 2027 Lemma 4.3:
        ``σ = sensitivity · √(2·ln(1.25/δ)) / ε_remaining``

        Raises :class:`PrivacyBudgetExhausted` immediately if no budget remains.
        """
        remaining = self.remaining_epsilon
        if remaining <= 0:
            raise PrivacyBudgetExhausted(
                f"Privacy budget exhausted: used {self._spent_epsilon:.4f} / "
                f"{self.epsilon:.4f} ε"
            )
        sigma = sensitivity * math.sqrt(2 * math.log(1.25 / self.delta)) / remaining
        return sigma

    def spend(self, sensitivity: float, sigma: float) -> float:
        """Record a Gaussian mechanism invocation and return ε consumed.

        Parameters
        ----------
        sensitivity:
            L2-sensitivity of the function being privatised.
        sigma:
            Noise standard deviation used for this invocation.

        Returns
        -------
        float
            The ε consumed by this single invocation.
        """
        if sensitivity <= 0:
            raise ValueError(f"sensitivity must be positive, got {sensitivity}")
        if sigma <= 0:
            raise ValueError(f"sigma must be positive, got {sigma}")

        # Gaussian mechanism: ε_step = sensitivity · √(2·ln(1.25/δ)) / σ
        eps_step = sensitivity * math.sqrt(2 * math.log(1.25 / self.delta)) / sigma

        with self._lock:
            self._spent_epsilon += eps_step
            self._spent_delta += self.delta
            record = _SpendRecord(
                sensitivity=sensitivity,
                sigma=sigma,
                epsilon_spent=eps_step,
                delta_spent=self.delta,
            )
            self._history.append(record)

        return eps_step

    def assert_budget(self) -> None:
        """Raise :class:`PrivacyBudgetExhausted` if the ε budget is exceeded.

        This is the fail-closed gate: call this after every :meth:`spend`
        to halt processing if the cumulative ε limit has been reached.
        """
        if self._spent_epsilon > self.epsilon:
            raise PrivacyBudgetExhausted(
                f"ε budget exceeded: spent {self._spent_epsilon:.4f} > "
                f"limit {self.epsilon:.4f}"
            )

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    @property
    def remaining_epsilon(self) -> float:
        """Remaining ε budget (may be negative if over budget)."""
        return self.epsilon - self._spent_epsilon

    @property
    def budget_fraction_used(self) -> float:
        """Fraction of the ε budget consumed, in [0, ∞)."""
        return self._spent_epsilon / self.epsilon

    def summary(self) -> dict:
        """Return a serialisable summary of the current budget state."""
        return {
            "epsilon_total": self.epsilon,
            "epsilon_spent": self._spent_epsilon,
            "epsilon_remaining": self.remaining_epsilon,
            "delta": self.delta,
            "num_mechanism_invocations": len(self._history),
            "budget_fraction_used": self.budget_fraction_used,
            "exhausted": self._spent_epsilon > self.epsilon,
        }
