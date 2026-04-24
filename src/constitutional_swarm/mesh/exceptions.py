"""Public exception types for the Constitutional Mesh package."""


class InsufficientPeersError(Exception):
    """Not enough peers available for validation."""


class DuplicateVoteError(Exception):
    """Peer already voted on this assignment."""


class UnauthorizedVoterError(Exception):
    """Voter is not assigned to this validation."""


class InvalidVoteSignatureError(Exception):
    """Vote signature is missing or does not match the registered agent key."""


class AssignmentSettledError(Exception):
    """Assignment is already settled; further votes are rejected."""


class RecoveredAssignmentError(AssignmentSettledError):
    """Assignment was already durably settled; replay is blocked."""


class MeshHaltedError(RuntimeError):
    """Mesh has been halted; all operations are blocked until resumed."""


class SettlementPersistenceError(RuntimeError):
    """Raised when a settled result cannot be persisted after freeze."""


class RemoteVoteReplayError(Exception):
    """Remote vote request reused a nonce inside the active replay window."""
