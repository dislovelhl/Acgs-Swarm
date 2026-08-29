"""Linux controlled-boot primitives for APCC privileged processes."""

from __future__ import annotations

import ctypes
import os
import resource
import stat
import sys
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path


_PR_GET_DUMPABLE = 3
_PR_SET_DUMPABLE = 4
_PR_SET_NO_NEW_PRIVS = 38
_PR_GET_NO_NEW_PRIVS = 39


class IsolationUnavailable(RuntimeError):
    """The publishable Linux isolation profile could not be established."""


@dataclass(frozen=True, slots=True)
class ControlledBootResult:
    """Truthful scope of the controlled-boot evidence claim."""

    profile: str
    phase: ControlledBootPhase
    evidence: ControlledBootEvidence
    authority_source_consumed: bool
    controller_source_consumed: bool
    observer_ready: bool
    positive_assumptions: tuple[str, ...]
    residual_exclusions: tuple[str, ...]

    def __post_init__(self) -> None:
        if type(self.profile) is not str:
            raise TypeError("controlled-boot profile must be an exact string")
        if type(self.phase) is not ControlledBootPhase:
            raise TypeError("controlled-boot phase must be an exact enum")
        if type(self.evidence) is not ControlledBootEvidence:
            raise TypeError("controlled-boot evidence must be an exact enum")
        if any(
            type(value) is not bool
            for value in (
                self.authority_source_consumed,
                self.controller_source_consumed,
                self.observer_ready,
            )
        ):
            raise TypeError("controlled-boot flags must be exact booleans")
        for value in (self.positive_assumptions, self.residual_exclusions):
            if type(value) is not tuple or any(type(item) is not str for item in value):
                raise TypeError(
                    "controlled-boot claims must be tuples of exact strings"
                )
        if self.profile != "linux-controlled-boot-v1":
            raise ValueError("invalid controlled-boot profile")
        if not self.authority_source_consumed:
            raise ValueError("authority source must be consumed before TCB readiness")
        publishable_phase = self.phase in {
            ControlledBootPhase.SCHEDULER_STARTING_PUBLISHABLE,
            ControlledBootPhase.SCHEDULER_STARTED_PUBLISHABLE,
        }
        if (self.evidence is ControlledBootEvidence.PUBLISHABLE) != (
            self.phase is ControlledBootPhase.SCHEDULER_STARTED_PUBLISHABLE
        ):
            raise ValueError("controlled-boot phase/evidence mismatch")
        if publishable_phase and not self.controller_source_consumed:
            raise ValueError("publishable evidence requires consumed controller source")
        observer_phase = self.phase in {
            ControlledBootPhase.OBSERVER_READY,
            ControlledBootPhase.SCHEDULER_STARTING_PUBLISHABLE,
            ControlledBootPhase.SCHEDULER_STARTED_PUBLISHABLE,
        }
        if self.observer_ready != observer_phase:
            raise ValueError("controlled-boot observer readiness mismatch")
        if self.controller_source_consumed and self.phase in {
            ControlledBootPhase.AUTHORITY_READY,
            ControlledBootPhase.SCHEDULER_STARTING_NONPUBLISHABLE,
            ControlledBootPhase.SCHEDULER_STARTED_NONPUBLISHABLE,
        }:
            raise ValueError("controller source consumption contradicts boot phase")
        if not self.positive_assumptions or not self.residual_exclusions:
            raise ValueError("controlled-boot trust boundary must be explicit")

    @property
    def tcb_ready(self) -> bool:
        return self.phase in {
            ControlledBootPhase.SCHEDULER_STARTED_NONPUBLISHABLE,
            ControlledBootPhase.SCHEDULER_STARTED_PUBLISHABLE,
        }

    @property
    def publishable_evidence(self) -> bool:
        return self.evidence is ControlledBootEvidence.PUBLISHABLE


class ControlledBootPhase(StrEnum):
    AUTHORITY_READY = "authority_ready"
    OBSERVER_STARTING = "observer_starting"
    OBSERVER_READY = "observer_ready"
    SCHEDULER_STARTING_NONPUBLISHABLE = "scheduler_starting_nonpublishable"
    SCHEDULER_STARTED_NONPUBLISHABLE = "scheduler_started_nonpublishable"
    SCHEDULER_STARTING_PUBLISHABLE = "scheduler_starting_publishable"
    SCHEDULER_STARTED_PUBLISHABLE = "scheduler_started_publishable"
    CLOSING = "closing"
    FAILED = "failed"
    CLOSED = "closed"


class ControlledBootEvidence(StrEnum):
    NONPUBLISHABLE = "nonpublishable"
    PUBLISHABLE = "publishable"


CONTROLLED_BOOT_RESIDUAL_EXCLUSIONS = (
    "pre_existing_attacker",
    "root_or_cap_sys_ptrace",
    "denial_of_service",
)

CONTROLLED_BOOT_POSITIVE_ASSUMPTIONS = (
    "dedicated_trusted_supervisor_precedes_untrusted_scheduler",
    "privileged_children_use_verified_spawn_entrypoints",
    "supervisor_hardening_is_process_lifetime_irreversible",
)


def _prctl(option: int, value: int = 0) -> int:
    libc = ctypes.CDLL(None, use_errno=True)
    prctl = libc.prctl
    prctl.argtypes = [
        ctypes.c_int,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
    ]
    prctl.restype = ctypes.c_int
    result = int(prctl(option, value, 0, 0, 0))
    if result < 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    return result


def harden_current_process() -> None:
    """Set and verify the mandatory Linux process-isolation controls."""
    if sys.platform != "linux":
        raise IsolationUnavailable("ISOLATION_UNAVAILABLE: Linux is required")
    try:
        _prctl(_PR_SET_DUMPABLE, 0)
        if _prctl(_PR_GET_DUMPABLE) != 0:
            raise IsolationUnavailable("ISOLATION_UNAVAILABLE: dumpable verification")
        _prctl(_PR_SET_NO_NEW_PRIVS, 1)
        if _prctl(_PR_GET_NO_NEW_PRIVS) != 1:
            raise IsolationUnavailable(
                "ISOLATION_UNAVAILABLE: no-new-privileges verification"
            )
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        if resource.getrlimit(resource.RLIMIT_CORE) != (0, 0):
            raise IsolationUnavailable("ISOLATION_UNAVAILABLE: core limit verification")
    except IsolationUnavailable:
        raise
    except (AttributeError, OSError, ValueError) as error:
        raise IsolationUnavailable(
            "ISOLATION_UNAVAILABLE: Linux hardening failed"
        ) from error


def isolation_is_active() -> bool:
    """Read process controls without changing irreversible supervisor state."""
    if sys.platform != "linux":
        return False
    try:
        return (
            _prctl(_PR_GET_DUMPABLE) == 0
            and _prctl(_PR_GET_NO_NEW_PRIVS) == 1
            and resource.getrlimit(resource.RLIMIT_CORE) == (0, 0)
        )
    except (AttributeError, OSError, ValueError):
        return False


def consume_secret_file(
    location: str,
    *,
    maximum_bytes: int,
    label: str,
) -> bytearray:
    """Read and unlink one exact safe secret inode, then fsync its directory."""
    if type(location) is not str or not location or maximum_bytes <= 0:
        raise ValueError(f"invalid {label} source")
    path = Path(location)
    parent = path.parent
    name = path.name
    if not name or name in {".", ".."}:
        raise ValueError(f"invalid {label} source")
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | os.O_CLOEXEC
    directory = os.open(parent, directory_flags)
    descriptor = -1
    try:
        parent_metadata = os.fstat(directory)
        if (
            not stat.S_ISDIR(parent_metadata.st_mode)
            or parent_metadata.st_uid != os.geteuid()
            or stat.S_IMODE(parent_metadata.st_mode) & 0o022
        ):
            raise PermissionError(f"unsafe {label} parent directory")
        try:
            descriptor = os.open(
                name,
                os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=directory,
            )
        except FileNotFoundError as error:
            raise IsolationUnavailable(
                f"ISOLATION_UNAVAILABLE: {label} rebootstrap required"
            ) from error
        except OSError as error:
            raise PermissionError(f"unsafe {label} source") from error
        before = os.fstat(descriptor)
        path_before = os.stat(name, dir_fd=directory, follow_symlinks=False)
        if stat.S_IMODE(before.st_mode) != 0o600:
            raise PermissionError(f"{label} source must use mode 0600")
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or before.st_nlink != 1
            or (before.st_dev, before.st_ino)
            != (path_before.st_dev, path_before.st_ino)
        ):
            raise PermissionError(f"unsafe {label} source")
        raw = bytearray()
        while len(raw) <= maximum_bytes:
            chunk = os.read(descriptor, min(65_536, maximum_bytes + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
        if len(raw) > maximum_bytes:
            raise ValueError(f"{label} source is too large")
        after = os.fstat(descriptor)
        path_after = os.stat(name, dir_fd=directory, follow_symlinks=False)
        if (before.st_dev, before.st_ino, before.st_size) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
        ) or (after.st_dev, after.st_ino) != (path_after.st_dev, path_after.st_ino):
            raise PermissionError(f"{label} source changed during consumption")
        os.unlink(name, dir_fd=directory)
        if os.fstat(descriptor).st_nlink != 0:
            raise PermissionError(f"{label} exact inode was not consumed")
        os.fsync(directory)
        try:
            os.stat(name, dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise PermissionError(f"{label} source remains present")
        return raw
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(directory)


def erase_secret(secret: bytearray) -> None:
    """Best-effort overwrite of the mutable supervisor copy."""
    for index in range(len(secret)):
        secret[index] = 0
