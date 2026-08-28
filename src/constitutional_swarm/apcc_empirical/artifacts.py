"""Crash-safe append-only artifacts for APCC-1 empirical runs."""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import stat
import tempfile
import ctypes
import errno
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Mapping, Sequence, TypeAlias, cast

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError

from constitutional_swarm.apcc_empirical.contract import (
    ExperimentMatrix,
    canonical_json_bytes,
    load_matrix,
    load_raw_result,
    planned_ablation_performance_runs,
    planned_ablation_trials,
    planned_attack_trials,
    planned_formal_runs,
    planned_parser_trials,
    planned_performance_runs,
    planned_race_recovery_trials,
    planned_storage_runs,
    planned_timing_trials,
)


REVIEWED_MATRIX_SHA256 = (
    "f919446ca5fae99d2297161959e0017250c402e542275a369b55b8281d158721"
)
REVIEWED_SCHEMA_SHA256 = (
    "7d869fd99381cd0ec65a1e9780ddf82b9a0700f11319c371f7b909a60a44fbae"
)

_RUN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_ARTIFACT_FILES = (
    "manifest.json",
    "matrix.v1.json",
    "raw-result.schema.json",
    "raw.jsonl",
)
_MAX_RAW_BYTES = 1 << 30
_MAX_METADATA_BYTES = 1 << 20
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_RENAME_NOREPLACE = 1
_MANIFEST_FIELDS = frozenset(
    {
        "environment",
        "environment_id",
        "git_sha",
        "matrix_revision",
        "matrix_sha256",
        "raw_record_count",
        "raw_sha256",
        "raw_size_bytes",
        "schema_sha256",
        "schema_version",
        "tool_versions",
        "trial_ids",
    }
)

_JsonValue: TypeAlias = (
    None | bool | int | float | str | list["_JsonValue"] | dict[str, "_JsonValue"]
)


class ArtifactViolation(ValueError):
    """Raised when an artifact is unsafe, incomplete, or non-canonical."""


@dataclass(frozen=True, slots=True)
class ArtifactRun:
    path: Path
    record_count: int
    raw_sha256: str
    manifest: Mapping[str, object]


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _require_owned(info: os.stat_result, *, name: str, directory: bool) -> None:
    expected = stat.S_ISDIR if directory else stat.S_ISREG
    if not expected(info.st_mode):
        raise ArtifactViolation(
            f"artifact {name} must be a {'directory' if directory else 'regular file'}"
        )
    if hasattr(os, "getuid") and info.st_uid != os.getuid():
        raise ArtifactViolation(f"artifact {name} has an unexpected owner")
    if info.st_mode & 0o022:
        raise ArtifactViolation(f"artifact {name} is group/other writable")


def _open_directory(path: Path, *, name: str) -> int:
    descriptor = -1
    try:
        descriptor = os.open(path, os.O_RDONLY | _DIRECTORY | _NOFOLLOW)
        _require_owned(os.fstat(descriptor), name=name, directory=True)
        return descriptor
    except ArtifactViolation:
        if descriptor >= 0:
            os.close(descriptor)
        raise
    except OSError as error:
        if descriptor >= 0:
            os.close(descriptor)
        raise ArtifactViolation(f"cannot open artifact {name}") from error


def _read_at(
    directory_fd: int,
    name: str,
    *,
    limit: int,
    require_private: bool = True,
) -> bytes:
    descriptor = -1
    try:
        descriptor = os.open(name, os.O_RDONLY | _NOFOLLOW, dir_fd=directory_fd)
        info = os.fstat(descriptor)
        _require_owned(info, name=name, directory=False)
        if require_private and stat.S_IMODE(info.st_mode) & 0o077:
            raise ArtifactViolation(f"artifact {name} is not private")
        stream = os.fdopen(descriptor, "rb")
        descriptor = -1
        with stream:
            raw = stream.read(limit + 1)
    except ArtifactViolation:
        if descriptor >= 0:
            os.close(descriptor)
        raise
    except OSError as error:
        if descriptor >= 0:
            os.close(descriptor)
        raise ArtifactViolation(f"cannot read artifact {name}") from error
    if len(raw) > limit:
        raise ArtifactViolation(f"artifact {name} exceeds bounded size")
    return raw


def _read_path(path: Path, *, name: str, limit: int) -> bytes:
    parent_fd = _open_directory(path.parent, name=f"{name} parent")
    try:
        try:
            return _read_at(parent_fd, path.name, limit=limit, require_private=False)
        except ArtifactViolation as error:
            raise ArtifactViolation(f"cannot read artifact {name}") from error
    finally:
        os.close(parent_fd)


def _write_at(directory_fd: int, name: str, raw: bytes) -> None:
    descriptor = -1
    try:
        descriptor = os.open(
            name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW,
            0o600,
            dir_fd=directory_fd,
        )
        stream = os.fdopen(descriptor, "wb")
        descriptor = -1
        with stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    except OSError as error:
        if descriptor >= 0:
            os.close(descriptor)
        raise ArtifactViolation(f"cannot write artifact {name}") from error


def _rename_noreplace(source_fd: int, source: str, target_fd: int, target: str) -> None:
    try:
        renameat2 = ctypes.CDLL(None, use_errno=True).renameat2
    except AttributeError as error:
        raise ArtifactViolation("atomic no-replace promotion is unavailable") from error
    renameat2.argtypes = (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    )
    renameat2.restype = ctypes.c_int
    result = renameat2(
        source_fd,
        os.fsencode(source),
        target_fd,
        os.fsencode(target),
        _RENAME_NOREPLACE,
    )
    if result == 0:
        return
    error_number = ctypes.get_errno()
    if error_number == errno.EEXIST:
        raise ArtifactViolation("artifact run already exists")
    if error_number in {errno.ENOSYS, errno.EINVAL, errno.ENOTSUP}:
        raise ArtifactViolation("atomic no-replace promotion is unavailable")
    raise ArtifactViolation("cannot atomically promote artifact run") from OSError(
        error_number, os.strerror(error_number)
    )


def _load_schema(raw: bytes) -> tuple[dict[str, object], Draft202012Validator]:
    if _sha256(raw) != REVIEWED_SCHEMA_SHA256:
        raise ArtifactViolation("artifact does not contain the exact reviewed schema")
    try:
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise TypeError("schema is not an object")
        Draft202012Validator.check_schema(value)
        validator = Draft202012Validator(value)
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, SchemaError) as error:
        raise ArtifactViolation("artifact schema is invalid") from error
    return value, validator


def _load_matrix_payload(raw: bytes) -> ExperimentMatrix:
    if _sha256(raw) != REVIEWED_MATRIX_SHA256:
        raise ArtifactViolation("artifact does not contain the exact reviewed matrix")
    with tempfile.TemporaryDirectory(prefix="apcc-matrix-") as temporary:
        path = Path(temporary) / "matrix.json"
        path.write_bytes(raw)
        try:
            return load_matrix(path)
        except ValueError as error:
            raise ArtifactViolation(
                "artifact matrix violates the reviewed contract"
            ) from error


@lru_cache(maxsize=4)
def frozen_planner_trial_ids(matrix: ExperimentMatrix) -> tuple[str, ...]:
    planners = (
        planned_attack_trials,
        planned_race_recovery_trials,
        planned_parser_trials,
        planned_timing_trials,
        planned_performance_runs,
        planned_ablation_performance_runs,
        planned_storage_runs,
        planned_ablation_trials,
        planned_formal_runs,
    )
    return tuple(run.trial_id for planner in planners for run in planner(matrix))


def _validate_planner_subsequence(
    matrix: ExperimentMatrix, trial_ids: Sequence[str]
) -> None:
    if len(set(trial_ids)) != len(trial_ids):
        raise ArtifactViolation("planner identities contain duplicates")
    frozen = {
        trial_id: index
        for index, trial_id in enumerate(frozen_planner_trial_ids(matrix))
    }
    try:
        positions = tuple(frozen[trial_id] for trial_id in trial_ids)
    except KeyError as error:
        raise ArtifactViolation("unknown frozen planner identity") from error
    if any(left >= right for left, right in zip(positions, positions[1:])):
        raise ArtifactViolation("records are outside frozen planner order")


def _validate_manifest(manifest: dict[str, object]) -> None:
    if frozenset(manifest) != _MANIFEST_FIELDS:
        raise ArtifactViolation("artifact manifest has missing or extra fields")
    environment = manifest["environment"]
    if not isinstance(environment, dict) or not all(
        isinstance(key, str) and isinstance(value, str)
        for key, value in environment.items()
    ):
        raise ArtifactViolation("artifact manifest environment is invalid")
    environment_id = manifest["environment_id"]
    if not isinstance(environment_id, str) or not environment_id:
        raise ArtifactViolation("artifact manifest environment_id is invalid")
    git_sha = manifest["git_sha"]
    if not isinstance(git_sha, str) or re.fullmatch(r"[0-9a-f]{40}", git_sha) is None:
        raise ArtifactViolation("artifact manifest git_sha is invalid")
    if manifest["matrix_revision"] != "apcc-1.matrix.v1":
        raise ArtifactViolation("artifact manifest matrix revision is invalid")
    if manifest["schema_version"] != "apcc-1.raw-result.v1":
        raise ArtifactViolation("artifact manifest schema version is invalid")
    tool_versions = manifest["tool_versions"]
    if (
        not isinstance(tool_versions, dict)
        or not tool_versions
        or not all(
            isinstance(key, str) and key and isinstance(value, str) and value
            for key, value in tool_versions.items()
        )
    ):
        raise ArtifactViolation("artifact manifest tool_versions is invalid")
    for field in ("raw_record_count", "raw_size_bytes"):
        value = manifest[field]
        if type(value) is not int or value < 0:
            raise ArtifactViolation(f"artifact manifest {field} is invalid")
    raw_sha = manifest["raw_sha256"]
    if not isinstance(raw_sha, str) or re.fullmatch(r"[0-9a-f]{64}", raw_sha) is None:
        raise ArtifactViolation("artifact manifest raw_sha256 is invalid")
    trial_ids = manifest["trial_ids"]
    if not isinstance(trial_ids, list) or not all(
        isinstance(trial_id, str) for trial_id in trial_ids
    ):
        raise ArtifactViolation("artifact manifest trial_ids is invalid")


class RawArtifactWriter:
    """Build a complete hidden staging directory, then atomically promote it."""

    def __init__(
        self,
        root: Path,
        run_id: str,
        *,
        matrix: ExperimentMatrix,
        matrix_path: Path,
        schema_path: Path,
        planned_trial_ids: Sequence[str],
        environment: Mapping[str, str],
        environment_id: str,
        git_sha: str,
        tool_versions: Mapping[str, str],
    ) -> None:
        if _RUN_ID.fullmatch(run_id) is None or run_id in {".", ".."}:
            raise ArtifactViolation("invalid run id")
        if not environment_id:
            raise ArtifactViolation("environment_id must be non-empty")
        if re.fullmatch(r"[0-9a-f]{40}", git_sha) is None:
            raise ArtifactViolation("git_sha must be a lowercase SHA-1")
        if not tool_versions or not all(
            isinstance(key, str) and key and isinstance(value, str) and value
            for key, value in tool_versions.items()
        ):
            raise ArtifactViolation("tool_versions must be a non-empty string map")
        self._matrix = matrix
        self._matrix_raw = _read_path(
            Path(matrix_path), name="matrix source", limit=_MAX_METADATA_BYTES
        )
        loaded_matrix = _load_matrix_payload(self._matrix_raw)
        if loaded_matrix != matrix:
            raise ArtifactViolation(
                "matrix object does not match reviewed matrix source"
            )
        self._schema_raw = _read_path(
            Path(schema_path), name="schema source", limit=_MAX_METADATA_BYTES
        )
        _, self._schema_validator = _load_schema(self._schema_raw)
        self._planned = tuple(planned_trial_ids)
        _validate_planner_subsequence(matrix, self._planned)
        self._environment = dict(environment)
        self._environment_id = environment_id
        self._git_sha = git_sha
        self._tool_versions = dict(tool_versions)
        self._seen: set[str] = set()
        self._count = 0
        self._closed = True
        self._root_fd = -1
        self._staging_fd = -1
        self._stream = None
        self.root = Path(root)
        try:
            self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        except OSError as error:
            raise ArtifactViolation("cannot create artifact root") from error
        self._root_fd = _open_directory(self.root, name="root")
        self.path = self.root / run_id
        try:
            os.stat(run_id, dir_fd=self._root_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            os.close(self._root_fd)
            raise ArtifactViolation("artifact run already exists")
        self._staging_name = f".{run_id}.{secrets.token_hex(8)}.partial"
        staging_created = False
        try:
            os.mkdir(self._staging_name, 0o700, dir_fd=self._root_fd)
            staging_created = True
            self._staging_fd = os.open(
                self._staging_name,
                os.O_RDONLY | _DIRECTORY | _NOFOLLOW,
                dir_fd=self._root_fd,
            )
        except OSError as error:
            if self._staging_fd >= 0:
                os.close(self._staging_fd)
                self._staging_fd = -1
            cleanup_error: OSError | None = None
            try:
                if staging_created:
                    os.rmdir(self._staging_name, dir_fd=self._root_fd)
                    os.fsync(self._root_fd)
            except OSError as caught:
                cleanup_error = caught
            finally:
                os.close(self._root_fd)
                self._root_fd = -1
            raise ArtifactViolation("cannot create artifact staging directory") from (
                cleanup_error or error
            )
        self._staging_path = self.root / self._staging_name
        try:
            descriptor = os.open(
                "raw.jsonl.partial",
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW,
                0o600,
                dir_fd=self._staging_fd,
            )
            self._stream = os.fdopen(descriptor, "wb")
            self._closed = False
        except Exception:
            self._discard_staging()
            raise

    def _discard_staging(self) -> None:
        cleanup_error: BaseException | None = None
        stream = self._stream
        self._stream = None
        if stream is not None and not stream.closed:
            stream.close()
        if self._staging_fd < 0 and self._root_fd >= 0:
            try:
                self._staging_fd = os.open(
                    self._staging_name,
                    os.O_RDONLY | _DIRECTORY | _NOFOLLOW,
                    dir_fd=self._root_fd,
                )
            except FileNotFoundError:
                pass
        if self._staging_fd >= 0:
            try:
                for name in os.listdir(self._staging_fd):
                    info = os.stat(name, dir_fd=self._staging_fd, follow_symlinks=False)
                    if not stat.S_ISREG(info.st_mode):
                        raise ArtifactViolation(
                            "artifact staging contains a non-regular entry"
                        )
                    os.unlink(name, dir_fd=self._staging_fd)
            except BaseException as error:
                cleanup_error = error
            finally:
                os.close(self._staging_fd)
                self._staging_fd = -1
        if self._root_fd >= 0:
            try:
                os.rmdir(self._staging_name, dir_fd=self._root_fd)
            except FileNotFoundError:
                pass
            except BaseException as error:
                if cleanup_error is None:
                    cleanup_error = error
            finally:
                try:
                    os.fsync(self._root_fd)
                finally:
                    os.close(self._root_fd)
                    self._root_fd = -1
        self._closed = True
        if cleanup_error is not None:
            raise cleanup_error

    def append(self, record: Mapping[str, object]) -> None:
        if self._closed:
            raise ArtifactViolation("artifact writer is closed")
        trial_id = record.get("trial_id")
        if not isinstance(trial_id, str):
            raise ArtifactViolation("raw record trial_id must be a string")
        if trial_id in self._seen:
            raise ArtifactViolation("duplicate trial_id")
        if self._count >= len(self._planned) or trial_id != self._planned[self._count]:
            raise ArtifactViolation("raw record is outside frozen planner order")
        expected_provenance = {
            "environment_id": self._environment_id,
            "git_sha": self._git_sha,
            "matrix_revision": self._matrix.revision,
            "matrix_sha256": REVIEWED_MATRIX_SHA256,
            "schema_version": "apcc-1.raw-result.v1",
            "tool_versions": self._tool_versions,
        }
        if any(record.get(key) != value for key, value in expected_provenance.items()):
            raise ArtifactViolation("raw record provenance does not match run manifest")
        raw = canonical_json_bytes(dict(record))
        errors = tuple(
            self._schema_validator.iter_errors(cast(_JsonValue, dict(record)))
        )
        if errors:
            raise ArtifactViolation("raw record violates the embedded reviewed schema")
        with tempfile.TemporaryDirectory(prefix="apcc-record-") as temporary:
            validation = Path(temporary) / "record.json"
            validation.write_bytes(raw)
            try:
                load_raw_result(validation, matrix=self._matrix)
            except ValueError as error:
                raise ArtifactViolation(
                    "raw record violates the reviewed contract"
                ) from error
        if self._stream is None:
            self._discard_staging()
            raise ArtifactViolation("artifact writer stream is unavailable")
        if self._stream.tell() + len(raw) > _MAX_RAW_BYTES:
            raise ArtifactViolation("raw artifact exceeds bounded size")
        self._stream.write(raw)
        self._stream.flush()
        os.fsync(self._stream.fileno())
        self._seen.add(trial_id)
        self._count += 1

    def abort(self) -> None:
        if self._closed:
            return
        self._discard_staging()

    def finalize(self) -> Path:
        if self._closed:
            raise ArtifactViolation("artifact writer is closed")
        if self._count != len(self._planned):
            self._discard_staging()
            raise ArtifactViolation("artifact run is incomplete")
        if self._stream is None:
            raise ArtifactViolation("artifact writer stream is unavailable")
        try:
            self._stream.flush()
            os.fsync(self._stream.fileno())
            self._stream.close()
            self._stream = None
            os.rename(
                "raw.jsonl.partial",
                "raw.jsonl",
                src_dir_fd=self._staging_fd,
                dst_dir_fd=self._staging_fd,
            )
            _write_at(self._staging_fd, "matrix.v1.json", self._matrix_raw)
            _write_at(self._staging_fd, "raw-result.schema.json", self._schema_raw)
            raw = _read_at(self._staging_fd, "raw.jsonl", limit=_MAX_RAW_BYTES)
            manifest = {
                "environment": self._environment,
                "environment_id": self._environment_id,
                "git_sha": self._git_sha,
                "matrix_revision": self._matrix.revision,
                "matrix_sha256": REVIEWED_MATRIX_SHA256,
                "raw_record_count": self._count,
                "raw_sha256": _sha256(raw),
                "raw_size_bytes": len(raw),
                "schema_sha256": REVIEWED_SCHEMA_SHA256,
                "schema_version": "apcc-1.raw-result.v1",
                "tool_versions": self._tool_versions,
                "trial_ids": list(self._planned),
            }
            _write_at(self._staging_fd, "manifest.json", canonical_json_bytes(manifest))
            sums = b"".join(
                f"{_sha256(_read_at(self._staging_fd, name, limit=_MAX_RAW_BYTES if name == 'raw.jsonl' else _MAX_METADATA_BYTES))}  {name}\n".encode()
                for name in sorted(_ARTIFACT_FILES)
            )
            _write_at(self._staging_fd, "SHA256SUMS", sums)
            os.fsync(self._staging_fd)
            os.close(self._staging_fd)
            self._staging_fd = -1
            _rename_noreplace(
                self._root_fd,
                self._staging_name,
                self._root_fd,
                self.path.name,
            )
            os.fsync(self._root_fd)
            os.close(self._root_fd)
            self._root_fd = -1
            self._closed = True
            return self.path
        except Exception:
            self._discard_staging()
            raise


def read_artifact_run(path: Path) -> ArtifactRun:
    run = Path(path)
    parent_fd = _open_directory(run.parent, name="run parent")
    run_fd = -1
    try:
        try:
            run_fd = os.open(
                run.name,
                os.O_RDONLY | _DIRECTORY | _NOFOLLOW,
                dir_fd=parent_fd,
            )
            _require_owned(os.fstat(run_fd), name="run", directory=True)
        except ArtifactViolation:
            if run_fd >= 0:
                os.close(run_fd)
                run_fd = -1
            raise
        except OSError as error:
            if run_fd >= 0:
                os.close(run_fd)
                run_fd = -1
            raise ArtifactViolation("cannot open artifact run") from error
    finally:
        os.close(parent_fd)
    try:
        expected = {*_ARTIFACT_FILES, "SHA256SUMS"}
        try:
            actual = set(os.listdir(run_fd))
        except OSError as error:
            raise ArtifactViolation("cannot list artifact run") from error
        if actual != expected:
            raise ArtifactViolation("artifact run has missing or extra files")
        payloads = {
            name: _read_at(
                run_fd,
                name,
                limit=_MAX_RAW_BYTES if name == "raw.jsonl" else _MAX_METADATA_BYTES,
            )
            for name in expected
        }
    finally:
        if run_fd >= 0:
            os.close(run_fd)
    expected_sums = b"".join(
        f"{_sha256(payloads[name])}  {name}\n".encode()
        for name in sorted(_ARTIFACT_FILES)
    )
    if payloads["SHA256SUMS"] != expected_sums:
        raise ArtifactViolation("artifact hash manifest is reordered or invalid")
    try:
        manifest = json.loads(payloads["manifest.json"])
        canonical = canonical_json_bytes(manifest) == payloads["manifest.json"]
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise ArtifactViolation("artifact manifest is invalid JSON") from error
    if not isinstance(manifest, dict) or not canonical:
        raise ArtifactViolation("artifact manifest is not canonical")
    _validate_manifest(manifest)
    if manifest.get("matrix_sha256") != REVIEWED_MATRIX_SHA256:
        raise ArtifactViolation("artifact manifest does not pin the reviewed matrix")
    if manifest.get("schema_sha256") != REVIEWED_SCHEMA_SHA256:
        raise ArtifactViolation("artifact manifest does not pin the reviewed schema")
    matrix = _load_matrix_payload(payloads["matrix.v1.json"])
    _, schema_validator = _load_schema(payloads["raw-result.schema.json"])
    checks = {
        "raw_sha256": _sha256(payloads["raw.jsonl"]),
        "raw_size_bytes": len(payloads["raw.jsonl"]),
    }
    if any(manifest.get(key) != value for key, value in checks.items()):
        raise ArtifactViolation("artifact content hash or size mismatch")
    lines = payloads["raw.jsonl"].splitlines(keepends=True)
    trial_ids: list[str] = []
    with tempfile.TemporaryDirectory(prefix="apcc-artifact-read-") as temporary:
        validation_path = Path(temporary) / "record.json"
        for line in lines:
            try:
                record = json.loads(line)
                record_is_canonical = canonical_json_bytes(record) == line
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
                raise ArtifactViolation(
                    "raw artifact contains invalid JSONL"
                ) from error
            if not isinstance(record, dict) or not record_is_canonical:
                raise ArtifactViolation("raw artifact contains non-canonical JSONL")
            expected_provenance = {
                "environment_id": manifest["environment_id"],
                "git_sha": manifest["git_sha"],
                "matrix_revision": manifest["matrix_revision"],
                "matrix_sha256": manifest["matrix_sha256"],
                "schema_version": manifest["schema_version"],
                "tool_versions": manifest["tool_versions"],
            }
            if any(
                record.get(key) != value for key, value in expected_provenance.items()
            ):
                raise ArtifactViolation(
                    "raw artifact record provenance does not match manifest"
                )
            if tuple(schema_validator.iter_errors(record)):
                raise ArtifactViolation("raw artifact record violates embedded schema")
            validation_path.write_bytes(line)
            try:
                load_raw_result(validation_path, matrix=matrix)
            except ValueError as error:
                raise ArtifactViolation(
                    "raw artifact record violates reviewed contract"
                ) from error
            trial_id = record.get("trial_id")
            if not isinstance(trial_id, str):
                raise ArtifactViolation("raw artifact trial_id is invalid")
            trial_ids.append(trial_id)
    if manifest.get("raw_record_count") != len(lines):
        raise ArtifactViolation("raw artifact record count mismatch")
    if manifest.get("trial_ids") != trial_ids:
        raise ArtifactViolation(
            "raw artifact manifest does not match record identities"
        )
    _validate_planner_subsequence(matrix, trial_ids)
    return ArtifactRun(run, len(lines), _sha256(payloads["raw.jsonl"]), manifest)
