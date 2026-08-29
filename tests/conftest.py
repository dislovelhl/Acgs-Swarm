"""Optional-extra collection hooks.

The frozen PostgreSQL suite (`tests/test_apcc_postgres.py`) must not be
collected without psycopg. Several of its tests import the postgres backend at
call time and would fail the default ``[dev]`` matrix. Live-store tests still
skip without ``APCC_POSTGRES_DSN`` when psycopg is present.
"""

from __future__ import annotations

collect_ignore: list[str] = []

try:
    import psycopg  # noqa: F401
except ImportError:
    collect_ignore.append("test_apcc_postgres.py")
