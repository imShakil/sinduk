"""
sinduk.audit
~~~~~~~~~~~~
Structured, append-only audit log for security-relevant events.

Every write is a newline-delimited JSON record so the log is:
  - Human-readable with ``jq``
  - Machine-parseable without special tooling
  - Tamper-evident via sequential record numbering

Usage::

    from sinduk.audit import AuditLog, AuditEvent

    log = AuditLog()
    log.record(AuditEvent.SECRET_CREATED, label="github", secret_type="token")
    log.record(AuditEvent.AUTH_FAILED)

File location: ``~/.config/sinduk/audit.log``
"""

from __future__ import annotations

import json
import os
import time
from enum import Enum
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

AUDIT_LOG_PATH: Path = Path.home() / ".config" / "sinduk" / "audit.log"
_MAX_LOG_BYTES: int = 5 * 1024 * 1024  # 5 MiB — rotate after this size
_MAX_ROTATIONS: int = 5  # keep .1 … .5 archives


# ---------------------------------------------------------------------------
# Event catalogue
# ---------------------------------------------------------------------------


class AuditEvent(str, Enum):
    """All auditable operations in sinduk.

    Values are kept short so they compress well in the JSONL log and remain
    unambiguous when ``grep``-ed by an operator.
    """

    # Authentication
    AUTH_SUCCESS = "auth.success"
    AUTH_FAILED = "auth.failed"
    AUTH_LOGOUT = "auth.logout"
    MASTER_PASSWORD_SET = "auth.master_password_set"
    MASTER_PASSWORD_CHANGED = "auth.master_password_changed"

    # Secret lifecycle
    SECRET_CREATED = "secret.created"
    SECRET_READ = "secret.read"
    SECRET_REVEALED = "secret.revealed"
    SECRET_UPDATED = "secret.updated"
    SECRET_DELETED = "secret.deleted"
    SECRET_EXPORTED = "secret.exported"
    SECRET_COPIED_CLIPBOARD = "secret.copied_clipboard"

    # Bulk / search
    SECRETS_LISTED = "secrets.listed"
    SECRETS_SEARCHED = "secrets.searched"

    # Backup
    BACKUP_EXPORTED = "backup.exported"
    BACKUP_IMPORTED = "backup.imported"

    # Web UI
    WEB_UI_STARTED = "webui.started"
    WEB_UI_STOPPED = "webui.stopped"

    # System
    FIRST_RUN_SETUP = "system.first_run_setup"


# ---------------------------------------------------------------------------
# Record structure
# ---------------------------------------------------------------------------


class AuditRecord:
    """A single immutable audit record.

    Attributes
    ----------
    seq:
        Monotonically increasing sequence number within this log file.
        Gaps indicate lines were removed.
    ts:
        Unix timestamp (float) with sub-second precision.
    event:
        The :class:`AuditEvent` that occurred.
    outcome:
        ``"ok"`` or ``"fail"``.
    details:
        Arbitrary caller-supplied key/value pairs (e.g. ``label``, ``type``).
        Sensitive values (passwords, secrets) must *never* be passed here.
    """

    __slots__ = ("seq", "ts", "event", "outcome", "details")

    def __init__(
        self,
        seq: int,
        ts: float,
        event: AuditEvent,
        outcome: str,
        details: dict[str, Any],
    ) -> None:
        self.seq = seq
        self.ts = ts
        self.event = event
        self.outcome = outcome
        self.details = details

    def to_dict(self) -> dict[str, Any]:
        return {
            "seq": self.seq,
            "ts": self.ts,
            "event": self.event.value,
            "outcome": self.outcome,
            **self.details,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AuditRecord":
        event = AuditEvent(data["event"])
        details = {k: v for k, v in data.items() if k not in {"seq", "ts", "event", "outcome"}}
        return cls(
            seq=data["seq"],
            ts=data["ts"],
            event=event,
            outcome=data.get("outcome", "ok"),
            details=details,
        )

    def __repr__(self) -> str:  # pragma: no cover
        return f"AuditRecord(seq={self.seq}, event={self.event.value}, outcome={self.outcome})"


# ---------------------------------------------------------------------------
# Log writer
# ---------------------------------------------------------------------------


class AuditLog:
    """Append-only, JSONL audit log with automatic rotation.

    Thread safety: each :meth:`record` call holds the GIL for the duration of
    the ``file.write`` + ``file.flush`` syscalls, which is sufficient for a
    CLI tool.  For a long-running server process, wrap :meth:`record` in a
    ``threading.Lock`` if needed.

    Parameters
    ----------
    path:
        Override the default log path (useful for testing).
    """

    def __init__(self, path: Path | None = None) -> None:
        self._path: Path = path or AUDIT_LOG_PATH
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._seq: int = self._read_last_seq()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def record(
        self,
        event: AuditEvent,
        outcome: str = "ok",
        **details: Any,
    ) -> AuditRecord:
        """Append one audit record to the log.

        Parameters
        ----------
        event:
            The event that occurred.
        outcome:
            ``"ok"`` (default) or ``"fail"``.
        **details:
            Arbitrary metadata.  Do **not** pass raw secret values here.

        Returns
        -------
        AuditRecord
            The written record (useful for testing).
        """
        self._rotate_if_needed()
        self._seq += 1
        rec = AuditRecord(
            seq=self._seq,
            ts=time.time(),
            event=event,
            outcome=outcome,
            details=details,
        )
        line = json.dumps(rec.to_dict(), separators=(",", ":")) + "\n"
        try:
            with self._path.open("a", encoding="utf-8") as fh:
                fh.write(line)
                fh.flush()
                os.fsync(fh.fileno())
        except OSError:
            # Audit failures must never crash the application.
            pass
        return rec

    def tail(self, n: int = 50) -> list[AuditRecord]:
        """Return the last *n* records, newest last.

        Skips malformed lines silently.
        """
        if not self._path.exists():
            return []
        lines: list[str] = self._path.read_text(encoding="utf-8").splitlines()
        records: list[AuditRecord] = []
        for line in lines[-n:]:
            line = line.strip()
            if not line:
                continue
            try:
                records.append(AuditRecord.from_dict(json.loads(line)))
            except (KeyError, ValueError):
                continue
        return records

    def query(
        self,
        event: AuditEvent | None = None,
        outcome: str | None = None,
        since: float | None = None,
    ) -> list[AuditRecord]:
        """Filter the full log by optional criteria.

        Parameters
        ----------
        event:
            If set, only return records with this event type.
        outcome:
            If set, filter by ``"ok"`` or ``"fail"``.
        since:
            Unix timestamp; only return records newer than this.
        """
        if not self._path.exists():
            return []
        results: list[AuditRecord] = []
        for line in self._path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = AuditRecord.from_dict(json.loads(line))
            except (KeyError, ValueError):
                continue
            if event is not None and rec.event != event:
                continue
            if outcome is not None and rec.outcome != outcome:
                continue
            if since is not None and rec.ts < since:
                continue
            results.append(rec)
        return results

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _read_last_seq(self) -> int:
        """Read the sequence number of the last written record."""
        if not self._path.exists():
            return 0
        try:
            with self._path.open("rb") as fh:
                # Seek to the end and walk back to find the last newline.
                fh.seek(0, 2)
                size = fh.tell()
                if size == 0:
                    return 0
                # Read last 512 bytes — enough for one JSONL record.
                fh.seek(max(0, size - 512))
                tail = fh.read().decode("utf-8", errors="replace")
            for line in reversed(tail.splitlines()):
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    return int(data.get("seq", 0))
                except ValueError:
                    continue
        except OSError:
            pass
        return 0

    def _rotate_if_needed(self) -> None:
        """Rotate the log file when it exceeds *_MAX_LOG_BYTES*."""
        try:
            if not self._path.exists() or self._path.stat().st_size < _MAX_LOG_BYTES:
                return
            # Shift existing rotated files: .5 → dropped, .4 → .5, …
            for i in range(_MAX_ROTATIONS - 1, 0, -1):
                src = self._path.with_suffix(f".log.{i}")
                dst = self._path.with_suffix(f".log.{i + 1}")
                if src.exists():
                    src.rename(dst)
            self._path.rename(self._path.with_suffix(".log.1"))
            self._seq = 0
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

#: Global audit log instance.  Import and use directly::
#:
#:     from sinduk.audit import audit_log, AuditEvent
#:     audit_log.record(AuditEvent.AUTH_SUCCESS)
audit_log: AuditLog = AuditLog()
