"""Tests for pacli.audit module."""

import json
import tempfile
import time
from pathlib import Path

from sinduk.audit import AuditEvent, AuditLog, AuditRecord


class TestAuditEvent:
    """Test AuditEvent enum."""

    def test_auth_events(self):
        """Auth events should have correct values."""
        assert AuditEvent.AUTH_SUCCESS.value == "auth.success"
        assert AuditEvent.AUTH_FAILED.value == "auth.failed"
        assert AuditEvent.AUTH_LOGOUT.value == "auth.logout"

    def test_secret_events(self):
        """Secret lifecycle events should exist."""
        assert AuditEvent.SECRET_CREATED.value == "secret.created"
        assert AuditEvent.SECRET_READ.value == "secret.read"
        assert AuditEvent.SECRET_DELETED.value == "secret.deleted"

    def test_backup_events(self):
        """Backup events should be defined."""
        assert AuditEvent.BACKUP_EXPORTED.value == "backup.exported"
        assert AuditEvent.BACKUP_IMPORTED.value == "backup.imported"

    def test_web_ui_events(self):
        """Web UI events should exist."""
        assert AuditEvent.WEB_UI_STARTED.value == "webui.started"
        assert AuditEvent.WEB_UI_STOPPED.value == "webui.stopped"

    def test_all_events_unique(self):
        """All event values should be unique."""
        values = [e.value for e in AuditEvent]
        assert len(values) == len(set(values))


class TestAuditRecord:
    """Test AuditRecord class."""

    def test_create_record(self):
        """AuditRecord should store all fields."""
        rec = AuditRecord(
            seq=1,
            ts=time.time(),
            event=AuditEvent.AUTH_SUCCESS,
            outcome="ok",
            details={"user": "admin"},
        )
        assert rec.seq == 1
        assert rec.event == AuditEvent.AUTH_SUCCESS
        assert rec.outcome == "ok"
        assert rec.details == {"user": "admin"}

    def test_to_dict(self):
        """AuditRecord.to_dict should serialize correctly."""
        ts = time.time()
        rec = AuditRecord(
            seq=5,
            ts=ts,
            event=AuditEvent.SECRET_CREATED,
            outcome="ok",
            details={"label": "github", "type": "token"},
        )
        data = rec.to_dict()
        assert data["seq"] == 5
        assert data["ts"] == ts
        assert data["event"] == "secret.created"
        assert data["outcome"] == "ok"
        assert data["label"] == "github"
        assert data["type"] == "token"

    def test_from_dict(self):
        """AuditRecord.from_dict should deserialize correctly."""
        data = {
            "seq": 3,
            "ts": 1234567890.0,
            "event": "auth.success",
            "outcome": "ok",
            "user": "testuser",
        }
        rec = AuditRecord.from_dict(data)
        assert rec.seq == 3
        assert rec.ts == 1234567890
        assert rec.event == AuditEvent.AUTH_SUCCESS
        assert rec.outcome == "ok"
        assert rec.details == {"user": "testuser"}

    def test_from_dict_default_outcome(self):
        """AuditRecord.from_dict should default outcome to 'ok'."""
        data = {
            "seq": 1,
            "ts": 1234567890.0,
            "event": "auth.success",
        }
        rec = AuditRecord.from_dict(data)
        assert rec.outcome == "ok"

    def test_from_dict_with_failure(self):
        """AuditRecord.from_dict should handle fail outcome."""
        data = {
            "seq": 2,
            "ts": 1234567890.0,
            "event": "auth.failed",
            "outcome": "fail",
            "reason": "invalid_password",
        }
        rec = AuditRecord.from_dict(data)
        assert rec.outcome == "fail"
        assert rec.details["reason"] == "invalid_password"

    def test_record_repr(self):
        """AuditRecord should have readable repr."""
        rec = AuditRecord(
            seq=1,
            ts=time.time(),
            event=AuditEvent.AUTH_SUCCESS,
            outcome="ok",
            details={},
        )
        repr_str = repr(rec)
        assert "AuditRecord" in repr_str
        assert "seq=1" in repr_str


class TestAuditLog:
    """Test AuditLog class."""

    def test_create_audit_log(self):
        """AuditLog should initialize with default path."""
        log = AuditLog()
        assert log._path is not None

    def test_create_audit_log_custom_path(self):
        """AuditLog should accept custom path."""
        with tempfile.TemporaryDirectory() as tmpdir:
            custom_path = Path(tmpdir) / "audit.log"
            log = AuditLog(path=custom_path)
            assert log._path == custom_path

    def test_record_basic(self):
        """AuditLog.record should write and return record."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "audit.log"
            log = AuditLog(path=log_path)
            rec = log.record(AuditEvent.AUTH_SUCCESS)
            assert rec.seq == 1
            assert rec.event == AuditEvent.AUTH_SUCCESS
            assert rec.outcome == "ok"

    def test_record_with_outcome(self):
        """AuditLog.record should handle outcome parameter."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "audit.log"
            log = AuditLog(path=log_path)
            rec = log.record(AuditEvent.AUTH_FAILED, outcome="fail", reason="wrong_password")
            assert rec.outcome == "fail"
            assert rec.details["reason"] == "wrong_password"

    def test_record_sequence_increments(self):
        """AuditLog should increment sequence numbers."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "audit.log"
            log = AuditLog(path=log_path)
            rec1 = log.record(AuditEvent.AUTH_SUCCESS)
            rec2 = log.record(AuditEvent.SECRET_CREATED, label="test")
            rec3 = log.record(AuditEvent.SECRET_READ, label="test")
            assert rec1.seq == 1
            assert rec2.seq == 2
            assert rec3.seq == 3

    def test_record_persists_to_file(self):
        """AuditLog.record should persist to file as JSONL."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "audit.log"
            log = AuditLog(path=log_path)
            log.record(AuditEvent.AUTH_SUCCESS, user="alice")
            log.record(AuditEvent.SECRET_CREATED, label="github", type="token")
            content = log_path.read_text()
            lines = content.strip().split("\n")
            assert len(lines) == 2
            data1 = json.loads(lines[0])
            data2 = json.loads(lines[1])
            assert data1["event"] == "auth.success"
            assert data2["event"] == "secret.created"

    def test_tail_empty_log(self):
        """AuditLog.tail on empty/non-existent log should return []."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "audit.log"
            log = AuditLog(path=log_path)
            records = log.tail(10)
            assert records == []

    def test_tail_returns_last_n(self):
        """AuditLog.tail should return last n records."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "audit.log"
            log = AuditLog(path=log_path)
            for _ in range(5):
                log.record(AuditEvent.AUTH_SUCCESS)
            records = log.tail(3)
            assert len(records) == 3
            assert records[-1].seq == 5

    def test_tail_default_count(self):
        """AuditLog.tail should default to 50 records."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "audit.log"
            log = AuditLog(path=log_path)
            for _ in range(10):
                log.record(AuditEvent.AUTH_SUCCESS)
            records = log.tail()
            assert len(records) == 10

    def test_query_by_event(self):
        """AuditLog.query should filter by event."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "audit.log"
            log = AuditLog(path=log_path)
            log.record(AuditEvent.AUTH_SUCCESS)
            log.record(AuditEvent.AUTH_FAILED)
            log.record(AuditEvent.AUTH_SUCCESS)
            records = log.query(event=AuditEvent.AUTH_SUCCESS)
            assert len(records) == 2
            assert all(r.event == AuditEvent.AUTH_SUCCESS for r in records)

    def test_query_by_outcome(self):
        """AuditLog.query should filter by outcome."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "audit.log"
            log = AuditLog(path=log_path)
            log.record(AuditEvent.AUTH_SUCCESS, outcome="ok")
            log.record(AuditEvent.AUTH_FAILED, outcome="fail")
            log.record(AuditEvent.AUTH_SUCCESS, outcome="ok")
            records = log.query(outcome="fail")
            assert len(records) == 1
            assert records[0].event == AuditEvent.AUTH_FAILED

    def test_query_by_timestamp(self):
        """AuditLog.query should filter by timestamp."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "audit.log"
            log = AuditLog(path=log_path)
            _ = log.record(AuditEvent.AUTH_SUCCESS)
            time.sleep(0.01)
            midpoint = time.time()
            time.sleep(0.01)
            _ = log.record(AuditEvent.AUTH_SUCCESS)
            records = log.query(since=midpoint)
            assert len(records) == 1
            assert records[0].seq == 2

    def test_query_combined_filters(self):
        """AuditLog.query should apply multiple filters."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "audit.log"
            log = AuditLog(path=log_path)
            log.record(AuditEvent.AUTH_SUCCESS, outcome="ok")
            log.record(AuditEvent.AUTH_FAILED, outcome="fail")
            log.record(AuditEvent.AUTH_SUCCESS, outcome="ok")
            records = log.query(
                event=AuditEvent.AUTH_SUCCESS,
                outcome="ok",
            )
            assert len(records) == 2

    def test_query_empty_log(self):
        """AuditLog.query on empty log should return []."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "audit.log"
            log = AuditLog(path=log_path)
            records = log.query(event=AuditEvent.AUTH_SUCCESS)
            assert records == []

    def test_malformed_lines_skipped(self):
        """AuditLog should skip malformed JSONL lines."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "audit.log"
            log = AuditLog(path=log_path)
            # Write valid records and malformed lines
            log.record(AuditEvent.AUTH_SUCCESS)
            log_path.write_text(log_path.read_text() + "not valid json\n")
            log.record(AuditEvent.AUTH_SUCCESS)
            records = log.tail(10)
            assert len(records) == 2

    def test_read_last_seq_existing_log(self):
        """AuditLog._read_last_seq should read sequence from existing log."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "audit.log"
            log = AuditLog(path=log_path)
            log.record(AuditEvent.AUTH_SUCCESS)
            log.record(AuditEvent.AUTH_SUCCESS)
            log2 = AuditLog(path=log_path)
            assert log2._seq == 2

    def test_record_resilient_to_io_errors(self):
        """AuditLog.record should not crash on IO errors."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "audit.log"
            log = AuditLog(path=log_path)
            # Record to a directory instead of file to cause IO error
            log._path = Path(tmpdir)
            rec = log.record(AuditEvent.AUTH_SUCCESS)
            assert rec is not None

    def test_audit_log_singleton(self):
        """Module-level audit_log should be available."""
        from sinduk.audit import audit_log as global_log

        assert global_log is not None
        assert isinstance(global_log, AuditLog)
