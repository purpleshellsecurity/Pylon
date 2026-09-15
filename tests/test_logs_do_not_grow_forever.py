"""One log file per run, at DEBUG, with nothing ever removing them.

A design run's log is not small, and on a machine that runs Pylon daily the
directory only grows. Nothing in `logs.py` had a `maxBytes`, a `backupCount` or
any cleanup at all.
"""
from pathlib import Path


from pylon import logs


def _runs(d: Path, n: int) -> None:
    for i in range(n):
        (d / f"run-2026091{i // 60:d}-{i:06d}.jsonl").write_text("{}", encoding="utf-8")


def test_the_newest_runs_are_kept_and_the_rest_go(tmp_path):
    _runs(tmp_path, 60)
    removed = logs._prune(tmp_path, keep=50)
    kept = sorted(p.name for p in tmp_path.glob("run-*.jsonl"))
    assert len(removed) == 10
    assert len(kept) == 50
    # Sorted by NAME: the stamps sort chronologically and, unlike mtime, do not
    # move when a file is copied or restored from a backup.
    assert kept[-1].endswith("000059.jsonl"), kept[-1]
    assert not any(p.name.endswith("000000.jsonl") for p in tmp_path.glob("*"))


def test_nothing_that_is_not_ours_is_deleted(tmp_path):
    """Only `run-*.jsonl` is considered. A file someone parked here by hand, or
    another tool's output, is not ours to remove."""
    _runs(tmp_path, 60)
    for stray in ("notes.txt", "analysis.json", "run-notes.md", "keep.jsonl"):
        (tmp_path / stray).write_text("x", encoding="utf-8")
    logs._prune(tmp_path, keep=10)
    for stray in ("notes.txt", "analysis.json", "run-notes.md", "keep.jsonl"):
        assert (tmp_path / stray).exists(), stray


def test_under_the_limit_nothing_is_touched(tmp_path):
    _runs(tmp_path, 5)
    assert logs._prune(tmp_path, keep=50) == []
    assert len(list(tmp_path.glob("run-*.jsonl"))) == 5


def test_keep_zero_is_a_no_op_not_delete_everything(tmp_path):
    """`PYLON_LOG_KEEP=0` reads as "do not prune", not "delete the lot". The
    other reading loses the log of the run that is happening right now."""
    _runs(tmp_path, 5)
    assert logs._prune(tmp_path, keep=0) == []
    assert len(list(tmp_path.glob("run-*.jsonl"))) == 5


def test_an_undeletable_file_does_not_stop_the_run(tmp_path, monkeypatch):
    """Pruning happens at startup, on the way to doing what the user asked. A
    locked or read-only file is not a reason to refuse to run."""
    _runs(tmp_path, 60)

    def refuse(self):
        raise OSError("in use by another process")

    monkeypatch.setattr(Path, "unlink", refuse)
    assert logs._prune(tmp_path, keep=50) == []   # nothing removed, nothing raised


def test_the_run_being_written_is_never_a_candidate(tmp_path, monkeypatch):
    """Pruning runs AFTER this run's handler is installed. Deleting the file
    about to be written would be the one unacceptable outcome."""
    monkeypatch.setattr(logs, "_configured", False)
    monkeypatch.setenv("PYLON_LOG_KEEP", "1")
    _runs(tmp_path, 5)
    target = tmp_path / "run-20260915-999999.jsonl"
    path = logs.configure(jsonl=target)
    log = logs.get_logger("pylon.test")
    log.info("hello", extra={"event": "command"})
    import logging
    for h in logging.getLogger("pylon").handlers:
        h.flush()
    assert path == target
    assert target.exists() and target.read_text(encoding="utf-8").strip()
