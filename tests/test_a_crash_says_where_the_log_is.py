"""An unexpected exception must not reach the terminal as a raw traceback.

`main()` called `args.func(args)` bare, so any bug surfaced as a stack trace.
For a tool whose purpose is advertising a consultancy that is a wasted first
impression, not merely a rough edge -- and the log path was already in hand.
`logs.configure()`'s own docstring says "a log nobody can find is barely better
than no log"; it returned the path and then never showed it at the one moment a
reader needs it.

Ctrl-C is separate: `design` costs money, and a run interrupted mid-phase has a
checkpoint. Exiting silently makes the reader pay twice.
"""
import argparse


from pylon import cli


def _args(func):
    return argparse.Namespace(command="design", func=func)


def test_a_bug_prints_the_log_path_and_where_to_report_it(monkeypatch, capsys, tmp_path):
    jsonl = tmp_path / "run.jsonl"
    monkeypatch.setattr(cli.logs, "configure", lambda: jsonl)
    monkeypatch.setattr(cli.config, "apply", lambda: None)

    def boom(_a):
        raise RuntimeError("something nobody predicted")

    monkeypatch.setattr(cli, "build_parser",
                        lambda: _Parser(_args(boom)))
    code = cli.main()
    err = capsys.readouterr().err
    assert code == 1
    assert "Pylon hit a bug" in err
    assert str(jsonl) in err, "the log path is not shown"
    assert "issues" in err, "the reader is not told where to report it"
    assert "Traceback" not in err, "the raw trace still reaches the terminal"


def test_ctrl_c_is_130_and_says_so(monkeypatch, capsys, tmp_path):
    jsonl = tmp_path / "run.jsonl"
    monkeypatch.setattr(cli.logs, "configure", lambda: jsonl)
    monkeypatch.setattr(cli.config, "apply", lambda: None)

    def interrupted(_a):
        raise KeyboardInterrupt

    monkeypatch.setattr(cli, "build_parser", lambda: _Parser(_args(interrupted)))
    code = cli.main()
    err = capsys.readouterr().err
    assert code == 130, "130 is the shell's convention for SIGINT"
    assert "Interrupted" in err
    assert "Traceback" not in err


def test_a_clean_run_is_untouched(monkeypatch, capsys, tmp_path):
    monkeypatch.setattr(cli.logs, "configure", lambda: tmp_path / "run.jsonl")
    monkeypatch.setattr(cli.config, "apply", lambda: None)
    monkeypatch.setattr(cli, "build_parser", lambda: _Parser(_args(lambda _a: 0)))
    assert cli.main() == 0
    assert "Pylon hit a bug" not in capsys.readouterr().err


def test_the_spend_note_is_silent_when_nothing_was_spent(capsys):
    """A free verb printing "$0.00" is noise, and a meter that never ran has no
    answer rather than a zero."""
    from pylon.usage import reset_meter

    reset_meter()
    cli._spend_note()
    assert capsys.readouterr().err == ""


def test_the_spend_note_never_masks_the_error_it_accompanies(monkeypatch, capsys):
    """It runs inside the crash path. If cost accounting itself is what broke,
    it must not raise on top of the exception being reported."""
    import pylon.usage as usage

    monkeypatch.setattr(usage, "current_meter", lambda: (_ for _ in ()).throw(ValueError("x")))
    cli._spend_note()          # must not raise
    assert capsys.readouterr().err == ""


class _Parser:
    def __init__(self, ns):
        self._ns = ns

    def parse_args(self):
        return self._ns
