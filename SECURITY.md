# Security

## Reporting a vulnerability

**[Open a private security advisory](https://github.com/purpleshellsecurity/Pylon/security/advisories/new).**
It is private between you and us, and it threads like an issue.

Please do not open a public issue for a vulnerability — a public issue is a
disclosure, and it happens before there is anything to upgrade to.

For anything that is *not* a vulnerability — a crash, a wrong result, a
detection that does not fire — [open an issue](https://github.com/purpleshellsecurity/Pylon/issues).
A crash prints the path to its own run log; attaching that log is the single
most useful thing you can include.

Useful things to include, as far as you have them: what the issue lets someone
do, the version (`pylon --version`), and the smallest way to reproduce it. We
will confirm receipt and tell you what we intend to do about it.

## What Pylon touches

Worth knowing when judging impact:

- **It reads.** `analyze`, `recommend` and `tabledrift` run read-only queries
  against Log Analytics and the Azure control plane. Pylon does not create,
  modify or delete Azure resources.
- **Credentials come from the environment**, or from `~/.config/pylon/config`
  (`0600` on Unix, owner-only ACL on Windows). They are never passed on the
  command line and never written to the run log.
- **The run log is tenant data.** `.pylon/logs/*.jsonl` records what a run did,
  including workspace names and resource ids. It carries no credentials, and a
  test enforces that in both directions. It is gitignored, and the newest 50
  runs are kept.
- **`design` sends data to a model provider** — the one command that does. What
  it sends is the table schema, operation names and the technique catalogue. It
  does not send your log rows.
- **Generated KQL and playbooks are output, not instructions.** Pylon never
  executes a generated playbook, and the PowerShell in one is for a human to
  read and run deliberately.

## Supported versions

Pylon is at 1.0.0 and fixes land on `main`. There is no separate maintenance
branch yet.
