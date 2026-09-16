# Changelog

Notable changes. Dates are the release date.

## 1.0.0 — 2026-09-16

First public release.

Pylon reads a Microsoft Sentinel tenant, reports what it detects, and generates
what it does not. Read-only: it signs in through the Azure CLI and creates
nothing.

### Commands

- **`pylon analyze`** measures the tenant and writes one page in the order the
  data moves: sources, arrival, volume and cost, analytics rules, MITRE
  coverage, Content Hub. Plus `analysis.json`, the measurements it renders from.
- **`pylon design`** enumerates what could be detected, writes the KQL, writes
  the incident-response playbook, and measures whether the detection fires on
  the events it claims. Eleven subcommands; four call a model and are marked
  `PAID` in `pylon design --help`.
- **`pylon validate`** runs a written detection against the workspace and
  reports hits, no hits, or NOT SEARCHED with exit code 1.
- **`pylon tabledrift`** checks Pylon's category-to-table map against what Azure
  currently offers.
- **`pylon config`** stores provider settings and API keys.

### Measurement over assertion

Every claim carries the measurement behind it. Where a measurement was not
taken, the output says so rather than filling the gap with a plausible number.

In `analysis.json` a section is `null` when its read did not run and `[]` when
it ran and found nothing. Every verdict carries a `basis` naming its evidence,
and a validator rejects any document claiming a measurement it never took.

A detection with no events to test against reports `no-ground-truth`, never a
pass.

### Platforms

Python 3.11, 3.12 and 3.13 on Linux, macOS and Windows — nine cells in CI, plus
an install job that uses the README's own `uv tool install` command.

Requires the Azure CLI with the `resource-graph` and `log-analytics` extensions,
Reader on the subscription and Microsoft Sentinel Reader on the workspace.

### Operational

- A crash prints the path to its run log and where to report it. Ctrl-C exits
  130 and reports what the run spent.
- The run log is bounded at 50 runs, and credentials are kept out of it both
  statically and at runtime.
- The config file holding an API key is owner-only, by ACL on Windows and mode
  600 elsewhere.
- Every file read and written names its encoding.
- `--max-cost` defaults to $5.00 and is checked between model calls.
