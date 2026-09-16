# Pylon

Reads a Microsoft Sentinel tenant and reports what it detects, what it is blind
to, and what to do about it.

Read-only. It signs in as you through the Azure CLI and creates nothing.

```
pylon analyze --workspace <name>    what is logging, detecting, exposed
pylon design                        generate detections and IR playbooks
pylon validate --kql d.kql          search the workspace for a detection's hits
pylon config                        settings and API keys
pylon tabledrift                    check Pylon's category-to-table map against Azure
```

`analyze`, `validate`, `tabledrift` and `config` are free.

`design` has eleven subcommands. Four call a model and cost money; they are
marked `PAID` in `pylon design --help`. The other seven are free, including
`design list`, `design tuning` and `design survey`.

---

## Install

Requires Python 3.11+, `uv`, and the Azure CLI. `uv` installs Python for you.

### Windows

```powershell
winget install --id=astral-sh.uv -e
winget install --exact --id Microsoft.AzureCLI
```

**Close PowerShell and open it again.** The Azure CLI is not on `PATH` until you
do.

Without `winget`:

```powershell
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
```

PowerShell chains with `;`, not `&&`.

### Linux (Ubuntu or Debian)

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
curl -fsSL 'https://azurecliprod.blob.core.windows.net/$root/deb_install.sh' | sudo bash
```

### Linux (RHEL, CentOS Stream, Fedora)

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
sudo rpm --import https://packages.microsoft.com/keys/microsoft.asc
sudo dnf install -y https://packages.microsoft.com/config/rhel/9.0/packages-microsoft-prod.rpm
sudo dnf install azure-cli
```

Change `rhel/9.0` to match your version.

### macOS

```bash
brew install uv azure-cli
```

### Any platform

```bash
git clone https://github.com/purpleshellsecurity/Pylon && cd Pylon
uv tool install ".[design,anthropic]"
```

This puts `pylon` on your `PATH`, usable from any directory with nothing to
activate.

Keep the quotes: `zsh` reads square brackets as a filename pattern.

For the free commands only, omit the extras. The extras are model SDKs and only
`design` needs them:

```bash
uv tool install .
```

**Reinstall after a `git pull`.** `uv tool install` copies the code rather than
linking it:

```bash
uv tool install --force ".[design,anthropic]"
```

`uv tool uninstall pylon` removes it.

### Working in the repo

```bash
uv sync --extra dev --extra design --extra anthropic
uv run pylon --help
uv run pytest -q
```

`uv sync` builds a `.venv` in the folder and `uv run` finds it. This reflects
the working tree and only works from inside the repo. `--extra dev` brings
`pytest`.

`uv pip install -e .` installs into whatever virtualenv is ACTIVE, not the
directory you are in. `pylon --version` prints the version and the path it
resolved to, on one line.

`design` writes `detections.html`: every query beside the technique it claims
and the argument for that mapping. Add `--extra pdf` and Pylon writes a PDF
directly:

```bash
uv sync --extra design --extra pdf
```

---

## Updating

Pylon publishes as a single commit, rewritten each release, so `git pull` finds
two histories with no common ancestor. Reset to the remote:

```bash
git fetch origin main
git reset --hard origin/main
uv sync --extra dev --extra design
```

`reset --hard` discards local edits to tracked files. Scan outputs are not
tracked and survive.

---

## Sign in to Azure

```bash
az login
az extension add --name resource-graph
az extension add --name log-analytics
```

Both extensions are required. Neither `az graph query` nor `az monitor
log-analytics query` ships in the core CLI. Without them Pylon reports those
checks as not measured.

**Permissions.** Reader on the subscription. Microsoft Sentinel Reader on the
workspace. Pylon issues GETs and Resource Graph queries only.

**Credentials.** Pylon stores no Azure credentials. It shells out to `az` and
reads nothing your own account cannot. A model API key goes in your home
directory, never the project folder.

---

## Run it

```bash
pylon analyze --workspace my-sentinel-workspace
```

The workspace is its name or a full ARM resource id. Output:

| File | What it is |
| --- | --- |
| `telemetry_health_report.html` | The scan, in the order the data moves: sources, arrival, volume, rules, MITRE coverage, Content Hub |
| `analysis.json` | The raw measurements it is rendered from |

`pylon analyze --render-only` redraws the page from an existing `analysis.json`
without rescanning.

A `recommendations.json` built from a different scan drops the Content Hub
section rather than the page.

In `analysis.json`, a section is `null` when its read did not run and `[]` when
it ran and found nothing. Every verdict carries a `basis` naming its evidence. A
validator rejects any document claiming a measurement it never took.

---

## Generate detections (paid)

Set a model provider:

```bash
pylon config set PYLON_PROVIDER=anthropic
pylon config set ANTHROPIC_API_KEY=sk-ant-...
pylon config show
```

OpenAI:

```bash
pylon config set PYLON_PROVIDER=openai
pylon config set OPENAI_API_KEY=sk-...
pylon config set OPENAI_CHAT_MODEL=gpt-4.1
```

Azure OpenAI:

```bash
pylon config set PYLON_PROVIDER=azure-openai
pylon config set AZURE_OPENAI_ENDPOINT=https://<resource>.openai.azure.com
pylon config set OPENAI_CHAT_MODEL=<your-deployment-name>
```

Settings write to `~/.config/pylon/config.env`, mode 600, or
`$XDG_CONFIG_HOME/pylon/config.env`. Secrets display as `set, ends cdef`.

Four sources are read, highest precedence first:

1. a real environment variable
2. the file `PYLON_CONFIG` names, if set
3. `./pylon.env` in the current directory
4. `~/.config/pylon/config.env`, what `pylon config set` writes

Format is `KEY=value`, one per line, `#` for comments. A leading `export ` is
accepted.

### The workflow

```bash
pylon design list
pylon design tuning Microsoft.KeyVault/vaults
pylon design plan Microsoft.KeyVault/vaults --out ./output
pylon design detections --from ./output --pick all
```

**`design list`** — every target you can design against. Free.

**`design tuning`** — per target: the fields an analyst filters on, the
activities the catalogue excluded and why, a baseline query measured against a
live workspace, the columns this table can be tuned on, and a severity floor
from ATT&CK's tactics. Free, no model call.

**`design plan`** — phase 1 only: what would be built. One model call.

**`design detections`** — phase 2: a query per vector. This is the bill.

Output is one `.kql` per detection, a `detections.html`, a `plan.json` of what
was enumerated, and a `report.json` of the run.

### Cost

Phase 2 is almost the entire cost. A measured Key Vault run made 102 model
calls; 101 were phase 2, totalling $5.83 and fifty-five minutes.

`design plan` shows the same list for one call. `--pick` then builds only what
you select; `--pick all` builds everything.

Plans are also comparable: the same target enumerated 55 vectors on one run and
40 on the next from identical input.

`--max-cost` defaults to $5.00 and is checked between calls, so a run can finish
slightly over.

### Know what the workspace can prove

A plan enumerates a service's entire operation vocabulary; a tenant exercises
part of it. Across every plan in this repo, 39 of 169 planned operations had
ever occurred. The other 130 cost full price and return `no-ground-truth`.

```bash
pylon design survey --from ./runs/kv --workspace my-workspace
```

Free, one query per table. It prints each vector with the number of real events
behind it and returns the `--pick` string for the ones the workspace can settle.
On one lab this reduced a $1.85 Key Vault run of 54 detections to 7 that could
all be proven.

On a table whose contract carries an attribution gate it also prints
`reachable`: rows a detection reporting an actor could match. Blob storage
recorded 95 `ListContainers` events in thirty days and none under OAuth.

A vector with no events is not worthless — it may matter most on a tenant where
the event has not happened yet. This reports what can be proven today.

### Incident-response playbooks

```bash
pylon design playbooks --from ./output --pick all
```

Reads the directory's `report.json`, so phases 1 and 2 are not re-run. `--pick`
accepts `all`, a technique like `T1528`, part of a name, or numbers like `1,3`.
One markdown file per detection, one model call each.

Each playbook runs in order: triage, the actor's full activity, investigation,
cross-log pivots, evidence preservation, containment with an undo for every
step, eradication, validation, recovery, prevention. Preservation precedes
containment because containment destroys the state it would collect.

### Verify against real events

```bash
pylon design verify --from ./output --workspace my-workspace --window 30d
```

Counts the operation in the raw table, counts what the detection returns over
the same window, and compares. The two numbers come from independent sources.

Measured on ten generated detections against a real tenant:

```
  Add application                                   41     41  exact
  Add delegated permission grant                     2      4  over
  Update service principal                          30      0  dead
```

- `exact` — counts match.
- `under` — fewer rows than events. Often correct: these detections exclude
  failed operations and known Microsoft service principals.
- `over` — more rows than events. Always a defect; no filter can add matches.
- `dead` — valid KQL, resolves against the real schema, executes, and cannot
  fire. The example above filtered `modifiedProperties` against the Graph API's
  schema names where the log writes the portal's display names.
- `no-ground-truth` — no events to test against. Not a pass.

It also runs every query inside every playbook in the directory, with responder
blanks filled from a real event. Not behind a flag.

Exits non-zero when anything is `dead`, `over` or errored.

### Sweep every target

```bash
pylon design sweep --out-root ./runs --workspace my-workspace --max-cost 25
```

Plans, builds, writes playbooks for and grades each target in turn. Resumable
and idempotent: each stage is skipped when its output exists, `--force` redoes
it, and a state file records what finished. One target failing does not stop the
rest.

**The budget is spent across the whole sweep**, not per target. Checked between
stages, so a sweep overshoots by at most one stage.

Targets with no telemetry are not skipped; they report `no-ground-truth`.

### What has been checked

```bash
pylon design coverage . /path/to/other/output
```

Reports targets never run and detections never measured alongside the verdicts.
Exits non-zero when anything is defective or unmeasured.

**Nothing generated is deployed.** Pylon does not create Sentinel rules.

### Grade offline, without a tenant

```bash
pylon design record --from ./runs/arm --workspace my-workspace --out fixtures/
```

Captures real rows once and strips the tenant out of them. Each fixture pairs a
detection's query with labelled events: `tp` rows are the operation it targets
and it must match them, `tn` rows are other operations on the same table and it
must not.

**Redacted:** GUIDs, user principal names, IPv4 and IPv6 — replaced with stable
placeholders of the same shape, so the same real id always maps to the same fake
one and joins still resolve. Azure's built-in role GUIDs are kept, in dashed and
undashed spellings, because detections compare against them.

**Not redacted: names.** A resource group called `PYLON-TRIGGER-RG` stays that.
Read a fixture before publishing it.

```bash
export PYLON_KUSTAINER_URL=http://localhost:8080
pylon design grade --fixtures fixtures/
```

Each fixture loads whole, not row by row: an ARM role grant writes a `Start` row
with the request body and a `Success` row with the outcome, and the detection
joins them. The `tp` set loads together and must return something; the `tn` set
loads alone and must return nothing.

A fixture matching nothing reports `silent`, not a failure.

You can only record what has happened. On one tenant, seven of Key Vault's 54
operations had any events.
`scripts/triggers/Invoke-KeyVaultSurfaceTrigger.ps1` performs the rest once —
create, read, list, back up, delete and purge across secrets, keys and
certificates — and cleans up after itself.

---

## validate and tabledrift

**`pylon validate --kql d.kql --workspace <name> --window 7d`** runs a written
detection against the workspace. Three outcomes: hits with a count and sample
rows, no hits, or NOT SEARCHED with exit code 1 when the query did not run.

**`pylon tabledrift`** checks Pylon's built-in map of diagnostic categories to
log tables against what Azure currently offers. The map is hand-written from
Microsoft's documentation; ARM names the categories a resource type emits but
never the table they land in, so it cannot be replaced by a lookup.

Every "enable X to fill Y" in the report comes from that map, so a missing row
makes a real category invisible to every coverage verdict.

Run it when a report does not mention a category you know a resource emits. It
is about eleven ARM calls and free.

It reports one direction: a category Azure offers that the map lacks. The
reverse is printed as context and fails nothing.

Exit 0 means the map matches, 1 means it drifted, 2 means the check could not
run.

---

## Environment variables

Everything here has a working default.

| Variable | Default | What it does |
|---|---|---|
| `PYLON_PROVIDER` | — | `anthropic`, `openai` or `azure-openai`. Usually set through `pylon config set`. |
| `PYLON_VERIFY_WORKSPACE` | off | Grade each detection against real events while generating it, and re-prompt once when it matches nothing. `design detections --workspace` is the same switch and wins over this. |
| `PYLON_VERIFY_WINDOW` | `30d` | How far back that grading looks. |
| `PYLON_KUSTAINER_URL` | off | Run each query through a real KQL engine before shipping it. See below. |
| `PYLON_PRICE_GB` | `4.30` | USD per GB of billable ingestion, for the cost column in the report. List price, Analytics tier. |
| `PYLON_PRICE_INPUT` / `PYLON_PRICE_OUTPUT` | `1.25` / `10.00` | USD per million tokens, for the cost a run reports. |
| `PYLON_CALL_TIMEOUT` | see `engine.py` | Seconds before one model call is abandoned. |
| `PYLON_CALL_DEADLINE` | 2× the timeout | Wall-clock backstop for a blocked event loop. |
| `PYLON_MAX_CONCURRENCY` | see `engine.py` | Detections generated at once. |
| `PYLON_MAX_RETRIES` | see `engine.py` | Retries per model call. |
| `PYLON_LOG_LEVEL` / `PYLON_LOG_FILE` | `INFO` | Console level, and where the structured run log is written. |
| `PYLON_LOG_KEEP` | `50` | Run logs kept in `.pylon/logs/`. Older ones are deleted at startup; `0` disables pruning. |
| `PYLON_RUN_ID` | generated | Force a run id, to join artifacts across commands. |
| `PYLON_CONFIG` | unset | Path to a config FILE read before the usual two. Not a directory, and not where `pylon config set` writes. |

Most can be stored with `pylon config set NAME=value`. Four cannot:
`PYLON_CONFIG`, `PYLON_LOG_LEVEL`, `PYLON_LOG_KEEP` and `PYLON_RUN_ID` are
environment-only and must be exported.

`PYLON_VERIFY_WORKSPACE` and `PYLON_KUSTAINER_URL` are the difference between a
detection that is well formed and one shown to work. Without them a run checks
the query text and nothing else.

### Offline KQL engine

`PYLON_KUSTAINER_URL` points at Microsoft's Kusto engine in a container, so
every query is parsed and resolved by the real engine rather than by regex. It
catches an operator written as a function, a column that does not exist, and an
`extend` reading a name defined beside it.

```bash
docker run -d --name pylon-kustainer -e ACCEPT_EULA=Y -m 4G -p 8080:8080 \
    mcr.microsoft.com/azuredataexplorer/kustainer-linux:latest
export PYLON_KUSTAINER_URL=http://localhost:8080
```

On Apple silicon the image is amd64-only and the command above exits 133 with
`rosetta error: rt_tgsigqueueinfo failed`. It needs the platform named and one
extra variable:

```bash
docker run -d --name pylon-kustainer --platform linux/amd64 \
    -e ACCEPT_EULA=Y -e DOTNET_EnableWriteXorExecute=0 -m 6G -p 8080:8080 \
    mcr.microsoft.com/azuredataexplorer/kustainer-linux:latest
```

Two measured behaviours: it reports no reason for a refusal, only that the query
is bad, identically for a syntax error and an unresolved column. And on Apple
silicon it still dies after a few queries, so treat the endpoint as something
that can vanish mid-run. `src/pylon/kusto_offline.py` has the details.

---

## If something goes wrong

**New to the terminal?** [docs/start-here.md](docs/start-here.md) starts from
opening a terminal window.

**First run not behaving?** [docs/testing.md](docs/testing.md) is the checklist,
in order, with what each step should print.

**Found a vulnerability?** [SECURITY.md](SECURITY.md) — report it privately. It
also states what Pylon touches: it reads and never writes Azure resources,
credentials never reach the command line or the run log, and `design` is the
only command that sends anything to a model provider.

**Hit a bug?** A crash prints the path to its run log and where to report it.
Attach that log.

---

## Licence and changes

MIT — see [LICENSE](LICENSE). What changed in this release is in
[CHANGELOG.md](CHANGELOG.md).
