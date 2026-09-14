# Pylon

Reads a Microsoft Sentinel tenant and tells you what it actually detects, what
it is blind to, and what to do about it.

Read-only. It signs in as you, through the Azure CLI, and creates nothing.

```
pylon analyze --workspace <name>    what is logging, detecting, exposed
pylon recommend                     what to turn on in Content Hub
pylon design                        write the detections and IR playbooks nobody ships
pylon validate --kql d.kql          search the workspace for a detection's hits
pylon tabledrift                    check the table map against what Azure offers
pylon config                        settings and API keys
```

Everything except `design` is free. `design` calls a model and costs money.

---

## Install

You need three things: Python 3.11 or newer, `uv`, and the Azure CLI. `uv` installs
Python for you, so really it is two.

### Windows

Open PowerShell.

```powershell
winget install --id=astral-sh.uv -e
winget install --exact --id Microsoft.AzureCLI
```

**Close PowerShell and open it again.** The Azure CLI is not on your `PATH`
until you do, and every command below will fail with "not recognized".

If `winget` is not available, install `uv` with:

```powershell
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
```

PowerShell chains commands with `;`, not `&&`. If you paste a command from
somewhere else and it errors on `&&`, that is why.

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

### Then, on any platform

```bash
git clone https://github.com/purpleshellsecurity/Pylon && cd Pylon
uv tool install ".[design,anthropic]"
```

That puts `pylon` on your `PATH`. It works from any directory, in any new
terminal, with no folder to be in and nothing to activate.

Keep the quotes. `zsh`, the default shell on macOS, reads square brackets as a
filename pattern and fails with `no matches found` without them.

Leave the brackets off entirely if you only want the free half:

```bash
uv tool install .
```

`analyze`, `recommend`, `validate`, `tabledrift` and `config` all work from that
install. The extras are the model SDKs, and only `design` needs them.

**After a `git pull`, reinstall.** `uv tool install` copies the code rather than
linking it, so a pull alone leaves the installed command on the old version:

```bash
uv tool install --force ".[design,anthropic]"
```

`uv tool uninstall pylon` removes it.

### Working in the repo instead

If you are changing the code, skip the tool install and use the checkout
directly:

```bash
uv sync --extra dev --extra design --extra anthropic
uv run pylon --help
uv run pytest -q
```

`uv sync` builds a `.venv` inside the folder and `uv run` finds it. That always
reflects what is in the working tree, which is what you want while editing, and
it only works from inside the repo folder.

`--extra dev` is what brings `pytest`. Leaving it out gives you a working tool
and no way to run its tests, which is a confusing five minutes.

**One trap worth knowing.** `uv pip install -e .` installs into whatever
virtualenv is ACTIVE, not the directory you are standing in. With another
checkout's venv active, running it here points that one at this source, and both
then run code from a tree you did not mean. `pylon --version` prints the version
AND the path it resolved to, in one line, for exactly this reason — check it
before a session that matters.

`design` writes `detections.html`, a page carrying every query alongside the
technique it claims and the argument for that mapping. Open it in a browser and
print to PDF whenever you need a file to send. Add `--extra pdf` and Pylon
writes the PDF itself, which is worth it only if you are generating reports
without a person present:

```bash
uv sync --extra design --extra pdf
```

---

## Updating

Pylon is published as a single commit that gets rewritten on every release, so
`git pull` finds two histories with no common ancestor and stops with
"divergent branches". Reset to the remote instead:

```bash
git fetch origin main
git reset --hard origin/main
uv sync --extra dev --extra design
```

`reset --hard` throws away local edits to tracked files. Your scan outputs are
not tracked, so `analysis.json` and both HTML reports survive it.

---

## Sign in to Azure

```bash
az login
az extension add --name resource-graph
az extension add --name log-analytics
```

Both extensions are required. Neither `az graph query` nor `az monitor
log-analytics query` ships in the core CLI, and they are what read your resource
inventory and your table activity. Without them Pylon reports those checks as
not measured, which is honest and not much use.

**Permissions you need.** Reader on the subscription, for the resource
inventory. Microsoft Sentinel Reader on the workspace, for the rules and the
logs. Nothing more. Pylon issues GETs and Resource Graph queries and never
creates, updates or deletes anything.

**Credentials.** Pylon stores no Azure credentials. It shells out to `az`, so it
runs as whoever you signed in as and can read nothing your own account cannot. A
model API key, if you add one, goes in a file in your home directory, never in
the project folder.

---

## Run it

```bash
pylon analyze --workspace my-sentinel-workspace
pylon recommend
```

The workspace is its name, or a full ARM resource id.

You get three files in the current folder:

| File | What it is |
| --- | --- |
| `telemetry_health_report.html` | What is logging, what is dark, what your rules can and cannot see |
| `content_hub_recommendations.html` | What to turn on in Content Hub, and which installed rules are switched off |
| `analysis.json` | The raw measurements both reports are rendered from |

Open the two HTML files in a browser. **Stop here if you only want the
assessment.** Everything past this point costs money.

`recommend` deliberately does not re-scan. It renders from the `analysis.json`
that `analyze` just wrote, so the two documents always describe the same moment.

---

## Generate detections (paid)

First tell Pylon which model to use:

```bash
pylon config set PYLON_PROVIDER=anthropic
pylon config set ANTHROPIC_API_KEY=sk-ant-...
pylon config show
```

Or OpenAI:

```bash
pylon config set PYLON_PROVIDER=openai
pylon config set OPENAI_API_KEY=sk-...
pylon config set OPENAI_CHAT_MODEL=gpt-4.1
```

Or Azure OpenAI:

```bash
pylon config set PYLON_PROVIDER=azure-openai
pylon config set AZURE_OPENAI_ENDPOINT=https://<resource>.openai.azure.com
pylon config set OPENAI_CHAT_MODEL=<your-deployment-name>
```

Settings go to `~/.config/pylon/config.env`, readable only by you. A real
environment variable always beats the file, so a CI secret wins over a config
you set weeks ago. Secrets print as `set, ends cdef`.

Then:

```bash
pylon design list
pylon design tuning Microsoft.KeyVault/vaults
pylon design plan Microsoft.KeyVault/vaults --out ./output
pylon design detections --from ./output --pick all
```

`design tuning` costs nothing and makes no model call. It prints, per target,
the fields an analyst actually filters on, the activities the catalogue
excluded and the written reason for each, a baseline query taken from the
table contract that was measured against a live workspace, the columns this
table can be tuned on, and a severity floor derived from ATT&CK's own tactics.

Its false-positive line is identical on every target, and deliberately so:
whether an actor is authorized is a fact about one organization, not a property
of the log data, so the field asks the question rather than inventing an
answer.

You get one `.kql` per detection, a `detections.html` page carrying each query
beside the technique it claims, a `plan.json` recording what was enumerated, and
a `report.json` with the whole run.

**What it costs, and why the two steps.** Phase 1 enumerates what could be
detected; phase 2 writes a query for each. A measured Key Vault run made 102
model calls and 101 of them were phase 2 — $5.83 and fifty-five minutes to find
out what was on offer. `design plan` shows the offer for the price of one call,
and `--pick` builds only what you want, so choosing costs a look rather than a
bill. `--pick all` skips the choosing.

The same target enumerated 55 vectors on one run and 40 on the next from
identical input, so a saved plan is also how you see that drift: diff two plans
instead of two invoices.

`--max-cost` defaults to $5.00 and is checked between calls, so a run can finish
slightly over.

**Incident-response playbooks.** A detection tells you something happened. The
playbook is what to do next, and it is generated from a run you have already paid
for rather than from scratch:

```bash
pylon design playbooks --from ./output --pick all
```

It reads the `report.json` in that directory, so phases 1 and 2 are not re-run.
`--pick` takes the same shapes as `design detections`: `all`, a technique like
`T1528`, part of a name, or numbers like `1,3`. One markdown file per detection
lands beside the `.kql`, costing one model call each.

Each playbook is one document worked in order: triage, the actor's full activity,
investigation, cross-log pivots, evidence preservation, containment with the undo
for every step, eradication, validation, recovery and prevention. Preservation
comes before containment on purpose, because containment destroys the state you
would have collected.

**Does the detection actually detect?** Every other check asks whether a query is
well formed. `design verify` asks whether it matches the events it claims to,
by counting the operation in the raw table and counting what the detection
returns over the same window:

```bash
pylon design verify --from ./output --workspace my-workspace --window 30d
```

The two numbers come from independent sources and the detection cannot influence
the first, which is what makes the comparison worth anything. Measured on ten
generated detections against a real tenant:

```
  Add application                                   41     41  exact
  Add delegated permission grant                     2      4  over
  Update service principal                          30      0  dead
```

It also runs every query inside every playbook the directory holds, with the
responder blanks filled from a real event, because a playbook carries six to ten
queries someone pastes at 3am and `check_playbook` only proves the document has
the right shape. Not behind a flag: a check nobody remembers to ask for is a
check that does not happen.

The asymmetry is deliberate. Returning FEWER rows than there are events is often
correct, because these detections exclude failed operations and known Microsoft
service principals on purpose. Returning MORE is never correct, since no filter
can add matches. So `over` is a defect and `under` is a question.

`dead` is the one that matters. That detection is valid KQL, resolves against the
real schema, executes without error, and cannot fire: it filtered
`modifiedProperties` against the Graph API's schema names where the log writes
the portal's display names. Nothing in the query text says so.

A detection with no events to test against is reported as `no-ground-truth`, never
as a pass. An empty workspace looks exactly like a detection that can never fire.
The command exits non-zero when anything is `dead`, `over` or errored.

**Every target, in one command.** `design sweep` plans, builds, writes playbooks
for and grades each target in turn, so the loop that already closes around a
single detection also closes across the catalogue:

```bash
pylon design sweep --out-root ./runs --workspace my-workspace --max-cost 25
```

It is resumable and idempotent. Each stage is skipped when its output is already
on disk, `--force` redoes it, and a state file records what finished, so a sweep
killed at target nine resumes at nine. One target failing does not stop the rest;
the state file says which stage stopped so a rerun retries only that.

The budget is spent **across the whole sweep**, not per target. Twenty-five
targets at $5 each is $125, and a flag that reads like it means five is worse
than no flag. It is checked between stages, so a sweep can overshoot by at most
one stage, because a model call already in flight cannot be un-spent.

Targets with no telemetry are not skipped. A detection nothing can grade is
reported as `no-ground-truth`, which is an answer: the workspace cannot settle
the question, which is different from the detection being wrong and different
again from nobody having asked. Skipping them would quietly shrink the
denominator of every coverage figure below.

**What has actually been checked.** Verification lives in each run's own
`report.json`, so across many targets "have we checked all of this" becomes a
question nobody can answer from memory:

```bash
pylon design coverage . /path/to/other/output
```

It reports targets never run and detections never measured alongside the
verdicts, because neither is a pass. It exits non-zero when anything is
defective or unmeasured.

**Nothing generated is deployed.** Pylon does not create Sentinel rules. You
review the KQL and deploy it yourself.

---

## The other two commands

**`pylon validate --kql d.kql --workspace <name> --window 7d`** runs a written
detection against the workspace and tells you what it would have caught. Three
outcomes, kept apart deliberately: hits with a count and sample rows, no hits,
or NOT SEARCHED with exit code 1 when the query did not run. A search that
failed is not a detection that found nothing.

**`pylon tabledrift`** checks the built-in map of diagnostic categories to log
tables against what Azure currently offers. That map is written by hand from
Microsoft's documentation and there is no second source for it, so it cannot be
replaced by a lookup. This is the expiry check on it. Exit 0 means the map
matches, 1 means it drifted, 2 means the check could not run.

---

## The rule the whole codebase enforces

Every claim carries the measurement behind it. Where a measurement was not
taken, the report says so rather than filling the gap with a plausible number.

This is enforced, not aspirational. In `analysis.json` a section is `null` when
its read did not run and `[]` when it ran and found nothing. A validator rejects
any document claiming a measurement it never took. Every verdict carries a
`basis` naming its evidence.

It matters because the failure mode is silent. When the ATT&CK index went
missing during a refactor, the loader swallowed the error, the denominator
became zero, and the report rendered "0 live Enterprise techniques apply to
them" as a finding. That is now a hard failure with the reason printed on the
page.

---

## Know what you can prove, before you pay for it

Phase 2 is almost the whole bill, and a plan enumerates a service's entire
operation vocabulary while a tenant exercises a handful of it. Measured across
every plan in this repo: **39 of 169 planned operations had ever happened.**
Building the other 130 costs full price and returns `no-ground-truth`, which is
not a pass and not a failure — it is a question nobody could answer.

One query per table says so in advance, for free:

```bash
pylon design survey --from ./runs/kv --workspace my-workspace
```

It prints each vector with the number of real events behind it, and hands you
the `--pick` string for the ones the workspace can settle. On the lab this was
written against that turned a $1.85 Key Vault run of 54 detections into a
7-detection run that could all be proven.

A vector with no events is not worthless — it may be the detection that matters
most on a tenant where the thing has not happened yet. This says which can be
proven today, not which are worth writing.

---

## Grade a detection without a tenant

Everything this tool knows about Azure's log shapes came from reading real rows:
that `Authorization.evidence.role` is the **caller's** role and not the granted
one, that `ResourceId` is empty on every role-assignment row while `_ResourceId`
is populated, that the assignment id arrives dashed on writes and undashed on
most deletes. None of it is in Microsoft's documentation.

`design record` captures those rows once and strips the tenant out of them, so
the same detections are graded offline from then on — no workspace, no
credentials, no retention window:

```bash
pylon design record --from ./runs/arm --workspace my-workspace --out fixtures/
```

Each fixture pairs the detection's query with labelled events. `tp` rows are the
operation the detection targets and it must match them; `tn` rows are other
operations on the same table and it must not. That is not a substitute for
judging whether a particular grant should alert, but it is a direct test of the
defects that actually happen: a filter comparing the wrong shape, a role GUID
that names a different role, a detection that quietly dropped its filter.

**What is redacted:** GUIDs, user principal names, IPv4 and IPv6 — replaced with
stable placeholders of the **same shape**, because the shape is what the bugs
are about, and the same real id always maps to the same fake one so joins still
resolve. Azure's own built-in role GUIDs are kept, in both the dashed and
undashed spellings, because several detections compare against exactly those.

**What is not:** names. A resource group called `PYLON-TRIGGER-RG` stays that,
and in a customer tenant it might be their company. Redacting names generically
would mangle the operation, table and role names that are a fixture's whole
content, so this strips identifiers and a human reads a fixture before
publishing it.

Then grade them, offline, with no tenant involved:

```bash
export PYLON_KUSTAINER_URL=http://localhost:8080
pylon design grade --fixtures fixtures/
```

Each fixture is loaded as a whole, not row by row. An ARM role grant writes a
`Start` row carrying the request body that says which role and a `Success` row
carrying the outcome, and the detection joins them — hand that query one row and
the join has nothing to join to, so a correct detection scores zero. The `tp`
set is loaded together and must return something; the `tn` set is loaded alone
and must return nothing.

A fixture that matches nothing is reported as `silent` rather than as a failure.
A detection filtering on a value *inside* the operation, or counting toward a
threshold, may need rows a small fixture does not hold.

You can only record what has happened. On the tenant this was written against,
seven of Key Vault's 54 operations had any events at all, because nobody in a
lab reads a secret or rotates a key. `scripts/triggers/Invoke-KeyVaultSurfaceTrigger.ps1`
performs the rest once — create, read, list, back up, delete and purge across
secrets, keys and certificates — so recording can cover them from then on. It
creates everything it touches and cleans up after itself.

---

## Environment variables

Everything here has a default that works. These change it.

| Variable | Default | What it does |
|---|---|---|
| `PYLON_PROVIDER` | — | `anthropic`, `openai` or `azure-openai`. Usually set through `pylon config set` instead. |
| `PYLON_VERIFY_WORKSPACE` | off | Grade each detection against real events **while generating it**, and re-prompt once when it matches nothing. `design detections --workspace` is the same switch, and wins over this. |
| `PYLON_VERIFY_WINDOW` | `30d` | How far back that grading looks. |
| `PYLON_KUSTAINER_URL` | off | Run each query through a real KQL engine before shipping it. See **Offline KQL engine** below. |
| `PYLON_PRICE_GB` | `4.30` | USD per GB of billable ingestion, for the cost column in the telemetry report. List price, Analytics tier — set your own. |
| `PYLON_PRICE_INPUT` / `PYLON_PRICE_OUTPUT` | `1.25` / `10.00` | USD per million tokens, for the cost a run reports. |
| `PYLON_CALL_TIMEOUT` | see `engine.py` | Seconds before one model call is abandoned. |
| `PYLON_CALL_DEADLINE` | 2× the timeout | Wall-clock backstop, for when a blocked event loop stops the timeout firing. It has. |
| `PYLON_MAX_CONCURRENCY` | see `engine.py` | Detections generated at once. |
| `PYLON_MAX_RETRIES` | see `engine.py` | Retries per model call. |
| `PYLON_LOG_LEVEL` / `PYLON_LOG_FILE` | `INFO` | Console level, and where the structured run log is written. |
| `PYLON_LOG_KEEP` | `50` | How many run logs to keep in `.pylon/logs/`. Older ones are deleted at startup; `0` disables pruning. |
| `PYLON_RUN_ID` | generated | Force a run id, to join artifacts across commands. |
| `PYLON_CONFIG` | `~/.pylon` | Where `pylon config` stores its settings. |

Anything in that table can be stored with `pylon config set NAME=value` instead
of exported. `PYLON_MAX_COST` and `PYLON_MAX_TOKENS` used to be accepted there
and were read by nothing — a cap you could set and did not have. They are gone;
use `--max-cost` and `--max-tokens` on the commands that spend.

**The two worth knowing about** are `PYLON_VERIFY_WORKSPACE` and
`PYLON_KUSTAINER_URL`, because they are the difference between a detection that
is well formed and one that has been shown to work. Without them a run checks
the query text and nothing else, and it will tell you it produced a valid
detection when the query matches none of the events it claims to detect.

### Offline KQL engine

`PYLON_KUSTAINER_URL` points at Microsoft's Kusto engine running as a container,
so every query is parsed and resolved by the real thing rather than by the
regexes here. It catches what a rule cannot: an operator written as a function,
a column that does not exist, an `extend` reading a name defined beside it.

```bash
docker run -d --name pylon-kustainer -e ACCEPT_EULA=Y -m 4G -p 8080:8080 \
    mcr.microsoft.com/azuredataexplorer/kustainer-linux:latest
export PYLON_KUSTAINER_URL=http://localhost:8080
```

**On Apple silicon** the image is amd64-only and the command above exits 133 with
`rosetta error: rt_tgsigqueueinfo failed`. It needs the platform named and one
extra variable, and it may still die after a few queries — treat the endpoint as
something that can vanish mid-run:

```bash
docker run -d --name pylon-kustainer --platform linux/amd64 \
    -e ACCEPT_EULA=Y -e DOTNET_EnableWriteXorExecute=0 -m 6G -p 8080:8080 \
    mcr.microsoft.com/azuredataexplorer/kustainer-linux:latest
```

Two things measured rather than assumed. It reports **no reason** for a refusal,
only that the query is bad, identically for a syntax error and an unresolved
column — so it is a gate, not a source of guidance. And on Apple silicon it dies
under Rosetta after a few queries even with the documented workaround, so treat
the endpoint as something that can vanish mid-run. `src/pylon/kusto_offline.py`
has the full Apple silicon invocation and what was measured.

---

## Known gaps

- KQL column validation in a PLAYBOOK is not a membership check. Detections are
  checked against Microsoft's own documented column list for the table and a
  column that is not on it is an error; playbook queries are not given that list,
  so the same column is only ever a warning.
- A playbook's validation result is not recorded on the artifact, so a playbook
  read later carries no evidence it was checked.
- `design` picks its table from a catalogue of what Azure offers. Where a scan
  document is present it says whether the tenant actually has that table. Where
  one is not, the table name is an assumption and is labelled as one.
- Rules that read a table through a KQL *function* are invisible to the coverage
  check, so a table may be listed as unread when a rule does read it.

---

## If something goes wrong

**New to the terminal?** [docs/start-here.md](docs/start-here.md) walks through
it from opening a terminal window, assuming nothing.

**First run not behaving?** [docs/testing.md](docs/testing.md) is the checklist,
in order, with what each step should print.
