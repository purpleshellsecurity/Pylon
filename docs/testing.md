# First run against a real tenant

Pylon's test suite runs entirely against stubs — no Azure, no workspace. That
is what makes it fast, and it is also why the first run against a real tenant
is the one that tells you something. This is the checklist for that run.

Work top to bottom. Each step says what to run, what a good result looks like,
and what it means if you get something else. **Stop and note it rather than
pushing through** — a step that fails tells you more than the four after it.

Budget about 30 minutes. Step 0 is setup. Steps 1–7 are free and read-only.
Step 8 costs money and is the only one that does.

**Never used a terminal?** Start with [start-here.md](start-here.md) instead —
it covers installing everything and getting one scan done, then sends you back
here.

---

## 0. Set up

One command. `uv` reads `pyproject.toml`, builds an isolated environment for
the tool, and puts `pylon` on your `PATH`.

```bash
cd ~/code/Pylon                 # wherever you cloned it
uv tool install ".[design,anthropic]"
pylon --help
```

Keep the quotes — `zsh` on macOS reads the brackets as a filename pattern.

**Every command below is just `pylon`.** After that install it runs from any
directory and in any new terminal, so there is no folder to be in and nothing
to activate.

**After a `git pull`, run the install again with `--force`.** It copies the
code rather than linking it, so a pull alone leaves the command on the old
version. That is the one thing that will waste your afternoon.

You may see `source .venv/bin/activate` in older notes. It does the same job by
editing your shell's PATH, and it wears off in a new terminal tab — which is
what produces `pylon: command not found`. Skip it.

**If `uv sync` says "does not appear to be a Python project"**, you are not in
the repo — an empty folder of the right name, or a leftover from a rename.
Check with `ls -la` and `git remote -v`, then clone properly:

```bash
cd ~/code
git clone https://github.com/purpleshellsecurity/Pylon.git
cd Pylon
uv sync
```

**Optional extras**, and you need neither for steps 1–7:

| | Installs | Needed for |
|---|---|---|
| `uv sync` | the tool | scan, report, validate, tabledrift |
| `uv sync --extra design` | model SDKs | step 8 only — the paid one |
| `uv sync --extra dev --extra design` | pytest too | running the test suite |

Then set the workspace once. **A new terminal tab loses this**, so if a later
step says the workspace is empty, this is why:

```bash
export WORKSPACE=my-sentinel-workspace
echo "$WORKSPACE"               # confirm it is set
```

---

## 1. Sign in

```bash
az login
az account show --query "{subscription:name, user:user.name}" -o tsv
```

**Good:** it prints the subscription holding the Sentinel workspace.

**If the subscription is wrong:** `az account set --subscription "<name>"`. Every
read below runs as this identity, so getting it wrong here makes everything
afterwards a test of the wrong tenant.

Then make sure the Resource Graph extension is present. The inventory leg needs
it, and if it is missing `az` installs it mid-query and prints a notice where a
JSON document is expected:

```bash
az extension add --name resource-graph
az extension add --name log-analytics
```

---

## 2. Scan

```bash
time pylon analyze --workspace "$WORKSPACE"
```

**Good:** it finishes, and prints a per-leg timing list as it goes.

**Watch the clock.** An early build ran for 38 minutes before being killed.
Every `az` call is now bounded at 120 seconds, so the worst case should be
minutes, not tens of minutes. If it runs past ~10 minutes, note which leg it is sitting on —
the per-leg lines tell you, and that is the whole reason they exist.

**If a leg reports a timeout:** that is the bound working. The scan should carry
on and the document should say that leg did not run. A timeout that kills the
whole scan is a bug worth reporting.

It writes two files: `analysis.json` (the measurements) and `telemetry_health_report.html` (the
readable version). Open the report — the **Not logging** section is the one to
check, grouped by resource type:

```bash
open telemetry_health_report.html                # macOS
```

---

## 3. Read the summary it prints

The last block of `analyze` output is the one to read carefully:

```
reads.inventory.ran = True
rows                = ...
rules               = ...
coverage_gaps       = ...
tables              = ...
provisioned_tables  = ...
```

**Good:** every line is either a number or the word `null`, and they mean
different things. `0` means the leg ran and found nothing. `null` means the leg
did not run.

**This is the thing to actually look at.** Until today the summary printed `0`
for legs that never ran, which reads as "your tenant has none of these". If you
see a `0` for something you know you have, that is a real bug — write down which
line.

---

## 4. Check what the tenant actually writes to

```bash
uv run python -c "
import json
d = json.load(open('analysis.json'))
data = {t['table_name'] for t in (d.get('tables') or [])}
prov = set(d.get('provisioned_tables') or [])
print('holding data   :', len(data))
print('schemas present:', len(prov))
print('sample with data:', sorted(data)[:8])
"
```

**Good:** the two numbers are very different, and that is expected.

`holding data` is the one that matters — it is what a generated detection gets
confirmed against. `schemas present` counts what your Content Hub solutions
provisioned, which is a much larger number and is **not** evidence anything is
logging.

A gap of one or two orders of magnitude between them is normal — a tenant with
a few dozen tables holding data can easily have several hundred schemas
provisioned. Nothing is wrong with that. An earlier version of this tool
treated the larger number as proof of use, which is the bug this check found.

**If `holding data` is 0 or null:** the table-activity query did not run or
found nothing. Everything else still works — `design` will label its tables
"unchecked" rather than confirming them.

---

## 5. Spot-check a service you know you do not run

```bash
uv run python -c "
import json
d = json.load(open('analysis.json'))
data = {t['table_name'] for t in (d.get('tables') or [])}
for t in ['AKSAudit','CDBDataPlaneRequests','AZMSRunTimeAuditLogs','AZKVAuditLogs']:
    print(f'{t:24} has_data={t in data}')
"
```

**Good:** `has_data=False` for every service you do not run, and `True` for ones
you do.

This is the check that caught the original bug. If a table shows `has_data=True`
for a service you are certain is not deployed, say so — that would mean the
confirmation signal is wrong again, in the other direction.

---

## 6. Table drift

```bash
pylon tabledrift
echo "exit: $?"
```

Three possible outcomes, and they are deliberately different:

| exit | meaning | what to do |
|---|---|---|
| 0 | the map matches, or a type could not be read | read the output — "NOT CHECKED" lines are a permissions gap, not a pass |
| 1 | Azure offers a log category the map has no row for | note which ones. This is the check doing its job |
| 2 | the check could not run at all | read the reason |

**The likely first-run result is a lot of NOT CHECKED**, because this needs
`Microsoft.Insights/diagnosticSettingsCategories/read` and nobody has confirmed
you have it. That is why it exits 0 rather than failing — but it also means it
told you nothing. If every line says NOT CHECKED, the permission is the thing to
fix before trusting the monthly job.

---

## 7. Validate a detection

Feed it a query you already know returns rows, so a `no hits` result means
something.

```bash
echo 'AzureActivity | where TimeGenerated > ago(24h)' > /tmp/known-good.kql
pylon validate --kql /tmp/known-good.kql --workspace "$WORKSPACE" --window 24h
```

**Good:** `HITS <n> row(s) in the last 24h`, and the rows print readably — time,
operation and caller first, not an alphabetical dump of empty columns.

**If you get `no hits`** on a query you know matches, something is wrong with the
search path, not the tenant.

**If you get `NOT SEARCHED`**, the query did not run and the message says why.
That is the honest outcome, not a failure of the tool.

---

## 8. Generate detections — this one costs money

Only if a model provider is configured (`pylon config show`).
This is the one step that needs the extra install:

```bash
uv sync --extra design
```

```bash
pylon design detections Microsoft.KeyVault/vaults \
                        --max-cost 2.00
```

The target is the Azure resource type. `pylon design list` prints every
one, with the tables it queries and the operation strings it grounds against.

Key Vault on purpose: it is the one target that carries both planes, so a single
run covers control-plane changes in `AzureActivity` and data-plane secret access
in `AZKVAuditLogs`, which is the sharpest test of the labelling below.

**Good:** it writes `.kql` files and a `report.json`, and the printed list looks
like this:

```
 1  T1098.003  RBAC role assignment outside change window
 2  T1078.004  Key Vault secret enumeration  [table not in the scanned workspace]

 ! 1 detection(s): AZKVAuditLogs: NOT confirmed — ...
```

**What to check:** does the labelling match reality? A detection against a table
your workspace genuinely has should carry **no** marker. One against a table you
have not deployed should be marked. If everything is marked, or nothing is, the
labelling is not reading step 4's list properly.

`--max-cost 2.00` is a hard cap. It stops between calls, so the real spend lands
a little under it.

### Then turn one of them into a playbook

Re-run the target with `--out` so the run is saved, then build the playbooks from
what is already paid for:

```bash
pylon design detections Microsoft.KeyVault/vaults \
                        --max-cost 2.00 --out ./output
pylon design playbooks --from ./output --pick 1 --max-cost 1.00
```

**Good:** one `-playbook.md` beside the `.kql`, and it names your table and your
operation rather than a generic example. `--pick` also takes `all`, a technique
like `T1555.006`, or part of a detection's name.

**What to check:** open it and read the Containment section. Every option there
has to state how to undo it. An option with no undo is the fault worth reporting.

---

## 8b. Audit the scan against Azure

The check that found three bugs on the first run, automated. It puts the scan's
conclusion about a resource next to the raw API response for that same resource,
across as many as you ask for.

```bash
uv run python scripts/audit-against-azure.py --limit 50
echo "exit: $?"
```

One `az` call per resource, so 50 takes a couple of minutes. `--type vm` or
`--type keyvault` narrows it.

**Good:** `every check agreed`.

**A disagreement is not automatically a bug.** It is a place two sources say
different things, which is where to look. The output names the resource, both
answers, and which check disagreed — read the raw response next to that row in
`analysis.json` before changing anything.

What it checks, and why each one can be trusted: every check compares against
something that does not come from the parse being checked.

- a resource reported as having **no diagnostic setting** must have none. (This
  check first matched `never configured`, which the scan used for two different
  states, and accused the workspace itself on the first real run. The
  vocabulary was split at the source rather than the check being loosened.)
- a resource reported as **logging** must have a setting pointing at the scanned
  workspace — a setting shipping elsewhere is not coverage here
- a table the scan names must **exist in this workspace**, checked against the
  workspace's own schema list rather than the hand-maintained column catalogue
- a **VM's table must match its operating system**, read from Azure. `Event` is
  Windows-only, so naming it for a Linux machine is advice nobody can follow

That last one is the check that would have caught the Ubuntu VM without anyone
reading JSON.

---

## 9. The one open question a single query settles

Paste this into the Log Analytics query window in the portal. It answers whether
SQL auditing in your tenant lands in the resource-specific table or the shared
one — which decides whether four missing rows can be added to the table map.

```kql
union isfuzzy=true
  (SQLSecurityAuditEvents | summarize n=count() | extend Where="dedicated table"),
  (AzureDiagnostics | where Category == "SQLSecurityAuditEvents"
                    | summarize n=count() | extend Where="AzureDiagnostics")
```

`isfuzzy=true` means a table that does not exist returns empty instead of
erroring, so this answers even if only one of the two is real.

Whichever side has rows is the mode your SQL auditing uses. If both are empty
you have no SQL auditing on and the question stays open.

---

## What to write down

For each step: pass, fail, or "odd". For anything not a clean pass, the useful
notes are:

- which step, and the exact command
- what it printed (the error line, not a paraphrase)
- how long it took, if it was slow

That is enough to act on. A finding without the output is a finding that gets
re-derived from scratch.

## What is already known to be incomplete

These are known and expected. No need to report them:

- **The table swap does not run yet.** `design` will *label* an unconfirmed
  table but will not substitute a different one. Labelling is the half that
  shipped; the substitution needs a resource-mode path the CLI does not set.
- **Playbook queries are checked more loosely than detections.** A detection is
  checked against Microsoft's documented column list for its table, and a column
  that is not on it fails. A playbook's queries are not given that list, so the
  same column is a warning nobody has to act on.
