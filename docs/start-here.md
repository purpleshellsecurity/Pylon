# Start here

For anyone who has not used a terminal much. It assumes nothing. If you already
live in a shell, skip to [testing.md](testing.md).

By the end you will have scanned a Microsoft Sentinel workspace and be looking
at a report of what it is and is not logging. About 30 minutes, most of it
waiting on installers. Nothing here costs money and nothing changes your Azure
tenant — every step only reads.

---

## What you need before you start

- **A Mac, a Linux machine, or Windows.** On Windows the three tools install
  differently — see [Windows: install the tools](#windows-install-the-tools) —
  and everything after that is the same.
- **An Azure account with a Sentinel workspace**, and permission to read it.
  Specifically **Reader** on the subscription and **Microsoft Sentinel Reader**
  on the workspace. If you do not know whether you have those, try anyway — the
  errors are clear and nothing breaks.

---

## Windows: install the tools

**Skip this if you are on a Mac or Linux.**

Everything runs natively in PowerShell. You do not need WSL.

Open PowerShell — press Start, type `PowerShell`, press Enter — and run:

```powershell
winget install --id Git.Git -e --source winget
winget install --id=astral-sh.uv -e
winget install --exact --id Microsoft.AzureCLI
```

`winget` ships with Windows 11 and current Windows 10. If it is not recognised,
install [App Installer](https://apps.microsoft.com/detail/9nblggh4nns1) from the
Microsoft Store, which is what provides it.

**Now close PowerShell and open it again.** This is not optional and it is the
single most common thing that goes wrong — Microsoft names it first in their own
troubleshooting. The tools are on your PATH, but only in a window opened after
the install.

Then check:

```powershell
git --version
uv --version
az --version
```

Three version numbers means you are ready. **Skip steps 1 to 3** and go to
[step 4](#step-4--download-pylon).

Everything from step 4 on works unchanged in PowerShell, with two differences
noted where they come up: `$env:WORKSPACE` instead of `export WORKSPACE`, and
`start telemetry_health_report.html` instead of `open telemetry_health_report.html`.

> **If you would rather use a Unix shell**, WSL works too — `wsl --install` from
> an administrator PowerShell, restart, then follow the Linux notes in step 2.
> It is not required, and it is a larger install than the three tools above.

---

## Step 1 — Open the terminal

On a Mac: press `Cmd + Space`, type `Terminal`, press Enter. On Linux, look for
Terminal in your applications. On Windows, open **PowerShell** from the Start
menu.

A window opens with a line of text and a blinking cursor. That is a prompt. You
type a command, press Enter, it runs, it prints something, you get a new prompt.
That is the entire model.

**Two things worth knowing now:**

- Nothing you type does anything until you press Enter.
- If a command seems stuck, `Ctrl + C` stops it. It is safe.

Copy and paste works normally — `Cmd + V` on a Mac, `Ctrl + V` in PowerShell,
`Ctrl + Shift + V` in most Linux terminals.

---

## Step 2 — Install Homebrew

**macOS only.** On Windows you have already installed everything. On Linux, use
your package manager instead:

```bash
sudo apt update && sudo apt install -y git curl          # Ubuntu or Debian
curl -LsSf https://astral.sh/uv/install.sh | sh
curl -fsSL 'https://azurecliprod.blob.core.windows.net/$root/deb_install.sh' | sudo bash
```

Then open a new terminal so the `uv` installer's PATH change takes effect, and
skip to [step 4](#step-4--download-pylon).

Homebrew installs software from the terminal. Almost everything else here comes
through it.

First check whether you already have it:

```bash
brew --version
```

**If that prints a version number**, skip to step 3.

**If it says `command not found`**, install it. This is the official command
from [brew.sh](https://brew.sh):

```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

It will ask for your password. **You will not see the characters as you type
it** — no dots, no stars. That is normal, not a frozen terminal. Type it and
press Enter.

It takes a few minutes and prints a lot. At the end it may tell you to run two
more commands to "add Homebrew to your PATH". **Do what it says** — copy those
lines and run them. If you skip that, the next step fails with `command not
found` and the reason will not be obvious.

Then confirm:

```bash
brew --version
```

---

## Step 3 — Install the three tools

```bash
brew install git uv azure-cli
```

That is one command installing three things:

| | What it does |
|---|---|
| **git** | downloads the code and keeps it up to date |
| **uv** | runs Python projects without you managing Python |
| **azure-cli** | the `az` command, which talks to Azure |

`azure-cli` is the slow one — several minutes. Let it finish.

Check all three:

```bash
git --version
uv --version
az --version
```

Three version numbers means you are set. Anything saying `command not found`
means that one did not install — run `brew install <name>` again for just that
one and read the error.

---

## Step 4 — Download Pylon

```bash
cd ~
git clone https://github.com/purpleshellsecurity/Pylon.git
cd Pylon
```

Line by line:

- `cd ~` moves you to your home folder. `~` means home.
- `git clone` downloads the code into a new folder called `Pylon`.
- `cd Pylon` moves you into it.

**You must stay in this folder for everything below.** If you close the terminal
and come back, run `cd ~/Pylon` first. To check where you are:

```bash
pwd
```

It should end in `/Pylon`.

---

## Step 5 — Install Pylon

```bash
uv tool install ".[design,anthropic]"
```

Type the quotation marks. On a Mac they are not optional: the shell reads the
square brackets as a filename pattern without them and stops with `no matches
found`.

That reads the project's own list of requirements, installs them into a private
folder of their own, and puts a `pylon` command on your system. Nothing else is
touched, and `uv tool uninstall pylon` removes every trace.

Check it worked:

```bash
pylon --help
```

You should see a list of commands: `analyze`, `recommend`, `validate`,
`tabledrift`, `design`, `config`.

**It works from anywhere now.** Any folder, any new terminal window. You do not
have to be inside the `Pylon` folder and there is nothing to "activate". Older
instructions may tell you to activate a virtual environment first — you do not
need to, and skipping it avoids the most common way this goes wrong.

**One thing to remember.** When you update Pylon later with `git pull`, run the
install line again with `--force` on the end. The command you just installed is
a copy, so a pull on its own leaves you running the old one.

---

## Step 6 — Sign in to Azure

```bash
az login
```

A browser window opens. Sign in with the account that can read your Sentinel
workspace. The terminal then lists your subscriptions.

Check which one you landed on:

```bash
az account show --query "{subscription:name, user:user.name}" -o tsv
```

**If it is the wrong subscription:**

```bash
az account set --subscription "The Right One"
```

This matters. Everything Pylon reads, it reads as you, from this subscription.
Getting it wrong means measuring a tenant you did not mean to.

Then add one Azure CLI extension. Pylon uses Azure Resource Graph to list your
resources, and that lives in an add-on rather than in `az` itself:

```bash
az extension add --name resource-graph
az extension add --name log-analytics
```

Already have them? The commands say so and change nothing. **Do not skip this.**
Two of the commands Pylon depends on are not in the core Azure CLI, and without
them it cannot read your inventory or work out which tables hold data.

---

## Step 7 — Find your workspace name

If you already know it, skip ahead. Otherwise:

```bash
az monitor log-analytics workspace list --query "[].name" -o tsv
```

That lists every Log Analytics workspace you can see. Your Sentinel workspace is
one of them — Sentinel is built on top of Log Analytics, so it appears here.

Save it so you do not retype it:

```bash
export WORKSPACE=the-name-you-just-found
echo "$WORKSPACE"
```

In PowerShell it is written differently:

```powershell
$env:WORKSPACE = "the-name-you-just-found"
echo $env:WORKSPACE
```

**This is forgotten when you close the terminal.** If a later command complains
the workspace is empty, run those two lines again.

---

## Step 8 — Scan

```bash
pylon analyze --workspace "$WORKSPACE"
```

This is the real thing. It reads your resources, your diagnostic settings, your
detection rules and your tables. It takes a few minutes and prints its progress
one step at a time.

It only reads. It cannot create, change or delete anything in Azure — that is a
property of the code, not a promise about how you use it.

It writes two files into the `Pylon` folder:

- `analysis.json` — every measurement, for other commands to use
- `telemetry_health_report.html` — the readable version

---

## Step 9 — Read the report

```bash
open telemetry_health_report.html            # macOS
xdg-open telemetry_health_report.html        # Linux
start telemetry_health_report.html           # Windows PowerShell
```

It opens in your browser. The section to look at first is **Not logging**: your
resources grouped by type, with how many of each are not sending logs anywhere
you can search.

Three things in that table are worth understanding, because they are not the
same thing:

| It says | It means |
|---|---|
| **none of 10 logging** | ten resources of that type, none sending logs |
| **not assessed** | Pylon could not check. Not the same as fine |
| a type is missing | it has nothing to log, so it is not a gap |

That middle one is the point of the whole tool. "I could not look" is never
reported as "I looked and it was fine."

---

## What now

You have the free half working. From here:

- **[testing.md](testing.md)** — the fuller checklist: table drift, validating a
  query, auditing the scan against Azure's raw answers.
- **[../README.md](../README.md)** — what each command does and how it works.

`pylon design` writes detections and is the one command that calls an AI model
and costs money. It needs an API key and an extra install. Leave it until the
rest makes sense.

---

## When something goes wrong

**`command not found: brew`** — Homebrew is installed but not on your PATH. Look
back at the end of step 2 for the two lines it told you to run. On Windows and
Linux there is no Homebrew; you are in the wrong section.

**Windows: `az` or `uv` is not recognised right after installing it** — close
PowerShell and open a new window. The PATH change only reaches windows opened
afterwards. This is the most common Windows problem by a wide margin.

**Windows: the scan says it could not run `az`, but `az --version` works** —
that was a real bug, fixed. Update with `git pull` and try again. If it still
happens, open an issue: it means `az` is somewhere `uv run` cannot see.

**The scan says `az` returned output that is not JSON, mentioning an
extension** — you skipped the `az extension add` line in step 6. Run it, then
run the scan again.

**`command not found: pylon`** — you left off `uv run`. Every Pylon command
starts with it.

**`does not appear to be a Python project`** — you are not in the `Pylon`
folder. Run `pwd`, then `cd ~/Pylon`.

**`az login` opens a browser and nothing happens** — try
`az login --use-device-code` instead. It gives you a code to type into a browser
by hand, which works when the automatic handoff does not.

**A step in the scan says it timed out** — that is deliberate. Each Azure call
is capped so one slow answer cannot hang the whole run. The scan carries on and
the report says that part could not be measured, rather than pretending it found
nothing.

**Something else** — copy the error text, the whole line, and open an issue.
An error described from memory is one that has to be worked out twice.
