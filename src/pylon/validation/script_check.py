"""Static gate for generated shell snippets: does it parse, and does every
command it calls exist?

The consumer is the playbook checker, whose containment steps are PowerShell a
responder is expected to run under pressure.

Nothing here executes the script under test. `bash -n` for bash; for PowerShell
a probe that parses the file into an AST and then resolves it. Linting
attacker-shaped lab code is therefore safe. Degrades gracefully: if the checker
(`bash`/`pwsh`) is missing the check is skipped (`ran=False`), never failed.

Three tiers for PowerShell, and the later two exist because each caught a defect
class the earlier one provably could not see.

1. **Syntax.** Truncated output (the model stopped mid-block), unbalanced
   braces or quotes, unparseable ``<placeholder>`` tokens.

2. **`param()` placement.** A param block that is not the script's first
   statement parses cleanly and fails at RUN time — PowerShell reads it as a
   command call and binds nothing. Tier 1 alone passed 21 of one run's 22
   scripts and all 21 were unrunnable.

3. **Command and parameter resolution.** `New-AzKeyVaultKey` is a perfectly
   good command NAME to a parser; it just does not exist (the cmdlet is
   `Add-AzKeyVaultKey`). Measured on the same 22 scripts: 11 called a cmdlet or
   a parameter that is not in the installed modules — `New-AzKeyVaultKey`,
   `New-AzKeyVaultCertificate`, `New-AzKeyVaultAccessPolicy`,
   `Get-AzKeyVaultDeletedSecret`, `Remove-AzKeyVaultDeletedCertificate`,
   `New-AzKeyVault -EnableRbacAuthorization/-AccessPolicy/-TenantId`,
   `Invoke-AzKeyVaultKeyOperation -Value`. Every one parses. This tier resolves
   each command against the modules the script's own `#Requires` lines name, and
   each named parameter against that command's real parameters and aliases.

Tier 3 needs those modules present to say anything, and "module not installed"
must never be reported as "cmdlet does not exist". So when a required module is
missing the tier does not run and says so, in `ParseResult.unchecked` — the same
discipline as `ran=False`, one level down. A check that quietly did not happen is
the failure mode this file keeps being rebuilt around.

Bash gets tier 1 only. The equivalent for `az` would have to resolve subcommands
against the installed CLI, which is a different mechanism, not this one wearing a
different hat; it is not built rather than half-built.
"""

import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from functools import lru_cache

# A parse is near-instant, but tier 3 imports the modules the script requires and
# an Az module import is seconds, not milliseconds. Sized for that, not the parse.
_TIMEOUT = 90


@dataclass
class ParseResult:
    """Outcome of a script check: whether the checker ran, what it found, and
    which of its tiers could not run at all."""

    ran: bool  # False = checker unavailable / errored out -> treated as skipped
    errors: list[str] = field(default_factory=list)
    # Tiers that could not run and why — e.g. resolution skipped because a module
    # the script requires is not installed here. NOT an error: "could not find
    # out" and "found nothing wrong" are different answers and are kept apart.
    unchecked: list[str] = field(default_factory=list)

    @property
    def failed(self) -> bool:
        """A real, actionable failure (the checker ran and found something)."""
        return self.ran and bool(self.errors)


def _run(cmd: list[str], env: dict | None = None,
         timeout: int | None = None) -> subprocess.CompletedProcess | None:
    """Run a command with output captured and a timeout; None if it can't run
    (missing tool, timeout, OS error) so the caller treats the check as skipped."""
    try:
        return subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout or _TIMEOUT,
            env=env, check=False
        )
    except (OSError, subprocess.SubprocessError):
        return None  # tool vanished mid-call, timeout, etc. -> skip, don't fail


def _lines(text: str) -> list[str]:
    """Split text into non-blank lines."""
    return [ln for ln in text.splitlines() if ln.strip()]


def _check_bash(path: str) -> ParseResult:
    """Parse-check a bash script with `bash -n`; skipped (ran=False) if bash is
    unavailable, else a ParseResult carrying any syntax errors."""
    if not shutil.which("bash"):
        return ParseResult(ran=False)
    proc = _run(["bash", "-n", path])
    if proc is None:
        return ParseResult(ran=False)
    if proc.returncode == 0:
        return ParseResult(ran=True)
    return ParseResult(ran=True, errors=_lines(proc.stderr) or ["bash -n reported a syntax error"])


# The PowerShell probe, run with -File against a temp copy. It parses the target
# into an AST and resolves it; it never dot-sources or executes it. The target
# path arrives via an env var to avoid -Command argument-quoting pitfalls.
#
# Tier 2 (`param` placement) and tier 3 (resolution) are not syntax checks — see
# this module's docstring for the measurement each is built on. A `param`
# CommandAst is the exact signal for tier 2: there is no `param` cmdlet, so a
# command by that name is always the misplaced-block mistake, while a legal param
# block (script or function) parses as a ParamBlockAst and never appears here.
_PWSH_PROBE = r"""
$ErrorActionPreference = 'Stop'
$Path = $env:DE_SCRIPT_PATH
$AstType = 'System.Management.Automation.Language'

$errs = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$null, [ref]$errs)
if ($errs) { $errs | ForEach-Object { $_.ToString() }; exit 1 }

$cmdAsts = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true))

# --- tier 2: param() must be the script's first statement -------------------
$misplaced = @($cmdAsts | Where-Object { $_.GetCommandName() -eq 'param' })
if ($misplaced) {
    $misplaced | ForEach-Object {
        "line " + $_.Extent.StartLineNumber + ": param() is not the script's first " +
        "statement, so PowerShell parses it as a command and binds no parameter. " +
        "Move the param(...) block above every statement - only comments and " +
        "#Requires may precede it."
    }
    exit 1
}

# --- tier 3: every command and named parameter must exist -------------------
# Anchored on the script's OWN #Requires lines. A missing module means we cannot
# tell "no such cmdlet" from "module not installed", so the tier does not run.
$required = @()
if ($ast.ScriptRequirements) { $required = @($ast.ScriptRequirements.RequiredModules) }
$missing = @($required | Where-Object { -not (Get-Module -ListAvailable -Name $_.Name) } |
             ForEach-Object { $_.Name })
if ($missing) {
    "UNCHECKED: command resolution did not run - module(s) not installed here: " +
        ($missing -join ', ')
    exit 0
}
foreach ($m in $required) { Import-Module -Name $m.Name -ErrorAction SilentlyContinue }

$local = @($ast.FindAll({ param($n)
    $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true) |
    ForEach-Object { $_.Name })

$problems = @()
foreach ($c in $cmdAsts) {
    $name = $c.GetCommandName()
    if (-not $name -or $local -contains $name) { continue }
    # Only Verb-Noun names are judged. A bare `az`, `kubectl` or `docker` is an
    # external tool the prompt explicitly allows, and its absence on THIS machine
    # is an environment fact, not a defect in the script.
    if ($name -notmatch '-') { continue }
    $cmd = Get-Command -Name $name -ErrorAction SilentlyContinue
    if (-not $cmd) {
        $hint = ''
        if ($name -match '^[A-Za-z]+-(.+)$') {
            $alt = @(Get-Command -Noun $Matches[1] -ErrorAction SilentlyContinue |
                     Select-Object -ExpandProperty Name -Unique)
            if ($alt) { $hint = " Commands with that noun: " + ($alt -join ', ') + "." }
        }
        $problems += "line " + $c.Extent.StartLineNumber + ": '" + $name +
            "' is not a command in the modules this script requires." + $hint
        continue
    }
    while ($cmd.CommandType -eq 'Alias' -and $cmd.ResolvedCommand) { $cmd = $cmd.ResolvedCommand }
    # A native executable has no declared parameters to check against.
    if ($cmd.CommandType -eq 'Application' -or -not $cmd.Parameters) { continue }
    $known = @($cmd.Parameters.Keys)
    $aliases = @($cmd.Parameters.Values | ForEach-Object { $_.Aliases } | Where-Object { $_ })
    $used = @()
    foreach ($el in $c.CommandElements) {
        if ($el -isnot [System.Management.Automation.Language.CommandParameterAst]) { continue }
        $p = $el.ParameterName
        if ($known -contains $p) { $used += $p; continue }
        $byAlias = @($cmd.Parameters.Values | Where-Object { $_.Aliases -contains $p })
        if ($byAlias.Count -eq 1) { $used += $byAlias[0].Name; continue }
        # PowerShell accepts an unambiguous prefix, so one match is not a defect.
        $prefix = @($known | Where-Object { $_ -like ($p + '*') })
        if ($prefix.Count -eq 1) { $used += $prefix[0]; continue }
        if ($prefix.Count -gt 1) {
            $hint = " Ambiguous prefix of: " + ($prefix -join ', ') + "."
        } else {
            $near = @($known | Where-Object { $_ -like ('*' + $p + '*') })
            $hint = if ($near) { " Did you mean: -" + ($near -join ', -') + "?" } else { '' }
        }
        $problems += "line " + $el.Extent.StartLineNumber + ": '" + $name +
            "' has no parameter -" + $p + "." + $hint
    }
    # --- tier 4a: the named parameters must all fit ONE parameter set ---------
    # Every parameter can exist and the call still be unrunnable:
    # `Invoke-AzRestMethod -Method GET -Path x -ApiVersion y` has -Path in ByPath
    # and -ApiVersion in ByParameters, and PowerShell answers "Parameter set
    # cannot be resolved". Existence is per-parameter; this is the combination.
    if ($used.Count -gt 1 -and $cmd.ParameterSets.Count -gt 1) {
        $fits = @($cmd.ParameterSets | Where-Object {
            $setNames = @($_.Parameters | Select-Object -ExpandProperty Name)
            @($used | Where-Object { $setNames -notcontains $_ }).Count -eq 0
        })
        if ($fits.Count -eq 0) {
            $detail = @()
            foreach ($u in ($used | Select-Object -Unique)) {
                $inSets = @($cmd.ParameterSets | Where-Object {
                    @($_.Parameters | Select-Object -ExpandProperty Name) -contains $u
                } | Select-Object -ExpandProperty Name)
                $detail += "-" + $u + " is in " + ($inSets -join '/')
            }
            $problems += "line " + $c.Extent.StartLineNumber + ": '" + $name +
                "' is called with parameters that do not all belong to one parameter " +
                "set, so PowerShell cannot resolve the call: " + ($detail -join '; ') + "."
        }
    }
}

# --- tier 4b: a script with several parameter sets needs a default ----------
# Two sets and no [CmdletBinding(DefaultParameterSetName=...)] means the script
# cannot be invoked at all - PowerShell cannot tell which set the caller meant
# and fails before the first line runs.
if ($ast.ParamBlock) {
    $setNames = @()
    foreach ($prm in $ast.ParamBlock.Parameters) {
        foreach ($at in $prm.Attributes) {
            if ($at -isnot [System.Management.Automation.Language.AttributeAst]) { continue }
            if ($at.TypeName.Name -ne 'Parameter') { continue }
            foreach ($na in $at.NamedArguments) {
                if ($na.ArgumentName -eq 'ParameterSetName') {
                    $setNames += $na.Argument.Extent.Text.Trim("'", '"')
                }
            }
        }
    }
    $setNames = @($setNames | Select-Object -Unique)
    if ($setNames.Count -gt 1) {
        $hasDefault = $false
        foreach ($at in $ast.ParamBlock.Attributes) {
            if ($at -isnot [System.Management.Automation.Language.AttributeAst]) { continue }
            if ($at.TypeName.Name -notmatch 'CmdletBinding') { continue }
            foreach ($na in $at.NamedArguments) {
                if ($na.ArgumentName -eq 'DefaultParameterSetName') { $hasDefault = $true }
            }
        }
        if (-not $hasDefault) {
            $problems += "line " + $ast.ParamBlock.Extent.StartLineNumber +
                ": the script declares " + $setNames.Count + " parameter sets (" +
                ($setNames -join ', ') + ") but no [CmdletBinding(" +
                "DefaultParameterSetName='...')], so PowerShell cannot resolve which " +
                "set the caller meant and the script cannot be invoked at all."
        }
    }
}
if ($problems) { $problems; exit 1 }
exit 0
"""

_UNCHECKED_PREFIX = "UNCHECKED: "


def _check_powershell(path: str) -> ParseResult:
    """Run the PowerShell probe against `path` — parse, `param()` placement and
    command/parameter resolution — without ever executing the script; skipped
    (ran=False) if no pwsh/powershell."""
    pwsh = shutil.which("pwsh") or shutil.which("powershell")
    if not pwsh:
        return ParseResult(ran=False)
    fd, probe = tempfile.mkstemp(suffix=".ps1")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(_PWSH_PROBE)
        env = {**os.environ, "DE_SCRIPT_PATH": path}
        proc = _run([pwsh, "-NoProfile", "-NonInteractive", "-File", probe], env=env)
    finally:
        try:
            os.unlink(probe)
        except OSError:
            pass
    if proc is None:
        return ParseResult(ran=False)
    lines = _lines(f"{proc.stdout}\n{proc.stderr}")
    unchecked = [ln[len(_UNCHECKED_PREFIX):] for ln in lines if ln.startswith(_UNCHECKED_PREFIX)]
    errors = [ln for ln in lines if not ln.startswith(_UNCHECKED_PREFIX)]
    if proc.returncode == 0:
        # A tier that did not run is not a finding; anything else on stdout at
        # exit 0 is noise (a module's own import warning), not the script's fault.
        return ParseResult(ran=True, unchecked=unchecked)
    return ParseResult(
        ran=True,
        errors=errors or ["PowerShell probe reported a failure with no detail"],
        unchecked=unchecked,
    )


# A reflection probe for Graph PERMISSIONS. Graph
# permission names do NOT map onto Graph cmdlet nouns, which is exactly how the
# cmdlet inventory came to encourage a wrong answer: `Add-MgServicePrincipalPassword`
# exists, so `ServicePrincipal.ReadWrite.All` feels right, and Entra rejects it
# with "the scope does not exist". Application-only permissions are listed
# separately because they are REAL and still invalid in `Connect-MgGraph -Scopes`,
# which fails identically but for a different reason worth telling apart.
_PERMISSION_PROBE = r"""
$ErrorActionPreference = 'Stop'
Import-Module Microsoft.Graph.Authentication -ErrorAction SilentlyContinue
if (-not (Get-Command Find-MgGraphPermission -ErrorAction SilentlyContinue)) {
    "MISSING:Microsoft.Graph.Authentication"; exit 0
}
foreach ($n in (Find-MgGraphPermission -PermissionType Delegated -All -ErrorAction SilentlyContinue).Name) {
    "D:" + $n
}
foreach ($n in (Find-MgGraphPermission -PermissionType Application -All -ErrorAction SilentlyContinue).Name) {
    "A:" + $n
}
"""


@lru_cache(maxsize=1)
def graph_permission_surface() -> tuple[frozenset[str], frozenset[str]]:
    """(delegated, application) Graph permission names.

    The VENDORED reference first, the installed module only as a fallback. That
    order is the whole point, and it was measured: `Find-MgGraphPermission`
    answers from whatever module version happens to be installed, which on the
    machine this was written for knew 344 permissions against the reference's 939.
    A checker built on it rejects 595 real permissions as nonexistent — worse than
    the fabricated-scope bug it was meant to catch, because a gate that fails
    valid input is one people learn to ignore.

    Empty sets mean neither source could be read, and the caller then checks
    NOTHING rather than judging a scope against a list it does not have.
    """
    vendored = _vendored_permissions()
    if vendored[0] or vendored[1]:
        return vendored
    return _module_permissions()


def _vendored_permissions() -> tuple[frozenset[str], frozenset[str]]:
    """The committed permissions reference, through the module that owns it.

    Read straight from `catalog/graph-permissions.json` until it turned out that
    file was a SECOND harvest of a catalog `graph_permissions` already vendors as
    `.gz`, and 153 scopes behind it. Going through the owning module is what stops
    the gate and the grounding disagreeing about what a real scope is."""
    try:
        from ..graph_permissions import permission_planes

        return permission_planes()
    except (OSError, ValueError, KeyError):
        return frozenset(), frozenset()


@lru_cache(maxsize=1)
def _module_permissions() -> tuple[frozenset[str], frozenset[str]]:
    """Fallback: whatever the installed Microsoft.Graph module knows. Stale by
    construction — see graph_permission_surface — but better than no check at all
    when the vendored file is missing."""
    pwsh = shutil.which("pwsh") or shutil.which("powershell")
    if not pwsh:
        return frozenset(), frozenset()
    fd, probe = tempfile.mkstemp(suffix=".ps1")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(_PERMISSION_PROBE)
        proc = _run([pwsh, "-NoProfile", "-NonInteractive", "-File", probe])
    finally:
        try:
            os.unlink(probe)
        except OSError:
            pass
    if proc is None or proc.returncode != 0:
        return frozenset(), frozenset()
    delegated, application = set(), set()
    for line in _lines(proc.stdout):
        if line.startswith("D:"):
            delegated.add(line[2:])
        elif line.startswith("A:"):
            application.add(line[2:])
    return frozenset(delegated), frozenset(application)


# Where a scope name can appear. Both matter, and the second is the one that
# actually bit: the failing script never passed the fabricated scope to
# Connect-MgGraph at all — it declared `$requiredScopes = @('...','...')` and
# compared it against the granted set, while its only Connect-MgGraph line sat
# inside a Write-Host help string.
#
# Anchoring on an invocation alone found 0 of 116. Not anchoring at all found 38
# of 116, all false — it matched that same help text and captured paragraphs as
# scope names. Both were measured before settling here.
_SCOPES_CALL = re.compile(
    r"^[ \t]*Connect-MgGraph\b[^\n]*?-Scopes[ \t]+([^\n]+)$", re.MULTILINE
)
_SCOPES_VAR = re.compile(
    r"^[ \t]*\$\w*[Ss]cope\w*[ \t]*=[ \t]*@?\(?([^\n]+)$", re.MULTILINE
)
_QUOTED = re.compile(r"['\"]([^'\"]+)['\"]")
# A permission name shape: Noun.Verb or Noun.Verb.Qualifier, no spaces.
_PERMISSION_SHAPE = re.compile(r"^[A-Z][A-Za-z]+(?:\.[A-Za-z]+){1,2}$")


def graph_scope_errors(script: str) -> list[str]:
    """Scopes named in `Connect-MgGraph -Scopes` that Entra will reject.

    Three verdicts, because the fix differs: a delegated scope is fine; an
    application-only permission is REAL but invalid here; anything else does not
    exist. All three fail the same way at run time ("the scope does not exist"),
    which is why the message has to say which it is.
    """
    delegated, application = graph_permission_surface()
    if not delegated:
        return []  # could not read the list; judge nothing
    out: list[str] = []
    seen: set[str] = set()
    candidates: list[str] = []
    for pattern in (_SCOPES_CALL, _SCOPES_VAR):
        for m in pattern.finditer(script):
            candidates.extend(_QUOTED.findall(m.group(1)))
    for scope in candidates:
        if True:
            # A variable holds scopes we cannot see; judging it would be guessing.
            # Space- or comma-separated names inside ONE quoted string are a
            # different bug (the parameter takes an array) and not this check's.
            if not _PERMISSION_SHAPE.match(scope):
                continue  # a variable, a sentence, or several names in one string
            if scope in delegated or scope in seen:
                continue
            seen.add(scope)
            if scope in application:
                out.append(
                    f"Connect-MgGraph -Scopes '{scope}': that is an APPLICATION "
                    f"permission and cannot be requested as a delegated scope. "
                    f"Entra rejects it with AADSTS70011. Use a delegated "
                    f"equivalent."
                )
            else:
                out.append(
                    f"Connect-MgGraph -Scopes '{scope}': no such Graph permission. "
                    f"Graph permission names do not follow its cmdlet nouns - a "
                    f"cmdlet named *ServicePrincipal* does not imply a scope named "
                    f"ServicePrincipal.*. Use a real delegated scope."
                )
    return out


# --- tier 5: `.Count` on something that can be $null, under StrictMode --------
# Measured. The first generated script anyone actually RAN died in under a second
# on `if ($missingScopes.Count -gt 0)`. `Where-Object` returns $null when nothing
# matches, and `Set-StrictMode -Version Latest` makes $null.Count a terminating
# error — so the script failed BECAUSE the Graph session had every scope it
# needed. The happy path was the broken one and the error path would have worked.
#
# Tiers 1-4 all pass it: `.Count` is legal syntax against a real property, and
# whether the value is null depends on data, not on the source. This is textual
# rather than AST-based on purpose — it then runs with no pwsh installed, which
# is where most of these get checked.
#
# `@($x).Count` is correct for every case, including when $x really is an array,
# so the fix is never wrong and the rule needs no exceptions.
_BARE_COUNT = re.compile(r"(?<!@\()\$(\w+)\.Count\b")
_STRICT = re.compile(r"Set-StrictMode\s+-Version", re.IGNORECASE)


def strict_mode_count_errors(script: str) -> list[str]:
    """`$x.Count` under Set-StrictMode, which is a terminating error when $x is
    $null. Returns one message per distinct variable."""
    if not _STRICT.search(script):
        return []
    seen: list[str] = []
    for line in script.splitlines():
        code = line.split("#", 1)[0]
        for m in _BARE_COUNT.finditer(code):
            var = m.group(1)
            if var in seen:
                continue
            seen.append(var)
    return [
        f"${v}.Count under Set-StrictMode: a pipeline that matches nothing yields "
        f"$null, and $null.Count is a TERMINATING error - so this fails on the "
        f"path where everything is fine. Use @(${v}).Count, which is correct "
        f"whether ${v} is null, a scalar, or an array."
        for v in seen
    ]


def parse_check(script: str, shell: str) -> ParseResult:
    """Parse-check a script for the given shell ('bash'|'powershell').

    Returns ParseResult; `.failed` is True only when the checker actually ran
    and found syntax errors. A missing checker yields `ran=False` (skipped).
    """
    suffix = ".sh" if shell == "bash" else ".ps1"
    fd, path = tempfile.mkstemp(suffix=suffix)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(script)
        if shell == "bash":
            return _check_bash(path)
        result = _check_powershell(path)
        # Textual, so it stands even when pwsh is absent and the probe was skipped.
        extra = [*strict_mode_count_errors(script), *graph_scope_errors(script)]
        if extra:
            return ParseResult(
                ran=True,
                errors=[*result.errors, *extra],
                unchecked=list(result.unchecked),
            )
        return result
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass
