"""Render a playbook per table and RUN every KQL block against a real workspace.

The offline gate (`contracts.conforms`, wired into
tests/test_playbook_sections_are_measured.py) checks a query against what the
contract measured. This checks it against the workspace itself, which is the
only thing that can say a column resolves.

It found four bugs the first time it was pointed at the playbooks, all the same
shape and all shipping: the data-plane asset spelled CallerIpAddress,
OperationName and CorrelationId by hand and fell through to the storage
defaults for RequesterUpn, so three tables added after the asset was written
failed four or five of their own queries. The ARM asset projected ResourceId,
which the AzureActivity contract has recorded as never populated since it was
written.

Usage: WORKSPACE=<customer id> python scripts/verify-playbook-kql.py
"""
import json, re, subprocess, sys
sys.path.insert(0, "src")
from types import SimpleNamespace
from pylon.playbook import PlaybookFill, document_template, render

import os
W = os.environ.get("WORKSPACE", "")
if not W:
    sys.exit("set WORKSPACE to a Log Analytics customer id")
FILL = PlaybookFill(
    what_happened="The actor reached the object.",
    attack_context="The actor reached the object. The material is now disclosed.",
    why_it_matters=["The material is disclosed", "The actor still holds the access"],
    true_positive_indicators=["No prior history for this principal", "Followed by an export"],
    containment_role="Reader")

# Only the blanks Pylon itself declares. A catch-all over [...] eats the JSON
# claim path in the ARM query -- ["http://schemas.microsoft.com/..."] -- and
# turns valid KQL into a parse error that looks like a product bug.
from pylon.playbook import RESPONDER_BLANKS
SUBS = []
for _b in RESPONDER_BLANKS:
    if "TimeGenerated" in _b or "CONTAINMENT" in _b:
        SUBS.append((re.escape(_b), "2026-09-13T00:00:00Z"))
    elif "WINDOW" in _b:
        SUBS.append((re.escape(_b), "90d"))
    else:
        SUBS.append((re.escape(_b), "x"))
SUBS.append((r"\[the operation from Phase 2\]", "Op"))
PRELUDE = ('let AlertTime = datetime(2026-09-13T00:00:00Z);\n'
           'let AlertActor = "x";\nlet AlertSrcIp = "x";\nlet AlertTarget = "x";\n'
           'let TriageWindow = 90d;\nlet AllowedActors = dynamic([]);\n')

CASES = [("dataplane", t, "", "Op") for t in
         ("AZKVAuditLogs", "StorageBlobLogs", "StorageFileLogs", "StorageQueueLogs",
          "StorageTableLogs", "AppServiceAuditLogs", "AppServiceIPSecAuditLogs",
          "FunctionAppLogs")]
CASES += [("dataplane", "AzureDiagnostics", s, "Op") for s in
          ("MICROSOFT.SQL/SQLSecurityAuditEvents", "MICROSOFT.AUTOMATION/AuditEvent",
           "MICROSOFT.AUTOMATION/JobLogs", "MICROSOFT.AUTOMATION/JobStreams")]
CASES += [("arm", "AzureActivity", "", "Op"), ("entra", "AuditLogs", "", "Op")]

fails = 0
for platform, table, section, op in CASES:
    target = SimpleNamespace(operation=op, priority="high", detection=SimpleNamespace(
        vector_name="V", mitre_technique="T1485 Data Destruction", false_positive_notes="fp"))
    t = document_template(platform, table, "V", operation=op,
                          technique="T1485 Data Destruction", az_provider=section)
    doc = render(t, target, table, FILL, section)
    bad = []
    for i, block in enumerate(re.findall(r"```kql\n(.*?)```", doc, re.S)):
        if "_GetWatchlist" in block:
            continue
        q = block
        for pat, val in SUBS:
            q = re.sub(pat, val, q)
        if "let ContainmentTime" in q or "let AlertCorrelationId" in q:
            prelude = PRELUDE
        else:
            prelude = PRELUDE + "let ContainmentTime = datetime(2026-09-13T00:00:00Z);\n"
        r = subprocess.run(["az", "monitor", "log-analytics", "query", "-w", W,
                            "--analytics-query", prelude + q, "-o", "none"],
                           capture_output=True, text=True)
        if r.returncode != 0:
            m = re.findall(r"\"message\": \"([^\"]+)\"", r.stderr)
            msg = m[-1] if m else r.stderr.strip()[:160]
            if "Let with the same name" in msg:
                continue
            bad.append((i, msg))
    label = f"{table}{'/' + section if section else ''}"
    print(f"{'FAIL' if bad else 'ok  '}  {label}")
    for i, msg in bad:
        fails += 1
        print(f"        block {i}: {msg}")
sys.exit(1 if fails else 0)
