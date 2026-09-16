#!/usr/bin/env python3
"""Every Azure API version this tool pins, in one place, with its evidence.

Pinned rather than floating, because an API version is part of the contract: a
newer one can add an enum value, rename a field or change a default, and a scan
that silently follows the latest would change its answers without anyone
deciding to.

But a pin left alone rots, and the rot is not always visible. The table plan
enum is the case that made this file exist. Pylon read `properties.plan` on
`2022-10-01`, where the enum has exactly two values, Basic and Analytics.
Auxiliary was added later. An Auxiliary table therefore came back with a plan
this code did not recognise, `tables.py` left its tier unset, and
`inventory.py` defaults an unset tier to Analytics -- which `rulehealth.py`
reads as "free to query". So the one gate that exists to stop Pylon spending
the client's money was being routed around by a four-year-old version string.

Each constant below records the date the version was checked against
Microsoft's REST reference and what that reference said. Re-checking is then a
matter of reading this file, not grepping eleven call sites.
"""

from __future__ import annotations

# Microsoft.OperationalInsights: workspaces, and the tables under them.
# Checked 2026-09-09: 2026-03-01 is the default and latest on the Tables
# reference. It is the version that carries Auxiliary in TablePlanEnum;
# 2022-10-01, which this was, carries only Basic and Analytics.
LOG_ANALYTICS = "2026-03-01"

# Microsoft.SecurityInsights: alertRules, alertRuleTemplates, dataConnectors,
# contentPackages, productPackages.
# Checked 2026-09-09: 2025-09-01 is the latest stable on the Sentinel
# operation-groups reference. Was 2024-09-01.
SENTINEL = "2025-09-01"

# Microsoft.Authorization: roleAssignments.
# Checked 2026-09-09: 2022-04-01 IS the default and latest. Old-looking and
# current; left alone deliberately.
AUTHORIZATION = "2022-04-01"

# Microsoft.Insights: diagnosticSettings and diagnosticSettingsCategories.
#
# PREVIEW, AND THERE IS NO ALTERNATIVE. Checked 2026-09-09: the Diagnostic
# Settings reference lists 2021-05-01-preview as the only version and as the
# default, with no "other supported versions" at all. Microsoft has never
# shipped a stable diagnostic settings API. Every tool that reads a diagnostic
# setting, the Azure CLI included, is on a preview version.
#
# This is the one pin that cannot be made stable by choosing better. It is
# recorded here so the next person to audit these does not spend an hour
# looking for a stable version that does not exist.
MONITOR_DIAGNOSTIC_SETTINGS = "2021-05-01-preview"

# microsoft.aadiam/diagnosticSettings: the tenant-scope Entra sign-in feed.
# A separate provider with its own versioning, unrelated to Microsoft.Insights
# above.
#
# Checked 2026-09-09: the provider offers only 2017-04-01 and its preview, and
# is not deprecated. Old and correct.
#
# DO NOT VALIDATE CATEGORIES AGAINST THAT PAGE. Its LogSettings.category enum
# lists AuditLogs and SignInLogs only, while its own sample enables five more.
# `scopes.tenant` reads whatever the setting returns and checks nothing, which
# is why every Entra category added since 2017 still gets through.
AADIAM = "2017-04-01"
