#!/usr/bin/env bash
#
# First-release go/no-go run. You drop in an API key; this does the rest.
#
# It does TWO things the unit tests can't:
#   1. eval.py  — runs the full pipeline against a LIVE model, several times per
#      target, and prints the aggregate quality numbers (invalid-rate, validator
#      catch-rate, operation warnings, run-to-run drift, cost).
#   2. a few real generations — writes readable reports/ folders so you can open
#      the actual .kql detections and judge them like a detection engineer.
#
# Then read docs/first-release-checklist.md and make the ship / no-ship call.
#
# Usage:
#   export PYLON_PROVIDER=openai        # or azure-openai / anthropic
#   export OPENAI_API_KEY=sk-...                    # (or AZURE_OPENAI_* for azure-openai)
#   export OPENAI_CHAT_MODEL=gpt-5                  # REQUIRED — there is no default
#   scripts/release-run.sh
#
# The model variable is not optional and Pylon does not pick one for you: the
# provider SDK resolves it from the environment and raises SettingNotFoundError
# if it is unset. Which variable depends on the provider — see the preflight.
#
# Overrides:
#   RUNS=3                 eval runs per target (default 2)
#   MAX_COST=3             per-run USD ceiling passed to the engine (default 2)
#   SKIP_EVAL=1            skip the aggregate eval, only do readable generations
#   SKIP_GEN=1             skip the readable generations, only do the eval
#
set -euo pipefail
cd "$(dirname "$0")/.."

RUNS="${RUNS:-2}"
MAX_COST="${MAX_COST:-2}"
OUT_DIR="reports/release"
EVAL_JSON="eval-runs/release-eval.json"

# --- 1. Preflight: fail loudly BEFORE spending a cent -------------------------
provider="${PYLON_PROVIDER:-}"
if [ -z "$provider" ]; then
  echo "ERROR: set PYLON_PROVIDER (openai | azure-openai | anthropic)." >&2
  exit 1
fi
# The model is REQUIRED for every provider and has no default anywhere: the
# Agent Framework client resolves it from the environment and raises
# SettingNotFoundError when it is missing. Checking only the API key here let a
# run start and then die inside the first agent call, which is exactly the
# failure this preflight exists to prevent.
#
# Which variable, per provider:
#   openai        OPENAI_CHAT_MODEL, or OPENAI_MODEL as a fallback.
#   azure-openai  the same two. clients.py builds a plain OpenAIChatClient
#                 pointed at the resource's /openai/v1/ surface, so the SDK
#                 reads the OPENAI_ prefix and never consults AZURE_OPENAI_*.
#                 The value is your DEPLOYMENT name, not the base model name.
#   anthropic     ANTHROPIC_CHAT_MODEL only — that settings class has no plain
#                 `model` field, so ANTHROPIC_MODEL is not read.
model=""
case "$provider" in
  openai)
    [ -n "${OPENAI_API_KEY:-}" ]        || { echo "ERROR: OPENAI_API_KEY not set." >&2; exit 1; }
    model="${OPENAI_CHAT_MODEL:-${OPENAI_MODEL:-}}"
    [ -n "$model" ] || { echo "ERROR: OPENAI_CHAT_MODEL not set (no default exists). e.g. export OPENAI_CHAT_MODEL=gpt-5" >&2; exit 1; } ;;
  azure-openai)
    [ -n "${AZURE_OPENAI_ENDPOINT:-}" ] || { echo "ERROR: AZURE_OPENAI_ENDPOINT not set." >&2; exit 1; }
    model="${OPENAI_CHAT_MODEL:-${OPENAI_MODEL:-}}"
    [ -n "$model" ] || { echo "ERROR: OPENAI_CHAT_MODEL not set — for azure-openai this is your DEPLOYMENT name." >&2; exit 1; } ;;
  anthropic)
    [ -n "${ANTHROPIC_API_KEY:-}" ]     || { echo "ERROR: ANTHROPIC_API_KEY not set." >&2; exit 1; }
    model="${ANTHROPIC_CHAT_MODEL:-}"
    [ -n "$model" ] || { echo "ERROR: ANTHROPIC_CHAT_MODEL not set (no default exists)." >&2; exit 1; } ;;
  *) echo "ERROR: unknown PYLON_PROVIDER '$provider'." >&2; exit 1 ;;
esac
command -v pylon >/dev/null 2>&1 || {
  echo "ERROR: 'pylon' not on PATH. Run: pip install -e ." >&2; exit 1; }

# A non-empty key is not a working key. Make one free listing call so a wrong or
# revoked credential fails here, in seconds, instead of as a traceback several
# layers inside the first agent call. No completion, no tokens.
echo "checking provider credentials (free — no tokens) ..."
pylon --check || {
  echo "" >&2
  echo "Provider preflight failed — nothing was spent. Common causes:" >&2
  echo "  • An Azure OpenAI / AI Foundry key exported as OPENAI_API_KEY. Those go" >&2
  echo "    in AZURE_OPENAI_API_KEY with PYLON_PROVIDER=azure-openai and" >&2
  echo "    AZURE_OPENAI_ENDPOINT set; OPENAI_API_KEY sends them to the wrong service." >&2
  echo "  • For azure-openai, OPENAI_CHAT_MODEL must be your DEPLOYMENT name." >&2
  exit 1; }

echo "provider=$provider  model=$model  runs=$RUNS  max-cost=\$$MAX_COST/run"
echo "This costs real tokens (expect a few dollars). Ctrl-C now to bail."
echo

# The go/no-go spread: one target per track, plus the T1562.008 case you care
# about (disabling diagnostic logging) and a resource-centric run.
EVAL_TARGETS=(
  "arm:Diagnostic Settings"     # T1562.008 — disable cloud logs (your example)
  "arm:Storage Account"         # control plane, common
  "dataplane:Blob Storage"      # data-plane audit
  "graph:Directory Changes"     # Entra / identity
  "m365:Exchange"               # OfficeActivity — newest table, least exercised
  "resource:Key Vault"          # resource-centric (control + data plane)
)

# --- 2. Aggregate quality numbers --------------------------------------------
if [ -z "${SKIP_EVAL:-}" ]; then
  echo "== [1/2] eval.py — aggregate quality across ${#EVAL_TARGETS[@]} targets =="
  mkdir -p "$(dirname "$EVAL_JSON")"
  python scripts/eval.py --runs "$RUNS" --max-cost "$MAX_COST" \
    --targets "${EVAL_TARGETS[@]}" --json "$EVAL_JSON"
  echo "  -> metrics written to $EVAL_JSON"
  echo
fi

# --- 3. Readable generations to eyeball --------------------------------------
if [ -z "${SKIP_GEN:-}" ]; then
  echo "== [2/2] real generations you can read (in $OUT_DIR/) =="
  gen() {  # gen <label> <flags...>
    local label="$1"; shift
    echo "  generating: $label"
    pylon "$@" --max-cost "$MAX_COST" \
      --output-dir "$OUT_DIR/$label" --no-checkpoint || echo "  (‼ $label failed — note it)"
  }
  # --retrohunt is a post-processing pass over the detections a run generated, not
  # a standalone probe: it cannot be reached without a generation. So attach it to
  # a generation already being paid for rather than running a second one. Only when
  # a workspace is configured — without it the flag raises SystemExit and would
  # take this generation down with it.
  #
  # This target lands in AzureActivity, which Microsoft documents as retained 90
  # days at no cost. That makes it the one table where "90d of 90d, not truncated"
  # is the known-correct answer, which is what the rounding fix (93963c2) has to
  # produce. scripts/verify-live-paths.py already proves the same code path with no
  # model spend; what this adds is only the CLI wiring around it.
  retro=()
  if [ -n "${AZURE_LOG_ANALYTICS_WORKSPACE_ID:-}" ]; then
    retro=(--retrohunt --retrohunt-days 90)
    echo "  (AZURE_LOG_ANALYTICS_WORKSPACE_ID set — adding --retrohunt to diagnostic-settings)"
  fi
  gen "diagnostic-settings" Microsoft.Insights/diagnosticSettings "${retro[@]+"${retro[@]}"}"
  gen "storage-account"     Microsoft.Storage/storageAccounts/blobServices
  gen "directory-changes"   Entra
  echo
fi

echo "DONE."
echo "  • Aggregate numbers:  $EVAL_JSON  (and the table printed above)"
echo "  • Read the detections: $OUT_DIR/*/report.md  and  $OUT_DIR/*/detections/*.kql"
echo "  • Then score it against docs/first-release-checklist.md"
