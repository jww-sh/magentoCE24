#!/bin/sh
# Entrypoint for the Upsun loadtesting-k6 task (also works locally: REPORT_ROOT=./reports sh run-task.sh).
# Writes report.html (k6 web dashboard export), summary.json, k6.log, console.log,
# failures.jsonl (full request/response of every failed check) and run-info.json into
# $REPORT_ROOT/<timestamp>-<profile>/, which on Upsun is the shared network
# storage visible from the app container at /app/var/k6-reports.
set -u
cd "$(dirname "$0")"

# ./k6 comes from the task's build hook; locally fall back to PATH
K6_BIN="./k6"
[ -x "$K6_BIN" ] || K6_BIN="$(command -v k6)"

PROFILE="${PROFILE:-combined}"
REPORT_ROOT="${REPORT_ROOT:-${PLATFORM_APP_DIR:-.}/reports}"
OUT="${REPORT_ROOT}/$(date -u +%Y%m%dT%H%M%SZ)-${PROFILE}"
mkdir -p "$OUT"

echo "$("$K6_BIN" version | head -1) | profile=${PROFILE} url=${URL:-} vus=${VUS:-} duration=${DURATION:-}"
echo "reports -> ${OUT}"

export K6_WEB_DASHBOARD=true
export K6_WEB_DASHBOARD_PORT=-1
export K6_WEB_DASHBOARD_EXPORT="${OUT}/report.html"

STARTED=$(date -u +%Y-%m-%dT%H:%M:%SZ)
# Console output (bootstrap info, K6FAIL failure records) goes to console.log verbatim;
# no PIPESTATUS in POSIX sh, so k6's exit code is kept in a file.
{ "$K6_BIN" run --log-format raw --console-output "${OUT}/console.log" --summary-export "${OUT}/summary.json" main.js 2>&1; echo $? > "${OUT}/.exit"; } | tee "${OUT}/k6.log"
status=$(cat "${OUT}/.exit")
rm -f "${OUT}/.exit"

# Failed checks and exceptions, one JSON object per line, with full request/response
grep '^K6FAIL ' "${OUT}/console.log" 2>/dev/null | sed 's/^K6FAIL //' > "${OUT}/failures.jsonl"
grep -v '^K6FAIL ' "${OUT}/console.log" 2>/dev/null > "${OUT}/console.tmp" && mv "${OUT}/console.tmp" "${OUT}/console.log"

# k6 only reports interrupted iterations in its final progress line:
#   running (04m24.6s), 0/6 VUs, 76 complete and 0 interrupted iterations
final=$(grep -oE '[0-9]+ complete and [0-9]+ interrupted iterations' "${OUT}/k6.log" | tail -1)
complete=$(echo "$final" | sed -E 's/^([0-9]+) complete.*/\1/')
interrupted=$(echo "$final" | sed -E 's/.* and ([0-9]+) interrupted.*/\1/')
cat > "${OUT}/run-info.json" <<JSON
{
  "profile": "${PROFILE}",
  "url": "${URL:-}",
  "vus": "${VUS:-}",
  "duration": "${DURATION:-}",
  "started": "${STARTED}",
  "finished": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "exit_code": ${status},
  "thresholds_crossed": $( [ "$status" = 99 ] && echo true || echo false ),
  "iterations_complete": ${complete:-0},
  "iterations_interrupted": ${interrupted:-0},
  "failure_records": $(wc -l < "${OUT}/failures.jsonl" | tr -d ' ')
}
JSON

ln -sfn "$(basename "$OUT")" "${REPORT_ROOT}/latest"
echo "k6 exited with ${status}; report: ${OUT}/report.html"
exit "$status"
