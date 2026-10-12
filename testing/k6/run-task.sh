#!/usr/bin/env bash
# Entrypoint for the Upsun "k6" task (also works locally: REPORT_ROOT=./reports ./run-task.sh).
# Writes report.html (k6 web dashboard export), summary.json and k6.log into
# $REPORT_ROOT/<timestamp>-<profile>/, which on Upsun is the shared network
# storage visible from the app container at /app/var/k6-reports.
set -uo pipefail
cd "$(dirname "$0")"

K6_BIN="./k6"
[ -x "$K6_BIN" ] || K6_BIN="$(command -v k6)"

PROFILE="${PROFILE:-combined}"
REPORT_ROOT="${REPORT_ROOT:-${PLATFORM_APP_DIR:-.}/reports}"
OUT="${REPORT_ROOT}/$(date -u +%Y%m%dT%H%M%SZ)-${PROFILE}"
mkdir -p "$OUT"

echo "k6 $("$K6_BIN" version | head -1) | profile=${PROFILE} url=${URL:-} vus=${VUS:-} duration=${DURATION:-}"
echo "reports -> ${OUT}"

export K6_WEB_DASHBOARD=true
export K6_WEB_DASHBOARD_PORT=-1
export K6_WEB_DASHBOARD_EXPORT="${OUT}/report.html"

"$K6_BIN" run --summary-export "${OUT}/summary.json" main.js 2>&1 | tee "${OUT}/k6.log"
status=${PIPESTATUS[0]}

ln -sfn "$(basename "$OUT")" "${REPORT_ROOT}/latest"
echo "k6 exited with ${status}; report: ${OUT}/report.html"
exit "$status"
