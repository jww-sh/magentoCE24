#!/bin/sh
# Entrypoint for the Upsun k6 tasks (also works locally: REPORT_ROOT=./reports sh run-task.sh).
# POSIX sh so it runs in the grafana/k6 (Alpine, no bash) image as well.
# Writes report.html (k6 web dashboard export), summary.json and k6.log into
# $REPORT_ROOT/<timestamp>-<profile>/, which on Upsun is the shared network
# storage visible from the app container at /app/var/k6-reports.
set -u
cd "$(dirname "$0")"

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

# no PIPESTATUS in POSIX sh: keep k6's exit code in a file
{ "$K6_BIN" run --summary-export "${OUT}/summary.json" main.js 2>&1; echo $? > "${OUT}/.exit"; } | tee "${OUT}/k6.log"
status=$(cat "${OUT}/.exit")
rm -f "${OUT}/.exit"

ln -sfn "$(basename "$OUT")" "${REPORT_ROOT}/latest"
echo "k6 exited with ${status}; report: ${OUT}/report.html"
exit "$status"
