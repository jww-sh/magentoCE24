#!/usr/bin/env bash
# Local run of the k6 benchmark (same k6 version as the Upsun task).
# Usage: ./run.sh [extra k6 -e flags], e.g. ./run.sh -e PROFILE=smoke
set -euo pipefail
cd "$(dirname "$0")/k6"

K6_VERSION=v2.3.0
if [ ! -x ./k6 ]; then
  curl -fsSL "https://github.com/grafana/k6/releases/download/${K6_VERSION}/k6-${K6_VERSION}-linux-amd64.tar.gz" \
    | tar -xz --strip-components=1 "k6-${K6_VERSION}-linux-amd64/k6"
fi

./k6 run \
  -e URL="https://shop.izinga.za.net" \
  -e PROFILE=crawler \
  -e MAX_DEPTH=15 \
  -e SLEEP=1 \
  -e FPC=ON \
  -e VUS=2 \
  -e RAMP=5s \
  -e DURATION=30s \
  "$@" \
  main.js
