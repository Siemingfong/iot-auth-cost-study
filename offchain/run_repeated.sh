#!/usr/bin/env bash
# Repeat the device or parallel benchmark several times on a single-board computer, pausing between runs so
# the board cools down, then compute statistics over the runs (summarize_runs.py) and pack everything into one
# archive to send back.
#   Usage:  cd offchain
#           RUNS=10 bash run_repeated.sh device      (single-core signing and verification)
#           RUNS=10 bash run_repeated.sh parallel    (aggregator throughput with 1, 2 and 4 workers)
#   Optional: PAUSE=60 (seconds between runs)
set -euo pipefail
cd "$(dirname "$0")"
mode=${1:-device}; runs=${RUNS:-10}; pause=${PAUSE:-60}
case "$mode" in device) script=run_device_bench.sh; prefix=results-device ;; parallel) script=run_parallel_bench.sh; prefix=results-parallel ;;
  *) echo "usage: RUNS=10 bash run_repeated.sh device|parallel" >&2; exit 1 ;; esac
model=$( (tr -d '\0' < /proc/device-tree/model) 2>/dev/null || echo "unknown-board")
slug=$(echo "$model" | tr 'A-Z' 'a-z' | tr -cs 'a-z0-9' '-' | sed 's/^-//; s/-$//')
batch="batch-${mode}-${slug}-$(date +%Y%m%d-%H%M%S)"; mkdir -p "$batch"
echo "Board: $model | $runs $mode runs, $pause s pause | results: offchain/$batch"
for i in $(seq 1 "$runs"); do
  echo "=== run $i of $runs ($(date +%H:%M))"
  before=$(ls -d ${prefix}-*/ 2>/dev/null | sort || true)
  bash "$script" > "$batch/console-run$i.txt" 2>&1
  new=$(comm -13 <(echo "$before") <(ls -d ${prefix}-*/ | sort) | head -1)
  mv "${new%/}" "$batch/"; rm -f "${new%/}.tar.gz"
  grep -h "Throttling flags" "$batch/console-run$i.txt" || true
  [ "$i" -lt "$runs" ] && sleep "$pause"
done
. .venv-bench/bin/activate
python summarize_runs.py "$batch"
tar czf "$batch.tar.gz" "$batch"
echo; echo "Done. Send this file back:  offchain/$batch.tar.gz"
