#!/usr/bin/env bash
# Parallel aggregator throughput on a single-board computer (run after run_device_bench.sh, which creates the
# Python environment). Records the board before and after and packs the results into one archive.
#   Usage:  cd offchain && bash run_parallel_bench.sh
set -euo pipefail
cd "$(dirname "$0")"
[ "$(uname -m)" = "aarch64" ] || [ "${ALLOW_ANY_ARCH:-0}" = "1" ] || { echo "ERROR: install Raspberry Pi OS (64-bit)" >&2; exit 1; }
[ -d .venv-bench ] || { echo "ERROR: run 'bash run_device_bench.sh' first (it creates the Python environment)" >&2; exit 1; }
. .venv-bench/bin/activate
model=$(tr -d '\0' < /proc/device-tree/model 2>/dev/null || echo "unknown-board")
slug=$(echo "$model" | tr 'A-Z' 'a-z' | tr -cs 'a-z0-9' '-' | sed 's/^-//; s/-$//')
out="results-parallel-${slug}-$(date +%Y%m%d-%H%M)"; mkdir -p "$out"
python machine_info.py "$out" machine.json > /dev/null
python parallel_bench.py --out "$out" 2>&1 | tee "$out/parallel_console.txt"
python machine_info.py "$out" machine_after.json > /dev/null
tar czf "$out.tar.gz" "$out"
echo; echo "Done. Send this file back:  offchain/$out.tar.gz"
command -v vcgencmd >/dev/null && echo "Throttling flags after the run: $(vcgencmd get_throttled | cut -d= -f2) (0x0 means none)" || true
