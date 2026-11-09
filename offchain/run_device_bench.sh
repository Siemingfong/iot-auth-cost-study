#!/usr/bin/env bash
# One-command device-side benchmark for single-board computers (Raspberry Pi Zero 2 W, Pi 4, ...).
# Installs the package versions used in the manuscript in a private virtual environment, records the
# board (model, CPU, temperature, throttling) before and after, runs the off-chain benchmarks and packs
# the results into one archive to send back.
#   Usage:  cd offchain && bash run_device_bench.sh          (full run)
#           QUICK=1 bash run_device_bench.sh                 (short test run)
set -euo pipefail
cd "$(dirname "$0")"

arch=$(uname -m)
if [ "$arch" != "aarch64" ] && [ "${ALLOW_ANY_ARCH:-0}" != "1" ]; then
  echo "ERROR: this system is '$arch'. Install Raspberry Pi OS (64-bit), which reports 'aarch64'." >&2
  echo "       The cryptographic packages have no ready-made builds for 32-bit ARM." >&2
  exit 1
fi
python3 -c 'import sys; assert sys.version_info >= (3, 10), "Python 3.10 or newer is required"'

model=$(tr -d '\0' < /proc/device-tree/model 2>/dev/null || echo "unknown-board")
slug=$(echo "$model" | tr 'A-Z' 'a-z' | tr -cs 'a-z0-9' '-' | sed 's/^-//; s/-$//')
out="results-device-${slug}-$(date +%Y%m%d-%H%M)"
mkdir -p "$out"
echo "Board: $model"
echo "Results: offchain/$out"

if [ ! -d .venv-bench ]; then
  echo "Creating the Python environment (first run only, a few minutes)..."
  python3 -m venv .venv-bench
fi
. .venv-bench/bin/activate
pip install --quiet --upgrade pip
pip install --quiet coincurve==21.0.0 cryptography==46.0.6 py_arkworks_bls12381==0.5.0

flag=""; [ "${QUICK:-0}" = "1" ] && flag="--quick" && echo "QUICK mode (test run; results are not for the paper)"
python machine_info.py "$out" machine.json > /dev/null
echo "[1/2] Device signing and aggregator verification..."
python compare_schemes.py --out "$out" $flag 2>&1 | tee "$out/compare_console.txt"
echo "[2/2] MLAV-IBS primitives and batch verification..."
python mlav_ibs_bench.py --out "$out" $flag 2>&1 | tee "$out/mlav_console.txt"
python machine_info.py "$out" machine_after.json > /dev/null

tar czf "$out.tar.gz" "$out"
echo
echo "Done. Send this file back:  offchain/$out.tar.gz"
if command -v vcgencmd >/dev/null; then
  t=$(vcgencmd get_throttled | cut -d= -f2)
  echo "Throttling flags after the run: $t (0x0 means none)"
  if [ "$t" != "0x0" ]; then
    echo "WARNING: the board throttled or saw low voltage during the run. Use the official power supply,"
    echo "         keep the board cool, close other programs, reboot and run again."
  fi
fi
