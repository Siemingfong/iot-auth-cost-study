#!/usr/bin/env python3
"""Record the hardware and software of the machine running the off-chain benchmarks."""
import json, os, platform, subprocess, sys
from importlib.metadata import version

def run(cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, check=True).stdout
    except Exception:
        return ""

info = {"python": platform.python_version(), "os": platform.platform(), "machine": platform.machine(),
        "logical_cpus": os.cpu_count(),
        "packages": {p: version(p) for p in ("coincurve", "cryptography", "py_arkworks_bls12381")},
        "runner": {k: os.environ.get(k) for k in ("RUNNER_OS", "RUNNER_ARCH", "ImageOS", "ImageVersion")}}
try:
    lscpu = json.loads(run(["lscpu", "-J"]))["lscpu"]
    keep = ("Architecture", "Vendor ID", "Model name", "CPU(s)", "Thread(s) per core", "Core(s) per socket",
            "Socket(s)", "CPU max MHz", "CPU min MHz", "BogoMIPS", "L1d cache", "L2 cache", "L3 cache", "Hypervisor vendor")
    info["lscpu"] = {e["field"].rstrip(":"): e["data"] for e in lscpu if e["field"].rstrip(":") in keep}
except Exception:
    info["lscpu_raw"] = run(["lscpu"])
try:
    info["mem_total_kb"] = int(next(l.split()[1] for l in open("/proc/meminfo") if l.startswith("MemTotal")))
except Exception:
    pass
# Raspberry Pi and other single-board computers: board model, temperature, throttling
try:
    info["board_model"] = open("/proc/device-tree/model").read().strip("\x00").strip()
except Exception:
    pass
if run(["which", "vcgencmd"]).strip():
    info["vcgencmd"] = {"temp": run(["vcgencmd", "measure_temp"]).strip(),
                        "throttled": run(["vcgencmd", "get_throttled"]).strip(),
                        "arm_clock_hz": run(["vcgencmd", "measure_clock", "arm"]).strip()}
out = sys.argv[1] if len(sys.argv) > 1 else "results"
os.makedirs(out, exist_ok=True)
name = sys.argv[2] if len(sys.argv) > 2 else "machine.json"
json.dump(info, open(os.path.join(out, name), "w"), indent=2)
print(json.dumps(info, indent=2))
