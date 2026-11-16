#!/usr/bin/env python3
"""Statistics over repeated runs (results-device-*/ or results-parallel-*/ folders in one directory).

Device runs: signing time and per-record verification time (n = 1000) per scheme.
Parallel runs: records per second and speedup per scheme and number of workers.
For each quantity: number of runs, mean, standard deviation, coefficient of variation, median, quartiles,
minimum, maximum and spread ((max - min) / median). Also lists the throttling flags seen before and after the runs.
Usage: python3 summarize_runs.py <folder with run subfolders> [--n 1000]"""
import csv, glob, json, os, statistics as st, sys

root = sys.argv[1]
n = sys.argv[sys.argv.index("--n") + 1] if "--n" in sys.argv else "1000"
runs = sorted(d for d in glob.glob(os.path.join(root, "results-*")) if os.path.isdir(d))
vals = {}
def add(key, v): vals.setdefault(key, []).append(float(v))
kinds = set()
for d in runs:
    if os.path.isfile(os.path.join(d, "compare_sign.csv")):
        kinds.add("device")
        for r in csv.DictReader(open(os.path.join(d, "compare_sign.csv"))): add(("sign_ms", r["scheme"], ""), r["sign_ms"])
        for r in csv.DictReader(open(os.path.join(d, "compare_verify.csv"))):
            if r["n"] == n: add((f"verify_n{n}_ms", r["scheme"], ""), r["per_msg_ms"])
    if os.path.isfile(os.path.join(d, "parallel.csv")):
        kinds.add("parallel")
        for r in csv.DictReader(open(os.path.join(d, "parallel.csv"))):
            add(("records_per_s", r["scheme"], r["workers"]), r["records_per_s"]); add(("speedup", r["scheme"], r["workers"]), r["speedup"])
flags = set()
for d in runs:
    for f in ("machine.json", "machine_after.json"):
        p = os.path.join(d, f)
        if os.path.isfile(p):
            v = json.load(open(p)).get("vcgencmd")
            if v: flags.add(v["throttled"])
def q(v, p):
    s = sorted(v); k = (len(s) - 1) * p; i = int(k); return s[i] + (s[min(i + 1, len(s) - 1)] - s[i]) * (k - i)
out = os.path.join(root, "summary_stats.csv")
with open(out, "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["metric", "scheme", "workers", "runs", "mean", "sd", "cv_pct", "median", "q1", "q3", "min", "max", "spread_pct"])
    for (metric, scheme, workers), v in vals.items():
        m, med = st.mean(v), st.median(v); sd = st.stdev(v) if len(v) > 1 else 0.0
        w.writerow([metric, scheme, workers, len(v), round(m, 4), round(sd, 4), round(sd / m * 100, 2), round(med, 4),
                    round(q(v, 0.25), 4), round(q(v, 0.75), 4), round(min(v), 4), round(max(v), 4), round((max(v) - min(v)) / med * 100, 1)])
print(f"{len(runs)} runs ({', '.join(sorted(kinds))}); throttling flags seen: {sorted(flags)}; written {out}")
