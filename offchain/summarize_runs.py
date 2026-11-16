#!/usr/bin/env python3
"""Median of repeated device runs (results-device-*/ folders) for the signing and verification timings.
Usage: python3 summarize_runs.py <folder with run subfolders> [--n 1000]"""
import csv, glob, json, os, statistics as st, sys

root = sys.argv[1]
n = sys.argv[sys.argv.index("--n") + 1] if "--n" in sys.argv else "1000"
runs = sorted(d for d in glob.glob(os.path.join(root, "results-device-*")) if os.path.isfile(os.path.join(d, "compare_sign.csv")))
rows = {}
for d in runs:
    for r in csv.DictReader(open(os.path.join(d, "compare_sign.csv"))):
        rows.setdefault(("sign", r["scheme"]), []).append(float(r["sign_ms"]))
    for r in csv.DictReader(open(os.path.join(d, "compare_verify.csv"))):
        if r["n"] == n:
            rows.setdefault((f"verify_n{n}", r["scheme"]), []).append(float(r["per_msg_ms"]))
flags = sorted({json.load(open(os.path.join(d, f)))["vcgencmd"]["throttled"]
                for d in runs for f in ("machine.json", "machine_after.json")
                if os.path.isfile(os.path.join(d, f)) and "vcgencmd" in json.load(open(os.path.join(d, f)))})
out = os.path.join(root, "summary_median.csv")
with open(out, "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["metric", "scheme", "runs", "median_ms", "min_ms", "max_ms", "spread_pct"])
    for (metric, scheme), v in rows.items():
        m = st.median(v)
        w.writerow([metric, scheme, len(v), round(m, 4), round(min(v), 4), round(max(v), 4), round((max(v) - min(v)) / m * 100, 1)])
print(f"{len(runs)} runs; throttling flags seen: {flags}; written {out}")
