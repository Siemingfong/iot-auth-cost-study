#!/usr/bin/env python3
"""Cross-design figures: gas per message vs batch size, and largest batch per transaction."""
import csv, json, os, sys
import matplotlib; matplotlib.use("Agg")
import matplotlib.pyplot as plt
d = sys.argv[1] if len(sys.argv) > 1 else "results"
base = [r for r in csv.DictReader(open(os.path.join(d, "baselines_scaling.csv"))) if r["ok"] == "true"]
ibs = [r for r in csv.DictReader(open(os.path.join(d, "gas_scaling.csv"))) if r["ok"] == "true"]
anch = list(csv.DictReader(open(os.path.join(d, "anchoring_only.csv"))))
bres = json.load(open(os.path.join(d, "baselines_results.json")))
ires = json.load(open(os.path.join(d, "gas_results.json")))
plt.rcParams.update({"font.size": 10, "figure.dpi": 150})
series = {
    "K1 ECDSA secp256k1": ([(int(r["n"]), int(r["per_msg_gas"])) for r in base if r["scheme"] == "K1"], dict(marker="o", color="C0")),
    "R1 ECDSA P-256": ([(int(r["n"]), int(r["per_msg_gas"])) for r in base if r["scheme"] == "R1"], dict(marker="s", color="C1")),
    "BLS aggregate": ([(int(r["n"]), int(r["per_msg_gas"])) for r in base if r["scheme"] == "BLS"], dict(marker="^", color="C2")),
    "IBS small-exponent (B2)": ([(int(r["n"]), int(r["per_msg_gas"])) for r in ibs if r["method"].startswith("B2")], dict(marker="v", ls="--", color="C3")),
    "IBS grouped (B3)": ([(int(r["n"]), int(r["per_msg_gas"])) for r in ibs if r["method"].startswith("B3")], dict(marker="D", color="C4")),
    "T1 anchoring, no authentication": ([(int(r["n"]), round(int(r["leaves_root_gas"]) / int(r["n"]))) for r in anch], dict(marker="x", ls=":", color="k")),
}
fig, ax = plt.subplots(figsize=(5.6, 3.9))
for name, (pts, st) in series.items():
    ax.plot(*zip(*sorted(pts)), label=name, **st)
ax.set_xscale("log"); ax.set_yscale("log")
ax.set_xlabel("Records per transaction (n)"); ax.set_ylabel("Gas per record")
ax.grid(True, which="both", ls=":", alpha=.5); ax.legend(fontsize=7); fig.tight_layout()
for e in ("pdf", "png"): fig.savefig(os.path.join(d, f"fig_compare_gas.{e}"))

mx = {"K1": bres["max_batch"]["K1"], "R1": bres["max_batch"]["R1"], "BLS": bres["max_batch"]["BLS"],
      "IBS B2": ires["max_batch"]["B2 small-exponent batch"], "IBS B3": ires["max_batch"]["B3 grouped small-exponent batch"]}
fig, ax = plt.subplots(figsize=(5.0, 3.0))
ax.barh(list(mx)[::-1], list(mx.values())[::-1], color=["C4", "C3", "C2", "C1", "C0"])
for i, v in enumerate(list(mx.values())[::-1]): ax.text(v + 20, i, str(v), va="center", fontsize=8)
ax.set_xlabel("Largest batch under the EIP-7825 cap (records)"); ax.set_xlim(0, max(mx.values()) * 1.15)
fig.tight_layout()
for e in ("pdf", "png"): fig.savefig(os.path.join(d, f"fig_max_batch.{e}"))
print(mx)
