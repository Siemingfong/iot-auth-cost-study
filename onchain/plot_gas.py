#!/usr/bin/env python3
"""Figures for the on-chain gas experiment (results/gas_*.csv)."""
import csv, os, sys
import matplotlib; matplotlib.use("Agg")
import matplotlib.pyplot as plt
d = sys.argv[1] if len(sys.argv) > 1 else "results"
rows = [r for r in csv.DictReader(open(os.path.join(d, "gas_scaling.csv"))) if r["total_gas"] not in ("", "null")]
sweep = list(csv.DictReader(open(os.path.join(d, "gas_device_sweep.csv"))))
CAP = 16_777_216
st = {"V individual (n txs)": dict(marker="s", color="C1"), "B1 naive batch (insecure)": dict(marker="x", ls=":", color="C2"),
      "B2 small-exponent batch": dict(marker="^", ls="--", color="C3"), "B3 grouped small-exponent batch": dict(marker="D", lw=2, color="C4")}
plt.rcParams.update({"font.size": 10, "figure.dpi": 150})

fig, ax = plt.subplots(figsize=(5.2, 3.6))
for m, s in st.items():
    p = [(int(r["n"]), int(r["per_msg_gas"])) for r in rows if r["method"] == m]
    ax.plot(*zip(*p), label=m, **s)
ax.set_xscale("log"); ax.set_yscale("log")
ax.set_xlabel("Messages per transaction (n)"); ax.set_ylabel("Gas per message")
ax.set_title("On-chain verification + anchoring (Osaka, EIP-2537), m = 10", fontsize=9)
ax.grid(True, which="both", ls=":", alpha=.5); ax.legend(fontsize=7); fig.tight_layout()
for e in ("pdf", "png"): fig.savefig(os.path.join(d, f"fig_gas_per_msg.{e}"))

fig, ax = plt.subplots(figsize=(5.2, 3.6))
for m, s in st.items():
    if m.startswith("V"): continue
    p = [(int(r["n"]), int(r["total_gas"]) / 1e6) for r in rows if r["method"] == m]
    ax.plot(*zip(*p), label=m, **s)
ax.axhline(CAP / 1e6, color="k", lw=1); ax.text(10, CAP / 1e6 * 1.03, "EIP-7825 per-tx cap (16.78M)", fontsize=8)
ax.set_xlabel("Messages per transaction (n)"); ax.set_ylabel("Transaction gas (millions)")
ax.grid(True, ls=":", alpha=.5); ax.legend(fontsize=7, loc="center right"); fig.tight_layout()
for e in ("pdf", "png"): fig.savefig(os.path.join(d, f"fig_gas_total.{e}"))
print("ok")
