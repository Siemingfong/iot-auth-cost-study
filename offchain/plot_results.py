#!/usr/bin/env python3
"""Plot figures for the paper from results/*.csv (PDF for LaTeX, PNG for preview)."""
import csv, sys, os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

d = sys.argv[1] if len(sys.argv) > 1 else "results"
rows = list(csv.DictReader(open(os.path.join(d, "scaling.csv"))))
sweep = list(csv.DictReader(open(os.path.join(d, "device_sweep.csv"))))
style = {
    "V1 individual (2 pairings)": dict(marker="o", ls="-"),
    "V2 individual (multi-pairing)": dict(marker="s", ls="-"),
    "B1 naive batch (insecure)": dict(marker="x", ls=":"),
    "B2 small-exponent batch": dict(marker="^", ls="--"),
    "B3 grouped small-exponent batch": dict(marker="D", ls="-", lw=2),
}
plt.rcParams.update({"font.size": 10, "figure.dpi": 150})

for recompute, tag in (("False", "cached"), ("True", "recomputed")):
    for metric, ylab, fname in (("total_ms", "Total verification time (ms)", "fig_total"),
                                ("per_msg_ms", "Verification time per message (ms)", "fig_per_msg")):
        fig, ax = plt.subplots(figsize=(5.2, 3.6))
        for meth, st in style.items():
            pts = [(int(r["n"]), float(r[metric])) for r in rows
                   if r["method"] == meth and r["recompute_H1"] == recompute]
            if pts:
                ax.plot(*zip(*pts), label=meth, **st)
        ax.set_xscale("log"); ax.set_yscale("log")
        ax.set_xlabel("Number of messages in batch (n)"); ax.set_ylabel(ylab)
        ax.set_title(f"BLS12-381, 50 devices, H1(ID) {tag}", fontsize=9)
        ax.grid(True, which="both", ls=":", alpha=.5); ax.legend(fontsize=7)
        fig.tight_layout()
        for ext in ("pdf", "png"):
            fig.savefig(os.path.join(d, f"{fname}_{tag}.{ext}"))
        plt.close(fig)

fig, ax = plt.subplots(figsize=(5.2, 3.6))
for meth in ("B2 small-exponent batch", "B3 grouped small-exponent batch"):
    pts = [(int(r["devices"]), float(r["total_ms"])) for r in sweep if r["method"] == meth]
    ax.plot(*zip(*pts), label=meth, **style[meth])
ax.set_xscale("log"); ax.set_xlabel("Number of distinct devices (m)")
ax.set_ylabel("Total verification time (ms)")
ax.set_title(f"n = {sweep[0]['n']} messages, H1(ID) cached", fontsize=9)
ax.set_ylim(bottom=0); ax.grid(True, which="both", ls=":", alpha=.5); ax.legend(fontsize=8)
fig.tight_layout()
for ext in ("pdf", "png"):
    fig.savefig(os.path.join(d, f"fig_device_sweep.{ext}"))
print("figures written")
