#!/usr/bin/env python3
"""Aggregator throughput with 1..P worker processes.

Each worker builds its own keys and pre-signed batches (not timed), waits at a barrier, and then verifies its
batches; throughput is the total number of records verified divided by the slowest worker's time. This models an
aggregator that verifies independent batches in parallel. Verification uses the same functions as
compare_schemes.py and mlav_ibs_bench.py.
Usage: python3 parallel_bench.py --out <dir> [--quick] [--workers 1,2,4]"""
import argparse, csv, json, multiprocessing as mp, os, time
import compare_schemes as cs
import mlav_ibs_bench as ibs

SCHEMES = ["K1", "R1", "BLS", "IBS (Q cached)"]


def prepare(scheme, n, batches, m):
    msgs = [[(i % m, cs.rec(b * n + i)) for i in range(n)] for b in range(batches)]
    if scheme == "K1":
        s = cs.K1(m); its = [[(j, x, s.sign(j, x)) for j, x in mb] for mb in msgs]
        return lambda it: s.verify_batch(it), its
    if scheme == "R1":
        s = cs.R1(m); its = [[(j, x, s.sign(j, x)) for j, x in mb] for mb in msgs]
        return lambda it: s.verify_batch(it), its
    if scheme == "BLS":
        s = cs.BLS(m); its = []
        for mb in msgs:
            it = [(j, x, s.sign(j, x)) for j, x in mb]
            its.append((it, s.aggregate([sg for _, _, sg in it])))
        return lambda it: s.verify_batch(*it), its
    k = ibs.KGC(); devs = [k.extract(f"farmer-{j}".encode()) for j in range(m)]
    its = [[devs[j].sign(x) for j, x in mb] for mb in msgs]
    return lambda it: ibs.batch_grouped(it, k, recompute=False), its


def worker(scheme, n, batches, m, barrier, q):
    verify, items = prepare(scheme, n, batches, m)
    verify(items[0])                                  # warm-up, outside the timed region
    barrier.wait()
    t0 = time.perf_counter()
    for it in items:
        assert verify(it) is not False
    q.put(time.perf_counter() - t0)


def measure(scheme, workers, n, batches, m):
    ctx = mp.get_context("fork")
    barrier, q = ctx.Barrier(workers), ctx.Queue()
    ps = [ctx.Process(target=worker, args=(scheme, n, batches, m, barrier, q)) for _ in range(workers)]
    for p in ps: p.start()
    times = [q.get() for _ in ps]
    for p in ps: p.join()
    if any(p.exitcode for p in ps): raise RuntimeError(f"a worker failed for {scheme}")
    return max(times)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="results")
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--workers", default=None, help="comma-separated worker counts (default 1,2,4,... up to the CPU count)")
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    cpus = os.cpu_count() or 1
    ws = [int(x) for x in a.workers.split(",")] if a.workers else sorted({w for w in (1, 2, 4, 8, 16, cpus) if w <= cpus})
    n, batches, m = (100, 1, 10) if a.quick else (1000, 3, 10)
    rows = []
    for scheme in SCHEMES:
        base = None
        for w in ws:
            t = measure(scheme, w, n, batches, m)
            rps = w * batches * n / t
            base = base or rps
            rows.append({"scheme": scheme, "workers": w, "records": w * batches * n, "seconds": round(t, 4),
                         "records_per_s": round(rps, 1), "speedup": round(rps / base, 2), "efficiency": round(rps / base / w, 2)})
            print(f"  {scheme:15s} workers={w:2d}  {rps:10.1f} records/s  speedup {rps / base:5.2f}", flush=True)
    with open(os.path.join(a.out, "parallel.csv"), "w", newline="") as f:
        wr = csv.DictWriter(f, fieldnames=list(rows[0])); wr.writeheader(); wr.writerows(rows)
    json.dump({"cpus": cpus, "workers": ws, "records_per_batch": n, "batches_per_worker": batches, "devices": m,
               "quick": a.quick}, open(os.path.join(a.out, "parallel_env.json"), "w"), indent=2)
    print("written", os.path.join(a.out, "parallel.csv"))


if __name__ == "__main__":
    main()
