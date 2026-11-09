#!/usr/bin/env python3
"""
LEGACY: the signature from the 2021 IoP/MLAV drafts, kept only to reproduce the
two attacks in legacy_2021_attacks.py. Do NOT use this scheme.

MLAV / IoP ID-based signature benchmark (BLS12-381, Type-3 pairing).

Scheme: the pseudo-identity signature used in the ICBC-2021 IoP draft
(adapted from Hu, Yeh, Liao, Yang, Computers & Security 86, 2019),
rewritten for an asymmetric pairing e: G1 x G2 -> GT.

  Setup   : P1 in G1, P2 in G2 generators; master keys c1, c2 in Z_r*;
            PK1 = c1*P2, PK2 = c2*P2  (in G2)
  Extract : t <- Z_r*;  SID1 = t*P1;  SID2 = RID xor H0(t*c1*c2*P1)
            Q = H1(SID1 || SID2) in G1   (RFC 9380 hash-to-curve)
            PrK1 = c1*SID1,  PrK2 = c2*Q
  Sign    : v = H2(ID || CT || TimeStamp), w = H2(ID || Chk || BT_seed)
            sigma = v*PrK1 + w*PrK2      (one G1 element, 48 bytes)
  Verify  : e(sigma, P2) == e(v*SID1, PK1) * e(w*Q, PK2)

Verification variants benchmarked
  V1  individual, textbook   : 3 full pairings per message
  V2  individual, multi-pair : 3 Miller loops + 1 final exponentiation
  B1  naive batch            : aggregate by plain summation (as in the
                               2021 drafts) -> INSECURE, see attack test
  B2  small-exponent batch   : random l-bit delta_i per message
                               (Bellare-Garay-Rabin 1998), sound w.p.
                               1 - 2^-l

Usage:  python3 mlav_bench.py [--quick] [--out DIR]
"""
import argparse, csv, hashlib, json, os, platform, secrets, statistics, time

from py_arkworks_bls12381 import G1Point, G2Point, GT, Scalar

DST_H1 = b"MLAV-IoP-V01-H1_BLS12381G1_XMD:SHA-256_SSWU_RO_"
DELTA_BITS = 64            # security level of the small-exponent test
P1, P2 = G1Point(), G2Point()


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def rand_scalar():
    return Scalar.from_le_bytes_mod_order(secrets.token_bytes(64))


def h_scalar(*parts):
    """H2: {0,1}* -> Z_r (SHA-512, reduced mod r)."""
    d = hashlib.sha512(b"MLAV-H2" + b"||".join(parts)).digest()
    return Scalar.from_le_bytes_mod_order(d)


def g1b(p):
    return bytes(p.to_compressed_bytes())


# --------------------------------------------------------------------------
# scheme
# --------------------------------------------------------------------------
class KGC:
    def __init__(self):
        self.c1, self.c2 = rand_scalar(), rand_scalar()
        self.PK1, self.PK2 = P2 * self.c1, P2 * self.c2

    def extract(self, rid: bytes):
        """Runs inside the device HSM in the original design."""
        t = rand_scalar()
        sid1 = P1 * t
        mask = hashlib.sha256(g1b(P1 * (t * self.c1 * self.c2))).digest()
        sid2 = bytes(a ^ b for a, b in zip(rid.ljust(32, b"\0"), mask))
        q = G1Point.hash_to_curve(g1b(sid1) + sid2, DST_H1)
        return Device(sid1, sid2, q, sid1 * self.c1, q * self.c2)

    def trace(self, sid1, sid2):
        """Conditional traceability: KGC recovers RID from a pseudo-ID."""
        mask = hashlib.sha256(g1b(sid1 * (self.c1 * self.c2))).digest()
        return bytes(a ^ b for a, b in zip(sid2, mask)).rstrip(b"\0")


class Device:
    def __init__(self, sid1, sid2, q, prk1, prk2):
        self.sid1, self.sid2, self.q = sid1, sid2, q
        self.prk1, self.prk2 = prk1, prk2
        self.id = g1b(sid1) + sid2

    def sign(self, ct, ts, chk, seed):
        v = h_scalar(self.id, ct, ts)
        w = h_scalar(self.id, chk, seed)
        sigma = self.prk1 * v + self.prk2 * w
        return Msg(self, ct, ts, chk, seed, sigma)


class Msg:
    __slots__ = ("sid1", "sid2", "q", "id", "ct", "ts", "chk", "seed", "sigma")

    def __init__(self, dev, ct, ts, chk, seed, sigma):
        self.sid1, self.sid2, self.q, self.id = dev.sid1, dev.sid2, dev.q, dev.id
        self.ct, self.ts, self.chk, self.seed, self.sigma = ct, ts, chk, seed, sigma

    def vw(self):
        return h_scalar(self.id, self.ct, self.ts), h_scalar(self.id, self.chk, self.seed)


def q_of(m, recompute_q):
    if recompute_q:
        return G1Point.hash_to_curve(g1b(m.sid1) + m.sid2, DST_H1)
    return m.q


# --- individual verification ----------------------------------------------
def verify_textbook(m, pk, recompute_q=False):
    v, w = m.vw()
    q = q_of(m, recompute_q)
    lhs = GT.pairing(m.sigma, P2)
    rhs = GT.pairing(m.sid1 * v, pk.PK1) * GT.pairing(q * w, pk.PK2)
    return lhs == rhs


def verify_multipairing(m, pk, recompute_q=False):
    v, w = m.vw()
    q = q_of(m, recompute_q)
    return GT.pairing_check([m.sigma, -(m.sid1 * v), -(q * w)], [P2, pk.PK1, pk.PK2])


# --- batch verification ---------------------------------------------------
def batch_naive(msgs, pk, recompute_q=False):
    """Plain-sum aggregation exactly as written in the 2021 drafts."""
    vs, ws, sids, qs, sigs = [], [], [], [], []
    for m in msgs:
        v, w = m.vw()
        vs.append(v); ws.append(w); sids.append(m.sid1)
        qs.append(q_of(m, recompute_q)); sigs.append(m.sigma)
    one = [Scalar(1)] * len(msgs)
    S = G1Point.multiexp_unchecked(sigs, one)
    A = G1Point.multiexp_unchecked(sids, vs)
    B = G1Point.multiexp_unchecked(qs, ws)
    return GT.pairing_check([S, -A, -B], [P2, pk.PK1, pk.PK2])


def batch_set(msgs, pk, recompute_q=False, delta_bits=DELTA_BITS):
    """Small-exponent test: random delta_i of `delta_bits` bits."""
    ds, dvs, dws, sids, qs, sigs = [], [], [], [], [], []
    for m in msgs:
        v, w = m.vw()
        d = Scalar(secrets.randbits(delta_bits) | 1)
        ds.append(d); dvs.append(d * v); dws.append(d * w)
        sids.append(m.sid1); qs.append(q_of(m, recompute_q)); sigs.append(m.sigma)
    S = G1Point.multiexp_unchecked(sigs, ds)
    A = G1Point.multiexp_unchecked(sids, dvs)
    B = G1Point.multiexp_unchecked(qs, dws)
    return GT.pairing_check([S, -A, -B], [P2, pk.PK1, pk.PK2])


def batch_set_grouped(msgs, pk, recompute_q=False, delta_bits=DELTA_BITS):
    """Small-exponent test with per-device grouping (new in this work).

    SID1 and Q depend only on the device identity, so
        sum_i (d_i v_i) SID1_i = sum_dev (sum_{i in dev} d_i v_i) SID1_dev
    The two identity-side MSMs shrink from n points to m devices; only the
    signature MSM stays at size n. Soundness is identical to batch_set.
    """
    ds, sigs, acc = [], [], {}
    for m in msgs:
        v, w = m.vw()
        d = Scalar(secrets.randbits(delta_bits) | 1)
        ds.append(d); sigs.append(m.sigma)
        g = acc.get(m.id)
        if g is None:
            acc[m.id] = [m.sid1, q_of(m, recompute_q), d * v, d * w]
        else:
            g[2] = g[2] + d * v; g[3] = g[3] + d * w
    grp = list(acc.values())
    S = G1Point.multiexp_unchecked(sigs, ds)
    A = G1Point.multiexp_unchecked([g[0] for g in grp], [g[2] for g in grp])
    B = G1Point.multiexp_unchecked([g[1] for g in grp], [g[3] for g in grp])
    return GT.pairing_check([S, -A, -B], [P2, pk.PK1, pk.PK2])


# --------------------------------------------------------------------------
# workload
# --------------------------------------------------------------------------
def make_messages(kgc, n, n_devices):
    devs = [kgc.extract(f"farmer-{i:05d}".encode()) for i in range(n_devices)]
    msgs = []
    for i in range(n):
        d = devs[i % n_devices]
        msgs.append(d.sign(b"CAM-RPI-V2", str(1_700_000_000 + i).encode(),
                           hashlib.sha256(secrets.token_bytes(32)).digest(),
                           secrets.token_bytes(20)))
    return msgs


def timeit(fn, reps):
    ts = []
    for _ in range(reps):
        t0 = time.perf_counter(); r = fn(); ts.append(time.perf_counter() - t0)
        assert r is True, "verification unexpectedly failed"
    return statistics.median(ts) * 1e3, (min(ts) * 1e3, max(ts) * 1e3)


# --------------------------------------------------------------------------
# tests
# --------------------------------------------------------------------------
def run_tests(kgc):
    out = {}
    msgs = make_messages(kgc, 20, 5)
    out["valid_all_accept"] = all([
        all(verify_textbook(m, kgc) for m in msgs),
        all(verify_multipairing(m, kgc) for m in msgs),
        batch_naive(msgs, kgc), batch_set(msgs, kgc), batch_set_grouped(msgs, kgc)])

    # one corrupted signature -> everything must reject
    bad = make_messages(kgc, 20, 5); bad[7].sigma = bad[7].sigma + P1
    out["single_invalid_rejected"] = {
        "individual": not verify_multipairing(bad[7], kgc),
        "naive_batch": not batch_naive(bad, kgc),
        "set_batch": not batch_set(bad, kgc),
        "set_batch_grouped": not batch_set_grouped(bad, kgc)}

    # cancellation attack: sigma_a + X, sigma_b - X are individually invalid
    atk = make_messages(kgc, 20, 5)
    X = P1 * rand_scalar()
    atk[3].sigma = atk[3].sigma + X
    atk[11].sigma = atk[11].sigma - X
    out["cancellation_attack"] = {
        "msg3_individually_valid": verify_multipairing(atk[3], kgc),
        "msg11_individually_valid": verify_multipairing(atk[11], kgc),
        "naive_batch_ACCEPTS": batch_naive(atk, kgc),
        "set_batch_accepts": batch_set(atk, kgc),
        "set_batch_grouped_accepts": batch_set_grouped(atk, kgc)}

    # traceability
    d = kgc.extract(b"farmer-TRACE")
    out["kgc_trace_ok"] = kgc.trace(d.sid1, d.sid2) == b"farmer-TRACE"
    return out


# --------------------------------------------------------------------------
# primitive costs (for the paper's cost-model table)
# --------------------------------------------------------------------------
def bench_primitives(reps):
    a, b = rand_scalar(), rand_scalar()
    g1, g2 = P1 * a, P2 * b
    small = Scalar(secrets.randbits(DELTA_BITS))
    pts = [P1 * rand_scalar() for _ in range(1000)]
    scs = [rand_scalar() for _ in range(1000)]
    ops = {
        "pairing (full)": lambda: GT.pairing(g1, g2),
        "multi-pairing check, 3 pairs": lambda: GT.pairing_check([g1, g1, g1], [g2, g2, g2]),
        "G1 scalar mult (255-bit)": lambda: g1 * b,
        "G1 scalar mult (64-bit)": lambda: g1 * small,
        "G2 scalar mult (255-bit)": lambda: g2 * a,
        "G1 point addition": lambda: g1 + g1,
        "GT multiplication": None,  # filled below
        "hash-to-G1 (RFC 9380)": lambda: G1Point.hash_to_curve(b"x" * 80, DST_H1),
        "H2 SHA-512 -> Z_r": lambda: h_scalar(b"x" * 80, b"y" * 10, b"z" * 10),
        "G1 MSM, n=100": lambda: G1Point.multiexp_unchecked(pts[:100], scs[:100]),
        "G1 MSM, n=1000": lambda: G1Point.multiexp_unchecked(pts, scs),
    }
    gt = GT.pairing(g1, g2)
    ops["GT multiplication"] = lambda: gt * gt
    rows = []
    for name, fn in ops.items():
        inner = 1000 if any(k in name for k in ("addition", "GT mult", "H2")) else 1
        ts = []
        for _ in range(reps):
            t0 = time.perf_counter()
            for _ in range(inner):
                fn()
            ts.append((time.perf_counter() - t0) / inner)
        rows.append({"operation": name, "median_ms": round(statistics.median(ts) * 1e3, 4)})
    return rows


# --------------------------------------------------------------------------
# scaling experiment
# --------------------------------------------------------------------------
def bench_scaling(kgc, sizes, n_devices, reps, recompute_q):
    rows = []
    for n in sizes:
        msgs = make_messages(kgc, n, min(n, n_devices))
        r_ind = max(1, min(reps, 2000 // n))
        cases = {
            "V1 individual (3 pairings)": (lambda: all(verify_textbook(m, kgc, recompute_q) for m in msgs), r_ind),
            "V2 individual (multi-pairing)": (lambda: all(verify_multipairing(m, kgc, recompute_q) for m in msgs), r_ind),
            "B1 naive batch (insecure)": (lambda: batch_naive(msgs, kgc, recompute_q), reps),
            "B2 small-exponent batch": (lambda: batch_set(msgs, kgc, recompute_q), reps),
            "B3 grouped small-exponent batch": (lambda: batch_set_grouped(msgs, kgc, recompute_q), reps),
        }
        for name, (fn, r) in cases.items():
            med, (lo, hi) = timeit(fn, r)
            rows.append({"n": n, "method": name, "recompute_H1": recompute_q,
                         "total_ms": round(med, 3), "per_msg_ms": round(med / n, 4),
                         "min_ms": round(lo, 3), "max_ms": round(hi, 3), "reps": r})
            print(f"  n={n:5d}  {name:32s} {med:10.2f} ms  ({med/n:.3f} ms/msg)", flush=True)
    return rows


def bench_device_sweep(kgc, n, device_counts, reps):
    """Fixed batch size n, vary number of distinct devices m."""
    rows = []
    for m in device_counts:
        msgs = make_messages(kgc, n, m)
        for name, fn in {
            "B2 small-exponent batch": lambda: batch_set(msgs, kgc),
            "B3 grouped small-exponent batch": lambda: batch_set_grouped(msgs, kgc),
        }.items():
            med, (lo, hi) = timeit(fn, reps)
            rows.append({"n": n, "devices": m, "method": name, "total_ms": round(med, 3),
                         "per_msg_ms": round(med / n, 4), "min_ms": round(lo, 3),
                         "max_ms": round(hi, 3), "reps": reps})
            print(f"  n={n} m={m:5d}  {name:34s} {med:9.2f} ms", flush=True)
    return rows


def env_info():
    import py_arkworks_bls12381 as lib
    cpu = "unknown"
    try:
        with open("/proc/cpuinfo") as f:
            cpu = next(l.split(":", 1)[1].strip() for l in f if l.startswith("model name"))
    except Exception:
        pass
    from importlib.metadata import version
    return {"cpu": cpu, "logical_cpus": os.cpu_count(), "python": platform.python_version(),
            "os": platform.platform(), "library": f"py_arkworks_bls12381 {version('py_arkworks_bls12381')}",
            "curve": "BLS12-381", "delta_bits": DELTA_BITS}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--out", default="results")
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)

    sizes = [1, 10, 50, 100] if a.quick else [1, 10, 50, 100, 200, 500, 1000]
    reps = 3 if a.quick else 7

    env = env_info(); print(json.dumps(env, indent=2))
    kgc = KGC()

    print("\n[1] correctness & attack tests")
    tests = run_tests(kgc); print(json.dumps(tests, indent=2))

    print("\n[2] primitive costs")
    prim = bench_primitives(reps * 3)
    for r in prim:
        print(f"  {r['operation']:34s} {r['median_ms']:9.4f} ms")

    print("\n[3] scaling, H1(ID) cached per device")
    rows = bench_scaling(kgc, sizes, n_devices=50, reps=reps, recompute_q=False)
    print("\n[4] scaling, H1(ID) recomputed per message")
    rows += bench_scaling(kgc, sizes, n_devices=50, reps=reps, recompute_q=True)

    print("\n[5] device sweep (n fixed, H1 cached)")
    dn = 200 if a.quick else 1000
    sweep = bench_device_sweep(kgc, dn, [1, 10, 50, 200, dn], reps)
    with open(os.path.join(a.out, "device_sweep.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(sweep[0])); w.writeheader(); w.writerows(sweep)

    with open(os.path.join(a.out, "scaling.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)
    with open(os.path.join(a.out, "primitives.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(prim[0])); w.writeheader(); w.writerows(prim)
    with open(os.path.join(a.out, "env_and_tests.json"), "w") as f:
        json.dump({"environment": env, "tests": tests}, f, indent=2)
    print(f"\nwritten to {a.out}/")


if __name__ == "__main__":
    main()
