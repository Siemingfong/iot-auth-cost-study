#!/usr/bin/env python3
"""
MLAV-IBS off-chain benchmark (BLS12-381, Type-3 pairing e: G1 x G2 -> GT).

Pseudonymous identity-based signature following Cha-Cheon (PKC 2003), replacing the
2021 IoP signature (broken, see legacy_2021_attacks.py).

  Setup    : s <- Z_r*;  Ppub1 = s*P1 (G1), Ppub2 = s*P2 (G2)
  Extract  : (KGC, once per pseudonym)  t <- Z_r*;  SID1 = t*P1;
             SID2 = RID xor H0(s*SID1);  ID = SID1 || SID2
             Q = H1(ID) in G1 (RFC 9380);  sk = s*Q   (only sk goes to the device HSM)
  Sign(M)  : r <- Z_r*;  U = r*Q;  h = H2(ID, M, U);  V = (r + h)*sk;   sigma = (U, V)
  Verify   : e(V, P2) == e(U + h*Q, Ppub2)
             i.e. e(V, P2) * e(U + h*Q, -Ppub2) == 1   (2-pair multi-pairing)

Batch variants (n messages, m distinct pseudonyms)
  B1 naive sum          : INSECURE (cancellation), shown for comparison only
  B2 small-exponent     : e(sum d_i V_i, P2) * e(sum d_i U_i + sum d_i h_i Q_i, -Ppub2) == 1
  B3 grouped small-exp. : identity terms aggregated per pseudonym: sum_j (sum_{i in j} d_i h_i) Q_j
                          -> one MSM of n + m points instead of 2n

Usage: python3 mlav_ibs_bench.py [--quick] [--out DIR]
"""
import argparse, csv, hashlib, json, os, platform, secrets, statistics, time
from py_arkworks_bls12381 import G1Point, G2Point, GT, Scalar

DST_H1 = b"MLAV-IBS-V01-H1_BLS12381G1_XMD:SHA-256_SSWU_RO_"
DELTA_BITS = 64          # private verifier randomness -> soundness error 2^-64
P1, P2 = G1Point(), G2Point()
ONE = Scalar(1)


def rand_scalar():
    return Scalar.from_le_bytes_mod_order(secrets.token_bytes(64))


def H2(*parts):
    return Scalar.from_le_bytes_mod_order(hashlib.sha512(b"MLAV-H2" + b"||".join(parts)).digest())


def ser(p):
    return bytes(p.to_compressed_bytes())


# ------------------------------------------------------------------ scheme
class KGC:
    def __init__(self):
        self.s = rand_scalar()
        self.Ppub1, self.Ppub2 = P1 * self.s, P2 * self.s
        self.nPpub2 = -self.Ppub2

    def extract(self, rid: bytes):
        t = rand_scalar()
        sid1 = P1 * t
        mask = hashlib.sha256(ser(sid1 * self.s)).digest()
        sid2 = bytes(a ^ b for a, b in zip(rid.ljust(32, b"\0"), mask))
        ident = ser(sid1) + sid2
        q = G1Point.hash_to_curve(ident, DST_H1)
        return Device(ident, sid1, sid2, q, q * self.s)

    def trace(self, sid1, sid2):
        mask = hashlib.sha256(ser(sid1 * self.s)).digest()
        return bytes(a ^ b for a, b in zip(sid2, mask)).rstrip(b"\0")


class Device:
    def __init__(self, ident, sid1, sid2, q, sk):
        self.id, self.sid1, self.sid2, self.q, self.sk = ident, sid1, sid2, q, sk

    def sign(self, m: bytes):
        r = rand_scalar()
        U = self.q * r
        h = H2(self.id, m, ser(U))
        V = self.sk * (r + h)
        return Msg(self.id, self.q, m, U, V)


class Msg:
    __slots__ = ("id", "q", "m", "U", "V")

    def __init__(self, ident, q, m, U, V):
        self.id, self.q, self.m, self.U, self.V = ident, q, m, U, V

    def h(self):
        return H2(self.id, self.m, ser(self.U))


def Q_of(x, recompute):
    return G1Point.hash_to_curve(x.id, DST_H1) if recompute else x.q


# ------------------------------------------------------------------ verification
def verify_textbook(x, k, recompute=False):
    lhs = GT.pairing(x.V, P2)
    rhs = GT.pairing(x.U + Q_of(x, recompute) * x.h(), k.Ppub2)
    return lhs == rhs


def verify_multipairing(x, k, recompute=False):
    return GT.pairing_check([x.V, x.U + Q_of(x, recompute) * x.h()], [P2, k.nPpub2])


def batch_naive(msgs, k, recompute=False):
    Vs = [x.V for x in msgs]
    pts = [x.U for x in msgs] + [Q_of(x, recompute) for x in msgs]
    scs = [ONE] * len(msgs) + [x.h() for x in msgs]
    S = G1Point.multiexp_unchecked(Vs, [ONE] * len(msgs))
    T = G1Point.multiexp_unchecked(pts, scs)
    return GT.pairing_check([S, T], [P2, k.nPpub2])


def batch_set(msgs, k, recompute=False, bits=DELTA_BITS):
    ds = [Scalar(secrets.randbits(bits) | 1) for _ in msgs]
    S = G1Point.multiexp_unchecked([x.V for x in msgs], ds)
    pts = [x.U for x in msgs] + [Q_of(x, recompute) for x in msgs]
    scs = ds + [d * x.h() for d, x in zip(ds, msgs)]
    T = G1Point.multiexp_unchecked(pts, scs)
    return GT.pairing_check([S, T], [P2, k.nPpub2])


def batch_grouped(msgs, k, recompute=False, bits=DELTA_BITS):
    ds, acc = [], {}
    for x in msgs:
        d = Scalar(secrets.randbits(bits) | 1); ds.append(d)
        dh = d * x.h()
        g = acc.get(x.id)
        if g is None:
            acc[x.id] = [Q_of(x, recompute), dh]
        else:
            g[1] = g[1] + dh
    S = G1Point.multiexp_unchecked([x.V for x in msgs], ds)
    T = G1Point.multiexp_unchecked([x.U for x in msgs] + [g[0] for g in acc.values()],
                                   ds + [g[1] for g in acc.values()])
    return GT.pairing_check([S, T], [P2, k.nPpub2])


# ------------------------------------------------------------------ workload & tests
def make_messages(k, n, m):
    devs = [k.extract(f"farmer-{j:05d}".encode()) for j in range(m)]
    return [devs[i % m].sign(b"CAM-RPI-V2|" + str(1_700_000_000 + i).encode() + b"|" +
                             secrets.token_bytes(32) + secrets.token_bytes(20)) for i in range(n)]


def run_tests(k):
    out = {}
    msgs = make_messages(k, 20, 5)
    out["valid_all_accept"] = all(verify_textbook(x, k) and verify_multipairing(x, k) for x in msgs) \
        and batch_naive(msgs, k) and batch_set(msgs, k) and batch_grouped(msgs, k)
    bad = make_messages(k, 20, 5); bad[7].V = bad[7].V + P1
    out["single_invalid_rejected"] = {"individual": not verify_multipairing(bad[7], k),
                                      "naive": not batch_naive(bad, k), "set": not batch_set(bad, k),
                                      "grouped": not batch_grouped(bad, k)}
    atk = make_messages(k, 20, 5); X = P1 * rand_scalar()
    atk[3].V = atk[3].V + X; atk[11].V = atk[11].V - X
    out["cancellation_attack"] = {"msg3_valid": verify_multipairing(atk[3], k),
                                  "naive_ACCEPTS": batch_naive(atk, k),
                                  "set_accepts": batch_set(atk, k), "grouped_accepts": batch_grouped(atk, k)}
    # the legacy key-recovery attack does not apply: two signatures of one device
    d = k.extract(b"farmer-KR"); a, b = d.sign(b"m1"), d.sign(b"m2")
    out["fresh_randomness_per_signature"] = a.U != b.U
    out["kgc_trace_ok"] = k.trace(d.sid1, d.id[48:]) == b"farmer-KR"
    return out


# ------------------------------------------------------------------ benchmarks
def timeit(fn, reps):
    ts = []
    for _ in range(reps):
        t0 = time.perf_counter(); ok = fn(); ts.append(time.perf_counter() - t0)
        assert ok is True
    return statistics.median(ts) * 1e3, min(ts) * 1e3, max(ts) * 1e3


def bench_primitives(reps):
    a, b = rand_scalar(), rand_scalar()
    g1, g2 = P1 * a, P2 * b
    pts = [P1 * rand_scalar() for _ in range(1000)]; scs = [rand_scalar() for _ in range(1000)]
    gt = GT.pairing(g1, g2)
    dev = KGC().extract(b"x")
    ops = {
        "pairing (full)": (lambda: GT.pairing(g1, g2), 1),
        "multi-pairing check, 2 pairs": (lambda: GT.pairing_check([g1, g1], [g2, g2]), 1),
        "G1 scalar mult (255-bit)": (lambda: g1 * b, 1),
        "G1 scalar mult (64-bit)": (lambda: g1 * Scalar(secrets.randbits(64)), 1),
        "G1 point addition": (lambda: g1 + g1, 1000),
        "GT multiplication": (lambda: gt * gt, 1000),
        "hash-to-G1 (RFC 9380)": (lambda: G1Point.hash_to_curve(b"x" * 80, DST_H1), 1),
        "H2 (SHA-512 -> Z_r)": (lambda: H2(b"x" * 80, b"y" * 64, b"z" * 48), 1000),
        "G1 MSM, 100 points": (lambda: G1Point.multiexp_unchecked(pts[:100], scs[:100]), 1),
        "G1 MSM, 1000 points": (lambda: G1Point.multiexp_unchecked(pts, scs), 1),
        "Sign (device)": (lambda: dev.sign(b"m" * 120), 1),
    }
    rows = []
    for name, (fn, inner) in ops.items():
        ts = []
        for _ in range(reps):
            t0 = time.perf_counter()
            for _ in range(inner):
                fn()
            ts.append((time.perf_counter() - t0) / inner)
        rows.append({"operation": name, "median_ms": round(statistics.median(ts) * 1e3, 4)})
    return rows


METHODS = {
    "V1 individual (2 pairings)": (verify_textbook, True),
    "V2 individual (multi-pairing)": (verify_multipairing, True),
    "B1 naive batch (insecure)": (batch_naive, False),
    "B2 small-exponent batch": (batch_set, False),
    "B3 grouped small-exponent batch": (batch_grouped, False),
}


def bench_scaling(k, sizes, m_dev, reps, recompute):
    rows = []
    for n in sizes:
        msgs = make_messages(k, n, min(n, m_dev))
        for name, (fn, per_msg) in METHODS.items():
            if per_msg:
                f = lambda fn=fn: all(fn(x, k, recompute) for x in msgs); r = max(1, min(reps, 2000 // n))
            else:
                f = lambda fn=fn: fn(msgs, k, recompute); r = reps
            med, lo, hi = timeit(f, r)
            rows.append({"n": n, "devices": min(n, m_dev), "method": name, "recompute_H1": recompute,
                         "total_ms": round(med, 3), "per_msg_ms": round(med / n, 4),
                         "min_ms": round(lo, 3), "max_ms": round(hi, 3), "reps": r})
            print(f"  n={n:5d} {name:34s} {med:10.2f} ms ({med / n:.4f}/msg)", flush=True)
    return rows


def bench_device_sweep(k, n, ms, reps):
    rows = []
    for m in ms:
        msgs = make_messages(k, n, m)
        for name in ("B2 small-exponent batch", "B3 grouped small-exponent batch"):
            fn = METHODS[name][0]
            med, lo, hi = timeit(lambda: fn(msgs, k), reps)
            rows.append({"n": n, "devices": m, "method": name, "total_ms": round(med, 3),
                         "per_msg_ms": round(med / n, 4), "min_ms": round(lo, 3), "max_ms": round(hi, 3), "reps": reps})
            print(f"  n={n} m={m:5d} {name:34s} {med:9.2f} ms", flush=True)
    return rows


def env_info():
    from importlib.metadata import version
    cpu = "unknown"
    try:
        cpu = next(l.split(":", 1)[1].strip() for l in open("/proc/cpuinfo") if l.startswith("model name"))
    except Exception:
        pass
    return {"cpu": cpu, "logical_cpus": os.cpu_count(), "python": platform.python_version(),
            "os": platform.platform(), "library": f"py_arkworks_bls12381 {version('py_arkworks_bls12381')}",
            "curve": "BLS12-381", "delta_bits": DELTA_BITS}


def write_csv(path, rows):
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--quick", action="store_true"); ap.add_argument("--out", default="results")
    a = ap.parse_args(); os.makedirs(a.out, exist_ok=True)
    sizes = [1, 10, 100] if a.quick else [1, 10, 50, 100, 200, 500, 1000]
    reps = 3 if a.quick else 7
    env = env_info(); print(json.dumps(env, indent=2)); k = KGC()
    print("\n[1] tests"); tests = run_tests(k); print(json.dumps(tests, indent=2))
    print("\n[2] primitives"); prim = bench_primitives(reps * 3)
    for r in prim: print(f"  {r['operation']:32s} {r['median_ms']:9.4f} ms")
    print("\n[3] scaling, H1 cached (m = 50)"); rows = bench_scaling(k, sizes, 50, reps, False)
    print("\n[4] scaling, H1 recomputed (m = 50)"); rows += bench_scaling(k, sizes, 50, reps, True)
    dn = 100 if a.quick else 1000
    print(f"\n[5] device sweep (n = {dn})"); sweep = bench_device_sweep(k, dn, sorted({1, 10, 50, 200, dn}), reps)
    write_csv(os.path.join(a.out, "scaling.csv"), rows)
    write_csv(os.path.join(a.out, "primitives.csv"), prim)
    write_csv(os.path.join(a.out, "device_sweep.csv"), sweep)
    json.dump({"environment": env, "tests": tests}, open(os.path.join(a.out, "env_and_tests.json"), "w"), indent=2)
    print(f"\nwritten to {a.out}/")


if __name__ == "__main__":
    main()
