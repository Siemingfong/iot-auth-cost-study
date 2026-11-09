// Gas benchmark for baseline authentication designs on a local Osaka EVM:
//   K1   ECDSA/secp256k1 via ecrecover          (EIP-155-era precompile, 3,000 gas)
//   R1   ECDSA/P-256 via EIP-7951               (6,900 gas)
//   BLS  per-device BLS, aggregated off-chain   (EIP-2537 + on-chain RFC 9380 hash-to-curve)
//   T0/T1 anchoring without on-chain authentication
// Usage: node baselines_bench.mjs [--quick] [--out results]
import fs from 'node:fs'
import crypto from 'node:crypto'
import solc from 'solc'
import { bls12_381 } from '@noble/curves/bls12-381.js'
import { secp256k1 } from '@noble/curves/secp256k1.js'
import { p256 } from '@noble/curves/nist.js'
import { keccak_256 } from '@noble/hashes/sha3.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { AbiCoder, Interface } from 'ethers'
import { createVM, runTx } from '@ethereumjs/vm'
import { Common, Hardfork, Mainnet } from '@ethereumjs/common'
import { createFeeMarket1559Tx } from '@ethereumjs/tx'
import { createBlock } from '@ethereumjs/block'
import { Account, Address, bytesToHex, hexToBytes, privateToAddress } from '@ethereumjs/util'

const QUICK = process.argv.includes('--quick')
const OUT = process.argv.includes('--out') ? process.argv[process.argv.indexOf('--out') + 1] : 'results'
fs.mkdirSync(OUT, { recursive: true })
const abi = AbiCoder.defaultAbiCoder()
const TX_GAS_CAP = 16_777_216n
const DST = 'MLAV-BENCH-BLS-SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_'
const G1 = bls12_381.G1.Point, G2 = bls12_381.G2.Point
const R = bls12_381.fields.Fr.ORDER
const fp = (x) => x.toString(16).padStart(128, '0')
const encG1 = (P) => { const a = P.toAffine(); return fp(a.x) + fp(a.y) }
const encG2 = (P) => { const a = P.toAffine(); return fp(a.x.c0) + fp(a.x.c1) + fp(a.y.c0) + fp(a.y.c1) }
const words = (h, k) => Array.from({ length: k }, (_, i) => '0x' + h.slice(64 * i, 64 * i + 64))
const rnd = (b) => '0x' + crypto.randomBytes(b).toString('hex')
const randScalar = () => (BigInt(rnd(64)) % (R - 1n)) + 1n
const hex = (u8) => '0x' + Buffer.from(u8).toString('hex')

// ------------------------------------------------------------------ compile all contracts
const src = fs.readFileSync('Baselines.sol.tpl', 'utf8')
  .replace('{{NEGP2}}', encG2(G2.BASE.negate())).replace('{{DST}}', DST)
const out = JSON.parse(solc.compile(JSON.stringify({ language: 'Solidity',
  sources: { 'Baselines.sol': { content: src } },
  settings: { optimizer: { enabled: true, runs: 200 }, viaIR: true, evmVersion: 'cancun',
    outputSelection: { '*': { '*': ['abi', 'evm.bytecode.object'] } } } })))
const errs = (out.errors || []).filter(e => e.severity === 'error')
if (errs.length) { console.error(errs.map(e => e.formattedMessage).join('\n')); process.exit(1) }
fs.writeFileSync(`${OUT}/Baselines.sol`, src)
const C = out.contracts['Baselines.sol']

// ------------------------------------------------------------------ EVM
const common = new Common({ chain: Mainnet, hardfork: Hardfork.Osaka })
const vm = await createVM({ common })
const pk = hexToBytes('0x' + '22'.repeat(32))
const sender = new Address(privateToAddress(pk))
await vm.stateManager.putAccount(sender, new Account(0n, 10n ** 30n))
const block = createBlock({ header: { number: 23_000_000n, gasLimit: 60_000_000n, baseFeePerGas: 1n, timestamp: 1_780_000_000n } }, { common })
let nonce = 0n
async function send(to, data, gasLimit = TX_GAS_CAP) {
  nonce = (await vm.stateManager.getAccount(sender)).nonce
  const tx = createFeeMarket1559Tx({ nonce, to, data, gasLimit, maxFeePerGas: 10n ** 10n, maxPriorityFeePerGas: 1n }, { common }).sign(pk)
  const r = await runTx(vm, { tx, block, skipBlockGasLimitValidation: true, skipHardForkValidation: true })
  nonce++
  return { gas: Number(r.totalGasSpent), ok: r.execResult.exceptionError === undefined, addr: r.createdAddress,
           calldata: data.length, err: r.execResult.exceptionError?.error }
}
async function call(to, data) {
  const r = await vm.evm.runCall({ to, caller: new Address(hexToBytes('0x' + '33'.repeat(20))), data, gasLimit: 10_000_000n, block })
  return r.execResult
}
async function deploy(name) {
  const r = await send(undefined, hexToBytes('0x' + C[name].evm.bytecode.object))
  if (!r.ok) throw new Error(`deploy ${name}: ${r.err}`)
  return { addr: r.addr, iface: new Interface(C[name].abi), deployGas: r.gas }
}

// ------------------------------------------------------------------ records
const M = 10
function record(i) { return { ct: rnd(32), ts: BigInt(1_700_000_000 + i), chk: rnd(32), seed: rnd(20) } }

// ------------------------------------------------------------------ schemes
const schemes = {}

// --- K1: ECDSA secp256k1 / ecrecover
schemes.K1 = {
  label: 'ECDSA secp256k1 (ecrecover)',
  async setup() {
    this.c = await deploy('K1Verifier')
    this.devs = []
    for (let j = 0; j < M; j++) {
      const sk = secp256k1.utils.randomSecretKey()
      const pub = secp256k1.getPublicKey(sk, false)
      const addr = '0x' + Buffer.from(keccak_256(pub.slice(1))).subarray(12).toString('hex')
      this.devs.push({ sk, addr })
      const r = await send(this.c.addr, hexToBytes(this.c.iface.encodeFunctionData('registerDevice', [addr])))
      this.regGas = r.gas
    }
  },
  sign(rec, j) {
    const h = keccak_256(hexToBytes(abi.encode(['address', 'bytes32', 'uint64', 'bytes32', 'bytes20'],
      [this.c.addr.toString(), rec.ct, rec.ts, rec.chk, rec.seed])))
    const s = secp256k1.Signature.fromBytes(secp256k1.sign(h, this.devs[j].sk, { prehash: false, format: 'recovered' }), 'recovered')
    return [rec.ct, rec.ts, rec.chk, rec.seed, 27 + s.recovery, '0x' + s.r.toString(16).padStart(64, '0'), '0x' + s.s.toString(16).padStart(64, '0')]
  },
  batch(n, tamper = false) {
    const ms = Array.from({ length: n }, (_, i) => this.sign(record(i), i % M))
    if (tamper) ms[Math.floor(n / 2)][2] = rnd(32)
    return hexToBytes(this.c.iface.encodeFunctionData('submitBatch', [ms]))
  },
  one() { return hexToBytes(this.c.iface.encodeFunctionData('submitOne', [this.sign(record(0), 0)])) },
}

// --- R1: ECDSA P-256 / EIP-7951
schemes.R1 = {
  label: 'ECDSA P-256 (EIP-7951)',
  async setup() {
    this.c = await deploy('R1Verifier')
    this.devs = []
    for (let j = 0; j < M; j++) {
      const sk = p256.utils.randomSecretKey()
      const pub = p256.getPublicKey(sk, false)
      const qx = hex(pub.slice(1, 33)), qy = hex(pub.slice(33))
      this.devs.push({ sk, qx, qy })
      const r = await send(this.c.addr, hexToBytes(this.c.iface.encodeFunctionData('registerDevice', [j, qx, qy])))
      this.regGas = r.gas
    }
  },
  sign(rec, j) {
    const h = sha256(hexToBytes(abi.encode(['address', 'bytes32', 'uint64', 'bytes32', 'bytes20'],
      [this.c.addr.toString(), rec.ct, rec.ts, rec.chk, rec.seed])))
    const sig = p256.sign(h, this.devs[j].sk, { prehash: false, format: 'compact' })
    return [j, rec.ct, rec.ts, rec.chk, rec.seed, hex(sig.slice(0, 32)), hex(sig.slice(32))]
  },
  dev(j) { return [j, this.devs[j].qx, this.devs[j].qy] },
  batch(n, tamper = false) {
    const m = Math.min(n, M)
    const ms = Array.from({ length: n }, (_, i) => this.sign(record(i), i % m))
    if (tamper) ms[Math.floor(n / 2)][3] = rnd(32)
    return hexToBytes(this.c.iface.encodeFunctionData('submitBatch', [Array.from({ length: m }, (_, j) => this.dev(j)), ms]))
  },
  one() { return hexToBytes(this.c.iface.encodeFunctionData('submitOne', [this.dev(0), this.sign(record(0), 0)])) },
}

// --- BLS: per-device keys, aggregate signature
schemes.BLS = {
  label: 'BLS12-381 aggregate (EIP-2537)',
  async setup() {
    this.c = await deploy('BLSAggVerifier')
    this.devs = []
    for (let j = 0; j < M; j++) {
      const sk = randScalar(), pkh = encG2(G2.BASE.multiply(sk))
      const r = await send(this.c.addr, hexToBytes(this.c.iface.encodeFunctionData('registerDevice', [j, words(pkh, 8)])))
      this.regGas = r.gas
      this.devs.push({ sk, pkh, commit: '0x' + Buffer.from(keccak_256(hexToBytes('0x' + pkh))).toString('hex') })
    }
  },
  enc(rec, j) { return abi.encode(['bytes32', 'bytes32', 'uint64', 'bytes32', 'bytes20'], [this.devs[j].commit, rec.ct, rec.ts, rec.chk, rec.seed]) },
  H(e) { return bls12_381.G1.hashToCurve(hexToBytes(e), { DST }) },
  build(n, m, tamper) {
    let agg = G1.ZERO
    const ms = []
    for (let i = 0; i < n; i++) {
      const j = i % m, rec = record(i)
      agg = agg.add(this.H(this.enc(rec, j)).multiply(this.devs[j].sk))
      ms.push([j, rec.ct, rec.ts, rec.chk, rec.seed])
    }
    if (tamper) ms[Math.floor(n / 2)][3] = rnd(32)
    return [Array.from({ length: m }, (_, j) => [j, words(this.devs[j].pkh, 8)]), ms, words(encG1(agg), 4)]
  },
  batch(n, tamper = false) { return hexToBytes(this.c.iface.encodeFunctionData('submitBatch', this.build(n, Math.min(n, M), tamper))) },
  one() { return hexToBytes(this.c.iface.encodeFunctionData('submitOne', this.build(1, 1, false))) },
}

// ------------------------------------------------------------------ run
const results = { environment: { evm: '@ethereumjs/vm 10.1.3', hardfork: 'osaka', solc: solc.version(), via_ir: true,
  tx_gas_cap: Number(TX_GAS_CAP), devices: M }, schemes: {}, scaling: [], max_batch: {}, anchoring: [] }

for (const [key, S] of Object.entries(schemes)) {
  await S.setup()
  const info = { label: S.label, deploy_gas: S.c.deployGas, register_device_gas: S.regGas }
  // correctness
  info.valid_batch_accepted = (await send(S.c.addr, S.batch(20))).ok
  info.tampered_batch_rejected = !(await send(S.c.addr, S.batch(20, true))).ok
  if (key === 'BLS') {   // on-chain hash_to_curve must equal RFC 9380 reference (noble)
    const e = S.enc(record(0), 0)
    const r = await call(S.c.addr, hexToBytes(S.c.iface.encodeFunctionData('hashToG1', [e])))
    const onchain = S.c.iface.decodeFunctionResult('hashToG1', r.returnValue)[0].slice(2)
    info.hash_to_curve_matches_rfc9380 = onchain === encG1(S.H(e))
    info.hash_to_g1_call_gas = Number(r.executionGasUsed)
  }
  // individual
  const ones = []
  for (let k = 0; k < 5; k++) { const r = await send(S.c.addr, S.one()); if (!r.ok) throw new Error(key + ' one ' + r.err); ones.push(r.gas) }
  info.individual_gas = Math.round(ones.reduce((a, b) => a + b) / ones.length)
  info.individual_calldata = S.one().length
  results.schemes[key] = info
  console.log(key, JSON.stringify(info))
  // scaling
  for (const n of QUICK ? [1, 10, 100] : [1, 10, 50, 100, 200, 500, 1000, 2000]) {
    const r = await send(S.c.addr, S.batch(n))
    results.scaling.push({ scheme: key, n, devices: Math.min(n, M), total_gas: r.ok ? r.gas : null,
      per_msg_gas: r.ok ? Math.round(r.gas / n) : null, calldata_bytes: r.calldata, ok: r.ok })
    console.log(`  ${key} n=${String(n).padStart(4)} ${r.ok ? r.gas.toLocaleString().padStart(12) + '  ' + Math.round(r.gas / n).toLocaleString() + '/msg' : 'FAILED (cap)'}`)
  }
  // largest batch under the per-transaction cap
  if (!QUICK) {
    let lo = 50, hi = 4000
    while (hi - lo > 10) { const mid = (lo + hi) >> 1; if ((await send(S.c.addr, S.batch(mid))).ok) lo = mid; else hi = mid }
    results.max_batch[key] = lo
    console.log(`  ${key} max n under cap ~${lo}`)
  }
}

// ------------------------------------------------------------------ anchoring without authentication
{
  const A = await deploy('AnchorOnly')
  for (const n of QUICK ? [10, 100] : [10, 100, 500, 1000]) {
    const h = Array.from({ length: n }, () => rnd(32))
    const t0 = await send(A.addr, hexToBytes(A.iface.encodeFunctionData('anchorRootOnly', [rnd(32), n])))
    const t1 = await send(A.addr, hexToBytes(A.iface.encodeFunctionData('anchorLeaves', [h])))
    const each = await send(A.addr, hexToBytes(A.iface.encodeFunctionData('anchorEach', [h.map(() => rnd(32))])))
    results.anchoring.push({ n, root_only_gas: t0.gas, leaves_root_gas: t1.gas, each_slot_gas: each.ok ? each.gas : null })
    console.log(`anchor n=${n} root-only=${t0.gas} leaves+root=${t1.gas} each=${each.ok ? each.gas : 'FAILED'}`)
  }
}

fs.writeFileSync(`${OUT}/baselines_results.json`, JSON.stringify(results, null, 2))
const csv = (rows) => [Object.keys(rows[0]).join(','), ...rows.map(r => Object.values(r).join(','))].join('\n') + '\n'
fs.writeFileSync(`${OUT}/baselines_scaling.csv`, csv(results.scaling))
fs.writeFileSync(`${OUT}/anchoring_only.csv`, csv(results.anchoring))
console.log('written to', OUT)
