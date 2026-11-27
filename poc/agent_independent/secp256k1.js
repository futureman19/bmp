'use strict';
// Independent BMP-0005 secp256k1 / RFC6979 implementation (Node built-ins only).
// Written from the secp256k1 curve parameters, RFC6979 (deterministic ECDSA),
// and BMP-0000 §4.1 / BMP-0005 §5.4. No code from poc/agent or poc/svcode.

const crypto = require('crypto');

const P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2Fn;
const N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;
const GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798n;
const GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8n;
const G = { x: GX, y: GY };
const HALF_N = N >> 1n;

function mod(a, m = P) { const r = a % m; return r >= 0n ? r : r + m; }

function modPow(base, exp, m) {
  base = mod(base, m);
  let acc = 1n;
  while (exp > 0n) {
    if (exp & 1n) acc = (acc * base) % m;
    base = (base * base) % m;
    exp >>= 1n;
  }
  return acc;
}

function modInv(a, m = P) {
  a = mod(a, m);
  if (a === 0n) throw new Error('modInv of zero');
  let [old_r, r] = [a, m];
  let [old_s, s] = [1n, 0n];
  while (r !== 0n) {
    const q = old_r / r;
    [old_r, r] = [r, old_r - q * r];
    [old_s, s] = [s, old_s - q * s];
  }
  return mod(old_s, m);
}

// Affine point addition; null = point at infinity.
function pointAdd(p1, p2) {
  if (p1 === null) return p2;
  if (p2 === null) return p1;
  if (p1.x === p2.x) {
    if (mod(p1.y + p2.y) === 0n) return null;
    return pointDouble(p1);
  }
  const lam = mod((p2.y - p1.y) * modInv(p2.x - p1.x));
  const x = mod(lam * lam - p1.x - p2.x);
  const y = mod(lam * (p1.x - x) - p1.y);
  return { x, y };
}

function pointDouble(p1) {
  if (p1 === null || p1.y === 0n) return null;
  const lam = mod(3n * p1.x * p1.x * modInv(2n * p1.y));
  const x = mod(lam * lam - 2n * p1.x);
  const y = mod(lam * (p1.x - x) - p1.y);
  return { x, y };
}

function scalarMult(k, pt) {
  k = mod(k, N);
  let acc = null;
  let addend = pt;
  while (k > 0n) {
    if (k & 1n) acc = pointAdd(acc, addend);
    addend = pointDouble(addend);
    k >>= 1n;
  }
  return acc;
}

function sha256(buf) { return crypto.createHash('sha256').update(buf).digest(); }
function hmacSha256(key, data) { return crypto.createHmac('sha256', key).update(data).digest(); }

function bytesToBigInt(buf) {
  let v = 0n;
  for (const b of buf) v = (v << 8n) | BigInt(b);
  return v;
}
function bigIntTo32(v) {
  const out = Buffer.alloc(32);
  for (let i = 31; i >= 0; i--) { out[i] = Number(v & 0xffn); v >>= 8n; }
  return out;
}
function hexToBytes(hex) {
  if (typeof hex !== 'string' || hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) {
    throw new Error('bad hex');
  }
  return Buffer.from(hex, 'hex');
}
function bytesToHex(buf) { return Buffer.from(buf).toString('hex'); }

function checkPrivateKey(d) {
  if (typeof d !== 'bigint' || d < 1n || d >= N) throw new Error('private key out of range');
}

// Compressed SEC1 public key (33 bytes) from private scalar.
function derivePubkey(dHex) {
  const d = BigInt('0x' + dHex);
  checkPrivateKey(d);
  const q = scalarMult(d, G);
  if (q === null) throw new Error('invalid public key');
  const prefix = (q.y & 1n) === 0n ? '02' : '03';
  return prefix + bigIntTo32(q.x).toString('hex');
}

// Decompress + full curve membership check. Throws on any invalid point.
function decompressPubkey(pubHex) {
  if (typeof pubHex !== 'string' || pubHex.length !== 66 || !/^[0-9a-f]{66}$/.test(pubHex)) {
    throw new Error('pubkey format');
  }
  const prefix = pubHex.slice(0, 2);
  if (prefix !== '02' && prefix !== '03') throw new Error('pubkey prefix');
  const x = BigInt('0x' + pubHex.slice(2));
  if (x >= P) throw new Error('pubkey x >= field prime');
  const rhs = mod(x * x * x + 7n);
  // p % 4 == 3, so sqrt(a) = a^((p+1)/4) when a is a quadratic residue.
  let y = modPow(rhs, (P + 1n) / 4n, P);
  if (mod(y * y) !== rhs) throw new Error('point not on curve');
  const wantOdd = prefix === '03';
  if ((y & 1n) !== (wantOdd ? 1n : 0n)) y = P - y;
  return { x, y };
}

function isOnCurve(pubHex) {
  try { decompressPubkey(pubHex); return true; } catch { return false; }
}

// --- RFC6979 deterministic nonce (HMAC-SHA256), secp256k1 qlen = 256 ---
// Returns the initial {V, K} state after the two setup HMAC rounds.
function rfc6979Init(d, h1) {
  const x = bigIntTo32(d);
  const z1 = bytesToBigInt(h1);
  const h1oct = bigIntTo32(mod(z1, N)); // bits2octets
  let V = Buffer.alloc(32, 0x01);
  let K = Buffer.alloc(32, 0x00);
  K = hmacSha256(K, Buffer.concat([V, Buffer.from([0x00]), x, h1oct]));
  V = hmacSha256(K, V);
  K = hmacSha256(K, Buffer.concat([V, Buffer.from([0x01]), x, h1oct]));
  V = hmacSha256(K, V);
  return { V, K };
}

// Deterministic low-s ECDSA over SHA-256(msg). Returns 64-byte r||s Buffer.
// msgBuf is the raw signed_bytes (header || payload); it is hashed exactly
// once with SHA-256 here, and that single digest feeds both RFC 6979 and ECDSA.
// WARNING: BigInt arithmetic is variable-time and secrets are not zeroized.
// Test/PoC use only — never sign with keys that control real funds.
function signDeterministic(privHex, msgBuf) {
  const d = BigInt('0x' + privHex);
  checkPrivateKey(d);
  const h1 = sha256(msgBuf);
  const z = bytesToBigInt(h1);
  let { V, K } = rfc6979Init(d, h1);
  for (;;) {
    V = hmacSha256(K, V);
    const k = bytesToBigInt(V);
    if (k >= 1n && k < N) {
      const R = scalarMult(k, G);
      if (R !== null) {
        const r = mod(R.x, N);
        if (r !== 0n) {
          let s = mod(modInv(k, N) * (z + r * d), N);
          if (s !== 0n) {
            if (s > HALF_N) s = N - s; // low-s canonical form
            return Buffer.concat([bigIntTo32(r), bigIntTo32(s)]);
          }
        }
      }
    }
    // RFC6979 retry: K = HMAC_K(V || 0x00); V = HMAC_K(V); loop.
    K = hmacSha256(K, Buffer.concat([V, Buffer.from([0x00])]));
    V = hmacSha256(K, V);
  }
}

// Mathematical ECDSA verify (accepts any 1 <= s < n; low-s policy is the
// decoder's job). pubHex must be a valid compressed curve point.
function verifySignature(pubHex, msgBuf, sigBuf) {
  if (!Buffer.isBuffer(sigBuf) || sigBuf.length !== 64) return false;
  const r = bytesToBigInt(sigBuf.subarray(0, 32));
  const s = bytesToBigInt(sigBuf.subarray(32, 64));
  if (r < 1n || r >= N || s < 1n || s >= N) return false;
  let Q;
  try { Q = decompressPubkey(pubHex); } catch { return false; }
  const z = bytesToBigInt(sha256(msgBuf));
  const w = modInv(s, N);
  const u1 = mod(z * w, N);
  const u2 = mod(r * w, N);
  const R = pointAdd(scalarMult(u1, G), scalarMult(u2, Q));
  if (R === null) return false;
  return mod(R.x, N) === r;
}

function isLowS(sigBuf) {
  return bytesToBigInt(sigBuf.subarray(32, 64)) <= HALF_N;
}

// --- OpenSSL cross-check helpers (independent verifier path) ---
function b64url(buf) { return Buffer.from(buf).toString('base64url'); }

function pubkeyToJwk(pubHex) {
  const { x, y } = decompressPubkey(pubHex);
  return { kty: 'EC', crv: 'secp256k1', x: b64url(bigIntTo32(x)), y: b64url(bigIntTo32(y)) };
}

function privkeyToJwk(privHex) {
  const pubHex = derivePubkey(privHex);
  const { x, y } = decompressPubkey(pubHex);
  return { kty: 'EC', crv: 'secp256k1', d: b64url(bigIntTo32(BigInt('0x' + privHex))), x: b64url(bigIntTo32(x)), y: b64url(bigIntTo32(y)) };
}

function derInt(v) {
  let b = bigIntTo32(v);
  let i = 0;
  while (i < b.length - 1 && b[i] === 0) i++;
  b = b.subarray(i);
  if (b[0] & 0x80) b = Buffer.concat([Buffer.from([0x00]), b]);
  return Buffer.concat([Buffer.from([0x02, b.length]), b]);
}

function rsToDer(sigBuf) {
  const r = derInt(bytesToBigInt(sigBuf.subarray(0, 32)));
  const s = derInt(bytesToBigInt(sigBuf.subarray(32, 64)));
  const body = Buffer.concat([r, s]);
  return Buffer.concat([Buffer.from([0x30, body.length]), body]);
}

function derToRs(der) {
  // minimal DER ECDSA-Sig-Value parser
  let o = 0;
  if (der[o++] !== 0x30) throw new Error('DER seq');
  const len = der[o++];
  if (len !== der.length - 2) throw new Error('DER len');
  function rd() {
    if (der[o++] !== 0x02) throw new Error('DER int');
    const l = der[o++];
    const v = der.subarray(o, o + l); o += l;
    return bytesToBigInt(v);
  }
  const r = rd(), s = rd();
  if (o !== der.length) throw new Error('DER trailing');
  return Buffer.concat([bigIntTo32(r), bigIntTo32(s)]);
}

// Verify a 64-byte r||s signature with OpenSSL (different codebase than ours).
function opensslVerify(pubHex, msgBuf, sigBuf) {
  const key = crypto.createPublicKey({ key: pubkeyToJwk(pubHex), format: 'jwk' });
  return crypto.verify('sha256', msgBuf, key, rsToDer(sigBuf));
}

// Produce a random-k OpenSSL signature (for cross-verifying OUR verifier).
function opensslSignRandomK(privHex, msgBuf) {
  const key = crypto.createPrivateKey({ key: privkeyToJwk(privHex), format: 'jwk' });
  const der = crypto.createSign('sha256').update(msgBuf).sign(key);
  let rs = derToRs(der);
  // normalize to low-s so it matches protocol policy
  const s = bytesToBigInt(rs.subarray(32, 64));
  if (s > HALF_N) rs = Buffer.concat([rs.subarray(0, 32), bigIntTo32(N - s)]);
  return rs;
}

module.exports = {
  P, N, G, HALF_N,
  mod, modInv, pointAdd, scalarMult,
  sha256, bytesToBigInt, bigIntTo32, hexToBytes, bytesToHex,
  derivePubkey, decompressPubkey, isOnCurve,
  signDeterministic, verifySignature, isLowS,
  pubkeyToJwk, opensslVerify, opensslSignRandomK, rsToDer, derToRs,
};
