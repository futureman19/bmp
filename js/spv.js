/* spv.js — BMP-0003 (L3) SPV inclusion verifier + BMP-0004 header trust,
   zero-dependency JS. Mirrors poc/svcode/spv.py exactly.
   Browser + Node (needs SVC + SVANCHOR). BigInt throughout; no floats in
   target/hash/work math. */
"use strict";
const SVSPV = (() => {
const _SVC = (typeof module !== "undefined") ? require("./svc.js") : SVC;
const _A = (typeof module !== "undefined") ? require("./anchor.js") : SVANCHOR;
const { hexToBytes, bytesToHex } = _SVC;
const sha256d = _A.sha256d;

const BEEF_V1 = [0x01, 0x00, 0xBE, 0xEF];
const FLAG_DUPLICATE = 0x01, FLAG_CLIENT_TXID = 0x02;

function rdVarint(b, off){
  const n = b[off]; off += 1;
  if (n < 0xFD) return [n, off];
  if (n === 0xFD) return [b[off] | (b[off+1] << 8), off + 2];
  if (n === 0xFE) return [(b[off] | b[off+1]<<8 | b[off+2]<<16 | b[off+3]<<24) >>> 0, off + 4];
  let v = 0n; for (let i = 0; i < 8; i++) v |= BigInt(b[off+i]) << (8n * BigInt(i));
  if (v > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error("varint too large");
  return [Number(v), off + 8];
}

/* ---------- BRC-74 BUMP ---------- */
function parseBumpFrom(b, off0){
  let off = off0;
  let blockHeight; [blockHeight, off] = rdVarint(b, off);
  const treeHeight = b[off]; off += 1;
  if (treeHeight === 0 || treeHeight > 64) throw new Error("bad tree height");
  const path = [];
  for (let level = 0; level < treeHeight; level++){
    let n; [n, off] = rdVarint(b, off);
    const leaves = [];
    for (let i = 0; i < n; i++){
      let offset; [offset, off] = rdVarint(b, off);
      const flags = b[off]; off += 1;
      let hash = null;
      if (!(flags & FLAG_DUPLICATE)){ hash = b.slice(off, off + 32); off += 32; }
      leaves.push({ offset, flags, hash });
    }
    leaves.sort((a, c) => a.offset - c.offset);
    path.push(leaves);
  }
  return [{ blockHeight, treeHeight, path }, off];
}

function parseBump(b){
  const [bump, off] = parseBumpFrom(b, 0);
  if (off !== b.length) throw new Error("trailing bytes after BUMP");
  return bump;
}

/* Merkle root (internal byte order, Uint8Array) for txid given as display hex. */
function bumpRoot(bump, txidDisplayHex){
  const txid = hexToBytes(txidDisplayHex).reverse();
  const leaf = bump.path[0].find(l => l.hash && eq(l.hash, txid));
  if (!leaf) throw new Error("txid not in BUMP level 0");
  const index = leaf.offset;
  let working = txid;
  for (let height = 0; height < bump.path.length; height++){
    const sibOff = (index >> height) ^ 1;
    const sib = bump.path[height].find(l => l.offset === sibOff);
    if (!sib) throw new Error(`missing sibling at level ${height}`);
    if (sib.flags & FLAG_DUPLICATE){
      working = sha256d(cat(working, working));
    } else if (sibOff & 1){
      working = sha256d(cat(working, sib.hash));   // working is LEFT child
    } else {
      working = sha256d(cat(sib.hash, working));   // working is RIGHT child
    }
  }
  return working;
}
function cat(a, b){ const o = new Uint8Array(a.length + b.length); o.set(a, 0); o.set(b, a.length); return o; }
function eq(a, b){ if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false; return true; }

/* ---------- BRC-62 BEEF v1 ---------- */
function parseRawTxStream(b, off){
  const start = off;
  off += 4;
  let nin; [nin, off] = rdVarint(b, off);
  for (let i = 0; i < nin; i++){
    off += 36;
    let slen; [slen, off] = rdVarint(b, off);
    off += slen + 4;
  }
  let nout; [nout, off] = rdVarint(b, off);
  for (let i = 0; i < nout; i++){
    off += 8;
    let slen; [slen, off] = rdVarint(b, off);
    off += slen;
  }
  off += 4;
  return [b.slice(start, off), off];
}

function parseBeef(b){
  if (!BEEF_V1.every((v, i) => b[i] === v)) throw new Error("not BEEF v1 (0100BEEF)");
  let off = 4;
  let nBumps; [nBumps, off] = rdVarint(b, off);
  const bumps = [];
  for (let i = 0; i < nBumps; i++){
    const [bump, noff] = parseBumpFrom(b, off);
    bumps.push(bump); off = noff;
  }
  let nTxs; [nTxs, off] = rdVarint(b, off);
  const txs = [];
  for (let i = 0; i < nTxs; i++){
    let raw; [raw, off] = parseRawTxStream(b, off);
    const hasBump = b[off]; off += 1;
    let bidx = null;
    if (hasBump){ [bidx, off] = rdVarint(b, off);
      if (bidx >= bumps.length) throw new Error("BUMP index out of range"); }
    txs.push({ raw, txid: bytesToHex(sha256d(raw).reverse()), bumpIndex: bidx });
  }
  if (off !== b.length) throw new Error("trailing bytes after BEEF");
  return { bumps, txs };
}

/* ---------- BMP-0004 §3: consensus constants, compact targets, work ---------- */
const MAINNET_POW_LIMIT = (1n << 224n) - 1n;
const MAINNET_GENESIS_HASH = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";

/* Core v32.1 arith_uint256::SetCompact port -> {target, negative, overflow}.
   The size<=3 right-shift happens BEFORE the flags are computed (the
   shift-order bug this spec was written against). Integer-only (BigInt). */
function decodeCompact(bits){
  const size = bits >>> 24;
  let word = bits & 0x007FFFFF;
  let target;
  if (size <= 3){
    word >>>= 8 * (3 - size);
    target = BigInt(word);
  } else {
    target = BigInt(word) << BigInt(8 * (size - 3));
  }
  const negative = word !== 0 && (bits & 0x00800000) !== 0;
  const overflow = word !== 0 && (
    size > 34 ||
    (word > 0xFF && size > 33) ||
    (word > 0xFFFF && size > 32));
  return { target, negative, overflow };
}

/* nBits -> target with full BMP-0004 §3.2 consensus validity. Throws with
   the pinned substrings 'negative target', 'zero target', 'target overflow',
   'target exceeds powLimit'. powLimit is injectable (§3.2); it gates the
   powLimit check only, never the consensus flags. */
function targetFromBits(bits, powLimit = MAINNET_POW_LIMIT){
  const { target, negative, overflow } = decodeCompact(bits);
  if (negative) throw new Error("negative target");
  if (target === 0n) throw new Error("zero target");
  if (overflow) throw new Error("target overflow");
  if (target > powLimit) throw new Error("target exceeds powLimit");
  return target;
}

/* BMP-0004 §3.4 floor form: ((2^256 − 1 − target) / (target + 1)) + 1
   (BigInt division floors). Equals Core GetBlockProof exactly for every
   valid target; the ceil variant is forbidden. */
function blockWork(target){
  return ((1n << 256n) - 1n - target) / (target + 1n) + 1n;
}

/* ---------- block headers ---------- */
function verifyHeader(header, powLimit = MAINNET_POW_LIMIT){
  if (header.length !== 80) throw new Error("header must be 80 bytes");
  const bits = (header[72] | header[73]<<8 | header[74]<<16 | header[75]<<24) >>> 0;
  const target = targetFromBits(bits, powLimit);
  const digest = sha256d(header);
  const hnum = bytesToBigLE(digest);
  if (hnum > target) throw new Error("header fails proof-of-work");
  return { hash: bytesToHex(digest.slice().reverse()),
           merkleRoot: header.slice(36, 68),
           prevHash: header.slice(4, 36) };
}
function bytesToBigLE(b){ let v = 0n; for (let i = b.length - 1; i >= 0; i--) v = (v << 8n) | BigInt(b[i]); return v; }

/* ---------- BMP-0004 §4: trusted header store ---------- */
/* createHeaderStore({ anchors: [{header, height}, ...], powLimit, maxOrphans })
   Mirrors Python HeaderStore exactly:
   - anchors (§4.1): full §3.2 validity, asserted heights, same-height ⇒
     same-hash ('anchor height conflict'), height-0 genesis rule under
     MAINNET_POW_LIMIT, idempotent duplicates, empty list allowed (inert).
   - add() (§4.2): validity → duplicate no-op → parent lookup against
     adopted/anchors ONLY → fork choice → transitive FIFO orphan drain.
   - best tip = max cumulative work; ties keep the incumbent (§4.3).
   - getByRoot() answers from the BEST CHAIN only (§4.5).
   - size counts anchors + adopted headers, never orphans (§4.4).
   Info: {hash(display hex), merkleRoot(internal bytes), prevHash(internal
   bytes), height(Number), work(BigInt)} — first three keys are exactly
   verifyHeader's return shape. */
function createHeaderStore({ anchors = [], powLimit = MAINNET_POW_LIMIT,
                             maxOrphans = 1024 } = {}){
  if (typeof powLimit !== "bigint" || powLimit <= 0n)
    throw new Error("powLimit must be a positive BigInt");
  if (!Number.isInteger(maxOrphans) || maxOrphans < 0)
    throw new Error("maxOrphans must be a non-negative integer");
  const byHash = new Map();      // display hash hex -> info
  const orphans = new Map();     // display hash hex -> {base, target}, FIFO
  const anchorHashes = [];
  const anchorHeights = new Map(); // asserted height -> anchor hash
  let tip = null;
  let rootIndex = new Map();     // merkle root hex (internal) -> info

  function parentOf(base){
    // prevHash is internal byte order; byHash is keyed by display hex
    return byHash.get(bytesToHex(base.prevHash.slice().reverse())) || null;
  }
  function rebuildRootIndex(){
    rootIndex = new Map();
    if (tip === null) return;
    const chain = [];
    let cur = tip;
    while (cur !== null){ chain.push(cur); cur = parentOf(cur); }
    chain.sort((a, b) => a.height - b.height);
    for (const info of chain){
      const key = bytesToHex(info.merkleRoot);
      if (!rootIndex.has(key)) rootIndex.set(key, info);  // first occurrence wins
    }
  }
  function considerTip(info){
    if (tip === null || info.work > tip.work){   // ties keep incumbent (§4.3)
      tip = info;
      rebuildRootIndex();
    }
  }
  function adopt(base, target, parent){
    const info = { hash: base.hash, merkleRoot: base.merkleRoot,
                   prevHash: base.prevHash, height: parent.height + 1,
                   work: parent.work + blockWork(target) };
    byHash.set(info.hash, info);
    considerTip(info);                            // §4.3
    return info;
  }
  function parkOrphan(base, target){
    if (!orphans.has(base.hash))                  // keep first slot (FIFO)
      orphans.set(base.hash, { base, target });
    while (orphans.size > maxOrphans){            // §4.4 silent eviction
      orphans.delete(orphans.keys().next().value);
    }
  }
  function drainOrphans(){
    // Transitive drain in pool insertion order (FIFO); repeat until a full
    // pass adopts nothing. Runs after every successful adoption (§4.2.5).
    for (;;){
      let adoptedAny = false;
      for (const h of Array.from(orphans.keys())){
        const entry = orphans.get(h);
        const parent = parentOf(entry.base);
        if (parent !== null){
          orphans.delete(h);
          adopt(entry.base, entry.target, parent);
          adoptedAny = true;
        }
      }
      if (!adoptedAny) break;
    }
  }
  function addAnchor(header, height){
    if (!Number.isInteger(height) || height < 0)
      throw new Error("anchor height must be a non-negative integer");
    const base = verifyHeader(header, powLimit);
    if (powLimit === MAINNET_POW_LIMIT && height === 0 &&
        base.hash !== MAINNET_GENESIS_HASH)
      throw new Error("height-0 anchor must hash to the mainnet genesis block");
    const h = base.hash;
    // §4.1.2: two anchors asserting the same height MUST have the same hash
    if (anchorHeights.has(height) && anchorHeights.get(height) !== h)
      throw new Error("anchor height conflict");
    if (byHash.has(h)){
      if (byHash.get(h).height !== height) throw new Error("anchor height conflict");
      return;                                     // idempotent duplicate anchor
    }
    const bits = (header[72] | header[73]<<8 | header[74]<<16 | header[75]<<24) >>> 0;
    const target = targetFromBits(bits, powLimit);
    const info = { hash: base.hash, merkleRoot: base.merkleRoot,
                   prevHash: base.prevHash, height, work: blockWork(target) };
    byHash.set(h, info);
    anchorHashes.push(h);
    anchorHeights.set(height, h);
    considerTip(info);
  }

  for (const a of anchors) addAnchor(a.header, a.height);

  return {
    /* add(header) -> info | null (§4.2). Throws on §3.2 invalidity or height
       conflicts; a rejected add leaves all state unchanged (§4.6.6). */
    add(header){
      const base = verifyHeader(header, powLimit);          // step 1
      const h = base.hash;
      if (byHash.has(h)){                                   // step 2
        const existing = byHash.get(h);
        const parent = parentOf(base);
        if (parent !== null && parent.height + 1 !== existing.height)
          throw new Error("duplicate header height conflict");
        return existing;
      }
      const bits = (header[72] | header[73]<<8 | header[74]<<16 | header[75]<<24) >>> 0;
      const target = targetFromBits(bits, powLimit);
      const parent = parentOf(base);                        // step 3
      if (parent === null){ parkOrphan(base, target); return null; }
      const info = adopt(base, target, parent);             // step 4
      drainOrphans();                                       // step 5
      return info;
    },
    /* addMany(headers): apply add() in order; returns the number of calls
       that returned info (adopted or duplicate no-op). Parked orphans do
       not count. */
    addMany(headers){
      let n = 0;
      for (const header of headers) if (this.add(header) !== null) n++;
      return n;
    },
    bestTip(){ return tip; },
    /* Best-chain header with this merkle root (internal byte order), else
       null. Losing-fork and orphan roots never match (§4.5). */
    getByRoot(merkleRoot){ return rootIndex.get(bytesToHex(merkleRoot)) || null; },
    has(hashHex){ return byHash.has(hashHex); },
    get size(){ return byHash.size; },
    /* inspection helpers (tests / parity refs) */
    orphanHashes(){ return Array.from(orphans.keys()); },
    anchorHashes(){ return anchorHashes.slice(); },
    get powLimit(){ return powLimit; },
  };
}

/* ---------- BMP-0004 §5: L3 pipeline (store-backed) ---------- */
/* store: a createHeaderStore() object — raw header arrays are no longer
   accepted (§5.1, no list fallback). tipHeight is REMOVED: burial depth is
   store-derived, depth = store.bestTip().height − matched.height + 1, using
   the STORE-assigned height of the matched header (never the BUMP's
   self-reported blockHeight — §5.2.6). seen: optional Map for freshness.
   Returns the envelope. */
function verifyL3(beef, authorityPubHex, store, seen = null, minDepth = 1){
  if (store === null || typeof store !== "object" ||
      typeof store.getByRoot !== "function" || typeof store.bestTip !== "function" ||
      typeof store.size !== "number")
    throw new TypeError("verifyL3 requires a header store (BMP-0004 §5.1); " +
                        "raw header arrays are no longer accepted");
  const doc = parseBeef(beef);                                    // 1. parse
  const subject = doc.txs[doc.txs.length - 1];                    // 2. subject = last
  const byTxid = new Map(doc.txs.map(t => [t.txid, t]));

  // BMP-0003 §5: "L3 without headers degrades safely — nothing verifies."
  // The subject MUST carry a BUMP proving inclusion into a held header; a
  // BEEF stripped of all BUMPs must not pass as L3 with an empty header store.
  // (R1, verbatim.)
  if (subject.bumpIndex === null)
    throw new Error("L3 requires a BUMP for the subject transaction");
  if (store.size === 0)
    throw new Error("L3 requires a non-empty header store");

  const parsedSubject = _A.parseTx(subject.raw);
  const prevouts = [];                                            // 3. derive evidence
  for (const inp of parsedSubject.inputs){
    const ptxid = bytesToHex(inp.outpoint.slice(0, 32).slice().reverse());
    const pvout = inp.outpoint[32] | inp.outpoint[33]<<8 | inp.outpoint[34]<<16 | inp.outpoint[35]<<24;
    const anc = byTxid.get(ptxid);
    if (!anc) throw new Error(`ancestor ${ptxid.slice(0, 16)}… not in BEEF`);
    const ancParsed = _A.parseTx(anc.raw);
    if (pvout >= ancParsed.outputs.length)
      throw new Error("input references nonexistent ancestor output");
    const o = ancParsed.outputs[pvout];
    prevouts.push({ txid: ptxid, vout: pvout, value: Number(o.value),
                    script_hex: bytesToHex(o.script) });
  }
  // 4. BMP-0002 §5. Freshness state is staged: verifyL2 commits into a scratch
  // copy which is merged into the caller's log only after ALL L3 checks pass
  // (BMP-0003 §5: a failed verification must leave no partial state behind).
  const staged = seen ? new Map(seen) : null;
  const env = _A.verifyL2(subject.raw, prevouts, authorityPubHex, staged);

  // 5. merkle inclusion: every tx carrying a BUMP must root into a BEST-CHAIN
  // header of the store (§4.5 / §5.2.5). Losing-fork and orphan roots fail
  // here — inclusion off the best chain is not settlement.
  const matched = [];
  for (const t of doc.txs){
    if (t.bumpIndex === null) continue;
    const bump = doc.bumps[t.bumpIndex];
    const root = bumpRoot(bump, t.txid);                          // 5a. BRC-74 walk
    const hdr = store.getByRoot(root);
    if (hdr === null)
      throw new Error(`tx ${t.txid.slice(0, 16)}…: merkle root not in header store`);
    matched.push(hdr);
  }
  // 6. burial depth (policy): STORE-derived heights on both sides (§5.2.6).
  // store.size > 0 guarantees a non-null tip (§4.6 / §5.2 step 3).
  const tip = store.bestTip();
  if (tip === null) throw new Error("L3 requires a non-empty header store");
  for (const hdr of matched){
    const depth = tip.height - hdr.height + 1;
    if (depth < minDepth) throw new Error(`insufficient burial depth ${depth} < ${minDepth}`);
  }
  if (seen && staged) for (const [k, v] of staged) seen.set(k, v);  // commit staged freshness
  return env;
}

return { parseBump, bumpRoot, parseBeef, verifyHeader, verifyL3,
         targetFromBits, decodeCompact, blockWork, createHeaderStore,
         MAINNET_POW_LIMIT, MAINNET_GENESIS_HASH,
         FLAG_DUPLICATE, FLAG_CLIENT_TXID };
})();
if (typeof module !== "undefined") module.exports = SVSPV;
