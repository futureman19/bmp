'use strict';
// BMP-0005 Q3 — independent seeded adversarial conformance + fuzz runner.
// Run: node fuzz_conformance.js            (default gate, >=20000 cases)
//      node fuzz_conformance.js --raw      (also emit raw byte corpus to fuzz_raw/)
//      node fuzz_conformance.js --nightly  (larger optional mode)
//
// Independence boundary (see README.md / FUZZ_README.md): derived ONLY from
// spec/BMP-0005, the published vector JSON under poc/vectors/, and Qwen's own
// poc/agent_independent implementation. No reference (poc/agent*) source/tests
// are read, imported or invoked. Offline; no network, wallets, funds, broadcast.
// Signing uses the two published test keys plus locally derived scalar 3.
//
// Determinism: a fixed-seed sfc32 PRNG drives every random choice. Case IDs are
// stable (`<class>-<seq>` in generation order). stdout and fuzz_manifest.json are
// byte-identical across runs (the twice-run gate). No wall-clock enters artifacts.

const fs = require('fs');
const path = require('path');
const wire = require('./wire.js');
const secp = require('./secp256k1.js');
const jcs = require('./jcs.js');

const ARGS = process.argv.slice(2);
const RAW = ARGS.includes('--raw');
const NIGHTLY = ARGS.includes('--nightly');
const SEED = 0x424d5033; // "BMP3" — fixed across runs and modes (mode scales counts only)

// ---------------------------------------------------------------------------
// Deterministic PRNG (sfc32). Pure 32-bit integer arithmetic; no Math.random.
function makeRng(seed) {
  let a = seed >>> 0, b = (seed ^ 0x9e3779b9) >>> 0, c = (seed + 0x85ebca6b) >>> 0, d = (seed ^ 0xc2b2ae35) >>> 0;
  function next() {
    a >>>= 0; b >>>= 0; c >>>= 0; d >>>= 0;
    let t = (a + b) | 0;
    a = b ^ (b >>> 9);
    b = (c + (c << 3)) | 0;
    c = (c << 21) | (c >>> 11);
    d = (d + 1) | 0;
    t = (t + d) | 0;
    c = (c + t) | 0;
    return (t >>> 0) / 4294967296;
  }
  for (let i = 0; i < 12; i++) next(); // warm up
  return {
    f: next,
    int(n) { return Math.floor(next() * n); },        // [0,n)
    range(lo, hi) { return lo + Math.floor(next() * (hi - lo + 1)); }, // inclusive
    pick(arr) { return arr[Math.floor(next() * arr.length)]; },
    bytes(n) { const b = Buffer.alloc(n); for (let i = 0; i < n; i++) b[i] = Math.floor(next() * 256); return b; },
    hex(n) { let s = ''; for (let i = 0; i < n; i++) s += '0123456789abcdef'[Math.floor(next() * 16)]; return s; },
  };
}
const rng = makeRng(SEED);

// ---------------------------------------------------------------------------
// Published inputs (data only).
const VEC = path.join(__dirname, '..', 'vectors', 'agent');
const positive = JSON.parse(fs.readFileSync(path.join(VEC, 'positive.json'), 'utf8'));
const negative = JSON.parse(fs.readFileSync(path.join(VEC, 'negative.json'), 'utf8'));
const FIXTURES = JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures_semantic.json'), 'utf8'));
const NOW = positive.now;
const posCases = Object.entries(positive.cases).map(([name, c]) => ({ name, ...c }));
const negCases = Array.isArray(negative) ? negative : negative.cases;
const posByName = {}; for (const c of posCases) posByName[c.name] = c;
const srcBytes = name => Buffer.from(posByName[name].envelopeHex, 'hex');
const canonBuf = name => srcBytes(name).subarray(85);
const canonStr = name => canonBuf(name).toString('utf8');
const NAMES = posCases.map(c => c.name);

const keyByPub = {};
for (const k of positive.publishedTestPrivateKeys) keyByPub[secp.derivePubkey(k)] = k;
const k1 = positive.publishedTestPrivateKeys[0];
const k2 = positive.publishedTestPrivateKeys[1];
const k3 = '0000000000000000000000000000000000000000000000000000000000000003';
const pub3 = secp.derivePubkey(k3);
const thirdParty = { agentPin: '3'.repeat(64) + '.0', pubkey: pub3, address: wire.deriveAddress(pub3) };
keyByPub[pub3] = k3;

// Decoded pool + full context (built once; controls reuse these).
const decoded = {};
for (const c of posCases) decoded[c.name] = wire.decodeEnvelope(srcBytes(c.name), { context: null, now: NOW });
const fullCtx = wire.makeContext(Object.values(decoded));
const DB = FIXTURES['request'].body.deliverBy;
const CAP = DB + 86400;

// ---------------------------------------------------------------------------
// Rejection-layer taxonomy (for coverage reporting). Every WireError code maps
// to exactly one layer; a blanket/unexpected exception is NEVER a pass.
const LAYER_OF = {
  truncated: 'wire', version: 'wire', action: 'wire', length: 'wire', target: 'wire',
  duplicate: 'json', noncanonical: 'json', number: 'json',
  missing: 'schema', unknown: 'schema', format: 'schema', text: 'schema',
  base64: 'schema', curve: 'schema', address: 'schema',
  signature: 'signature', 'high-s': 'signature',
  role: 'role', distinct: 'role', recipient: 'role',
  thread: 'thread',
  window: 'window', future: 'window', expired: 'window',
  'reference-action': 'binding', 'context-required': 'binding',
  conflict: 'state', 'duplicate-proof': 'state', nonce: 'state', nesting: 'schema',
};
const CODES = Object.keys(LAYER_OF);
const CLASSES = ['published-pos', 'published-neg', 'control', 'frame', 'json', 'utf8',
  'identity', 'base64', 'shape', 'signature', 'window', 'binding', 'payment-data',
  'encoder', 'property'];

// ---------------------------------------------------------------------------
// Case registry + executor.
const cases = [];
const seqByClass = {};
const controlCache = new Map();
let controlCount = 0;
const findings = [];          // explicit acceptReason annotations for accepted artifacts
const acceptedMutations = []; // tagged accepting mutations; acceptReason adds a normative annotation

function addCase(cls, c) {
  const expected = c.kind === 'property' || c.expect === undefined ? [] : (Array.isArray(c.expect) ? c.expect : [c.expect]);
  const known = new Set(['accept', 'PROPERTY', 'ERROR', ...CODES]);
  for (const code of expected) if (!known.has(code)) throw new Error('unknown expected category: ' + String(code));
  seqByClass[cls] = (seqByClass[cls] || 0) + 1;
  const id = `${cls}-${String(seqByClass[cls]).padStart(5, '0')}`;
  cases.push({ id, cls, ...c });
  return id;
}

// optsTag: stable string identifying the decode options for control caching.
function ensureControl(name, opts, optsTag) {
  const key = name + '|' + optsTag;
  if (controlCache.has(key)) return controlCache.get(key);
  const id = addCase('control', {
    kind: 'decode', bytes: srcBytes(name), opts, expect: 'accept',
    desc: `non-vacuity control: ${name} @ ${optsTag}`, controlFor: optsTag,
  });
  controlCache.set(key, id);
  controlCount++;
  return id;
}

// Build envelope bytes from a (possibly mutated) payload.
// sigMode: 'keep' = copy source signature (pre-verify checks only, cheap);
//          'sign' = re-sign with from's key; or a private-key hex to sign with.
function mkBytes(name, payloadBuf, hdrEdit, sigMode) {
  const src = srcBytes(name);
  const hdr = Buffer.from(src.subarray(0, 21));
  if (hdrEdit) hdrEdit(hdr);
  hdr.writeUInt16BE(payloadBuf.length, 19);
  let sig;
  if (sigMode === 'keep') sig = Buffer.from(src.subarray(21, 85));
  else {
    const key = (sigMode && sigMode !== 'sign') ? sigMode : keyByPub[JSON.parse(payloadBuf.toString('utf8')).from.pubkey];
    sig = secp.signDeterministic(key, Buffer.concat([hdr, payloadBuf]));
  }
  return Buffer.concat([hdr, sig, payloadBuf]);
}
const mutJson = (name, fn) => { const p = JSON.parse(canonStr(name)); fn(p); return jcs.canonicalBytes(p); };
const rawReplace = (name, needle, repl) => {
  const s = canonStr(name);
  if (!s.includes(needle)) throw new Error('anchor missing: ' + needle);
  return Buffer.from(s.replace(needle, repl), 'utf8');
};
function splicePayload(name, needleStr, replacementBuf) {
  const pb = Buffer.from(canonBuf(name));
  const needle = Buffer.from(needleStr, 'utf8');
  const i = pb.indexOf(needle);
  if (i < 0) throw new Error('splice anchor missing: ' + needleStr);
  return Buffer.concat([pb.subarray(0, i), replacementBuf, pb.subarray(i + needle.length)]);
}
const NULLOPTS = { context: null, now: NOW };
const FULLOPTS = { context: fullCtx, now: NOW };

// ---------------------------------------------------------------------------
// 0. Published vectors (start with every positive/negative + valid controls).
for (const c of posCases) {
  ensureControl(c.name, NULLOPTS, 'null');
  addCase('published-pos', { kind: 'decode', bytes: srcBytes(c.name), opts: NULLOPTS, expect: 'accept', desc: `published positive ${c.name} (null ctx)` });
  addCase('published-pos', { kind: 'decode', bytes: srcBytes(c.name), opts: FULLOPTS, expect: 'accept', desc: `published positive ${c.name} (full ctx)` });
  addCase('published-pos', {
    kind: 'encode', fx: { ...structuredClone(FIXTURES[c.name]), privateKey: keyByPub[FIXTURES[c.name].from.pubkey] },
    expect: 'accept', expectHash: c.sha256, desc: `semantic re-encode byte-exact ${c.name}`,
  });
}
ensureControl('accept', FULLOPTS, 'full');
for (const neg of negCases) {
  const src = srcBytes(neg.source);
  let buf;
  if (neg.appendZeroes !== undefined) buf = Buffer.concat([src, Buffer.alloc(neg.appendZeroes)]);
  else {
    const ins = Buffer.from(neg.insertHex, 'hex');
    buf = Buffer.concat([src.subarray(0, neg.offset), ins, src.subarray(neg.offset + neg.remove)]);
  }
  addCase('published-neg', {
    kind: 'decode', bytes: buf, opts: { context: neg.context ? fullCtx : null, now: neg.now },
    expect: neg.code, desc: `published negative ${neg.name}`,
  });
}

// ---------------------------------------------------------------------------
// 1. frame — header/version/action/length/truncation/trailing/target.
const SCALE = NIGHTLY ? 2 : 1;
function genFrame() {
  const N = 3600 * SCALE;
  for (let i = 0; i < N; i++) {
    const name = rng.pick(NAMES);
    const src = srcBytes(name);
    const sub = i % 6;
    let buf, expect, desc;
    if (sub === 0) { // version byte != 2
      buf = Buffer.from(src); let v = rng.range(0, 255); if (v === 2) v = 3; buf[0] = v;
      expect = 'version'; desc = `version=${v}`;
    } else if (sub === 1) { // unknown action uint16
      buf = Buffer.from(src);
      const unknown = rng.pick([0x0000, 0x0001, 0x9fff, 0xa00a, 0xa0ff, 0xb000, 0xffff, 0x1234]);
      buf.writeUInt16BE(unknown, 5); expect = 'action'; desc = `action=0x${unknown.toString(16)}`;
    } else if (sub === 2) { // length field mismatch
      buf = Buffer.from(src); const actual = src.length - 85;
      const delta = rng.pick([-rng.range(1, 40), rng.range(1, 40)]);
      let declared = actual + delta; if (declared < 0) declared = 0; if (declared > 65535) declared = 65535;
      if (declared === actual) declared = (actual + 1) & 0xffff;
      buf.writeUInt16BE(declared, 19); expect = 'length'; desc = `declared=${declared} actual=${actual}`;
    } else if (sub === 3) { // truncation
      const cut = rng.range(0, src.length - 1);
      buf = src.subarray(0, cut); expect = cut < 85 ? 'truncated' : 'length'; desc = `truncate@${cut}`;
    } else if (sub === 4) { // trailing bytes
      buf = Buffer.concat([src, rng.bytes(rng.range(1, 64))]); expect = 'length'; desc = 'trailing bytes';
    } else { // target != recipient derivation
      buf = Buffer.from(src); buf.writeUInt32BE(rng.range(0, 0xffffffff) >>> 0, 1);
      // ensure it differs from the real target
      if (buf.readUInt32BE(1) === src.readUInt32BE(1)) buf.writeUInt32BE((src.readUInt32BE(1) ^ 1) >>> 0, 1);
      expect = 'target'; desc = 'target mismatch';
    }
    const ctrl = ensureControl(name, NULLOPTS, 'null');
    addCase('frame', { kind: 'decode', bytes: buf, opts: NULLOPTS, expect, desc, control: ctrl });
  }
}

// ---------------------------------------------------------------------------
// 2. json — canonical-JSON violations (all pre-verify, cheap).
function genJson() {
  const N = 4000 * SCALE;
  for (let i = 0; i < N; i++) {
    const name = rng.pick(NAMES);
    const sub = i % 10;
    let payload, expect, desc;
    const s = canonStr(name);
    if (sub === 0) { // duplicate key
      const m = s.match(/"([a-zA-Z]+)":/); const key = m ? m[1] : 'body';
      payload = Buffer.from(s.replace('"' + key + '":', '"' + key + '":1,"' + key + '":'), 'utf8');
      expect = 'duplicate'; desc = 'duplicate key ' + key;
    } else if (sub === 1) { // key reorder (swap first two top-level keys textually)
      // canonical order is body,expiresAt?... use a known adjacent pair from the object
      const obj = JSON.parse(s); const keys = Object.keys(obj);
      // rebuild with two keys swapped -> noncanonical order
      const swapped = { ...obj };
      if (keys.length >= 2) {
        const entries = keys.map(k => [k, obj[k]]);
        const t = entries[0]; entries[0] = entries[1]; entries[1] = t;
        payload = Buffer.from('{' + entries.map(([k, v]) => JSON.stringify(k) + ':' + JSON.stringify(v)).join(',') + '}', 'utf8');
      } else payload = Buffer.from(s + ' ', 'utf8');
      expect = 'noncanonical'; desc = 'key order';
    } else if (sub === 2) { // whitespace injection
      payload = Buffer.from(s.slice(0, 1) + rng.pick([' ', '\n', '\t', '\r']) + s.slice(1), 'utf8');
      expect = 'noncanonical'; desc = 'whitespace';
    } else if (sub === 3) { // number grammar
      const nm = s.match(/:(0|[1-9][0-9]*)([,}])/);
      if (nm) {
        const repl = rng.pick([nm[1] + '.5', nm[1] + 'e2', '0' + nm[1], '-' + nm[1], nm[1] + '.0', '9007199254740993']);
        payload = Buffer.from(s.replace(':' + nm[1] + nm[2], ':' + repl + nm[2]), 'utf8');
        expect = ['number', 'noncanonical', 'duplicate']; desc = 'number grammar ' + repl;
      } else { payload = Buffer.from(s.replace('{', '{ "x" : 1 ,'), 'utf8'); expect = 'noncanonical'; desc = 'ws fallback'; }
    } else if (sub === 4) { // non-canonical escape
      const anchor = rng.pick(['provider', 'requester', 'text', 'endpoint']);
      if (s.includes(anchor)) {
        const esc = rng.pick(['\\u00' + anchor.charCodeAt(0).toString(16), '\\u0041', '\\/']);
        payload = Buffer.from(s.replace(anchor, esc + anchor.slice(1)), 'utf8');
        expect = 'noncanonical'; desc = 'escape ' + esc;
      } else { payload = Buffer.from(s.replace('"body"', '"\\u0062ody"'), 'utf8'); expect = 'noncanonical'; desc = 'escape body'; }
    } else if (sub === 5) { // raw control char in string
      payload = splicePayload(name, 'body', Buffer.concat([Buffer.from('bod'), Buffer.from([rng.range(0, 0x1f)]), Buffer.from('y')]));
      expect = 'noncanonical'; desc = 'raw control';
    } else if (sub === 6) { // depth bomb (>64)
      const depth = rng.range(65, 80);
      const chain = '{"c":'.repeat(depth) + '{"v":1}' + '}'.repeat(depth);
      payload = Buffer.from(s.replace(/"body":\{[^{}]*\}/, '"body":' + chain), 'utf8');
      if (!payload.toString('utf8').includes('"c"')) payload = Buffer.from('{"body":' + chain + '}', 'utf8');
      expect = 'noncanonical'; desc = 'depth ' + depth;
    } else if (sub === 7) { // trailing garbage after value
      payload = Buffer.concat([canonBuf(name), Buffer.from(rng.pick([' ', 'x', '{}', 'null', ',']))]);
      expect = 'noncanonical'; desc = 'trailing garbage';
    } else if (sub === 8) { // BOM
      payload = Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), canonBuf(name)]);
      expect = 'noncanonical'; desc = 'BOM';
    } else { // bad literal / unexpected char
      payload = Buffer.from(s.replace('"body"', '"body"').replace(/:(true|false|null)/, ':truX'), 'utf8');
      if (payload.toString('utf8') === s) payload = Buffer.from(s.replace('{', '{x'), 'utf8');
      expect = 'noncanonical'; desc = 'bad literal';
    }
    const ctrl = ensureControl(name, NULLOPTS, 'null');
    addCase('json', { kind: 'decode', bytes: mkBytes(name, payload, null, 'keep'), opts: NULLOPTS, expect, desc, control: ctrl });
  }
}

// ---------------------------------------------------------------------------
// 3. utf8 — invalid sequences (cheap) + Unicode confusables (re-signed).
const BAD_UTF8 = [
  [0xff], [0xfe], [0xc0, 0xaf], [0xe0, 0x80, 0xaf], [0xed, 0xa0, 0x80], [0xed, 0xb0, 0x80],
  [0x80], [0xbf], [0xe2, 0x82], [0xf0, 0x90, 0x80], [0xf4, 0x90, 0x80, 0x80], [0xc2],
  [0xe2, 0x82, 0xac, 0x80], [0xf0, 0x9f, 0x9a],
];
function genUtf8() {
  const N = 1600 * SCALE;
  for (let i = 0; i < N; i++) {
    if (i < 1200 * SCALE) { // invalid UTF-8 byte splice into a string field -> noncanonical
      const name = rng.pick(['deliver', 'reject', 'requester-ad', 'offer']);
      const anchor = rng.pick(['text/markdown', 'body', 'reason', 'kind']);
      const bad = Buffer.from(rng.pick(BAD_UTF8));
      let payload;
      try { payload = splicePayload(name, anchor, Buffer.concat([Buffer.from(anchor.slice(0, 2)), bad, Buffer.from(anchor.slice(2))])); }
      catch (_) { payload = splicePayload(name, 'body', Buffer.concat([Buffer.from('bo'), bad, Buffer.from('dy')])); }
      const ctrl = ensureControl(name, NULLOPTS, 'null');
      addCase('utf8', { kind: 'decode', bytes: mkBytes(name, payload, null, 'keep'), opts: NULLOPTS, expect: 'noncanonical', desc: 'invalid utf8 ' + bad.toString('hex'), control: ctrl });
    } else if (i < 1400 * SCALE) { // confusable in kind/service (ASCII-only grammar) -> format
      const name = rng.pick(['requester-ad', 'provider-ad', 'request']);
      const conf = rng.pick(['\u0430', '\u03bf', '\u0455', '\u0501', '\u0261']); // а ο ѕ ԁ ɡ
      const payload = mutJson(name, p => {
        if (Array.isArray(p.body.services) && p.body.services.length) p.body.services[0].kind = 're' + conf + 'quest';
        else if (typeof p.body.kind === 'string') p.body.kind = 're' + conf + 'quest';
        else p.body.zzKind = 're' + conf + 'quest';
      });
      const ctrl = ensureControl(name, NULLOPTS, 'null');
      addCase('utf8', { kind: 'decode', bytes: mkBytes(name, payload, null, 'sign'), opts: NULLOPTS, expect: Array.isArray(JSON.parse(canonStr(name)).body.services) && JSON.parse(canonStr(name)).body.services.length || typeof JSON.parse(canonStr(name)).body.kind === 'string' ? 'format' : 'unknown', desc: 'kind confusable U+' + conf.codePointAt(0).toString(16), control: ctrl });
    } else { // confusable in FREE TEXT (reason/content) -> ACCEPT (spec: opaque text)
      const name = rng.pick(['reject', 'deliver']);
      const conf = rng.pick(['\u0430', '\u03bf', '\u2014', '\u00e9', '\u4e2d']);
      const payload = mutJson(name, p => {
        if (p.body.reason !== undefined) p.body.reason = 're' + conf + 'son';
        else p.body.content = 'con' + conf + 'tent';
      });
      const ctrl = ensureControl(name, NULLOPTS, 'null');
      const id = addCase('utf8', { kind: 'decode', bytes: mkBytes(name, payload, null, 'sign'), opts: NULLOPTS, expect: 'accept', desc: 'free-text confusable U+' + conf.codePointAt(0).toString(16), control: ctrl, acceptReason: '§10.6/§10.9 reason/content are opaque single-line UTF-8 text; non-ASCII is legal (no ASCII-only grammar on free text).' });
      acceptedMutations.push(id);
    }
  }
}

// ---------------------------------------------------------------------------
// 4. identity — principal format/curve/address/target/evidence (pre-verify).
function genIdentity() {
  const N = 3400 * SCALE;
  for (let i = 0; i < N; i++) {
    const name = rng.pick(NAMES);
    const sub = i % 6;
    let payload, expect, desc, hdrEdit = null;
    if (sub === 0) { // agentPin format violations
      const badFns = [
        p => { p.from.agentPin = p.from.agentPin.replace(/\.(\d+)$/, '.01'); },
        p => { p.from.agentPin = p.from.agentPin.replace(/\.(\d+)$/, '.4294967296'); },
        p => { p.from.agentPin = p.from.agentPin.replace(/\.(\d+)$/, '.-1'); },
        p => { p.from.agentPin = p.from.agentPin.replace('.', ''); },
        p => { p.from.agentPin = 'g'.repeat(64) + '.0'; },
        p => { p.from.agentPin = 'a'.repeat(63) + '.0'; },
      ];
      const bad = rng.pick(badFns);
      payload = mutJson(name, bad); expect = 'format'; desc = 'pin format';
    } else if (sub === 1) { // pubkey curve / format
      const bad = rng.pick([
        p => { p.from.pubkey = '02' + 'ff'.repeat(32); },
        p => { p.from.pubkey = '04' + '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'; },
        p => { p.from.pubkey = '05' + '00'.repeat(32); },
        p => { p.from.pubkey = '02' + '00'.repeat(32); },
        p => { p.from.pubkey = '02' + 'ab'.repeat(31); },
      ]);
      payload = mutJson(name, bad); expect = 'curve'; desc = 'pubkey curve/format';
    } else if (sub === 2) { // address checksum/charset/version/length
      const bad = rng.pick([
        p => { const a = p.from.address; p.from.address = a.slice(0, -1) + (a.slice(-1) === 'H' ? 'J' : 'H'); },
        p => { p.from.address = '0OIl'; },
        p => { p.from.address = '1'.repeat(65); },
        p => { p.from.address = ''; },
        p => { p.from.address = 'mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn'; },
      ]);
      payload = mutJson(name, bad); expect = 'address'; desc = 'address';
    } else if (sub === 3) { // from.address != deriveAddress(pubkey)
      payload = mutJson(name, p => { p.from.address = wire.deriveAddress(pub3); });
      expect = 'address'; desc = 'from address mismatch';
    } else if (sub === 4) { // evidence placement
      const which = rng.int(3);
      if (which === 0 && (name === 'requester-ad' || name === 'provider-ad')) { payload = mutJson(name, p => { p.to.identityEvidence = 'V0lSRS1PTkxZ'; }); expect = 'duplicate-proof'; desc = 'evidence in to'; }
      else if (which === 1 && (name === 'request' || name === 'proof-identity')) {
        payload = mutJson(name, p => { p.from.identityEvidence = 'V0lSRS1PTkxZ'; }); expect = 'duplicate-proof'; desc = 'evidence in forbidden from';
      } else { payload = mutJson(name, p => { p.from.extraField = 1; }); expect = 'unknown'; desc = 'unknown principal field'; }
    } else { // missing principal field
      const field = rng.pick(['agentPin', 'pubkey', 'address']);
      payload = mutJson(name, p => { delete p.from[field]; }); expect = 'missing'; desc = 'missing from.' + field;
    }
    const ctrl = ensureControl(name, NULLOPTS, 'null');
    addCase('identity', { kind: 'decode', bytes: mkBytes(name, payload, hdrEdit, 'keep'), opts: NULLOPTS, expect, desc, control: ctrl });
  }
}

// ---------------------------------------------------------------------------
// 5. base64 — evidence blob canonicality (pre-verify, cheap).
const B64_BAD = ['QUI', 'QR==', 'A===', 'AB=C', 'aa==', 'ab-_', 'ab c', '', 'A', 'QUJD\n', 'QU JD', '====', 'QQ==QQ=='];
function genBase64() {
  const N = 1800 * SCALE;
  const evNames = ['requester-ad', 'provider-ad', 'proof-identity', 'payment', 'proof-payment'];
  for (let i = 0; i < N; i++) {
    const name = rng.pick(evNames);
    const bad = rng.pick(B64_BAD);
    const field = (name === 'payment' || name === 'proof-payment') ? 'atomicBeef' : 'identityEvidence';
    const payload = mutJson(name, p => {
      if (field === 'atomicBeef') p.body.atomicBeef = bad; else p.from.identityEvidence = bad;
    });
    const ctrl = ensureControl(name, NULLOPTS, 'null');
    addCase('base64', { kind: 'decode', bytes: mkBytes(name, payload, null, field === 'atomicBeef' ? 'sign' : 'keep'), opts: NULLOPTS, expect: 'base64', desc: `${field}=${JSON.stringify(bad)}`, control: ctrl });
  }
}

// ---------------------------------------------------------------------------
// 6. shape — body schema: missing/unknown/type/enum/hash/numeric/text.
function genShape() {
  const N = 3600 * SCALE;
  for (let i = 0; i < N; i++) {
    const name = rng.pick(NAMES);
    const sub = i % 7;
    let payload, expect, desc;
    const obj = JSON.parse(canonStr(name));
    const bodyKeys = Object.keys(obj.body);
    if (sub === 0) { // missing required body field
      const k = rng.pick(bodyKeys);
      payload = mutJson(name, p => { delete p.body[k]; });
      // reason is optional on reject; some fields may be optional
      const optionalFields = { reject: ['reason'] };
      expect = (optionalFields[name] || []).includes(k) ? 'accept' : 'missing';
      desc = 'missing body.' + k;
    } else if (sub === 1) { // unknown body field
      payload = mutJson(name, p => { p.body.zzExtra = 1; }); expect = 'unknown'; desc = 'unknown body field';
    } else if (sub === 2) { // wrong type on a body field
      const k = rng.pick(bodyKeys);
      const cur = obj.body[k];
      const repl = typeof cur === 'number' ? 'x' : (typeof cur === 'string' ? 5 : (Array.isArray(cur) ? {} : 'x'));
      payload = mutJson(name, p => { p.body[k] = repl; });
      const b64Fields = ['atomicBeef', 'requesterAdvertisement', 'providerAdvertisement', 'identityEvidence'];
      expect = typeof cur === 'number' ? 'number' : (b64Fields.includes(k) ? 'base64' : (Array.isArray(cur) ? ['format', 'number'] : 'format'));
      desc = `type body.${k}`;
    } else if (sub === 3) { // enum violations
      if (name === 'offer') { payload = mutJson(name, p => { p.body.terms.confirmationPolicy = 'two-block'; }); expect = 'format'; desc = 'confirmationPolicy enum'; }
      else if (name === 'reject') { payload = mutJson(name, p => { p.body.code = 'not-a-code'; }); expect = 'format'; desc = 'reject code enum'; }
      else { payload = mutJson(name, p => { p.body.zzExtra = 1; }); expect = 'unknown'; desc = 'enum fallback'; }
    } else if (sub === 4) { // hash field format (uppercase/short/long/non-hex)
      const hk = bodyKeys.find(k => /Hash$/.test(k) && typeof obj.body[k] === 'string');
      if (hk) {
        const bad = rng.pick([v => v.slice(0, 63), v => v + '0', v => 'g'.repeat(64), v => 'G'.repeat(64)]);
        payload = mutJson(name, p => { p.body[hk] = bad(p.body[hk]); }); expect = 'format'; desc = 'hash format ' + hk;
      } else { payload = mutJson(name, p => { p.body.zzExtra = 1; }); expect = 'unknown'; desc = 'hash fallback'; }
    } else if (sub === 5) { // numeric range / type
      if (name === 'payment') {
        const bad = rng.pick([p => { p.body.amountSats = 0; }, p => { p.body.vout = 4294967296; }, p => { p.body.amountSats = '2500'; }]);
        payload = mutJson(name, bad); expect = ['number', 'format']; desc = 'payment numeric range';
      } else if (name === 'offer') { payload = mutJson(name, p => { p.body.terms.priceSats = 0; }); expect = 'number'; desc = 'priceSats 0'; }
      else { payload = mutJson(name, p => { p.body.zzExtra = 1; }); expect = 'unknown'; desc = 'numeric fallback'; }
    } else { // text length boundaries
      if (name === 'reject') { payload = mutJson(name, p => { p.body.reason = 'a'.repeat(281); }); expect = 'text'; desc = 'reason 281'; }
      else if (name === 'deliver') { payload = mutJson(name, p => { p.body.content = 'x'.repeat(16385); }); expect = 'text'; desc = 'content 16385'; }
      else if ((name === 'requester-ad' || name === 'provider-ad') && Array.isArray(JSON.parse(canonStr(name)).body.services) && JSON.parse(canonStr(name)).body.services.length) { payload = mutJson(name, p => { p.body.services[0].kind = 'a'.repeat(129); }); expect = 'format'; desc = 'kind 129'; }
      else { payload = mutJson(name, p => { p.body.zzExtra = 1; }); expect = 'unknown'; desc = 'text fallback'; }
    }
    const ctrl = ensureControl(name, NULLOPTS, 'null');
    const id = addCase('shape', { kind: 'decode', bytes: mkBytes(name, payload, null, 'sign'), opts: NULLOPTS, expect, desc, control: ctrl,
      acceptReason: expect === 'accept' ? '§10.9: REJECT reason is optional; omitting it preserves a valid envelope.' : undefined });
    if (expect === 'accept') acceptedMutations.push(id);
  }
}

// ---------------------------------------------------------------------------
// 7. signature — range/high-S (cheap) + random/wrong-key/cross (verify).
function genSignature() {
  const N = 1200 * SCALE;
  for (let i = 0; i < N; i++) {
    const name = rng.pick(NAMES);
    const src = srcBytes(name);
    const sub = i % 5;
    let buf, expect, desc;
    if (sub === 0) { // r/s out of range (cheap range check)
      buf = Buffer.from(src);
      const which = rng.int(2); const off = which === 0 ? 21 : 53;
      const val = rng.pick([0n, secp.N, secp.N + 1n, (1n << 256n) - 1n]);
      secp.bigIntTo32(val).copy(buf, off);
      expect = which === 1 && val > secp.N / 2n ? ['signature', 'high-s'] : 'signature';
      desc = `sig ${which ? 's' : 'r'}=${val}`;
    } else if (sub === 1) { // high-S flip of valid signature
      buf = Buffer.from(src);
      const s = secp.bytesToBigInt(src.subarray(53, 85));
      secp.bigIntTo32(secp.N - s).copy(buf, 53);
      expect = 'high-s'; desc = 'high-s flip';
    } else if (sub === 2) { // random in-range r/s -> full verify fails
      buf = Buffer.from(src);
      const off = rng.int(2) === 0 ? 21 : 53;
      const val = BigInt('0x' + rng.hex(64)) % (secp.N - 1n) + 1n;
      secp.bigIntTo32(val).copy(buf, off);
      expect = ['signature', 'high-s']; desc = 'random in-range sig';
    } else if (sub === 3) { // wrong key (re-sign with other published key)
      const other = decoded[name].from.pubkey === secp.derivePubkey(k1) ? k2 : k1;
      const payload = Buffer.from(canonBuf(name));
      buf = mkBytes(name, payload, null, other);
      expect = 'signature'; desc = 'wrong signing key';
    } else { // signature from a different envelope (same header layout)
      const other = rng.pick(NAMES.filter(n => n !== name));
      buf = Buffer.from(src); srcBytes(other).subarray(21, 85).copy(buf, 21);
      expect = 'signature'; desc = 'cross-envelope signature';
    }
    const ctrl = ensureControl(name, NULLOPTS, 'null');
    addCase('signature', { kind: 'decode', bytes: buf, opts: NULLOPTS, expect, desc, control: ctrl });
  }
}

// ---------------------------------------------------------------------------
// 8. window — created/expires/future-skew + body deadline boundaries (re-signed).
function hdrTimes(hdr, created, expires) { hdr.writeUInt32BE(created >>> 0, 7); hdr.writeUInt32BE(expires >>> 0, 11); }
// Preserve the OFFER/REQUEST body chronology while changing envelope times.
// In particular, payBy and deliverBy are strict neighbours: setting both to
// expires+1 creates an unintended second `window` violation.
function mutateBodyDeadlines(p, c, e) {
  if (p.body.deliverBy !== undefined) p.body.deliverBy = Math.max(p.body.deliverBy, e + 1);
  if (p.body.terms) {
    const t = p.body.terms;
    if (t.payBy !== undefined) t.payBy = Math.max(t.payBy, e + 1, c + 2);
    if (t.acceptBefore !== undefined) {
      t.acceptBefore = Math.min(t.acceptBefore, e, t.payBy - 1);
      if (t.acceptBefore <= c && e > c) t.acceptBefore = c + 1;
    }
    if (t.deliverBy !== undefined) t.deliverBy = Math.max(t.deliverBy, t.payBy + 1, e + 2);
  }
}
function genWindow() {
  const acts = ['requester-ad', 'request', 'offer', 'accept', 'ack', 'payment', 'deliver', 'receipt', 'proof-identity', 'reject'];
  const maxWin = { 'requester-ad': 604800, request: 3600, offer: 3600, accept: 900, ack: 900, payment: 86400, deliver: 86400, receipt: 86400, 'proof-identity': 86400, reject: 86400 };
  let n = 0;
  // Deterministic boundary matrix per action.
  for (const name of acts) {
    const w = maxWin[name];
    const base = FIXTURES[name];
    const variants = [
      { c: NOW, e: NOW, expect: 'window', d: 'expires==created' },
      { c: NOW, e: NOW + w, expect: 'accept', d: 'expires==created+max' },
      { c: NOW, e: NOW + w + 1, expect: 'window', d: 'expires==created+max+1' },
      { c: NOW + 300, e: NOW + 300 + w, expect: 'accept', d: 'future skew +300' },
      { c: NOW + 301, e: NOW + 301 + w, expect: 'future', d: 'future skew +301' },
      { c: NOW - 10, e: NOW - 1, expect: 'expired', d: 'arrived after expiry' },
      { c: NOW - 10, e: NOW, expect: 'accept', d: 'arrived exactly at expiry' },
      { c: NOW, e: NOW + 1, expect: 'accept', d: 'minimal 1s window' },
    ];
    for (const v of variants) {
      const payload = mutJson(name, p => mutateBodyDeadlines(p, v.c, v.e));
      const buf = mkBytes(name, payload, h => hdrTimes(h, v.c, v.e), 'sign');
      const exp = v.expect;
      const ctrl = ensureControl(name, NULLOPTS, 'null');
      const id = addCase('window', { kind: 'decode', bytes: buf, opts: { context: null, now: NOW }, expect: exp, desc: `${name} ${v.d}`, control: ctrl });
      if (exp === 'accept') acceptedMutations.push(id);
      n++;
    }
  }
  // Task expiry cap (§8.2): deliver/receipt expires vs request deliverBy+86400.
  for (const name of ['deliver', 'receipt']) {
    for (const [c, e, expect, d] of [
      [DB, CAP, 'future', 'expires==request cap (created far future)'],
      [DB, CAP + 1, ['window', 'future'], 'expires==cap+1 (created far future; structural window checked before clock)'],
      [DB + 1, CAP + 1, 'future', 'created beyond request deliverBy'],
    ]) {
      const buf = mkBytes(name, Buffer.from(canonBuf(name)), h => hdrTimes(h, c, e), 'sign');
      const ctrl = ensureControl(name, FULLOPTS, 'full');
      const id = addCase('window', { kind: 'decode', bytes: buf, opts: { context: fullCtx, now: NOW }, expect, desc: `${name} ${d}`, control: ctrl });
      if (expect === 'accept') acceptedMutations.push(id);
      n++;
    }
    // Reach the §8.2 originating-request cap itself: omitting the receiver clock
    // bypasses future-skew rejection, while exact 86400-second envelopes bypass
    // the generic structural-window rejection. These cases fail if the cap check
    // is removed; the cases above only verify earlier rejection precedence.
    const noClock = { context: fullCtx };
    const capCtrl = ensureControl(name, noClock, 'full-no-clock');
    for (const [c, e, expect, d] of [
      [DB, CAP, 'accept', 'expires exactly at request cap without receiver clock'],
      [DB + 1, CAP + 1, 'window', 'expires beyond request cap with exact 86400s window'],
    ]) {
      const buf = mkBytes(name, Buffer.from(canonBuf(name)), h => hdrTimes(h, c, e), 'sign');
      const id = addCase('window', { kind: 'decode', bytes: buf, opts: noClock, expect, desc: `${name} ${d}`, control: capCtrl,
        acceptReason: expect === 'accept' ? '§8.2: task expiry exactly at originating request deliverBy + 86400 is valid.' : undefined });
      if (expect === 'accept') acceptedMutations.push(id);
      n++;
    }
  }
  // Randomized timestamp perturbations (re-signed), bounded count.
  const target = 500 * SCALE;
  while (n < target) {
    const name = rng.pick(acts);
    const w = maxWin[name];
    const c = NOW + rng.range(-400, 400);
    const e = c + rng.range(0, w + 5);
    let expect;
    if (e <= c) expect = 'window';
    else if (e - c > w) expect = 'window';
    else if (c > NOW + 300) expect = 'future';
    else if (NOW > e) expect = 'expired';
    else expect = 'accept';
    const payload = mutJson(name, p => mutateBodyDeadlines(p, c, e));
    const buf = mkBytes(name, payload, h => hdrTimes(h, c, e), 'sign');
    const ctrl = ensureControl(name, NULLOPTS, 'null');
    const id = addCase('window', { kind: 'decode', bytes: buf, opts: { context: null, now: NOW }, expect, desc: `${name} c=${c} e=${e}`, control: ctrl });
    if (expect === 'accept') acceptedMutations.push(id);
    n++;
  }
}

// ---------------------------------------------------------------------------
// 9. binding — replay/thread/role/parent/context (contextual).
function ctxWithout(filterFn, tag) {
  const list = Object.values(decoded).filter(filterFn);
  return { ctx: wire.makeContext(list), tag };
}
function genBinding() {
  const N = 1200 * SCALE;
  // Predefined context variants (built once, tagged for controls).
  const noAck = ctxWithout(e => e.action !== 'ACCEPT_ACK', 'no-ack');
  const noAcceptAck = ctxWithout(e => e.action !== 'ACCEPT' && e.action !== 'ACCEPT_ACK', 'no-accept-ack');
  for (let i = 0; i < N; i++) {
    const sub = i % 10;
    let bytes, opts, expect, desc, name, optsTag;
    if (sub === 0) { // accept offerHash -> wrong action (request hash)
      name = 'accept';
      bytes = mkBytes(name, mutJson(name, p => { p.body.offerHash = decoded['request'].sha256; }), null, 'sign');
      opts = FULLOPTS; optsTag = 'full'; expect = 'reference-action'; desc = 'accept offerHash->request';
    } else if (sub === 1) { // accept wrong thread
      name = 'accept';
      bytes = mkBytes(name, mutJson(name, p => { p.threadId = 'f'.repeat(32); }), null, 'sign');
      opts = FULLOPTS; optsTag = 'full'; expect = 'thread'; desc = 'accept wrong thread';
    } else if (sub === 2) { // payment without ACK
      name = 'payment'; bytes = srcBytes(name);
      opts = { context: noAck.ctx, now: NOW }; optsTag = 'no-ack'; expect = 'reference-action'; desc = 'payment without ACCEPT_ACK';
      // non-vacuity control uses full context where payment passes
    } else if (sub === 3) { // payment without ACCEPT/ACK
      name = 'payment'; bytes = srcBytes(name);
      opts = { context: noAcceptAck.ctx, now: NOW }; optsTag = 'no-accept-ack'; expect = 'reference-action'; desc = 'payment without ACCEPT/ACK';
    } else if (sub === 4) { // payment amount != price
      name = 'payment';
      bytes = mkBytes(name, mutJson(name, p => { p.body.amountSats = 2501; }), null, 'sign');
      opts = FULLOPTS; optsTag = 'full'; expect = 'number'; desc = 'payment amount!=price';
    } else if (sub === 5) { // payment to != offer provider (third party)
      name = 'payment';
      bytes = mkBytes(name, mutJson(name, p => { p.to = thirdParty; }), h => h.writeUInt32BE(wire.targetId(pub3).readUInt32BE(0), 1), 'sign');
      opts = FULLOPTS; optsTag = 'full'; expect = 'role'; desc = 'payment to third party';
    } else if (sub === 6) { // receipt paymentId != delivery
      name = 'receipt';
      bytes = mkBytes(name, mutJson(name, p => { p.body.paymentId = '5'.repeat(64) + '.0'; }), null, 'sign');
      opts = FULLOPTS; optsTag = 'full'; expect = 'reference-action'; desc = 'receipt paymentId mismatch';
    } else if (sub === 7) { // ack acceptHash -> offer (wrong action)
      name = 'ack';
      bytes = mkBytes(name, mutJson(name, p => { p.body.acceptHash = decoded['offer'].sha256; }), null, 'sign');
      opts = FULLOPTS; optsTag = 'full'; expect = 'reference-action'; desc = 'ack acceptHash->offer';
    } else if (sub === 8) { // deliver roles reversed (structurally consistent)
      name = 'deliver';
      // re-sign with new sender (requester) key:
      const payload = mutJson(name, p => { const t = p.from; p.from = p.to; p.to = t; });
      const hdr = Buffer.from(srcBytes(name).subarray(0, 21));
      const swappedTo = JSON.parse(payload.toString('utf8')).to.pubkey;
      hdr.writeUInt32BE(wire.targetId(swappedTo).readUInt32BE(0), 1);
      hdr.writeUInt16BE(payload.length, 19);
      const sig = secp.signDeterministic(k1, Buffer.concat([hdr, payload]));
      bytes = Buffer.concat([hdr, sig, payload]);
      opts = FULLOPTS; optsTag = 'full'; expect = 'role'; desc = 'deliver roles reversed';
    } else { // proof wrong subject
      name = 'proof-payment';
      bytes = mkBytes(name, mutJson(name, p => { p.body.subjectHash = '0'.repeat(64); }), null, 'sign');
      opts = FULLOPTS; optsTag = 'full'; expect = 'reference-action'; desc = 'proof wrong subject';
    }
    const ctrlTag = (sub === 2 || sub === 3) ? 'full' : optsTag;
    const ctrlOpts = (sub === 2 || sub === 3) ? FULLOPTS : opts;
    const ctrl = ensureControl(name, ctrlOpts, ctrlTag);
    addCase('binding', { kind: 'decode', bytes, opts, expect, desc, control: ctrl });
  }
  // Replay conflict (§9 rule 8): same (threadId,from,messageId) different bytes.
  for (let r = 0; r < 40 * SCALE; r++) {
    const name = rng.pick(['offer', 'accept', 'deliver']);
    // build a conflicting pair: same messageId/thread/from, different bytes
    const fx = structuredClone(FIXTURES[name]);
    const alt = structuredClone(FIXTURES[name]);
    if (alt.body.content !== undefined) alt.body.content = 'alt' + r; else if (alt.body.reason !== undefined) alt.body.reason = 'alt' + r;
    // force differing bytes via a legal free-text field where present, else timestamp
    if (alt.body.content === undefined && alt.body.reason === undefined) { alt.createdAt = fx.createdAt - 1; alt.expiresAt = fx.expiresAt - 1; }
    const e1 = wire.encodeEnvelope({ ...fx, privateKey: keyByPub[fx.from.pubkey] });
    const e2 = wire.encodeEnvelope({ ...alt, privateKey: keyByPub[alt.from.pubkey] });
    const d1 = wire.decodeEnvelope(e1.bytes, { context: null });
    const d2 = wire.decodeEnvelope(e2.bytes, { context: null });
    addCase('binding', { kind: 'context', list: [d1, d2], expect: 'conflict', desc: 'replay conflict (same id, different bytes)' });
  }
  // §9.8 positive control: an exact serialized replay is idempotent, not a conflict.
  addCase('binding', { kind: 'context', list: [decoded['offer'], decoded['offer']], expect: 'accept',
    desc: 'exact-byte replay is idempotent', acceptReason: '§9.8: an exact duplicate serialized envelope is an idempotent duplicate.' });
  // PROOF replay conflict: same (threadId,from,messageId), different bytes.
  for (let r = 0; r < 20 * SCALE; r++) {
    const pi = decoded['proof-identity'];
    const alt = wire.decodeEnvelope(mkBytes('proof-identity', mutJson('proof-identity', p => { p.body.atomicBeef = 'QUJDRA=='; }), null, 'sign'), { context: null });
    addCase('binding', { kind: 'context', list: [pi, alt], expect: 'conflict', desc: 'PROOF replay conflict (same id, different bytes)' });
  }
  // Distinct PROOF envelopes may share a subject/agentPin when messageId differs.
  // §9.8 requires exact-byte idempotency and same-(thread,sender,messageId)
  // conflict rejection; §10.8 does not impose subject-level PROOF deduplication.
  {
    const pi = decoded['proof-identity'];
    const newMid = rng.hex(32);
    const alt = wire.decodeEnvelope(mkBytes('proof-identity', mutJson('proof-identity', p => { p.body.atomicBeef = 'QUJDRA=='; p.messageId = newMid; }),
      h => Buffer.from(newMid, 'hex').copy(h, 15, 0, 4), 'sign'), { context: null });
    const id = addCase('binding', { kind: 'context', list: [pi, alt], expect: 'accept', desc: 'two identity proofs same pin, different messageId',
      acceptReason: '§9.8/§10.8: distinct messageIds are not replay conflicts; subject-level PROOF deduplication is not required.' });
    acceptedMutations.push(id);
  }
}

// ---------------------------------------------------------------------------
// 10. payment-data — PAYMENT/RECEIPT/PROOF schema using published tx fixtures.
// Minimal bounded tx DATA extraction (txid + output values); NOT tx validation.
function readVarint(buf, off) {
  const b = buf[off];
  if (b < 0xfd) return { v: b, off: off + 1 };
  if (b === 0xfd) return { v: buf.readUInt16LE(off + 1), off: off + 3 };
  if (b === 0xfe) return { v: buf.readUInt32LE(off + 1), off: off + 5 };
  return { v: Number(buf.readBigUInt64LE(off + 1)), off: off + 9 };
}
function txData(rawHex) {
  const buf = Buffer.from(rawHex, 'hex');
  if (buf.length > 1000000) throw new Error('tx too large');
  const txid = Buffer.from(secp.sha256(secp.sha256(buf))).reverse().toString('hex');
  let off = 4;
  const nin = readVarint(buf, off); off = nin.off;
  for (let i = 0; i < nin.v; i++) { off += 36; const sl = readVarint(buf, off); off = sl.off + sl.v + 4; }
  const nout = readVarint(buf, off); off = nout.off;
  const values = [];
  for (let i = 0; i < nout.v; i++) { values.push(Number(buf.readBigUInt64LE(off))); off += 8; const sl = readVarint(buf, off); off = sl.off + sl.v; }
  return { txid, values, nout: nout.v };
}
// Published payment fixtures are mandatory known answers. Missing or malformed
// data aborts the gate; it never silently disables the positive corpus.
const paymentPositive = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'vectors', 'agent_payment', 'positive.json'), 'utf8'));
if (!Array.isArray(paymentPositive.cases) || paymentPositive.cases.length === 0) throw new Error('published payment fixtures missing');
const expectedPaymentAmount = FIXTURES.payment.body.amountSats;
const PAY_FIX = paymentPositive.cases.map(c => ({ name: c.name, vout: c.vout, paymentId: c.paymentId, ...txData(c.raw) }));
function genPaymentData() {
  for (const f of PAY_FIX) {
    addCase('payment-data', { kind: 'property', desc: `published tx known answers ${f.name}`, fn: () =>
      f.txid + '.' + f.vout === f.paymentId && Number.isSafeInteger(f.values[f.vout]) && f.values[f.vout] === expectedPaymentAmount });
  }
  const N = 900 * SCALE;
  for (let i = 0; i < N; i++) {
    const sub = i % 5;
    let name, payload, expect, desc, opts = NULLOPTS, optsTag = 'null';
    if (sub === 0) { // valid published txid/vout/value known answers (null ctx) -> accept
      name = 'payment';
      const f = rng.pick(PAY_FIX);
      payload = mutJson(name, p => { p.body.txid = f.txid; p.body.vout = f.vout; p.body.amountSats = f.values[f.vout]; });
      expect = 'accept'; desc = `published tx ${f.name} schema`;
    } else if (sub === 1) { // txid format mutations
      name = 'payment';
      const bad = rng.pick([v => v.slice(0, 63), v => v + '0', v => 'g'.repeat(64), v => 'G'.repeat(64)]);
      payload = mutJson(name, p => { p.body.txid = bad(p.body.txid); }); expect = ['format', 'unknown']; desc = 'txid format';
    } else if (sub === 2) { // vout boundaries
      name = 'payment';
      const v = rng.pick([0, 4294967295, 4294967296, -1]);
      if (v === -1) { payload = rawReplace(name, '"vout":0', '"vout":-1'); expect = 'number'; }
      else { payload = mutJson(name, p => { p.body.vout = v; }); expect = (v === 0 || v === 4294967295) ? 'accept' : ['number', 'format']; }
      desc = 'vout=' + v;
    } else if (sub === 3) { // amountSats boundaries
      name = 'payment';
      const a = rng.pick([1, 9007199254740991, 0, 9007199254740992]);
      if (a === 9007199254740992) { payload = rawReplace(name, '"amountSats":2500', '"amountSats":9007199254740992'); expect = 'number'; }
      else { payload = mutJson(name, p => { p.body.amountSats = a; }); expect = a === 0 ? 'number' : 'accept'; }
      desc = 'amountSats=' + a;
    } else { // receipt paymentId format
      name = 'receipt';
      const bad = rng.pick([v => v.replace(/\.(\d+)$/, '.01'), v => v.replace(/\.(\d+)$/, '.4294967296'), v => v.replace(/[0-9a-f]/, 'g')]);
      payload = mutJson(name, p => { p.body.paymentId = bad(p.body.paymentId); }); expect = 'format'; desc = 'paymentId format';
    }
    const ctrl = ensureControl(name, opts, optsTag);
    const id = addCase('payment-data', { kind: 'decode', bytes: mkBytes(name, payload, null, 'sign'), opts, expect, desc, control: ctrl });
    if (expect === 'accept') acceptedMutations.push(id);
  }
}

// ---------------------------------------------------------------------------
// 11. encoder — encode-time rejections + roundtrip/determinism properties.
function genEncoder() {
  const N = 600 * SCALE;
  for (let i = 0; i < N; i++) {
    const name = rng.pick(NAMES);
    const sub = i % 6;
    if (sub === 0) { // negative zero
      const fx = { ...structuredClone(FIXTURES[name]), privateKey: keyByPub[FIXTURES[name].from.pubkey] };
      // find a numeric body field to set -0
      const nk = Object.keys(fx.body).find(k => typeof fx.body[k] === 'number');
      if (nk) fx.body[nk] = -0; else fx.createdAt = -0;
      addCase('encoder', { kind: 'encode', fx, expect: nk ? ['number', 'format', 'window'] : 'window', desc: 'negative zero ' + (nk || 'createdAt') });
    } else if (sub === 1) { // lone surrogate in a string field
      const fx = { ...structuredClone(FIXTURES[name]), privateKey: keyByPub[FIXTURES[name].from.pubkey] };
      const sk = Object.keys(fx.body).find(k => typeof fx.body[k] === 'string');
      if (sk) fx.body[sk] = 'x\uD800y'; else fx.threadId = 'x\uD800y';
      addCase('encoder', { kind: 'encode', fx, expect: ['noncanonical', 'format', 'base64', 'text'], desc: 'lone surrogate' });
    } else if (sub === 2) { // wrong private key for from.pubkey
      const fx = { ...structuredClone(FIXTURES[name]), privateKey: keyByPub[FIXTURES[name].from.pubkey] === k1 ? k2 : k1 };
      addCase('encoder', { kind: 'encode', fx, expect: 'signature', desc: 'wrong private key' });
    } else if (sub === 3) { // unsafe integer
      const fx = { ...structuredClone(FIXTURES[name]), privateKey: keyByPub[FIXTURES[name].from.pubkey] };
      const nk = Object.keys(fx.body).find(k => typeof fx.body[k] === 'number');
      if (nk) fx.body[nk] = 9007199254740993; else fx.createdAt = 9007199254740993;
      addCase('encoder', { kind: 'encode', fx, expect: 'number', desc: 'unsafe integer' });
    } else if (sub === 4) { // roundtrip property: encode->decode->re-encode byte-exact
      const fx = { ...structuredClone(FIXTURES[name]), privateKey: keyByPub[FIXTURES[name].from.pubkey] };
      addCase('encoder', { kind: 'property', desc: 'roundtrip byte-exact ' + name, fn: () => {
        const e1 = wire.encodeEnvelope(fx);
        const d = wire.decodeEnvelope(e1.bytes, { context: null });
        const e2 = wire.encodeEnvelope({ action: d.action, createdAt: d.createdAt, expiresAt: d.expiresAt, messageId: d.messageId, threadId: d.threadId, from: d.from, to: d.to, body: d.body, privateKey: keyByPub[d.from.pubkey] });
        return e1.bytes.equals(e2.bytes) && e1.sha256 === e2.sha256;
      }});
    } else { // determinism: same fixture twice -> identical bytes (RFC6979)
      const fx = { ...structuredClone(FIXTURES[name]), privateKey: keyByPub[FIXTURES[name].from.pubkey] };
      addCase('encoder', { kind: 'property', desc: 'RFC6979 determinism ' + name, fn: () => {
        const a = wire.encodeEnvelope(fx); const b = wire.encodeEnvelope(fx);
        return a.bytes.equals(b.bytes) && a.signatureHex === b.signatureHex;
      }});
    }
  }
}

// ---------------------------------------------------------------------------
// 12. property — cross-cutting cheap invariants + bounded encode roundtrips.
function genProperty() {
  const N = 2200 * SCALE;
  for (let i = 0; i < N; i++) {
    const sub = i % 8;
    if (sub === 0) { // JCS idempotence on random canonical objects
      addCase('property', { kind: 'property', desc: 'JCS idempotence', fn: () => {
        const o = { b: rng.int(1000), a: rng.hex(8), z: [rng.int(5), rng.int(5)] };
        const c = jcs.canonicalBytes(o);
        const back = jcs.parseCanonical(c);
        return jcs.canonicalBytes(back).equals(c);
      }});
    } else if (sub === 1) { // base64 canonical roundtrip
      addCase('property', { kind: 'property', desc: 'base64 roundtrip', fn: () => {
        const b = rng.bytes(rng.range(1, 48));
        const s = b.toString('base64');
        try { wire.checkBase64(s, '$'); return Buffer.from(s, 'base64').equals(b); } catch (_) { return false; }
      }});
    } else if (sub === 2) { // base58 roundtrip
      addCase('property', { kind: 'property', desc: 'base58 roundtrip', fn: () => {
        const b = rng.bytes(rng.range(1, 30));
        return wire.b58decode(wire.b58encode(b)).equals(b);
      }});
    } else if (sub === 3) { // low-S predicate vs BigInt comparison (no verify)
      addCase('property', { kind: 'property', desc: 'low-S predicate consistency', fn: () => {
        const s = BigInt('0x' + rng.hex(64));
        const buf = Buffer.concat([rng.bytes(32), secp.bigIntTo32(s % secp.N)]);
        const expectLow = (s % secp.N) <= secp.N / 2n && (s % secp.N) > 0n;
        try { return secp.isLowS(buf) === ((s % secp.N) <= secp.N / 2n); } catch (_) { return false; }
      }});
    } else if (sub === 4) { // targetId derivation consistency
      addCase('property', { kind: 'property', desc: 'targetId consistency', fn: () => {
        const pub = rng.pick([secp.derivePubkey(k1), secp.derivePubkey(k2), pub3]);
        const t = wire.targetId(pub);
        return t.length === 4 && t.equals(wire.targetId(pub));
      }});
    } else if (sub === 5) { // address derivation matches published vectors
      addCase('property', { kind: 'property', desc: 'address derivation KAT', fn: () => {
        return wire.deriveAddress(secp.derivePubkey(k1)) === '1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH'
          && wire.deriveAddress(secp.derivePubkey(k2)) === '1cMh228HTCiwS8ZsaakH8A8wze1JR5ZsP';
      }});
    } else if (sub === 6) { // decode(encode(fx)) semantics equal fx (normalized)
      const name = rng.pick(NAMES);
      addCase('property', { kind: 'property', desc: 'encode/decode semantic equality ' + name, fn: () => {
        const fx = { ...structuredClone(FIXTURES[name]), privateKey: keyByPub[FIXTURES[name].from.pubkey] };
        const e = wire.encodeEnvelope(fx);
        const d = wire.decodeEnvelope(e.bytes, { context: null });
        const norm = JSON.parse(JSON.stringify({ action: d.action, createdAt: d.createdAt, expiresAt: d.expiresAt, messageId: d.messageId, threadId: d.threadId, from: d.from, to: d.to, body: d.body }));
        return JSON.stringify(norm) === JSON.stringify(FIXTURES[name]);
      }});
    } else { // sha256 stability of published envelopes
      const name = rng.pick(NAMES);
      addCase('property', { kind: 'property', desc: 'sha256 stability ' + name, fn: () => {
        return secp.sha256(srcBytes(name)).toString('hex') === posByName[name].sha256;
      }});
    }
  }
}

// ---------------------------------------------------------------------------
// Execute all cases.
genFrame(); genJson(); genUtf8(); genIdentity(); genBase64(); genShape();
genSignature(); genWindow(); genBinding(); genPaymentData(); genEncoder(); genProperty();

const byClass = {}, byLayer = {}, byCode = {};
let passed = 0, failed = 0, accepted = 0, rejected = 0, errors = 0;
const rows = []; // compact manifest rows: [classIdx, expectIdx, gotIdx, okBit]
const expectLegend = ['accept', ...CODES, 'PROPERTY', 'ERROR'];
const failures = [];

function idxOf(arr, v) {
  const i = arr.indexOf(v);
  if (i < 0) throw new Error('unmapped manifest category: ' + String(v));
  return i;
}

for (const c of cases) {
  byClass[c.cls] = (byClass[c.cls] || 0) + 1;
  let outcome, code = null;
  try {
    if (c.kind === 'decode') { wire.decodeEnvelope(c.bytes, c.opts); outcome = 'accept'; }
    else if (c.kind === 'encode') {
      const o = wire.encodeEnvelope(c.fx); outcome = 'accept';
      if (c.expectHash && o.sha256 !== c.expectHash) { outcome = 'reject'; code = 'HASH-MISMATCH'; }
    }
    else if (c.kind === 'context') { wire.makeContext(c.list); outcome = 'accept'; }
    else if (c.kind === 'property') { outcome = c.fn() ? 'accept' : 'PROPERTY-FAIL'; if (outcome !== 'accept') code = 'PROPERTY-FAIL'; }
  } catch (e) {
    if (e instanceof wire.WireError) { outcome = 'reject'; code = e.code; }
    else if (e instanceof jcs.JsonError) { outcome = 'reject'; code = 'noncanonical'; }
    else { outcome = 'ERROR'; code = 'UNEXPECTED:' + (e && e.message); }
  }
  // Determine pass/fail against expectation.
  let ok;
  const exp = c.expect;
  if (outcome === 'ERROR') ok = false;
  else if (exp === 'accept' || (c.kind === 'property' && exp === undefined)) ok = outcome === 'accept';
  else if (outcome === 'accept') ok = false;
  else {
    const want = Array.isArray(exp) ? exp : [exp];
    ok = want.includes(code);
  }
  if (outcome === 'accept') accepted++;
  else if (outcome === 'reject') { rejected++; byCode[code] = (byCode[code] || 0) + 1; const ly = LAYER_OF[code]; if (ly) byLayer[ly] = (byLayer[ly] || 0) + 1; }
  else errors++;
  if (ok) passed++; else { failed++; failures.push({ id: c.id, cls: c.cls, desc: c.desc, expect: exp, got: outcome === 'accept' ? 'ACCEPTED' : code }); }
  // manifest row: unknown categories fail closed rather than masquerading as ERROR.
  const expIdx = c.kind === 'property' ? idxOf(expectLegend, 'PROPERTY') :
    exp === 'accept' ? 0 : idxOf(expectLegend, Array.isArray(exp) ? exp[0] : exp);
  const gotIdx = outcome === 'accept' ? 0 : outcome === 'ERROR' ? idxOf(expectLegend, 'ERROR') :
    outcome === 'PROPERTY-FAIL' ? idxOf(expectLegend, 'PROPERTY') : idxOf(expectLegend, code);
  rows.push([CLASSES.indexOf(c.cls), expIdx, gotIdx, ok ? 1 : 0]);
  if (outcome === 'accept' && c.acceptReason) {
    findings.push({ id: c.id, cls: c.cls, desc: c.desc, classification: c.acceptReason });
  }
}

// ---------------------------------------------------------------------------
// Manifest (compact, deterministic). Raw bytes are NOT committed; optional --raw.
const manifest = {
  scope: 'BMP-0005 R3.1 independent adversarial conformance + fuzz (wire/JSON/signature/address/target/binding/window/schema). No SPV/BEEF/payment-shape/live/Stable claims.',
  seed: SEED,
  mode: NIGHTLY ? 'nightly' : 'default',
  independence: 'spec/BMP-0005 + published poc/vectors JSON + Qwen poc/agent_independent only; no reference source/tests read or invoked',
  caseIdScheme: '<class>-<5-digit seq> in deterministic generation order; class order: ' + CLASSES.join(','),
  totals: { cases: cases.length, passed, failed, accepted, rejected, unexpectedErrors: errors, controls: controlCount },
  coverage: { byClass, byLayer, byCode },
  expectLegend,
  classLegend: CLASSES,
  acceptedMutationCount: acceptedMutations.length,
  findings,
  failures,
  rows,
};
const manifestBytes = Buffer.from(JSON.stringify(manifest));
fs.writeFileSync(path.join(__dirname, 'fuzz_manifest.json'), manifestBytes);
const manifestHash = secp.sha256(manifestBytes).toString('hex');

if (RAW) {
  const rawDir = path.join(__dirname, 'fuzz_raw');
  fs.mkdirSync(rawDir, { recursive: true });
  const rawRows = [];
  for (const c of cases) {
    if (c.kind === 'decode') rawRows.push({ id: c.id, cls: c.cls, hex: c.bytes.toString('hex'), now: c.opts.now ?? null, ctx: c.opts.context ? true : false, expect: c.expect });
  }
  fs.writeFileSync(path.join(rawDir, 'corpus.json'), JSON.stringify(rawRows));
}

// ---------------------------------------------------------------------------
// Deterministic stdout (no wall-clock).
console.log('BMP-0005 Q3 independent fuzz/conformance');
console.log('seed=0x' + SEED.toString(16) + ' mode=' + (NIGHTLY ? 'nightly' : 'default'));
console.log('cases=' + cases.length + ' passed=' + passed + ' failed=' + failed + ' accepted=' + accepted + ' rejected=' + rejected + ' unexpectedErrors=' + errors + ' controls=' + controlCount);
console.log('coverage.byClass=' + JSON.stringify(byClass));
console.log('coverage.byLayer=' + JSON.stringify(byLayer));
console.log('acceptedMutations=' + acceptedMutations.length + ' findings=' + findings.length);
console.log('manifest sha256: ' + manifestHash);
if (failures.length) {
  console.log('FAILURES (' + failures.length + '):');
  for (const f of failures.slice(0, 60)) console.log('  ' + f.id + ' [' + f.cls + '] ' + f.desc + ' expect=' + JSON.stringify(f.expect) + ' got=' + f.got);
  if (failures.length > 60) console.log('  ... ' + (failures.length - 60) + ' more');
  console.log('FAILURES PRESENT');
  process.exit(1);
}
console.log('ALL PASS');
