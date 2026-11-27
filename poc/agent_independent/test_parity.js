'use strict';
// Independent BMP-0005 parity + adversarial suite (Q1R corrected).
// Run: node test_parity.js
// Reads only the published JSON vectors plus the literal semantic fixtures in
// fixtures_semantic.json (semantic fields of each published envelope, recorded
// once from the published bytes; the encoder reproduces every golden envelope
// from those literal inputs, not from decoder output). Writes a deterministic
// manifest (manifest.json) for the twice-run gate.
// Offline only: no network, no wallets, no funded transactions. Signing uses
// published test keys exclusively. The BigInt signer is variable-time and does
// not zeroize secrets — PoC only, never production (see secp256k1.js).

const fs = require('fs');
const path = require('path');
const assert = require('assert');
const wire = require('./wire.js');
const secp = require('./secp256k1.js');
const jcs = require('./jcs.js');

const VEC = path.join(__dirname, '..', 'vectors', 'agent');
const positive = JSON.parse(fs.readFileSync(path.join(VEC, 'positive.json'), 'utf8'));
const negative = JSON.parse(fs.readFileSync(path.join(VEC, 'negative.json'), 'utf8'));
const FIXTURES = JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures_semantic.json'), 'utf8'));
const NOW = positive.now;
// positive.cases is keyed by case name; negative.json is a bare array.
const posCases = Object.entries(positive.cases).map(([name, c]) => ({ name, ...c }));
const negCases = Array.isArray(negative) ? negative : negative.cases;

const manifest = {
  scope: 'BMP-0005 R3 wire/JSON/signature/address/target parity (no PAID/SPV/live/Stable claims)',
  now: NOW,
  positives: [],
  negatives: [],
  probes: [],
};

let pass = 0, failed = 0;
function ok(cond, label) {
  if (cond) { pass++; }
  else { failed++; console.log(`FAIL: ${label}`); }
}
function deepEq(a, b) { try { assert.deepStrictEqual(a, b); return true; } catch (_) { return false; } }

const keyByPub = {};
for (const k of positive.publishedTestPrivateKeys) keyByPub[secp.derivePubkey(k)] = k;
const posByName = {};
for (const c of posCases) posByName[c.name] = c;
const srcBytes = name => Buffer.from(posByName[name].envelopeHex, 'hex');

// ---------------------------------------------------------------------------
console.log('== A. secp256k1 / RFC6979 known-answer + cross-verifier ==');
const k1 = '0000000000000000000000000000000000000000000000000000000000000001';
const k2 = '0000000000000000000000000000000000000000000000000000000000000002';
ok(secp.derivePubkey(k1) === '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798', 'derivePubkey(1) = G');
ok(secp.derivePubkey(k2) === '02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5', 'derivePubkey(2) = 2G');
ok(wire.targetId(secp.derivePubkey(k1)).toString('hex') === '60604559', 'target derivation pubkey(1)');
ok(wire.targetId(secp.derivePubkey(k2)).toString('hex') === '13e5b3b1', 'target derivation pubkey(2)');
ok(wire.deriveAddress(secp.derivePubkey(k1)) === '1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH', 'address(1)');
ok(wire.deriveAddress(secp.derivePubkey(k2)) === '1cMh228HTCiwS8ZsaakH8A8wze1JR5ZsP', 'address(2)');
const msg = Buffer.from('BMP-0005 deterministic signing probe');
const s1 = secp.signDeterministic(k1, msg);
const s1again = secp.signDeterministic(k1, msg);
ok(s1.equals(s1again), 'RFC6979 determinism (same bytes twice)');
ok(secp.isLowS(s1), 'signature low-s (full 64-byte r||s)');
ok(secp.verifySignature(secp.derivePubkey(k1), msg, s1), 'self-verify signature');
ok(secp.opensslVerify(secp.derivePubkey(k1), msg, s1), 'OpenSSL verifies our RFC6979 signature');
// --- Q2R item 6: low-S predicate is length-strict and non-vacuous ---
{
  const lowThrows = fn => { try { fn(); return false; } catch (_) { return true; } };
  ok(lowThrows(() => secp.isLowS(s1.subarray(32))), 'item6: 32-byte input rejected (not vacuously low)');
  ok(lowThrows(() => secp.isLowS(s1.subarray(0, 63))), 'item6: 63-byte input rejected');
  ok(lowThrows(() => secp.isLowS(Buffer.concat([s1, Buffer.from([0])]))), 'item6: 65-byte input rejected');
  ok(lowThrows(() => secp.isLowS(Buffer.alloc(0))), 'item6: empty input rejected');
  const lowKat = Buffer.concat([Buffer.alloc(32, 0xab), secp.bigIntTo32(1n)]);
  ok(secp.isLowS(lowKat) === true, 'item6: KAT s=1 low-S accepted');
  const highKat = Buffer.concat([Buffer.alloc(32, 0xab), secp.bigIntTo32(secp.N - 1n)]);
  ok(secp.isLowS(highKat) === false, 'item6: KAT s=N-1 high-S rejected');
  ok(secp.isLowS(s1) === true, 'item6: real RFC6979 signature is low-S');
}
const osslSig = secp.opensslSignRandomK(k2, msg);
ok(secp.verifySignature(secp.derivePubkey(k2), msg, osslSig), 'we verify OpenSSL random-k signature');
ok(!secp.verifySignature(secp.derivePubkey(k2), Buffer.from('tampered'), osslSig), 'tampered message rejected');
ok(!secp.isOnCurve('02' + 'ff'.repeat(32)), 'x >= field prime rejected');
ok(!secp.isOnCurve('04' + '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'), 'uncompressed prefix rejected');
// Fixed RFC6979 known-answer (private key 1, message "Satoshi Nakamoto"),
// cross-checked against an independent pure-Python RFC6979 implementation.
const katSig = secp.signDeterministic(k1, Buffer.from('Satoshi Nakamoto'));
ok(katSig.toString('hex') ===
  '934b1ea10a4b3c1757e2b0c017d0b6143ce3c9a7e6a4a49860d7a6ab210ee3d8' +
  '2442ce9d2b916064108014783e923ec36b49743e2ffa1c4496f01a512aafd9e5',
  'RFC6979 fixed KAT r||s (key 1, "Satoshi Nakamoto")');
ok(secp.opensslVerify(secp.derivePubkey(k1), Buffer.from('Satoshi Nakamoto'), katSig), 'OpenSSL verifies fixed KAT signature');
// Q2R item 6 (review): direct isLowS low/high assertions on the FIXED RFC6979
// KAT signature and its high-S counterpart (full 64-byte buffers).
ok(secp.isLowS(katSig) === true, 'item6: fixed RFC6979 KAT signature is low-S (full 64 bytes)');
const katHighS = Buffer.concat([katSig.subarray(0, 32), secp.bigIntTo32(secp.N - secp.bytesToBigInt(katSig.subarray(32, 64)))]);
ok(secp.isLowS(katHighS) === false, 'item6: fixed KAT high-S counterpart rejected');

// ---------------------------------------------------------------------------
console.log('== A2. JCS / Base64 / Base58 / outpoint boundary units ==');
const chain = n => { let o = { v: 1 }; for (let i = 0; i < n; i++) o = { c: o }; return o; };
ok(jcs.jcsSerialize(chain(63)).length > 0, 'JCS depth 64 accepted');
let depthThrew = false;
try { jcs.jcsSerialize(chain(64)); } catch (e) { depthThrew = e instanceof jcs.JsonError; }
ok(depthThrew, 'JCS depth 65 rejected');
const jcsThrows = fn => { try { fn(); return false; } catch (e) { return e instanceof jcs.JsonError; } };
// Positive/negative boundary controls at the canonical-JSON layer (typed
// envelope bodies cannot legally nest this deep, so the boundary is tested
// where §5.4 enforces it): 64 levels parse, 65 do not.
let parseDepth64ok = true;
try { jcs.parseCanonical(jcs.canonicalBytes(chain(63))); } catch (_) { parseDepth64ok = false; }
ok(parseDepth64ok, 'parseCanonical depth 64 accepted');
ok(jcsThrows(() => jcs.parseCanonical(Buffer.from(JSON.stringify(chain(64)), 'utf8'))), 'parseCanonical depth 65 rejected');
ok(jcsThrows(() => jcs.jcsSerialize(-0)), 'JCS rejects negative zero');
ok(jcsThrows(() => jcs.jcsSerialize('x\uD800y')), 'JCS rejects lone high surrogate');
ok(jcsThrows(() => jcs.jcsSerialize('x\uDC00y')), 'JCS rejects lone low surrogate');
ok(jcs.jcsSerialize('🚀') === '"🚀"', 'JCS surrogate pair (astral) round-trips');
// UTF-16 code-unit key order: U+10000 (astral) sorts before U+E000 (BMP).
ok(jcs.jcsSerialize({ '\uE000': 1, '\u{10000}': 2 }) === '{"' + '\u{10000}' + '":2,"' + '\uE000' + '":1}', 'JCS UTF-16 key order (astral before BMP U+E000)');
ok(jcs.jcsSerialize({ b: 1, a: 2 }) === '{"a":2,"b":1}', 'JCS key sort');
ok(jcs.jcsSerialize({ z: 'é', a: '\n' }) === '{"a":"\\n","z":"é"}', 'JCS escapes/non-ASCII literal');
const b64Throws = s => { try { wire.checkBase64(s, '$'); return false; } catch (e) { return e instanceof wire.WireError && e.code === 'base64'; } };
ok(b64Throws(''), 'Base64 empty rejected');
ok(b64Throws('A'), 'Base64 length%4==1 rejected');
ok(b64Throws('AB'), 'Base64 unpadded rejected');
ok(b64Throws('A==='), 'Base64 excess padding rejected');
ok(b64Throws('AB=C'), 'Base64 interior padding rejected');
ok(b64Throws('aa=='), 'Base64 nonzero pad bits rejected');
ok(b64Throws('AAB'), 'Base64 3-char unpadded rejected');
ok(!b64Throws('QUJD'), 'Base64 no-pad-needed canonical accepted');
ok(!b64Throws('QQ==') && !b64Throws('QUI=') && !b64Throws('QUJD'), 'Base64 canonical forms accepted');
const pinOk = s => { try { wire.checkPin(s, '$'); return true; } catch (_) { return false; } };
ok(pinOk('a'.repeat(64) + '.0'), 'outpoint vout 0 accepted');
ok(pinOk('a'.repeat(64) + '.4294967295'), 'outpoint vout uint32 max accepted');
ok(!pinOk('a'.repeat(64) + '.4294967296'), 'outpoint vout beyond uint32 rejected');
ok(!pinOk('a'.repeat(64) + '.01'), 'outpoint leading zero rejected');
ok(!pinOk('a'.repeat(64) + '.-1'), 'outpoint negative rejected');
ok(!pinOk('A'.repeat(64) + '.0'), 'outpoint uppercase txid rejected');
// Base58 units (resource bound + leading zeros + alphabet).
const b25 = Buffer.from('000102030405060708090a0b0c0d0e0f101112131415161718', 'hex');
ok(wire.b58decode(wire.b58encode(b25)).equals(b25), 'Base58 roundtrip 25 bytes');
ok(wire.b58encode(Buffer.from('0000deadbeef', 'hex')).startsWith('11'), 'Base58 leading zero bytes -> 1s');
ok(wire.b58decode(wire.b58encode(Buffer.from('0000deadbeef', 'hex'))).equals(Buffer.from('0000deadbeef', 'hex')), 'Base58 leading-zero roundtrip');
ok(wire.b58decode('0OIl') === null, 'Base58 invalid alphabet chars rejected');
ok(wire.b58decode('') === null, 'Base58 empty rejected');
ok(wire.b58decode('1'.repeat(65)) === null, 'Base58 65-char string rejected before BigInt (resource bound)');
ok(wire.b58decode('1'.repeat(64)).length === 64, 'Base58 64-char boundary decodes (no superlinear work)');
const addrPayload = wire.b58decode('1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH');
ok(addrPayload && addrPayload.length === 25 && addrPayload[0] === 0x00, 'Base58 known mainnet address payload');

// ---------------------------------------------------------------------------
console.log('== B. positive golden vectors: literal semantic fixtures reproduce bytes ==');
ok(Object.keys(FIXTURES).length === 12, 'literal semantic fixtures cover all 12 cases');
let posTotal = 0, posSemExact = 0, posRtExact = 0;
const decoded = {};
for (const c of posCases) {
  const buf = srcBytes(c.name);
  const d = wire.decodeEnvelope(buf, { context: null, now: NOW });
  ok(d.sha256 === c.sha256, `${c.name}: envelope sha256 matches published`);
  ok(d.action === c.action && d.messageId === c.messageId, `${c.name}: decoded action/messageId match published metadata`);
  ok(secp.opensslVerify(d.from.pubkey, Buffer.concat([buf.subarray(0, 21), buf.subarray(85)]), Buffer.from(d.signatureHex, 'hex')),
    `${c.name}: OpenSSL verifies envelope signature`);
  decoded[c.name] = d;
}
const fullCtx = wire.makeContext(Object.values(decoded));
for (const c of posCases) {
  const buf = srcBytes(c.name);
  const d = wire.decodeEnvelope(buf, { context: fullCtx, now: NOW });
  ok(d.sha256 === c.sha256, `${c.name}: full-context decode sha256`);
  ok(d.action === c.action && d.messageId === c.messageId, `${c.name}: full-context action/messageId match published metadata`);
  // The literal semantic fixture must equal the decoded semantics of the
  // published bytes (ties the committed fixture to the published vector).
  // JSON-normalize both sides: the parser returns null-prototype objects.
  const sem = FIXTURES[c.name];
  ok(deepEq(JSON.parse(JSON.stringify({ action: d.action, createdAt: d.createdAt, expiresAt: d.expiresAt, messageId: d.messageId, threadId: d.threadId, from: d.from, to: d.to, body: d.body })), sem),
    `${c.name}: literal semantic fixture equals decoded semantics`);
  // Semantic reproduction: encode from the LITERAL fixture inputs only.
  const encSem = wire.encodeEnvelope({ ...structuredClone(sem), privateKey: keyByPub[sem.from.pubkey] });
  const semByteExact = encSem.bytes.equals(buf);
  ok(semByteExact, `${c.name}: semantic fixture re-encode byte-exact`);
  ok(encSem.sha256 === c.sha256, `${c.name}: semantic fixture re-encode sha256 match`);
  ok(encSem.signatureHex === d.signatureHex, `${c.name}: semantic fixture re-encode signature byte-exact`);
  // Decode->encode roundtrip (distinct claim: re-encode of decoder output).
  const encRt = wire.encodeEnvelope({ action: d.action, createdAt: d.createdAt, expiresAt: d.expiresAt, messageId: d.messageId, threadId: d.threadId, from: d.from, to: d.to, body: d.body, privateKey: keyByPub[d.from.pubkey] });
  const rtByteExact = encRt.bytes.equals(buf);
  ok(rtByteExact, `${c.name}: decode->encode roundtrip byte-exact`);
  // Item 7 (review): success counts derive from OBSERVED comparisons, never
  // from container length — a forced failure must print a failing count.
  posTotal++;
  if (semByteExact) posSemExact++;
  if (rtByteExact) posRtExact++;
  manifestPushPositive(c, encSem, semByteExact, rtByteExact);
}
function manifestPushPositive(c, enc, semReproduced, rtRoundtrip) {
  manifest.positives.push({ name: c.name, action: c.action, messageId: c.messageId, sha256: enc.sha256, hex: enc.bytes.toString('hex'), semanticFixtureReproduced: semReproduced, decodeEncodeRoundtrip: rtRoundtrip });
}

// ---------------------------------------------------------------------------
console.log('== C. negative mutations: all must be rejected with matching category ==');
let negRejected = 0, negCodeMatch = 0;
for (const neg of negCases) {
  // Published mutation models: splice `remove` bytes at `offset` and insert
  // insertHex, or append `appendZeroes` zero bytes; decode with the published
  // per-case now/context settings.
  const src = Buffer.from(posByName[neg.source].envelopeHex, 'hex');
  let buf;
  if (neg.appendZeroes !== undefined) {
    buf = Buffer.concat([src, Buffer.alloc(neg.appendZeroes)]);
  } else {
    const ins = Buffer.from(neg.insertHex, 'hex');
    buf = Buffer.concat([src.subarray(0, neg.offset), ins, src.subarray(neg.offset + neg.remove)]);
  }
  let err = null;
  try { wire.decodeEnvelope(buf, { context: neg.context ? fullCtx : null, now: neg.now }); } catch (e) { err = e; }
  const rejected = err instanceof wire.WireError;
  if (rejected) negRejected++;
  const match = rejected && err.code === neg.code;
  if (match) negCodeMatch++;
  ok(rejected, `negative[${neg.name}] rejected`);
  // Item 13: category mismatch is a HARD failure, not a note.
  ok(match, `negative[${neg.name}] category match: published=${neg.code} got=${rejected ? err.code : 'ACCEPTED'}`);
  manifest.negatives.push({ name: neg.name, source: neg.source, publishedCode: neg.code, publishedPath: neg.path, outcome: rejected ? 'reject' : 'ACCEPTED', code: rejected ? err.code : null, path: rejected ? err.path : null });
}

// ---------------------------------------------------------------------------
console.log('== D. edge / false-accept probes (validly re-signed where noted) ==');
const noClock = { context: null };
let probeCount = 0;
function probe(label, bytes, expectCode, opts) {
  probeCount++;
  let err = null;
  try { wire.decodeEnvelope(bytes, opts || { context: null, now: NOW }); } catch (e) { err = e; }
  const want = Array.isArray(expectCode) ? expectCode : [expectCode];
  const good = expectCode === null ? err === null : err instanceof wire.WireError && want.includes(err.code);
  ok(good, `probe ${label}: expected ${expectCode}, got ${err ? err.code + ' ' + err.message : 'accept'}`);
  manifest.probes.push({ label, outcome: err ? 'reject' : 'accept', code: err ? err.code : null, expected: expectCode });
}
const canonBuf = name => srcBytes(name).subarray(85);
const canonStr = name => canonBuf(name).toString('utf8');
const chainText = n => '{"c":'.repeat(n) + '{"v":1}' + '}'.repeat(n);
// Byte-level splice into a payload string field (injects bytes that JS
// string->Buffer conversion would silently normalize, e.g. lone surrogates).
function splicePayload(name, needleStr, replacementBuf) {
  const pb = Buffer.from(canonBuf(name));
  const needle = Buffer.from(needleStr, 'utf8');
  const i = pb.indexOf(needle);
  if (i < 0) throw new Error('splice anchor missing: ' + needleStr);
  return Buffer.concat([pb.subarray(0, i), replacementBuf, pb.subarray(i + needle.length)]);
}
function rebuild(name, payloadBytes, hdrEdit, signerPub) {
  const src = srcBytes(name);
  const hdr = Buffer.from(src.subarray(0, 21));
  if (hdrEdit) hdrEdit(hdr);
  hdr.writeUInt16BE(payloadBytes.length, 19);
  const d = wire.decodeEnvelope(src, { context: null });
  // signerPub lets role-reversal probes re-sign with the NEW sender's key.
  const sig = secp.signDeterministic(keyByPub[signerPub || d.from.pubkey], Buffer.concat([hdr, payloadBytes]));
  return Buffer.concat([hdr, sig, payloadBytes]);
}
const mutate = (name, fn) => { const p = JSON.parse(canonStr(name)); fn(p); return Buffer.from(jcs.jcsSerialize(p), 'utf8'); };

// --- original edge battery (kept) ---
probe('uppercase hex hash', rebuild('accept', mutate('accept', p => { p.body.offerHash = p.body.offerHash.toUpperCase(); })), 'format');
probe('uppercase hex txid', rebuild('payment', mutate('payment', p => { p.body.txid = 'A' + p.body.txid.slice(1); })), 'format');
probe('pin leading-zero vout', rebuild('receipt', mutate('receipt', p => { p.body.paymentId = p.body.paymentId.replace('.0', '.00'); })), 'format');
probe('pin negative vout', rebuild('receipt', mutate('receipt', p => { p.body.paymentId = p.body.paymentId.replace('.0', '.-1'); })), 'format');
probe('pin vout overflow', rebuild('receipt', mutate('receipt', p => { p.body.paymentId = p.body.paymentId.replace('.0', '.4294967296'); })), 'format');
probe('float number', rebuild('payment', Buffer.from(canonStr('payment').replace('"amountSats":2500', '"amountSats":1.5'), 'utf8')), 'number');
probe('exponent number', rebuild('payment', Buffer.from(canonStr('payment').replace('"amountSats":2500', '"amountSats":2.5e3'), 'utf8')), 'number');
probe('negative zero', rebuild('payment', Buffer.from(canonStr('payment').replace('"vout":0', '"vout":-0'), 'utf8')), 'number');
probe('unsafe integer', rebuild('payment', Buffer.from(canonStr('payment').replace('"amountSats":2500', '"amountSats":9007199254740993'), 'utf8')), 'number');
probe('payload nesting depth 65 rejected', rebuild('accept', Buffer.from(canonStr('accept').replace(/"body":\{[^{}]*\}/, '"body":' + chainText(63)), 'utf8')), 'noncanonical');
probe('duplicate key', rebuild('accept', Buffer.from(canonStr('accept').replace('"body":{', '"body":{"offerHash":"x",'), 'utf8')), 'duplicate');
probe('lone surrogate (invalid UTF-8 bytes)', rebuild('deliver', splicePayload('deliver', 'text/markdown', Buffer.concat([Buffer.from('text/mark'), Buffer.from([0xed, 0xa0, 0x80]), Buffer.from('down')]))), 'noncanonical');
probe('raw control char', rebuild('deliver', splicePayload('deliver', 'text/markdown', Buffer.concat([Buffer.from('text/mark'), Buffer.from([0x0a]), Buffer.from('down')]))), 'noncanonical');
probe('bad escape', rebuild('deliver', splicePayload('deliver', 'text/markdown', Buffer.from('text/mark\\qdown'))), 'noncanonical');
// DELIVER content is raw UTF-8 text (§10.6), NOT base64; base64 canonicality
// probes target identityEvidence (ADVERTISE) and atomicBeef (PAYMENT/PROOF).
probe('unpadded base64', rebuild('requester-ad', mutate('requester-ad', p => { p.from.identityEvidence = 'QUI'; })), 'base64');
probe('nonzero pad bits', rebuild('requester-ad', mutate('requester-ad', p => { p.from.identityEvidence = 'QR=='; })), 'base64');
probe('empty base64', rebuild('requester-ad', mutate('requester-ad', p => { p.from.identityEvidence = ''; })), 'base64');
probe('base64url chars', rebuild('requester-ad', mutate('requester-ad', p => { p.from.identityEvidence = 'ab-_'; })), 'base64');
probe('deliver content over 16384 bytes', rebuild('deliver', mutate('deliver', p => { p.body.content = 'x'.repeat(16385); })), 'text');
probe('deliver content exactly 16384 bytes accepted (boundary)', rebuild('deliver', mutate('deliver', p => { p.body.content = 'x'.repeat(16384); })), null);
probe('mime uppercase', rebuild('deliver', mutate('deliver', p => { p.body.mime = 'Text/Markdown'; })), 'format');
probe('mime over 100 bytes', rebuild('deliver', mutate('deliver', p => { p.body.mime = 'text/' + 'a'.repeat(96); })), 'format');
probe('endpoint http', rebuild('provider-ad', mutate('provider-ad', p => { p.body.endpoint = 'http://provider.example/x'; })), 'format');
probe('endpoint userinfo', rebuild('provider-ad', mutate('provider-ad', p => { p.body.endpoint = 'https://user@provider.example/x'; })), 'format');
probe('endpoint fragment', rebuild('provider-ad', mutate('provider-ad', p => { p.body.endpoint = 'https://provider.example/x#f'; })), 'format');
probe('endpoint query accepted', rebuild('provider-ad', mutate('provider-ad', p => { p.body.endpoint = 'https://provider.example/x?q=1'; })), null);
probe('reason newline', rebuild('reject', mutate('reject', p => { p.body.reason = 'a\nb'; })), 'text');
probe('reason 281 bytes', rebuild('reject', mutate('reject', p => { p.body.reason = 'a'.repeat(281); })), 'text');
probe('reason 280 bytes accepted', rebuild('reject', mutate('reject', p => { p.body.reason = 'a'.repeat(280); })), null);
probe('Expires_At == Created_At', rebuild('accept', Buffer.from(canonBuf('accept')), hdr => hdr.writeUInt32BE(NOW, 11)), 'window');
probe('ACCEPT window 901s', rebuild('accept', Buffer.from(canonBuf('accept')), hdr => hdr.writeUInt32BE(NOW + 901, 11)), 'window');
probe('ACCEPT window 900s accepted', rebuild('accept', Buffer.from(canonBuf('accept')), hdr => hdr.writeUInt32BE(NOW + 900, 11)), null);
probe('future skew +301', rebuild('accept', Buffer.from(canonBuf('accept')), hdr => { hdr.writeUInt32BE(NOW + 301, 7); hdr.writeUInt32BE(NOW + 901, 11); }), 'future');
probe('future skew +300 accepted', rebuild('accept', Buffer.from(canonBuf('accept')), hdr => { hdr.writeUInt32BE(NOW + 300, 7); hdr.writeUInt32BE(NOW + 900, 11); }), null);
probe('expired arrival', rebuild('accept', Buffer.from(canonBuf('accept')), hdr => { hdr.writeUInt32BE(NOW - 500, 7); hdr.writeUInt32BE(NOW - 1, 11); }), 'expired');
probe('requester evidence in to', rebuild('requester-ad', mutate('requester-ad', p => { p.to.identityEvidence = 'V0lSRS1PTkxZ'; })), 'duplicate-proof');
probe('proof-payment agentPin forbidden', rebuild('proof-payment', mutate('proof-payment', p => { p.body.agentPin = p.from.agentPin; })), 'unknown');
probe('identity proof missing agentPin', rebuild('proof-identity', mutate('proof-identity', p => { delete p.body.agentPin; })), 'missing');
probe('offer paymentAddress != provider address', rebuild('offer', mutate('offer', p => { p.body.terms.paymentAddress = '1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH'; })), 'address');
// Third principal from locally derived test scalar 3 (offline, low-value):
// distinct from both published parties, so the probe isolates the §10.5
// provider-recipient rule instead of tripping the structural `distinct` check.
const k3 = '0000000000000000000000000000000000000000000000000000000000000003';
const pub3 = secp.derivePubkey(k3);
const thirdParty = { agentPin: '3'.repeat(64) + '.0', pubkey: pub3, address: wire.deriveAddress(pub3) };
probe('payment to != offer provider (full ctx)', rebuild('payment', mutate('payment', p => { p.to = thirdParty; }), h => h.writeUInt32BE(wire.targetId(pub3).readUInt32BE(0), 1)), 'role', { context: fullCtx, now: NOW });
probe('payment amount != price', rebuild('payment', mutate('payment', p => { p.body.amountSats = 2501; })), 'number', { context: fullCtx, now: NOW });
// Roles reversed AND made structurally consistent (target = new recipient,
// re-signed by the new sender) so the contextual §10.6 role rule is what fires.
probe('deliver roles reversed', rebuild('deliver', mutate('deliver', p => { const t = p.from; p.from = p.to; p.to = t; }), h => h.writeUInt32BE(wire.targetId(decoded['provider-ad'].from.pubkey).readUInt32BE(0), 1), decoded['requester-ad'].from.pubkey), 'role', { context: fullCtx, now: NOW });
probe('accept wrong thread', rebuild('accept', mutate('accept', p => { p.threadId = 'f'.repeat(32); })), 'thread', { context: fullCtx, now: NOW });
probe('accept offerHash -> request (wrong action)', rebuild('accept', mutate('accept', p => { p.body.offerHash = decoded['request'].sha256; })), 'reference-action', { context: fullCtx, now: NOW });
probe('ack thread mismatch', rebuild('ack', mutate('ack', p => { p.threadId = 'e'.repeat(32); })), 'thread', { context: fullCtx, now: NOW });
const r0 = secp.bigIntTo32(0n), s0 = secp.bigIntTo32(0n);
{
  const b = Buffer.from(srcBytes('accept')); r0.copy(b, 21); s0.copy(b, 53);
  probe('r=0,s=0 signature', b, 'signature');
}
{
  const b = Buffer.from(srcBytes('accept')); secp.bigIntTo32(secp.N).copy(b, 21);
  probe('r == n out of range', b, ['signature', 'high-s']);
}
{
  const b = Buffer.from(srcBytes('accept')); secp.bigIntTo32(secp.N).copy(b, 53);
  probe('s == n out of range', b, ['signature', 'high-s']);
}
{
  // high-s flip of a valid signature: s' = n - s (still verifies mathematically)
  const src = srcBytes('accept');
  const s = secp.bytesToBigInt(src.subarray(53, 85));
  const b = Buffer.from(src); secp.bigIntTo32(secp.N - s).copy(b, 53);
  probe('high-s flipped valid signature', b, 'high-s');
}
{
  // sender pubkey not on curve (x = p-1 has no square root)
  const bad = '02' + 'ff'.repeat(32);
  const p = JSON.parse(canonStr('requester-ad'));
  p.from.pubkey = bad; p.from.address = '1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH';
  probe('sender pubkey off curve', rebuild('requester-ad', Buffer.from(jcs.jcsSerialize(p), 'utf8')), 'curve');
}
{
  // address checksum corruption (valid length/charset)
  const p = JSON.parse(canonStr('accept'));
  const a = p.from.address;
  p.from.address = a.slice(0, -1) + (a.slice(-1) === 'H' ? 'J' : 'H');
  probe('address bad checksum', rebuild('accept', Buffer.from(jcs.jcsSerialize(p), 'utf8')), 'address');
}
{
  // target mismatch: header target != derivation of recipient pubkey
  const b = Buffer.from(srcBytes('accept'));
  b.writeUInt32BE(0xdeadbeef, 1);
  probe('target != recipient derivation', b, 'target');
}

// --- Q1R item 1: RECEIPT offer binding (false-accept regressions) ---
probe('receipt offerHash all-zero (full ctx)', rebuild('receipt', mutate('receipt', p => { p.body.offerHash = '0'.repeat(64); })), 'reference-action', { context: fullCtx, now: NOW });
probe('receipt offerHash all-zero (null ctx, binding is contextual)', rebuild('receipt', mutate('receipt', p => { p.body.offerHash = '0'.repeat(64); })), null);
probe('receipt paymentId != delivery (full ctx)', rebuild('receipt', mutate('receipt', p => { p.body.paymentId = '5'.repeat(64) + '.0'; })), 'reference-action', { context: fullCtx, now: NOW });
{
  // Context where the DELIVER references a different (all-zero) offer: the
  // receipt's own offerHash is valid, but delivery binding must still fail.
  const deliverZero = wire.decodeEnvelope(rebuild('deliver', mutate('deliver', p => { p.body.offerHash = '0'.repeat(64); })), { context: null });
  const ctxMut = wire.makeContext(Object.values(decoded).map(e => e.messageId === deliverZero.messageId ? deliverZero : e));
  probe('receipt vs delivery bound to another offer', srcBytes('receipt'), 'reference-action', { context: ctxMut, now: NOW });
}

// --- Q1R item 2: structural freshness without a receiver clock ---
probe('Expires == Created without now', rebuild('accept', Buffer.from(canonBuf('accept')), hdr => hdr.writeUInt32BE(NOW, 11)), 'window', noClock);
probe('ACCEPT window 901s without now', rebuild('accept', Buffer.from(canonBuf('accept')), hdr => hdr.writeUInt32BE(NOW + 901, 11)), 'window', noClock);
probe('ACCEPT window exactly 900s without now (boundary)', rebuild('accept', Buffer.from(canonBuf('accept')), hdr => hdr.writeUInt32BE(NOW + 900, 11)), null, noClock);
probe('ADVERTISE window 604801s without now', rebuild('requester-ad', Buffer.from(canonBuf('requester-ad')), hdr => hdr.writeUInt32BE(hdr.readUInt32BE(7) + 604801, 11)), 'window', noClock);
probe('ADVERTISE window exactly 604800s without now (boundary)', rebuild('requester-ad', Buffer.from(canonBuf('requester-ad')), hdr => hdr.writeUInt32BE(hdr.readUInt32BE(7) + 604800, 11)), null, noClock);

// --- Q1R item 3: PAYMENT sequencing (§9 rule 4) ---
probe('payment without ACCEPT/ACCEPT_ACK in context', srcBytes('payment'), 'reference-action', { context: wire.makeContext(Object.values(decoded).filter(e => e.action !== 'ACCEPT' && e.action !== 'ACCEPT_ACK')), now: NOW });
probe('payment with ACCEPT but no provider ACCEPT_ACK', srcBytes('payment'), 'reference-action', { context: wire.makeContext(Object.values(decoded).filter(e => e.action !== 'ACCEPT_ACK')), now: NOW });
probe('payment full context accepted (control)', srcBytes('payment'), null, { context: fullCtx, now: NOW });
probe('ack acceptHash -> offer (wrong action, full ctx)', rebuild('ack', mutate('ack', p => { p.body.acceptHash = decoded['offer'].sha256; })), 'reference-action', { context: fullCtx, now: NOW });

// --- Q1R item 4: task expiry cap = REQUEST deliverBy + 86400 (§8.2) ---
const DB = FIXTURES['request'].body.deliverBy;
const CAP = DB + 86400;
probe('deliver expires 1s beyond request cap', rebuild('deliver', Buffer.from(canonBuf('deliver')), hdr => { hdr.writeUInt32BE(DB + 1, 7); hdr.writeUInt32BE(CAP + 1, 11); }), 'window', { context: fullCtx });
probe('deliver expires exactly at request cap (boundary)', rebuild('deliver', Buffer.from(canonBuf('deliver')), hdr => { hdr.writeUInt32BE(DB, 7); hdr.writeUInt32BE(CAP, 11); }), null, { context: fullCtx });
probe('receipt expires beyond request cap', rebuild('receipt', Buffer.from(canonBuf('receipt')), hdr => { hdr.writeUInt32BE(DB + 1, 7); hdr.writeUInt32BE(DB + 1 + 86400, 11); }), 'window', { context: fullCtx });

// --- Q1R item 5: provider advertisement freshness at REQUEST (§10.2) ---
{
  const expiredAd = wire.decodeEnvelope(rebuild('provider-ad', Buffer.from(canonBuf('provider-ad')), hdr => { hdr.writeUInt32BE(NOW - 100, 7); hdr.writeUInt32BE(NOW - 1, 11); }), { context: null });
  const ctxExpiredAd = wire.makeContext(Object.values(decoded).map(e => e.messageId === expiredAd.messageId ? expiredAd : e));
  // The REQUEST must reference the expired ad by its (new) envelope hash.
  const reqRefExpired = rebuild('request', mutate('request', p => { p.body.providerAdvertisementHash = expiredAd.sha256; }));
  probe('request with expired provider ad (now supplied)', reqRefExpired, 'expired', { context: ctxExpiredAd, now: NOW });
  probe('request with expired provider ad (no clock; freshness needs now)', reqRefExpired, null, { context: ctxExpiredAd });
  probe('request full context at NOW accepted (control)', srcBytes('request'), null, { context: fullCtx, now: NOW });
}

// --- Q1R item 6: outer REQUEST identityEvidence forbidden ---
probe('REQUEST outer from.identityEvidence (decoder)', rebuild('request', mutate('request', p => { p.from.identityEvidence = 'V0lSRS1PTkxZ'; })), 'duplicate-proof');

// --- Q1R item 7: identity PROOF local binding without context ---
probe('identity proof agentPin != sender (null ctx)', rebuild('proof-identity', mutate('proof-identity', p => { p.body.agentPin = '0'.repeat(64) + '.0'; })), 'role');
probe('identity proof agentPin != sender (full ctx)', rebuild('proof-identity', mutate('proof-identity', p => { p.body.agentPin = '0'.repeat(64) + '.0'; })), 'role', { context: fullCtx, now: NOW });
probe('identity proof null ctx accepted (control)', srcBytes('proof-identity'), null);

// --- Q1R item 8: strict endpoint / REJECT reason forms ---
probe('endpoint trailing empty fragment', rebuild('provider-ad', mutate('provider-ad', p => { p.body.endpoint = 'https://provider.example/x#'; })), 'format');
for (const [label, ch] of [['VT', '\u000b'], ['FF', '\u000c'], ['NEL', '\u0085'], ['U+2028', '\u2028'], ['U+2029', '\u2029']]) {
  probe(`reject reason ${label} terminator`, rebuild('reject', mutate('reject', p => { p.body.reason = 'a' + ch + 'b'; })), 'text');
}
probe('reject reason tab accepted (single-line boundary)', rebuild('reject', mutate('reject', p => { p.body.reason = 'a\tb'; })), null);

// --- Q1R item 10: long-address resource bound ---
probe('address 65 chars rejected before BigInt', rebuild('accept', mutate('accept', p => { p.from.address = '1'.repeat(65); })), 'address');
probe('address 64 chars bad payload (boundary)', rebuild('accept', mutate('accept', p => { p.from.address = '1'.repeat(64); })), 'address');

// --- Q1R item 11: MIME grammar + body timestamp parity ---
const MIME_FULL = "text/a!#$%&'*+.^_`|~-z";
probe('mime full token grammar accepted (deliver)', rebuild('deliver', mutate('deliver', p => { p.body.mime = MIME_FULL; })), null);
probe('mime full token grammar accepted (request)', rebuild('request', mutate('request', p => { p.body.deliveryMime = MIME_FULL; })), null);
probe('mime invalid token char (', rebuild('deliver', mutate('deliver', p => { p.body.mime = 'text/a(b'; })), 'format');
probe('mime exactly 100 bytes accepted (boundary)', rebuild('deliver', mutate('deliver', p => { p.body.mime = 'text/' + 'a'.repeat(95); })), null);
probe('mime 101 bytes rejected', rebuild('deliver', mutate('deliver', p => { p.body.mime = 'text/' + 'a'.repeat(96); })), 'format');
{
  // Body timestamps are safe integers with chronology rules, NOT uint32:
  // header stays uint32 by wire format; deliverBy may exceed 2^32-1.
  const farCreated = 0xffffffff - 1000;
  const farHdr = hdr => { hdr.writeUInt32BE(farCreated, 7); hdr.writeUInt32BE(farCreated + 600, 11); };
  probe('request deliverBy beyond uint32 accepted', rebuild('request', mutate('request', p => { p.body.deliverBy = 4295000000; }), farHdr), null, noClock);
  probe('request deliverBy = created+2592000 (boundary)', rebuild('request', mutate('request', p => { p.body.deliverBy = farCreated + 2592000; }), farHdr), null, noClock);
  probe('request deliverBy = created+2592001 rejected', rebuild('request', mutate('request', p => { p.body.deliverBy = farCreated + 2592001; }), farHdr), 'window', noClock);
  // acceptBefore is capped by Expires_At (uint32 header) per §10.4, so the
  // beyond-uint32 body-timestamp parity probe uses payBy/deliverBy, which are
  // safe-integer/chronology fields with no uint32 cap.
  probe('offer payBy/deliverBy beyond uint32 accepted', rebuild('offer', mutate('offer', p => { p.body.terms.acceptBefore = farCreated + 300; p.body.terms.payBy = 4294967296; p.body.terms.deliverBy = 4294967297; }), farHdr), null, noClock);
  probe('request deliverBy unsafe integer', rebuild('request', Buffer.from(canonStr('request').replace('"deliverBy":1795603600', '"deliverBy":9007199254740992'), 'utf8')), 'number');
  probe('offer acceptBefore unsafe integer', rebuild('offer', Buffer.from(canonStr('offer').replace('"acceptBefore":1795600500', '"acceptBefore":9007199254740992'), 'utf8')), 'number');
}
probe('envelope nesting depth 65 rejected', rebuild('accept', Buffer.from(canonStr('accept').replace(/"body":\{[^{}]*\}/, '"body":' + chainText(65)), 'utf8')), 'noncanonical');

// ---------------------------------------------------------------------------
console.log('== E. encoder safety / consistency probes (item 9, 12) ==');
function encProbe(label, fx, expectCode) {
  probeCount++;
  let err = null, out = null;
  try { out = wire.encodeEnvelope(fx); } catch (e) { err = e; }
  const good = expectCode === null ? err === null : err instanceof wire.WireError && err.code === expectCode;
  ok(good, `encoder probe ${label}: expected ${expectCode}, got ${err ? err.code + ' ' + err.message : 'accept'}`);
  manifest.probes.push({ label: 'encoder: ' + label, outcome: err ? 'reject' : 'accept', code: err ? err.code : null, expected: expectCode });
  return out;
}
const encFx = name => ({ ...structuredClone(FIXTURES[name]), privateKey: keyByPub[FIXTURES[name].from.pubkey] });
{
  const fx = encFx('payment'); fx.body.vout = -0;
  encProbe('negative zero rejected before signing', fx, 'number');
}
{
  // Lone surrogate in a field that reaches JCS (REJECT reason has no prior
  // charset regex): the serializer must reject before signing.
  const fx = encFx('reject'); fx.body.reason = 'a\uD800b';
  encProbe('lone surrogate rejected before signing', fx, 'noncanonical');
}
{
  const fx = encFx('request'); fx.from.identityEvidence = 'V0lSRS1PTkxZ';
  encProbe('REQUEST outer identityEvidence rejected', fx, 'duplicate-proof');
}
{
  const fx = encFx('proof-identity'); fx.from.identityEvidence = 'V0lSRS1PTkxZ';
  encProbe('identity PROOF outer identityEvidence rejected at encode', fx, 'duplicate-proof');
}
{
  const fx = encFx('accept'); fx.privateKey = k2; // provider key, requester from
  encProbe('wrong signer key (pubkey mismatch)', fx, 'signature');
}
{
  const fx = encFx('accept'); fx.privateKey = '0'.repeat(64);
  encProbe('zero private key rejected', fx, 'signature');
}
{
  const fx = encFx('accept'); fx.privateKey = secp.N.toString(16).padStart(64, '0');
  encProbe('private key == n rejected', fx, 'signature');
}
{
  const fx = encFx('accept'); fx.expiresAt = fx.createdAt;
  encProbe('expires == created rejected at encode', fx, 'window');
}
{
  const fx = encFx('accept'); fx.expiresAt = fx.createdAt + 901;
  encProbe('ACCEPT window 901s rejected at encode', fx, 'window');
}
{
  const fx = encFx('deliver'); fx.body.content = '🚀';
  const out = encProbe('astral content encodes and round-trips', fx, null);
  if (out) {
    const back = wire.decodeEnvelope(out.bytes, { context: null });
    ok(back.body.content === '🚀', 'encoder astral roundtrip content preserved');
  }
}
{
  const out = encProbe('correct key reproduces golden accept', encFx('accept'), null);
  if (out) ok(out.bytes.equals(srcBytes('accept')), 'encoder positive control byte-exact');
}

// --- Q2R item 1: DELIVER/RECEIPT bind the PAYMENT (offer/thread/roles/ACCEPT+ACK/amount) ---
const ctxPay = mut => wire.makeContext(Object.values(decoded).map(d => d.action === 'PAYMENT' ? wire.decodeEnvelope(rebuild('payment', mut), { context: null }) : d));
probe('item1: DELIVER payment bound to different offer', rebuild('deliver', canonBuf('deliver')), 'reference-action', { context: ctxPay(mutate('payment', p => { p.body.offerHash = '0'.repeat(64); })) });
keyByPub[pub3] = k3; // third principal key for role-mismatch re-signing
probe('item1: DELIVER payment sender != requester', rebuild('deliver', canonBuf('deliver')), 'role', { context: wire.makeContext(Object.values(decoded).map(d => d.action === 'PAYMENT' ? wire.decodeEnvelope(rebuild('payment', mutate('payment', p => { p.from = thirdParty; }), null, pub3), { context: null }) : d)) });
probe('item1: DELIVER payment thread mismatch', rebuild('deliver', canonBuf('deliver')), 'thread', { context: ctxPay(mutate('payment', p => { p.threadId = 'f'.repeat(32); })) });
probe('item1: DELIVER payment amount != offer price', rebuild('deliver', canonBuf('deliver')), 'number', { context: ctxPay(mutate('payment', p => { p.body.amountSats = 2501; })) });
probe('item1: RECEIPT payment amount != offer price', rebuild('receipt', canonBuf('receipt')), 'number', { context: ctxPay(mutate('payment', p => { p.body.amountSats = 2501; })) });
{
  const noAck = wire.makeContext(Object.values(decoded).filter(d => d.action !== 'ACCEPT_ACK'));
  probe('item1: DELIVER payment without provider ACCEPT_ACK', rebuild('deliver', canonBuf('deliver')), 'reference-action', { context: noAck });
  probe('item1: RECEIPT payment without provider ACCEPT_ACK', rebuild('receipt', canonBuf('receipt')), 'reference-action', { context: noAck });
}
probe('item1 control: DELIVER full context accepted', rebuild('deliver', canonBuf('deliver')), null, { context: fullCtx });
probe('item1 control: RECEIPT full context accepted', rebuild('receipt', canonBuf('receipt')), null, { context: fullCtx });
// Q2R item 1 (review): missing ACCEPT and wrong ACK recipient must break
// DELIVER and RECEIPT identically through the shared binding helper.
{
  const noAccept = wire.makeContext(Object.values(decoded).filter(d => d.action !== 'ACCEPT'));
  probe('item1: DELIVER with missing ACCEPT', rebuild('deliver', canonBuf('deliver')), 'reference-action', { context: noAccept });
  probe('item1: RECEIPT with missing ACCEPT', rebuild('receipt', canonBuf('receipt')), 'reference-action', { context: noAccept });
  const ackWrongTo = wire.decodeEnvelope(rebuild('ack', mutate('ack', p => { p.to = thirdParty; }),
    hdr => { hdr.writeUInt32BE(wire.targetId(pub3).readUInt32BE(0), 1); }), { context: null });
  const ctxWrongAck = wire.makeContext(Object.values(decoded).map(d => d.action === 'ACCEPT_ACK' ? ackWrongTo : d));
  probe('item1: DELIVER with wrong ACK recipient', rebuild('deliver', canonBuf('deliver')), 'reference-action', { context: ctxWrongAck });
  probe('item1: RECEIPT with wrong ACK recipient', rebuild('receipt', canonBuf('receipt')), 'reference-action', { context: ctxWrongAck });
}

// --- Q2R item 2: REQUEST-time provider advertisement future skew ---
{
  const futureAd = wire.decodeEnvelope(rebuild('provider-ad', canonBuf('provider-ad'), hdr => { hdr.writeUInt32BE(NOW + 301, 7); hdr.writeUInt32BE(NOW + 301 + 604800, 11); }), { context: null });
  const ctxFutureAd = wire.makeContext(Object.values(decoded).map(d => d.action === 'ADVERTISE' && d.from.pubkey === decoded['provider-ad'].from.pubkey ? futureAd : d));
  const reqRefFuture = rebuild('request', mutate('request', p => { p.body.providerAdvertisementHash = futureAd.sha256; }));
  probe('item2: REQUEST references future-skewed provider ad', reqRefFuture, 'future', { context: ctxFutureAd, now: NOW });
  probe('item2 control: REQUEST valid provider ad accepted', rebuild('request', canonBuf('request')), null, { context: fullCtx, now: NOW });
}
// Q2R item 2 (review): +300s boundary accepted; wrong-sender ad binding rejected.
{
  const adAt300Bytes = rebuild('provider-ad', canonBuf('provider-ad'), hdr => { hdr.writeUInt32BE(NOW + 300, 7); hdr.writeUInt32BE(NOW + 300 + 604800, 11); });
  const adAt300 = wire.decodeEnvelope(adAt300Bytes, { context: null });
  const reqAt300Bytes = rebuild('request', mutate('request', p => { p.body.providerAdvertisementHash = adAt300.sha256; }));
  const ctxAt300 = wire.makeContext([wire.decodeEnvelope(reqAt300Bytes, { context: null }), adAt300]);
  probe('item2: REQUEST references provider ad at +300s boundary', reqAt300Bytes, null, { context: ctxAt300, now: NOW });
  probe('item2: REQUEST references wrong-sender advertisement', rebuild('request', mutate('request', p => { p.body.providerAdvertisementHash = decoded['requester-ad'].sha256; })), 'role', { context: fullCtx, now: NOW });
}

// --- Q2R item 3 (review): normative replay-conflict identity ---
// BMP-0005 §8.2 / §9 rule 8: the conflict key is EXACTLY the triple
// (threadId, from.pubkey, messageId). Action/role/outpoint belong only in
// contextual reference resolution. Same-principal different-byte reuse
// conflicts across actions and outpoints; different principals coexist on
// one messageId; exact-byte duplicates stay idempotent.
{
  const d1 = decoded['deliver'];
  const d2 = wire.decodeEnvelope(rebuild('deliver', mutate('deliver', p => { p.body.content = 'conflicting delivery content'; })), { context: null });
  let conflict = false;
  try { wire.makeContext([d1, d2]); } catch (e) { conflict = e instanceof wire.WireError && e.code === 'conflict'; }
  ok(conflict, 'item3: conflicting stored bytes for one replay identity rejected');
  let idem = true;
  try { wire.makeContext([d1, d1]); } catch (_) { idem = false; }
  ok(idem, 'item3: same-byte idempotent retry preserved');

  // (a) Two standalone-valid REQUESTs, same thread/messageId, DIFFERENT
  // sender keys: must coexist (cross-principal false-conflict regression).
  const reqMsgId = decoded['request'].messageId;
  const thirdPartyAd = { ...thirdParty, identityEvidence: 'V0lSRS1PTkxZ' };
  const adFx = structuredClone(FIXTURES['requester-ad']);
  adFx.from = thirdPartyAd; adFx.to = thirdParty; // ADVERTISE: evidence on from only
  const adEnc = wire.encodeEnvelope({ ...adFx, privateKey: k3 });
  const unrelFx = structuredClone(FIXTURES['request']);
  unrelFx.from = thirdParty;                    // to stays the provider
  unrelFx.body.requesterAdvertisement = adEnc.bytes.toString('base64');
  unrelFx.body.requesterAdvertisementHash = adEnc.sha256;
  unrelFx.body.deliverBy = DB + 100000;         // looser cap than the real REQUEST
  const unrelReq = wire.decodeEnvelope(wire.encodeEnvelope({ ...unrelFx, privateKey: k3 }).bytes, { context: null });
  let coexist = false;
  try {
    const cx = wire.makeContext([unrelReq, decoded['request']]);
    coexist = cx.findByAction('REQUEST').length === 2 &&
      cx.findByReplay(reqMsgId, pub3, reqMsgId) === unrelReq &&
      cx.findByReplay(reqMsgId, decoded['request'].from.pubkey, reqMsgId) === decoded['request'];
  } catch (_) { coexist = false; }
  ok(coexist, 'item3: same thread/messageId from different senders coexists');

  // (b) Same provider/thread/messageId reused across OFFER and ACCEPT_ACK
  // with different bytes: conflict (cross-action same-principal regression).
  const off = decoded['offer'];
  const ackReuse = wire.decodeEnvelope(rebuild('ack', mutate('ack', p => { p.messageId = off.messageId; }), hdr => { Buffer.from(off.messageId, 'hex').copy(hdr, 15, 0, 4); }), { context: null });
  let crossActionConflict = false;
  try { wire.makeContext([off, ackReuse]); } catch (e) { crossActionConflict = e instanceof wire.WireError && e.code === 'conflict'; }
  ok(crossActionConflict, 'item3: same-principal cross-action messageId reuse conflicts');

  // (c) Same requester/thread/messageId across two PAYMENTs after changing
  // txid/outpoint: conflict (outpoint-substitution regression).
  const pay1 = decoded['payment'];
  const pay2 = wire.decodeEnvelope(rebuild('payment', mutate('payment', p => { p.body.txid = '5'.repeat(64); })), { context: null });
  let outpointConflict = false;
  try { wire.makeContext([pay1, pay2]); } catch (e) { outpointConflict = e instanceof wire.WireError && e.code === 'conflict'; }
  ok(outpointConflict, 'item3: same-principal PAYMENT outpoint substitution conflicts');

  // Cross-thread reuse by one principal stays distinguishable (threadId is
  // part of the normative triple).
  const delivThread = wire.decodeEnvelope(rebuild('deliver', mutate('deliver', p => { p.threadId = 'f'.repeat(32); })), { context: null });
  let crossThread = true;
  try { wire.makeContext([d1, delivThread]); } catch (_) { crossThread = false; }
  ok(crossThread, 'item3: cross-thread messageId reuse distinguished');

  // Original plan regression: a valid unrelated ADVERTISE carrying the
  // originating REQUEST's messageId must not displace the REQUEST for cap
  // enforcement; over-cap DELIVER still rejects 'window', at-cap accepted.
  const collAdFx = structuredClone(FIXTURES['requester-ad']);
  collAdFx.from = thirdPartyAd; collAdFx.to = thirdParty;
  collAdFx.messageId = reqMsgId; collAdFx.threadId = reqMsgId;
  const collAd = wire.decodeEnvelope(wire.encodeEnvelope({ ...collAdFx, privateKey: k3 }).bytes, { context: null });
  const ctxCollision = wire.makeContext([...Object.values(decoded), collAd]);
  ok(ctxCollision.findByReplay(reqMsgId, decoded['request'].from.pubkey, reqMsgId).action === 'REQUEST',
    'item3: unrelated ADVERTISE does not displace the originating REQUEST');
  probe('item3: over-cap DELIVER despite ADVERTISE messageId collision',
    rebuild('deliver', canonBuf('deliver'), hdr => { hdr.writeUInt32BE(DB + 1, 7); hdr.writeUInt32BE(CAP + 1, 11); }),
    'window', { context: ctxCollision });
  probe('item3: at-cap DELIVER valid despite ADVERTISE messageId collision',
    rebuild('deliver', canonBuf('deliver'), hdr => { hdr.writeUInt32BE(DB, 7); hdr.writeUInt32BE(CAP, 11); }),
    null, { context: ctxCollision });

  // First-request poisoning: an unrelated REQUEST with the same messageId
  // and a looser deliverBy must not satisfy the real thread's cap check.
  // Participant/role-aware resolution selects the real REQUEST; the
  // unrelated REQUEST is placed FIRST to expose first-match selection.
  const ctxPoison = wire.makeContext([unrelReq, ...Object.values(decoded)]);
  probe('item3: over-cap DELIVER despite unrelated same-messageId REQUEST',
    rebuild('deliver', canonBuf('deliver'), hdr => { hdr.writeUInt32BE(DB + 1, 7); hdr.writeUInt32BE(CAP + 1, 11); }),
    'window', { context: ctxPoison });
  probe('item3: at-cap DELIVER valid despite unrelated same-messageId REQUEST',
    rebuild('deliver', canonBuf('deliver'), hdr => { hdr.writeUInt32BE(DB, 7); hdr.writeUInt32BE(CAP, 11); }),
    null, { context: ctxPoison });

  // Comment 862: exact-byte duplicate REQUEST copies in context must stay
  // idempotent for contextual candidate enumeration — one extra identical
  // copy of the published REQUEST must not turn a valid DELIVER into
  // context-required, and must not loosen the cap check either.
  const ctxDupReq = wire.makeContext([...Object.values(decoded), decoded['request']]);
  ok(ctxDupReq.findByAction('REQUEST').length === 1, 'item3: exact-byte duplicate REQUEST enumerated once');
  ok(ctxDupReq.findByMsg('REQUEST', reqMsgId, reqMsgId) === decoded['request'], 'item3: findByMsg resolves exact-byte duplicate REQUEST uniquely');
  probe('item3: valid DELIVER unchanged with exact duplicate REQUEST copy in context', srcBytes('deliver'), null, { context: ctxDupReq, now: NOW });
  probe('item3: over-cap DELIVER still window-rejected with duplicate REQUEST copy',
    rebuild('deliver', canonBuf('deliver'), hdr => { hdr.writeUInt32BE(DB + 1, 7); hdr.writeUInt32BE(CAP + 1, 11); }),
    'window', { context: ctxDupReq });
  probe('item3: at-cap DELIVER valid with duplicate REQUEST copy',
    rebuild('deliver', canonBuf('deliver'), hdr => { hdr.writeUInt32BE(DB, 7); hdr.writeUInt32BE(CAP, 11); }),
    null, { context: ctxDupReq });

  // Exact-byte duplicates of the whole payment-binding chain must also stay
  // idempotent for the shared DELIVER/RECEIPT binding lookups.
  const ctxDupChain = wire.makeContext([...Object.values(decoded), decoded['payment'], decoded['accept'], decoded['ack']]);
  probe('item3: valid RECEIPT with exact duplicate PAYMENT/ACCEPT/ACK copies', srcBytes('receipt'), null, { context: ctxDupChain, now: NOW });

  // Genuinely distinct matching REQUESTs (different bytes, different
  // principals, both participant-matching the DELIVER pair) must STILL
  // reject as context-required — dedup must not collapse real ambiguity.
  const revFx = structuredClone(FIXTURES['request']);
  revFx.from = structuredClone(FIXTURES['offer'].from);   // provider principal
  revFx.to = structuredClone(FIXTURES['request'].from);   // requester principal
  revFx.body.requesterAdvertisement = srcBytes('provider-ad').toString('base64');
  revFx.body.requesterAdvertisementHash = decoded['provider-ad'].sha256;
  revFx.body.providerAdvertisementHash = decoded['requester-ad'].sha256;
  const revReq = wire.decodeEnvelope(wire.encodeEnvelope({ ...revFx, privateKey: keyByPub[revFx.from.pubkey] }).bytes, { context: null });
  const ctxAmbig = wire.makeContext([...Object.values(decoded), revReq]);
  ok(ctxAmbig.findByAction('REQUEST').length === 2, 'item3: distinct role-reversed REQUEST coexists (not deduplicated)');
  probe('item3: genuinely distinct matching REQUESTs reject context-required', srcBytes('deliver'), 'context-required', { context: ctxAmbig, now: NOW });
}

// --- Q2R item 4: identity PROOF must not carry from.identityEvidence ---
probe('item4: identity PROOF with from.identityEvidence rejected', rebuild('proof-identity', mutate('proof-identity', p => { p.from.identityEvidence = 'V0lSRS1PTkxZ'; })), 'duplicate-proof');
probe('item4 control: identity PROOF without evidence accepted', rebuild('proof-identity', canonBuf('proof-identity')), null);
probe('item4 control: payment PROOF unchanged', rebuild('proof-payment', canonBuf('proof-payment')), null);
// Q2R item 4 (review): full-context variant, plus a payment-PROOF control
// that actually carries distinct sender identity evidence (must stay valid:
// the prohibition is identity-PROOF-specific, not blanket).
probe('item4: identity PROOF with from.identityEvidence (full context)', rebuild('proof-identity', mutate('proof-identity', p => { p.from.identityEvidence = 'V0lSRS1PTkxZ'; })), 'duplicate-proof', { context: fullCtx, now: NOW });
probe('item4 control: payment PROOF carrying sender identity evidence (full context)', rebuild('proof-payment', mutate('proof-payment', p => { p.from.identityEvidence = 'V0lSRS1PTkxZ'; })), null, { context: fullCtx, now: NOW });
probe('item4 control: payment PROOF carrying sender identity evidence (null context)', rebuild('proof-payment', mutate('proof-payment', p => { p.from.identityEvidence = 'V0lSRS1PTkxZ'; })), null);

// --- Q2R item 5: endpoint exact-string validation (controls/userinfo/fragment) ---
const epProbe = (label, ep, code) => probe(label, rebuild('provider-ad', mutate('provider-ad', p => { p.body.endpoint = ep; })), code);
epProbe('item5: endpoint leading space', ' https://provider.example/bmp-agent/1', 'format');
epProbe('item5: endpoint trailing space', 'https://provider.example/bmp-agent/1 ', 'format');
epProbe('item5: endpoint embedded tab', 'https://provider.example/\tbmp-agent/1', 'format');
epProbe('item5: endpoint embedded newline', 'https://provider.example/\nbmp-agent/1', 'format');
epProbe('item5: endpoint C0 control', 'https://provider.example/\u0001x', 'format');
epProbe('item5: endpoint DEL control', 'https://provider.example/\u007fx', 'format');
epProbe('item5: endpoint empty userinfo @host', 'https://@provider.example/bmp-agent/1', 'format');
epProbe('item5: endpoint userinfo', 'https://user:pass@provider.example/bmp-agent/1', 'format');
epProbe('item5: endpoint fragment', 'https://provider.example/bmp-agent/1#frag', 'format');
epProbe('item5: endpoint http scheme', 'http://provider.example/bmp-agent/1', 'format');
epProbe('item5 control: clean https endpoint accepted', 'https://provider.example/bmp-agent/1', null);
epProbe('item5 control: https with query accepted', 'https://provider.example/bmp-agent/1?q=1', null);
// Q2R item 5 (review): CR + leading/trailing tab/newline boundaries; a bare
// HTTPS root (no path) is a valid endpoint and must not be normalized away.
epProbe('item5: endpoint embedded CR', 'https://provider.example/\rbmp-agent/1', 'format');
epProbe('item5: endpoint leading CR', '\rhttps://provider.example/bmp-agent/1', 'format');
epProbe('item5: endpoint trailing CR', 'https://provider.example/bmp-agent/1\r', 'format');
epProbe('item5: endpoint leading tab', '\thttps://provider.example/bmp-agent/1', 'format');
epProbe('item5: endpoint trailing tab', 'https://provider.example/bmp-agent/1\t', 'format');
epProbe('item5: endpoint leading newline', '\nhttps://provider.example/bmp-agent/1', 'format');
epProbe('item5: endpoint trailing newline', 'https://provider.example/bmp-agent/1\n', 'format');
epProbe('item5 control: bare HTTPS root accepted', 'https://provider.example', null);
epProbe('item5 control: HTTPS root with explicit slash accepted', 'https://provider.example/', null);

// ---------------------------------------------------------------------------
manifest.assertions = { passed: pass, failed };
manifest.edgeProbes = probeCount;
manifest.negativesRejected = negRejected;
manifest.negativesCodeMatch = negCodeMatch;
manifest.positivesTotal = posTotal;
manifest.positivesSemanticByteExact = posSemExact;
manifest.positivesRoundtripByteExact = posRtExact;
const manifestBytes = Buffer.from(JSON.stringify(manifest, null, 0));
fs.writeFileSync(path.join(__dirname, 'manifest.json'), manifestBytes);
const manifestHash = secp.sha256(manifestBytes).toString('hex');
console.log('');
console.log(`positives reproduced byte-exact: ${posSemExact}/${posTotal}`);
console.log(`negatives rejected: ${negRejected}/${negCases.length} (code-category match ${negCodeMatch}/${negCases.length})`);
console.log(`edge probes: ${probeCount}`);
console.log(`assertions passed: ${pass}, failed: ${failed}`);
console.log(`manifest sha256: ${manifestHash}`);
if (failed > 0) { console.log('FAILURES PRESENT'); process.exit(1); }
console.log('ALL PASS');