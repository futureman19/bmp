'use strict';
// Independent BMP-0005 parity + adversarial suite. Run: node test_parity.js
// Reads ONLY the published JSON vectors and the normative-spec-derived codec
// in this directory. Writes a deterministic manifest for the twice-run gate.

const fs = require('fs');
const path = require('path');
const assert = require('assert');
const secp = require('./secp256k1.js');
const jcs = require('./jcs.js');
const wire = require('./wire.js');

const VEC = path.join(__dirname, '..', 'vectors', 'agent');
const positive = JSON.parse(fs.readFileSync(path.join(VEC, 'positive.json'), 'utf8'));
const negative = JSON.parse(fs.readFileSync(path.join(VEC, 'negative.json'), 'utf8'));
const NOW = positive.now;

let pass = 0, failed = 0;
const failures = [];
function ok(cond, label) {
  if (cond) { pass++; }
  else { failed++; failures.push(label); console.error('  FAIL: ' + label); }
}
function section(t) { console.log('\n== ' + t + ' =='); }

const keyByPub = {};
for (const k of positive.publishedTestPrivateKeys) keyByPub[secp.derivePubkey(k)] = k;
const posByName = {};
for (const [name, c] of Object.entries(positive.cases)) posByName[name] = { ...c, name };
const srcBytes = name => Buffer.from(posByName[name].envelopeHex, 'hex');

// ---------------------------------------------------------------- A. crypto KAT
section('A. secp256k1 / RFC6979 known-answer + cross-verifier');
{
  const k1 = keyByPub['0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'];
  const k2 = keyByPub['02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5'];
  ok(secp.derivePubkey(k1) === '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798', 'derive pubkey 1');
  ok(secp.derivePubkey(k2) === '02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5', 'derive pubkey 2');
  ok(wire.targetId('0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798').toString('hex') === '60604559', 'target id requester');
  ok(wire.targetId('02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5').toString('hex') === '13e5b3b1', 'target id provider');
  ok(wire.deriveAddress('0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798') === '1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH', 'derive address 1');
  ok(wire.deriveAddress('02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5') === '1cMh228HTCiwS8ZsaakH8A8wze1JR5ZsP', 'derive address 2');
  const msg = Buffer.from('BMP-0005 deterministic signing probe');
  const s1 = secp.signDeterministic(k1, msg);
  const s2 = secp.signDeterministic(k1, msg);
  ok(s1.equals(s2), 'RFC6979 determinism (same bytes twice)');
  ok(secp.isLowS(s1), 'signature is low-s');
  ok(secp.verifySignature(secp.derivePubkey(k1), msg, s1), 'self-verify deterministic sig');
  ok(secp.opensslVerify(secp.derivePubkey(k1), msg, s1), 'OpenSSL verifies our deterministic sig');
  const rnd = secp.opensslSignRandomK(k2, msg);
  ok(secp.verifySignature(secp.derivePubkey(k2), msg, rnd), 'our verifier accepts OpenSSL random-k sig');
  ok(!secp.verifySignature(secp.derivePubkey(k1), Buffer.from('tampered'), s1), 'verify rejects tampered message');
  ok(!secp.isOnCurve('02' + 'ff'.repeat(32)), 'reject x >= field prime');
  ok(!secp.isOnCurve('04' + '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'), 'reject uncompressed prefix');
}

// ------------------------------------------- B. positive reproduction + decode
section('B. positive golden vectors: decode, hash, signature, byte-exact re-encode');
const decoded = {};
const manifest = { scope: positive.scope, now: NOW, positives: [], probes: [] };
{
  // first pass without context to build the transcript index
  const list = [];
  for (const c of Object.values(posByName)) {
    const d = wire.decodeEnvelope(srcBytes(c.name), { now: NOW, context: null });
    decoded[c.name] = d;
    list.push(d);
  }
  const ctx = wire.makeContext(list);
  for (const c of Object.values(posByName)) {
    const buf = srcBytes(c.name);
    const d = wire.decodeEnvelope(buf, { now: NOW, context: ctx }); // full context checks
    ok(d.sha256 === c.sha256, `${c.name}: envelope sha256 matches published`);
    // independent OpenSSL cross-verification of the published signature
    const signedBytes = Buffer.concat([buf.subarray(0, 21), buf.subarray(85)]);
    ok(secp.opensslVerify(d.from.pubkey, signedBytes, buf.subarray(21, 85)), `${c.name}: OpenSSL verifies published sig`);
    // re-encode purely from semantic fixture data (no envelopeHex reuse)
    const fx = {
      action: d.action, createdAt: d.createdAt, expiresAt: d.expiresAt,
      messageId: d.messageId, threadId: d.threadId,
      from: d.from, to: d.to, body: d.body,
      privateKey: keyByPub[d.from.pubkey],
    };
    const enc = wire.encodeEnvelope(fx);
    ok(enc.bytes.equals(buf), `${c.name}: re-encoded bytes identical to golden envelopeHex`);
    ok(enc.sha256 === c.sha256, `${c.name}: re-encoded sha256 matches`);
    ok(enc.signatureHex === d.signatureHex, `${c.name}: deterministic r||s matches golden signature`);
    manifest.positives.push({ name: c.name, hex: enc.bytes.toString('hex'), sha256: enc.sha256 });
  }
  ok(Object.keys(decoded).length === 12, 'decoded 12 positive envelopes');
}
const fullCtx = wire.makeContext(Object.values(decoded));

// ------------------------------------------------------- C. negative replay
section('C. negative mutations: all must be rejected');
function applyMutation(neg) {
  const src = srcBytes(neg.source);
  if (neg.appendZeroes) return Buffer.concat([src, Buffer.alloc(neg.appendZeroes)]);
  const ins = Buffer.from(neg.insertHex || '', 'hex');
  return Buffer.concat([src.subarray(0, neg.offset), ins, src.subarray(neg.offset + (neg.remove || 0))]);
}
let negRejected = 0, negCodeMatch = 0;
for (const neg of negative) {
  const buf = applyMutation(neg);
  const opts = { now: neg.now ?? NOW, context: neg.context ? fullCtx : null };
  let err = null;
  try { wire.decodeEnvelope(buf, opts); } catch (e) { err = e; }
  const rejected = err instanceof wire.WireError;
  ok(rejected, `negative[${neg.name}] ${neg.source}/${neg.code}: rejected`);
  if (rejected) {
    negRejected++;
    if (err.code === neg.code) negCodeMatch++;
    else console.error(`  note: negative[${neg.name}] expected code ${neg.code}, got ${err.code} (${err.message})`);
  }
}
ok(negRejected === 33, 'all 33 negative mutations rejected');
console.log(`  negative code-category match: ${negCodeMatch}/33`);

// ------------------------------------------------------- D. edge probes
section('D. independent edge probes');
const payloadOf = name => ({
  profile: wire.PROFILE, threadId: decoded[name].threadId, messageId: decoded[name].messageId,
  from: decoded[name].from, to: decoded[name].to, body: decoded[name].body,
});
// rebuild an envelope with a new payload (and optional header edits), re-signed
// with the source sender key so semantic-layer probes carry a VALID signature.
function rebuild(name, payloadBytes, hdrEdit) {
  const src = srcBytes(name);
  const hdr = Buffer.from(src.subarray(0, 21));
  if (hdrEdit) hdrEdit(hdr);
  hdr.writeUInt16BE(payloadBytes.length, 19);
  const sig = secp.signDeterministic(keyByPub[decoded[name].from.pubkey], Buffer.concat([hdr, payloadBytes]));
  return Buffer.concat([hdr, sig, payloadBytes]);
}
const canonStr = name => jcs.jcsSerialize(payloadOf(name));
const canonBuf = name => Buffer.from(canonStr(name), 'utf8');
function mutate(name, fn) { const p = structuredClone(payloadOf(name)); fn(p); return jcs.canonicalBytes(p); }

let probeCount = 0;
function probe(label, bytes, expectCode, opts = {}) {
  probeCount++;
  let err = null;
  try { wire.decodeEnvelope(bytes, { now: opts.now ?? NOW, context: opts.context ?? null }); } catch (e) { err = e; }
  const want = Array.isArray(expectCode) ? expectCode : [expectCode];
  const good = err instanceof wire.WireError && (expectCode ? want.includes(err.code) : true);
  ok(good, `probe ${label}: expected ${expectCode || 'reject'}, got ${err ? err.code : 'ACCEPTED'}`);
  if (err) manifest.probes.push({ label, code: err.code });
  else manifest.probes.push({ label, code: 'ACCEPTED' });
}

// parse / canonicalization
probe('duplicate top-level key', rebuild('accept', Buffer.from(canonStr('accept').slice(0, -1) + ',"profile":"bmp-agent/1"}')), 'duplicate');
{
  const p = payloadOf('accept');
  const rev = '{' + Object.keys(p).reverse().map(k => jcs.jcsSerialize(k) + ':' + jcs.jcsSerialize(p[k])).join(',') + '}';
  probe('noncanonical key order', rebuild('accept', Buffer.from(rev)), 'noncanonical');
}
probe('\\u-escaped ASCII key', rebuild('accept', Buffer.from(canonStr('accept').replace('"body"', '"\\u0062ody"'))), 'noncanonical');
probe('exponent number', rebuild('payment', Buffer.from(canonStr('payment').replace('"amountSats":2500', '"amountSats":25e2'))), 'number');
probe('negative number', rebuild('payment', Buffer.from(canonStr('payment').replace('"vout":0', '"vout":-1'))), 'number');
probe('leading-zero number', rebuild('payment', Buffer.from(canonStr('payment').replace('"vout":0', '"vout":01'))), 'number');
probe('unsafe integer', rebuild('payment', Buffer.from(canonStr('payment').replace('"amountSats":2500', '"amountSats":9007199254740993'))), 'number');
probe('lone surrogate', rebuild('deliver', Buffer.from(canonStr('deliver').replace('Café.', 'Caf\\ud800.'))), 'noncanonical');
probe('invalid UTF-8 byte', rebuild('deliver', Buffer.concat([canonBuf('deliver').subarray(0, 10), Buffer.from([0xff]), canonBuf('deliver').subarray(10)])), 'noncanonical');
probe('UTF-8 BOM', rebuild('deliver', Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), canonBuf('deliver')])), 'noncanonical');
probe('raw control char in string', rebuild('deliver', Buffer.from(canonStr('deliver').replace('Summary', 'Sum\u0001mary'))), 'noncanonical');
probe('trailing newline', rebuild('deliver', Buffer.concat([canonBuf('deliver'), Buffer.from('\n')])), 'noncanonical');
{
  let deep = '{"a":'.repeat(70) + '0' + '}'.repeat(70);
  probe('nesting depth 70', rebuild('accept', Buffer.from(deep)), 'noncanonical');
}

// identity / curve / encoding
probe('uncompressed pubkey prefix', rebuild('accept', mutate('accept', p => { p.from.pubkey = '04' + p.from.pubkey.slice(2); })), 'curve');
probe('uppercase pubkey hex', rebuild('accept', mutate('accept', p => { p.from.pubkey = p.from.pubkey.toUpperCase(); })), 'curve');
probe('address bad checksum', rebuild('accept', mutate('accept', p => { p.from.address = p.from.address.slice(0, -1) + (p.from.address.slice(-1) === 'H' ? 'J' : 'H'); })), 'address');
probe('uppercase agentPin', rebuild('accept', mutate('accept', p => { p.from.agentPin = 'A' + p.from.agentPin.slice(1); })), 'format');
probe('vout overflow', rebuild('accept', mutate('accept', p => { p.from.agentPin = '0'.repeat(64) + '.4294967296'; })), 'format');
probe('vout leading zero', rebuild('accept', mutate('accept', p => { p.from.agentPin = '0'.repeat(64) + '.01'; })), 'format');
probe('base64 invalid char', rebuild('proof-payment', mutate('proof-payment', p => { p.body.atomicBeef = 'Zh-='; })), 'base64');
probe('base64 bad length', rebuild('proof-payment', mutate('proof-payment', p => { p.body.atomicBeef = 'Zh='; })), 'base64');
probe('empty identityEvidence', rebuild('provider-ad', mutate('provider-ad', p => { p.from.identityEvidence = ''; })), 'base64');

// header / length
{
  const b = Buffer.from(srcBytes('accept')); b[0] = 0x03;
  probe('version 0x03', b, 'version');
}
{
  const b = Buffer.from(srcBytes('accept')); b.writeUInt16BE(0xa00a, 5);
  probe('unknown action 0xA00A', b, 'action');
}
{
  const b = Buffer.from(srcBytes('accept')); b.writeUInt16BE(b.readUInt16BE(19) + 1, 19);
  probe('payload length +1', b, 'length');
}
probe('trailing byte', Buffer.concat([srcBytes('accept'), Buffer.from([0x00])]), 'length');
probe('84-byte header', srcBytes('accept').subarray(0, 84), 'truncated');

// semantic layer (valid signatures via rebuild)
probe('wrong profile', rebuild('accept', mutate('accept', p => { p.profile = 'bmp-agent/2'; })), 'format');
probe('unknown top-level field', rebuild('accept', mutate('accept', p => { p.extra = 1; })), 'unknown');
probe('missing required body field', rebuild('accept', mutate('accept', p => { delete p.body.offerHash; })), 'missing');
probe('REQUEST threadId != messageId', rebuild('request', mutate('request', p => { p.threadId = 'e'.repeat(32); })), 'thread');
{
  const prov = decoded['provider-ad'].to;
  const b = rebuild('requester-ad', mutate('requester-ad', p => { p.to = structuredClone(prov); }),
    hdr => wire.targetId(prov.pubkey).copy(hdr, 1));
  probe('ADVERTISE not self-addressed', b, 'role');
}
probe('same agentPin both parties', rebuild('accept', mutate('accept', p => { p.to.agentPin = p.from.agentPin; })), 'distinct');
probe('Created_At now+301', rebuild('accept', canonBuf('accept'), hdr => hdr.writeUInt32BE(NOW + 301, 7)), 'future');
probe('Expires_At == Created_At', rebuild('accept', canonBuf('accept'), hdr => hdr.writeUInt32BE(NOW, 11)), 'window');
probe('ACCEPT window 901s', rebuild('accept', canonBuf('accept'), hdr => hdr.writeUInt32BE(NOW + 901, 11)), 'window');
probe('arrived after expiry', rebuild('accept', canonBuf('accept')), 'expired', { now: NOW + 601 });
probe('task 4097 bytes', rebuild('request', mutate('request', p => { p.body.task = 'x'.repeat(4097); })), 'text');
probe('description 281 bytes', rebuild('provider-ad', mutate('provider-ad', p => { p.body.services[0].description = 'x'.repeat(281); })), 'text');
probe('17 services', rebuild('provider-ad', mutate('provider-ad', p => {
  const e = p.body.services[0]; p.body.services = Array.from({ length: 17 }, (_, i) => ({ ...e, kind: 'kind-' + i }));
})), 'number');
probe('reject reason multiline', rebuild('reject', mutate('reject', p => { p.body.reason = 'a\nb'; })), 'text');
probe('deliver content 16385 bytes', rebuild('deliver', mutate('deliver', p => { p.body.content = 'x'.repeat(16385); })), 'text');
probe('uppercase mime', rebuild('deliver', mutate('deliver', p => { p.body.mime = 'Text/Markdown'; })), 'format');
probe('http endpoint', rebuild('provider-ad', mutate('provider-ad', p => { p.body.endpoint = 'http://provider.example/x'; })), 'format');
probe('endpoint fragment', rebuild('provider-ad', mutate('provider-ad', p => { p.body.endpoint = 'https://provider.example/x#f'; })), 'format');
probe('deliverBy <= expires', rebuild('request', mutate('request', p => { p.body.deliverBy = decoded['request'].expiresAt; })), 'window');
probe('offer acceptBefore <= created', rebuild('offer', mutate('offer', p => { p.body.terms.acceptBefore = decoded['offer'].createdAt; })), 'window');
probe('paymentAddress != provider', rebuild('offer', mutate('offer', p => { p.body.terms.paymentAddress = decoded['requester-ad'].from.address; })), 'address');
probe('unknown reject code', rebuild('reject', mutate('reject', p => { p.body.code = 'nope'; })), 'format');
probe('payment proof with agentPin', rebuild('proof-payment', mutate('proof-payment', p => { p.body.agentPin = '0'.repeat(64) + '.0'; })), 'unknown');
probe('identity proof missing agentPin', rebuild('proof-identity', mutate('proof-identity', p => { delete p.body.agentPin; })), 'missing');
probe('receipt outcome rejected', rebuild('receipt', mutate('receipt', p => { p.body.outcome = 'rejected'; })), 'format');
// high-s and out-of-range s on an otherwise valid envelope
{
  const b = Buffer.from(srcBytes('accept'));
  const s = secp.bytesToBigInt(b.subarray(53, 85));
  secp.bigIntTo32(secp.N - s).copy(b, 53);
  probe('high-s (n - s)', b, 'high-s');
}
{
  const b = Buffer.from(srcBytes('accept'));
  secp.bigIntTo32(secp.N).copy(b, 53);
  probe('s == n out of range', b, ['signature', 'high-s']);
}
// context-dependent reference probes
probe('accept offerHash -> request (wrong action)', rebuild('accept', mutate('accept', p => { p.body.offerHash = decoded['request'].sha256; })), 'reference-action', { context: fullCtx });
probe('ack thread mismatch', rebuild('ack', mutate('ack', p => { p.threadId = 'e'.repeat(32); })), 'thread', { context: fullCtx });

// ------------------------------------------------------- E. determinism manifest
const manifestBytes = Buffer.from(JSON.stringify(manifest, null, 0));
fs.writeFileSync(path.join(__dirname, 'manifest.json'), manifestBytes);
const manifestHash = secp.sha256(manifestBytes).toString('hex');

section('SUMMARY');
console.log(`positives reproduced byte-exact: ${manifest.positives.length}/12`);
console.log(`negatives rejected: ${negRejected}/33 (code-category match ${negCodeMatch}/33)`);
console.log(`edge probes: ${probeCount}`);
console.log(`assertions passed: ${pass}, failed: ${failed}`);
console.log(`manifest sha256: ${manifestHash}`);
if (failed > 0) {
  console.error('FAILURES:\n' + failures.map(f => '  - ' + f).join('\n'));
  process.exit(1);
}
console.log('ALL PASS');
