'use strict';
// Independent BMP-0005 R3 wire codec (Node built-ins only).
// Implemented from spec/BMP-0005-agent-interaction-profile.md (§§5,6,8,9,10)
// and spec/BMP-0000-bitcoin-machine-protocol.md (§4 envelope conventions),
// plus the published vector schemas. No code from poc/agent or poc/svcode.
//
// SCOPE: wire/schema + freshness + transcript-reference parity only. This does
// NOT verify Atomic BEEF / SPV / header PoW, Locus chain state, payment policy,
// or Dogfood signing boundaries. identityEvidence/atomicBeef are treated as
// exact-base64 opaque placeholders, exactly as the published vectors declare.

const crypto = require('crypto');
const secp = require('./secp256k1.js');
const jcs = require('./jcs.js');

const VERSION = 0x02;
const PROFILE = 'bmp-agent/1';
const PREFIX = Buffer.from('BMP-AGENT/1', 'ascii');
const HEADER_LEN = 85;
const SIG_LEN = 64;

const ACTIONS = {
  ADVERTISE: 0xa000, REQUEST: 0xa001, OFFER: 0xa002, ACCEPT: 0xa003,
  PAYMENT: 0xa004, DELIVER: 0xa005, RECEIPT: 0xa006, REJECT: 0xa007,
  PROOF: 0xa008, ACCEPT_ACK: 0xa009,
};
const ACTION_BY_CODE = Object.fromEntries(Object.entries(ACTIONS).map(([k, v]) => [v, k]));
const WINDOWS = {
  ADVERTISE: 604800, REQUEST: 3600, OFFER: 3600, ACCEPT: 900, ACCEPT_ACK: 900,
  PAYMENT: 86400, DELIVER: 86400, RECEIPT: 86400, PROOF: 86400, REJECT: 86400,
};
const MAX_FUTURE_SKEW = 300;
const REJECT_CODES = ['unsupported', 'busy', 'terms', 'policy', 'expired',
  'identity-proof-required', 'payment-proof-required', 'payment-policy', 'malformed', 'conflict'];
const CONFIRMATION_POLICIES = ['zero-conf', 'one-block'];

class WireError extends Error {
  constructor(code, path, msg) {
    super(`${code}${path ? ' @ ' + path : ''}: ${msg || code}`);
    this.name = 'WireError';
    this.code = code;
    this.path = path || '';
  }
}
function fail(code, path, msg) { throw new WireError(code, path, msg); }

// ---------- primitive format rules ----------
const RE_HEX64 = /^[0-9a-f]{64}$/;
const RE_HEX32 = /^[0-9a-f]{32}$/;
const RE_HEX66 = /^[0-9a-f]{66}$/;
const RE_PIN = /^[0-9a-f]{64}\.(0|[1-9][0-9]*)$/;
const RE_KIND = /^[a-z][a-z0-9._-]{0,63}$/;
const RE_MIME = /^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+$/;
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function isHex64(s) { return typeof s === 'string' && RE_HEX64.test(s); }
function utf8Len(s) { return Buffer.byteLength(s, 'utf8'); }

function checkHex64(s, path) {
  if (!isHex64(s)) fail('format', path, 'expected 64 lowercase hex chars');
}
function checkHex32(s, path) {
  if (typeof s !== 'string' || !RE_HEX32.test(s)) fail('format', path, 'expected 32 lowercase hex chars (16 bytes)');
}
function checkPin(s, path) {
  if (typeof s !== 'string' || !RE_PIN.test(s)) fail('format', path, 'bad agentPin/outpoint');
  const vout = Number(s.slice(65));
  if (!Number.isSafeInteger(vout) || vout > 0xffffffff) fail('format', path, 'vout out of range');
}
function checkBase64(s, path) {
  if (typeof s !== 'string' || s.length === 0 || s.length % 4 !== 0 ||
      !/^[A-Za-z0-9+/]+={0,2}$/.test(s)) fail('base64', path, 'bad base64 form');
  const buf = Buffer.from(s, 'base64');
  if (buf.length === 0 || buf.toString('base64') !== s) fail('base64', path, 'noncanonical base64 / pad bits');
  return buf;
}
function checkMime(s, path) {
  if (typeof s !== 'string' || !RE_MIME.test(s) || utf8Len(s) > 100) fail('format', path, 'bad mime');
}
function checkUintRange(v, lo, hi, path) {
  if (typeof v !== 'number' || !Number.isSafeInteger(v) || v < lo || v > hi) {
    fail('number', path, `expected integer in [${lo},${hi}]`);
  }
}

// base58check (mainnet P2PKH) — independent BigInt implementation
function b58encode(buf) {
  let v = 0n;
  for (const b of buf) v = (v << 8n) | BigInt(b);
  let out = '';
  while (v > 0n) { out = B58[Number(v % 58n)] + out; v /= 58n; }
  for (const b of buf) { if (b === 0) out = '1' + out; else break; }
  return out || '1';
}
function b58decode(s) {
  if (typeof s !== 'string' || s.length === 0) return null;
  let v = 0n;
  for (const ch of s) {
    const idx = B58.indexOf(ch);
    if (idx < 0) return null;
    v = v * 58n + BigInt(idx);
  }
  const bytes = [];
  while (v > 0n) { bytes.unshift(Number(v & 0xffn)); v >>= 8n; }
  for (const ch of s) { if (ch === '1') bytes.unshift(0); else break; }
  return Buffer.from(bytes);
}
function hash160(buf) {
  return crypto.createHash('ripemd160').update(secp.sha256(buf)).digest();
}
function checkAddress(addr, pubHex, path) {
  const raw = b58decode(addr);
  if (!raw || raw.length !== 25 || raw[0] !== 0x00) fail('address', path, 'not mainnet P2PKH');
  const body = raw.subarray(0, 21);
  const checksum = secp.sha256(secp.sha256(body)).subarray(0, 4);
  if (!checksum.equals(raw.subarray(21, 25))) fail('address', path, 'bad base58 checksum');
  if (b58encode(raw) !== addr) fail('address', path, 'noncanonical base58');
  const expect = hash160(secp.hexToBytes(pubHex));
  if (!expect.equals(raw.subarray(1, 21))) fail('address', path, 'address does not match pubkey');
}
function deriveAddress(pubHex) {
  const h = hash160(secp.hexToBytes(pubHex));
  const body = Buffer.concat([Buffer.from([0x00]), h]);
  const checksum = secp.sha256(secp.sha256(body)).subarray(0, 4);
  return b58encode(Buffer.concat([body, checksum]));
}

function targetId(pubHex) {
  return secp.sha256(Buffer.concat([PREFIX, secp.hexToBytes(pubHex)])).subarray(0, 4);
}

// ---------- closed-schema helpers ----------
function checkKeys(obj, allowed, path) {
  if (obj === null || typeof obj !== 'object' || Array.isArray(obj)) fail('format', path, 'expected object');
  for (const k of Object.keys(obj)) {
    if (!allowed.includes(k)) fail('unknown', path + '.' + k, 'unknown field');
  }
}
function requireKeys(obj, required, path) {
  for (const k of required) {
    if (!(k in obj)) fail('missing', path + '.' + k, 'missing required field');
  }
}
function checkStr(v, path) { if (typeof v !== 'string') fail('format', path, 'expected string'); }

// ---------- identity objects (§5.6) ----------
function validateIdentity(id, path, opts = {}) {
  checkKeys(id, ['agentPin', 'pubkey', 'address', 'identityEvidence'], path);
  requireKeys(id, ['agentPin', 'pubkey', 'address'], path);
  checkPin(id.agentPin, path + '.agentPin');
  if (typeof id.pubkey !== 'string' || !RE_HEX66.test(id.pubkey) || !secp.isOnCurve(id.pubkey)) {
    fail('curve', path + '.pubkey', 'invalid compressed secp256k1 point');
  }
  checkAddress(id.address, id.pubkey, path + '.address');
  if ('identityEvidence' in id) {
    checkBase64(id.identityEvidence, path + '.identityEvidence');
  } else if (opts.requireEvidence) {
    fail('missing', path + '.identityEvidence', 'required identity evidence');
  }
  if (opts.forbidEvidence && 'identityEvidence' in id) {
    fail('duplicate-proof', path + '.identityEvidence', 'evidence not allowed here');
  }
}
function principalEq(a, b) {
  return a.agentPin === b.agentPin && a.pubkey === b.pubkey && a.address === b.address;
}

// ---------- body schemas (§§6,9,10) ----------
function validateServiceEntry(e, i, path) {
  const p = `${path}[${i}]`;
  checkKeys(e, ['kind', 'description', 'maxTaskBytes', 'maxDeliveryBytes'], p);
  requireKeys(e, ['kind', 'description', 'maxTaskBytes', 'maxDeliveryBytes'], p);
  if (typeof e.kind !== 'string' || !RE_KIND.test(e.kind)) fail('format', p + '.kind', 'bad kind');
  checkStr(e.description, p + '.description');
  const dl = utf8Len(e.description);
  if (dl < 1 || dl > 280) fail('text', p + '.description', 'description 1..280 bytes');
  checkUintRange(e.maxTaskBytes, 1, 65535, p + '.maxTaskBytes');
  checkUintRange(e.maxDeliveryBytes, 1, 65535, p + '.maxDeliveryBytes');
}

function validateBody(action, body, env, opts) {
  const path = '$.body';
  const ctx = opts.context;
  switch (action) {
    case 'ADVERTISE': {
      checkKeys(body, ['endpoint', 'services'], path);
      requireKeys(body, ['endpoint', 'services'], path);
      checkStr(body.endpoint, path + '.endpoint');
      let u;
      try { u = new URL(body.endpoint); } catch { fail('format', path + '.endpoint', 'bad URL'); }
      if (u.protocol !== 'https:' || u.username || u.password || u.hash || !u.hostname) {
        fail('format', path + '.endpoint', 'must be absolute https without credentials/fragment');
      }
      if (!Array.isArray(body.services) || body.services.length > 16) fail('number', path + '.services', '0..16 services');
      const kinds = new Set();
      body.services.forEach((e, i) => {
        validateServiceEntry(e, i, path + '.services');
        if (kinds.has(e.kind)) fail('duplicate', path + '.services', 'duplicate kind ' + e.kind);
        kinds.add(e.kind);
      });
      break;
    }
    case 'REQUEST': {
      checkKeys(body, ['providerAdvertisementHash', 'requesterAdvertisementHash', 'requesterAdvertisement',
        'service', 'task', 'maxPriceSats', 'deliverBy', 'deliveryMime', 'maxDeliveryBytes'], path);
      requireKeys(body, ['providerAdvertisementHash', 'requesterAdvertisementHash', 'requesterAdvertisement',
        'service', 'task', 'maxPriceSats', 'deliverBy', 'deliveryMime', 'maxDeliveryBytes'], path);
      checkHex64(body.providerAdvertisementHash, path + '.providerAdvertisementHash');
      checkHex64(body.requesterAdvertisementHash, path + '.requesterAdvertisementHash');
      const adBytes = checkBase64(body.requesterAdvertisement, path + '.requesterAdvertisement');
      // recursively decode the embedded requester advertisement (§6.1)
      const embedded = decodeEnvelope(adBytes, { now: opts.now, context: ctx, depth: (opts.depth || 0) + 1 });
      if (embedded.action !== 'ADVERTISE') fail('recipient', path + '.requesterAdvertisement', 'embedded not ADVERTISE');
      if (embedded.sha256 !== body.requesterAdvertisementHash) fail('recipient', path + '.requesterAdvertisementHash', 'embedded hash mismatch');
      if (!principalEq(embedded.from, env.from)) fail('recipient', path + '.requesterAdvertisement/$.from', 'embedded sender != requester');
      if (!principalEq(embedded.to, env.from)) fail('recipient', path + '.requesterAdvertisement/$.to', 'embedded not addressed to requester');
      checkStr(body.service, path + '.service');
      if (!RE_KIND.test(body.service)) fail('format', path + '.service', 'bad service kind');
      checkStr(body.task, path + '.task');
      const tl = utf8Len(body.task);
      if (tl < 1 || tl > 4096) fail('text', path + '.task', 'task 1..4096 bytes');
      checkUintRange(body.maxPriceSats, 1, Number.MAX_SAFE_INTEGER, path + '.maxPriceSats');
      checkUintRange(body.deliverBy, 0, 0xffffffff, path + '.deliverBy');
      if (body.deliverBy <= env.expiresAt) fail('window', path + '.deliverBy', 'deliverBy must exceed Expires_At');
      if (body.deliverBy > env.createdAt + 30 * 86400) fail('window', path + '.deliverBy', 'deliverBy beyond 30 days');
      checkMime(body.deliveryMime, path + '.deliveryMime');
      checkUintRange(body.maxDeliveryBytes, 1, 16384, path + '.maxDeliveryBytes');
      if (ctx) {
        const provAd = ctx.findBySha(body.providerAdvertisementHash);
        if (!provAd || provAd.action !== 'ADVERTISE') fail('missing', path + '.providerAdvertisementHash', 'provider advertisement not in context');
        if (!principalEq(provAd.from, env.to)) fail('role', path + '.providerAdvertisementHash', 'provider ad sender != recipient');
        const entry = provAd.body.services.find(e => e.kind === body.service);
        if (!entry) fail('reference-action', path + '.service', 'service not advertised');
        if (tl > entry.maxTaskBytes) fail('text', path + '.task', 'task exceeds advertised maxTaskBytes');
        if (body.maxDeliveryBytes > entry.maxDeliveryBytes) fail('number', path + '.maxDeliveryBytes', 'exceeds advertised maxDeliveryBytes');
      }
      break;
    }
    case 'OFFER': {
      checkKeys(body, ['terms'], path);
      requireKeys(body, ['terms'], path);
      const t = body.terms;
      const tp = path + '.terms';
      checkKeys(t, ['requestHash', 'priceSats', 'paymentAddress', 'acceptBefore', 'payBy', 'deliverBy',
        'confirmationPolicy', 'deliveryMime', 'maxDeliveryBytes'], tp);
      requireKeys(t, ['requestHash', 'priceSats', 'paymentAddress', 'acceptBefore', 'payBy', 'deliverBy',
        'confirmationPolicy', 'deliveryMime', 'maxDeliveryBytes'], tp);
      checkHex64(t.requestHash, tp + '.requestHash');
      checkUintRange(t.priceSats, 1, Number.MAX_SAFE_INTEGER, tp + '.priceSats');
      checkStr(t.paymentAddress, tp + '.paymentAddress');
      if (t.paymentAddress !== env.from.address) fail('address', tp + '.paymentAddress', 'must be provider address');
      for (const f of ['acceptBefore', 'payBy', 'deliverBy']) checkUintRange(t[f], 0, 0xffffffff, tp + '.' + f);
      if (!(env.createdAt < t.acceptBefore && t.acceptBefore <= t.payBy && t.payBy < t.deliverBy)) {
        fail('window', tp, 'offer chronology violated');
      }
      if (t.acceptBefore > env.expiresAt) fail('window', tp + '.acceptBefore', 'acceptBefore beyond Expires_At');
      if (!CONFIRMATION_POLICIES.includes(t.confirmationPolicy)) fail('format', tp + '.confirmationPolicy', 'bad policy');
      checkMime(t.deliveryMime, tp + '.deliveryMime');
      checkUintRange(t.maxDeliveryBytes, 1, 16384, tp + '.maxDeliveryBytes');
      if (ctx) {
        const req = ctx.findBySha(t.requestHash);
        if (!req || req.action !== 'REQUEST') fail('reference-action', tp + '.requestHash', 'request not in context');
        if (env.threadId !== req.messageId) fail('thread', '$.threadId', 'offer thread != request');
        if (!principalEq(env.from, req.to) || !principalEq(env.to, req.from)) fail('role', '$.from', 'offer roles reversed');
        if (t.priceSats > req.body.maxPriceSats) fail('number', tp + '.priceSats', 'exceeds maxPriceSats');
        if (t.deliveryMime !== req.body.deliveryMime) fail('format', tp + '.deliveryMime', 'mime mismatch');
        if (t.deliverBy > req.body.deliverBy) fail('window', tp + '.deliverBy', 'beyond request deadline');
        const provAd = ctx.findBySha(req.body.providerAdvertisementHash);
        const entry = provAd && provAd.body.services.find(e => e.kind === req.body.service);
        const cap = entry ? Math.min(req.body.maxDeliveryBytes, entry.maxDeliveryBytes) : req.body.maxDeliveryBytes;
        if (t.maxDeliveryBytes > cap) fail('number', tp + '.maxDeliveryBytes', 'exceeds delivery cap');
      }
      break;
    }
    case 'ACCEPT': {
      checkKeys(body, ['offerHash'], path);
      requireKeys(body, ['offerHash'], path);
      checkHex64(body.offerHash, path + '.offerHash');
      if (ctx) {
        const offer = ctx.findBySha(body.offerHash);
        if (!offer || offer.action !== 'OFFER') fail('reference-action', path + '.offerHash', 'offer not in context');
        if (env.threadId !== offer.threadId) fail('thread', '$.threadId', 'accept thread mismatch');
        if (!principalEq(env.from, offer.to) || !principalEq(env.to, offer.from)) fail('role', '$.from', 'accept roles reversed');
      }
      break;
    }
    case 'ACCEPT_ACK': {
      checkKeys(body, ['offerHash', 'acceptHash'], path);
      requireKeys(body, ['offerHash', 'acceptHash'], path);
      checkHex64(body.offerHash, path + '.offerHash');
      checkHex64(body.acceptHash, path + '.acceptHash');
      if (ctx) {
        const accept = ctx.findBySha(body.acceptHash);
        if (!accept || accept.action !== 'ACCEPT') fail('reference-action', path + '.acceptHash', 'accept not in context');
        if (accept.body.offerHash !== body.offerHash) fail('reference-action', path + '.offerHash', 'ack offerHash != accept offerHash');
        const offer = ctx.findBySha(body.offerHash);
        if (!offer || offer.action !== 'OFFER') fail('reference-action', path + '.offerHash', 'offer not in context');
        if (env.threadId !== accept.threadId) fail('thread', '$.threadId', 'ack thread mismatch');
        if (!principalEq(env.from, accept.to) || !principalEq(env.to, accept.from)) fail('role', '$.from', 'ack roles reversed');
      }
      break;
    }
    case 'PAYMENT': {
      checkKeys(body, ['offerHash', 'txid', 'vout', 'amountSats', 'atomicBeef'], path);
      requireKeys(body, ['offerHash', 'txid', 'vout', 'amountSats'], path);
      checkHex64(body.offerHash, path + '.offerHash');
      checkHex64(body.txid, path + '.txid');
      checkUintRange(body.vout, 0, 0xffffffff, path + '.vout');
      checkUintRange(body.amountSats, 1, Number.MAX_SAFE_INTEGER, path + '.amountSats');
      if ('atomicBeef' in body) checkBase64(body.atomicBeef, path + '.atomicBeef');
      if (ctx) {
        const offer = ctx.findBySha(body.offerHash);
        if (!offer || offer.action !== 'OFFER') fail('reference-action', path + '.offerHash', 'offer not in context');
        if (env.threadId !== offer.threadId) fail('thread', '$.threadId', 'payment thread mismatch');
        if (!principalEq(env.from, offer.to) || !principalEq(env.to, offer.from)) fail('role', '$.from', 'payment roles reversed');
        if (body.amountSats !== offer.body.terms.priceSats) fail('number', path + '.amountSats', 'amount != offer price');
      }
      break;
    }
    case 'DELIVER': {
      checkKeys(body, ['offerHash', 'paymentId', 'mime', 'content'], path);
      requireKeys(body, ['offerHash', 'paymentId', 'mime', 'content'], path);
      checkHex64(body.offerHash, path + '.offerHash');
      checkPin(body.paymentId, path + '.paymentId');
      checkMime(body.mime, path + '.mime');
      checkStr(body.content, path + '.content');
      const cl = utf8Len(body.content);
      if (cl > 16384) fail('text', path + '.content', 'content exceeds 16384 bytes');
      if (ctx) {
        const offer = ctx.findBySha(body.offerHash);
        if (!offer || offer.action !== 'OFFER') fail('reference-action', path + '.offerHash', 'offer not in context');
        if (cl > offer.body.terms.maxDeliveryBytes) fail('text', path + '.content', 'content exceeds accepted maxDeliveryBytes');
        if (body.mime !== offer.body.terms.deliveryMime) fail('format', path + '.mime', 'mime != accepted offer mime');
        if (env.threadId !== offer.threadId) fail('thread', '$.threadId', 'deliver thread mismatch');
        if (!principalEq(env.from, offer.from) || !principalEq(env.to, offer.to)) fail('role', '$.from', 'deliver roles reversed');
        const pay = ctx.findByPaymentId(body.paymentId);
        if (!pay || pay.body.offerHash !== body.offerHash) fail('reference-action', path + '.paymentId', 'payment not in context');
      }
      break;
    }
    case 'RECEIPT': {
      checkKeys(body, ['offerHash', 'deliveryHash', 'paymentId', 'outcome'], path);
      requireKeys(body, ['offerHash', 'deliveryHash', 'paymentId', 'outcome'], path);
      checkHex64(body.offerHash, path + '.offerHash');
      checkHex64(body.deliveryHash, path + '.deliveryHash');
      checkPin(body.paymentId, path + '.paymentId');
      if (body.outcome !== 'accepted') fail('format', path + '.outcome', 'outcome must be accepted');
      if (ctx) {
        const del = ctx.findBySha(body.deliveryHash);
        if (!del || del.action !== 'DELIVER') fail('reference-action', path + '.deliveryHash', 'delivery not in context');
        if (del.body.paymentId !== body.paymentId) fail('reference-action', path + '.paymentId', 'receipt paymentId != delivery');
        if (env.threadId !== del.threadId) fail('thread', '$.threadId', 'receipt thread mismatch');
        if (!principalEq(env.from, del.to) || !principalEq(env.to, del.from)) fail('role', '$.from', 'receipt roles reversed');
      }
      break;
    }
    case 'PROOF': {
      checkKeys(body, ['subjectHash', 'proofKind', 'atomicBeef', 'agentPin'], path);
      requireKeys(body, ['subjectHash', 'proofKind', 'atomicBeef'], path);
      checkHex64(body.subjectHash, path + '.subjectHash');
      if (body.proofKind !== 'identity' && body.proofKind !== 'payment') fail('format', path + '.proofKind', 'bad proofKind');
      checkBase64(body.atomicBeef, path + '.atomicBeef');
      if (body.proofKind === 'identity') {
        requireKeys(body, ['agentPin'], path);
        checkPin(body.agentPin, path + '.agentPin');
      } else if ('agentPin' in body) {
        fail('unknown', path + '.agentPin', 'agentPin only for identity proof');
      }
      if (ctx) {
        const subj = ctx.findBySha(body.subjectHash);
        if (!subj) fail('reference-action', path + '.subjectHash', 'subject not in context');
        if (env.threadId !== subj.threadId) fail('thread', '$.threadId', 'proof thread mismatch');
        if (!principalEq(env.from, subj.from) || !principalEq(env.to, subj.to)) fail('role', '$.from', 'proof roles mismatch');
        if (body.proofKind === 'identity') {
          if (body.agentPin !== subj.from.agentPin) fail('role', path + '.agentPin', 'agentPin != subject sender');
        } else if (subj.action !== 'PAYMENT') {
          fail('reference-action', path + '.subjectHash', 'payment proof subject must be PAYMENT');
        }
      }
      break;
    }
    case 'REJECT': {
      checkKeys(body, ['subjectHash', 'code', 'reason'], path);
      requireKeys(body, ['subjectHash', 'code'], path);
      checkHex64(body.subjectHash, path + '.subjectHash');
      if (!REJECT_CODES.includes(body.code)) fail('format', path + '.code', 'bad reject code');
      if ('reason' in body) {
        checkStr(body.reason, path + '.reason');
        if (/[\n\r]/.test(body.reason) || utf8Len(body.reason) > 280) fail('text', path + '.reason', 'reason single-line <=280 bytes');
      }
      if (ctx) {
        const subj = ctx.findBySha(body.subjectHash);
        if (!subj) fail('reference-action', path + '.subjectHash', 'subject not in context');
        if (env.threadId !== subj.threadId) fail('thread', '$.threadId', 'reject thread mismatch');
        if (!principalEq(env.from, subj.to) || !principalEq(env.to, subj.from)) fail('role', '$.from', 'reject roles reversed');
        if ((body.code === 'payment-proof-required' || body.code === 'payment-policy') && subj.action !== 'PAYMENT') {
          fail('reference-action', path + '.subjectHash', 'payment reject code requires PAYMENT subject');
        }
      }
      break;
    }
    default: fail('action', '$.body', 'unknown action');
  }
}

// ---------- context index ----------
function makeContext(decodedList) {
  const bySha = new Map();
  const byMsg = new Map();
  const payments = [];
  for (const d of decodedList) {
    bySha.set(d.sha256, d);
    byMsg.set(d.messageId, d);
    if (d.action === 'PAYMENT') payments.push(d);
  }
  return {
    findBySha: h => bySha.get(h) || null,
    findByMsg: m => byMsg.get(m) || null,
    findByPaymentId: pid => payments.find(p => (p.body.txid + '.' + p.body.vout) === pid) || null,
  };
}

// ---------- decoder ----------
function decodeEnvelope(buf, opts = {}) {
  const depth = opts.depth || 0;
  if (depth > 2) fail('nesting', '$', 'embedded envelope nesting too deep');
  if (!Buffer.isBuffer(buf)) fail('format', '$', 'envelope not bytes');
  if (buf.length < HEADER_LEN) fail('truncated', '$', 'shorter than 85-byte header');
  if (buf[0] !== VERSION) fail('version', '$.version', 'expected 0x02');
  const actionCode = buf.readUInt16BE(5);
  const action = ACTION_BY_CODE[actionCode];
  if (!action) fail('action', '$.action', 'unknown action code');
  const payloadLen = buf.readUInt16BE(19);
  if (buf.length !== HEADER_LEN + payloadLen) fail('length', '$', 'envelope length != 85 + Payload_Length');

  const createdAt = buf.readUInt32BE(7);
  const expiresAt = buf.readUInt32BE(11);
  const nonce = buf.subarray(15, 19);
  const signature = buf.subarray(21, 85);
  const payloadBytes = buf.subarray(85);

  let payload;
  try {
    payload = jcs.parseCanonical(payloadBytes);
  } catch (e) {
    if (e instanceof jcs.JsonError) {
      const m = e.message;
      if (/duplicate key/.test(m)) fail('duplicate', '$', m);
      if (/number|integer|leading zero/.test(m)) fail('number', '$', m);
      if (/UTF-8|surrogate|control/.test(m)) fail('noncanonical', '$', m);
      fail('noncanonical', '$', m);
    }
    throw e;
  }

  checkKeys(payload, ['profile', 'threadId', 'messageId', 'from', 'to', 'body'], '$');
  requireKeys(payload, ['profile', 'threadId', 'messageId', 'from', 'to', 'body'], '$');
  if (payload.profile !== PROFILE) fail('format', '$.profile', 'profile must be bmp-agent/1');
  checkHex32(payload.messageId, '$.messageId');
  checkHex32(payload.threadId, '$.threadId');
  const msgIdBytes = secp.hexToBytes(payload.messageId);
  if (!nonce.equals(msgIdBytes.subarray(0, 4))) fail('nonce', '$.nonce', 'nonce != first 4 bytes of messageId');

  validateIdentity(payload.from, '$.from', action === 'ADVERTISE' ? { requireEvidence: true } : {});
  validateIdentity(payload.to, '$.to', action === 'ADVERTISE' ? { forbidEvidence: true } : {});

  // target binding (§5.5)
  const expectTarget = targetId(payload.to.pubkey);
  if (!expectTarget.equals(buf.subarray(1, 5))) fail('target', '$.target', 'target != SHA256(prefix||to.pubkey)[:4]');

  // principal rules (§5.6)
  if (action === 'ADVERTISE') {
    if (!principalEq(payload.from, payload.to)) fail('role', '$.to', 'ADVERTISE must be self-addressed');
    if (payload.threadId !== payload.messageId) fail('thread', '$.threadId', 'threadId must equal messageId');
  } else {
    if (payload.from.agentPin === payload.to.agentPin || payload.from.pubkey === payload.to.pubkey) {
      fail('distinct', '$.to', 'sender and recipient must have distinct pins and pubkeys');
    }
    if (action === 'REQUEST' || action === 'ADVERTISE') {
      if (payload.threadId !== payload.messageId) fail('thread', '$.threadId', 'threadId must equal messageId');
    }
  }

  // signature: low-s policy then ECDSA verify over SHA256(signed_bytes)
  if (!secp.isLowS(signature)) fail('high-s', '$.signature', 's > n/2');
  const signedBytes = Buffer.concat([buf.subarray(0, 21), payloadBytes]);
  if (!secp.verifySignature(payload.from.pubkey, signedBytes, signature)) fail('signature', '$.signature', 'ECDSA verify failed');

  const env = {
    action, actionCode, version: VERSION, profile: payload.profile,
    targetHex: buf.subarray(1, 5).toString('hex'),
    createdAt, expiresAt,
    nonceHex: nonce.toString('hex'),
    messageId: payload.messageId, threadId: payload.threadId,
    from: payload.from, to: payload.to, body: payload.body,
    signatureHex: signature.toString('hex'),
    payloadLen,
    sha256: secp.sha256(buf).toString('hex'),
  };

  // freshness (§8.2)
  if (typeof opts.now === 'number') {
    if (expiresAt <= createdAt) fail('window', '$.expires', 'Expires_At must exceed Created_At');
    if (expiresAt - createdAt > WINDOWS[action]) fail('window', '$.expires', 'expiry window exceeded');
    if (createdAt > opts.now + MAX_FUTURE_SKEW) fail('future', '$.created', 'Created_At too far in future');
    if (opts.now > expiresAt) fail('expired', '$.expires', 'message arrived after Expires_At');
  }

  validateBody(action, payload.body, env, { now: opts.now, context: opts.context || null, depth });
  return env;
}

// ---------- encoder ----------
// fixture: {action, createdAt, expiresAt, messageId, threadId, from, to, body, privateKey}
function encodeEnvelope(fx) {
  const action = fx.action;
  const actionCode = ACTIONS[action];
  if (!actionCode) fail('action', '$.action', 'unknown action');
  checkUintRange(fx.createdAt, 0, 0xffffffff, '$.created');
  checkUintRange(fx.expiresAt, 0, 0xffffffff, '$.expires');
  checkHex32(fx.messageId, '$.messageId');
  checkHex32(fx.threadId, '$.threadId');
  validateIdentity(fx.from, '$.from', action === 'ADVERTISE' ? { requireEvidence: true } : {});
  validateIdentity(fx.to, '$.to', action === 'ADVERTISE' ? { forbidEvidence: true } : {});
  if (action === 'ADVERTISE') {
    if (!principalEq(fx.from, fx.to)) fail('role', '$.to', 'ADVERTISE self-addressed');
  } else if (fx.from.agentPin === fx.to.agentPin || fx.from.pubkey === fx.to.pubkey) {
    fail('distinct', '$.to', 'distinct principals required');
  }
  const envShape = { from: fx.from, to: fx.to, createdAt: fx.createdAt, expiresAt: fx.expiresAt, threadId: fx.threadId, messageId: fx.messageId };
  validateBody(action, fx.body, envShape, { now: undefined, context: null, depth: 0 });

  const payload = { profile: PROFILE, threadId: fx.threadId, messageId: fx.messageId, from: fx.from, to: fx.to, body: fx.body };
  const payloadBytes = jcs.canonicalBytes(payload);
  if (payloadBytes.length > 0xffff) fail('length', '$', 'payload exceeds 65535 bytes');

  const header = Buffer.alloc(21);
  header[0] = VERSION;
  targetId(fx.to.pubkey).copy(header, 1);
  header.writeUInt16BE(actionCode, 5);
  header.writeUInt32BE(fx.createdAt, 7);
  header.writeUInt32BE(fx.expiresAt, 11);
  secp.hexToBytes(fx.messageId).subarray(0, 4).copy(header, 15);
  header.writeUInt16BE(payloadBytes.length, 19);

  const signedBytes = Buffer.concat([header, payloadBytes]);
  const sig = secp.signDeterministic(fx.privateKey, signedBytes);
  const bytes = Buffer.concat([header, sig, payloadBytes]);
  return { bytes, sha256: secp.sha256(bytes).toString('hex'), payloadLen: payloadBytes.length, signatureHex: sig.toString('hex') };
}

module.exports = {
  VERSION, PROFILE, ACTIONS, WINDOWS, HEADER_LEN,
  WireError, decodeEnvelope, encodeEnvelope, makeContext,
  targetId, deriveAddress, checkBase64, checkPin, checkHex64,
};
