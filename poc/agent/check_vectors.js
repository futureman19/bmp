'use strict';
// Independent reader for emitted positive bytes; no Python encoder/decoder imports.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const doc = JSON.parse(fs.readFileSync(path.join(__dirname, '../vectors/agent/positive.json')));
const sha = data => crypto.createHash('sha256').update(data).digest();
const actions = ['ADVERTISE','REQUEST','OFFER','ACCEPT','PAYMENT','DELIVER','RECEIPT','REJECT','PROOF','ACCEPT_ACK'];
const halfN = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n / 2n;
function jcs(x) {
  if (Array.isArray(x)) return '[' + x.map(jcs).join(',') + ']';
  if (x !== null && typeof x === 'object') return '{' + Object.keys(x).sort().map(k => JSON.stringify(k)+':'+jcs(x[k])).join(',') + '}';
  return JSON.stringify(x);
}
for (const row of Object.values(doc.cases)) {
  const b = Buffer.from(row.envelopeHex, 'hex');
  assert.equal(b[0], 2);
  assert.equal(actions[b.readUInt16BE(5)-0xa000], row.action);
  assert.equal(b.readUInt16BE(19), b.length-85);
  assert.equal(b.readUInt32BE(7), doc.now);
  assert.equal(b.readUInt32BE(11), doc.now+600);
  const data = b.subarray(85), p = JSON.parse(data);
  assert.deepEqual(Buffer.from(jcs(p)), data);
  assert.equal(b.subarray(15,19).toString('hex'), p.messageId.slice(0,8));
  assert.deepEqual(b.subarray(1,5), sha(Buffer.concat([Buffer.from('BMP-AGENT/1'), Buffer.from(p.to.pubkey,'hex')])).subarray(0,4));
  const uncompressed = crypto.ECDH.convertKey(p.from.pubkey,'secp256k1','hex',undefined,'uncompressed');
  const key = crypto.createPublicKey({format:'jwk',key:{kty:'EC',crv:'secp256k1',x:uncompressed.subarray(1,33).toString('base64url'),y:uncompressed.subarray(33).toString('base64url')}});
  assert(BigInt('0x'+b.subarray(53,85).toString('hex')) <= halfN);
  assert(crypto.verify('sha256', Buffer.concat([b.subarray(0,21),data]), {key,dsaEncoding:'ieee-p1363'}, b.subarray(21,85)));
  assert.equal(sha(b).toString('hex'), row.sha256);
}
console.log(`${Object.keys(doc.cases).length} independently decoded envelopes and OpenSSL signatures passed`);
