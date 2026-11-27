'use strict';
// Offline interoperability checks. CURRENT selects examples; it is not a JS policy verdict.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { createHash } = require('node:crypto');
const { Beef, MerklePath } = require('@bsv/sdk');

const sha = bytes => createHash('sha256').update(bytes).digest();
const hash256 = bytes => sha(sha(bytes));
const display = bytes => Buffer.from(bytes).reverse().toString('hex');
const pair = (left, right) => hash256(Buffer.concat([left, right]));

function checkCompound() {
  const { parents } = require('../vectors/agent_payment/positive.json').cases[0];
  assert.equal(parents.length, 2);
  const hashes = [Buffer.from('coinbase'), ...parents.map(p => Buffer.from(p, 'hex')), Buffer.from('fourth')].map(hash256);
  const leaves = hashes.map((hash, i) => Buffer.concat([Buffer.from([i, i === 1 || i === 2 ? 2 : 0]), hash]));
  // Four leaves; the omitted level-one sibling must be derived for each parent.
  const encode = (base, upper = []) => Buffer.concat([Buffer.from([100, 2, base.length]), ...base,
    Buffer.from([upper.length]), ...upper]);
  const root = display(pair(pair(hashes[0], hashes[1]), pair(hashes[2], hashes[3])));
  const proof = MerklePath.fromBinary(encode(leaves));
  for (const i of [1, 2]) assert.equal(proof.computeRoot(display(hashes[i])), root);
  assert.throws(() => MerklePath.fromBinary(encode(leaves.slice(0, 3))), /Missing hash/i);
  const wrong = Buffer.concat([Buffer.from([1, 0]), Buffer.alloc(32)]);
  assert.throws(() => MerklePath.fromBinary(encode(leaves, [wrong])), /Mismatched roots/i);
}

function checkCase(f, c) {
  const serialized = f.beefs[c.beef];
  assert.match(serialized, /^(?:[0-9a-f]{2})+$/i);
  const beef = Beef.fromBinaryStrict(Buffer.from(serialized, 'hex'));
  const subject = beef.txs.at(-1);
  assert.ok(subject?.tx, 'last BEEF entry must be a full subject');
  assert.equal(beef.atomicTxid, display(hash256(subject.rawTxUint8Array)), 'atomic ID must identify last transaction');
  const chain = f.chains[c.chain];
  function checkPath(entry) {
    const id = display(hash256(entry.rawTxUint8Array));
    const proof = beef.bumps[entry.bumpIndex];
    assert.ok(proof?.path[0].some(leaf => leaf.hash === id && leaf.txid === true), 'missing marked txid in assigned BUMP');
    const record = c.support.find(s => s.txid === id);
    assert.ok(record);
    const header = f.headers[chain[record.height - f.anchor_height]];
    assert.match(header, /^[0-9a-f]{160}$/i, `no 80-byte header for proof height ${proof.blockHeight}`);
    const expected = display(Buffer.from(header, 'hex').subarray(36, 68));
    assert.equal(proof.computeRoot(id), expected, `wrong root for ${id} at height ${proof.blockHeight}`);
  }
  assert.equal(subject.txid, f.payment_id.split('.')[0]);
  if (subject.bumpIndex !== undefined) checkPath(subject);
  else assert.equal(c.policy, 'zero-conf');
  assert.ok(subject.tx.inputs.length > 0, 'payment has no inputs');
  const parents = new Map();
  for (const input of subject.tx.inputs) {
    const parent = beef.txs.slice(0, -1).find(entry => entry.txid === input.sourceTXID);
    assert.ok(parent?.tx, `missing full parent ${input.sourceTXID}`);
    assert.ok(parent.tx.outputs[input.sourceOutputIndex], 'missing referenced output');
    parents.set(input.sourceTXID, parent);
  }
  for (const entry of parents.values()) checkPath(entry);
  return parents.size;
}

function main() {
  checkCompound();
  const files = process.argv.length > 2 ? process.argv.slice(2) :
    [path.join(__dirname, '../vectors/agent_evidence/scenarios.json')];
  let count = 0, parents = 0;
  for (const file of files) {
    const f = JSON.parse(fs.readFileSync(file === '-' ? 0 : file, 'utf8'));
    for (const c of f.cases.filter(c => c.expected === 'CURRENT')) {
      try { parents += checkCase(f, c); } catch (err) { throw new Error(`${file}: ${c.name}: ${err.message}`, { cause: err }); }
      count++;
    }
  }
  assert.ok(count > 0, 'no CURRENT examples checked');
  console.log(`SDK: compound BUMP and both malformed controls passed; ${count} Atomic BEEF subjects and ${parents} direct parent proofs matched fixture headers. C4 policy not evaluated.`);
}
if (require.main === module) main();
