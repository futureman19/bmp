// Independent offline BSV implementation; no Python digests, decoded outputs or trusted txids.
'use strict';
const assert = require('node:assert/strict');
const { Transaction, Spend } = require('@bsv/sdk');
const positive = require('../vectors/agent_payment/positive.json').cases;
const negative = require('../vectors/agent_payment/negative.json').cases;
function validate(c) {
  const tx = Transaction.fromHex(c.raw);
  const parents = c.parents.map(hex => Transaction.fromHex(hex));
  assert.equal(tx.toHex(), c.raw);
  tx.inputs.forEach((input, index) => {
    const parent = parents.find(p => p.id('hex') === input.sourceTXID);
    const coin = parent.outputs[input.sourceOutputIndex];
    const spend = new Spend({sourceTXID: input.sourceTXID, sourceOutputIndex: input.sourceOutputIndex,
      sourceSatoshis: coin.satoshis, lockingScript: coin.lockingScript, transactionVersion: tx.version,
      otherInputs: tx.inputs.filter((_, j) => j !== index), outputs: tx.outputs, inputIndex: index,
      unlockingScript: input.unlockingScript, inputSequence: input.sequence, lockTime: tx.lockTime});
    assert.equal(spend.validate(), true);
  });
  return `${tx.id('hex')}.${c.vout}`;
}
for (const c of positive) assert.equal(validate(c), c.paymentId);
const sourceTxid = Transaction.fromHex(positive.find(c => c.name === 'change').raw).id('hex');
// Same parents and signatures, shape-valid outputs, but a different change amount.
const changedOutputs = negative.find(c => c.name === 'signed-other-outputs');
assert.notEqual(Transaction.fromHex(changedOutputs.raw).id('hex'), sourceTxid);
assert.throws(() => validate(changedOutputs), /top stack element must be truthy after script evaluation/i);
for (const [name, rejection] of [
  ['high-s', /signature format is invalid/i],
  ['nonminimal-push', /not minimally-encoded/i],
]) {
  const mutated = negative.find(c => c.name === name);
  assert.notEqual(Transaction.fromHex(mutated.raw).id('hex'), sourceTxid);
  assert.throws(() => validate(mutated), rejection);
}
console.log(`${positive.length} SDK transaction IDs and all input spends verified; changed outputs, high-S and non-minimal pushes rejected`);
