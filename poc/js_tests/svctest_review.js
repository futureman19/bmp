// svctest_review.js — regressions from the 2026-11-20 weekly deep review.
// One section per confirmed finding (R# ids match repro_review/repro.js).
// Run from poc/: node js_tests/svctest_review.js
global.SVC = require('../../js/svc.js');
const SVANCHOR = require('../../js/anchor.js');
const SVSPV = require('../../js/spv.js');
const fs = require('fs');
const l3 = JSON.parse(fs.readFileSync('vectors/l3_live.json', 'utf8'));

const unhex = (h) => Uint8Array.from(Buffer.from(h, 'hex'));
let pass = 0, fail = 0;
function ok(cond, name){ if (cond) pass++; else { fail++; console.log('FAIL: ' + name); } }
function throws(fn, match, name){
  try { fn(); fail++; console.log('FAIL (no throw): ' + name); }
  catch (e) { ok(e.message.includes(match), name + ` [${e.message.slice(0, 60)}]`); }
}

const BEEF = unhex(l3.beef_hex);
const HEADERS = [unhex(l3.subject_block.header_hex), unhex(l3.parent_block.header_hex)];
const TIP = l3.tip_height_at_fetch;

/* ---------- R2: rejected L3 must not poison the freshness log ---------- */
{
  const doc = SVSPV.parseBeef(BEEF);
  // level-1 merkle sibling (not the level-0 txid/client leaf) -> wrong root ->
  // header-store lookup fails AFTER verifyL2 staged freshness
  const leaf = doc.bumps[0].path[1][0];
  const pos = Buffer.from(BEEF).indexOf(Buffer.from(leaf.hash));
  ok(pos >= 0, 'R2 locate leaf hash in BEEF');
  const bad = Uint8Array.from(BEEF); bad[pos] ^= 1;
  const seen = new Map();
  throws(() => SVSPV.verifyL3(bad, l3.authority_pubkey, HEADERS, seen, TIP),
         'merkle root', 'R2 corrupt-BUMP L3 rejected');
  ok(seen.size === 0, 'R2 rejected L3 leaves freshness log empty');
  const env = SVSPV.verifyL3(BEEF, l3.authority_pubkey, HEADERS, seen, TIP, 1);
  ok(new TextDecoder().decode(env.payload) === l3.expected_payload,
     'R2 legit command still verifies after rejection');
  ok(seen.size === 1, 'R2 successful verify commits outpoints');
  // same txid again = idempotent duplicate (BMP-0002 §5.6)
  SVSPV.verifyL3(BEEF, l3.authority_pubkey, HEADERS, seen, TIP, 1);
  ok(seen.size === 1, 'R2 idempotent re-verify keeps log size');
}

/* ---------- R1: L3 must not pass without header-backed inclusion ---------- */
{
  const doc = SVSPV.parseBeef(BEEF);
  const stripped = new Uint8Array([0x01, 0x00, 0xbe, 0xef, 0x00, 0x02,
    ...doc.txs[0].raw, 0x00, ...doc.txs[1].raw, 0x00]);
  throws(() => SVSPV.verifyL3(stripped, l3.authority_pubkey, [], new Map(), TIP, 1),
         'BUMP for the subject', 'R1 stripped BEEF (zero BUMPs) rejected');
  throws(() => SVSPV.verifyL3(BEEF, l3.authority_pubkey, [], new Map(), TIP, 1),
         'non-empty header store', 'R1 empty header store rejected');
}

/* ---------- R5: a tx must not spend the same outpoint twice ---------- */
{
  const l2 = JSON.parse(fs.readFileSync('vectors/l2_live.json', 'utf8'));
  const raw = unhex(l2.raw_tx_hex);
  const parsed = SVANCHOR.parseTx(raw);
  ok(parsed.inputs.length === 1, 'R5 fixture has one input');
  const inp = parsed.inputs[0];
  const input0 = new Uint8Array([...inp.outpoint, ...SVANCHOR.serVarint(inp.scriptSig.length),
                                 ...inp.scriptSig, ...inp.sequence]);
  const tail = raw.slice(5 + input0.length);   // 4-byte version + 1-byte varint(1)
  const bad = Uint8Array.from(Buffer.concat([
    Buffer.from(raw.slice(0, 4)), Buffer.from(SVANCHOR.serVarint(2)),
    Buffer.from(input0), Buffer.from(input0), Buffer.from(tail)]));
  throws(() => SVANCHOR.verifyL2(bad, l2.prevouts, l2.authority_pubkey, new Map()),
         'duplicate outpoint', 'R5 duplicate outpoint within tx rejected');
}

/* ---------- R7: parse must preserve a zero wire nonce (JS parity) ---------- */
{
  const payload = new Uint8Array([0x4e, 0x4f, 0x4e, 0x43, 0x45, 0x30]); // "NONCE0"
  const wire = SVC.buildEnvelopeFields(0x53564331, 0x00FF, new Uint8Array(8), 0,
                                       payload, new Uint8Array(64));
  const p = SVC.parseEnvelope(wire);
  ok(p.nonce === 0, 'R7 JS parse preserves nonce 0');
  const rt = SVC.buildEnvelopeFields(p.targetId, p.action, p.params, p.nonce, p.payload, p.signature);
  ok(rt.length === wire.length && rt.every((b, i) => b === wire[i]), 'R7 JS nonce-0 roundtrip');
}

console.log(`svctest_review: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
