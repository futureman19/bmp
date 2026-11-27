# BMP-0005 R3 §10.5.1: offline payment shape

A passing result is a transaction ID, payee output index and fee **relative to the supplied parent bytes**. It does not mean `PAID`.

`shape.golden_agreement()` decodes the signed C1 request, offer, acceptance and acknowledgment (and the provider advertisement) at the fixture clock. It checks the message links and obtains the exact offer/accept pair from the ACK. The C1 PAYMENT outpoint is a wire placeholder; it is not the ID of a C2 transaction. Never fund the published test keys.

`build(agreement, parents, outpoints, fee, fixture_key)` takes full serialized parents and ordered `(txid, index)` pairs. It emits version 1, payee first, zero-sat `00 6a 25 || ASCII("BMPA1") || acceptHash_bytes` second, and requester change last if needed. `verify(raw, parents, agreement, *, offer_hash, vout, payment_id=None)` instead checks the **selected** payee output, without mandating the builder's order. It resolves each spent output by hashing and parsing its parent, verifies each requester signature against that output's actual script and amount, and returns `(paymentId, feeSats)`. Every signature must be strict DER with low-s (`s <= secp256k1.N // 2`) and trailing sighash byte `0x41`. Every unlocking script must be exactly two direct pushes: a one-byte length, `<DER signature || 0x41>`, then `0x21 || requester_compressed_pubkey`. PUSHDATA1/2/4, extra operations, trailing bytes and alternate encodings are rejected. The stored agreement is trusted context, never supplied by the payment sender. Malformed or mismatched shapes raise `ShapeError`.

## Reproduce

From `poc/`, use Python with `requirements.txt` installed and Node.js. The independent payment check needs `@bsv/sdk` **4.1.0** resolvable by Node (if already installed elsewhere, set `NODE_PATH` to that `node_modules` directory). No network is used by these commands:

```sh
python -m agent_payment.vectors          # generate twice, byte-compare, write both JSON files
python -m agent_payment.vectors --check  # repeat and compare to checked-in bytes; no writes
python -m pytest agent_payment -q
python -m pytest tests/test_agent_wire.py -q
python -m pytest -q                      # complete Python suite, including C2
node agent_payment/check_sdk.js           # SDK parses txs/parents and executes P2PKH Spend.validate()
node agent/check_vectors.js              # independent C1 Node/OpenSSL envelope check
for f in js_tests/svctest_*.js; do node "$f" || exit 1; done
```

`../vectors/agent_payment/{positive,negative}.json` contain complete subject and synthetic parent hex per case. Positive fixtures cover change, no change and a nonzero payee index; each spends two distinct prevouts. Most negative output changes are re-signed, so the expected rejection is about shape rather than an accidentally stale signature. The signed-other-outputs case intentionally leaves both signatures unchanged; the independent SDK must reject it.

## Limits

No SPV, Atomic BEEF, BUMP or mined-parent proof. Parent ancestry, spendability and chain inclusion are not checked. No double-spend detection, unique outpoint ledger, durable acknowledgment, freshness policy beyond the historical fixture clock, Dogfood integration, wallet access, broadcast, or funded/live validation. This is not a general Script interpreter or a claim of interoperability with a live wallet. Script references: [BRC-16 P2PKH](https://bsv.brc.dev/scripts/0016.md), [BRC-18 false return](https://bsv.brc.dev/scripts/0018.md); the payment commitment contract is BMP-0005, not a BRC payment profile.
