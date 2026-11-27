# BMP-0005 R3 wire reference (Draft)

From `poc/`, with Python dependencies from `requirements.txt` and Node.js:

```sh
python -m agent.vectors                    # regenerate both JSON files twice; require byte equality
python -m agent.vectors --check            # same two generations, compare to published bytes, no write
python -m pytest tests/test_agent_wire.py -q
node agent/check_vectors.js                # independent Node/OpenSSL read of emitted positive bytes
python -m pytest tests -q                  # complete Python suite
```

`agent.codec.decode(raw)` verifies a complete v2 envelope and its closed payload. This is historical verification: pass `now=<receiver UNIX seconds>` to reject stale or future messages, and `recipient=(agentPin, pubkey, address)` when checking delivery to a particular party. A routing tag alone is insufficient. `WireError.code` and `.path` identify rejections. `decode` verifies the embedded requester advertisement; `agent.links.check_links(message, request, lookup, now=...)` checks the roles and references for a task message against previously decoded wire messages indexed by complete-envelope hash. Treat these in-memory objects as read-only. Neither API records arrival or grants permission to act.

`../vectors/agent/positive.json` publishes disposable test private keys (never fund), the fixed verification clock, full envelopes, and SHA-256 references. The two advertisements have separate return endpoints. `negative.json` specifies edits to those bytes: replace `remove` bytes at `offset` with `insertHex`, or append `appendZeroes` zero bytes. Each case records the clock, expected code/path, and whether reference context is needed. Encodings and signatures in the files are real; pins, payment outpoints and evidence are **wire/schema-only fixtures**, not transactions or Atomic BEEF. Proof messages reference unchanged subjects.

This is not SPV, Locus identity, payment, Dogfood, interoperability, or Stable validation. No wallet, transport, replay ledger, state machine, policy decision, live chain, or execution of message content. The independent reader checks positive envelope bytes, canonical JSON and signatures; it is not a second implementation of the full profile.
