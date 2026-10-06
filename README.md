# Bitcoin Machine Protocol (BMP)

An open protocol for delivering **Bitcoin-verified commands to machines** — robots,
sensors, locks, drones, vending machines — over any bearer, including no internet
at all. A machine that receives a BMP message can prove, locally:

1. **Who sent it** — ECDSA/secp256k1 envelope signature (L1)
2. **That it paid** — the command is anchored in a real fee-paying BSV
   transaction, verifiable offline from ancestor evidence (L2)
3. **That the ledger keeps it** — SPV inclusion proof (BEEF + BUMP merkle path)
   against proof-of-work-verified block headers (L3)

**Live demo:** [futureman19.github.io/sv-codes/verify/](https://futureman19.github.io/sv-codes/verify/)
— a real anchored command (txid
[`4a6f612b…b3d1`](https://whatsonchain.com/tx/4a6f612be1f8984ee13da679c1c5f7698f4d118304ca51ea98e895c4a977b3d1),
buried in block 969,795) verified layer-by-layer in your browser, trusting no server.

## Specifications

| Spec | Title | Status |
|---|---|---|
| [BMP-0000](spec/BMP-0000-bitcoin-machine-protocol.md) | Umbrella: envelope schema, verification tiers L1/L2/L3 | **Stable** |
| [BMP-0001](spec/BMP-0001-bmp-ble.md) | BMP-BLE — connectionless Bluetooth LE advertising transport | **Stable** |
| [BMP-0002](spec/BMP-0002-l2-on-chain-anchoring.md) | On-Chain Anchoring (L2) — envelopes in fee-paying transactions, offline payment evidence | **Stable** |
| [BMP-0003](spec/BMP-0003-l3-spv-inclusion.md) | SPV Inclusion (L3) — BEEF-packaged commands, BUMP merkle proofs vs local headers | **Stable** |
| [SV-0001](https://github.com/futureman19/sv-codes) | SV Code visual matrix transport (camera-readable animated grids) — companion product repo | **Stable** |

**Status labels:** *Stable* = two independent implementations (Python `poc/` +
browser JS `js/`) pass the golden vectors with bit-identical results. *Draft* =
proposed, awaiting a second implementation.

Notes: [Alignment with bsv-multicast (BRC-148/149)](spec/notes/brc-148-149-alignment.md)
— BMP L3 objects compose directly with the BEEF multicast plane.

## Implementations

- **Python** — `poc/svcode/`: `envelope` (BMP-0000), `ble` (BMP-0001),
  `tx` + `anchor` (BMP-0002), `spv` (BMP-0003: BRC-62 BEEF + BRC-74 BUMP +
  header PoW). Live demos: `poc/l2_demo.py` (broadcast an anchored command),
  `poc/l3_live.py` (assemble real BEEF from the public ledger and verify).
- **JavaScript (zero-dep, browser + Node)** — `js/`: `svc.js` (envelope/crypto),
  `ble.js`, `anchor.js`, `spv.js`. These power the in-browser verifier linked
  above.

## Tests

```bash
cd poc && pip install -r requirements.txt
python -m pytest tests -q          # 34 passed
node js_tests/svctest_l2l3.js      # 26 passed — JS vs Python byte-identical on live mainnet vectors
node js_tests/svctest_ble.js       # 25 passed — BLE parity
```

Frozen live-mainnet evidence (real txids, BEEF, BUMPs, headers, Python reference
intermediates) ships in `poc/vectors/` — every claim in this repo is replayable
offline.

## Relationship to SV Codes

**[SV Codes](https://github.com/futureman19/sv-codes)** is the flagship product
built on BMP: the visual matrix code (SV-0001), the browser scanner/transmitter,
and the sticker campaign with its BSV faucet. BMP is the open protocol layer
underneath — transport-agnostic, so the same envelope and verification stack
works over light, radio, or chain delivery.

## Status

All four BMP specs are Stable and mainnet-proven as of 2026-10-05. Next:
additional transports (reserved: BMP-RFID, BMP-LoRa), a gateway reference
implementation, and eventually submission of the family as BSV BRCs.
