# BMP Python reference implementation

```bash
pip install -r requirements.txt
python -m pytest tests -q          # 34 passed
node js_tests/svctest_l2l3.js      # JS parity, 26 passed (needs Node)
node js_tests/svctest_ble.js       # BLE parity, 25 passed
```

- `svcode/envelope.py`, `crypto.py`, `stream.py` — BMP-0000 core (envelope, secp256k1, stream framing)
- `svcode/ble.py` — BMP-0001 BMP-BLE codec (`make_ble_vectors.py` regenerates `vectors/ble_vectors.json`)
- `svcode/tx.py`, `anchor.py` — BMP-0002 L2 anchoring; `l2_demo.py` broadcasts a real anchored command via the SV Codes faucet
- `svcode/spv.py` — BMP-0003 L3 SPV (BEEF/BUMP/headers); `l3_live.py` assembles and verifies the live proof
- `vectors/` — golden vectors + frozen live-mainnet evidence; `js_tests/l2l3_ref.json` — Python reference intermediates for the JS parity harness

The canonical JavaScript verifiers live in `../js/`. The visual-matrix
implementation (SV-0001) lives in the companion repo,
[github.com/futureman19/sv-codes](https://github.com/futureman19/sv-codes).
