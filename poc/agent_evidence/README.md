# BMP-0005 C4: offline payment evidence

`agent_evidence.evaluate(...)` returns a frozen `Result`, never a payment or delivery state transition. Pass the stored C2 `Agreement`, acknowledged `offer_hash`, assigned PAYMENT `txid`, `payment_id`, integer `vout` and `amount_sats`; `pay_by` and `policy` must come from the same stored agreement. Supply a stable receiver-owned BMP-0004 `HeaderStore` (serialize reads against updates), the raw Atomic BEEF bytes, receiver-observed `arrival` time, and local watcher result `conflict_status` (`clear`, `conflicted`, `unavailable`). Pass `b''` for no evidence. Do not accept prior decisions, header-store anchors, watcher status, or arrival times from the peer.

| Local status | Meaning |
|---|---|
| `CURRENT` | The assigned payment meets its current evidence policy and its first complete evidence was timely. `zero-conf` is not finality. |
| `LATE` | First complete evidence arrived after `pay_by`; a refresh cannot make it timely. |
| `PENDING` | Evidence or a trusted local service is missing. `verification-unavailable` means a computed root cannot be anchored locally; it is **not** a request to the peer for another proof. |
| `SUSPENDED` | `payment-revalidation-required`: known conflict under zero-conf policy or loss of required best-chain support; history is not current assurance. |
| `INVALID` | Binding, framing, proof, C2 shape, or caller-input failure. No current assurance. |

On recheck/refresh pass the **last trusted local record**, including after `LATE`, `PENDING`, or `SUSPENDED`. `record` may be historical even when not `CURRENT`. It binds the assignment and terms, preserves first complete arrival, first support/depth and most recent complete support/depth. Result depth is computed from the current best tip only for a complete evaluation. Roots use header-wire hex; txids and block hashes use display hex. The BUMP height is never a trust input. A local miss is distinguishable from an orphaned block when the store still knows the prior block hash. A new complete proof can replace lost support without changing the assignment.

This layer does not validate envelope expiry, PROOF-to-PAYMENT linkage, task liveness, or durable assignment. The caller must check those separately before using a refresh; expired envelopes are not admitted as new payments. No broadcast, conflict detection, second payment, persistence, PAID transition, or delivery is performed.

## Offline verification (from `poc/`)

```
python agent_evidence/vectors.py --check
python -m pytest tests agent_payment agent_state agent_evidence -q
node agent_evidence/check_sdk.js
```

The generator uses the checked-in C2 bytes and mines deterministic **test-only** headers (`0x207fffff`) against a separately injected PoW limit. Tests use actual fork choice, proof of work, linkage and best-chain root lookup. Nothing here proves a mainnet payment. The local SDK check uses `@bsv/sdk` from `NODE_PATH` (verified with 3.1.0, not a claim about 4.1.0); it independently checks Atomic BEEF subjects, full prevouts, and BUMP roots, not receiver policy or persistence. `agent_payment/check_sdk.js` separately validates the spends. Standards: [BRC-62](https://bsv.brc.dev/transactions/0062), [BRC-74](https://bsv.brc.dev/transactions/0074), [BRC-95](https://bsv.brc.dev/transactions/0095). No upstream network queries are needed or performed.
