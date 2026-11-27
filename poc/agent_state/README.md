# Offline agreement ledger (BMP-0005 R3.1)

`agent_state.store.Store(path)` opens a dedicated local SQLite file. Use a separate connection per worker, a trusted filesystem and a trusted receiver clock (`now=` is required Unix seconds). Do not use separate databases for agreements sharing an outpoint namespace. `StateError` carries a stable refusal code via `str(error)`; SQLite I/O/locking errors propagate, not a successful transition.

```python
with Store(path) as store:
    r = store.accept(provider_ad, request, offer, accept, now=arrival)
    # Only after accept() returns has the provider committed the selection.
    r = store.ack(signed_ack, now=ack_arrival)
    pair = (r.thread, r.offer_hash, r.accept_hash)
    gate = store.authorize_payment_construction(*pair, now=decision_time)
    r = store.assign(*pair, raw=payment_bytes, parents=full_parent_bytes_list,
                     vout=payee_index, payment_id=expected_outpoint, now=assignment_time)
```

This combined reference ledger models provider acceptance and requester ACK validation; it neither issues nor transports signed messages. `accept` validates the entire supplied chain at intake (including advertisements and the inclusive `acceptBefore` cutoff). `ack` rechecks historical links and verifies the fresh signed reply. Authorization rechecks the stored bytes, exact pair, fresh ACK and inclusive `payBy`. A snapshot authorization is not a wallet reservation or a reusable signing permit. Caller policy must independently ensure enough time to deliver evidence. The caller must also authenticate its own principal, validate current identity evidence, authorize terms and enforce wallet policy. For signing integrations, serialize spend intents separately; a read-only gate does not prevent two concurrent callers from constructing candidates.

Schema v1 (`PRAGMA user_version`): one row per thread, unique offer and accept hashes, nullable unique payment ID. ACK bytes and first validated arrival times are retained. `ASSIGNED` is derived from the payment ID and raw transaction committed together in the same row, avoiding a second mutable state flag. Every transition uses `BEGIN IMMEDIATE`, FULL synchronous commits and rollback on failure. A validated but late ACCEPT is recorded separately by hash; it never selects a pair. No cleanup runs. `get(thread)` returns the immutable historical record, or `None`. Exact historical retries do not extend eligibility. An assignment retry still verifies the supplied parents and selected output, even after expiry. Different accepted bytes, conflicting ACKs, a second outpoint, or reusing an outpoint on a different pair cannot replace the first record.

An assignment is **not PAID**. It proves neither parent inclusion nor best-chain membership, confirmations, zero-conf safety, timely proof delivery, wallet approval or successful broadcast. No automatic transaction construction, signing, payment retry, refund, or network access.

From `poc/`: `python -m pytest agent_state -q` and `python -m agent_state.vectors --check`. The C3 recipes reference the signed C1 envelopes and C2 transactions by their actual identifiers; they are not a new wire format.
