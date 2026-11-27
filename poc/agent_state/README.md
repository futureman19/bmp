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

## Evidence and delivery (schema v2)

Opening a v1 file upgrades it in place in one `BEGIN IMMEDIATE` transaction. No agreement, assignment or late ACCEPT is copied or discarded. A migrated assignment starts with `paid_at=NULL`, `evidence_revision=0`; it is **not** grandfathered into PAID. Unknown versions are refused. Each check appends one `evidence_history` row and advances the agreement's per-thread revision in the same commit. The journal records the exact input BEEF, payment ID, receiver time, tip hash/height, local conflict assessment, status/reason, evaluation depth, support record and whether that call authorized delivery. SQL triggers reject updates and deletes to the journal. This is not tamper protection against a database administrator.

```python
check = store.submit_evidence(thread, atomic_beef, headers=current_headers,
                              conflict_status='clear', now=receipt_time)
# Obtain the current receiver inputs AGAIN for each contemplated delivery.
decision = store.authorize_delivery(thread, headers=current_headers,
                                    conflict_status=local_conflict_status, now=decision_time)
# Only decision.authorized from this invocation is an affirmative decision.
```

These are local APIs, not peer request shapes. Supply a stable receiver-owned `HeaderStore` for the duration of each call, or `None` if unavailable. The clock and conflict assessment are trusted receiver inputs; never copy them from a message. The store derives all terms from the original signed chain and all payment coordinates from the C3 assignment. It compares actual subject bytes with the stored raw transaction inside C4 and runs C2 verification. `authorize_delivery` with no `beef` re-evaluates the exact bytes from the last revision (empty evidence if none); pass `beef=...` to replace incomplete/stale evidence for the **same** assigned payment. `evidence_history(thread)` is an ordered audit snapshot, **never** an authorization API.

| Current evidence | Durable effect / decision |
|---|---|
| `CURRENT` (`confirmed` or `zero-conf`) | First complete arrival at or before `payBy` records PAID once. Only a delivery call can return `authorized=True`. |
| `LATE` (`late-first-qualification`) | First complete evidence after `payBy`; refresh or clock rollback cannot qualify it. |
| `PENDING` | Missing evidence, parent/subject proof, local headers (`verification-unavailable`) or conflict assessment (`conflict-policy-unavailable`). No delivery; local unavailability is not a peer fault. |
| `INVALID` | Bad framing/proof, shape or binding, including `assigned-raw-mismatch`. No delivery. |
| `SUSPENDED` (`payment-revalidation-required`) | Known loss of required support or conflicted zero-conf. No delivery. Same-payment evidence on the current chain can restore previously timely assurance. |

`get(thread).state == 'PAID'` is historical, not current permission. A denied recheck writes a new reason and no current depth; it does not erase original qualification or the last complete support record. Record JSON v1 names agreement fields, policy, deadline, first complete arrival, first/latest complete depth and first/latest support lists explicitly. Public key and script bytes are hex; transaction IDs and block hashes are display hex, Merkle roots are header-wire hex, heights and times are integers. No field is inferred from a peer-declared height. A local decision covers the payment-evidence gate only: it does not send, sign, or record DELIVER, check recipient identity, run a watcher, or detect double-spends.

From `poc/`: `python -m pytest agent_state -q` and `python -m agent_state.vectors --check`. The C3 recipes reference the signed C1 envelopes and C2 transactions by their actual identifiers; they are not a new wire format.
