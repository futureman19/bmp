# BMP-0005 — Agent Interaction Profile: Authenticated Paid Tasks

| | |
|---|---|
| **Number** | BMP-0005 |
| **Title** | Agent Interaction Profile — Authenticated Paid Tasks |
| **Status** | **Draft — unimplemented; no interoperability or conformance claim** |
| **Revision** | R3.1 — canonical payment-script hardening |
| **Category** | Protocol Specification (Bitcoin Machine Protocol) |
| **Created** | 2026-11-26 |
| **Requires** | BMP-0000; BRC-62, BRC-74, BRC-95 for evidence; Locus Protocol v3 for identity anchors |
| **Profile identifier** | `bmp-agent/1` |

---

## 1. Abstract

BMP-0005 defines a minimum interaction profile by which two independently operated software agents can discover one another, authenticate, negotiate a fixed-price digital task, authorize and evidence a BSV payment, deliver a result, and issue a portable receipt.

The profile composes existing components rather than replacing them:

- **BMP** supplies the signed envelope and evidence philosophy.
- **Locus** supplies a persistent agent identity anchor.
- **Dogfood** is the reference policy and signing boundary, not a required implementation.
- **Gryd** is a discovery and presentation layer, not a trusted protocol authority.
- **BSV** supplies payment and durable transaction evidence.

The initial profile intentionally supports one interaction: a requester pays a provider for an inline digital deliverable. It does not claim that payment and fulfillment are atomic, that a deliverable is correct, or that an agent is safe merely because its signatures verify.

## 2. Scope and non-goals

### 2.1 In scope

1. Self-signed agent service advertisements.
2. Discovery through an untrusted directory such as Gryd.
3. Locus-anchored identity binding.
4. Signed request, offer, acceptance, provider acceptance acknowledgment, payment notice, delivery, receipt, proof-repair, and rejection messages.
5. Fixed-price BSV P2PKH settlement with Atomic BEEF evidence.
6. Expiry, replay rejection, duplicate handling, and fail-closed state transitions.
7. Offline verification of stored protocol transcripts, subject to the evidence requirements below.

### 2.2 Out of scope for `bmp-agent/1`

- Delegated or rotating agent keys.
- Recovery from owner-key loss.
- Reputation scores, certificates, or selective disclosure.
- Private/encrypted payload serialization.
- High-frequency chat or streaming.
- On-chain anchoring of agent messages.
- Physical actuation and offline machine transports.
- x402, OSP grants, 1Sat sales, OTDA, SHIP/SLAP, and other settlement or discovery protocols.
- Refunds, escrow, disputes, arbitration, or proof that work was performed correctly.
- Any guarantee that Gryd, Dogfood, or a particular model provider must remain available.

These omissions are deliberate scope boundaries, not claims that the subjects are unimportant.

## 3. Roles and trust boundaries

- **Owner:** the human or organization that controls an agent's root authority.
- **Agent:** software acting under an owner-defined directive and local policy.
- **Requester:** the agent requesting a task and supplying payment.
- **Provider:** the agent offering and delivering the task result.
- **Directory:** a service that stores and returns signed advertisements. Gryd is the reference directory.
- **Verifier:** software checking envelope, identity, payment, delivery, and receipt evidence.

A directory is a witness and cache. It MUST NOT be able to alter an advertisement or transcript without invalidating a signature or hash.

A model MUST NOT receive an owner root private key. An implementation MAY let a model request an envelope signature, but the signing boundary MUST apply local policy before key use. Cryptographic validity never overrides local policy.

## 4. Relationship to BMP-0000

BMP-0000 version `0x01` assumes that each `Target_ID` has one provisioned authority key. That model fits pre-provisioned machines but does not support permissionless, bidirectional messaging between previously unknown agents.

BMP-0005 therefore defines **envelope version `0x02`**. It retains the 85-byte BMP header and compact signature shape but defines agent-specific target derivation, authority resolution, `Params`, `Nonce`, and replay semantics.

Implementations MUST NOT interpret a version `0x02` agent envelope under BMP-0000 version `0x01` authority rules. Existing BMP-0000 parsers are expected to reject unknown versions.

BMP-0005 version `0x02` envelopes are not valid BMP-0002 L2 or BMP-0003 L3 messages. Agent-message anchoring requires a separate document. Payment and identity evidence nevertheless use BEEF/BUMP directly as specified here.

## 5. Agent envelope

### 5.1 Binary layout

All multi-byte integers are big-endian. The fixed header remains 85 bytes.

| Offset | Size | Field | `bmp-agent/1` rule |
|---|---:|---|---|
| `0x00` | 1 | `Version` | Exactly `0x02`. |
| `0x01` | 4 | `Target_ID` | Derived from the recipient public key (§5.2). |
| `0x05` | 2 | `Action_Code` | One of §8.1. |
| `0x07` | 4 | `Created_At` | Unsigned UNIX seconds. |
| `0x0B` | 4 | `Expires_At` | Unsigned UNIX seconds; greater than `Created_At`. |
| `0x0F` | 4 | `Nonce` | First four bytes of the decoded `messageId`. |
| `0x13` | 2 | `Payload_Length` | Exact byte length of `Payload_Data`. |
| `0x15` | 64 | `Signature` | Low-s secp256k1 compact `r || s`. |
| `0x55` | n | `Payload_Data` | Canonical JSON payload (§5.4). |

The complete serialized length MUST be exactly `85 + Payload_Length` bytes. `Payload_Length` MUST NOT exceed 65,535. Implementations MAY enforce a smaller advertised limit.

### 5.2 Target derivation

```text
Target_ID = uint32_be(first_4_bytes(
  SHA256(ASCII("BMP-AGENT/1") || recipient_compressed_public_key_bytes)
))
```

The recipient public key is the `to.pubkey` value in the signed payload. A receiver MUST recompute this value and reject a mismatch.

`Target_ID` is a routing hint, not a globally unique identity. A 32-bit collision does not authorize delivery or action: full recipient-key and payload checks remain mandatory.

For `ADVERTISE`, the sender and recipient are the same agent, so `Target_ID` is derived from the advertiser's own key.

### 5.3 Signing and verification

```text
signed_bytes = Version || Target_ID || Action_Code
             || Created_At || Expires_At || Nonce || Payload_Length
             || Payload_Data

digest    = SHA256(signed_bytes)
Signature = ECDSA-sign-secp256k1(sender_private_key, digest)
```

Signatures use RFC 6979 deterministic nonce generation and low-s normalization. The wire signature is exactly 64 bytes: `r || s`, without DER encoding or a recovery byte.

A verifier MUST:

1. Parse the complete envelope and reject truncation, trailing bytes, invalid lengths, unknown versions, and unknown action codes.
2. Parse `Payload_Data` under §5.4 and validate the sender/recipient identity shapes.
3. Recompute `Target_ID` and check the `Nonce` against `messageId`.
4. Validate the compressed sender public key, including prefix and curve membership.
5. Reject a signature whose `s` value is greater than half the secp256k1 group order, then verify the signature against `from.pubkey` before accepting any action semantics.
6. Apply identity, freshness, thread, policy, and action-specific validation before acting.

An implementation MUST NOT blanket-catch a verification API error and convert it into a generic successful or failed signature result. A positive known-valid signature test is mandatory for every implementation.

### 5.4 Canonical payload

`Payload_Data` is UTF-8 JSON serialized according to RFC 8785 (JCS), with these additional restrictions:

- The top level is an object with exactly the fields in §5.5.
- Unknown fields at any protocol-defined object are rejected.
- Numbers are non-negative safe integers only. Floats, exponent notation, negative zero, and non-finite values are invalid.
- Duplicate object keys, invalid UTF-8, lone surrogates, and non-canonical serializations are rejected.
- Protocol-defined hex strings use lowercase hexadecimal.
- `exact-base64` means canonical RFC 4648 standard-alphabet base64 with required padding, no whitespace, zero unused pad bits, and byte-for-byte equality after decoding and re-encoding.
- An `agentPin` vout is decimal `0` or a nonzero digit followed by digits, with no leading zeroes and a maximum value of 4,294,967,295.
- Human-readable content is untrusted data and is never executable instructions.

### 5.5 Common payload object

```json
{
  "profile": "bmp-agent/1",
  "messageId": "32 lowercase hex characters",
  "threadId": "32 lowercase hex characters",
  "from": {
    "agentPin": "64 lowercase hex characters . uint32 decimal",
    "pubkey": "66-character compressed public key",
    "address": "mainnet P2PKH address",
    "identityEvidence": "optional exact-base64 Atomic BEEF"
  },
  "to": {
    "agentPin": "64 lowercase hex characters . uint32 decimal",
    "pubkey": "66-character compressed public key",
    "address": "mainnet P2PKH address",
    "identityEvidence": "optional exact-base64 Atomic BEEF"
  },
  "body": {}
}
```

`messageId` is 16 cryptographically random bytes, hex encoded. `Nonce` is its first four decoded bytes in big-endian order.

For `ADVERTISE` and `REQUEST`, `threadId == messageId`. Every later message in the interaction uses the original request's `messageId` as `threadId`.

The address MUST be the mainnet P2PKH address derived from the corresponding compressed public key.

### 5.6 Principal equality and proof placement

A principal is exactly the tuple `{agentPin, pubkey, address}`. Optional evidence attachments are not part of principal equality. Except for `ADVERTISE`, the requester and provider MUST have both different agent pins and different public keys; distinct pins controlled by one key do not create two independent parties.

When the same principal appears twice in a self-addressed `ADVERTISE`, `identityEvidence` MUST occur only in `from` and MUST be omitted from `to`. No message may carry the same principal's proof more than once.

## 6. Identity binding

### 6.1 Locus identity anchor

An `agentPin` references the tip output of a Locus v3 `mint` transaction. The transaction MUST satisfy every applicable Locus mint rule, including required common/mint fields and canonical payload rules, not merely the fields listed here. The profile intentionally requires `type = "agent"`; a `type = "object"` / `subtype = "AGENT"` record is not a substitute.

The conforming payload has:

```text
p = "locus"
v = 3
op = "mint"
type = "agent"
owner = address derived from owner_pubkey
owner_pubkey = the Identity.pubkey in this profile
```

For each output beginning with the Locus-accepted `OP_RETURN` forms, a verifier concatenates all pushes according to the Locus discovery rule before parsing JSON; a single-push-only decoder is insufficient. The mint transaction MUST contain exactly one Locus payload and it MUST be the unique conforming agent-mint payload. Competing or additional Locus payloads are rejected rather than resolved by first-match behavior.

The referenced `agentPin` vout MUST identify an output in that transaction paying exactly 1 satoshi by plain P2PKH to the owner address. Explicit vout selection resolves other non-Locus outputs; no first-matching-output rule is permitted.

### 6.2 Identity evidence

`identityEvidence`, when present, is exact-base64 Atomic BEEF whose subject is the referenced agent-mint transaction. A chain-anchored identity check requires:

1. Atomic BEEF structural and subject validation, with the mint transaction present in full.
2. Complete ancestry for any unmined dependencies and authenticated mined boundaries required by the SPV implementation.
3. A BUMP proving inclusion of the mint transaction.
4. Merkle-root validation against a header accepted by the verifier's trusted, most-chainwork header store under BMP-0004.
5. The Locus payload, tip, owner, and key checks in §6.1.

BRC-96 txid-only shorthand, an indexer assertion, a bare txid, and a fetched transaction without inclusion evidence are not substitutes for this proof.

### 6.3 Evidence caching and failure

`ADVERTISE` MUST carry the advertiser's `identityEvidence`. A `REQUEST` or `OFFER` SHOULD carry the sender's evidence unless the receiver can obtain it from a validated advertisement or durable cache.

If peer-supplied identity evidence is absent or invalid, the receiver MAY issue a non-terminal `REJECT` with `identity-proof-required`; the sender repairs it through `PROOF` (§10.8) without changing the original message or its hash. If the receiver lacks trusted headers or another local resource needed to evaluate otherwise complete evidence, it returns a local `verification-unavailable` result and leaves the subject pending. It MUST NOT ask the peer to repair a local outage.

Later messages MAY omit evidence only when the receiver has durably cached a valid binding for that exact principal. A cached decision records the supporting block header/root and validation time. Before relying on a cached identity to authorize any new paid-task state transition, the receiver MUST recheck that the mint's supporting block remains in its best chain. Loss of best-chain membership marks the identity `not-currently-included` and blocks new paid-task actions until valid evidence is restored; it does not erase or rewrite historical observations.

### 6.4 What the identity anchor does not prove

The anchor proves that a particular Locus mint binds an agent identifier to a public key and that the current message signer controls that key. It does not prove:

- current ownership of the latest pin tip;
- owner humanity, competence, honesty, or reputation;
- consent implied solely by permissionless Locus attribution;
- key safety or absence of compromise.

Consent to use the anchor in this profile comes from the agent's signed advertisement or message, not from Locus attribution alone. Pin transfer, rotation, recovery, and delegated session keys are deferred.

## 7. Discovery through Gryd or another directory

A directory advertisement is an `ADVERTISE` envelope whose `from` and `to` are the same identity.

A directory MUST store and return the original envelope bytes and MUST NOT synthesize identity or service evidence. Before listing an advertisement as verified, it MUST validate:

- the complete agent envelope;
- the self-addressed `ADVERTISE` semantics;
- the chain-anchored identity binding;
- freshness and expiry;
- the endpoint and service schema.

A directory MAY apply additional anti-spam, availability, and presentation policy. It MUST distinguish `signature-valid`, `identity-anchored`, and `recently-online`; none implies service quality.

A lookup response MUST return the original signed advertisement bytes. A client revalidates them rather than trusting a directory's `verified` label. Gryd can index Locus objects and advertisements, but no directory is a required message relay or protocol authority.

## 8. Message registry and common rules

### 8.1 Action codes

Codes below occupy the BMP vendor range under envelope version `0x02`; they do not modify BMP-0000's version `0x01` core registry.

| Code | Mnemonic | Sender → recipient |
|---|---|---|
| `0xA000` | `ADVERTISE` | Provider → self/directory |
| `0xA001` | `REQUEST` | Requester → provider |
| `0xA002` | `OFFER` | Provider → requester |
| `0xA003` | `ACCEPT` | Requester → provider |
| `0xA009` | `ACCEPT_ACK` | Provider → requester |
| `0xA004` | `PAYMENT` | Requester → provider |
| `0xA005` | `DELIVER` | Provider → requester |
| `0xA006` | `RECEIPT` | Requester → provider |
| `0xA007` | `REJECT` | Either party → the other |
| `0xA008` | `PROOF` | Original subject sender → original recipient |

Unknown actions are rejected. The action-specific payload schemas below are closed in `bmp-agent/1`.

### 8.2 Freshness and retention

- `Created_At` MUST NOT be more than 300 seconds ahead of the receiver's clock. It is sender-asserted metadata, not independent evidence of sending or arrival time.
- `Expires_At` MUST be greater than `Created_At` and no more than the action's maximum validity window: seven days for `ADVERTISE`; one hour for `REQUEST` and `OFFER`; 15 minutes for `ACCEPT` and `ACCEPT_ACK`; and 24 hours for `PAYMENT`, `DELIVER`, `RECEIPT`, `REJECT`, and `PROOF`.
- A task message also expires no later than 24 hours after its originating request's `deliverBy`.
- New messages arriving after `Expires_At` are rejected. Expiry stops new pending actions; it never regresses an already accepted, paid, or delivered state.
- Stored historical messages remain cryptographically verifiable after expiry. Live online decisions additionally use the receiver's first validated arrival time as defined in §10.
- Replay conflict detection is keyed by `(threadId, from.pubkey, messageId)`. Receivers retain live thread state until 24 hours after the request's `deliverBy`, rather than for an arbitrary sender-supplied far-future expiry. Long-term evidence retention is a separate owner/policy decision.

### 8.3 References and hashes

Whenever a message references a previous message, the reference is the SHA-256 hash of that previous message's **complete serialized envelope, including its signature**, encoded as 64 lowercase hex characters.

```text
advertisementHash = SHA256(serialized ADVERTISE envelope)
requestHash       = SHA256(serialized REQUEST envelope)
offerHash         = SHA256(serialized OFFER envelope)
acceptHash        = SHA256(serialized ACCEPT envelope)
paymentHash       = SHA256(serialized PAYMENT envelope)
deliveryHash      = SHA256(serialized DELIVER envelope)
subjectHash       = SHA256(serialized referenced envelope)
```

Hashing the complete signed envelope binds the header, payload, identities, action, and signature. Implementations MUST NOT hash a reserialized approximation or an unsigned display object.

A payment also has a stable, proof-independent identifier:

```text
paymentId = payment_txid || "." || canonical_decimal(payment_vout)
```

`paymentId` identifies the exact payment outpoint across evidence refreshes. `paymentHash` identifies one signed payment notice. `DELIVER` and `RECEIPT` bind to `paymentId`; proof repair does not change it.

## 9. Paid-task state machine

```text
DISCOVERED
  → REQUESTED
  → OFFERED
  → ACCEPTED
  → PAID
  → DELIVERED
  → ACKNOWLEDGED
```

`REJECTED` and `EXPIRED` apply only to the pending message, offer, or pre-acceptance thread they target. They never erase or regress an established `ACCEPTED`, `PAID`, or `DELIVERED` record. A terminal rejection of an unselected offer does not reject sibling offers or the originating request.

`PROOF` supplies evidence for an immutable subject hash and causes no standalone state transition. The receiver evaluates a pending original subject only after the required proof arrives. For a previously accepted payment whose current assurance was suspended, PROOF instead revalidates the unchanged subject under §10.5.3. A non-terminal `REJECT` carrying `identity-proof-required` or `payment-proof-required` leaves the current state unchanged.

Rules:

1. A request creates a thread. Multiple offers MAY reference it, but each party atomically selects at most one `{offerHash, acceptHash}` pair per thread. The requester durably stores the exact ACCEPT bytes before transmission. Exact-byte retries are idempotent; any distinct ACCEPT for that thread, including another ACCEPT for the same offer, is a conflict.
2. `ACCEPT` expresses agreement to exact terms; it does not itself move funds or prove that the provider accepted.
3. The provider durably enters `ACCEPTED` and stores the selected `{offerHash, acceptHash}` before issuing `ACCEPT_ACK`. The requester MUST validate that acknowledgment before authorizing payment construction, signing, or broadcast. No valid acknowledgment means no spend.
4. `PAYMENT` is valid only after the corresponding acknowledged `ACCEPT` and must match the stored offer/acceptance pair exactly. Its transaction commits to `acceptHash` under §10.5.
5. Exactly one logical `paymentId` may be accepted for an offer. A provider durably assigns each accepted `paymentId` to one `offerHash` and one `acceptHash`; reuse for another offer is a conflict, and a different payment for the same offer is not silently selected.
6. `DELIVER` is valid only after the referenced `paymentId` currently satisfies all required ancestry, confirmation, and conflict checks and must name that payment explicitly.
7. `RECEIPT` references an existing delivery and the same `paymentId`.
8. An exact duplicate serialized envelope is an idempotent duplicate. Reuse of the same `(threadId, from.pubkey, messageId)` with different bytes is a conflict and MUST be rejected.
9. Out-of-order, wrong-role, wrong-thread, wrong-party, and wrong-action transitions are rejected.
10. Terminal `REJECT` is permitted only by the recipient of a `REQUEST` before acceptance or by the requester recipient of an `OFFER` that has not been accepted. After acceptance, a party may reject an invalid incoming message without changing the established task state; self-rejection, withdrawal, post-acceptance cancellation, and refusal have no state transition in this profile.
11. A failed or ambiguous payment broadcast MUST NOT cause an automatic second payment.
12. If any required mined parent loses best-chain membership, a known conflict invalidates a zero-conf subject under provider policy, or a one-block subject loses best-chain membership/depth, the provider records `payment-revalidation-required` and withholds delivery until valid evidence is restored. This changes current assurance, not the historical fact that evidence was once accepted.

Protocol state is derived from verified messages and evidence, not from a directory's display state. Locally observed arrival, current inclusion, and assurance status are recorded separately from the portable signed facts.

## 10. Action payloads

### 10.1 `ADVERTISE`

```json
{
  "endpoint": "https://provider.example/bmp-agent/1",
  "services": [
    {
      "kind": "research.summary",
      "description": "Short source-backed research summary",
      "maxTaskBytes": 4096,
      "maxDeliveryBytes": 16384
    }
  ]
}
```

Rules:

- `endpoint` is one absolute HTTPS URL with no embedded credentials or fragments.
- `services` contains 0–16 entries with unique, lowercase `kind` strings of 1–64 characters matching `[a-z][a-z0-9._-]*`. A requester-only advertisement MAY use an empty list; a provider advertisement selected by a REQUEST MUST contain the requested service.
- `description` is 1–280 UTF-8 bytes.
- Limits are positive safe integers no greater than 65,535.
- The advertisement expiry is at most seven days after creation.

The service registry is application-level. A directory MUST treat descriptions as untrusted text.

### 10.2 `REQUEST`

```json
{
  "providerAdvertisementHash": "64 lowercase hex characters",
  "requesterAdvertisementHash": "64 lowercase hex characters",
  "requesterAdvertisement": "exact-base64 serialized requester ADVERTISE envelope",
  "service": "research.summary",
  "task": "Summarize the specified sources and distinguish direct evidence from inference.",
  "maxPriceSats": 5000,
  "deliverBy": 1795700000,
  "deliveryMime": "text/markdown",
  "maxDeliveryBytes": 16384
}
```

Rules:

- Both advertisement hashes reference valid, unexpired `ADVERTISE` envelopes. The provider advertisement belongs to `to` and was obtained during discovery. `requesterAdvertisement` decodes to the complete requester ADVERTISE, hashes to `requesterAdvertisementHash`, belongs to `from`, and supplies the provider's return path. The requester identity's optional inline evidence is omitted when already carried by this embedded advertisement.
- `service` exactly matches one entry in the selected provider advertisement. The request's `task` UTF-8 length MUST NOT exceed that entry's `maxTaskBytes`.
- `task` is 1–4,096 UTF-8 bytes and is untrusted content.
- `maxPriceSats` is a positive safe integer.
- `deliverBy` is a UNIX time later than `Expires_At` and no more than 30 days after creation.
- `deliveryMime` is lowercase ASCII `type/subtype`, at most 100 bytes.
- `maxDeliveryBytes` is 1–16,384 and no greater than the selected advertisement entry's `maxDeliveryBytes`.

The two hashes bind discovery, the provider's offered service and limits, and both parties' return paths into the paid-task transcript.

### 10.3 `OFFER`

```json
{
  "terms": {
    "requestHash": "64 lowercase hex characters",
    "priceSats": 2500,
    "paymentAddress": "provider mainnet P2PKH address",
    "acceptBefore": 1795690000,
    "payBy": 1795695000,
    "deliverBy": 1795700000,
    "confirmationPolicy": "zero-conf",
    "deliveryMime": "text/markdown",
    "maxDeliveryBytes": 16384
  }
}
```

Rules:

- `requestHash` references a valid request in the same thread and transitively binds the selected provider advertisement.
- `priceSats` is positive and no greater than the request's `maxPriceSats`.
- `paymentAddress` equals the provider identity address.
- The chronology MUST satisfy `OFFER.Created_At < acceptBefore <= payBy < deliverBy`; `acceptBefore` is also no later than the offer envelope's `Expires_At`.
- `deliverBy` is no later than the request deadline and later than `payBy`.
- `confirmationPolicy` is exactly `zero-conf` or `one-block`.
- `deliveryMime` exactly equals the request's MIME value; there is no subtype ordering or wildcard matching.
- `maxDeliveryBytes` exactly matches or is smaller than both the request and selected advertisement limits.

`zero-conf` is an explicit provider risk decision for low-value tasks, not a finality claim. Higher-value deployments SHOULD require `one-block` or a later stronger settlement profile.

### 10.4 `ACCEPT`

```json
{
  "offerHash": "64 lowercase hex characters"
}
```

The referenced offer MUST be valid and not superseded by another accepted offer in the same thread. The provider applies the acceptance cutoff using its own first validated arrival time: an `ACCEPT` first arriving at or before `acceptBefore`, and no later than its own `Expires_At`, may be timely; later arrival is recorded as late and does not enter `ACCEPTED`. Equality at the cutoff is accepted.

The requester signs only after its local policy authorizes the exact task, provider, price, and deadlines. Before transmission it durably stores the exact serialized ACCEPT and its `{offerHash, acceptHash}`. `Created_At` alone cannot establish timely acceptance.

The provider atomically records at most one `{offerHash, acceptHash}` for the thread. A repeated byte-identical ACCEPT returns the same stored acknowledgment; a distinct ACCEPT is a conflict, even when it names the same offer.

### 10.4.1 `ACCEPT_ACK`

```json
{
  "offerHash": "64 lowercase hex characters",
  "acceptHash": "64 lowercase hex characters"
}
```

The provider sends `ACCEPT_ACK` only after its acceptance-cutoff, identity, policy, uniqueness, and durable-state checks succeed. It MUST reference the stored offer and exact serialized ACCEPT. A duplicate ACCEPT elicits the same acknowledgment without creating a new transition.

The requester MUST verify the provider signature, thread/roles, stored pair, and freshness before entering its local payment-authorized state, and MUST still be able to deliver required payment evidence by `payBy`. Payment construction, signing, and broadcast remain blocked until this verification succeeds. An HTTP success response, unsigned acknowledgment, or locally sent ACCEPT is insufficient.

### 10.5 `PAYMENT`

```json
{
  "offerHash": "64 lowercase hex characters",
  "txid": "64 lowercase hex characters",
  "vout": 0,
  "amountSats": 2500,
  "atomicBeef": "optional exact-base64 Atomic BEEF"
}
```

`paymentId` is the canonical string `txid.vout`. The `atomicBeef` field MAY be omitted only while evidence is pending; `PAID` requires the evidence through this field or a later `PROOF` referencing this exact PAYMENT envelope.

#### 10.5.1 Offer-bound transaction shape

The payment transaction MUST commit to the signed acceptance, not merely pay a reusable address. It MUST have:

1. `nLockTime = 0` and `nSequence = 0xffffffff` on every input. Non-final or time-locked payment forms are outside this profile.
2. Only P2PKH inputs whose evidenced prevouts pay the **requester identity address**. Every input signature MUST use exactly `SIGHASH_ALL | FORKID` (`0x41`), committing to all outputs, including the acceptance commitment. Each signature MUST use strict DER and low-s (`s <= n/2`). The unlocking script MUST be exactly two canonical direct pushes: `<signature || 0x41>` followed by the 33-byte compressed requester pubkey; `OP_PUSHDATA1/2/4`, extra operations, and alternate encodings are invalid. Sponsored, third-party, and mixed-payer inputs are excluded.
3. The payee output selected by `vout`: exactly `priceSats` by plain mainnet P2PKH to the offer's `paymentAddress`.
4. Exactly one zero-satoshi commitment output:

   ```text
   OP_FALSE OP_RETURN <one 37-byte push: ASCII("BMPA1") || acceptHash_bytes>
   ```

   `acceptHash_bytes` is the 32-byte SHA-256 hash of the complete serialized ACCEPT envelope. Exactly one such commitment output MUST exist and its hash MUST equal the accepted offer's `acceptHash`.
5. Optionally, one change output paying the requester identity address by plain P2PKH. No other outputs are permitted in `bmp-agent/1`.
6. A positive fee computed from evidenced input values minus actual output values.

Because every input is requester-controlled and signed `0x41`, the transaction proves requester authorization of the payee output and the exact accepted agreement. A valid payment to the same address for another offer cannot satisfy these rules.

#### 10.5.2 Evidence validation

The provider MUST validate:

1. The referenced acknowledged offer, thread roles, stored `{offerHash, acceptHash}`, and transaction shape in §10.5.1.
2. Atomic BEEF structure and that its full subject transaction's txid equals `txid`.
3. That `vout` is a uint32 identifying the actual payee output and `amountSats` is a positive safe integer equal to `priceSats`.
4. For every subject input, the exact referenced parent transaction and prevout. Every parent MUST be mined, present in the Atomic BEEF, and supplied with a BUMP resolving to a trusted header. Unconfirmed ancestors are excluded from `bmp-agent/1`.
5. Each input's prevout address, `0x41` sighash, signature, and P2PKH script validity, plus the transaction's structural validity and positive fee.
6. That no txid-only, implicitly trusted, unrelated, or conflicting entries substitute for required full transactions and proofs.
7. For `zero-conf`, the provider's explicit double-spend policy in addition to the mined-parent requirement. This is a minimum evidence policy: the subject MAY be unconfirmed, while later best-chain confirmation is stronger replacement evidence for the same `paymentId`, never a new logical payment.
8. For `one-block`, a subject-transaction BUMP whose Merkle root resolves to a trusted best-chain header with at least one-block depth under BMP-0004, in addition to every mined-parent requirement.

A bare txid, explorer response, directory assertion, or BRC-96 txid-only shorthand is insufficient. The profile never describes an unconfirmed payment as final.

The provider's first validated arrival of the PAYMENT **with all evidence required by its confirmation policy** establishes the payment-arrival time. It MUST be at or before `payBy` to enter `PAID`; equality is accepted. A PAYMENT notice without evidence remains pending and does not stop the deadline. Late payment is recorded as late and does not authorize delivery, automatic repayment, or refund.

#### 10.5.3 Unique assignment, evidence refresh, and reorg

Before entering `PAID` or permitting delivery, the provider MUST atomically and durably assign the `paymentId` to one `{offerHash, acceptHash}`. Re-presenting the same assignment is idempotent. Assigning that outpoint to another offer is a conflict, and accepting a different `paymentId` for the same offer is a conflict. This assignment MUST NOT expire with replay-thread state.

A `PROOF` message MAY refresh evidence for the same `paymentId` without changing the original PAYMENT bytes, `paymentHash`, offer, payee, amount, or logical payment. It MUST reference the original `paymentHash`; refreshed evidence never creates a replacement payment notice.

The provider records every supporting parent block/root, plus the subject block/root when the subject is confirmed. Before delivery it rechecks that every required parent remains in the best chain, applies its current zero-conf conflict policy, and rechecks subject membership/depth when applicable. If required support is lost or a known conflict invalidates a zero-conf subject, current payment assurance becomes `payment-revalidation-required` and delivery waits. Historical evidence, first-qualification time, and the durable payment assignment remain recorded.

First qualification and restoration are different operations. Evidence required for the first transition into `PAID` MUST arrive by `payBy`. After a timely `PAID` transition, a later PROOF MAY restore current assurance for the same outpoint after `payBy` or after the original PAYMENT envelope's expiry while the task remains live. It never makes a payment that first qualified late become timely.

No ambiguity, rejection, proof refresh, or timeout automatically triggers a second payment or refund.

### 10.6 `DELIVER`

```json
{
  "offerHash": "64 lowercase hex characters",
  "paymentId": "64 lowercase hex characters . canonical uint32 decimal",
  "mime": "text/markdown",
  "content": "# Result\n\nThe delivered UTF-8 content."
}
```

Rules:

- The offer is accepted and acknowledged, `paymentId` is the unique payment assigned to it, and that payment currently satisfies all required parent-inclusion, conflict-policy, and subject-confirmation requirements.
- `mime` exactly equals the accepted offer's MIME value and the content length satisfies the accepted byte limit.
- `content` is valid UTF-8 and at most `maxDeliveryBytes` bytes.
- The requester records its first validated arrival time. Arrival at or before `deliverBy` is timely; equality is accepted. A later valid delivery is retained as `late` evidence but is not represented as timely.
- `Created_At` proves only a sender assertion. A stored offline transcript proves which signed bytes exist, not when they actually arrived.
- Content remains untrusted. It is never executed or fed to a model as trusted instructions.

### 10.7 `RECEIPT`

```json
{
  "offerHash": "64 lowercase hex characters",
  "deliveryHash": "64 lowercase hex characters",
  "paymentId": "64 lowercase hex characters . canonical uint32 decimal",
  "outcome": "accepted"
}
```

`outcome` is exactly `accepted` in this profile. The delivery and payment MUST belong to the same accepted offer and thread, and `paymentId` MUST equal the payment referenced by the accepted DELIVER. A receipt acknowledges receipt/acceptance by the requester; it does not prove objective quality, timely arrival, or current chain inclusion and cannot undo payment or delivery evidence.

Absence of a receipt does not erase a valid signed delivery. Disputes and negative outcomes require a later document.

### 10.8 `PROOF`

Identity proof variant:

```json
{
  "subjectHash": "64 lowercase hex characters",
  "proofKind": "identity",
  "agentPin": "64 lowercase hex characters . canonical uint32 decimal",
  "atomicBeef": "exact-base64 Atomic BEEF"
}
```

Payment proof variant:

```json
{
  "subjectHash": "64 lowercase hex characters",
  "proofKind": "payment",
  "atomicBeef": "exact-base64 Atomic BEEF"
}
```

Rules:

- `subjectHash` references the exact earlier message whose evidence is pending or whose previously accepted payment requires revalidation. The PROOF sender and recipient MUST equal the subject's original sender and recipient, and the thread MUST match.
- For `identity`, `agentPin` is required and MUST identify the subject sender's principal. The Atomic BEEF subject MUST be the corresponding Locus mint and pass §6. The `payment` variant MUST NOT contain `agentPin`.
- For `payment`, the subject MUST be a PAYMENT envelope, the Atomic BEEF subject MUST equal its `txid`, and the logical `paymentId`, offer, payee, amount, and acceptance commitment MUST remain unchanged.
- PROOF never changes the referenced message bytes, hashes, terms, or logical action. It supplies only evidence needed to evaluate that message.
- Proof arriving after a relevant acceptance/payment deadline does not make a first-time qualification timely. The sole exception is restoration of a payment that already entered `PAID` timely: a fresh PROOF MAY revalidate its unchanged original `paymentHash` after `payBy` or subject-message expiry while the task remains live. Locally unavailable verification remains pending without a peer PROOF request loop.

### 10.9 `REJECT`

```json
{
  "subjectHash": "64 lowercase hex characters",
  "code": "policy",
  "reason": "The requested work exceeds local policy."
}
```

Allowed codes:

- `unsupported`
- `busy`
- `terms`
- `policy`
- `expired`
- `identity-proof-required`
- `payment-proof-required`
- `payment-policy`
- `malformed`
- `conflict`

`reason` is optional, untrusted, single-line UTF-8 of at most 280 bytes.

Scope is deterministic:

- An actionable REJECT is sent by the referenced subject's recipient to its sender: `from` equals `subject.to`, `to` equals `subject.from`, and the thread matches. A self-rejection or reversed-party forgery has no protocol effect.
- `identity-proof-required` is non-terminal and MAY target any received message lacking required sender identity evidence. `payment-proof-required` is non-terminal and MAY target only a received PAYMENT lacking required evidence.
- `malformed`, `conflict`, and `payment-policy` reject only the received referenced message; they do not erase another valid message or an established task state.
- Only the provider recipient of a REQUEST may terminally reject that request before acceptance. Only the requester recipient of an unaccepted OFFER may terminally reject that offer. `unsupported`, `busy`, `terms`, `policy`, and `expired` have terminal scope only in those two cases. Against any other received message they reject only that message and create no terminal thread/offer state. A request rejection closes the pre-acceptance thread; an offer rejection closes only that offer.
- `payment-policy` MAY target only a received PAYMENT. It rejects that notice without selecting another payment.
- After ACCEPT, no REJECT regresses ACCEPTED, PAID, or DELIVERED. It may reject only the referenced incoming message. Self-withdrawal, post-acceptance cancellation, refusal, and refund semantics are deferred.

A rejection never authorizes payment retry, key access, or automatic escalation.

## 11. Online transport

The initial bearer is HTTPS:

```text
POST <advertised endpoint>
Content-Type: application/octet-stream

<one complete serialized agent envelope>
```

- Both parties advertise return endpoints. A REQUEST explicitly binds the provider advertisement and the requester advertisement. The provider sends OFFER and later asynchronous messages to the requester endpoint from the selected requester advertisement; the requester uses the selected provider advertisement for provider-bound messages.
- TLS protects the connection; it does not replace the agent signature.
- HTTP success means transport receipt only. It does not prove protocol acceptance, payment, execution, or delivery.
- Protocol acceptance is represented by the next valid signed state transition or a signed `REJECT`/`PROOF` exchange.
- Request bodies MUST be bounded before parsing. Transport timeouts and retries MUST NOT repeat payment construction or signing automatically.
- A validly signed endpoint is still untrusted network input. Clients apply an explicit egress policy: by default they reject loopback, private, link-local, multicast, and cloud-metadata destinations, use no ambient credentials, bound connection/read time and response size, and disable redirects. A deployment MAY explicitly enable owner-approved local test endpoints. Any later redirect support must revalidate HTTPS and the same destination policy for every hop.
- Binary payloads containing evidence that exceed the envelope limit are rejected in `bmp-agent/1`; multipart or alternate paid-HTTP transport is deferred.

Gryd is not required to relay these messages. Direct HTTPS in both directions is sufficient once discovery has supplied both signed endpoint advertisements.

## 12. Integration boundaries

### 12.1 Dogfood

Dogfood is the reference owner-controlled policy/signing boundary. In `bmp-agent/1`:

- The agent identity public key is the Dogfood vault public key.
- The model never receives that private key.
- New signing and payment actions remain subject to the killfile and applicable policy.
- Historical verification is keyless and remains possible while spending/signing is stopped.
- `ACCEPT`, `ACCEPT_ACK`, and `PAYMENT` do not bypass caps, allowlists, permits, human approval, durable payment intent, or ambiguous-broadcast holds. The requester payment guard MUST require a valid provider ACCEPT_ACK for the stored `{offerHash, acceptHash}` before payment construction or signing.
- Dogfood's generic address/amount send is not automatically a valid `bmp-agent/1` payment. The adapter must construct the requester-input, all-output-signature, and `BMPA1 || acceptHash` commitment shape in §10.5 through the existing guarded payment path.

Dogfood's `Dogfood Auth v1` BSM signatures and its BitCom `B | MAP | AIP` agent messages are **not wire-compatible** with this profile. An adapter MUST construct and sign the exact BMP-0005 envelope; it MUST NOT detach or reuse a signature over different bytes.

Dogfood's existing agent-pin resolver checks mint structure and key binding. The chain-anchored identity requirement in §6 additionally requires inclusion evidence and trusted-header validation.

### 12.2 Locus

Locus supplies the identity anchor only. This document does not change Locus transaction formats, attribution rules, transfer semantics, or indexer governance.

### 12.3 Gryd

Gryd is the reference directory, map, onboarding surface, and interaction-history viewer. It can make the network usable without becoming a custodian or mandatory relay. Gryd-derived display state is always subordinate to signed messages and chain evidence.

### 12.4 OSP, x402, Emberhall, and physical BMP

These are later adapters:

- OSP can express scoped digital access after negotiation.
- x402 can supply a separate paid-HTTP settlement profile.
- Emberhall can map verified intents and receipts into an authoritative world without putting game ticks on-chain.
- A later physical-machine profile can translate an authorized agreement into a BMP command with the required local safety and evidence tier.

None is required to implement or verify `bmp-agent/1`.

## 13. Security and privacy considerations

1. **Signature validity is not authority sufficiency.** Local policy, owner limits, expiry, and thread state remain mandatory.
2. **Payment is not fulfillment.** This profile coordinates evidence; it does not make generic work atomic with payment.
3. **Delivery is not correctness.** A hash proves which bytes were delivered, not whether they are true, safe, or useful.
4. **Identity is not reputation.** A valid agent pin and key do not imply trustworthy behavior.
5. **No confidentiality is claimed.** The initial profile provides authentication and integrity. Payloads, endpoints, metadata, and payment linkage may be visible to transport and directory operators. Do not place secrets or private credentials in payloads.
6. **On-chain publication is not required.** Private task content should remain off-chain. A later encryption profile must define sender authentication, expiry, replay behavior, and compromise limits rather than treating encryption as sufficient by itself.
7. **Untrusted content is data.** Task text, reasons, service descriptions, and delivered content MUST NOT become executable instructions merely because they arrived in a valid envelope.
8. **Zero-conf is risk acceptance.** Providers accepting it assume double-spend risk and SHOULD restrict it to low-value interactions.
9. **Evidence availability can fail closed.** Missing headers, ancestry, identity evidence, or payment evidence produces an explicit unavailable/required result, never simulated verification.
10. **No new payment on ambiguity.** Transport failure, timeout, process restart, or an unknown broadcast result does not authorize another spend.
11. **No payment before provider acknowledgment.** A sent ACCEPT, HTTP success, or unsigned status is insufficient. Only a valid ACCEPT_ACK for the requester's stored offer/acceptance pair unlocks payment construction and signing.
12. **Key recovery is unresolved.** Owners require an out-of-band recovery process until a later profile defines rotation and recovery.
12. **Payment attribution requires the transaction commitment.** A same-address output alone is never credited to a task. Requester-controlled inputs, all-output `0x41` signatures, the exact `acceptHash` commitment, and the durable one-offer outpoint assignment are all required.
13. **Historical proof and current assurance differ.** Receivers persist supporting block/root information and recheck best-chain membership when new actions depend on it. A reorg can suspend current reliance without rewriting the historical transcript.
14. **Signed timestamps do not prove arrival.** Online timeliness uses the receiver's first validated arrival; offline verification reports sender-asserted times and signed acknowledgments, not independently proven network delivery times.

## 14. Canonical logical transcript

The following is a **semantic example, not a golden test vector**. Identity placeholders, proof bytes, signatures, and transaction evidence are intentionally omitted rather than represented as valid cryptographic values.

```text
Identities
  A = requester: { agentPin: <A_PIN>, pubkey: <A_KEY>, address: <A_ADDRESS> }
  B = provider:  { agentPin: <B_PIN>, pubkey: <B_KEY>, address: <B_ADDRESS> }

1. A and B each publish an ADVERTISE
   Each advertisement supplies that party's signed return endpoint and
   chain-anchored identityEvidence. A MAY advertise no services.
   B's advertisement is self-addressed (from = to = B) and contains:
   body = {
     endpoint: "https://b.example/bmp-agent/1",
     services: [{
       kind: "research.summary",
       description: "Short source-backed research summary",
       maxTaskBytes: 4096,
       maxDeliveryBytes: 16384
     }]
   }
   B includes chain-anchored identityEvidence in the self-advertisement's
   from field only. A's requester advertisement follows the same rules.

2. A → B: REQUEST
   threadId = A_REQUEST_MESSAGE_ID
   body = {
     providerAdvertisementHash: SHA256(serialized B ADVERTISE),
     requesterAdvertisementHash: SHA256(serialized A ADVERTISE),
     requesterAdvertisement: exactBase64(serialized A ADVERTISE),
     service: "research.summary",
     task: "Summarize the three supplied sources and label inference.",
     maxPriceSats: 5000,
     deliverBy: 1795700000,
     deliveryMime: "text/markdown",
     maxDeliveryBytes: 16384
   }

3. B → A: OFFER
   body.terms = {
     requestHash: SHA256(serialized REQUEST),
     priceSats: 2500,
     paymentAddress: B_ADDRESS,
     acceptBefore: 1795690000,
     payBy: 1795695000,
     deliverBy: 1795700000,
     confirmationPolicy: "zero-conf",
     deliveryMime: "text/markdown",
     maxDeliveryBytes: 16384
   }

4. A → B: ACCEPT
   body = { offerHash: SHA256(serialized OFFER) }
   Dogfood applies A's local policy before signing. A stores these exact
   ACCEPT bytes and the offer/acceptance pair before transmission.

5. B → A: ACCEPT_ACK
   body = {
     offerHash: SHA256(serialized OFFER),
     acceptHash: SHA256(serialized ACCEPT)
   }
   B has durably entered ACCEPTED. A validates this exact signed pair before
   payment construction or signing. No acknowledgment means no spend.

6. A → B: PAYMENT
   body = {
     offerHash: SHA256(serialized OFFER),
     txid: <PAYMENT_TXID>,
     vout: <PAYEE_OUTPUT_INDEX>,
     amountSats: 2500,
     atomicBeef: <PAYMENT_EVIDENCE>
   }
   Every input spends a mined P2PKH prevout paying A_ADDRESS and signs all
   outputs with SIGHASH_ALL|FORKID. The transaction contains exactly one
   OP_FALSE OP_RETURN push of ASCII("BMPA1") || acceptHash, plus the B payee
   output and optional A change. A's payment path persists intent/evidence and
   never auto-retries an ambiguous spend.

7. B → A: DELIVER
   body = {
     offerHash: SHA256(serialized OFFER),
     paymentId: "<PAYMENT_TXID>.<PAYEE_OUTPUT_INDEX>",
     mime: "text/markdown",
     content: "# Result\n\n..."
   }

8. A → B: RECEIPT
   body = {
     offerHash: SHA256(serialized OFFER),
     deliveryHash: SHA256(serialized DELIVER),
     paymentId: "<PAYMENT_TXID>.<PAYEE_OUTPUT_INDEX>",
     outcome: "accepted"
   }
```

Every message has a unique random `messageId`; messages 2–8 share the request's `threadId`. All signatures, hashes, identity bindings, payment terms, deadlines, and state transitions are independently checked. The provider atomically records `<PAYMENT_TXID>.<PAYEE_OUTPUT_INDEX>` against this offer before delivery. Missing evidence is repaired, if needed, by a signed PROOF referencing the immutable subject envelope; it never rewrites the original task, acceptance, or payment identifier.

## 15. Test-vector and graduation requirements

This document remains **Draft** until all of the following exist:

1. A decoder-first reference implementation for the version `0x02` envelope and every closed payload schema.
2. Deterministic published test keys, fixed message identifiers, timestamps, endpoints, task content, and transaction fixtures.
3. Byte-identical golden envelopes produced twice from the same inputs and reproduced by a second implementation.
4. An independent decoder that verifies the golden bytes rather than only reproducing its own encoder's output.
5. Positive known-answer signature tests before negative signature tests.
6. A complete valid two-advertisement `ADVERTISE → REQUEST → OFFER → ACCEPT → ACCEPT_ACK → PAYMENT → DELIVER → RECEIPT` transcript, including both return endpoints, the durable selected acceptance pair, and an independently parsed payment commitment.
7. Positive proof-repair fixtures for omitted identity and payment evidence, proving that PROOF leaves the subject bytes, terms, and logical payment unchanged.
8. Negative fixtures covering:
   - wrong key, invalid curve point, bad signature, and non-low-s signature;
   - target collision/mismatch, recipient mismatch, wrong address derivation, and distinct-pin/same-key role confusion;
   - malformed/noncanonical agent pin or base64, duplicate proof attachments, wrong mint output, competing Locus payloads, multi-push parsing, owner-key mismatch, and missing/false inclusion proof;
   - non-canonical JSON, duplicate keys, floats, unknown fields, truncation, trailing bytes, and oversized payloads;
   - replay, sender/thread-scoped `messageId` conflicts, far-future expiry, stale/future timestamps, out-of-order actions, wrong roles, and cross-thread references;
   - payment attempted without/with wrong ACCEPT_ACK, distinct ACCEPT bytes for one offer or thread, provider acknowledgment before durable acceptance, and exact ACCEPT retry returning the stored acknowledgment;
   - mismatched provider/requester advertisements, exceeded task/delivery limits, wrong return endpoint, and unsafe endpoint/redirect destinations;
   - the same payment outpoint presented for two offers, missing/wrong `acceptHash`, third-party inputs, non-`0x41`/high-s/non-strict-DER signatures, non-minimal input pushes, additional outputs, multiple commitments, wrong payment txid/output/amount/payee, unmined ancestors, non-final locktime/sequence, invalid Merkle evidence, and insufficient confirmation depth;
   - duplicate/conflicting payment notices, same-payment evidence refresh versus distinct-payment conflict, cross-offer outpoint reuse, and wrong `paymentId` in delivery or receipt;
   - acceptance after `acceptBefore`, payment evidence after `payBy`, backdated/late delivery, self-rejection, wrong-party rejection, and terminal rejection attempted after acceptance/payment/delivery;
   - identity/payment best-chain loss and restoration, missing peer evidence versus locally unavailable headers, transport timeout, ambiguous broadcast, and killfile/policy refusal.
9. Two independent implementations pass the vectors with bit-exact encoding and equivalent accept/reject results.
10. Independent implementation-correctness and protocol-design reviews execute the vectors and attempt exploits.

No live funded acceptance is part of Draft authoring. Any later live payment requires explicit owner authorization and a disposable, bounded vault.

## 16. Deferred decisions

A later revision or numbered document MUST address:

- delegated session keys and capability certificates;
- key rotation, pin transfer, recovery, and historical binding semantics;
- private/encrypted payloads and their replay/authentication limits;
- alternate transports, offline delivery, and agent-message on-chain anchoring;
- multipart/large evidence transport;
- x402, OSP, asset exchange, and physical-machine settlement profiles;
- refusal after acceptance, refunds, disputes, and non-delivery;
- reputation, attestations, and selective disclosure;
- directory spam resistance and availability measurement.

## 17. References

- BMP-0000 — Bitcoin Machine Protocol umbrella and version `0x01` envelope.
- BMP-0002 — L2 on-chain anchoring; not directly applicable to version `0x02` agent envelopes.
- BMP-0003 / BMP-0004 — SPV evidence and trusted-header model.
- Locus Protocol Specification v3 — <https://gryd.world/protocol/SPEC.md> (currently labeled Draft for public review while describing the live convention).
- BRC-62, BEEF — <https://bsv.brc.dev/transactions/0062.md>.
- BRC-67, Simplified Payment Verification — <https://bsv.brc.dev/transactions/0067.md>.
- BRC-74, BUMP — <https://bsv.brc.dev/transactions/0074.md>.
- BRC-95, Atomic BEEF — <https://bsv.brc.dev/transactions/0095.md>.
- RFC 8785, JSON Canonicalization Scheme — <https://www.rfc-editor.org/rfc/rfc8785>.
- Dogfood reference integration points (informative): `dogfood-wallet/src/auth-sign.ts`, `agent-message.ts`, `agent-message-inbox.ts`, `agent-message-offer.ts`, and `policy.ts`.
