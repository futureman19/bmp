# BMP-0004 — Trusted Header Store and PoW Target Validation

| | |
|---|---|
| **Number** | BMP-0004 |
| **Title** | Trusted Header Store + Consensus PoW Target Validation (L3 hardening) |
| **Status** | **Stable** |
| **Category** | Protocol Specification (Bitcoin Machine Protocol) |
| **Created** | 2026-11-20 |
| **Requires** | BMP-0000, BMP-0003 |
| **Refines** | BMP-0003 §3 step 4 ("Header trust") and §5 ("Header store is the trust root") |
| **Revision** | 2026-11-20 round-1 review fixes: Core shift-order flag taxonomy (§3.1, §8.2), orphan-chain adoption semantics (§4.2, §4.4, §8.4), citation pins to Bitcoin Core v32.1 (§3, §13), chainwork sanity wording (§3.4, §9.1) |

## 1. Abstract and motivation

BMP-0003 (L3) proves a command was mined by walking BRC-74 BUMP merkle paths
into locally held block headers. Its §3 step 4 requires that every header used
"pass local validation: 80 bytes, proof-of-work … and linkage into the
receiver's known chain", and its §5 names the header store as the trust root.
The reference implementations do not yet enforce that sentence:

- `poc/svcode/spv.py` `verify_header` / `js/spv.js` `verifyHeader` compare the
  header digest only against the target decoded from the header's **own
  self-advertised `nBits`**. There is no mainnet `powLimit` ceiling, no
  compact-target overflow rejection, and no zero-target rejection.
- `verify_l3` / `verifyL3` accept the header store as an unordered bag of
  80-byte strings indexed by merkle root. `prev_hash` is extracted but never
  checked: nothing links any header to a known chain.

**Reproduced (review R3, 2026-11-20, on `main` @ `7c0a0b0`):** taking the live
mainnet fixture header (block 969795, `nBits = 0x1826ca34`), setting
`nBits = 0xff00ffff` (exponent 255 ⇒ target ≈ 2^2032) and flipping one
merkle-root byte yields a header that **passes `verify_header` today** —
`SHA256d(header) ≤ target` is trivially true for an astronomically large
target. Python integers and JS BigInts both grow silently past 2^256, so the
overflow is invisible to the current code. An attacker does not even need to
grind: any 80 bytes with overflow `nBits` "has valid PoW". With no linkage
requirement, a whole fake chain of such headers can be fabricated offline and
fed to a machine as its "header store".

The R1 fix (landed, `2bd0af0`) made this gap load-bearing: L3 now *requires* a
non-empty header store, so the store's trust model is the security boundary.
This document specifies that boundary:

1. **Consensus-grade header validity** — an exact integer port of Bitcoin's
   compact-target rules (`SetCompact` + `CheckProofOfWork`), including the
   mainnet `powLimit` ceiling (§3).
2. **A trusted header store with chain linkage** — an injectable store anchored
   to provisioned checkpoints; every other header must link by `prev_hash`
   into an anchor-descended chain, with heights, cumulative chainwork, bounded
   orphan handling, and best-chain fork choice (§4).
3. **L3 consumption of the store** — `verify_l3`/`verifyL3` take the store
   instead of a raw header list; inclusion roots must resolve on the best
   chain; burial depth is computed from store-derived heights, never from
   self-reported evidence (§5).

Parity is required: the Python (`poc/svcode/spv.py`) and JS (`js/spv.js`)
implementations MUST accept/reject identically and produce byte-identical
intermediates, per the repo's Stable convention (§12).

## 2. Threat model and trust boundary

**Assets.** The machine actuates physical commands. L3 acceptance is the gate
between "bytes arrived over a transport" and "the command was settled on the
network". The header store is the only offline evidence of what "the network"
is.

**Attacker capabilities assumed.**

- Full control of any BMP transport (BLE, visual matrix, future RF): can
  inject, replay, and fabricate BEEF containers, BUMPs, and headers.
- Unlimited offline computation *except* real mainnet-scale hash power: can
  grind low-difficulty headers cheaply, cannot out-work the honest mainnet
  chain from a recent checkpoint.
- No control of the operator's provisioning channel (see below).

**What "trusted" means.** Trust is a property of **provenance**, not a waiver
of mathematics:

- **Anchors (checkpoints)** are headers whose (header, height) pairs the
  operator provisions out-of-band. They are trusted *because of how they
  arrived* — an authenticated channel, ideally cross-checked against ≥2
  independent sources (e.g. a personal full node plus a public indexer).
  Anchors are the trust root; they are not required to link to anything.
  They are **still subject to every consensus validity check of §3** — a
  malformed anchor is a provisioning error and MUST be rejected.
- **Every other header is untrusted**, regardless of transport. It enters the
  store only through `add()` (§4.2), which enforces validity **and** linkage
  into an anchor-descended chain. A header that cannot link is never usable
  for inclusion, no matter how much PoW it carries.
- Headers arriving over BMP transports as ordinary content (BMP-0003 §3.4)
  are untrusted inputs to `add()`. They can never become anchors. Anchor
  provisioning is a local/operator act, never a protocol message.

**Deployment trust profiles** are normatively described in §6. The PoC
default is a demonstration trust root (the frozen published live-vector
header); production machines provision recent multi-source checkpoints.

**Security goal.** After this spec, fabricating an L3-accepting proof requires
either (a) compromising the provisioning channel, or (b) producing real
mainnet-difficulty PoW for a chain that links to a provisioned anchor and
out-works the stored best chain from the fork point. Grinding a
low-difficulty fake chain — the R3 attack — no longer suffices: overflow and
over-`powLimit` targets are rejected outright, and even a *valid*
difficulty-1 chain is useless unless it links to an anchor and wins the
chainwork comparison (§10 discusses the residual easier-fork risk and its
mitigations).

## 3. Consensus rules for header validity (normative)

All arithmetic in this section is **integer-only**. Implementations MUST NOT
use floating-point anywhere in target, hash, or work math (no `Math.pow`, no
`Number` coercion of targets/hashes; Python `int`, JS `BigInt`). This mirrors
Bitcoin Core, which uses fixed-width unsigned integer arithmetic.

### 3.1 Compact target decoding (`nBits`)

Port of `arith_uint256::SetCompact` (Bitcoin Core v32.1 `src/arith_uint256.cpp`;
same rules in Bitcoin SV). Given the 32-bit little-endian `nBits` field at
header bytes 72..76:

```
size = nBits >> 24                  # exponent byte, 0..255
word = nBits & 0x007FFFFF           # 23-bit mantissa

if size <= 3:
    word >>= 8 * (3 - size)         # Core shifts the word FIRST
    target = word
else:
    target = word << (8 * (size - 3))

# Flags are computed AFTER the shift, from the post-shift word (Core order).
negative = (word != 0) and (nBits & 0x00800000 != 0)
overflow = (word != 0) and (
      size > 34
   or (word > 0xFF   and size > 33)
   or (word > 0xFFFF and size > 32))
```

Notes:

- The sign bit (`0x00800000`) only makes a target *negative* when the
  **post-shift** mantissa is non-zero — Core computes both flags after the
  size ≤ 3 right-shift. So `nBits = 0x00800000` (mantissa 0) and the size ≤ 2
  sign-bit compacts whose mantissa shifts to zero (`0x00800001`, `0x0180ffff`,
  `0x02800001`) decode to target 0 and are rejected as **zero target**, not
  negative; sign-bit compacts whose post-shift mantissa stays non-zero
  (`0x03800001`, `0x02800100`, `0x1d80ffff`) are **negative target**. (The
  current code rejects any sign bit as "negative target"; accept/reject
  outcomes for every input are unchanged — both reject — but the error
  taxonomy below follows Core exactly, including this shift-order subtlety.)
- Flag order does not affect `overflow`: every one of its size clauses
  requires `size > 32`, where no shift happens, so pre-shift and post-shift
  words are identical there. Only the `negative` taxonomy moves.
- `overflow` is what the current implementations lack: e.g. `0xff00ffff`
  (size 255) or `0x21010000` (size 33, word `0x010000` > `0xFFFF`) decode to
  values ≥ 2^256 that no 256-bit digest can exceed. Core rejects them before
  any comparison; so MUST BMP.
- The shift form above is exact for all inputs; implementations MAY compute
  the target as an unbounded integer and rely on the `overflow` flag rather
  than masking to 256 bits. The flag conditions are normative.

### 3.2 Validity checks, in order

Port of `CheckProofOfWork`/`CheckProofOfWorkImpl`/`DeriveTarget` (Bitcoin
Core v32.1 `src/pow.cpp`; formerly `src/consensus/pow.cpp` — the order below
matches `DeriveTarget`'s range check exactly). A header
MUST be rejected on the first failing check, with the listed error substring
(stable across both implementations — the parity harnesses match on them):

| # | Check | Error substring |
|---|---|---|
| 1 | length == 80 | `header must be 80 bytes` |
| 2 | not `negative` (§3.1) | `negative target` |
| 3 | `target != 0` | `zero target` |
| 4 | not `overflow` (§3.1) | `target overflow` |
| 5 | `target <= pow_limit` (§3.3) | `target exceeds powLimit` |
| 6 | `SHA256d(header) <= target` (digest as little-endian integer) | `header fails proof-of-work` |

Checks 1 and 6 keep their existing messages; 2 keeps its message but narrows
to Core's definition; 3–5 are new. Every header accepted by today's code with
a *non-overflow, in-range* target is still accepted iff its target is
≤ `pow_limit` — which holds for every real mainnet header by consensus, so
the live fixtures and all existing green tests survive migration (§7).

`verify_header` / `verifyHeader` remain exported as **pure validity checks**
(no linkage, no store). On success they return the same shape as today:
`{hash (display hex), merkle_root (internal bytes), prev_hash (internal
bytes)}`. Linkage, height, and work are the store's job (§4).

### 3.3 `powLimit` and chain parameters

Mainnet `powLimit` (Bitcoin Core v32.1 `src/kernel/chainparams.cpp`,
`CMainParams` — moved from `src/chainparams.cpp`, now a wrapper; BSV
mainnet inherits it — the chains share the genesis block and the original
consensus parameters):

```
MAINNET_POW_LIMIT = 0x00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff
                  = 2^224 − 1
```

- The constant MUST be exported by both implementations
  (`spv.MAINNET_POW_LIMIT`, `SVSPV.MAINNET_POW_LIMIT`).
- The compact encoding `0x1d00ffff` ("difficulty 1") decodes to
  `0xffff << 208 = 2^224 − 2^208`, which is **strictly below** `powLimit`
  (compact encoding is lossy). Check 5 is `<=`, not equality-based; the
  genesis header passes it.
- `pow_limit` is an injectable **chain parameter** (mainnet / testnet /
  regtest), defaulting to `MAINNET_POW_LIMIT`. It identifies the chain; it is
  NOT a security knob. Mainnet deployments MUST use the mainnet constant.
  Tests use a trivial limit (`2^256 − 1`) to exercise store logic without
  grinding (§8.3); that configuration MUST NOT appear in production profiles.
- **Genesis anchor rule:** when `pow_limit == MAINNET_POW_LIMIT`, an anchor
  asserted at height 0 MUST hash to the mainnet genesis block
  `000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f`.
  This prevents a fabricated "genesis" trust root. (For other chain
  parameters the check is skipped; the operator owns the genesis identity.)

### 3.4 Block work (integer-only)

Port of `GetBitsProof` (Bitcoin Core v32.1 `src/chain.cpp`; formerly
`GetBlockProof` in `src/consensus/pow.cpp`):

```
work(target) = ((2^256 − 1 − target) // (target + 1)) + 1
```

This is identically Core's `(~target / (target + 1)) + 1` and
`floor(2^256 / (target + 1))`. **Beware the off-by-one:** the tempting
`((2^256 − 1) // (target + 1)) + 1` is `ceil(2^256 / (target + 1))` and
diverges from Core whenever `target + 1` does not divide 2^256 — it MUST NOT
be used (caught and corrected during spec drafting by a 2000-target
equivalence check). Sanity: `work(0xffff << 208) = 4295032833 = 0x100010001
= 2^32 + 2^16 + 1`, which is the per-block work of any difficulty-1 block:
it equals mainnet **genesis (block 0) cumulative chainwork** `0x100010001`,
while block 1's cumulative chainwork is `0x200020002` (genesis + block 1,
both difficulty 1; both values re-verified live via WhatsOnChain). (The
"difficulty 1 ≈ 2^32 work" figure is the nominal approximation using 2^224,
not the compact target.) Cumulative chainwork is the sum of block works
along a branch. Both implementations use unbounded integers (Python
`int`, JS `BigInt`); no wrapping. (Core's `uint256` chainwork could
theoretically wrap after ~2^224 blocks; the divergence is immaterial and
unbounded arithmetic is simpler to keep parity-exact.)

## 4. The trusted header store (normative)

### 4.1 Construction and anchors

```
Python:  HeaderStore(anchors, *, pow_limit=MAINNET_POW_LIMIT, max_orphans=1024)
         # anchors: iterable of (header_bytes, height_int)
JS:      SVSPV.createHeaderStore({ anchors: [{header, height}, ...],
                                   powLimit, maxOrphans })
         # defaults identical; returns a store object
```

Construction rules:

1. Each anchor header MUST pass §3.2 in full (trust ≠ skip math). Invalid
   anchor ⇒ construction error.
2. Anchor heights are operator assertions (§2). Two anchors asserting the
   **same height MUST have the same hash**; otherwise construction fails with
   `anchor height conflict`. Duplicate identical anchors are idempotent.
3. The height-0 genesis rule of §3.3 applies.
4. Anchors need not link to each other (checkpoints may be sparse). Each is
   an independent branch root until linkage merges them.
5. An empty anchor list is allowed: the store is then inert (nothing can
   link, `len == 0`), and L3 rejects it per §5. This preserves the R1
   "empty header store" failure mode.
6. `max_orphans` bounds the orphan pool (§4.4); default 1024 (≈80 KB of
   headers — safe for constrained machines).

Anchors are **roots, not Core-style checkpoints**: a branch that conflicts
with an anchor at the same height is arbitrated by chainwork (§4.3), not
auto-rejected. Rationale: with real mainnet difficulty, out-working the
honest chain from before a recent anchor is infeasible; auto-rejection would
add a second trust mechanism with its own failure modes. Operators SHOULD
provision mutually consistent anchors; rule 2 catches the common error.

### 4.2 `add(header)` algorithm

`add(header) -> info | None` (JS: `info | null`). Raises/throws `ValueError`
with the §3.2 / §4 substrings on rejection. Returns the adopted header's
info, or `None`/`null` when parked as an orphan. `add_many(headers)` applies
`add` in order and returns the number adopted.

In order:

1. **Validity.** Apply §3.2 in full. Reject on failure. (No state changes on
   rejection — the R2 "failed verification leaves no partial state" invariant
   extends to the store.)
2. **Duplicate.** If the hash is already stored: return the existing info
   (idempotent no-op). The live L3 vector lists the same header twice (subject
   and parent share block 969795); this MUST remain a no-op, not an error.
3. **Parent lookup.** Resolve `prev_hash` (internal byte order) against
   **adopted** headers and anchors only. Orphan-pool entries do NOT qualify
   as parents: they have no derived height/work yet, so `parent.height + 1`
   would be undefined.
   - **Found (adopted header or anchor):** adopt. `height = parent.height + 1`;
     `work = parent.work + work(target)` (§3.4). Insert. Proceed to step 4.
   - **Not found, or found only in the orphan pool:** park in the orphan
     pool (§4.4); return `None`/`null`. A header whose parent is itself an
     orphan therefore parks too — orphan chains park whole and resolve via
     the drain (step 5), never against undefined height/work.
4. **Fork choice.** Recompute the best chain (§4.3). If the tip changed,
   rebuild the best-chain root index (§4.5).
5. **Orphan drain.** Repeatedly scan the orphan pool for headers whose
   `prev_hash` now resolves to an adopted header/anchor; adopt them (steps
   3–4 recurse) until no orphan can be adopted. Re-parenting is
   **transitive**: adopting A makes A a valid parent, so an orphan B with
   `prev_hash = A` adopts in the same drain at `height(A) + 1` /
   `work(A) + work(B)`, and so on down arbitrarily long orphan chains that
   arrived parent-last. A single `add` can therefore cascade-adopt a whole
   chain, and best-chain selection (step 4) sees the fully drained chain
   before `add` returns. Drain scans run in pool insertion order (FIFO):
   adoption is monotone, so the final adopted set is order-independent, but
   equal-work tie-break incumbents (§4.3) depend on adoption order, and
   insertion-order scans keep them deterministic and parity-identical.
6. Return the adopted info.

Info shape (both languages, same field semantics):

```
{ hash: <display hex>, merkle_root: <internal bytes>, prev_hash: <internal bytes>,
  height: <int>, work: <cumulative int> }
```

**Height conflict:** if a header with the same hash would be adopted at a
height different from the stored one (possible only via inconsistent anchor
assertions), reject with `duplicate header height conflict`.

### 4.3 Fork choice and the best chain

- Each stored header belongs to exactly one branch rooted at an anchor
  (linkage is a tree: one parent per header; multiple children per parent are
  allowed — that is a fork).
- The **best tip** is the stored header with the greatest cumulative `work`.
  Ties keep the **incumbent** (the tip already best before the add). A new
  header replaces the tip only on **strictly greater** work. This rule is
  deterministic given insertion order and MUST be identical in both
  implementations.
- The **best chain** is the parent-linked path from the best tip back to its
  root anchor.
- Reorgs are normal: extending a losing fork until its cumulative work
  strictly exceeds the incumbent's flips the best tip. Headers on the losing
  branch remain stored (they are valid PoW history) but are **not** on the
  best chain and are invisible to inclusion lookups (§4.5).

### 4.4 Orphan pool

- Headers whose `prev_hash` does not resolve to an adopted header/anchor
  are parked — including headers whose parent is itself an orphan (orphan
  chains, §4.2 step 3) — keyed by hash, in insertion order (FIFO).
- Capacity `max_orphans`. On overflow, evict the **oldest** entries first.
  Eviction is silent (the header may be re-added later); adopted headers are
  never evicted.
- Orphans are not counted in `len(store)`, are not on any chain, and never
  satisfy inclusion.
- The drain in §4.2 step 5 runs after every successful adoption.

### 4.5 Query surface

| Method | Behavior |
|---|---|
| `best_tip()` | info of the best tip, or `None`/`null` for an empty store |
| `get_by_root(merkle_root)` | info of the **best-chain** header with that root, else `None`/`null` |
| `has(hash)` | membership (adopted headers and anchors; not orphans) |
| `len(store)` / `store.size` | count of adopted headers + anchors (not orphans) |

Root index: built over the best chain in **ascending height order, first
occurrence wins** (two best-chain headers sharing a merkle root is
pathological; determinism is what matters). Rebuilt only when the best tip
changes. `get_by_root` MUST NOT return headers from losing forks or orphans —
this is the normative tightening of BMP-0003 §3.3c ("a header in the
receiver's store" ⇒ "a header on the receiver's best chain"). Inclusion on a
losing fork is not network-accepted settlement and MUST NOT authorize a
command.

### 4.6 Invariants (testable)

1. Every stored header passes §3.2.
2. Every non-anchor header's `prev_hash` resolves to an adopted
   header/anchor at `height − 1` (orphan-pool entries are not parents).
3. `work` equals the sum of §3.4 block works along the branch from the root.
4. Best tip = argmax cumulative work, ties to incumbent.
5. `len` counts adopted only; orphan pool ≤ `max_orphans`.
6. Rejected `add` leaves all state unchanged.
7. Duplicate `add` is a no-op returning the existing info.

## 5. L3 pipeline consumption (normative)

### 5.1 New signatures (breaking change)

```
Python: verify_l3(beef, authority_vk_hex, store, seen=None, min_depth=1)
JS:     verifyL3(beef, authorityPubHex, store, seen=null, minDepth=1)
```

- The third parameter is a **HeaderStore**, not a list of raw headers. There
  is no list-compatible fallback: silently auto-anchoring a caller-supplied
  list would re-introduce the self-advertised trust hole this spec closes.
  All callers migrate in the implementation commit (§7).
- The `tip_height` / `tipHeight` parameter is **removed**. Burial depth uses
  the store's best-tip height (§5.2 step 6). A caller-asserted tip was a
  depth-inflation footgun (claim a higher tip than the store knows ⇒ commands
  look deeper than they are). The live vector's `tip_height_at_fetch` remains
  as provenance metadata only.

### 5.2 Validation order

Given an L3 message, authority keys, a store, and a freshness log:

1. **Parse** the BEEF (unchanged, BMP-0003 §3.1).
2. **Subject BUMP required** (R1, unchanged): subject `bump_index` null ⇒
   `L3 requires a BUMP for the subject transaction`.
3. **Non-empty store** (R1, unchanged): `len(store) == 0` ⇒
   `L3 requires a non-empty header store`. Orphans do not count toward
   `len` (§4.4), so an anchorless store holding only parked orphans still
   fails here with the same R1 message. Conversely `len > 0` implies
   `best_tip()` is non-null (every counted header is an anchor or descends
   from one), so step 6 never dereferences a null tip.
4. **BMP-0002 validation** of the subject per BMP-0002 §5 steps 1–6 —
   including the authority-signature check (§5.3) — with prevout evidence
   derived from BEEF ancestors (unchanged, BMP-0003 §3.2). Staged freshness
   (§5 step 6) is preserved (R2 invariant: commit only after all checks
   pass).
5. **Merkle inclusion.** For every transaction carrying a BUMP: compute the
   BRC-74 root (unchanged walk, including the working-node-parity concat
   order); `store.get_by_root(root)` MUST return a header, else
   `merkle root not in header store` (message preserved). Because the store
   only returns best-chain headers, stale-fork and orphan roots fail here.
6. **Burial depth (policy).** For each matched header:
   `depth = store.best_tip().height − matched_header.height + 1`;
   reject if `depth < min_depth` with `insufficient burial depth` (message
   preserved). **The matched header's store-derived height replaces the
   BUMP's self-reported `blockHeight`** in this computation. A BUMP could
   otherwise claim an arbitrarily low `blockHeight` to inflate depth; the
   header's height is anchored (§2) and cannot be forged without breaking
   linkage. The BUMP `blockHeight` remains advisory evidence (BRC-74); root
   equality remains the inclusion proof (BMP-0003 §3.3c). For the live
   vector both heights are 969795, so behavior is unchanged.
7. Commit staged freshness; return the envelope (unchanged).

### 5.3 Delta vs BMP-0003

| BMP-0003 behavior | BMP-0004 |
|---|---|
| Header PoW vs self-advertised `nBits` only | §3.2 full consensus validity (negative/zero/overflow/powLimit/PoW) |
| Store = unordered bag, root-indexed | Anchored store, linkage + heights + chainwork (§4) |
| Inclusion: root in *any* held header | Inclusion: root on *best chain* (§4.5) |
| Burial depth from BUMP `blockHeight`, caller tip | Depth from matched header's store height and store tip (§5.2.6) |
| `headers` list + `tip_height` args | `store` arg; tip derived (§5.1) |
| Empty-store rejection (R1) | Preserved verbatim |
| Staged freshness (R2) | Preserved verbatim; extended to store adds (§4.2.1) |

BMP-0003 remains Stable; on BMP-0004 graduation its §3 step 4 gains a
cross-reference to this document (§12).

## 6. Deployment trust profiles

| Profile | Anchors | Header ingress | "Trusted" means |
|---|---|---|---|
| **PoC default** (`poc/`) | The frozen live-vector header (block 969795) at its recorded height, from `poc/vectors/l3_live.json` | Fixture replay; `l3_live.py` re-fetch provisions the same header | The published, frozen vector is a demonstration trust root. Adequate for replaying the proof; NOT production guidance. |
| **Production machine** | Recent checkpoints provisioned by the operator from ≥2 independent sources over an authenticated channel; refreshed periodically | `add()` only — transport-delivered headers are untrusted (§2) | The provisioning channel is authenticated; anchors are recent enough that out-working the honest chain from them is infeasible (§10). |
| **Gateway / sync node** | Same as production, denser | Out of scope here (no networking, §11) | — |

The PoC default MUST be constructed explicitly in `l3_live.py` and the test
fixtures — there is no implicit "trust whatever headers arrive" mode anywhere
in the API. A store with no anchors accepts nothing (§4.1.5).

## 7. Migration

Breaking API change; **all callers migrate in the implementation commit** so
every baseline stays green. Error substrings relied on by existing harnesses
are preserved (§3.2, §5.2).

| Caller | Migration |
|---|---|
| `poc/svcode/spv.py` | Harden `target_from_bits` per §3.1–3.2 (new errors: zero/overflow/powLimit); export `MAINNET_POW_LIMIT`, `HeaderStore`; `verify_l3` per §5.1–5.2. `verify_header` keeps its name/return shape. |
| `js/spv.js` | Mirror exactly: `targetFromBits`, `verifyHeader`, `MAINNET_POW_LIMIT`, `createHeaderStore`, `verifyL3(beef, authorityPubHex, store, seen, minDepth)`. BigInt throughout; no floating point. |
| `poc/l3_live.py` | Build `HeaderStore([(subj_hdr, subj_h)])`; `store.add(parent_hdr)` (duplicate no-op — same block); `verify_l3(beef, AUTH_PUB, store, seen={}, min_depth=1)`. Vector JSON schema unchanged (`tip_height_at_fetch` stays as metadata). |
| `poc/tests/test_spv.py` | `HEADERS` list → store fixture anchored at 969795. `test_corrupt_header_rejected`: the corrupt header now fails at `store.add()` (PoW message unchanged) — assert there. `test_missing_header_rejected`: genesis-anchored store (height 0, genesis rule §3.3); subject root still absent ⇒ same error. Depth test: `min_depth=TIP+10` still fails (store tip 969795). |
| `poc/tests/test_review_regressions.py` | Store fixture; R1 empty-store cases use an anchorless store (`len == 0` ⇒ same message). R2 staged-freshness assertions unchanged. |
| `poc/js_tests/svctest_l2l3.js` | Mirror the Python migration; `l2l3_ref.json` intermediates are **unchanged** (valid targets/hashes/roots are byte-identical under the new rules). |
| `poc/js_tests/svctest_review.js` | Mirror; R1/R2/R5/R7/R8 assertions preserved. |
| `poc/tests/test_anchor.py`, `test_ble.py`, `svctest_ble.js` | Untouched (no SPV surface). |
| `README.md` | Spec table gains the BMP-0004 row (Draft at spec time; Stable on graduation). |
| **Downstream mirror** (`sv-codes` repo) | `docs/js/spv.js` + `/verify/` page duplicate the canonical verifier by design. Sync is a **separate card in that repo** after BMP-0004 lands here; canonical = bmp. Not touched by this spec's implementation. |

New files (implementation card): `poc/make_header_fixtures.py`,
`poc/vectors/mainnet_headers.json`, `poc/tests/test_header_store.py`,
`poc/js_tests/svctest_headers.js`, `poc/js_tests/headers_ref.json` (+ its
Python generator, following the `l2l3_ref.json` pattern).

## 8. Fixtures

### 8.1 Real mainnet header range

`poc/vectors/mainnet_headers.json` — **300 consecutive mainnet headers,
heights 969496..969795 inclusive**, ending at the live-vector block so the
existing L3 proof replays against the fixture store.

Generation (`poc/make_header_fixtures.py`, one-time, network allowed at
generation only):

1. Start from the known blockhash of 969795 (`l3_live.json`
   `subject_block.blockhash`).
2. Walk `previousblockhash` backwards 299 times via WoC
   `GET /v1/bsv/main/block/{hash}/header`, assembling the 80-byte header
   exactly as `l3_live.py:fetch_header` does (version LE ‖ prevhash rev ‖
   merkleroot rev ‖ time LE ‖ bits LE ‖ nonce LE).
3. **Serialize requests and back off on HTTP 429** (WoC resets parallel
   bursts and rate-limits unauthenticated clients — known pitfall, hit
   during spec drafting). ~300 sequential calls with retry/backoff,
   one-time cost.
4. Validate at generation time: each header's `prev_hash` equals the next
   entry's hash; heights descend by 1; every header passes §3.2; record
   `nBits` per header.
5. Freeze with metadata:

```json
{
  "note": "...",
  "source": "https://api.whatsonchain.com/v1/bsv/main",
  "fetched_at": "<ISO8601>",
  "range": {"first_height": 969496, "last_height": 969795, "count": 300},
  "pow_limit_hex": "00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
  "anchor": {"height": 969496, "hash": "<display>", "header_hex": "..."},
  "headers": [{"height": 969497, "hash": "<display>", "header_hex": "..."}, ...]
}
```

≈70–120 KB JSON — repo-friendly. The anchor is the **first** (lowest) header;
the remaining 299 are added via `add()` in ascending height order. Tests also
construct a store anchored directly at 969795 (PoC default profile).

The genesis header (already inline in `test_spv.py`) remains the canonical
height-0 anchor fixture.

### 8.2 Synthetic `nBits` validity vectors (exact integers)

Shared table for pytest and the JS parity harness; each row is applied to a
real fixture header with only bytes 72..76 replaced (so length/structure are
valid and the failure is attributable to the target rule):

| `nBits` | Expect | Why |
|---|---|---|
| `0x1d80ffff` | reject `negative target` | sign bit, post-shift mantissa ≠ 0 |
| `0x03800001` | reject `negative target` | size 3: shift 0, post-shift word 1 ≠ 0 ⇒ negative (shift-order boundary) |
| `0x02800100` | reject `negative target` | size 2, sign bit: word `0x0100 >> 8 = 1` ≠ 0 ⇒ negative despite size ≤ 2 |
| `0x1d000000` | reject `zero target` | mantissa 0 |
| `0x00800000` | reject `zero target` | sign bit but mantissa 0 ⇒ Core: not negative, target 0 |
| `0x00800001` | reject `zero target` | size 0, sign bit: word `1 >> 24 = 0` ⇒ post-shift word 0 ⇒ zero, not negative (Core shift order) |
| `0x0180ffff` | reject `zero target` | size 1, sign bit: word `0xFFFF >> 16 = 0` ⇒ zero, not negative |
| `0x02800001` | reject `zero target` | size 2, sign bit: word `1 >> 8 = 0` ⇒ zero, not negative |
| `0x02000001` | reject `zero target` | size 2: `1 >> 8 = 0` |
| `0xff123456` | reject `target overflow` | size 255 > 34 (the R3 repro) |
| `0x23000001` | reject `target overflow` | size 35 > 34, any nonzero word |
| `0x22000100` | reject `target overflow` | size 34 > 33, word `0x0100` > `0xFF` |
| `0x21010000` | reject `target overflow` | size 33 > 32, word `0x010000` > `0xFFFF` |
| `0x20010000` | reject `target exceeds powLimit` | size 32, word `0x010000`: NOT overflow (boundary — third condition needs size > 32); target 2^248 > powLimit |
| `0x2000ffff` | reject `target exceeds powLimit` | size 32, word `0xFFFF`: NOT overflow (max word at size 32); target ≈ 2^248 > 2^224−1 |
| `0x1e00ffff` | reject `target exceeds powLimit` | target ≈ 2^232 > powLimit |
| `0x1d00ffff` | accept (validity) | difficulty-1 compact; target < powLimit (§3.3) |
| `0x03000001` | accept (validity) | size 3, target 1 — tiny but legal |
| `0x1826ca34` | accept + PoW pass | the live fixture's real `nBits` |

("accept (validity)" = passes §3.2 checks 1–5; check 6 then depends on the
actual digest — with a real header's digest and an easy target, PoW fails,
which is correct and separately asserted.)

The three size ≤ 2 sign-bit zero rows and the two sign-bit negative contrast
rows pin the Core shift-order taxonomy (§3.1): a pre-shift negative flag
misclassifies the zero rows as `negative target`. Accept/reject is unchanged
(both reject), but the parity harness matches on error substrings, so these
rows are parity-load-bearing.

### 8.3 Fake-chain methodology (no mainnet grinding in tests)

Grinding a real difficulty-1 header costs ~2^32 hashes — unacceptable in a
test suite. The plan separates **math tests** from **logic tests**:

- **Math (mainnet parameters):** real fixture headers (§8.1) prove the
  consensus port accepts genuine mainnet PoW; §8.2 vectors prove every
  validity gate rejects. A random 80-byte header with easy `nBits`
  (`0x1d00ffff`) fails check 6 with overwhelming probability — asserted as
  `header fails proof-of-work`. This is exactly where the R3 attack dies on
  mainnet parameters: overflow/over-limit targets never reach the comparison,
  and in-range easy targets still require real grinding.
- **Logic (trivial `pow_limit = 2^256 − 1`):** with every digest passing PoW,
  fake chains are constructed deterministically (nonce = 0, 1, 2, …; arbitrary
  merkle roots; correct `prev_hash` linkage; synthetic heights). This
  exercises linkage, orphans, forks, chainwork, reorgs, and best-chain
  inclusion without grinding. Sound because the logic under test is
  independent of the target ceiling; the ceiling itself is covered by the
  math tests. The trivial limit is a test-only chain parameter (§3.3).
- **Real-PoW wrong-chain:** a genuine fixture header (passes §3.2 on mainnet
  parameters) added to a store anchored elsewhere ⇒ orphan, never best chain,
  inclusion fails. Proves linkage gates real headers too, not just synthetic
  ones.

### 8.4 Synthetic store scenarios (orphan / fork logic fixtures)

Deterministic scenarios shared by both harnesses, built per §8.3 (trivial
powLimit, `nonce = 0, 1, 2, …`, arbitrary merkle roots, correct `prev_hash`
linkage, synthetic anchor heights). The orphan family exercises the §4.2
step 3/5 semantics normatively:

- **S1 — orphan pair, parent-last.** Store anchored at height `h`. Add B
  (`prev_hash = A`) first: A is unknown ⇒ B parks. Add A (`prev_hash =`
  anchor): A adopts at `h+1`; the drain then adopts B at `h+2` with
  `work(B) = work(anchor) + work(A) + work(B)`. Best tip is B;
  `get_by_root` finds both; `len` = anchor + 2.
- **S2 — orphan chain of three, fully parent-last.** Add C (`prev = B`),
  B (`prev = A`), A (`prev =` anchor) in that order: C and B park (B's
  parent A is unknown at that point; C's parent B is an orphan). A's
  adoption cascade-adopts B then C in one drain: heights `h+1, h+2, h+3`,
  cumulative work, best tip C.
- **S3 — orphan-only anchorless store.** No anchors; add A then B
  (`prev = A`): both park, `len == 0`, `best_tip() == None`, and L3 rejects
  with the R1 `L3 requires a non-empty header store` message (§5.2 step 3).

Fork/reorg, FIFO-eviction, and duplicate-add scenarios use the same
construction rules with the expected outcomes already normatively fixed in
§4.3 (tie-breaks, strict-greater reorg), §4.4 (eviction), §4.2 step 1
(duplicate no-op); their case lists are in §9.1.

### 8.5 Parity reference (`headers_ref.json`)

Python-generated reference intermediates consumed byte-identically by the
JS harness (§9.3), following the `l2l3_ref.json` pattern. It MUST cover:

1. Every §8.2 row (19 vectors): decoded target, flags, accept/reject **and
   error substring** — including the size ≤ 2 sign-bit rows, whose taxonomy
   is shift-order-sensitive.
2. The §8.1 fixture sample: per-header hash, target, work, height.
3. Every §8.4 scenario: adoption order, heights, cumulative works, orphan
   pool states, best-tip selections, `get_by_root` results.
4. The §4.3 equal-work tie-break determinism case (both insertion orders).
5. Work-formula spot values (§3.4), including the genesis/block-1 chainwork
   cross-check.

## 9. Test plan (implementation card)

Runner (provisioned): WSL Ubuntu-24.04, python3.12 + pytest 9.2.0 + ecdsa
0.19.2, node v22.22.1. Worktree at
`/mnt/c/Users/futur/Desktop/bmp/.worktrees/<id>`; copy to WSL-native fs for
speed. Baselines re-verified green at spec time (2026-11-20): pytest **41**,
`svctest_ble.js` **26**, `svctest_l2l3.js` **26**, `svctest_review.js` **16**
(109 checks).

### 9.1 Python — `poc/tests/test_header_store.py` (new, ~40 cases)

Validity (§3): each §8.2 row; real-fixture PoW pass; genesis pass;
`MAINNET_POW_LIMIT` constant value; no-float audit (targets/work are `int`).

Store (§4): anchor validation rejects bad anchor; same-height conflicting
anchors rejected; duplicate anchor idempotent; height-0 non-genesis anchor
rejected (mainnet params); linkage adoption heights/work correct over the
300-header fixture (best tip = 969795, work = sum); duplicate add no-op;
orphan parked then cascade-adopted parent-last (chain of 3, §8.4 S2);
orphan pair whose parent is itself an orphan (§8.4 S1): B parks while A
is parked, both adopt transitively when A's parent arrives, heights and
cumulative work correct, best tip sees them; orphan-only anchorless
store (§8.4 S3): `len == 0`, `best_tip() is None`, L3 R1 message; orphan
FIFO eviction at `max_orphans=4`; rejected add leaves state unchanged; fork:
two children, higher work wins; equal work keeps incumbent; reorg flips tip;
`get_by_root` hides losing-fork and orphan roots; root index deterministic
(first-wins ascending height).

Work math (§3.4): `work(0xffff << 208) == 4295032833 (0x100010001)` =
mainnet genesis cumulative chainwork; block 1 cumulative = `0x200020002`
(2×, both blocks difficulty 1) — re-verify both via indexer at
fixture-generation time; the off-by-one `ceil` variant is
asserted **not** equal for a target where `target+1 ∤ 2^256`; equivalence
with `floor(2^256/(target+1))` over the fixture's real targets.

L3 (§5): live vector passes against (a) PoC-default store anchored at 969795
and (b) full fixture store anchored at 969496; fake low-difficulty chain on
mainnet params rejected (validity/PoW gate); fake chain on trivial-limit
store rejected when unlinked, accepted into store when linked but inclusion
still requires the subject root; depth inflation via forged BUMP
`blockHeight` rejected (depth uses header height); empty/anchorless store
rejected with R1 message; R2 staged-freshness invariant preserved through
store-based verification.

### 9.2 Python — migrated existing suites

`test_spv.py` (9) and `test_review_regressions.py` keep every assertion,
migrated per §7. `test_anchor.py`, `test_ble.py` untouched. Suite total grows
from 41 to ~80; **zero regressions**.

### 9.3 JS parity — `poc/js_tests/svctest_headers.js` (new)

Runs the same §8.2 table, the same fixture sample, and the same §8.4
synthetic store scenarios against `js/spv.js`, comparing to
`poc/js_tests/headers_ref.json` — the §8.5 Python-generated reference
intermediates (targets, works, hashes, best-tip selections, accept/reject +
error substrings), following the `l2l3_ref.json` pattern. Includes
BigInt/no-float checks and the tie-break determinism case. `svctest_l2l3.js` (26) and
`svctest_review.js` (16) migrate per §7 with counts preserved or grown;
`svctest_ble.js` (26) untouched.

### 9.4 Acceptance gates

1. `cd poc && python3 -m pytest tests -q` — all green (≥41 prior + new).
2. `node poc/js_tests/svctest_ble.js` — 26/26.
3. `node poc/js_tests/svctest_l2l3.js` — ≥26, zero failures.
4. `node poc/js_tests/svctest_review.js` — ≥16, zero failures.
5. `node poc/js_tests/svctest_headers.js` — all green; every intermediate
   byte-identical to `headers_ref.json`.
6. Fixture replay: 300-header store + live L3 vector verifies end-to-end
   offline, both implementations.
7. R3 repro inverted: the `0xff00ffff` fake header from §1 is rejected with
   `target overflow` in both implementations.
8. Local commits only; no push, no deploy (repo rule).

## 10. Security considerations and residual risks

- **Easier-fork from an anchor (retarget gap).** This spec does NOT validate
  the 2016-block difficulty retarget schedule. An attacker with modest hash
  power who forks *at* a provisioned anchor can grind a chain at easier-than-
  honest difficulty (down to difficulty 1, which `powLimit` permits) that
  links correctly. Mitigations in this spec: (a) anchors are recent and
  multi-source (§6) — the attacker must out-work the honest chain *from the
  anchor* to become best chain, and the honest extension keeps accumulating
  real-difficulty work; (b) best-chain inclusion (§4.5) means a fake branch
  that never wins the work comparison can never authorize a command;
  (c) bounded orphan pool limits resource abuse. **Follow-up hardening
  card:** retarget validation (+ timestamp/MTP rules) for stores that accept
  long untrusted extensions. Until then, production profiles SHOULD keep the
  anchor-to-tip window short and re-provision frequently.
- **Anchor heights are assertions.** Linkage authenticates relative heights;
  the absolute height of an anchor is only as trustworthy as provisioning.
  Burial depth inherits that assumption. **Authenticated burial height is
  the designated child card** (out of scope here, §11). §5.2.6 already
  removes the *evidence-side* inflation vector (forged BUMP `blockHeight`).
- **No timestamp/MTP/version-bits checks.** Header `nTime` is not validated
  (no trusted clock, no 11-ancestor MTP window in a sparse store). Deferred
  with the retarget card; does not weaken the linkage or target gates.
- **Provisioning channel is the root.** Compromise of anchor provisioning
  defeats L3 by design (§2) — same trust model as Bitcoin SPV clients'
  checkpoints. Machines SHOULD cross-check ≥2 independent sources.
- **Reorgs can invalidate proofs.** A command proven on a branch that later
  loses best-chain status would fail re-verification. The freshness log
  (BMP-0002 §5 step 6, freshness) already prevents re-execution;
  actuation-on-reorg policy is local (BMP-0000 §8.4), unchanged.
- **Fail-closed preserved.** No store / empty store / unlinked headers ⇒
  nothing verifies, the command waits (BMP-0003 §5). No partial state on any
  rejection (R2).

## 11. Out of scope (explicit)

1. **Authenticated burial height** — designated child card; anchor-height
   authentication beyond operator assertion.
2. **Networking / peer sync / gateway** — no header-fetch protocol, no P2P;
   provisioning and transport-content ingress only.
3. **Difficulty retarget + timestamp/MTP validation** — follow-up hardening
   (§10); residual risk documented, not hidden.
4. **BIP34/66/65 height-in-coinbase checks** — require coinbase transactions,
   not headers.
5. **BEEF/BUMP parsing changes** — BMP-0003 parsers are unchanged; only their
   header-store consumption changes.
6. **Full script evaluation** — BMP-0003's P2PKH-only template stands.
7. **`sv-codes` mirror sync** — separate repo/card (§7); canonical = bmp.
8. **Store persistence format** — in-memory store; durable provisioning is
   deployment business.

## 12. Conformance and graduation

Per the repo convention (README): **Stable** requires two independent
implementations (Python `poc/` + browser JS `js/`) passing golden vectors
with bit-identical results. BMP-0004 graduates Draft → Stable when §9.4 gates
1–7 are green on the implementation card, at which point:

- BMP-0003 §3 step 4 gains a cross-reference to BMP-0004 (normative header
  trust definition), and its §5 "chainwork comparison" sentence is realized
  by §4.3.
- README spec table status flips to Stable.
- The `sv-codes` mirror sync card is unblocked.

## 13. References

- Bitcoin Core consensus sources, pinned to release tag **v32.1** (latest
  stable at spec time; BSV inherits the same rules — pinning keeps the
  citations from rotting as master moves):
  - `src/arith_uint256.cpp` — `SetCompact` (compact decode; flags computed
    after the size ≤ 3 shift):
    https://github.com/bitcoin/bitcoin/blob/v32.1/src/arith_uint256.cpp
  - `src/pow.cpp` — `CheckProofOfWork` / `CheckProofOfWorkImpl` /
    `DeriveTarget` (validity check order):
    https://github.com/bitcoin/bitcoin/blob/v32.1/src/pow.cpp
    (formerly `src/consensus/pow.cpp`; that path no longer exists at v32.1)
  - `src/chain.cpp` — `GetBitsProof` (block-work formula; formerly
    `GetBlockProof` in `src/consensus/pow.cpp`):
    https://github.com/bitcoin/bitcoin/blob/v32.1/src/chain.cpp
  - `src/kernel/chainparams.cpp` — `CMainParams` `powLimit` (moved from
    `src/chainparams.cpp`, which is now a wrapper):
    https://github.com/bitcoin/bitcoin/blob/v32.1/src/kernel/chainparams.cpp
  - Bitcoin SV node mirror: https://github.com/bitcoin-sv/bitcoin-sv —
    same consensus rules; current master also uses `src/pow.cpp` (older
    releases keep `src/consensus/pow.cpp`). BMP ports the rules, not the
    file paths.
- BMP-0000 §5 (tiers), §8.4 (local policy); BMP-0002 (L2); BMP-0003 (L3,
  refined here); BMP-0001 (BLE transport, untrusted ingress).
- BRC-62 (BEEF), BRC-74 (BUMP): https://bsv-blockchain.github.io/
- Review R3 finding: weekly deep review `t_115987e3` (2026-11-20); R1 fix
  `2bd0af0` (non-empty header store requirement) makes this boundary
  load-bearing.
- Live fixtures: `poc/vectors/l3_live.json` (block 969795,
  `nBits 0x1826ca34`, difficulty ≈ 2.83×10^10 vs powLimit).