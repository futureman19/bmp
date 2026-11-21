"""svcode.spv — BMP-0003 (L3): SPV inclusion proof for anchored commands,
with BMP-0004 header trust (consensus-valid PoW + trusted header store).

Implements spec/BMP-0003-l3-spv-inclusion.md:
- parse_bump / bump_root: BRC-74 BUMP parsing and merkle root calculation
- parse_beef: BRC-62 (v1, `0100BEEF`) container parsing
- verify_header: 80-byte block header PoW + field extraction
- verify_l3: full pipeline — BEEF → subject TX → BMP-0002 §5 validation with
  prevout evidence DERIVED from the included ancestor transactions → merkle
  inclusion of every BUMPed ancestor against the receiver's header store.

Implements spec/BMP-0004-trusted-header-store.md:
- §3: Core v32.1 SetCompact port (shift order!), negative/zero/overflow/
  powLimit consensus checks, floor-form block work. Integer-only — no
  floats anywhere in target/hash/work math.
- §4: HeaderStore — provisioned anchors, parent linkage, cumulative-work
  fork choice (ties keep the incumbent), bounded FIFO orphan pool,
  best-chain-only root index.
- §5: verify_l3 takes the STORE (breaking change; no list fallback, no
  caller-asserted tip). Burial depth uses the matched header's store-derived
  height and the store's best tip. R1 error messages and R2 staged
  freshness are preserved verbatim.

Hash byte-order convention: all hashes handled internally in natural
(internal/little-endian) byte order; display-hex conversion happens only at
API boundaries (txid arguments and returned values are display hex).
"""
from __future__ import annotations

from . import tx as txm
from .anchor import verify_l2
from .crypto import vk_from_hex  # noqa: F401  (re-export convenience)

BEEF_V1 = bytes.fromhex("0100beef")
FLAG_DUPLICATE = 0x01
FLAG_CLIENT_TXID = 0x02


# ---------- varint stream helpers ----------

def _rd(b: bytes, off: int, n: int) -> tuple[bytes, int]:
    if off + n > len(b):
        raise ValueError("truncated")
    return b[off:off + n], off + n

def rd_varint(b: bytes, off: int) -> tuple[int, int]:
    n = b[off]; off += 1
    if n < 0xFD: return n, off
    if n == 0xFD: v, off = _rd(b, off, 2); return int.from_bytes(v, "little"), off
    if n == 0xFE: v, off = _rd(b, off, 4); return int.from_bytes(v, "little"), off
    v, off = _rd(b, off, 8); return int.from_bytes(v, "little"), off

def ser_varint(n: int) -> bytes:
    if n < 0xFD: return bytes([n])
    if n <= 0xFFFF: return b"\xfd" + n.to_bytes(2, "little")
    if n <= 0xFFFFFFFF: return b"\xfe" + n.to_bytes(4, "little")
    return b"\xff" + n.to_bytes(8, "little")


# ---------- BRC-74 BUMP ----------

def parse_bump(b: bytes):
    """-> {block_height, tree_height, path: [[{offset, flags, hash(32B)|None}]]}"""
    height, off = rd_varint(b, 0)
    tree_height = b[off]; off += 1
    if tree_height == 0 or tree_height > 64:
        raise ValueError("bad tree height")
    path = []
    for _level in range(tree_height):
        n, off = rd_varint(b, off)
        leaves = []
        for _ in range(n):
            offset, off = rd_varint(b, off)
            flags = b[off]; off += 1
            h = None
            if not (flags & FLAG_DUPLICATE):
                h, off = _rd(b, off, 32)
            leaves.append({"offset": offset, "flags": flags, "hash": h})
        leaves.sort(key=lambda l: l["offset"])
        path.append(leaves)
    if off != len(b):
        raise ValueError("trailing bytes after BUMP")
    return {"block_height": height, "tree_height": tree_height, "path": path}


def bump_root(bump, txid_display_hex: str) -> bytes:
    """Merkle root (internal byte order) implied by this BUMP for the given txid."""
    txid = bytes.fromhex(txid_display_hex)[::-1]
    level0 = bump["path"][0]
    leaf = next((l for l in level0 if l["hash"] == txid), None)
    if leaf is None:
        raise ValueError("txid not in BUMP level 0")
    index = leaf["offset"]
    working = txid
    for height, leaves in enumerate(bump["path"]):
        sib_off = (index >> height) ^ 1
        sib = next((l for l in leaves if l["offset"] == sib_off), None)
        if sib is None:
            raise ValueError(f"missing sibling at level {height}")
        if sib["flags"] & FLAG_DUPLICATE:
            working = txm.sha256d(working + working)
        elif sib_off & 1:
            # sibling offset odd ⇒ working node is the LEFT child
            working = txm.sha256d(working + sib["hash"])
        else:
            # sibling offset even ⇒ working node is the RIGHT child
            working = txm.sha256d(sib["hash"] + working)
    return working


# ---------- BRC-62 BEEF (v1) ----------

def parse_raw_tx_stream(b: bytes, off: int):
    """Parse one raw tx starting at off; return (raw_bytes, new_off)."""
    start = off
    _ver, off = _rd(b, off, 4)
    nin, off = rd_varint(b, off)
    for _ in range(nin):
        _, off = _rd(b, off, 36)
        slen, off = rd_varint(b, off)
        _, off = _rd(b, off, slen)
        _, off = _rd(b, off, 4)
    nout, off = rd_varint(b, off)
    for _ in range(nout):
        _, off = _rd(b, off, 8)
        slen, off = rd_varint(b, off)
        _, off = _rd(b, off, slen)
    _, off = _rd(b, off, 4)
    return b[start:off], off


def parse_beef(b: bytes):
    """-> {bumps: [parsed BUMP], txs: [{raw, txid(display), bump_index|None}]}
    Subject transaction is the LAST entry (BRC-62 topological ordering)."""
    if b[:4] != BEEF_V1:
        raise ValueError("not BEEF v1 (0100BEEF)")
    off = 4
    n_bumps, off = rd_varint(b, off)
    bumps = []
    for _ in range(n_bumps):
        # a BUMP's length is implicit; parse and track consumption
        sub = parse_bump_stream(b, off)
        bumps.append(sub[0]); off = sub[1]
    n_txs, off = rd_varint(b, off)
    txs = []
    for _ in range(n_txs):
        raw, off = parse_raw_tx_stream(b, off)
        has_bump = b[off]; off += 1
        bidx = None
        if has_bump:
            bidx, off = rd_varint(b, off)
            if bidx >= len(bumps):
                raise ValueError("BUMP index out of range")
        txs.append({"raw": raw, "txid": txm.sha256d(raw)[::-1].hex(), "bump_index": bidx})
    if off != len(b):
        raise ValueError("trailing bytes after BEEF")
    return {"bumps": bumps, "txs": txs}


def parse_bump_stream(b: bytes, off: int):
    """Streaming BUMP parse; returns (bump, new_off)."""
    start = off
    height, off = rd_varint(b, off)
    tree_height = b[off]; off += 1
    if tree_height == 0 or tree_height > 64:
        raise ValueError("bad tree height")
    path = []
    for _level in range(tree_height):
        n, off = rd_varint(b, off)
        leaves = []
        for _ in range(n):
            offset, off = rd_varint(b, off)
            flags = b[off]; off += 1
            h = None
            if not (flags & FLAG_DUPLICATE):
                h, off = _rd(b, off, 32)
            leaves.append({"offset": offset, "flags": flags, "hash": h})
        leaves.sort(key=lambda l: l["offset"])
        path.append(leaves)
    return ({"block_height": height, "tree_height": tree_height, "path": path,
             "raw": b[start:off]}, off)


# ---------- BMP-0004 §3: consensus constants, compact targets, work ----------

MAINNET_POW_LIMIT = (1 << 224) - 1
MAINNET_GENESIS_HASH = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"


def decode_compact(bits: int) -> tuple[int, bool, bool]:
    """Core v32.1 arith_uint256::SetCompact port -> (target, negative, overflow).
    The size<=3 right-shift happens BEFORE the flags are computed (the
    shift-order bug this spec was written against). Integer-only."""
    size = bits >> 24
    word = bits & 0x007FFFFF
    if size <= 3:
        word >>= 8 * (3 - size)
        target = word
    else:
        target = word << (8 * (size - 3))
    negative = word != 0 and (bits & 0x00800000) != 0
    overflow = (word != 0 and (
        (size > 34)
        or (word > 0xFF and size > 33)
        or (word > 0xFFFF and size > 32)))
    return target, negative, overflow


def target_from_bits(bits: int, pow_limit: int = MAINNET_POW_LIMIT) -> int:
    """nBits -> target with full BMP-0004 §3.2 consensus validity. Raises
    ValueError with the pinned substrings 'negative target', 'zero target',
    'target overflow', 'target exceeds powLimit'. pow_limit is injectable
    (§3.2); it gates the powLimit check only, never the consensus flags."""
    target, negative, overflow = decode_compact(bits)
    if negative:
        raise ValueError("negative target")
    if target == 0:
        raise ValueError("zero target")
    if overflow:
        raise ValueError("target overflow")
    if target > pow_limit:
        raise ValueError("target exceeds powLimit")
    return target


def block_work(target: int) -> int:
    """BMP-0004 §3.4 floor form: ((2^256 − 1 − target) // (target + 1)) + 1.
    Equals Core GetBlockProof and floor(2^256 / (target+1)) exactly for every
    valid target. The forbidden off-by-one variant is
    ((2^256 − 1) // (target+1)) + 1 = ceil(2^256 / (target+1)), which diverges
    whenever (target+1) does not divide 2^256."""
    return ((1 << 256) - 1 - target) // (target + 1) + 1


# ---------- block headers ----------

def verify_header(header: bytes, pow_limit: int = MAINNET_POW_LIMIT):
    """Full §3.2 validity + PoW on an 80-byte header. -> {hash(display),
    merkle_root(internal), prev_hash(internal)} — return shape unchanged
    from BMP-0003. Raises on failure."""
    if len(header) != 80:
        raise ValueError("header must be 80 bytes")
    bits = int.from_bytes(header[72:76], "little")
    target = target_from_bits(bits, pow_limit)
    digest = txm.sha256d(header)
    if int.from_bytes(digest, "little") > target:
        raise ValueError("header fails proof-of-work")
    return {
        "hash": digest[::-1].hex(),
        "merkle_root": header[36:68],
        "prev_hash": header[4:36],
    }


# ---------- BMP-0004 §4: trusted header store ----------

class HeaderStore:
    """Anchored, linkage-validated, cumulative-work header store (§4).

    - Anchors are provisioned out-of-band (§4.1): each passes full §3.2,
      carries an asserted height, and needs no parent in the store. Under
      MAINNET_POW_LIMIT a height-0 anchor must hash to the genesis block.
    - add() (§4.2): validity → duplicate no-op → parent lookup against
      adopted/anchors ONLY → fork choice → transitive FIFO orphan drain.
    - Best tip = max cumulative work; ties keep the incumbent (§4.3).
    - get_by_root() answers from the BEST CHAIN only (§4.5).
    - len() counts anchors + adopted headers, never orphans (§4.4).

    Info dicts: {hash(display hex), merkle_root(internal bytes),
    prev_hash(internal bytes), height(int), work(int)} — the first three
    keys are exactly verify_header's return shape.
    """

    def __init__(self, anchors=(), *, pow_limit: int = MAINNET_POW_LIMIT,
                 max_orphans: int = 1024):
        if isinstance(pow_limit, bool) or not isinstance(pow_limit, int) or pow_limit <= 0:
            raise ValueError("pow_limit must be a positive integer")
        if isinstance(max_orphans, bool) or not isinstance(max_orphans, int) or max_orphans < 0:
            raise ValueError("max_orphans must be a non-negative integer")
        self._pow_limit = pow_limit
        self._max_orphans = max_orphans
        self._by_hash: dict[str, dict] = {}     # display hash hex -> info
        self._targets: dict[str, int] = {}      # display hash hex -> target
        self._orphans: dict[str, dict] = {}     # display hash hex -> {base, target}, FIFO
        self._tip: dict | None = None
        self._root_index: dict[str, dict] = {}  # merkle root hex (internal) -> info
        self._anchor_hashes: list[str] = []
        self._anchor_heights: dict[int, str] = {}  # asserted height -> anchor hash
        for header, height in anchors:
            self._add_anchor(header, height)

    # -- provisioning (§4.1) --

    def _add_anchor(self, header: bytes, height: int) -> None:
        if isinstance(height, bool) or not isinstance(height, int) or height < 0:
            raise ValueError("anchor height must be a non-negative integer")
        base = verify_header(header, self._pow_limit)
        if (self._pow_limit == MAINNET_POW_LIMIT and height == 0
                and base["hash"] != MAINNET_GENESIS_HASH):
            raise ValueError("height-0 anchor must hash to the mainnet genesis block")
        h = base["hash"]
        # §4.1.2: two anchors asserting the same height MUST have the same hash
        if height in self._anchor_heights and self._anchor_heights[height] != h:
            raise ValueError("anchor height conflict")
        if h in self._by_hash:
            if self._by_hash[h]["height"] != height:
                raise ValueError("anchor height conflict")
            return                                   # idempotent duplicate anchor
        target = target_from_bits(int.from_bytes(header[72:76], "little"),
                                  self._pow_limit)
        info = dict(base, height=height, work=block_work(target))
        self._by_hash[h] = info
        self._targets[h] = target
        self._anchor_hashes.append(h)
        self._anchor_heights[height] = h
        self._consider_tip(info)

    # -- ingress (§4.2) --

    def add(self, header: bytes) -> dict | None:
        """Validate + adopt one header. Returns its info when adopted (or an
        idempotent duplicate), None when parked in the orphan pool. Raises
        ValueError on §3.2 invalidity or height conflicts; a rejected add
        leaves all state unchanged (§4.6.6)."""
        base = verify_header(header, self._pow_limit)          # step 1
        h = base["hash"]
        if h in self._by_hash:                                 # step 2
            existing = self._by_hash[h]
            parent = self._parent_of(base)
            if parent is not None and parent["height"] + 1 != existing["height"]:
                raise ValueError("duplicate header height conflict")
            return existing
        target = target_from_bits(int.from_bytes(header[72:76], "little"),
                                  self._pow_limit)
        parent = self._parent_of(base)                         # step 3
        if parent is None:
            self._park_orphan(base, target)
            return None
        info = self._adopt(base, target, parent)               # step 4
        self._drain_orphans()                                  # step 5
        return info

    def add_many(self, headers) -> int:
        """Apply add() in order; returns the number of calls that returned
        info (adopted or duplicate no-op). Parked orphans do not count."""
        n = 0
        for header in headers:
            if self.add(header) is not None:
                n += 1
        return n

    def _parent_of(self, base: dict) -> dict | None:
        # prev_hash is internal byte order; _by_hash is keyed by display hex
        return self._by_hash.get(base["prev_hash"][::-1].hex())

    def _adopt(self, base: dict, target: int, parent: dict) -> dict:
        info = dict(base, height=parent["height"] + 1,
                    work=parent["work"] + block_work(target))
        self._by_hash[info["hash"]] = info
        self._targets[info["hash"]] = target
        self._consider_tip(info)                               # §4.3
        return info

    def _park_orphan(self, base: dict, target: int) -> None:
        h = base["hash"]
        if h not in self._orphans:                             # keep first slot (FIFO)
            self._orphans[h] = {"base": base, "target": target}
        while len(self._orphans) > self._max_orphans:          # §4.4 silent eviction
            self._orphans.pop(next(iter(self._orphans)))

    def _drain_orphans(self) -> None:
        """Transitive drain in pool insertion order (FIFO); repeats until a
        full pass adopts nothing. Runs after every successful adoption."""
        while True:
            adopted_any = False
            for h in list(self._orphans):
                entry = self._orphans[h]
                parent = self._parent_of(entry["base"])
                if parent is not None:
                    del self._orphans[h]
                    self._adopt(entry["base"], entry["target"], parent)
                    adopted_any = True
            if not adopted_any:
                break

    # -- fork choice + best-chain root index (§4.3, §4.5) --

    def _consider_tip(self, info: dict) -> None:
        if self._tip is None or info["work"] > self._tip["work"]:
            self._tip = info                                   # ties keep incumbent
            self._rebuild_root_index()

    def _rebuild_root_index(self) -> None:
        self._root_index = {}
        if self._tip is None:
            return
        chain = []
        cur = self._tip
        while cur is not None:
            chain.append(cur)
            cur = self._parent_of(cur)
        for info in sorted(chain, key=lambda i: i["height"]):
            self._root_index.setdefault(info["merkle_root"].hex(), info)

    # -- query surface (§4.5) --

    def best_tip(self) -> dict | None:
        return self._tip

    def get_by_root(self, merkle_root: bytes) -> dict | None:
        """Best-chain header with this merkle root (internal byte order),
        else None. Losing-fork and orphan roots never match (§4.5)."""
        return self._root_index.get(merkle_root.hex())

    def has(self, hash_hex: str) -> bool:
        return hash_hex in self._by_hash

    def __len__(self) -> int:
        return len(self._by_hash)

    # -- inspection helpers (tests / parity refs) --

    def orphan_hashes(self) -> list[str]:
        return list(self._orphans)

    def anchor_hashes(self) -> list[str]:
        return list(self._anchor_hashes)

    @property
    def pow_limit(self) -> int:
        return self._pow_limit


# ---------- the L3 pipeline (BMP-0004 §5) ----------

def verify_l3(beef: bytes, authority_vk_hex: str, store: HeaderStore,
              seen: dict | None = None, min_depth: int = 1):
    """Full BMP-0003 validation, L3 per BMP-0004 §5. `store`: a HeaderStore
    (§4) — raw header lists are no longer accepted and there is no
    list-compatible fallback (§5.1). The caller-asserted tip_height is
    REMOVED: burial depth is store-derived,
    depth = store.best_tip().height − matched_header.height + 1, using the
    STORE-assigned height of the matched header (never the BUMP's
    self-reported blockHeight — §5.2.6, the R4 evidence-side fix).
    Returns the command Envelope."""
    if not isinstance(store, HeaderStore):
        raise TypeError("verify_l3 requires a HeaderStore (BMP-0004 §5.1); "
                        "raw header lists are no longer accepted")
    doc = parse_beef(beef)                                   # 1. parse
    subject = doc["txs"][-1]                                 # 2. subject = last
    by_txid = {t["txid"]: t for t in doc["txs"]}

    # BMP-0003 §5: "L3 without headers degrades safely — nothing verifies."
    # The subject MUST carry a BUMP proving inclusion into a held header. A
    # BEEF stripped of all BUMPs (subject bump_index None) must not pass as L3,
    # and an empty header store can never prove inclusion. (R1, verbatim.)
    if subject["bump_index"] is None:
        raise ValueError("L3 requires a BUMP for the subject transaction")
    if len(store) == 0:
        raise ValueError("L3 requires a non-empty header store")

    parsed_subject = txm.parse_tx(subject["raw"])
    # 3. derive prevout evidence from included ancestors (no separate bundle)
    prevouts = []
    for inp in parsed_subject["inputs"]:
        ptxid = inp["outpoint"][:32][::-1].hex()
        pvout = int.from_bytes(inp["outpoint"][32:], "little")
        anc = by_txid.get(ptxid)
        if anc is None:
            raise ValueError(f"ancestor {ptxid[:16]}… not in BEEF")
        anc_parsed = txm.parse_tx(anc["raw"])
        if pvout >= len(anc_parsed["outputs"]):
            raise ValueError("input references nonexistent ancestor output")
        val, script = anc_parsed["outputs"][pvout]
        prevouts.append({"txid": ptxid, "vout": pvout, "value": val,
                         "script_hex": script.hex()})
    # 4. full BMP-0002 §5 validation (envelope, authority, input sigs, fee, freshness)
    # Freshness state is staged: verify_l2 commits into a scratch copy which is
    # merged into the caller's log only after ALL L3 checks pass (BMP-0003 §5:
    # a command that fails verification must leave no partial state behind).
    staged = dict(seen) if seen is not None else None
    env = verify_l2(subject["raw"], prevouts, authority_vk_hex, staged)

    # 5. merkle inclusion: every tx carrying a BUMP must root into a
    # BEST-CHAIN header of the store (§4.5 / §5.2.5). Losing-fork and orphan
    # roots fail here — inclusion off the best chain is not settlement.
    matched = []
    for t in doc["txs"]:
        if t["bump_index"] is None:
            continue
        bump = doc["bumps"][t["bump_index"]]
        root = bump_root(bump, t["txid"])                    # 5a. BRC-74 walk
        hdr = store.get_by_root(root)
        if hdr is None:
            raise ValueError(f"tx {t['txid'][:16]}…: merkle root not in header store")
        matched.append(hdr)

    # 6. burial depth (policy): STORE-derived heights on both sides (§5.2.6).
    # len(store) > 0 guarantees a non-null tip (§4.6): every counted header
    # is an anchor or descends from one.
    tip = store.best_tip()
    if tip is None:  # unreachable when len(store) > 0 (§4.6 / §5.2 step 3)
        raise ValueError("L3 requires a non-empty header store")
    for hdr in matched:
        depth = tip["height"] - hdr["height"] + 1
        if depth < min_depth:
            raise ValueError(f"insufficient burial depth {depth} < {min_depth}")

    if seen is not None and staged is not None:              # commit staged freshness
        seen.update(staged)
    return env
