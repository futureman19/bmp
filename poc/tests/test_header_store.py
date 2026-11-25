"""Tests for BMP-0004 §3 (SetCompact/PoW consensus checks) + §4 (HeaderStore)
+ §5 (store-backed verify_l3), per spec/BMP-0004-trusted-header-store.md §9.1.

Offline: consumes only the frozen fixtures vectors/l3_live.json and
vectors/mainnet_headers.json (§8.1). Synthetic logic-test headers are built
with a deterministic NONCE-SEARCH helper (§8.4 caveat 1 — PoW is never
assumed from a trivial powLimit alone). Equal-work fork choice keeps the
INCUMBENT (§4.3 / §9.1 normative text; manager tie-break over comment 518).

Known fixture gap (flagged for review, not silently dropped): §8.1/§9.1 ask
for a captured losing-fork branch of >=12 REAL headers in the fixture; the
frozen fixture carries only the linear 300-header chain, so the reorg cases
below exercise every §9.1 reorg behavior (tip switch, losing headers held,
losing roots excluded, lower-work resistance) on nonce-searched synthetic
branches. A real-branch capture needs a fixture-generation decision (deep
historical reorg at the anchor height, or a high-difficulty-era branch
provisioned as a second anchor) — see task t_ab6d2671 handoff.
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import struct

import pytest

from svcode import spv
from svcode.tx import sha256d

ROOT = pathlib.Path(__file__).parent.parent
L3 = json.loads((ROOT / "vectors" / "l3_live.json").read_text())
FIX = json.loads((ROOT / "vectors" / "mainnet_headers.json").read_text())

BEEF = bytes.fromhex(L3["beef_hex"])
AUTH = L3["authority_pubkey"]
SUBJ = bytes.fromhex(L3["subject_block"]["header_hex"])
PARENT = bytes.fromhex(L3["parent_block"]["header_hex"])
SUBJ_H = L3["subject_block"]["height"]

GENESIS = bytes.fromhex(
    "0100000000000000000000000000000000000000000000000000000000000000"
    "000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa"
    "4b1e5e4a29ab5f49ffff001d1dac2b7c")

TRIVIAL = (1 << 256) - 1
EASY_BITS = 0x220000FF   # target 2^256 - 2^248, work 1, ~1 nonce trial
HARD_BITS = 0x20010000   # target 2^248, ~256 nonce trials expected
SYNTH_TIME = 1700000000

ENTRIES = [FIX["anchor"]] + FIX["headers"]          # 300, ascending heights
HDRS = [bytes.fromhex(e["header_hex"]) for e in ENTRIES]
START_H = FIX["range"]["first_height"]


# ---------- deterministic synthetic headers (nonce search, §8.4) ----------

def synth(label: str, prev_internal: bytes, bits: int = EASY_BITS,
          seed: str | None = None) -> bytes:
    merkle = hashlib.sha256((seed or label).encode()).digest()
    prefix = (struct.pack("<I", 1) + prev_internal + merkle
              + struct.pack("<I", SYNTH_TIME) + struct.pack("<I", bits))
    target, neg, ovf = spv.decode_compact(bits)
    assert not neg and not ovf and target > 0
    for nonce in range(1 << 32):
        hdr = prefix + struct.pack("<I", nonce)
        if int.from_bytes(sha256d(hdr), "little") <= target:
            return hdr
    raise RuntimeError(f"nonce exhausted for {label}")


def internal_hash(hdr: bytes, pow_limit: int = TRIVIAL) -> bytes:
    return bytes.fromhex(spv.verify_header(hdr, pow_limit)["hash"])[::-1]


def _build_synth() -> dict:
    t: dict[str, bytes] = {}
    h: dict[str, bytes] = {}

    def add(label, prev_label, bits=EASY_BITS, seed=None):
        prev = h[prev_label] if prev_label else b"\x00" * 32
        t[label] = synth(label, prev, bits, seed=seed)
        h[label] = internal_hash(t[label])

    for label, prev, bits in [
        ("H0", None, EASY_BITS), ("A", "H0", EASY_BITS),
        ("B", "A", EASY_BITS), ("C", "B", EASY_BITS),
        ("X", "H0", EASY_BITS), ("Y", "H0", HARD_BITS),
        ("X2", "X", EASY_BITS), ("P", "H0", EASY_BITS),
        ("Q", "H0", EASY_BITS), ("Q2", "Q", EASY_BITS),
        ("R0", None, EASY_BITS),
        ("AP3", None, EASY_BITS), ("AH10", "AP3", EASY_BITS),
        ("O1", None, EASY_BITS), ("O2", None, EASY_BITS),
        ("O3", None, EASY_BITS), ("O4", None, EASY_BITS),
        ("O5", None, EASY_BITS), ("O6", None, EASY_BITS),
        ("EXT", None, EASY_BITS),
    ]:
        if label == "EXT":
            t[label] = synth(label, internal_hash(SUBJ, spv.MAINNET_POW_LIMIT))
            h[label] = internal_hash(t[label])
        else:
            add(label, prev, bits)
    add("D", "R0", EASY_BITS, seed="R0")   # D shares R0's merkle root
    return t


SYNTH = _build_synth()
EASY_WORK = spv.block_work(spv.target_from_bits(EASY_BITS, TRIVIAL))
HARD_WORK = spv.block_work(spv.target_from_bits(HARD_BITS, TRIVIAL))

_bad_pow = bytearray(SUBJ)
_bad_pow[0] ^= 0x01
REAL_CORRUPT_POW = bytes(_bad_pow)                     # version flip ⇒ PoW fails
REAL_OVERFLOW = SUBJ[:72] + struct.pack("<I", 0xFF00FFFF) + SUBJ[76:]


def h0_store() -> spv.HeaderStore:
    return spv.HeaderStore([(SYNTH["H0"], 100)], pow_limit=TRIVIAL)


def poc_store() -> spv.HeaderStore:
    """§6 PoC default trust profile: subject header anchored at its recorded
    height; the parent header is the same block ⇒ duplicate no-op."""
    store = spv.HeaderStore([(SUBJ, SUBJ_H)])
    store.add(PARENT)
    return store


def forge_low_blockheight(beef: bytes) -> bytes:
    """Rewrite the subject BUMP's blockHeight varint to 0 (§5.2.6). Tree and
    path untouched ⇒ bumpRoot unchanged; BUMP associations preserved."""
    doc = spv.parse_beef(beef)
    b = doc["bumps"][1]
    vlen = (1 if b["block_height"] < 0xFD else
            3 if b["block_height"] <= 0xFFFF else
            5 if b["block_height"] <= 0xFFFFFFFF else 9)
    new_raw = spv.ser_varint(0) + b["raw"][vlen:]
    out = bytearray(bytes.fromhex("0100beef"))
    out += spv.ser_varint(len(doc["bumps"]))
    out += doc["bumps"][0]["raw"] + new_raw
    out += spv.ser_varint(len(doc["txs"]))
    for t in doc["txs"]:
        out += t["raw"]
        out += (b"\x00" if t["bump_index"] is None
                else b"\x01" + spv.ser_varint(t["bump_index"]))
    forged = bytes(out)
    d2 = spv.parse_beef(forged)
    assert d2["bumps"][1]["block_height"] == 0
    assert spv.bump_root(d2["bumps"][1], d2["txs"][1]["txid"]) == \
        spv.bump_root(b, doc["txs"][1]["txid"])
    return forged


# ---------- §3.2 / §8.2: the EXACT normative nBits validity table ----------

VALIDITY_ROWS = [
    (0x1D80FFFF, "negative target"), (0x03800001, "negative target"),
    (0x02800100, "negative target"),
    (0x1D000000, "zero target"), (0x00800000, "zero target"),
    (0x00800001, "zero target"), (0x0180FFFF, "zero target"),
    (0x02800001, "zero target"), (0x02000001, "zero target"),
    (0xFF123456, "target overflow"), (0x23000001, "target overflow"),
    (0x22000100, "target overflow"), (0x21010000, "target overflow"),
    (0x20010000, "target exceeds powLimit"),
    (0x2000FFFF, "target exceeds powLimit"),
    (0x1E00FFFF, "target exceeds powLimit"),
    (0x1D00FFFF, "accept-validity"), (0x03000001, "accept-validity"),
    (0x1826CA34, "accept-pow-pass"),
]


@pytest.mark.parametrize("nbits,expect", VALIDITY_ROWS,
                         ids=[f"{b:08x}" for b, _ in VALIDITY_ROWS])
def test_compact_validity_table(nbits, expect):
    assert int.from_bytes(SUBJ[72:76], "little") == 0x1826CA34  # fixture sanity
    mod = SUBJ[:72] + struct.pack("<I", nbits) + SUBJ[76:]
    try:
        info = spv.verify_header(mod)                    # MAINNET pow_limit
        err = None
    except ValueError as e:
        info, err = None, str(e)
    if expect == "accept-validity":
        # checks 1–5 pass; check 6 depends on the actual digest (§8.2)
        assert err is None or err == "header fails proof-of-work"
    elif expect == "accept-pow-pass":
        assert err is None and info["hash"] == spv.verify_header(SUBJ)["hash"]
    else:
        assert err is not None and expect in err


def test_shift_order_regression():
    # The R3 bug: flags computed on the PRE-shift mantissa let huge-size
    # encodings through. 0xFF00FFFF MUST flag overflow (word 0xFFFF, size 255
    # ⇒ target 0xFFFF << 2016 > 2^256), and verify_header MUST reject it.
    t, neg, ovf = spv.decode_compact(0xFF00FFFF)
    assert (t, neg, ovf) == (0x00FFFF << (8 * (0xFF - 3)), False, True)
    with pytest.raises(ValueError, match="target overflow"):
        spv.verify_header(REAL_OVERFLOW)
    assert spv.decode_compact(0x03800001) == (0x01, True, False)
    assert spv.decode_compact(0x02800100) == (0x01, True, False)
    assert spv.decode_compact(0x0180FFFF) == (0, False, False)
    assert spv.decode_compact(0x1D00FFFF)[0] == 0xFFFF << 208


def test_truncated_header():
    with pytest.raises(ValueError, match="header must be 80 bytes"):
        spv.verify_header(SUBJ[:79])


def test_check_order_length_before_bits():
    bad = REAL_OVERFLOW[:79]
    with pytest.raises(ValueError, match="header must be 80 bytes"):
        spv.verify_header(bad)


def test_mainnet_easy_target_fails_pow():
    # §8.3: easy nBits under MAINNET_POW_LIMIT passes validity but the random
    # digest fails check 6 — no grinding shortcut on mainnet params.
    rnd = (b"\x00" * 4 + b"\x00" * 32
           + hashlib.sha256(b"bmp-0004-mainnet-easy").digest()
           + struct.pack("<I", SYNTH_TIME)
           + struct.pack("<I", 0x1D00FFFF) + b"\x00" * 4)
    with pytest.raises(ValueError, match="header fails proof-of-work"):
        spv.verify_header(rnd)


def test_pow_limit_injection_flags_still_fire():
    # §3.2: injected powLimit gates ONLY the powLimit check, never the flags.
    with pytest.raises(ValueError, match="target overflow"):
        spv.target_from_bits(0xFF00FFFF, TRIVIAL)
    with pytest.raises(ValueError, match="negative target"):
        spv.target_from_bits(0x1D80FFFF, TRIVIAL)
    with pytest.raises(ValueError, match="zero target"):
        spv.target_from_bits(0x1D000000, TRIVIAL)


def test_pow_limit_injection_accepts_above_mainnet():
    assert spv.target_from_bits(0x20010000, TRIVIAL) == 1 << 248
    with pytest.raises(ValueError, match="target exceeds powLimit"):
        spv.target_from_bits(0x20010000)
    easy = spv.HeaderStore([(SYNTH["H0"], 100)], pow_limit=TRIVIAL)
    assert len(easy) == 1
    mainnet = spv.HeaderStore([(GENESIS, 0)])
    with pytest.raises(ValueError, match="target exceeds powLimit"):
        mainnet.add(SYNTH["H0"])


# ---------- §3.4 / §8.5.5: floor-form work ----------

def test_work_difficulty1_and_genesis_block1():
    w = spv.block_work(spv.target_from_bits(0x1D00FFFF))
    assert w == 0x100010001                              # Core GetBlockProof
    assert 2 * w == 0x200020002                          # genesis + block 1
    assert int.from_bytes(GENESIS[72:76], "little") == 0x1D00FFFF
    spv.verify_header(GENESIS)                           # real genesis PoW
    cw = FIX["chainwork_crosscheck"]
    assert cw["genesis_chainwork_hex"] == format(w, "x") == "100010001"
    assert cw["block1_chainwork_hex"] == "200020002"


def test_work_floor_not_ceil():
    t = spv.target_from_bits(0x1D00FFFF)
    floor_w = spv.block_work(t)
    forbidden = ((1 << 256) - 1) // (t + 1) + 1          # = true ceiling
    assert floor_w == (1 << 256) // (t + 1)
    assert forbidden == floor_w + 1                      # (t+1) ∤ 2^256


def test_work_floor_equivalence_300_real():
    for raw in HDRS:
        t = spv.target_from_bits(int.from_bytes(raw[72:76], "little"))
        assert spv.block_work(t) == (1 << 256) // (t + 1)


def test_fixture_chainwork_crosscheck():
    cw = FIX["chainwork_crosscheck"]
    assert cw["per_block_work_matches_indexer"] is True
    assert int(cw["range_chainwork_delta_hex"], 16) == \
        int(cw["tip_chainwork_hex"], 16) - int(cw["anchor_parent_chainwork_hex"], 16)
    assert FIX["pow_limit_hex"] == format(spv.MAINNET_POW_LIMIT, "064x")


# ---------- §4.1: anchor provisioning ----------

def test_anchor_invalid_pow_rejected():
    with pytest.raises(ValueError, match="proof-of-work"):
        spv.HeaderStore([(REAL_CORRUPT_POW, 100)])
    with pytest.raises(ValueError, match="target overflow"):
        spv.HeaderStore([(REAL_OVERFLOW, 100)])


def test_anchor_same_height_conflict():
    with pytest.raises(ValueError, match="anchor height conflict"):
        spv.HeaderStore([(SYNTH["H0"], 100), (SYNTH["A"], 100)],
                        pow_limit=TRIVIAL)


def test_anchor_duplicate_idempotent():
    store = spv.HeaderStore([(SYNTH["H0"], 100), (SYNTH["H0"], 100)],
                            pow_limit=TRIVIAL)
    assert len(store) == 1


def test_anchor_height0_non_genesis_rejected():
    with pytest.raises(ValueError, match="genesis"):
        spv.HeaderStore([(SUBJ, 0)])


def test_anchor_height0_genesis_ok():
    store = spv.HeaderStore([(GENESIS, 0)])
    assert len(store) == 1
    assert store.best_tip()["hash"] == spv.MAINNET_GENESIS_HASH
    assert store.best_tip()["height"] == 0


def test_empty_store_inert():
    store = spv.HeaderStore(pow_limit=TRIVIAL)
    assert len(store) == 0 and store.best_tip() is None
    assert store.get_by_root(b"\x00" * 32) is None
    assert store.add(SYNTH["A"]) is None                 # nothing to link to
    assert store.orphan_hashes() == [spv.verify_header(
        SYNTH["A"], TRIVIAL)["hash"]]
    assert not store.has(spv.verify_header(SYNTH["A"], TRIVIAL)["hash"])


# ---------- §4.2 / §4.4: linkage, orphans, duplicates ----------

def test_orphan_then_connect():
    store = h0_store()
    assert store.add(SYNTH["B"]) is None                 # parent A missing
    assert len(store) == 1                               # orphans don't count
    info_a = store.add(SYNTH["A"])
    assert info_a["height"] == 101
    assert store.has(spv.verify_header(SYNTH["B"], TRIVIAL)["hash"])
    assert store.best_tip()["height"] == 102             # B drained
    assert store.orphan_hashes() == []
    assert len(store) == 3


def test_transitive_orphan_drain():
    store = h0_store()
    assert store.add(SYNTH["C"]) is None
    assert store.add(SYNTH["B"]) is None
    assert len(store.orphan_hashes()) == 2               # C, B parked (FIFO)
    store.add(SYNTH["A"])                                # drains B then C
    assert store.orphan_hashes() == []
    assert len(store) == 4
    assert store.best_tip()["height"] == 103             # heights monotone


def test_orphan_not_parent_until_adopted():
    store = h0_store()
    store.add(SYNTH["B"])                                # orphan
    assert store.add(SYNTH["C"]) is None                 # B is NOT a parent
    assert len(store) == 1
    store.add(SYNTH["A"])
    assert store.best_tip()["height"] == 103


def test_unlinked_real_header_parks_orphan():
    store = spv.HeaderStore([(GENESIS, 0)])              # MAINNET params
    assert store.add(SUBJ) is None                       # real PoW, wrong chain
    h = spv.verify_header(SUBJ)["hash"]
    assert store.orphan_hashes() == [h]
    assert len(store) == 1 and not store.has(h)
    assert store.best_tip()["hash"] == spv.MAINNET_GENESIS_HASH


def test_fifo_eviction_silent():
    store = spv.HeaderStore(pow_limit=TRIVIAL, max_orphans=4)
    hashes = {k: spv.verify_header(SYNTH[k], TRIVIAL)["hash"]
              for k in ("O1", "O2", "O3", "O4", "O5", "O6")}
    for k in ("O1", "O2", "O3", "O4", "O5"):
        assert store.add(SYNTH[k]) is None
    assert store.orphan_hashes() == [hashes[k] for k in ("O2", "O3", "O4", "O5")]
    store.add(SYNTH["O6"])                               # evicts O2 silently
    assert store.orphan_hashes() == [hashes[k] for k in ("O3", "O4", "O5", "O6")]
    store.add(SYNTH["O1"])                               # re-park at the TAIL
    assert store.orphan_hashes() == [hashes[k] for k in ("O4", "O5", "O6", "O1")]
    assert len(store) == 0


def test_duplicate_add_noop():
    store = h0_store()
    info1 = store.add(SYNTH["A"])
    info2 = store.add(SYNTH["A"])
    assert info1 == info2 and len(store) == 2


def test_duplicate_height_conflict():
    # AH10's parent AP3 is held at height 3 ⇒ adoption height would be 4,
    # but the anchor asserts 10 (§4.2 step 2).
    store = spv.HeaderStore([(SYNTH["AP3"], 3), (SYNTH["AH10"], 10)],
                            pow_limit=TRIVIAL)
    with pytest.raises(ValueError, match="duplicate header height conflict"):
        store.add(SYNTH["AH10"])
    assert len(store) == 2                               # state unchanged


def test_rejected_add_leaves_state():
    store = h0_store()
    store.add(SYNTH["A"])
    store.add(SYNTH["O1"])
    snap = (len(store), store.best_tip()["hash"], store.orphan_hashes())
    for bad, msg in ((REAL_OVERFLOW, "target overflow"),
                     (REAL_CORRUPT_POW, "proof-of-work")):
        with pytest.raises(ValueError, match=msg):
            store.add(bad)
        assert (len(store), store.best_tip()["hash"],
                store.orphan_hashes()) == snap


def test_add_many_counts_duplicates_not_orphans():
    store = h0_store()
    assert store.add_many([SYNTH["A"], SYNTH["B"], SYNTH["B"]]) == 3
    assert len(store) == 3
    assert store.add_many([SYNTH["O1"]]) == 0            # parked, not counted
    assert len(store) == 3


# ---------- §4.3: fork choice — work, incumbent ties, reorg ----------

def test_fork_choice_by_work():
    store = h0_store()
    store.add(SYNTH["X"])                                # easy child, work 1+1
    assert store.best_tip()["hash"] == spv.verify_header(
        SYNTH["X"], TRIVIAL)["hash"]
    store.add(SYNTH["Y"])                                # hard child wins
    tip = store.best_tip()
    assert tip["hash"] == spv.verify_header(SYNTH["Y"], TRIVIAL)["hash"]
    assert tip["work"] == EASY_WORK + HARD_WORK
    assert EASY_WORK == 1 and HARD_WORK > EASY_WORK


def test_tie_keeps_incumbent_PQ():
    store = h0_store()
    store.add(SYNTH["P"])
    store.add(SYNTH["Q"])                                # equal work
    assert store.best_tip()["hash"] == spv.verify_header(
        SYNTH["P"], TRIVIAL)["hash"]


def test_tie_keeps_incumbent_QP():
    store = h0_store()
    store.add(SYNTH["Q"])
    store.add(SYNTH["P"])                                # equal work
    assert store.best_tip()["hash"] == spv.verify_header(
        SYNTH["Q"], TRIVIAL)["hash"]


def test_reorg_switch_and_losing_root_excluded():
    store = h0_store()
    store.add(SYNTH["X"])                                # tip X (work 2)
    store.add(SYNTH["Q"])                                # tie ⇒ X stays
    assert store.best_tip()["hash"] == spv.verify_header(
        SYNTH["X"], TRIVIAL)["hash"]
    store.add(SYNTH["Q2"])                               # work 3 > 2 ⇒ flip
    assert store.best_tip()["hash"] == spv.verify_header(
        SYNTH["Q2"], TRIVIAL)["hash"]
    x_hash = spv.verify_header(SYNTH["X"], TRIVIAL)["hash"]
    assert store.has(x_hash)                             # losing header held
    assert store.get_by_root(spv.verify_header(
        SYNTH["X"], TRIVIAL)["merkle_root"]) is None     # but not best-chain
    got = store.get_by_root(spv.verify_header(SYNTH["Q2"], TRIVIAL)["merkle_root"])
    assert got is not None and got["height"] == 102
    assert store.get_by_root(spv.verify_header(
        SYNTH["H0"], TRIVIAL)["merkle_root"])["height"] == 100


def test_reorg_resist_lower_work():
    store = h0_store()
    store.add(SYNTH["Y"])                                # tip Y (work 256)
    y_hash = store.best_tip()["hash"]
    store.add(SYNTH["X"])
    store.add(SYNTH["X2"])                               # work 3 < 256
    assert store.best_tip()["hash"] == y_hash
    assert store.get_by_root(spv.verify_header(
        SYNTH["X2"], TRIVIAL)["merkle_root"]) is None


# ---------- §4.5: root index ----------

def test_root_index_first_wins():
    store = spv.HeaderStore([(SYNTH["R0"], 100)], pow_limit=TRIVIAL)
    store.add(SYNTH["D"])                                # same merkle root
    root = spv.verify_header(SYNTH["R0"], TRIVIAL)["merkle_root"]
    assert spv.verify_header(SYNTH["D"], TRIVIAL)["merkle_root"] == root
    got = store.get_by_root(root)
    assert got["height"] == 100                          # ascending first wins
    assert store.has(spv.verify_header(SYNTH["D"], TRIVIAL)["hash"])


def test_orphan_root_never_matches():
    store = spv.HeaderStore(pow_limit=TRIVIAL)
    store.add(SYNTH["O1"])
    assert store.get_by_root(spv.verify_header(
        SYNTH["O1"], TRIVIAL)["merkle_root"]) is None


# ---------- §8.1: full 300-header fixture replay ----------

def test_full_fixture_replay():
    assert len(ENTRIES) == 300
    store = spv.HeaderStore([(HDRS[0], START_H)])
    assert store.add_many(HDRS[1:]) == 299
    assert len(store) == 300
    tip = store.best_tip()
    assert tip["height"] == FIX["range"]["last_height"] == SUBJ_H
    assert tip["hash"] == ENTRIES[-1]["hash"]
    cw = FIX["chainwork_crosscheck"]
    assert tip["work"] == int(cw["range_chainwork_delta_hex"], 16)
    for e, raw in zip(ENTRIES, HDRS):
        info = spv.verify_header(raw)
        assert info["hash"] == e["hash"]
        assert store.has(e["hash"])
        got = store.get_by_root(info["merkle_root"])
        assert got is not None and got["height"] == e["height"]
    assert HDRS[-1] == SUBJ                              # continuity with L3


# ---------- §5: store-backed verify_l3 ----------

def test_l3_live_vector_via_store():
    store = poc_store()
    assert len(store) == 1                               # parent = duplicate
    env = spv.verify_l3(BEEF, AUTH, store, seen={}, min_depth=1)
    assert env.payload.decode() == L3["expected_payload"]


def test_l3_list_arg_rejected():
    with pytest.raises(TypeError, match="HeaderStore"):
        spv.verify_l3(BEEF, AUTH, [SUBJ], seen={})       # no list fallback


def test_l3_empty_store_rejected():
    with pytest.raises(ValueError, match="non-empty header store"):
        spv.verify_l3(BEEF, AUTH, spv.HeaderStore(), seen={})


def test_l3_orphan_root_rejected():
    store = spv.HeaderStore([(GENESIS, 0)])
    store.add(SUBJ)                                      # real PoW ⇒ orphan
    with pytest.raises(ValueError, match="merkle root not in header store"):
        spv.verify_l3(BEEF, AUTH, store, seen={})


def test_l3_forged_blockheight_depth():
    # §5.2.6 / R4 evidence-side: BUMP blockHeight is untrusted. Forging it
    # to 0 changes nothing at min_depth=1 and cannot inflate depth to 2.
    store = poc_store()
    forged = forge_low_blockheight(BEEF)
    env = spv.verify_l3(forged, AUTH, store, seen={}, min_depth=1)
    assert env.payload.decode() == L3["expected_payload"]
    with pytest.raises(ValueError, match="insufficient burial depth"):
        spv.verify_l3(forged, AUTH, store, seen={}, min_depth=2)


def test_l3_forged_blockheight_full_fixture_store():
    # R4 hardening: the same forged BUMP under the §6 full-fixture trust
    # profile (anchor 969496 + 299 real headers). Store-derived depth stays
    # 1; the old BUMP-height math would have claimed depth 969796.
    store = spv.HeaderStore([(HDRS[0], START_H)])
    assert store.add_many(HDRS[1:]) == 299
    forged = forge_low_blockheight(BEEF)
    env = spv.verify_l3(forged, AUTH, store, seen={}, min_depth=1)
    assert env.payload.decode() == L3["expected_payload"]
    with pytest.raises(ValueError, match="insufficient burial depth"):
        spv.verify_l3(forged, AUTH, store, seen={}, min_depth=2)


def test_l3_store_derived_depth_extension():
    # Positive control: a trivial-limit child on top of the real subject
    # header makes depth 2 satisfiable from STORE-assigned heights.
    store = spv.HeaderStore([(SUBJ, SUBJ_H)], pow_limit=TRIVIAL)
    info = store.add(SYNTH["EXT"])
    assert info["height"] == SUBJ_H + 1
    env = spv.verify_l3(BEEF, AUTH, store, seen={}, min_depth=2)
    assert env.payload.decode() == L3["expected_payload"]


def test_l3_stripped_beef_r1():
    doc = spv.parse_beef(BEEF)
    stripped = (bytes.fromhex("0100beef") + spv.ser_varint(0)
                + spv.ser_varint(2) + doc["txs"][0]["raw"] + b"\x00"
                + doc["txs"][1]["raw"] + b"\x00")
    with pytest.raises(ValueError, match="BUMP for the subject"):
        spv.verify_l3(stripped, AUTH, poc_store(), seen={}, min_depth=1)


def test_l3_staged_freshness_r2():
    store = poc_store()
    bad = bytearray(BEEF); bad[60] ^= 0xFF               # corrupt first BUMP
    seen = {}
    with pytest.raises(ValueError, match="txid not in BUMP"):
        spv.verify_l3(bytes(bad), AUTH, store, seen=seen)
    assert seen == {}                                    # no partial state
    env = spv.verify_l3(BEEF, AUTH, store, seen=seen)
    assert env.payload.decode() == L3["expected_payload"]
    assert len(seen) == 1                                # committed on success
