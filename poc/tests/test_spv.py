"""Tests for svcode.spv — BMP-0003 L3, replaying the live mainnet proof vector
(poc/vectors/l3_live.json) offline against a BMP-0004 trusted header store.

Store fixture: PoC default trust profile (§6) — anchored at the subject
header's recorded height (969795). The parent header shares that block, so
add() is a duplicate no-op (§4.2 step 2)."""
from __future__ import annotations

import json
import pathlib

import pytest

from svcode import spv
from svcode.crypto import generate_key, pubkey_hex

L3 = json.loads(
    (pathlib.Path(__file__).parent.parent / "vectors" / "l3_live.json").read_text()
)
BEEF = bytes.fromhex(L3["beef_hex"])
HEADERS = [bytes.fromhex(L3["subject_block"]["header_hex"]),
           bytes.fromhex(L3["parent_block"]["header_hex"])]
AUTH = L3["authority_pubkey"]
TIP = L3["tip_height_at_fetch"]          # provenance metadata only (§5.1)
SUBJ_H = L3["subject_block"]["height"]

GENESIS = bytes.fromhex(
    "0100000000000000000000000000000000000000000000000000000000000000"
    "000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa"
    "4b1e5e4a29ab5f49ffff001d1dac2b7c")


def make_store() -> spv.HeaderStore:
    store = spv.HeaderStore([(HEADERS[0], SUBJ_H)])
    store.add(HEADERS[1])                # same block ⇒ duplicate no-op
    return store


STORE = make_store()


def test_live_vector_passes():
    env = spv.verify_l3(BEEF, AUTH, STORE, seen={}, min_depth=1)
    assert env.payload.decode() == L3["expected_payload"]


def test_bump_parser_structure():
    doc = spv.parse_beef(BEEF)
    assert len(doc["bumps"]) == 2 and len(doc["txs"]) == 2
    assert doc["txs"][-1]["txid"] == L3["subject_txid"]   # subject is last (BRC-62 ordering)
    assert doc["txs"][0]["txid"] == L3["parent_txid"]
    for b in doc["bumps"]:
        assert b["block_height"] in (L3["subject_block"]["height"], L3["parent_block"]["height"])


@pytest.fixture
def compound_path():
    # Seven transactions: the last leaf has an explicit duplicate on its right.
    hashes = [spv.txm.sha256d(bytes([i])) for i in range(7)]
    leaves = [{"offset": i, "flags": 2 if i in (0, 6) else 0, "hash": h}
              for i, h in enumerate(hashes)]
    leaves.append({"offset": 7, "flags": spv.FLAG_DUPLICATE, "hash": None})
    layer = hashes + [hashes[-1]]
    while len(layer) > 1:
        layer = [spv.txm.sha256d(a + b) for a, b in zip(layer[::2], layer[1::2])]
    return {"tree_height": 3, "path": [leaves, [], []]}, layer[0]


@pytest.mark.parametrize("target", [0, 6])
def test_compound_root_for_each_target(compound_path, target):
    bump, expected = compound_path
    txid = bump["path"][0][target]["hash"][::-1].hex()
    assert spv.bump_root(bump, txid) == expected


@pytest.mark.parametrize("missing", [4, 5, 7])
def test_compound_requires_both_children(compound_path, missing):
    bump, _ = compound_path
    leaves = bump["path"][0]
    txid = leaves[0]["hash"][::-1].hex()
    del leaves[missing]
    with pytest.raises(ValueError, match="missing sibling"):
        spv.bump_root(bump, txid)


@pytest.mark.parametrize("pruned", [False, True])
def test_consistent_intermediate(compound_path, pruned):
    bump, expected = compound_path
    leaves = bump["path"][0]
    pair = spv.txm.sha256d(leaves[4]["hash"] + leaves[5]["hash"])
    bump["path"][1].append({"offset": 2, "flags": 0, "hash": pair})
    if pruned:
        del leaves[4:6]
    assert spv.bump_root(bump, leaves[0]["hash"][::-1].hex()) == expected


@pytest.mark.parametrize("offset,flag", [(0, 0), (2, 0), (3, 1)])
def test_reject_inconsistent_intermediate(compound_path, offset, flag):
    bump, _ = compound_path
    bump["path"][1].append({"offset": offset, "flags": flag, "hash": None if flag else bytes(32)})
    with pytest.raises(ValueError):
        spv.bump_root(bump, bump["path"][0][0]["hash"][::-1].hex())


@pytest.mark.parametrize("matches", [0, 2])
def test_exactly_one_marked_target(compound_path, matches):
    bump, _ = compound_path
    leaves = bump["path"][0]
    if matches == 0:
        leaves[0]["flags"] = 0
    else:
        leaves[6]["hash"] = leaves[0]["hash"]
    with pytest.raises(ValueError):
        spv.bump_root(bump, leaves[0]["hash"][::-1].hex())


def test_header_pow_real_blocks():
    for h in HEADERS:
        info = spv.verify_header(h)  # raises on PoW failure
        assert len(info["hash"]) == 64


def test_corrupt_bump_rejected():
    beef = bytearray(BEEF)
    beef[60] ^= 0xFF  # inside first BUMP's data
    with pytest.raises(ValueError):
        spv.verify_l3(bytes(beef), AUTH, make_store(), seen={})


def test_corrupt_header_rejected():
    # BMP-0004 §7: the corrupt header now fails at store.add() (consensus
    # PoW gate, §3.2) — a rejected add leaves store state unchanged (§4.6.6).
    bad = bytearray(HEADERS[0]); bad[10] ^= 0xFF
    store = make_store()
    tip = store.best_tip()
    assert tip is not None
    before = (len(store), tip["hash"])
    with pytest.raises(ValueError, match="proof-of-work"):
        store.add(bytes(bad))
    tip2 = store.best_tip()
    assert tip2 is not None
    assert (len(store), tip2["hash"]) == before


def test_missing_header_rejected():
    # A genesis-anchored store (height 0, genesis rule §3.3) does not contain
    # the subject's merkle root, so the subject's inclusion lookup must fail.
    # The live vector's parent and subject share block 969795 (one header
    # proves both), so an unrelated block header isolates the missing-root case.
    spv.verify_header(GENESIS)  # sanity: a real PoW header
    store = spv.HeaderStore([(GENESIS, 0)])
    with pytest.raises(ValueError, match="merkle root not in header store"):
        spv.verify_l3(BEEF, AUTH, store, seen={})


def test_wrong_authority_rejected():
    with pytest.raises(ValueError, match="envelope signature invalid"):
        spv.verify_l3(BEEF, pubkey_hex(generate_key()), make_store(), seen={})


def test_depth_requirement_enforced():
    # Store tip is 969795 (not the caller-asserted fetch tip): depth 1 can
    # never satisfy TIP + 10 (§5.2.6 — no depth-inflation footgun).
    with pytest.raises(ValueError, match="insufficient burial depth"):
        spv.verify_l3(BEEF, AUTH, make_store(), seen={}, min_depth=TIP + 10)


def test_freshness_applies_at_l3():
    seen = {}
    spv.verify_l3(BEEF, AUTH, make_store(), seen=seen)
    # a different command reusing the same parent outpoint must be rejected
    # (the live vector's subject already consumed it)
    from svcode import anchor
    from svcode.crypto import key_from_hex
    from svcode.envelope import Envelope
    from pathlib import Path
    import json as _json
    V = _json.loads(Path(__file__).parent.parent.joinpath("vectors/vectors.json").read_text())
    l2 = _json.loads(Path(__file__).parent.parent.joinpath("vectors/l2_live.json").read_text())
    env2 = Envelope(target_id=0x53564331, action=0x00FF, payload=b"SECOND COMMAND")
    env2.sign(key_from_hex(V["private_key_hex"]))
    raw2, _t2, prev2 = anchor.build_l2_tx(
        env2.serialize(), [{"txid": l2["claim_txid"], "vout": 0, "value": 50_000}],
        int(l2["payer_priv_hex"], 16))
    with pytest.raises(ValueError, match="double-spend"):
        anchor.verify_l2(bytes.fromhex(raw2), prev2, AUTH, seen)