"""Regression tests from the 2026-11-20 weekly deep review.

One section per confirmed finding (R# ids match poc/repro_review/repro.py).
Each section landed with its fix commit; gates: pytest tests -q + js_tests/*.
"""
import json
from pathlib import Path

import pytest

from svcode import spv

VEC = json.loads(
    (Path(__file__).resolve().parents[1] / "vectors" / "l3_live.json").read_text())
BEEF = bytes.fromhex(VEC["beef_hex"])
AUTH = VEC["authority_pubkey"]
HEADERS = [bytes.fromhex(VEC["subject_block"]["header_hex"]),
           bytes.fromhex(VEC["parent_block"]["header_hex"])]
TIP = VEC["tip_height_at_fetch"]


# ---------- R2: rejected L3 must not poison the freshness log ----------

def test_r2_rejected_l3_leaves_freshness_log_untouched():
    """A corrupt BUMP fails merkle inclusion AFTER verify_l2 ran; the caller's
    `seen` log must stay empty so the legit command can still verify later."""
    doc = spv.parse_beef(BEEF)
    # Corrupt a level-1 merkle SIBLING (not the level-0 txid/client leaf) so the
    # BRC-74 walk computes a wrong root and fails at the header-store lookup —
    # an inclusion-stage rejection that runs AFTER verify_l2 staged freshness.
    leaf = doc["bumps"][0]["path"][1][0]
    assert leaf["hash"] is not None
    pos = BEEF.find(leaf["hash"])
    assert pos >= 0
    bad = bytearray(BEEF)
    bad[pos] ^= 0x01
    seen = {}
    with pytest.raises(ValueError, match="merkle root"):
        spv.verify_l3(bytes(bad), AUTH, HEADERS, seen=seen, tip_height=TIP)
    assert seen == {}
    # the legit command still verifies afterwards and commits its outpoints
    env = spv.verify_l3(BEEF, AUTH, HEADERS, seen=seen, tip_height=TIP)
    assert env.payload.decode() == VEC["expected_payload"]
    assert len(seen) == 1


def test_r2_successful_l3_commits_freshness_and_blocks_double_spend():
    seen = {}
    spv.verify_l3(BEEF, AUTH, HEADERS, seen=seen, tip_height=TIP)
    assert len(seen) == 1
    # same txid again = idempotent duplicate (BMP-0002 §5.6), still allowed
    spv.verify_l3(BEEF, AUTH, HEADERS, seen=seen, tip_height=TIP)
    assert len(seen) == 1


# ---------- R1: L3 must not pass without header-backed inclusion ----------

def test_r1_stripped_beef_zero_bumps_rejected():
    """BMP-0003 §5: a BEEF stripped of all BUMPs must not verify as L3 even at
    min_depth=1 with valid envelope/signatures — nothing verifies without
    headers. The subject must carry a BUMP proving inclusion."""
    doc = spv.parse_beef(BEEF)
    stripped = (bytes.fromhex("0100beef") + spv.ser_varint(0) + spv.ser_varint(2)
                + doc["txs"][0]["raw"] + b"\x00" + doc["txs"][1]["raw"] + b"\x00")
    with pytest.raises(ValueError, match="BUMP for the subject"):
        spv.verify_l3(stripped, AUTH, [], seen={}, tip_height=TIP, min_depth=1)


def test_r1_empty_header_store_rejected():
    with pytest.raises(ValueError, match="non-empty header store"):
        spv.verify_l3(BEEF, AUTH, [], seen={}, tip_height=TIP, min_depth=1)


# ---------- R5: a tx must not spend the same outpoint twice ----------

def test_r5_duplicate_outpoint_within_tx_rejected():
    """Two inputs referencing one outpoint is consensus-invalid and would
    double-count totalIn (forging fee payment). verify_l2 must reject it."""
    from svcode import anchor
    from svcode.envelope import Envelope
    from svcode.crypto import generate_key, pubkey_hex
    sk = generate_key()
    env = Envelope(target_id=0x53564331, action=0x00FF, payload=b"DUP")
    env.sign(sk)
    u = {"txid": "ab" * 32, "vout": 0, "value": 10_000}
    raw, _txid, prev = anchor.build_l2_tx(env.serialize(), [u, u], 2)
    with pytest.raises(ValueError, match="duplicate outpoint"):
        anchor.verify_l2(bytes.fromhex(raw), prev, pubkey_hex(sk), {})


# ---------- R7: parse must preserve a zero wire nonce ----------

def test_r7_parse_preserves_zero_nonce():
    """Envelope.__post_init__ auto-stamps nonce=0 -> time() for new envelopes;
    parse must NOT apply that convenience, or a valid nonce-0 wire envelope
    fails verify and roundtrip (JS parse already preserves it)."""
    from svcode.envelope import Envelope
    from svcode.crypto import generate_key
    sk = generate_key()
    env = Envelope(target_id=0x53564331, action=0x00FF, payload=b"NONCE0")
    env.nonce = 0                      # force wire nonce 0 (post-init stamps otherwise)
    env.sign(sk)
    wire = env.serialize()
    assert wire[15:19] == b"\x00\x00\x00\x00"
    parsed = Envelope.parse(wire)
    assert parsed.nonce == 0
    assert parsed.verify(sk.verifying_key)
    assert parsed.serialize() == wire
