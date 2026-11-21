#!/usr/bin/env python3
"""Generate poc/js_tests/headers_ref.json — Python reference intermediates for
the BMP-0004 JS parity harness (svctest_headers.js), following the
l2l3_ref.json pattern (spec §8.5).

OFFLINE: reads vectors/l3_live.json + vectors/mainnet_headers.json (frozen by
make_header_fixtures.py). No network. Run from poc/:
    python3 js_tests/make_headers_ref.py

Pinned caveats (spec-card comment 518):
1. Synthetic logic-test headers are built with a NONCE-SEARCH helper — PoW is
   never assumed from a trivial powLimit alone.
2. Equal-work fork choice keeps the INCUMBENT (§4.3 / §9.1 normative text);
   both insertion orders are recorded (§8.5.4). len counts anchors + adopted.
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import struct
import sys

POC = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(POC))
from svcode import spv  # noqa: E402
from svcode.tx import sha256d  # noqa: E402

TRIVIAL = (1 << 256) - 1
EASY_BITS = 0x220000FF   # target 2^256 - 2^248, work 1, nonce ~0 trials
HARD_BITS = 0x20010000   # target 2^248, work 256, nonce ~256 trials expected
SYNTH_TIME = 1700000000

GENESIS_HEX = (
    "0100000000000000000000000000000000000000000000000000000000000000"
    "000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa"
    "4b1e5e4a29ab5f49ffff001d1dac2b7c")

L3 = json.loads((POC / "vectors" / "l3_live.json").read_text())
SUBJ = bytes.fromhex(L3["subject_block"]["header_hex"])
AUTH = L3["authority_pubkey"]
BEEF = bytes.fromhex(L3["beef_hex"])


def le_num(b: bytes) -> int:
    return int.from_bytes(b, "little")


def synth(label: str, prev_internal: bytes, bits: int,
          version: int = 1, time_: int = SYNTH_TIME,
          seed: str | None = None) -> tuple[bytes, int]:
    """Deterministic synthetic header with nonce search (§8.4 caveat 1).
    merkle_root = sha256(seed or label) — single hash, fixed seed. Grinding
    starts at nonce 0 and stops at the first digest <= target (decoded)."""
    merkle = hashlib.sha256((seed or label).encode()).digest()
    prefix = (struct.pack("<I", version) + prev_internal + merkle
              + struct.pack("<I", time_) + struct.pack("<I", bits))
    target, neg, ovf = spv.decode_compact(bits)
    assert not neg and not ovf and target > 0
    for nonce in range(1 << 32):
        hdr = prefix + struct.pack("<I", nonce)
        if le_num(sha256d(hdr)) <= target:
            return hdr, nonce
    raise RuntimeError(f"nonce exhausted for {label}")


def build_synth_table() -> dict:
    """Construction order: parents before children. prev_label null ⇒ 32 zero
    bytes (synthetic root). 'kind: real_mod' entries mutate the frozen live
    subject header instead of grinding."""
    table: dict[str, dict] = {}
    built: dict[str, bytes] = {}

    def add_synth(label, prev_label, bits=EASY_BITS, seed=None):
        # built[...] holds the parent's INTERNAL hash bytes — exactly what the
        # child's prev_hash field carries (no re-reversal).
        if prev_label == "REAL_SUBJ":
            prev = bytes.fromhex(spv.verify_header(SUBJ)["hash"])[::-1]
        else:
            prev = built[prev_label] if prev_label else b"\x00" * 32
        hdr, nonce = synth(label, prev, bits, seed=seed)
        info = spv.verify_header(hdr, pow_limit=TRIVIAL)
        built[label] = bytes.fromhex(info["hash"])[::-1]  # internal bytes
        table[label] = {
            "kind": "synth", "label": label, "prev_label": prev_label,
            "bits_hex": f"{bits:08x}", "version": 1, "time": SYNTH_TIME,
            "nonce": nonce, "header_hex": hdr.hex(), "hash_hex": info["hash"],
            "merkle_hex": info["merkle_root"][::-1].hex(),
            "target_hex": format(spv.target_from_bits(bits, TRIVIAL), "x"),
            "work_str": str(spv.block_work(spv.target_from_bits(bits, TRIVIAL))),
        }

    for label, prev, bits in [
        ("H0", None, EASY_BITS), ("A", "H0", EASY_BITS),
        ("B", "A", EASY_BITS), ("C", "B", EASY_BITS),
        ("X", "H0", EASY_BITS), ("Y", "H0", HARD_BITS),
        ("Y2", "Y", EASY_BITS), ("X2", "X", EASY_BITS),
        ("P", "H0", EASY_BITS), ("Q", "H0", EASY_BITS),
        ("Q2", "Q", EASY_BITS),
        ("R0", None, EASY_BITS),
        ("AP3", None, EASY_BITS), ("AH10", "AP3", EASY_BITS),
        ("O1", None, EASY_BITS), ("O2", None, EASY_BITS),
        ("O3", None, EASY_BITS), ("O4", None, EASY_BITS),
        ("O5", None, EASY_BITS), ("O6", None, EASY_BITS),
        ("EXT", "REAL_SUBJ", EASY_BITS),
    ]:
        add_synth(label, prev, bits)
    # D shares R0's merkle SEED ⇒ identical merkle root (root-index first-wins)
    add_synth("D", "R0", EASY_BITS, seed="R0")
    assert table["D"]["merkle_hex"] == table["R0"]["merkle_hex"]

    bad_pow = bytearray(SUBJ); bad_pow[0] ^= 0x01      # version flip ⇒ PoW fails
    bad_ovf = SUBJ[:72] + struct.pack("<I", 0xFF00FFFF) + SUBJ[76:]
    table["REAL_CORRUPT_POW"] = {"kind": "real_mod", "mod": "version_flip",
                                 "header_hex": bytes(bad_pow).hex()}
    table["REAL_OVERFLOW"] = {"kind": "real_mod", "mod": "bits_overflow",
                              "header_hex": bad_ovf.hex()}
    return table


def resolve(label: str, table: dict) -> bytes:
    if label == "GENESIS":
        return bytes.fromhex(GENESIS_HEX)
    if label == "REAL_SUBJ":
        return SUBJ
    return bytes.fromhex(table[label]["header_hex"])


def info_snap(info: dict | None) -> dict | None:
    if info is None:
        return None
    return {"hash": info["hash"], "height": info["height"],
            "work_str": str(info["work"])}


def run_scenario(name: str, table: dict, anchors: list, adds: list,
                 pow_limit: int = TRIVIAL, max_orphans: int = 1024,
                 root_queries: list | None = None,
                 has_queries: list | None = None) -> dict:
    store = spv.HeaderStore(
        [(resolve(lbl, table), h) for lbl, h in anchors],
        pow_limit=pow_limit, max_orphans=max_orphans)
    steps = []
    for lbl in adds:
        err = None
        info = None
        try:
            info = store.add(resolve(lbl, table))
        except ValueError as e:
            err = str(e)
        tip = store.best_tip()
        steps.append({
            "label": lbl, "adopted": info is not None,
            "info": info_snap(info), "error": err,
            "len": len(store), "tip_hash": tip["hash"] if tip else None,
            "orphan_hashes": store.orphan_hashes(),
        })
    out = {"name": name,
           "pow_limit": "trivial" if pow_limit == TRIVIAL else "mainnet",
           "max_orphans": max_orphans,
           "anchors": [{"label": lbl, "height": h} for lbl, h in anchors],
           "adds": adds, "steps": steps,
           "final_len": len(store), "final_tip": info_snap(store.best_tip())}
    if root_queries:
        out["by_root"] = {}
        for lbl in root_queries:
            root_disp = table[lbl]["merkle_hex"] if lbl in table else None
            if root_disp is None:
                continue
            got = store.get_by_root(bytes.fromhex(root_disp)[::-1])
            out["by_root"][root_disp] = info_snap(got)
    if has_queries:
        out["has"] = {table[lbl]["hash_hex"]: store.has(table[lbl]["hash_hex"])
                      for lbl in has_queries if lbl in table}
    return out


def forge_low_blockheight(beef: bytes) -> bytes:
    """Rewrite the subject BUMP's blockHeight varint to 0 (§5.2.6 / R4
    evidence-side regression). Tree + path untouched ⇒ bumpRoot unchanged.
    Rebuilds the BEEF preserving every tx's BUMP association exactly."""
    doc = spv.parse_beef(beef)
    b = doc["bumps"][1]
    h = b["block_height"]
    vlen = 1 if h < 0xFD else 3 if h <= 0xFFFF else 5 if h <= 0xFFFFFFFF else 9
    new_raw = spv.ser_varint(0) + b["raw"][vlen:]
    assert spv.bump_root(spv.parse_bump(new_raw), doc["txs"][1]["txid"]) == \
        spv.bump_root(b, doc["txs"][1]["txid"])
    out = bytearray(bytes.fromhex("0100beef"))
    out += spv.ser_varint(len(doc["bumps"]))
    out += doc["bumps"][0]["raw"] + new_raw
    out += spv.ser_varint(len(doc["txs"]))
    for t in doc["txs"]:
        out += t["raw"]
        if t["bump_index"] is None:
            out += b"\x00"
        else:
            out += b"\x01" + spv.ser_varint(t["bump_index"])
    forged = bytes(out)
    d2 = spv.parse_beef(forged)
    assert d2["bumps"][1]["block_height"] == 0
    assert [t["bump_index"] for t in d2["txs"]] == [0, 1]
    return forged


def main() -> None:
    fixture = json.loads((POC / "vectors" / "mainnet_headers.json").read_text())
    cw = fixture["chainwork_crosscheck"]
    entries = [fixture["anchor"]] + fixture["headers"]   # 300, ascending
    start_height = fixture["range"]["first_height"]
    table = build_synth_table()

    # ---- §8.2 nBits validity table — the EXACT normative spec rows, applied
    # to the real fixture header with only bytes 72..76 replaced, under the
    # MAINNET pow_limit. "accept (validity)" rows pass checks 1–5; check 6
    # then depends on the actual digest (recorded, never assumed). ----------
    assert int.from_bytes(SUBJ[72:76], "little") == 0x1826CA34
    rows = [
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
    vectors = []
    for nbits, expect in rows:
        mod = SUBJ[:72] + struct.pack("<I", nbits) + SUBJ[76:]
        target, neg, ovf = spv.decode_compact(nbits)
        err = None
        try:
            spv.verify_header(mod)                # MAINNET_POW_LIMIT default
        except ValueError as e:
            err = str(e)
        if expect == "accept-validity":
            assert err is None or err == "header fails proof-of-work", (hex(nbits), err)
        elif expect == "accept-pow-pass":
            assert err is None, (hex(nbits), err)
        else:
            assert err is not None and expect in err, (hex(nbits), expect, err)
        vectors.append({"nbits_hex": f"{nbits:08x}",
                        "target_hex": format(target, "x"),
                        "negative": neg, "overflow": ovf,
                        "expect": expect, "error": err})

    # ---- §8.3 math test: random header, easy nBits, MAINNET limit ⇒ the
    # digest still fails check 6 (no grinding shortcut on mainnet params). --
    rnd = (b"\x00" * 4 + b"\x00" * 32
           + hashlib.sha256(b"bmp-0004-mainnet-easy").digest()
           + struct.pack("<I", SYNTH_TIME)
           + struct.pack("<I", 0x1D00FFFF) + b"\x00" * 4)
    rnd_err = None
    try:
        spv.verify_header(rnd)
    except ValueError as e:
        rnd_err = str(e)
    assert rnd_err == "header fails proof-of-work", rnd_err

    # ---- §8.5.5 work spot values ------------------------------------------
    t1 = spv.target_from_bits(0x1D00FFFF)
    floor_w = spv.block_work(t1)
    # §3.4 forbidden variant: ((2^256 − 1) // (target+1)) + 1 = true ceiling
    forbidden_w = ((1 << 256) - 1) // (t1 + 1) + 1
    assert floor_w == 0x100010001                 # Core GetBlockProof, difficulty 1
    assert forbidden_w == floor_w + 1             # off by one: (t1+1) ∤ 2^256
    assert floor_w == (1 << 256) // (t1 + 1)      # ≡ floor(2^256/(target+1))

    # ---- fixture samples + full-store replay (§8.1 / §8.5.2) --------------
    hdrs = [bytes.fromhex(e["header_hex"]) for e in entries]
    fstore = spv.HeaderStore([(hdrs[0], start_height)])
    adopted = fstore.add_many(hdrs[1:])
    assert adopted == len(hdrs) - 1
    ftip = fstore.best_tip()
    assert ftip is not None
    anchor_info = fstore.get_by_root(spv.verify_header(hdrs[0])["merkle_root"])
    assert anchor_info is not None
    # Store work starts at the anchor's OWN block work, so the tip accumulates
    # all 300 blocks = tip_chainwork − anchor_parent_chainwork = range delta.
    assert ftip["work"] == int(cw["range_chainwork_delta_hex"], 16)
    assert ftip["work"] == (int(cw["tip_chainwork_hex"], 16)
                            - int(cw["anchor_parent_chainwork_hex"], 16))
    samples = []
    for e, raw in zip(entries, hdrs):
        info = spv.verify_header(raw)
        bits = int.from_bytes(raw[72:76], "little")
        t = spv.target_from_bits(bits)
        got = fstore.get_by_root(info["merkle_root"])
        assert got is not None
        samples.append({"height": e["height"], "header_hex": e["header_hex"],
                        "hash_hex": info["hash"], "bits_hex": f"{bits:08x}",
                        "target_hex": format(t, "x"),
                        "work_hex": format(spv.block_work(t), "x"),
                        "root_height": got["height"]})
    fixture_equiv = all(
        spv.block_work(t) == (1 << 256) // (t + 1)
        for t in (spv.target_from_bits(int.from_bytes(r[72:76], "little"))
                  for r in hdrs))
    assert fixture_equiv   # §8.5.5: ≡ floor(2^256/(target+1)) on real targets

    # ---- §8.4 / §9.1 store scenarios --------------------------------------
    scen = {}
    scen["s1_orphan_pair"] = run_scenario(
        "s1_orphan_pair", table, [("H0", 100)], ["B", "A"],
        root_queries=["A", "B"], has_queries=["A", "B"])
    scen["s2_orphan_chain"] = run_scenario(
        "s2_orphan_chain", table, [("H0", 100)], ["C", "B", "A"],
        root_queries=["C"], has_queries=["A", "B", "C"])
    s3 = run_scenario("s3_anchorless", table, [], ["A", "B"])
    try:
        spv.verify_l3(BEEF, AUTH,
                      spv.HeaderStore(), seen={})
        raise AssertionError("anchorless store must reject L3")
    except ValueError as e:
        s3["l3_error"] = str(e)
    scen["s3_anchorless"] = s3
    scen["fork_work"] = run_scenario(
        "fork_work", table, [("H0", 100)], ["X", "Y"],
        root_queries=["X", "Y", "H0"], has_queries=["X", "Y"])
    scen["tie_order_PQ"] = run_scenario(
        "tie_order_PQ", table, [("H0", 100)], ["P", "Q"], root_queries=["P", "Q"])
    scen["tie_order_QP"] = run_scenario(
        "tie_order_QP", table, [("H0", 100)], ["Q", "P"], root_queries=["P", "Q"])
    scen["reorg"] = run_scenario(
        "reorg", table, [("H0", 100)], ["X", "Q", "Q2"],
        root_queries=["X", "Q", "Q2"])
    # equal-work sibling keeps incumbent X; extending Q to Q2 (work 2 > 1)
    # flips the tip. Lower-work extensions must NOT flip a higher-work tip:
    scen["reorg_resist"] = run_scenario(
        "reorg_resist", table, [("H0", 100)], ["Y", "X", "X2"],
        root_queries=["X", "X2", "Y"])
    scen["eviction"] = run_scenario(
        "eviction", table, [], ["O1", "O2", "O3", "O4", "O5", "O6", "O1"],
        max_orphans=4)
    scen["duplicate"] = run_scenario(
        "duplicate", table, [("H0", 100)], ["A", "A"], has_queries=["A"])
    scen["rejected_state"] = run_scenario(
        "rejected_state", table, [("H0", 100)], ["A", "O1", "REAL_OVERFLOW"],
        root_queries=["A"], has_queries=["A", "O1"])
    scen["root_first_wins"] = run_scenario(
        "root_first_wins", table, [("R0", 100)], ["D"], root_queries=["R0", "D"])
    scen["dup_height_conflict"] = run_scenario(
        "dup_height_conflict", table, [("AP3", 3), ("AH10", 10)], ["AH10"])
    scen["real_wrong_chain"] = run_scenario(
        "real_wrong_chain", table, [("GENESIS", 0)], ["REAL_SUBJ"],
        pow_limit=spv.MAINNET_POW_LIMIT)
    rw = spv.HeaderStore([(bytes.fromhex(GENESIS_HEX), 0)],
                         pow_limit=spv.MAINNET_POW_LIMIT)
    rw.add(SUBJ)                        # real PoW, wrong chain ⇒ orphan
    try:
        spv.verify_l3(BEEF, AUTH, rw, seen={})
        raise AssertionError("unlinked real header must not prove inclusion")
    except ValueError as e:
        scen["real_wrong_chain"]["l3_error"] = str(e)
    scen["r3_repro_overflow"] = run_scenario(
        "r3_repro_overflow", table, [("GENESIS", 0)], ["REAL_OVERFLOW"],
        pow_limit=spv.MAINNET_POW_LIMIT)
    scen["mainnet_pow_reject"] = run_scenario(
        "mainnet_pow_reject", table, [("GENESIS", 0)], ["REAL_CORRUPT_POW"],
        pow_limit=spv.MAINNET_POW_LIMIT)
    scen["mainnet_easy_target_reject"] = run_scenario(
        "mainnet_easy_target_reject", table, [("GENESIS", 0)], ["H0"],
        pow_limit=spv.MAINNET_POW_LIMIT)
    # store-derived depth: a trivial-limit child on top of the real subject
    # header makes depth 2 satisfiable (§5.2.6 positive control)
    de = run_scenario("depth_extension", table,
                      [("REAL_SUBJ", L3["subject_block"]["height"])], ["EXT"])
    de_store = spv.HeaderStore([(SUBJ, L3["subject_block"]["height"])],
                               pow_limit=TRIVIAL)
    de_store.add(resolve("EXT", table))
    env_de = spv.verify_l3(BEEF, AUTH, de_store, seen={}, min_depth=2)
    de["l3_min_depth2_payload"] = env_de.payload.decode()
    scen["depth_extension"] = de

    # anchor provisioning rules (§4.1)
    anchor_rules = {}
    try:
        spv.HeaderStore([(resolve("REAL_OVERFLOW", table), 100)])
        anchor_rules["bad_anchor"] = None
    except ValueError as e:
        anchor_rules["bad_anchor"] = str(e)
    try:
        spv.HeaderStore([(resolve("H0", table), 100), (resolve("A", table), 100)],
                        pow_limit=TRIVIAL)
        anchor_rules["same_height_conflict"] = None
    except ValueError as e:
        anchor_rules["same_height_conflict"] = str(e)
    st = spv.HeaderStore([(resolve("H0", table), 100), (resolve("H0", table), 100)],
                         pow_limit=TRIVIAL)
    anchor_rules["duplicate_anchor_len"] = len(st)
    try:
        spv.HeaderStore([(SUBJ, 0)], pow_limit=spv.MAINNET_POW_LIMIT)
        anchor_rules["height0_non_genesis"] = None
    except ValueError as e:
        anchor_rules["height0_non_genesis"] = str(e)
    gst = spv.HeaderStore([(bytes.fromhex(GENESIS_HEX), 0)],
                          pow_limit=spv.MAINNET_POW_LIMIT)
    anchor_rules["height0_genesis_len"] = len(gst)

    # ---- L3 store-derived depth (§5.2.6 / §8.5) ----------------------------
    am = spv.HeaderStore([(resolve("H0", table), 100)], pow_limit=TRIVIAL)
    am_ret = am.add_many([resolve("A", table), resolve("B", table),
                          resolve("B", table)])
    add_many_count = {"returned": am_ret, "len": len(am)}
    assert am_ret == 3 and len(am) == 3   # duplicates still return info (§4.2)
    forged = forge_low_blockheight(BEEF)
    poc_store = spv.HeaderStore([(SUBJ, L3["subject_block"]["height"])])
    env = spv.verify_l3(BEEF, AUTH, poc_store, seen={}, min_depth=1)
    assert env.payload.decode() == L3["expected_payload"]
    env_f = spv.verify_l3(forged, AUTH, poc_store, seen={}, min_depth=1)
    assert env_f.payload.decode() == L3["expected_payload"]  # blockHeight untrusted
    try:
        spv.verify_l3(forged, AUTH, poc_store, seen={}, min_depth=2)
        raise AssertionError("forged low blockHeight must not inflate depth")
    except ValueError as e:
        forged_err = str(e)
    try:
        spv.verify_l3(BEEF, AUTH, [SUBJ], seen={})  # type: ignore[arg-type]
        raise AssertionError("list arg must be rejected")
    except TypeError as e:
        list_err = str(e)

    ref = {
        "meta": {"spec": "BMP-0004 §8.5", "generator": "js_tests/make_headers_ref.py",
                 "fixture": "vectors/mainnet_headers.json",
                 "tie_break": "incumbent (§4.3/§9.1 normative)",
                 "synth_bits": {"easy": f"{EASY_BITS:08x}", "hard": f"{HARD_BITS:08x}"}},
        "mainnet_pow_limit_hex": format(spv.MAINNET_POW_LIMIT, "x"),
        "compact_vectors": vectors,
        "mainnet_easy_pow_fail": {"header_hex": rnd.hex(), "error": rnd_err},
        "work_spots": {
            "difficulty1_target_hex": format(t1, "x"),
            "difficulty1_work_hex": format(floor_w, "x"),
            "genesis_plus_block1_work_hex": format(2 * floor_w, "x"),
            "genesis_chainwork_hex": cw["genesis_chainwork_hex"],
            "block1_chainwork_hex": cw["block1_chainwork_hex"],
            "ceil_counterexample": {"target_hex": format(t1, "x"),
                                    "floor_work_hex": format(floor_w, "x"),
                                    "ceil_work_hex": format(forbidden_w, "x")},
            "fixture_floor_equivalence_count": len(hdrs) if fixture_equiv else 0,
            "difficulty1_target_le_powlimit":
                spv.target_from_bits(0x1D00FFFF) <= spv.MAINNET_POW_LIMIT,
        },
        "synth_headers": table,
        "scenarios": scen,
        "anchor_rules": anchor_rules,
        "add_many_count": add_many_count,
        "fixture_samples": samples,
        "fixture_store_replay": {
            "anchor_height": start_height, "adopted_via_add_many": adopted,
            "final_len": len(fstore), "tip": info_snap(ftip),
            "tip_work_hex": format(ftip["work"], "x"),
            "range_chainwork_delta_hex": cw["range_chainwork_delta_hex"],
        },
        "l3": {"expected_payload": L3["expected_payload"],
               "poc_anchor_height": L3["subject_block"]["height"],
               "forged_beef_hex": forged.hex(),
               "forged_min_depth": 2, "forged_error": forged_err,
               "list_arg_error": list_err},
    }
    out = POC / "js_tests" / "headers_ref.json"
    out.write_text(json.dumps(ref, indent=1) + "\n")
    print(f"WROTE {out} ({out.stat().st_size} bytes): "
          f"{len(vectors)} compact vectors, {len(table)} synth headers, "
          f"{len(scen)} scenarios, {len(samples)} fixture samples")


if __name__ == "__main__":
    main()