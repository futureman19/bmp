#!/usr/bin/env python3
"""One-shot generator for poc/vectors/mainnet_headers.json (BMP-0004 §8.1).

Fetches 300 consecutive real mainnet headers (heights 969496..969795, ending
at the block anchoring poc/vectors/l3_live.json) by walking `previousblockhash`
BACKWARDS from the subject blockhash via WhatsOnChain. Requests are
serialized with backoff on 429/5xx/connection errors. This script is the ONLY
place network access is allowed; the frozen fixture is what tests consume.

Validated at generation time (§8.1 step 4):
  * linkage: each header's prev_hash is the next-lower header's hash, and the
    assembled 80 bytes hash to the indexer's claimed block hash;
  * heights descend by 1 (checked against the indexer's `height` field);
  * every header passes §3.2 under MAINNET_POW_LIMIT (real PoW);
  * per-block work from the floor form (§3.4) matches the indexer's
    cumulative `chainwork` deltas for ALL 300 blocks, plus the genesis /
    block-1 chainwork cross-check required by §9.1.

Usage:  python3 make_header_fixtures.py [--force]
Without --force, an existing fixture is re-validated OFFLINE and kept.
Fetched responses are cached under ~/.cache/bmp-header-fixtures/ so an
interrupted walk resumes without re-fetching.
"""
from __future__ import annotations

import json
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from svcode import spv

ROOT = Path(__file__).resolve().parent
WOC = "https://api.whatsonchain.com/v1/bsv/main"
OUT = ROOT / "vectors" / "mainnet_headers.json"
CACHE = Path.home() / ".cache" / "bmp-header-fixtures"
N_HEADERS = 300
BLOCK1_HASH = "00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048"
POW_LIMIT_HEX = format(spv.MAINNET_POW_LIMIT, "064x")


def fetch_block_json(hash_display: str, tries: int = 8) -> dict:
    """GET /block/{hash}/header (returns height + chainwork too). Serialized,
    cached, exponential backoff on 429/5xx/transient network errors."""
    cf = CACHE / f"{hash_display}.json"
    if cf.exists():
        return json.loads(cf.read_text())
    delay = 1.0
    last = None
    for _ in range(tries):
        try:
            req = urllib.request.Request(
                f"{WOC}/block/{hash_display}/header",
                headers={"User-Agent": "bmp-fixture-generator/1.0"})
            with urllib.request.urlopen(req, timeout=30) as r:
                doc = json.load(r)
            CACHE.mkdir(parents=True, exist_ok=True)
            cf.write_text(json.dumps(doc))
            return doc
        except urllib.error.HTTPError as e:
            last = e
            if e.code == 429 or e.code >= 500:
                time.sleep(delay)
                delay = min(delay * 2, 60)
                continue
            raise
        except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as e:
            last = e
            time.sleep(delay)
            delay = min(delay * 2, 60)
    raise RuntimeError(f"failed to fetch {hash_display}: {last}")


def assemble_header(h: dict) -> bytes:
    """Byte assembly identical to poc/l3_live.py fetch_header. Genesis has an
    empty previousblockhash on WoC ⇒ 32 zero bytes (consensus convention)."""
    prev = h.get("previousblockhash") or ""
    prev_bytes = bytes.fromhex(prev)[::-1] if prev else b"\x00" * 32
    return b"".join([
        int(h["version"]).to_bytes(4, "little"),
        prev_bytes,
        bytes.fromhex(h["merkleroot"])[::-1],
        int(h["time"]).to_bytes(4, "little"),
        bytes.fromhex(h["bits"])[::-1],
        int(h["nonce"]).to_bytes(4, "little"),
    ])


def entry_from(h: dict, header: bytes, info: dict) -> dict:
    return {"height": h["height"], "hash": info["hash"],
            "header_hex": header.hex(), "nbits_hex": h["bits"]}


def validate_fixture(fix: dict) -> None:
    """Offline re-validation of a frozen fixture (§3.2 + linkage + heights)."""
    entries = [fix["anchor"]] + fix["headers"]
    rng = fix["range"]
    lo, hi = rng["first_height"], rng["last_height"]
    assert len(entries) == N_HEADERS == hi - lo + 1 == rng["count"]
    assert fix["source"] == WOC
    assert fix["pow_limit_hex"] == POW_LIMIT_HEX
    prev_entry = None
    for i, e in enumerate(entries):
        hdr = bytes.fromhex(e["header_hex"])
        info = spv.verify_header(hdr)              # §3.2, mainnet pow_limit
        assert info["hash"] == e["hash"], f"hash mismatch at {e['height']}"
        assert e["height"] == lo + i, f"height gap at index {i}"
        bits = int.from_bytes(hdr[72:76], "little")
        assert format(bits, "08x") == e["nbits_hex"]
        if prev_entry is not None:
            assert info["prev_hash"][::-1].hex() == prev_entry["hash"], \
                f"linkage break at {e['height']}"
        prev_entry = e
    # work cross-check metadata must be internally consistent
    cw = fix["chainwork_crosscheck"]
    assert cw["genesis_chainwork_hex"] == format(
        spv.block_work(spv.target_from_bits(0x1D00FFFF)), "x") == "100010001"
    assert cw["block1_chainwork_hex"] == "200020002"


def generate() -> dict:
    live = json.loads((ROOT / "vectors" / "l3_live.json").read_text())
    subj_hash = live["subject_block"].get("blockhash")
    if not subj_hash:
        # older frozen vectors carry only height + header_hex; the blockhash
        # is deterministic from the frozen 80 bytes (double-SHA256, reversed)
        subj_hash = spv.verify_header(
            bytes.fromhex(live["subject_block"]["header_hex"]))["hash"]
    subj_height = live["subject_block"]["height"]
    lo = subj_height - (N_HEADERS - 1)

    # walk backwards: index 0 = subject (highest), index 299 = anchor (lowest)
    walk = []
    cur = subj_hash
    for i in range(N_HEADERS):
        h = fetch_block_json(cur)
        hdr = assemble_header(h)
        info = spv.verify_header(hdr)              # real PoW, mainnet params
        assert info["hash"] == h["hash"] == cur, "assembly/hash mismatch"
        assert h["height"] == subj_height - i, "height did not descend by 1"
        walk.append((h, hdr, info))
        cur = h["previousblockhash"]
        time.sleep(0.12)                           # serialized, polite pacing
        if (i + 1) % 50 == 0:
            print(f"  fetched {i + 1}/{N_HEADERS} (height {h['height']})",
                  flush=True)
    # one extra: the anchor's parent, for the cumulative-work delta check
    anchor_parent = fetch_block_json(cur)
    assert anchor_parent["height"] == lo - 1

    # §9.1 genesis / block-1 chainwork cross-check, live from the indexer
    gen = fetch_block_json(spv.MAINNET_GENESIS_HASH)
    b1 = fetch_block_json(BLOCK1_HASH)
    gen_hdr, b1_hdr = assemble_header(gen), assemble_header(b1)
    spv.verify_header(gen_hdr)
    spv.verify_header(b1_hdr)
    gen_work = spv.block_work(spv.target_from_bits(
        int.from_bytes(gen_hdr[72:76], "little")))
    b1_work = spv.block_work(spv.target_from_bits(
        int.from_bytes(b1_hdr[72:76], "little")))
    assert gen["height"] == 0 and b1["height"] == 1
    assert int(gen["chainwork"], 16) == gen_work == 0x100010001, \
        "genesis chainwork cross-check failed"
    assert int(b1["chainwork"], 16) == gen_work + b1_work == 0x200020002, \
        "block-1 chainwork cross-check failed"

    # per-block work vs indexer chainwork deltas across the whole range
    ascending = list(reversed(walk))               # lowest .. highest
    prev_cw = int(anchor_parent["chainwork"], 16)
    for h, hdr, info in ascending:
        target = spv.target_from_bits(int.from_bytes(hdr[72:76], "little"))
        cw = int(h["chainwork"], 16)
        assert cw - prev_cw == spv.block_work(target), \
            f"work delta mismatch at height {h['height']}"
        prev_cw = cw
    range_delta = prev_cw - int(anchor_parent["chainwork"], 16)

    # continuity with the frozen live vector: subject header byte-identical
    assert walk[0][1].hex() == live["subject_block"]["header_hex"]

    anchor_h, anchor_hdr, anchor_info = ascending[0]
    fix = {
        "note": ("300 consecutive real mainnet headers (969496..969795) "
                 "ending at the block anchoring l3_live.json; frozen evidence "
                 "for BMP-0004 §8.1, generated by poc/make_header_fixtures.py "
                 "(one-shot; tests NEVER hit the network). Every header passes "
                 "§3.2 under MAINNET_POW_LIMIT; linkage, heights and per-block "
                 "work were validated against WhatsOnChain at generation."),
        "source": WOC,
        "fetched_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "range": {"first_height": lo, "last_height": subj_height,
                  "count": N_HEADERS},
        "pow_limit_hex": POW_LIMIT_HEX,
        "anchor": entry_from(anchor_h, anchor_hdr, anchor_info),
        "headers": [entry_from(h, hdr, info) for h, hdr, info in ascending[1:]],
        "chainwork_crosscheck": {
            "genesis_hash": spv.MAINNET_GENESIS_HASH,
            "genesis_chainwork_hex": format(gen_work, "x"),
            "block1_hash": BLOCK1_HASH,
            "block1_chainwork_hex": format(gen_work + b1_work, "x"),
            "anchor_parent_height": lo - 1,
            "anchor_parent_chainwork_hex": anchor_parent["chainwork"],
            "tip_chainwork_hex": walk[0][0]["chainwork"],
            "range_chainwork_delta_hex": format(range_delta, "x"),
            "per_block_work_matches_indexer": True,
            "verified_via": "WoC /block/{hash}/header chainwork field at generation",
        },
    }
    validate_fixture(fix)
    return fix


def main() -> None:
    force = "--force" in sys.argv
    if OUT.exists() and not force:
        fix = json.loads(OUT.read_text())
        validate_fixture(fix)
        print(f"{OUT.name} exists and re-validates offline "
              f"({len(fix['headers']) + 1} headers, range {fix['range']}); "
              f"use --force to regenerate")
        return
    fix = generate()
    OUT.write_text(json.dumps(fix, indent=1) + "\n")
    size = OUT.stat().st_size
    print(f"wrote {OUT} ({size} bytes, {N_HEADERS} headers, "
          f"range {fix['range']})")
    assert size < 1024 * 1024, "fixture exceeds the §8.1 ~1MB budget"


if __name__ == "__main__":
    main()