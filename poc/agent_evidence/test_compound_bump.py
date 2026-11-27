"""A single BRC-74 path can prove both direct parents in the same block."""
import json
from hashlib import sha256
from pathlib import Path

import pytest
from svcode.spv import bump_root, parse_bump


def digest(data):
    return sha256(sha256(data).digest()).digest()


def compound():
    fixture = Path(__file__).resolve().parents[1] / 'vectors/agent_payment/positive.json'
    parents = json.loads(fixture.read_bytes())['cases'][0]['parents']
    leaves = [digest(b'coinbase'), *(digest(bytes.fromhex(p)) for p in parents), digest(b'fourth')]
    # Height 100; two tree levels. Level 1 is derivable from the four level-0 leaves.
    raw = b'\x64\x02\x04' + b''.join(bytes([i, 2 if i in (1, 2) else 0]) + leaf
                                      for i, leaf in enumerate(leaves)) + b'\x00'
    root = digest(digest(b''.join(leaves[:2])) + digest(b''.join(leaves[2:])))
    return raw, [leaf[::-1].hex() for leaf in leaves[1:3]], root


@pytest.mark.parametrize('which', [0, 1])
def test_existing_walk_resolves_compound_payment_parent(which):
    raw, ids, root = compound()
    assert bump_root(parse_bump(raw), ids[which]) == root
