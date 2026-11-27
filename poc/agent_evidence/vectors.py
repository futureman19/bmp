"""Construct C4 evidence from C2 wire bytes, without the parser or evaluator.

Run directly to regenerate; --check compares exact bytes without writing.
Hashes in support records: txid/block_hash display hex, root header-wire hex.
"""
import argparse
import json
import struct
from hashlib import sha256
from pathlib import Path

POC = Path(__file__).resolve().parents[1]
ROOT = POC / 'vectors/agent_evidence'
GOLD = ROOT / 'scenarios.json'
BITS = 0x207fffff
TARGET = 0x7fffff << 232


def digest(data):
    return sha256(sha256(data).digest()).digest()


def mine(prev, root, timestamp):
    prefix = struct.pack('<I', 1) + prev + root + struct.pack('<II', timestamp, BITS)
    for n in range(2**32):
        raw = prefix + struct.pack('<I', n)
        if int.from_bytes(digest(raw), 'little') <= TARGET:
            return raw
    raise AssertionError('exhausted fixture nonce range')


def proof(height, leaves, marked):
    # Complete two- or four-leaf synthetic block; upper level is derivable.
    assert len(leaves) in (2, 4)
    depth = 1 if len(leaves) == 2 else 2
    raw = bytes((height, depth, len(leaves))) + b''.join(
        bytes((i, 2 if i in marked else 0)) + leaf for i, leaf in enumerate(leaves))
    level = leaves
    while len(level) > 1:
        level = [digest(a + b) for a, b in zip(level[::2], level[1::2])]
    return raw + bytes(depth - 1), level[0]


def atomic(subject, bumps, entries):
    # All CompactSize fields here fit one byte. None means a full unmined tx.
    return (bytes.fromhex('01010101') + digest(subject) + bytes.fromhex('0100beef') +
            bytes([len(bumps)]) + b''.join(bumps) + bytes([len(entries)]) +
            b''.join(tx + (b'\0' if i is None else bytes([1, i])) for tx, i in entries))


def build():
    c2 = json.loads((POC / 'vectors/agent_payment/positive.json').read_bytes())['cases'][0]
    parents = list(map(bytes.fromhex, c2['parents']))
    subject = bytes.fromhex(c2['raw'])
    ids = list(map(digest, parents))
    sid = digest(subject)
    assert len(ids) == 2 and c2['paymentId'] == sid[::-1].hex() + '.' + str(c2['vout'])
    paths, roots = {}, {}
    for name, cb in [('parents', b'coinbase'), ('new_parents', b'new coinbase')]:
        paths[name], roots[name] = proof(101, [digest(cb), *ids, digest(b'fourth')], {1, 2})
    for name in ['subject', 'new_subject', 'fork_subject']:
        paths[name], roots[name] = proof(102, [digest(name.encode()), sid], {1})
    headers = {}

    def block(name, prev, height):
        headers[name] = mine(digest(headers[prev]) if prev else bytes(32),
                             roots.get(name, digest(name.encode())), 1700000000 + height)

    block('anchor', None, 100)
    chains = {'original': ['anchor', 'parents', 'subject'],
              'replacement': ['anchor', 'new_parents', 'new_subject', 'replacement_tip'],
              'subject_fork': ['anchor', 'parents', 'fork_subject', 'fork_tip'],
              'parents_only': ['anchor', 'parents'], 'anchor_only': ['anchor']}
    for chain in chains.values():
        for i, (prev, name) in enumerate(zip(chain, chain[1:]), 101):
            if name not in headers:
                block(name, prev, i)

    parent_entries = [(p, 0) for p in parents]
    entries = parent_entries + [(subject, 1)]
    orig_paths = [paths['parents'], paths['subject']]
    full = atomic(subject, orig_paths, entries)
    beefs = {'original': full,
             'replacement': atomic(subject, [paths['new_parents'], paths['new_subject']], entries),
             'subject_fork': atomic(subject, [paths['parents'], paths['fork_subject']], entries),
             'parents_only': atomic(subject, orig_paths[:1], parent_entries + [(subject, None)]),
             'missing_parent_proof': atomic(subject, orig_paths, [(parents[0], None), *entries[1:]]),
             'missing_parent': atomic(subject, orig_paths, entries[1:]),
             'substituted_parent': atomic(subject, orig_paths, [(bytes.fromhex(c2['parents'][0])[:-1]+b'\x01', 0), *entries[1:]]),
             'wrong_last_subject': atomic(subject, orig_paths, entries[::-1]),
             'unknown_root': full[:46] + bytes([full[46] ^ 1]) + full[47:],
             'bad_flag': full[:-2] + b'\x02\x01',
             'truncated': full[:-1], 'trailing': full + b'\x00', 'bare_v1': full[36:],
             'wrong_atomic_id': full[:4] + sid[::-1] + full[36:],
             'bad_index': full[:-1] + b'\x02',
             'duplicate_entry': atomic(subject, orig_paths, [entries[0], *entries]),
             'wrong_assigned_path': atomic(subject, orig_paths, [(parents[0], 1), *entries[1:]])}
    cases = []

    def case(name, expected, chain='original', beef='original', policy='one-block',
             conflict='clear', arrival=1000, prior=None, supported=()):
        c = dict(name=name, chain=chain, beef=beef, policy=policy, conflict=conflict,
                 arrival=arrival, pay_by=1000, expected=expected)
        if prior is not None:
            c['prior'] = prior
        if supported:
            c['support'] = []
            for entity, header in zip([*ids, sid], supported):
                c['support'].append(dict(role='subject' if entity == sid else 'parent',
                    txid=entity[::-1].hex(), height=100 + chains[chain].index(header),
                    block_hash=digest(headers[header])[::-1].hex(), root=headers[header][36:68].hex()))
        cases.append(c)

    original = ('parents', 'parents', 'subject')
    replacement = ('new_parents', 'new_parents', 'new_subject')
    case('timely_one_block', 'CURRENT', supported=original)
    case('zero_conf', 'CURRENT', chain='parents_only', beef='parents_only', policy='zero-conf', supported=original[:2])
    case('subject_proof_missing', 'PENDING', beef='parents_only')
    case('parent_proof_missing', 'PENDING', beef='missing_parent_proof')
    case('parent_header_unavailable', 'PENDING', chain='anchor_only')
    case('subject_header_unavailable', 'PENDING', chain='parents_only')
    case('first_qualification_late', 'LATE', arrival=1001)
    case('late_after_missing_subject', 'LATE', prior='subject_proof_missing', arrival=1001)
    case('zero_conf_parent_loss', 'SUSPENDED', chain='replacement', beef='parents_only', policy='zero-conf',
         prior='zero_conf', arrival=1001)
    case('conflict_after_payment', 'SUSPENDED', chain='parents_only', beef='parents_only', policy='zero-conf',
         prior='zero_conf', conflict='conflicted', arrival=1001)
    case('parent_reorg', 'SUSPENDED', chain='replacement', prior='timely_one_block', arrival=1001)
    case('parent_reproof', 'CURRENT', chain='replacement', beef='replacement', prior='parent_reorg',
         arrival=1002, supported=replacement)
    case('subject_only_reorg', 'SUSPENDED', chain='subject_fork', prior='timely_one_block', arrival=1001)
    case('subject_only_reproof', 'CURRENT', chain='subject_fork', beef='subject_fork', prior='subject_only_reorg',
         arrival=1002, supported=('parents', 'parents', 'fork_subject'))
    case('strengthened', 'CURRENT', policy='zero-conf', prior='zero_conf', arrival=1010, supported=original)
    case('late_stays_late', 'LATE', prior='first_qualification_late', arrival=1020)
    case('missing_parent', 'PENDING', beef='missing_parent')
    case('unknown_root', 'PENDING', beef='unknown_root')
    case('conflict_unavailable', 'PENDING', policy='zero-conf', beef='parents_only', conflict='unavailable')
    case('conflicted', 'SUSPENDED', policy='zero-conf', beef='parents_only', conflict='conflicted')
    for name in ['bad_flag', 'substituted_parent', 'wrong_last_subject', 'truncated', 'trailing', 'bare_v1', 'wrong_atomic_id', 'bad_index', 'duplicate_entry', 'wrong_assigned_path']:
        case(name, 'INVALID', beef=name)
    return dict(anchor_height=100, pow_limit_hex=f'{TARGET:064x}', payment_id=c2['paymentId'],
                headers={k: v.hex() for k, v in headers.items()}, chains=chains,
                beefs={k: v.hex() for k, v in beefs.items()}, cases=cases)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    data = (json.dumps(build(), indent=2) + '\n').encode('ascii')
    if args.check:
        if not GOLD.is_file() or GOLD.read_bytes() != data:
            parser.exit(1, 'missing or stale scenarios.json\n')
        print('scenarios.json matches')
    else:
        ROOT.mkdir(parents=True, exist_ok=True)
        GOLD.write_bytes(data)


if __name__ == '__main__':
    main()
