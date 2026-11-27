"""Offline checks of the checked-in bytes; no evidence evaluator is used."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import unittest

POC = Path(__file__).resolve().parents[1]
GOLD = POC / 'vectors/agent_evidence/scenarios.json'


def h(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


class EvidenceVectors(unittest.TestCase):
    def fixture(self):
        self.assertTrue(GOLD.is_file(), 'missing checked-in scenarios.json')
        return json.loads(GOLD.read_bytes())

    def test_check(self):
        cmd = [sys.executable, str(POC / 'agent_evidence/vectors.py'), '--check']
        self.assertEqual(subprocess.run(cmd, check=False).returncode, 0)

    def test_headers_and_support(self):
        v = self.fixture()
        headers = {k: bytes.fromhex(s) for k, s in v['headers'].items()}
        for path in v['chains'].values():
            self.assertEqual(path[0], 'anchor')
            for i, name in enumerate(path):
                raw = headers[name]
                self.assertEqual(len(raw), 80)
                self.assertEqual(raw[72:76], bytes.fromhex('ffff7f20'))
                self.assertLessEqual(int.from_bytes(h(raw), 'little'), 0x7fffff << 232)
                if i:
                    self.assertEqual(raw[4:36], h(headers[path[i - 1]]))
        self.assertEqual(v['anchor_height'], 100)
        seen = set()
        for c in v['cases']:
            self.assertNotIn(c['name'], seen)
            if 'prior' in c:
                self.assertIn(c['prior'], seen)
            seen.add(c['name'])
            if c['expected'] == 'CURRENT':
                records = c['support']
                self.assertEqual(sum(r['role'] == 'parent' for r in records), 2)
                for r in records:
                    raw = headers[v['chains'][c['chain']][r['height'] - 100]]
                    self.assertEqual(r['block_hash'], h(raw)[::-1].hex())
                    self.assertEqual(r['root'], raw[36:68].hex())
        self.assertEqual({c['expected'] for c in v['cases']}, {'CURRENT','PENDING','LATE','INVALID','SUSPENDED'})

    def test_forks_isolate_parent_and_subject_loss(self):
        v = self.fixture()
        by_name = {c['name']: c for c in v['cases']}
        def roots(name):
            return [r['root'] for r in by_name[name]['support']]
        old = roots('timely_one_block')
        new = roots('parent_reproof')
        fork = roots('subject_only_reproof')
        self.assertEqual(old[:2], fork[:2])
        self.assertNotEqual(old[2], fork[2])
        self.assertTrue(set(old).isdisjoint(new))
        self.assertEqual(by_name['zero_conf_parent_loss']['expected'], 'SUSPENDED')
        self.assertEqual(by_name['late_after_missing_subject']['prior'], 'subject_proof_missing')
        self.assertEqual(by_name['late_after_missing_subject']['expected'], 'LATE')

    def test_c2_compound_bytes(self):
        v = self.fixture()
        c2 = json.loads((POC / 'vectors/agent_payment/positive.json').read_bytes())['cases'][0]
        parents = list(map(bytes.fromhex, c2['parents']))
        subject = bytes.fromhex(c2['raw'])
        wire = bytes.fromhex(v['beefs']['original'])
        self.assertEqual(wire[:41], bytes.fromhex('01010101') + h(subject) + bytes.fromhex('0100beef02'))
        self.assertEqual(wire[-(1+sum(map(len,parents))+len(subject)+6):],
                         b'\x03' + b''.join(p+b'\x01\x00' for p in parents) + subject+b'\x01\x01')
        self.assertEqual(wire[41:44], bytes([101, 2, 4]))
        leaves = []
        for i in range(4):
            pos = 44 + 34*i
            self.assertEqual(wire[pos:pos+2], bytes([i, 2 if i in (1,2) else 0]))
            leaves.append(wire[pos+2:pos+34])
        self.assertEqual(leaves[1:3], list(map(h, parents)))
        self.assertEqual(wire[180], 0)  # derived upper nodes, no explicit hashes
        root = h(h(leaves[0]+leaves[1])+h(leaves[2]+leaves[3]))
        self.assertEqual(root.hex(), v['headers']['parents'][72:136])


if __name__ == '__main__':
    unittest.main()
