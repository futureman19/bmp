"""End-to-end decisions against checked-in, independently constructed expectations."""
from dataclasses import asdict, FrozenInstanceError, replace
import json
from pathlib import Path

import pytest
from agent_payment.shape import golden_agreement
from svcode.spv import HeaderStore
from agent_evidence import evaluator

V = json.loads((Path(__file__).resolve().parents[1] / 'vectors/agent_evidence/scenarios.json').read_bytes())
CASES = {c['name']: c for c in V['cases']}
A = golden_agreement()
ID = V['payment_id']


def store(chain):
    raw = lambda n: bytes.fromhex(V['headers'][n])
    s = HeaderStore([(raw('anchor'), 100)], pow_limit=int(V['pow_limit_hex'], 16))
    if chain in ('replacement', 'subject_fork'):
        s.add_many(map(raw, V['chains']['original'][1:]))  # real fork choice, not removal mocks
    s.add_many(map(raw, V['chains'][chain][1:]))
    return s


def run(name='timely_one_block', **overrides):
    c = CASES[name]
    args = dict(beef=bytes.fromhex(V['beefs'][c['beef']]), store=store(c['chain']), agreement=A,
                offer_hash=A.offer, txid=ID.split('.')[0], payment_id=ID, vout=0, amount_sats=A.price,
                policy=c['policy'], conflict_status=c['conflict'], arrival=c['arrival'], pay_by=c['pay_by'],
                prior=run(c['prior']).record if 'prior' in c else None)
    return evaluator.evaluate(**(args | overrides))


@pytest.mark.parametrize('name', CASES)
def test_scenario(name):
    c = CASES[name]
    r = run(name)
    assert r.status == c['expected']
    if 'support' in c:
        assert [asdict(s) for s in r.record.support] == c['support']
        assert r.record.payment_id == ID
        subject = next((s for s in r.record.support if s.role == 'subject'), None)
        assert r.depth == (100 + len(V['chains'][c['chain']]) - subject.height if subject else None)
    if r.status == 'SUSPENDED':
        assert r.reason == 'payment-revalidation-required'
        assert r.record == (run(c['prior']).record if 'prior' in c else None)
    if name.endswith('header_unavailable'):
        assert r.reason == 'verification-unavailable'


@pytest.mark.parametrize('kwargs', [dict(vout=True), dict(vout='0'), dict(vout=-1), dict(vout=2**32),
                                   dict(amount_sats=True), dict(amount_sats=A.price+1), dict(payment_id=None),
                                   dict(payment_id=ID+'0'), dict(txid='00'*32), dict(offer_hash='00'*32)])
def test_payment_binding(kwargs):
    assert run(**kwargs).status == 'INVALID'


def test_historical_record_and_late_latch():
    first = run('first_qualification_late').record
    assert run(prior=first, arrival=999).status == 'LATE'
    restored = run('parent_reproof').record
    old = run().record
    assert restored.first_arrival == old.first_arrival == 1000
    assert restored.first_support == old.support != restored.support
    with pytest.raises(FrozenInstanceError):
        old.support[0].height = 0
    assert run(prior=old, agreement=replace(A, accept='00'*32)).status == 'INVALID'


def test_policy_not_peer_time_or_height():
    wire = bytearray.fromhex(V['beefs']['original']); wire[41] = 1
    r = run(beef=bytes(wire))
    assert r.status == 'CURRENT' and r.record.support[0].height == 101
    old = run().record
    assert run(prior=old, store=store('anchor_only')).reason == 'verification-unavailable'
    assert run(prior=old, policy='zero-conf').status == 'INVALID'


def test_reorg_with_broken_refresh_preserves_suspension():
    old = run().record
    r = run(prior=old, store=store('replacement'), beef=b'malformed')
    assert (r.status, r.reason, r.record) == ('SUSPENDED', 'payment-revalidation-required', old)


def test_depth_retained_across_loss_and_restoration():
    restored = run('parent_reproof').record
    assert (restored.first_depth, restored.depth) == (1, 2)


def test_topological_ancestry_and_unrelated_entries():
    from agent_evidence.vectors import atomic
    from svcode.spv import parse_beef
    b = parse_beef(bytes.fromhex(V['beefs']['original'])[36:])
    proofs = [p['raw'] for p in b['bumps']]
    entries = [(e['raw'], e['bump_index']) for e in b['txs']]
    pay = entries[-1][0]
    unrelated = entries[0][0][:-1] + b'\x01'
    assert run(beef=atomic(pay, proofs, [(unrelated, None), *entries])).status == 'INVALID'


def test_prior_payment_id_cannot_be_transplanted():
    from agent_payment.shape import parse
    fixture = json.loads((Path(__file__).resolve().parents[1] / 'vectors/agent_payment/positive.json').read_bytes())
    raw = bytes.fromhex(fixture['cases'][1]['raw'])
    other = parse(raw)['txid']
    assert other != ID.split('.')[0]
    assert run(txid=other, payment_id=other+'.0', prior=run().record).reason == 'prior-binding'
