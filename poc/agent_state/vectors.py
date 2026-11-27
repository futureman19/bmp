"""Portable C3 transition recipes referencing checked-in C1 and C2 fixtures."""
import argparse
import json
from pathlib import Path

from .store import Store, StateError

ROOT = Path(__file__).resolve().parents[1] / 'vectors/agent_state'


def inputs():
    c1 = json.loads((ROOT.parent/'agent/positive.json').read_bytes())
    c2 = json.loads((ROOT.parent/'agent_payment/positive.json').read_bytes())
    return c1['cases'], c2['cases'], c1['now']


def artifacts():
    c, payments, now = inputs()
    key = [c['request']['messageId'], c['offer']['sha256'], c['accept']['sha256']]

    def case(name, *steps):
        return dict(name=name, pair=key, ackHash=c['ack']['sha256'],
                    paymentIds=[p['paymentId'] for p in payments],
                    steps=[dict(action=a, now=now+t, expect=e) for a,t,e in steps])

    accept = ('accept', 0, 'ACCEPTED')
    ack = ('ack', 0, 'ACKNOWLEDGED')
    authorize = ('authorize', 0, 'AUTHORIZED')
    assign = ('assign:0', 0, 'ASSIGNED')
    cases = {'positive': [case('accept-ack-authorize', accept, ack, authorize),
                          case('assign-and-retry', accept, ack, assign, ('assign:0', 10000, 'ASSIGNED'))],
             'negative': [case('ack-first', ('ack', 0, 'not-accepted')),
                          case('accept-only', accept, ('authorize', 0, 'not-acknowledged')),
                          case('late-accept', ('accept', 501, 'late')),
                          case('expired-ack', accept, ack, ('authorize', 601, 'expired')),
                          case('replacement', accept, ack, assign, ('assign:1', 1, 'conflict'))]}
    return {name+'.json': (json.dumps({'version':1, 'cases':rows}, indent=2)+'\n').encode()
            for name,rows in cases.items()}


def replay(case, path):
    c, payments, _ = inputs()
    chain = [bytes.fromhex(c[n]['envelopeHex']) for n in ('provider-ad','request','offer','accept','ack')]
    with Store(path) as store:
        for step in case['steps']:
            op, now = step['action'], step['now']
            try:
                if op == 'accept': result = store.accept(*chain[:4], now=now).state
                elif op == 'ack': result = store.ack(chain[4], now=now).state
                elif op == 'authorize':
                    auth = store.authorize_payment_construction(*case['pair'], now=now)
                    assert auth.ack_hash == case['ackHash']
                    result = 'AUTHORIZED'
                else:
                    idx = int(op.split(':')[1]); p = payments[idx]
                    result = store.assign(*case['pair'], raw=bytes.fromhex(p['raw']),
                                          parents=[bytes.fromhex(x) for x in p['parents']], vout=p['vout'],
                                          payment_id=case['paymentIds'][idx], now=now).state
            except StateError as exc:
                result = str(exc)
            assert result == step['expect'], (case['name'], op, result)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--check', action='store_true')
    check = parser.parse_args().check
    first = artifacts()
    if first != artifacts(): raise SystemExit('non-deterministic generation')
    for name, data in first.items():
        path = ROOT / name
        if not check: path.write_bytes(data)
        if path.read_bytes() != data: raise SystemExit(f'mismatch: {name}')
        print(f'{name}: {len(json.loads(data)["cases"])} transition recipes, byte-identical')
