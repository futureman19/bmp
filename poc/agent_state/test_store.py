import json
from hashlib import sha256
from pathlib import Path

import pytest
from agent.codec import decode, encode
from agent.vectors import KEYS

ROOT = Path(__file__).resolve().parents[1] / 'vectors'
C1 = json.loads((ROOT / 'agent/positive.json').read_bytes())
NOW = C1['now']
NAMES = ('provider-ad', 'request', 'offer', 'accept', 'ack')
CHAIN = tuple(bytes.fromhex(C1['cases'][n]['envelopeHex']) for n in NAMES)
PAY = json.loads((ROOT / 'agent_payment/positive.json').read_bytes())['cases']


def changed(raw, signer, edit):
    msg = decode(raw)
    edit(msg.payload)
    return encode(msg.action, msg.payload, msg.created, msg.expires, KEYS[signer])


def digest(raw):
    return sha256(raw).hexdigest()


def other_chain():
    ad, req, offer, accept, ack = CHAIN
    thread = digest(b'second request')[:32]
    req = changed(req, 0, lambda p: p.update(threadId=thread, messageId=thread))
    offer = changed(offer, 1, lambda p: (p.update(threadId=thread), p['body']['terms'].update(requestHash=digest(req))))
    accept = changed(accept, 0, lambda p: (p.update(threadId=thread), p['body'].update(offerHash=digest(offer))))
    ack = changed(ack, 1, lambda p: (p.update(threadId=thread), p['body'].update(offerHash=digest(offer), acceptHash=digest(accept))))
    return ad, req, offer, accept, ack


def pair(chain):
    return (decode(chain[1]).payload['threadId'], digest(chain[2]), digest(chain[3]))


def payment(i=0):
    c = PAY[i]
    return dict(raw=bytes.fromhex(c['raw']), parents=tuple(bytes.fromhex(p) for p in c['parents']),
                vout=c['vout'], payment_id=c['paymentId'])


def ready(store, chain=CHAIN):
    store.accept(*chain[:4], now=NOW)
    return store.ack(chain[4], now=NOW)


@pytest.fixture
def store(tmp_path):
    from agent_state.store import Store
    s = Store(tmp_path / 'state.db')
    yield s
    s.close()


def fails(code):
    from agent_state.store import StateError
    return pytest.raises(StateError, match='^' + code + '$')


def test_gate_and_restart(tmp_path):
    from agent_state.store import Store
    key = pair(CHAIN)
    with Store(tmp_path/'s') as s:
        with fails('not-accepted'):
            s.ack(CHAIN[4], now=NOW)
        first = s.accept(*CHAIN[:4], now=NOW+500)
        assert first.accepted_at == NOW+500
        with fails('not-acknowledged'):
            s.authorize_payment_construction(*key, now=NOW+500)
    with Store(tmp_path/'s') as s:
        assert s.get(key[0]) == first
        ack = s.ack(CHAIN[4], now=NOW+501)
        assert ack.ack == CHAIN[4]
        assert s.accept(*CHAIN[:4], now=NOW+9999) == s.ack(CHAIN[4], now=NOW+9999) == ack
        assert s.authorize_payment_construction(*key, now=NOW+502).accept_hash == key[2]
        with fails('conflict'):
            s.authorize_payment_construction(key[0], key[2], key[1], now=NOW+502)
        with fails('expired'):
            s.authorize_payment_construction(*key, now=NOW+601)
        row = s.assign(*key, **payment(), now=NOW+502)
        assert row.state == 'ASSIGNED' and row.payment_id == PAY[0]['paymentId'] and row.raw == payment()['raw']
    with Store(tmp_path/'s') as s:
        assert row == s.get(key[0]) == s.assign(*key, **payment(), now=NOW+9999)
        assert (row.ad, row.request, row.offer, row.accept, row.ack) == CHAIN
        assert [decode(b).action for b in CHAIN][-1] == 'ACCEPT_ACK'
        with fails('conflict'):
            s.authorize_payment_construction(*key, now=NOW+502)


@pytest.mark.parametrize('path', [':memory:', '', 'file::memory:?cache=shared'])
def test_refuse_nondurable_paths(path):
    from agent_state.store import Store
    with fails('not-durable'):
        Store(path)


def test_late_first_arrival_cannot_be_backdated(store):
    with fails('late'):
        store.accept(*CHAIN[:4], now=NOW+501)
    with fails('late'):
        store.accept(*CHAIN[:4], now=NOW+500)
    assert store.get(pair(CHAIN)[0]) is None


def test_competing_connections_assign_once(tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier
    from agent_state.store import Store, StateError
    path = tmp_path / 'race'
    with Store(path) as s:
        ready(s)
    start = Barrier(2)
    def attempt(i):
        with Store(path) as s:
            args, key = payment(i), pair(CHAIN)
            start.wait(timeout=10)
            try:
                return s.assign(*key, **args, now=NOW).payment_id
            except StateError as exc:
                return str(exc)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(attempt, [0, 1]))
    with Store(path) as s:
        winner = s.get(pair(CHAIN)[0])
    assert results.count('conflict') == 1
    assert winner.payment_id in results and winner.raw == bytes.fromhex(next(
        c['raw'] for c in PAY if c['paymentId'] == winner.payment_id))


def test_cross_assignment(tmp_path):
    from agent_state.store import Store
    other = other_chain()
    with Store(tmp_path/'s') as a, Store(tmp_path/'s') as b:
        ready(a)
        second = ready(b, other)
        first = a.assign(*pair(CHAIN), **payment(), now=NOW)
        with fails('conflict'):
            b.assign(*pair(other), **payment(), now=NOW)
        with fails('conflict'):
            b.assign(*pair(CHAIN), **payment(1), now=NOW)
        assert b.get(first.thread) == first and a.get(second.thread) == second


@pytest.mark.parametrize('action', ['accept','ack','ack-pair'])
def test_conflicting_envelopes(store, action):
    original = ready(store)
    if action == 'accept':
        bad = changed(CHAIN[3], 0, lambda p: p.update(messageId=p['threadId']))
        with fails('conflict'):
            store.accept(*CHAIN[:3], bad, now=NOW)
    else:
        bad = changed(CHAIN[4], 1, lambda p: p.update(messageId=p['threadId']) if action == 'ack' else p['body'].update(acceptHash=digest(CHAIN[1])))
        with fails('conflict'):
            store.ack(bad, now=NOW)
    assert store.get(original.thread) == original


@pytest.mark.parametrize('kind', ['role','thread','reference','signature','action','late','expired','future','no-clock','replay'])
def test_reject_chain(store, kind):
    chain = list(CHAIN[:4]); now = NOW
    if kind == 'role':
        chain[3] = changed(chain[3], 1, lambda p: p.update({'from':p['to'], 'to':p['from']}))
    elif kind == 'thread':
        chain[3] = changed(chain[3], 0, lambda p: p.update(threadId=p['messageId']))
    elif kind == 'reference':
        chain[3] = changed(chain[3], 0, lambda p: p['body'].update(offerHash=digest(chain[1])))
    elif kind == 'replay':
        chain[3] = changed(chain[3], 0, lambda p: p.update(messageId=p['threadId']))
    elif kind == 'signature':
        chain[3] = chain[3][:21] + bytes([chain[3][21]^1]) + chain[3][22:]
    elif kind == 'action': chain[3] = CHAIN[4]
    else: now = {'late':NOW+501,'expired':NOW+601,'future':NOW-301,'no-clock':None}[kind]
    with fails({'replay':'conflict','signature':'invalid-message','action':'invalid-message','role':'invalid-message','reference':'invalid-message','thread':'invalid-message','no-clock':'invalid-clock'}.get(kind,kind)):
        store.accept(*chain, now=now)
    assert store.get(pair(CHAIN)[0]) is None


@pytest.mark.parametrize('bad', ['raw','parents','vout','payment_id','missing-id'])
def test_invalid_payment(store, bad):
    before = ready(store)
    args = payment()
    if bad == 'missing-id': args['payment_id'] = None
    else: args[bad] = {'raw':b'','parents':(), 'vout':False,'payment_id':PAY[1]['paymentId']}[bad]
    with fails('invalid-payment'):
        store.assign(*pair(CHAIN), **args, now=NOW)
    assert store.get(before.thread) == before
