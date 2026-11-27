"""C5 uses signed agreements, real payment signatures and local PoW forks."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import sqlite3
from threading import Barrier

import pytest
from agent.codec import decode
from agent_evidence.test_evaluate import V, store as headers
from agent_evidence.vectors import atomic, digest as dh, mine, proof
from agent_payment.shape import build, golden_agreement, parse
from agent_state.store import Store, SCHEMA
from agent_state.test_store import CHAIN, NOW, changed, digest, fails, pair, payment, ready

KEY = pair(CHAIN)
BY = decode(CHAIN[2]).payload['body']['terms']['payBy']
B = {k: bytes.fromhex(v) for k, v in V['beefs'].items()}


def assigned(s, i=0):
    ready(s)
    return s.assign(*KEY, **payment(i), now=NOW)


def opts(chain='original', conflict='clear', now=BY):
    return dict(headers=headers(chain), conflict_status=conflict, now=now)


@pytest.mark.parametrize('offset,status', [(0,'CURRENT'), (1,'LATE')])
def test_first_complete_and_restart(tmp_path, offset, status):
    path = tmp_path/'ledger'
    with Store(path) as s:
        assigned(s)
        r = s.submit_evidence(KEY[0], B['parents_only'], **opts(now=BY+offset))
        assert r.status == status and r.record.first_arrival == BY+offset
        assert not r.authorized
    with Store(path) as s:
        again = s.authorize_delivery(KEY[0], **opts(now=BY-1))
        assert again.record == r.record and again.status == status
        assert again.authorized == (offset == 0)
        assert s.get(KEY[0]).paid_at == (None if offset else BY)
        assert s.get(KEY[0]).state == ('ASSIGNED' if offset else 'PAID')


def test_live_fork_and_history(tmp_path):
    path = tmp_path/'ledger'; h = headers('original')
    args = opts(); args['headers'] = h
    with Store(path) as s:
        assigned(s)
        first = s.submit_evidence(KEY[0], B['parents_only'], **args)
        strong = s.authorize_delivery(KEY[0], beef=B['original'], **args)
        assert strong.authorized and strong.depth == 1 and first.depth is None
        h.add_many(bytes.fromhex(V['headers'][n]) for n in V['chains']['replacement'][1:])
        lost = s.authorize_delivery(KEY[0], **args)
        assert (lost.status,lost.reason,lost.authorized) == ('SUSPENDED','payment-revalidation-required',False)
        assert lost.depth is None and lost.record == strong.record
    with Store(path) as s:
        assert s.evidence_history(KEY[0])[-1] == lost
        restored = s.authorize_delivery(KEY[0], beef=B['replacement'], **opts('replacement', now=BY+999))
        assert restored.authorized and restored.depth == 2 and restored.record.first_support == first.record.support
    with Store(path) as s:
        assert s.evidence_history(KEY[0]) == [first,strong,lost,restored]
        assert s.authorize_delivery(KEY[0], **opts('replacement', now=BY+1000)).authorized


@pytest.mark.parametrize('wire,chain,conflict,status,reason', [
    (b'', 'original','clear','PENDING','missing-evidence'),
    (B['unknown_root'], 'original','clear','PENDING','verification-unavailable'),
    (B['original'], 'anchor_only','clear','PENDING','verification-unavailable'),
    (B['truncated'], 'original','clear','INVALID','invalid-evidence'),
    (B['parents_only'], 'original','unavailable','PENDING','conflict-policy-unavailable'),
    (B['parents_only'], 'original','conflicted','SUSPENDED','payment-revalidation-required')],
    ids=['empty','unknown-root','headers-missing','malformed','no-conflict-policy','conflicted'])
def test_denials_do_not_start_clock(tmp_path,wire,chain,conflict,status,reason):
    with Store(tmp_path/'db') as s:
        assigned(s)
        denied = s.authorize_delivery(KEY[0], beef=wire, **opts(chain, conflict))
        assert (denied.status,denied.reason,denied.record,denied.authorized) == (status,reason,None,False)
        assert s.submit_evidence(KEY[0], B['original'], **opts(now=BY+1)).status == 'LATE'


def test_no_substitute_inputs_or_raw_subject(tmp_path):
    with Store(tmp_path/'db') as s:
        ready(s)
        with fails('not-assigned'):
            s.submit_evidence(KEY[0], B['original'], **opts())
        assigned(s,1)
        assert s.submit_evidence(KEY[0], B['original'], **opts()).status == 'INVALID'
        for key in ('prior','arrival','payment_id','vout','amount_sats','agreement','offer_hash','accept_hash','policy','pay_by'):
            with pytest.raises(TypeError):
                s.authorize_delivery(KEY[0], beef=B['original'], **opts(), **{key:None})
        # Fault injection: the outpoint column still matches the supplied BEEF, raw doesn't.
        # Switch to a separate real assignment: a historical outpoint cannot be edited.
        with pytest.raises(sqlite3.IntegrityError):
            s._db.execute('UPDATE agreements SET payment_id=?', (payment()['payment_id'],))
    with Store(tmp_path/'corrupt') as s:
        assigned(s)
        s._db.execute('UPDATE agreements SET raw=?', (payment(1)['raw'],))
        assert s.submit_evidence(KEY[0], B['original'], **opts()).reason == 'assigned-raw-mismatch'
        assert s.get(KEY[0]).state == 'ASSIGNED'


@pytest.mark.parametrize('mutation', ['thread','offer','accept','amount'])
def test_other_signed_terms_cannot_use_assigned_evidence(tmp_path, mutation):
    from agent_state.test_store import other_chain
    chain = list(other_chain() if mutation == 'thread' else CHAIN)
    if mutation in ('offer','amount'):
        chain[2] = changed(chain[2], 1, lambda p: p['body']['terms'].update(
            {'priceSats':2501} if mutation == 'amount' else {'payBy':BY-1}))
    if mutation != 'thread':
        chain[3] = changed(chain[3], 0, lambda p: (p.update(messageId='ab'*16),
                                                   p['body'].update(offerHash=digest(chain[2]))))
        chain[4] = changed(chain[4], 1, lambda p: p['body'].update(offerHash=digest(chain[2]),acceptHash=digest(chain[3])))
    key = pair(chain)
    with Store(tmp_path/'db') as s:
        ready(s, chain)
        with fails('invalid-payment'):
            s.assign(*key, **payment(), now=NOW)
        with fails('not-assigned'):
            s.authorize_delivery(key[0], beef=B['original'], **opts())
        assert s.evidence_history(key[0]) == []


def test_durable_paid_not_permission(tmp_path):
    with Store(tmp_path/'db') as s:
        assigned(s)
        first = s.authorize_delivery(KEY[0], beef=B['parents_only'], **opts())
        for args, status in [(opts(conflict='conflicted'), 'SUSPENDED'), (opts(conflict='unavailable'), 'PENDING'),
                             (opts('anchor_only'), 'PENDING'), (opts() | {'headers':None}, 'PENDING')]:
            denied = s.authorize_delivery(KEY[0], **args)
            assert denied.status == status and not denied.authorized and denied.record == first.record
            assert s.get(KEY[0]).paid_at == BY
        assert s.authorize_delivery(KEY[0], **opts(now=BY+1)).authorized


def test_migrate_v1(tmp_path):
    path = tmp_path/'old'; p = payment()
    db = sqlite3.connect(path)
    db.execute(SCHEMA); db.execute('CREATE TABLE late_accepts(accept_hash TEXT PRIMARY KEY, first_arrival INTEGER NOT NULL)')
    db.execute('INSERT INTO agreements VALUES(?,?,?,?,?,?,?,?,?,?,?,?)', (*KEY,*CHAIN[:4],NOW,CHAIN[-1],NOW,p['payment_id'],p['raw']))
    db.execute("INSERT INTO late_accepts VALUES('kept',123)"); db.execute('PRAGMA user_version=1'); db.commit(); db.close()
    with Store(path) as s:
        assert s._db.execute('PRAGMA user_version').fetchone() == (2,)
        assert s._db.execute('SELECT * FROM late_accepts').fetchone() == ('kept',123)
        assert s.get(KEY[0]).raw == p['raw'] and s.evidence_history(KEY[0]) == []
        assert s.authorize_delivery(KEY[0], beef=B['original'], **opts()).authorized


def test_rollback_after_state_write(tmp_path):
    with Store(tmp_path/'db') as s:
        assigned(s)
        s._db.execute("CREATE TEMP TRIGGER fault AFTER UPDATE OF evidence_revision ON agreements BEGIN SELECT RAISE(ABORT,'fault'); END")
        with pytest.raises(sqlite3.IntegrityError, match='fault'):
            s.submit_evidence(KEY[0], B['original'], **opts())
        assert s.get(KEY[0]).state == 'ASSIGNED' and s.evidence_history(KEY[0]) == []
        s._db.execute('DROP TRIGGER fault')
        first = s.submit_evidence(KEY[0], B['original'], **opts())
        s._db.execute("CREATE TEMP TRIGGER fault AFTER UPDATE OF evidence_revision ON agreements BEGIN SELECT RAISE(ABORT,'fault'); END")
        with pytest.raises(sqlite3.IntegrityError, match='fault'):
            s.authorize_delivery(KEY[0], **opts('replacement'))
        assert s.evidence_history(KEY[0]) == [first] and s.get(KEY[0]).paid_at == BY


def test_competing_first_and_fork_rechecks(tmp_path):
    path = tmp_path/'race'
    with Store(path) as s:
        assigned(s)
    def race(jobs):
        gate = Barrier(2)
        def worker(job):
            with Store(path) as s:
                wire, args = job; gate.wait(timeout=10)
                return s.authorize_delivery(KEY[0], beef=wire, **args)
        with ThreadPoolExecutor(2) as ex:
            return list(ex.map(worker,jobs))
    a,b = race([(B['original'],opts(now=BY-1)),(B['original'],opts())])
    assert a.authorized and b.authorized and a.record.first_arrival == b.record.first_arrival
    race([(B['replacement'],opts('replacement',now=BY+10)),(B['original'],opts('replacement',now=BY+11))])
    with Store(path) as s:
        hist = s.evidence_history(KEY[0]); row = s.get(KEY[0])
        assert len(hist) == 4 and hist[-1].revision == row.evidence_revision
        assert row.paid_at == a.record.first_arrival and all(r.record.first_support == a.record.first_support for r in hist)
        assert all(r.authorized == (r.status=='CURRENT') for r in hist)
        for sql in ('DELETE FROM evidence_history','UPDATE evidence_history SET reason=reason',
                    'INSERT OR REPLACE INTO evidence_history SELECT * FROM evidence_history'):
            with pytest.raises(sqlite3.IntegrityError):
                s._db.execute(sql)


@pytest.mark.parametrize('offset', [0,1])
def test_one_block_real_agreement_and_subject_only_loss(tmp_path,offset):
    # Policy lives in signed terms. Re-sign the actual chain/payment and mine a subject proof.
    ad,req,o,a,k = CHAIN
    o = changed(o,1,lambda p:p['body']['terms'].update(confirmationPolicy='one-block'))
    a = changed(a,0,lambda p:p['body'].update(offerHash=digest(o)))
    k = changed(k,1,lambda p:p['body'].update(offerHash=digest(o),acceptHash=digest(a)))
    chain = ad,req,o,a,k; key = pair(chain); p = payment(); ps = p['parents']
    raw = build(replace(golden_agreement(),offer=key[1],accept=key[2]), ps, [(parse(v)['txid'],n) for v,n in zip(ps,[1,0])],100,1)
    from agent_evidence.evaluator import atomic as unpack
    bumps,_ = unpack(B['original'],p['payment_id'].split('.')[0]); pp = bumps[0]['raw']
    path,root = proof(102,[dh(b'coin'),dh(raw)],{1}); parent = bytes.fromhex(V['headers']['parents'])
    h = headers('parents_only'); h.add_many([mine(dh(parent),root,1700000102)])
    entries = [(v,0) for v in ps]; partial = atomic(raw,[pp],entries+[(raw,None)])
    full = atomic(raw,[pp,path],entries+[(raw,1)]); args = opts(); args['headers'] = h
    with Store(tmp_path/'db') as s:
        ready(s,chain); s.assign(*key,raw=raw,parents=ps,vout=0,payment_id=parse(raw)['txid']+'.0',now=NOW)
        assert s.submit_evidence(key[0],B['original'],**args).status == 'INVALID'
        assert s.submit_evidence(key[0],partial,**args).record is None
        args['now'] += offset
        complete = s.authorize_delivery(key[0],beef=full,**args)
        assert complete.authorized == (offset==0) and complete.record.first_arrival == BY+offset
        h.add_many(bytes.fromhex(V['headers'][n]) for n in ['fork_subject','fork_tip'])
        assert s.authorize_delivery(key[0],**args).status == 'SUSPENDED'
