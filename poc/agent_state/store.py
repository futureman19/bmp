"""Offline BMP agreement ledger. No signer, wallet, network or implicit clock."""
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass

from agent.codec import decode
from agent.links import check_links
from agent.values import WireError
from agent_payment.shape import Agreement, ShapeError, verify
from svcode import tx as btc


class StateError(ValueError):
    """Stable refusal code (str(error)); underlying validation error is chained)."""


@dataclass(frozen=True)
class Record:
    thread: str
    offer_hash: str
    accept_hash: str
    ad: bytes
    request: bytes
    offer: bytes
    accept: bytes
    accepted_at: int
    ack: bytes | None
    acknowledged_at: int | None
    payment_id: str | None
    raw: bytes | None

    @property
    def state(self):
        if self.payment_id is not None:
            return 'ASSIGNED'
        return 'ACKNOWLEDGED' if self.ack is not None else 'ACCEPTED'


@dataclass(frozen=True)
class Authorization:
    thread: str
    offer_hash: str
    accept_hash: str
    ack_hash: str
    checked_at: int


SCHEMA = '''CREATE TABLE agreements(
    thread TEXT NOT NULL PRIMARY KEY, offer_hash TEXT NOT NULL UNIQUE,
    accept_hash TEXT NOT NULL UNIQUE, ad BLOB NOT NULL, request BLOB NOT NULL,
    offer BLOB NOT NULL, accept BLOB NOT NULL, accepted_at INTEGER NOT NULL,
    ack BLOB, acknowledged_at INTEGER, payment_id TEXT UNIQUE, raw BLOB,
    CHECK ((ack IS NULL) = (acknowledged_at IS NULL)),
    CHECK ((payment_id IS NULL) = (raw IS NULL)),
    CHECK (payment_id IS NULL OR ack IS NOT NULL))'''


def require(condition, code):
    if not condition:
        raise StateError(code)


def clock(now):
    require(type(now) is int and 0 <= now < 2**63, 'invalid-clock')


def chain(ad, request, offer, accept, now=None):
    msgs = [decode(b, expected_action=a, now=now) for b, a in zip(
        (ad, request, offer, accept), ('ADVERTISE', 'REQUEST', 'OFFER', 'ACCEPT'))]
    lookup = {m.digest: m for m in msgs}
    for m in msgs[1:]:
        check_links(m, msgs[1], lookup, now=now)
    unique_ids(msgs[1:])
    return msgs, lookup


def unique_ids(msgs):
    keys = {(m.payload['from']['pubkey'], m.payload['messageId']) for m in msgs}
    require(len(keys) == len(msgs), 'conflict')


class Store:
    def __init__(self, path):
        require(str(path) not in ('', ':memory:') and not str(path).startswith('file:'), 'not-durable')
        self._db = sqlite3.connect(str(path), isolation_level=None)
        try:
            self._db.execute('PRAGMA synchronous=FULL')
            with self._write():
                version, = self._db.execute('PRAGMA user_version').fetchone()
                if version == 0:
                    require(not self._db.execute('SELECT 1 FROM sqlite_master LIMIT 1').fetchone(), 'schema-version')
                    self._db.execute(SCHEMA)
                    self._db.execute('CREATE TABLE late_accepts(accept_hash TEXT NOT NULL PRIMARY KEY, first_arrival INTEGER NOT NULL)')
                    self._db.execute('PRAGMA user_version=1')
                else:
                    require(version == 1, 'schema-version')
        except BaseException:
            self.close()
            raise

    def close(self):
        self._db.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    @contextmanager
    def _write(self):
        self._db.execute('BEGIN IMMEDIATE')
        try:
            yield
            self._db.commit()
        except BaseException as e:
            self._db.rollback()
            if isinstance(e, WireError):
                raise StateError(e.code if e.code in ('expired', 'future') else 'invalid-message') from e
            if isinstance(e, ShapeError):
                raise StateError('invalid-payment') from e
            raise

    def get(self, thread):
        row = self._db.execute('SELECT * FROM agreements WHERE thread=?', (thread,)).fetchone()
        return Record(*row) if row is not None else None

    def accept(self, ad, request, offer, accept, *, now):
        clock(now)
        with self._write():
            req = decode(request, expected_action='REQUEST')
            thread = req.payload['threadId']
            row = self.get(thread)
            if row and (ad, request, offer, accept) == (row.ad, row.request, row.offer, row.accept):
                return row
            msgs, _ = chain(ad, request, offer, accept)
            require(row is None, 'conflict')
            chain(ad, request, offer, accept, now)
            require(not self._db.execute('SELECT 1 FROM late_accepts WHERE accept_hash=?', (msgs[3].digest,)).fetchone(), 'late')
            if now <= msgs[2].payload['body']['terms']['acceptBefore']:
                self._db.execute('INSERT INTO agreements(thread,offer_hash,accept_hash,ad,request,offer,accept,accepted_at) VALUES(?,?,?,?,?,?,?,?)',
                                 (thread, msgs[2].digest, msgs[3].digest, ad, request, offer, accept, now))
                return self.get(thread)
            self._db.execute('INSERT INTO late_accepts VALUES(?,?)', (msgs[3].digest, now))
        # Commit the validated late arrival before reporting refusal.
        raise StateError('late')

    @staticmethod
    def _ack_check(row, raw, now):
        msg = decode(raw, expected_action='ACCEPT_ACK', now=now)
        msgs, lookup = chain(row.ad, row.request, row.offer, row.accept)
        require((msgs[2].digest, msgs[3].digest) == (row.offer_hash, row.accept_hash), 'conflict')
        require(msg.payload['body'] == {'offerHash':row.offer_hash, 'acceptHash':row.accept_hash}, 'conflict')
        check_links(msg, msgs[1], lookup)
        unique_ids([*msgs[1:], msg])
        return msg, msgs

    def ack(self, raw, *, now):
        clock(now)
        with self._write():
            thread = decode(raw, expected_action='ACCEPT_ACK').payload['threadId']
            row = self.get(thread)
            require(row is not None, 'not-accepted')
            if row.ack is not None:
                require(row.ack == raw, 'conflict')
                return row
            self._ack_check(row, raw, now)
            self._db.execute('UPDATE agreements SET ack=?, acknowledged_at=? WHERE thread=?', (raw, now, thread))
            return self.get(thread)

    def _selected(self, thread, offer_hash, accept_hash):
        row = self.get(thread)
        require(row is not None, 'not-accepted')
        require((offer_hash, accept_hash) == (row.offer_hash, row.accept_hash), 'conflict')
        require(row.ack is not None, 'not-acknowledged')
        return row

    def _authorize(self, row, now):
        require(row.payment_id is None, 'conflict')
        msg, msgs = self._ack_check(row, row.ack, now)
        require(now <= msgs[2].payload['body']['terms']['payBy'], 'late')
        return Authorization(row.thread, row.offer_hash, row.accept_hash, msg.digest, now), msgs

    def authorize_payment_construction(self, thread, offer_hash, accept_hash, *, now):
        clock(now)
        with self._write():
            auth, _ = self._authorize(self._selected(thread, offer_hash, accept_hash), now)
            return auth

    def assign(self, thread, offer_hash, accept_hash, *, raw, parents, vout, payment_id, now):
        clock(now)
        require(type(raw) is bytes and type(payment_id) is str and isinstance(parents, (tuple, list))
                and all(type(p) is bytes for p in parents), 'invalid-payment')
        with self._write():
            row = self._selected(thread, offer_hash, accept_hash)
            owner = self._db.execute('SELECT thread FROM agreements WHERE payment_id=?', (payment_id,)).fetchone()
            require(owner in (None, (thread,)), 'conflict')
            if row.payment_id is not None:
                require((payment_id, raw) == (row.payment_id, row.raw), 'conflict')
                _, msgs = self._ack_check(row, row.ack, None)
            else:
                _, msgs = self._authorize(row, now)
            terms = msgs[2].payload['body']['terms']
            addr = btc.b58decode(terms['paymentAddress'])
            agreement = Agreement(offer_hash, accept_hash, bytes.fromhex(msgs[1].payload['from']['pubkey']),
                                  b'\x76\xa9\x14' + addr[1:21] + b'\x88\xac', terms['priceSats'])
            verify(raw, parents, agreement, offer_hash=offer_hash, vout=vout, payment_id=payment_id)
            if row.payment_id is None:
                self._db.execute('UPDATE agreements SET payment_id=?, raw=? WHERE thread=?', (payment_id, raw, thread))
            return self.get(thread)
