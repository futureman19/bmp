"""Local SQLite v2 evidence journal. Not a protocol message or bearer permission."""
from dataclasses import dataclass
import json

from agent_evidence.evaluator import Record, Support
from agent_payment.shape import Agreement


def migrate(db):
    # Individual statements: sqlite3.executescript would prematurely commit.
    db.execute('ALTER TABLE agreements ADD COLUMN paid_at INTEGER')
    db.execute('ALTER TABLE agreements ADD COLUMN evidence_revision INTEGER NOT NULL DEFAULT 0')
    db.execute('''CREATE TABLE evidence_history(
        thread TEXT NOT NULL REFERENCES agreements(thread), revision INTEGER NOT NULL,
        payment_id TEXT NOT NULL REFERENCES agreements(payment_id), checked_at INTEGER NOT NULL,
        beef BLOB NOT NULL, tip_hash TEXT, tip_height INTEGER, conflict_status TEXT NOT NULL,
        status TEXT NOT NULL, reason TEXT NOT NULL, depth INTEGER, record TEXT,
        authorized INTEGER NOT NULL CHECK(authorized IN (0,1)), PRIMARY KEY(thread,revision))''')
    for verb in ('UPDATE', 'DELETE'):
        db.execute(f'''CREATE TRIGGER history_no_{verb} BEFORE {verb} ON evidence_history
                       BEGIN SELECT RAISE(ABORT,'immutable-history'); END''')
    db.execute('PRAGMA user_version=2')


def pack(record):
    if record is None:
        return None
    a = record.agreement
    def supports(items):
        return [dict(role=s.role, txid=s.txid, block_hash=s.block_hash, root=s.root, height=s.height) for s in items]
    return json.dumps(dict(version=1, agreement=dict(offer=a.offer, accept=a.accept, requester=a.requester.hex(),
        payee=a.payee.hex(), price=a.price), payment_id=record.payment_id, policy=record.policy, pay_by=record.pay_by,
        first_arrival=record.first_arrival, first_support=supports(record.first_support), support=supports(record.support),
        first_depth=record.first_depth, depth=record.depth), sort_keys=True, separators=(',', ':'))


def unpack(text):
    if text is None:
        return None
    fields = json.loads(text)
    if fields.pop('version') != 1:
        raise ValueError('unknown-evidence-record')
    a = fields.pop('agreement')
    for key in ('payee','requester'):
        a[key] = bytes.fromhex(a[key])
    for key in ('support','first_support'):
        fields[key] = tuple(Support(**s) for s in fields[key])
    return Record(agreement=Agreement(**a), **fields)


@dataclass(frozen=True)
class Evaluation:
    thread: str
    revision: int
    payment_id: str
    checked_at: int
    beef: bytes
    tip_hash: str | None
    tip_height: int | None
    conflict_status: str
    status: str
    reason: str
    depth: int | None
    record: Record | None
    authorized: bool

    @classmethod
    def from_row(cls, row):
        return cls(*row[:-2], unpack(row[-2]), bool(row[-1]))
