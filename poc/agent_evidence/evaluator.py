"""Offline, receiver-local BMP-0005 evidence decisions (not state transitions)."""
from dataclasses import dataclass

from agent_payment.shape import Agreement, ShapeError, parse, verify
from svcode.spv import BEEF_V1, HeaderStore, bump_root, parse_beef, ser_varint


@dataclass(frozen=True)
class Support:
    role: str
    txid: str
    block_hash: str
    root: str  # header-wire hex; txid and block_hash are display hex
    height: int


@dataclass(frozen=True)
class Record:
    agreement: Agreement
    payment_id: str
    policy: str
    pay_by: int
    first_arrival: int
    first_support: tuple[Support, ...]
    support: tuple[Support, ...]
    first_depth: int | None
    depth: int | None


@dataclass(frozen=True)
class Result:
    status: str
    reason: str
    record: Record | None = None
    depth: int | None = None  # subject depth on this evaluation only


def atomic(wire, txid):
    """No txid-only variant. Ensure strict container lengths, flags and references."""
    if type(wire) is not bytes or wire[:4] != b'\x01'*4 or wire[4:36][::-1].hex() != txid:
        raise ValueError('atomic-id')
    inner = wire[36:]
    b = parse_beef(inner)
    bumps, entries = b['bumps'], b['txs']
    # Shared reader also accepts nonminimal CompactSize and nonbinary hasBUMP.
    # Reconstruct the framing (preserve transmitted BUMP leaf order).
    v = ser_varint
    out = bytearray(BEEF_V1 + v(len(bumps)))
    for proof in bumps:
        size = len(v(proof['block_height'])) + 1
        for level, leaves in enumerate(proof['path']):
            offsets = {n['offset'] for n in leaves}
            if len(offsets) != len(leaves):
                raise ValueError('duplicate-proof-offset')
            size += len(v(len(leaves)))
            for n in leaves:
                flag, offset = n['flags'], n['offset']
                if (flag not in (0, 1, 2) or (flag == 1 and not offset % 2)
                        or (level and flag == 2) or offset >= 1 << (proof['tree_height'] - level)):
                    raise ValueError('proof-node')
                size += len(v(offset)) + 1 + (0 if flag == 1 else 32)
        if size != len(proof['raw']):
            raise ValueError('nonminimal-proof')
        out.extend(proof['raw'])
    out.extend(v(len(entries)))
    seen = set()
    for entry in entries:
        if entry['txid'] in seen:
            raise ValueError('duplicate-transaction')
        seen.add(entry['txid'])
        index = entry['bump_index']
        out.extend(entry['raw'])
        out.extend(b'\x00' if index is None else b'\x01' + v(index))
    if out != inner or not entries or entries[-1]['txid'] != txid:
        raise ValueError('atomic-framing')
    return bumps, entries


def evaluate(*, beef: bytes, store: HeaderStore, agreement: Agreement, offer_hash: str,
             txid: str, payment_id: str, vout: int, amount_sats: int, policy: str,
             conflict_status: str, arrival: int, pay_by: int, prior: Record | None = None) -> Result:
    """Evaluate against a stable local HeaderStore snapshot and stored terms.

    arrival is trusted receiver time, never a peer timestamp. Only a local
    watcher supplies conflict_status. Never deserialize prior from a peer.
    A failed refresh returns history, not authorization or a new arrival.
    """
    lost = False

    def invalid(reason):
        if lost:
            return Result('SUSPENDED', 'payment-revalidation-required', prior)
        return Result('INVALID', reason, prior)

    if (policy not in ('one-block', 'zero-conf') or conflict_status not in ('clear', 'conflicted', 'unavailable')
            or any(type(t) is not int or t < 0 for t in (arrival, pay_by))):
        return invalid('local-input')
    if (type(vout) is not int or not 0 <= vout < 2**32 or type(amount_sats) is not int
            or not 0 < amount_sats <= 2**53-1 or amount_sats != agreement.price
            or payment_id != f'{txid}.{vout}' or offer_hash != agreement.offer):
        return invalid('payment-binding')
    if prior and (prior.agreement, prior.payment_id, prior.policy, prior.pay_by) != (agreement, payment_id, policy, pay_by):
        return invalid('prior-binding')

    if prior:
        for s in prior.support:
            if s.role == 'subject' and policy == 'zero-conf':
                continue
            h = store.get_by_root(bytes.fromhex(s.root))
            if store.has(s.block_hash) and (not h or h['hash'] != s.block_hash):
                lost = True

    def pending(reason):
        if lost:
            return Result('SUSPENDED', 'payment-revalidation-required', prior)
        return Result('PENDING', reason, prior)

    if policy == 'zero-conf' and conflict_status == 'conflicted':
        return Result('SUSPENDED', 'payment-revalidation-required', prior)
    if not beef and type(beef) is bytes:
        return pending('missing-evidence')
    try:
        bumps, entries = atomic(beef, txid)
        subject = entries[-1]
        needed = tuple(dict.fromkeys(i['outpoint'][:32][::-1].hex() for i in parse(subject['raw'])['inputs']))
        by_id = {e['txid']: e for e in entries[:-1]}
        if any(p not in by_id for p in needed):
            if by_id.keys() - set(needed):
                return invalid('substituted-parent')
            return pending('missing-parent')
        # Reverse topological walk: included grandparents may be redundant but
        # cannot stand in for parents. No disconnected or forward dependencies.
        ancestry = set(needed)
        for e in reversed(entries[:-1]):
            if e['txid'] not in ancestry:
                return invalid('unrelated-or-unordered')
            ancestry.update(i['outpoint'][:32][::-1].hex() for i in parse(e['raw'])['inputs'])
        parents = [by_id[p] for p in needed]
        verify(subject['raw'], [e['raw'] for e in parents], agreement, offer_hash=offer_hash,
               vout=vout, payment_id=payment_id)
        support = []
        missing = None
        depth = None
        roots = {}
        for e in [*parents, subject]:
            role = 'subject' if e is subject else 'parent'
            index = e['bump_index']
            if index is None:
                if role == 'parent' or policy == 'one-block':
                    missing = 'missing-' + role + '-proof'
                continue
            root = bump_root(bumps[index], e['txid'])
            if roots.setdefault(index, root) != root:
                return invalid('inconsistent-proof')
            header = store.get_by_root(root)
            if header is None:
                missing = 'verification-unavailable'
                continue
            support.append(Support(role, e['txid'], header['hash'], root.hex(), header['height']))
            if role == 'subject':
                depth = store.best_tip()['height'] - header['height'] + 1
                if depth < 1:
                    missing = 'verification-unavailable'
    except ShapeError as exc:
        return invalid('shape:' + str(exc))
    except (ValueError, IndexError, OverflowError):
        return invalid('invalid-evidence')
    if missing:
        return pending(missing)
    if policy == 'zero-conf' and conflict_status != 'clear':
        return pending('conflict-policy-unavailable')
    support = tuple(support)
    first = prior.first_arrival if prior else arrival
    record = Record(agreement, payment_id, policy, pay_by, first,
                    prior.first_support if prior else support, support,
                    prior.first_depth if prior else depth, depth)
    if first > pay_by:
        return Result('LATE', 'late-first-qualification', record, depth)
    return Result('CURRENT', 'confirmed' if depth else 'zero-conf', record, depth)
