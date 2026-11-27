"""Offline BMP-0005 payment shapes. Callers supply full parent bytes, not UTXO claims."""
from dataclasses import dataclass
import json
from pathlib import Path

from ecdsa import BadSignatureError, der, util
from agent.codec import decode
from agent.links import check_links
from svcode.crypto import vk_from_hex
from svcode import tx as btc

FINAL = b'\xff' * 4
C1 = Path(__file__).resolve().parents[1] / 'vectors/agent/positive.json'
MAX_MONEY = 21_000_000 * 100_000_000


class ShapeError(ValueError):
    pass


def need(ok, code):
    if not ok:
        raise ShapeError(code)


@dataclass(frozen=True)
class Agreement:
    offer: str
    accept: str
    requester: bytes  # compressed identity key
    payee: bytes      # locking script
    price: int

    @property
    def payer(self):
        return btc.p2pkh_script(self.requester)

    @property
    def commitment(self):
        return b'\x00\x6a\x25BMPA1' + bytes.fromhex(self.accept)


def golden_agreement():
    data = json.loads(C1.read_bytes())
    msgs = {}
    for name in ('provider-ad', 'request', 'offer', 'accept', 'ack'):
        case = data['cases'][name]
        msg = decode(bytes.fromhex(case['envelopeHex']), now=data['now'])
        need(case['sha256'] == msg.digest, 'c1-hash')
        msgs[name] = msg
    lookup = {m.digest: m for m in msgs.values()}
    for name in ('request', 'offer', 'accept', 'ack'):
        check_links(msgs[name], msgs['request'], lookup, now=data['now'])
    pair = msgs['ack'].payload['body']
    need(pair == {'offerHash': msgs['offer'].digest, 'acceptHash': msgs['accept'].digest}, 'ack-pair')
    terms = msgs['offer'].payload['body']['terms']
    addr = btc.b58decode(terms['paymentAddress'])
    need(len(addr) == 25 and addr[0] == 0 and addr[-4:] == btc.sha256d(addr[:-4])[:4], 'payee-address')
    return Agreement(pair['offerHash'], pair['acceptHash'], bytes.fromhex(msgs['request'].payload['from']['pubkey']),
                     b'\x76\xa9\x14' + addr[1:21] + b'\x88\xac', terms['priceSats'])


def serialize(t):
    ins, outs = t['inputs'], t['outputs']
    return (t['version'].to_bytes(4, 'little') + btc.varint(len(ins)) +
            b''.join(i['outpoint'] + btc.varint(len(i['script_sig'])) + i['script_sig'] + i['sequence'] for i in ins) +
            btc.varint(len(outs)) + b''.join(btc.ser_output(*o) for o in outs) + t['locktime'].to_bytes(4, 'little'))


def parse(raw):
    try:
        t = btc.parse_tx(raw)
    except (IndexError, ValueError, OverflowError) as e:
        raise ShapeError('encoding') from e
    # Exact, canonical CompactSize for every count/length; no truncated or surplus bytes.
    need(serialize(t) == raw, 'encoding')
    need(t['inputs'] and t['outputs'], 'empty-tx')
    need(sum(v for v, _ in t['outputs']) <= MAX_MONEY, 'money-range')
    points = [i['outpoint'] for i in t['inputs']]
    need(len(points) == len(set(points)), 'duplicate-input')
    return t


def resolve(t, parents):
    parsed = [parse(p) for p in parents]
    by_id = {p['txid']: p for p in parsed}
    need(len(parsed) == len(by_id), 'duplicate-parent')
    used, coins = set(), []
    for i in t['inputs']:
        op = i['outpoint']
        h, index = op[:32][::-1].hex(), int.from_bytes(op[32:], 'little')
        need(h in by_id and index < len(by_id[h]['outputs']), 'missing-prevout')
        used.add(h)
        coins.append(by_id[h]['outputs'][index])
    need(used == by_id.keys(), 'unrelated-parent')
    need(sum(v for v, _ in coins) <= MAX_MONEY, 'money-range')
    return coins


def digest(t, j, coin):
    value, script = coin
    return btc.sighash_forkid(t['inputs'], t['outputs'], j, script, value, version=t['version'], locktime=t['locktime'])


def verify(raw, parents, agreement, *, offer_hash, vout, payment_id=None):
    a = agreement
    need(offer_hash == a.offer, 'offer-hash')
    t = parse(raw)
    need(t['locktime'] == 0, 'locktime')
    outs = t['outputs']
    need(type(vout) is int and 0 <= vout < min(2**32, len(outs)) and outs[vout] == (a.price, a.payee), 'payee')
    others = outs[:vout] + outs[vout+1:]
    need(others.count((0, a.commitment)) == 1, 'commitment')
    others.remove((0, a.commitment))
    need(not others or (len(others) == 1 and others[0][1] == a.payer), 'change')
    coins = resolve(t, parents)
    fee = sum(v for v, _ in coins) - sum(v for v, _ in outs)
    need(fee > 0, 'fee')
    for j, (i, coin) in enumerate(zip(t['inputs'], coins)):
        need(i['sequence'] == FINAL, 'sequence')
        need(coin[1] == a.payer, 'prevout-script')
        try:
            sig, flag, pub = btc.parse_p2pkh_scriptsig(i['script_sig'])
        except (IndexError, ValueError) as e:
            raise ShapeError('scriptsig') from e
        need(len(sig) + 1 <= 75 and len(pub) == 33, 'scriptsig')
        need(i['script_sig'] == btc.push(sig + bytes([flag])) + b'\x21' + pub, 'scriptsig')
        need(flag == 0x41, 'sighash')
        need(pub == a.requester, 'signer')
        try:
            r, s = util.sigdecode_der(sig, btc.N)
            need(util.sigencode_der(r, s, btc.N) == sig, 'signature')
            need(0 < r < btc.N and 0 < s <= btc.N // 2, 'signature')
            vk_from_hex(pub.hex()).verify_digest(sig, digest(t, j, coin), sigdecode=util.sigdecode_der)
        except (BadSignatureError, util.MalformedSignature, der.UnexpectedDER) as e:
            raise ShapeError('signature') from e
    result = f"{t['txid']}.{vout}"
    need(payment_id is None or payment_id == result, 'payment-id')
    return result, fee


def sign(t, coins, key):
    pub = btc.compress_pub(btc.pubkey_from_priv(key))
    for j, i in enumerate(t['inputs']):
        sig = btc.sign(key, digest(t, j, coins[j])) + b'\x41'
        i['script_sig'] = btc.push(sig) + btc.push(pub)
    return serialize(t)


def build(agreement, parents, outpoints, fee, fixture_key):
    """Ordered outpoints (txid, index); deterministic version/order; fixture signer only."""
    a = agreement
    need(1 <= fixture_key < btc.N and btc.compress_pub(btc.pubkey_from_priv(fixture_key)) == a.requester, 'signer')
    need(type(fee) is int and fee > 0, 'fee')
    t = dict(version=1, locktime=0, inputs=[dict(outpoint=btc.ser_outpoint(*op), sequence=FINAL, script_sig=b'')
                                           for op in outpoints], outputs=[(a.price, a.payee), (0, a.commitment)])
    parse(serialize(t))
    coins = resolve(t, parents)
    need(all(script == a.payer for _, script in coins), 'prevout-script')
    change = sum(v for v, _ in coins) - a.price - fee
    need(change >= 0, 'insufficient-value')
    if change:
        t['outputs'].append((change, a.payer))
    raw = sign(t, coins, fixture_key)
    verify(raw, parents, a, offer_hash=a.offer, vout=0)
    return raw
