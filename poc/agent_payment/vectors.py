"""Generate portable raw-byte fixtures. No wallet, network or external state."""
import argparse
import json
from pathlib import Path
from ecdsa import util
from .shape import C1, FINAL, btc, build, golden_agreement, parse, resolve, serialize, sign, verify

DIR = C1.parent.parent / 'agent_payment'
SCOPE = 'Synthetic full parent transactions are supplied shape evidence only, not mined parents or SPV proof. Never fund fixture keys.'


def generate():
    a = golden_agreement()
    key = int(json.loads(C1.read_bytes())['publishedTestPrivateKeys'][0], 16)

    def parent(tag, outputs):
        return serialize(dict(version=1, inputs=[dict(outpoint=bytes([tag])*32 + bytes(4), sequence=FINAL, script_sig=b'')],
                              outputs=outputs, locktime=0))

    parents = [parent(8, [(10, a.payee), (2100, a.payer)]), parent(9, [(1100, a.payer)])]
    ops = [(parse(p)['txid'], n) for p, n in zip(parents, [1, 0])]
    base = build(a, parents, ops, 100, key)
    coins = resolve(parse(base), parents)
    pos, neg = [], []

    def case(name, raw, ps=parents, vout=0, **kwargs):
        return dict(name=name, raw=raw.hex(), parents=[p.hex() for p in ps], vout=vout,
                    offerHash=a.offer, acceptHash=a.accept, **kwargs)

    def positive(name, raw, vout):
        pid, fee = verify(raw, parents, a, offer_hash=a.offer, vout=vout)
        pos.append(case(name, raw, vout=vout, paymentId=pid, fee=fee))

    positive('change', base, 0)
    positive('no-change', build(a, parents, ops, 700, key), 0)
    t = parse(base)
    t['outputs'].reverse()
    positive('payee-last', sign(t, coins, key), 2)

    def bad(name, code, raw, ps=parents):
        neg.append(case(name, raw, ps, error=code))

    c, p, r = (0, a.commitment), (a.price, a.payee), (600, a.payer)
    for name, code, outputs in [
        ('wrong-accept', 'commitment', [p, (0, a.commitment[:-1]+bytes([a.commitment[-1]^1])), r]),
        ('missing-accept', 'commitment', [p, r]), ('duplicate-commitment', 'commitment', [p,c,c]),
        ('commitment-value', 'commitment', [p,(1,c[1])]),
        ('non-direct-commitment', 'commitment', [p,(0,c[1][:2]+b'\x4c'+c[1][2:])]),
        ('wrong-payee', 'payee', [(a.price,a.payer),c]), ('wrong-amount','payee',[(a.price-1,a.payee),c]),
        ('extra-output','change',[p,c,r,(1,a.payer)]), ('wrong-change-address','change',[p,c,(600,a.payee)]),
        ('wrong-change-type','change',[p,c,(600,b'\x51')]), ('zero-fee','fee',[p,c,(700,a.payer)]),
        ('negative-fee','fee',[p,c,(701,a.payer)])]:
        t = parse(base)
        t['outputs'] = outputs
        bad(name, code, sign(t, coins, key))

    for name, script, signing_key in [('third-party-input', a.payee, 2), ('wrong-prevout-script', b'\x51', key)]:
        ps = [parent(10, [(3200, script)])]
        t = parse(base)
        t['inputs'] = [dict(outpoint=btc.ser_outpoint(parse(ps[0])['txid'], 0), sequence=FINAL, script_sig=b'')]
        bad(name, 'prevout-script', sign(t, resolve(t, ps), signing_key), ps)
    t = parse(base)
    t['locktime'] = 1
    bad('nonzero-locktime', 'locktime', sign(t, coins, key))
    t = parse(base)
    t['inputs'][1]['sequence'] = b'\xfe\xff\xff\xff'
    bad('nonfinal-second-input', 'sequence', sign(t, coins, key))
    t = parse(base)
    t['outputs'][-1] = (599, a.payer)
    bad('signed-other-outputs', 'signature', serialize(t))
    t = parse(base)
    for i in t['inputs']:
        sig, flag, pub = btc.parse_p2pkh_scriptsig(i['script_sig'])
        r, s = util.sigdecode_der(sig, btc.N)
        high_s = util.sigencode_der(r, btc.N - s, btc.N)
        i['script_sig'] = btc.push(high_s + bytes([flag])) + btc.push(pub)
    bad('high-s', 'signature', serialize(t))
    t = parse(base)
    for i in t['inputs']:
        sig, flag, pub = btc.parse_p2pkh_scriptsig(i['script_sig'])
        sig_with_flag = sig + bytes([flag])
        i['script_sig'] = (b'\x4c' + bytes([len(sig_with_flag)]) + sig_with_flag +
                           b'\x4c\x21' + pub)
    bad('nonminimal-push', 'scriptsig', serialize(t))
    t = parse(base)
    script = bytearray(t['inputs'][1]['script_sig'])
    script[script[0]] = 0x42
    t['inputs'][1]['script_sig'] = bytes(script)
    bad('wrong-sighash-second-input', 'sighash', serialize(t))
    t['inputs'][1]['script_sig'] = b'\x4c\x50\x01'
    bad('truncated-push', 'scriptsig', serialize(t))
    bad('short-locktime', 'encoding', base[:-1])
    bad('trailing-data', 'encoding', base+b'\x00')
    bad('nonminimal-varint', 'encoding', base[:4]+b'\xfd\x02\x00'+base[5:])
    bad('missing-parent','missing-prevout',base,parents[:1])
    t = parse(base)
    t['inputs'][1] = t['inputs'][0]
    bad('reused-input','duplicate-input',serialize(t))
    neg.append(dict(case('wrong-payment-id', base, error='payment-id'), paymentId=pos[0]['paymentId']+'0'))
    neg.append(dict(case('wrong-stored-offer', base, error='offer-hash'), offerHash='00'*32))
    return {f'{label}.json': (json.dumps(dict(scope=SCOPE, cases=cases), indent=2)+'\n').encode()
            for label, cases in [('positive',pos),('negative',neg)]}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    files = generate()
    if files != generate():
        raise SystemExit('non-deterministic generation')
    if not args.check:
        DIR.mkdir(exist_ok=True)
    for name, data in files.items():
        if args.check and (DIR/name).read_bytes() != data:
            raise SystemExit(f'stale: {name}')
        if not args.check:
            (DIR/name).write_bytes(data)
        print(name, len(json.loads(data)['cases']), 'cases')


if __name__ == '__main__':
    main()
