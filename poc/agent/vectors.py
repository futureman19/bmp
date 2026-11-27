"""Reproducible offline fixtures. All keys are public test material; NEVER fund."""
import argparse
import base64
import json
from pathlib import Path
from struct import pack

from ecdsa import SECP256k1
from svcode.crypto import key_from_hex, pubkey_hex, sha256, sign_digest
from svcode.tx import address_from_pubkey
from .codec import CODE, PREFIX, canonical, decode, encode, target

ROOT = Path(__file__).resolve().parents[1]/'vectors'/'agent'
NOW = 1795600000
KEYS = [key_from_hex(f'{n:064x}') for n in (1, 2)]
EVIDENCE = 'V0lSRS1PTkxZ'  # ASCII WIRE-ONLY, not BEEF


def identities():
    return [dict(agentPin=f'{n:064x}.0', pubkey=pubkey_hex(key),
                 address=address_from_pubkey(bytes.fromhex(pubkey_hex(key))))
            for n, key in enumerate(KEYS, 1)]


def positives():
    rows = {}
    parties = identities()
    def add(name, action, sender, body):
        ad = action == 'ADVERTISE'
        mid = sha256(name.encode())[:16].hex()
        p = {'profile':'bmp-agent/1', 'messageId':mid,
             'threadId':mid if ad or action == 'REQUEST' else rows['request']['messageId'],
             'from':dict(parties[sender]), 'to':parties[sender if ad else 1-sender], 'body':body}
        if ad:
            p['from']['identityEvidence'] = EVIDENCE
        raw = encode(action, p, NOW, NOW+600, KEYS[sender])
        h = sha256(raw).hex()
        rows[name] = dict(action=action, messageId=mid, envelopeHex=raw.hex(), sha256=h)
        return h
    a = add('requester-ad','ADVERTISE',0,dict(endpoint='https://a.example/bmp-agent/1',services=[]))
    b = add('provider-ad','ADVERTISE',1,dict(endpoint='https://b.example/bmp-agent/1', services=[dict(
        kind='research.summary',description='Short summary',maxTaskBytes=4096,maxDeliveryBytes=16384)]))
    r = add('request','REQUEST',0,dict(providerAdvertisementHash=b, requesterAdvertisementHash=a,
        requesterAdvertisement=base64.b64encode(bytes.fromhex(rows['requester-ad']['envelopeHex'])).decode(),
        service='research.summary',task='Summarize the supplied sources.',maxPriceSats=5000,
        deliverBy=NOW+3600,deliveryMime='text/markdown',maxDeliveryBytes=16384))
    o = add('offer','OFFER',1,dict(terms=dict(requestHash=r,priceSats=2500,paymentAddress=parties[1]['address'],
        acceptBefore=NOW+500,payBy=NOW+1000,deliverBy=NOW+3600,confirmationPolicy='zero-conf',
        deliveryMime='text/markdown',maxDeliveryBytes=16384)))
    c = add('accept','ACCEPT',0,dict(offerHash=o))
    add('ack','ACCEPT_ACK',1,dict(offerHash=o,acceptHash=c))
    txid = '44'*32
    pay = add('payment','PAYMENT',0,dict(offerHash=o,txid=txid,vout=0,amountSats=2500))
    d = add('deliver','DELIVER',1,dict(offerHash=o,paymentId=txid+'.0',mime='text/markdown',content='# Summary\n\nCafé.'))
    add('receipt','RECEIPT',0,dict(offerHash=o,deliveryHash=d,paymentId=txid+'.0',outcome='accepted'))
    add('reject','REJECT',1,dict(subjectHash=pay,code='payment-proof-required',reason='Evidence missing.'))
    add('proof-payment','PROOF',0,dict(subjectHash=pay,proofKind='payment',atomicBeef=EVIDENCE))
    add('proof-identity','PROOF',1,dict(subjectHash=o,proofKind='identity',agentPin=parties[1]['agentPin'],atomicBeef=EVIDENCE))
    return rows


def negatives(rows):
    """Small deterministic byte edits against named positives, not invalid encoder inputs."""
    result = []
    def case(name, source, code, path, *, edit=None, modify=None, data=None, clock=NOW, signer=None, context=False):
        raw = bytes.fromhex(rows[source]['envelopeHex'])
        prefix, sig, old = raw[:21], raw[21:85], raw[85:]
        p = json.loads(old)
        if modify:
            modify(p)
        data = data(old) if data else canonical(p)
        prefix = prefix[:19]+pack('>H', len(data))
        if modify or data != old or signer is not None:
            index = next(i for i,k in enumerate(KEYS) if pubkey_hex(k) == p['from']['pubkey']) if signer is None else signer
            sig = sign_digest(KEYS[index], sha256(prefix+data))
        bad = prefix+sig+data
        if edit:
            bad = edit(bad)
        # Store the differing span; an empty insertion/deletion is meaningful.
        left = 0
        while left < min(len(raw),len(bad)) and raw[left] == bad[left]: left += 1
        right = 0
        while right < min(len(raw),len(bad))-left and raw[-1-right] == bad[-1-right]: right += 1
        result.append(dict(name=name, source=source, offset=left, remove=len(raw)-left-right,
                           insertHex=bad[left:len(bad)-right].hex(), now=clock, context=context, code=code,path=path))
    def at(i,value): return lambda b: b[:i]+bytes([value])+b[i+1:]
    case('short','accept','truncated','header',edit=lambda b:b[:84])
    case('truncated','accept','length','header.length',edit=lambda b:b[:-1])
    case('trailing','accept','length','header.length',edit=lambda b:b+b'!')
    case('version','accept','version','header.version',edit=at(0,1))
    case('action','accept','action','header.action',edit=at(5,0))
    case('target','accept','target','header.target',edit=lambda b:b[:1]+bytes([b[1]^1])+b[2:])
    case('nonce','accept','nonce','header.nonce',edit=lambda b:b[:15]+bytes([b[15]^1])+b[16:])
    case('signature','accept','signature','header.signature',edit=lambda b:b[:21]+bytes([b[21]^1])+b[22:])
    case('wrong-key','accept','signature','header.signature',signer=1)
    case('high-s','accept','high-s','header.signature',edit=lambda b:b[:53]+(SECP256k1.order-int.from_bytes(b[53:85],'big')).to_bytes(32,'big')+b[85:])
    case('whitespace','accept','noncanonical','$',data=lambda b:b+b' ')
    case('duplicate','accept','duplicate','$',data=lambda b:b'{"body":{},'+b[1:])
    case('float','payment','number','$',data=lambda b:b.replace(b':2500',b':2500.0'))
    case('unknown-field','accept','unknown','$.body.extra',modify=lambda p:p['body'].update(extra=True))
    case('bad-point','accept','curve','$.from.pubkey',modify=lambda p:p['from'].update(pubkey='02'+'ff'*32),signer=0)
    case('bad-address','accept','address','$.from.address',modify=lambda p:p['from'].update(address='x'))
    case('pin','accept','format','$.from.agentPin',modify=lambda p:p['from'].update(agentPin='00'*32+'.00'))
    case('pad-bits','proof-payment','base64','$.body.atomicBeef',modify=lambda p:p['body'].update(atomicBeef='Zh=='))
    case('wrong-role','reject','role','$.from',modify=lambda p:p.update({'from':p['to'],'to':p['from']}),
         edit=lambda b: retarget(b,0),context=True)
    case('wrong-subject','reject','reference-action','$.body.subjectHash',modify=lambda p:p['body'].update(subjectHash=rows['request']['sha256']),context=True)
    case('same-key-distinct-pins','accept','distinct','$.to',modify=lambda p:p['from'].update(pubkey=p['to']['pubkey'],address=p['to']['address']))
    case('duplicate-proof','provider-ad','duplicate-proof','$.to.identityEvidence',modify=lambda p:p['to'].update(identityEvidence=EVIDENCE))
    case('missing-proof','provider-ad','missing','$.from.identityEvidence',modify=lambda p:p['from'].pop('identityEvidence'))
    case('bad-nested-field','provider-ad','unknown','$.body.services[0].extra',modify=lambda p:p['body']['services'][0].update(extra=True))
    case('duplicate-service','provider-ad','duplicate','$.body.services[1].kind',modify=lambda p:p['body']['services'].extend(p['body']['services'][:1]))
    case('wrong-embedded-ad','request','recipient','$.body.requesterAdvertisement/$.to',modify=lambda p:p['body'].update(requesterAdvertisement=base64.b64encode(bytes.fromhex(rows['provider-ad']['envelopeHex'])).decode(),requesterAdvertisementHash=rows['provider-ad']['sha256']))
    case('cross-thread','ack','thread','$.threadId',modify=lambda p:p.update(threadId='ee'*16),context=True)
    case('wrong-offer-role','offer','role','$.from',modify=lambda p:(p.update({'from':p['to'],'to':p['from']}),p['body']['terms'].update(paymentAddress=p['from']['address'])),edit=lambda b:retarget(b,0),context=True)
    case('future','accept','future','header.created',clock=NOW-301)
    case('stale','accept','expired','header.expires',clock=NOW+601)
    case('far-expiry','accept','window','header.expires',edit=lambda b:resign(b[:11]+pack('>I',NOW+901)+b[15:],0))
    case('task-limit','request','text','$.body.task',modify=lambda p:p['body'].update(task='x'*4097))
    # No uint16 can describe this payload; use a compact suffix recipe rather than 64 KiB of zeroes.
    result.append(dict(name='oversize',source='accept',appendZeroes=65536,now=NOW,context=False,code='length',path='header.length'))
    return result


def resign(raw, index):
    return raw[:21]+sign_digest(KEYS[index],sha256(raw[:21]+raw[85:]))+raw[85:]


def retarget(raw,index):
    p = json.loads(raw[85:])
    return resign(raw[:1]+target(p['to']['pubkey'])+raw[5:], index)


def artifacts():
    pos = positives()
    objects = {'positive.json':dict(scope='Wire/schema only. Evidence is NOT Atomic BEEF or SPV.',
               publishedTestPrivateKeys=[k.to_string().hex() for k in KEYS], now=NOW, cases=pos),
               'negative.json':negatives(pos)}
    return {k:(json.dumps(v,indent=2,ensure_ascii=True)+'\n').encode() for k,v in objects.items()}


def main():
    cli = argparse.ArgumentParser()
    cli.add_argument('--check',action='store_true')
    opts = cli.parse_args()
    first = artifacts()
    if first != artifacts(): raise SystemExit('non-deterministic generation')
    for name,data in first.items():
        path = ROOT/name
        if opts.check:
            if path.read_bytes() != data: raise SystemExit('golden mismatch: '+name)
        else:
            ROOT.mkdir(exist_ok=True)
            path.write_bytes(data)
    print('Two generations identical:', ', '.join(first))


if __name__ == '__main__':
    main()
