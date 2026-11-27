"""Closed BMP-0005 R3 bodies. Evidence bytes are opaque at this layer."""
import re
from urllib.parse import urlsplit

from .values import U32, exact64, fields, integer, outpoint, pattern, require

ACTIONS = {0xA000+i: a for i, a in enumerate((
    'ADVERTISE', 'REQUEST', 'OFFER', 'ACCEPT', 'PAYMENT', 'DELIVER',
    'RECEIPT', 'REJECT', 'PROOF', 'ACCEPT_ACK'))}
DAY = 86400
WINDOW = dict.fromkeys(ACTIONS.values(), DAY)
WINDOW.update(ADVERTISE=7*DAY, REQUEST=3600, OFFER=3600, ACCEPT=900, ACCEPT_ACK=900)
KIND = '[a-z][a-z0-9._-]{0,63}'
TOKEN = "[a-z0-9!#$%&'*+.^_`|~-]+"
CODES = ('unsupported', 'busy', 'terms', 'policy', 'expired', 'identity-proof-required',
         'payment-proof-required', 'payment-policy', 'malformed', 'conflict')
REQUIRED = {
    'ADVERTISE': 'endpoint services',
    'REQUEST': 'providerAdvertisementHash requesterAdvertisementHash requesterAdvertisement service task maxPriceSats deliverBy deliveryMime maxDeliveryBytes',
    'OFFER': 'terms', 'ACCEPT': 'offerHash', 'ACCEPT_ACK': 'offerHash acceptHash',
    'PAYMENT': 'offerHash txid vout amountSats', 'DELIVER': 'offerHash paymentId mime content',
    'RECEIPT': 'offerHash deliveryHash paymentId outcome', 'REJECT': 'subjectHash code',
    'PROOF': 'subjectHash proofKind atomicBeef',
}


def principal(identity):
    return tuple(identity[k] for k in ('agentPin', 'pubkey', 'address'))


def text(s, path, lo, hi):
    require(type(s) is str and lo <= len(s.encode('utf-8')) <= hi, path, 'text')


def mime(s, path):
    text(s, path, 1, 100)
    pattern(s, path, TOKEN + '/' + TOKEN)


def endpoint(s, path):
    pattern(s, path, r"[A-Za-z0-9:/?\[\]@!$&'()*+,;=._~%\-]+")
    require(not re.search(r'%(?![\da-fA-F]{2})', s), path)
    try:
        url = urlsplit(s)
        authority = re.fullmatch(r'(?:\[[^\]]+\]|[^:\[\]@]+)(?::[0-9]*)?', url.netloc)
        ok = url.scheme == 'https' and url.hostname and authority and url.username is None
        _ = url.port  # validate the parsed port
    except ValueError:
        ok = False
    require(ok, path)


def validate_body(action, payload, created, expires):
    b, p = payload['body'], '$.body.'
    optional = {'PAYMENT': 'atomicBeef', 'REJECT': 'reason', 'PROOF': 'agentPin'}
    fields(b, '$.body', REQUIRED[action], optional.get(action, ''))
    for k, v in b.items():
        if k.endswith('Hash') or k == 'txid':
            pattern(v, p+k, '[0-9a-f]{64}')
    if 'atomicBeef' in b:
        require(exact64(b['atomicBeef'], p+'atomicBeef'), p+'atomicBeef', 'empty-evidence')
    if 'paymentId' in b:
        outpoint(b['paymentId'], p+'paymentId')
    if action == 'ADVERTISE':
        endpoint(b['endpoint'], p+'endpoint')
        services = b['services']
        require(type(services) is list and len(services) <= 16, p+'services')
        seen = set()
        for i, s in enumerate(services):
            q = f'{p}services[{i}]'
            fields(s, q, 'kind description maxTaskBytes maxDeliveryBytes')
            pattern(s['kind'], q+'.kind', KIND)
            require(s['kind'] not in seen, q+'.kind', 'duplicate')
            seen.add(s['kind'])
            text(s['description'], q+'.description', 1, 280)
            for k in ('maxTaskBytes', 'maxDeliveryBytes'):
                integer(s[k], q+'.'+k, 1, 65535)
    elif action == 'REQUEST':
        pattern(b['service'], p+'service', KIND)
        text(b['task'], p+'task', 1, 4096)
        integer(b['maxPriceSats'], p+'maxPriceSats', 1)
        integer(b['deliverBy'], p+'deliverBy', expires+1, created+30*DAY)
        mime(b['deliveryMime'], p+'deliveryMime')
        integer(b['maxDeliveryBytes'], p+'maxDeliveryBytes', 1, 16384)
    elif action == 'OFFER':
        t, q = b['terms'], p+'terms.'
        fields(t, p+'terms', 'requestHash priceSats paymentAddress acceptBefore payBy deliverBy confirmationPolicy deliveryMime maxDeliveryBytes')
        pattern(t['requestHash'], q+'requestHash', '[0-9a-f]{64}')
        integer(t['priceSats'], q+'priceSats', 1)
        require(t['paymentAddress'] == payload['from']['address'], q+'paymentAddress')
        integer(t['acceptBefore'], q+'acceptBefore', created+1, expires)
        integer(t['payBy'], q+'payBy', t['acceptBefore'])
        integer(t['deliverBy'], q+'deliverBy', t['payBy']+1)
        require(t['confirmationPolicy'] in ('zero-conf','one-block'), q+'confirmationPolicy')
        mime(t['deliveryMime'], q+'deliveryMime')
        integer(t['maxDeliveryBytes'], q+'maxDeliveryBytes', 1, 16384)
    elif action == 'PAYMENT':
        integer(b['vout'], p+'vout', hi=U32)
        integer(b['amountSats'], p+'amountSats', 1)
    elif action == 'DELIVER':
        mime(b['mime'], p+'mime')
        text(b['content'], p+'content', 0, 16384)
    elif action == 'RECEIPT':
        require(b['outcome'] == 'accepted', p+'outcome')
    elif action == 'REJECT':
        require(b['code'] in CODES, p+'code')
        if 'reason' in b:
            text(b['reason'], p+'reason', 0, 280)
            require(not re.search(r'[\r\n\v\f\x1c-\x1e\x85\u2028\u2029]', b['reason']), p+'reason')
    elif action == 'PROOF':
        require(b['proofKind'] in ('identity', 'payment'), p+'proofKind')
        if b['proofKind'] == 'identity':
            require(b.get('agentPin') == payload['from']['agentPin'], p+'agentPin')
        else:
            require('agentPin' not in b, p+'agentPin', 'unknown')
