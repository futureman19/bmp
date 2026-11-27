"""Optional contextual checks using caller-supplied, wire-verified messages only.

Does not track or advance state. Missing referenced bytes are not a match.
"""
from .schema import DAY, principal
from .values import require


def check_links(msg, request, lookup, *, now=None):
    """request and lookup[full_envelope_hash] are outputs of decode(), not JSON claims."""
    p, action = msg.payload, msg.action
    require(action != 'ADVERTISE', 'header.action', 'not-task-message')
    body = p['body']
    r = request.payload
    require(request.action == 'REQUEST', '$.threadId', 'request')
    require(p['threadId'] == r['messageId'], '$.threadId', 'thread')
    require(msg.expires <= r['body']['deliverBy']+DAY, 'header.expires', 'task-window')
    parties = lambda x: (principal(x['from']), principal(x['to']))
    direction = parties(p)
    forward = parties(r)
    require(direction in (forward, forward[::-1]), '$.from', 'party')
    if action not in ('PROOF','REJECT'):
        expected = forward[::-1] if action in ('OFFER','ACCEPT_ACK','DELIVER') else forward
        require(direction == expected, '$.from', 'role')

    def ref(value, field, kind=None):
        other = lookup.get(value)
        path = '$.body.'+field
        require(other is not None and other.digest == value, path, 'reference')
        require(kind in (None, other.action), path, 'reference-action')
        if other.action != 'ADVERTISE':
            require(other.payload['threadId'] == p['threadId'], path, 'thread')
            require(parties(other.payload) in (forward, forward[::-1]), path, 'party')
        return other

    rb = r['body']
    if action == 'REQUEST':
        require(request.digest == msg.digest, '$.threadId', 'request')
        ad = ref(body['providerAdvertisementHash'], 'providerAdvertisementHash', 'ADVERTISE')
        require(principal(ad.payload['from']) == forward[1], '$.to', 'provider')
        if now is not None:
            require(ad.created <= now+300 and now <= ad.expires, '$.body.providerAdvertisementHash', 'freshness')
        service = next((s for s in ad.payload['body']['services'] if s['kind'] == rb['service']), None)
        require(service is not None, '$.body.service', 'service')
        require(len(rb['task'].encode()) <= service['maxTaskBytes'], '$.body.task', 'limit')
        require(rb['maxDeliveryBytes'] <= service['maxDeliveryBytes'], '$.body.maxDeliveryBytes', 'limit')
    elif action == 'OFFER':
        t = body['terms']
        require(t['requestHash'] == request.digest, '$.body.terms.requestHash', 'reference')
        for field, bound in [('priceSats','maxPriceSats'), ('maxDeliveryBytes','maxDeliveryBytes'), ('deliverBy','deliverBy')]:
            require(t[field] <= rb[bound], '$.body.terms.'+field, 'limit')
        require(t['deliveryMime'] == rb['deliveryMime'], '$.body.terms.deliveryMime', 'mime')
    elif action in ('PROOF','REJECT'):
        subject = ref(body['subjectHash'], 'subjectHash')
        orig = parties(subject.payload)
        require(direction == (orig if action == 'PROOF' else orig[::-1]), '$.from', 'role')
        if body.get('proofKind') == 'payment' or body.get('code') in ('payment-policy','payment-proof-required'):
            require(subject.action == 'PAYMENT', '$.body.subjectHash', 'reference-action')
    else:
        offer = ref(body['offerHash'], 'offerHash', 'OFFER')
        require(parties(offer.payload) == forward[::-1], '$.body.offerHash', 'role')
        terms = offer.payload['body']['terms']
        require(terms['requestHash'] == request.digest, '$.body.offerHash', 'request')
        if action == 'ACCEPT_ACK':
            accept = ref(body['acceptHash'], 'acceptHash', 'ACCEPT')
            require(parties(accept.payload) == forward and accept.payload['body']['offerHash'] == offer.digest,
                    '$.body.acceptHash', 'pair')
        elif action == 'PAYMENT':
            require(body['amountSats'] == terms['priceSats'], '$.body.amountSats', 'amount')
        elif action == 'DELIVER':
            require(body['mime'] == terms['deliveryMime'], '$.body.mime', 'mime')
            require(len(body['content'].encode()) <= terms['maxDeliveryBytes'], '$.body.content', 'limit')
        elif action == 'RECEIPT':
            delivery = ref(body['deliveryHash'], 'deliveryHash', 'DELIVER')
            require(parties(delivery.payload) == forward[::-1] and delivery.payload['body']['offerHash'] == offer.digest,
                    '$.body.deliveryHash', 'pair')
            require(body['paymentId'] == delivery.payload['body']['paymentId'], '$.body.paymentId', 'outpoint')
