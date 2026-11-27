"""BMP-0005 R3 offline, wire-only envelope verification."""
from dataclasses import dataclass
from struct import Struct

from ecdsa import BadSignatureError, MalformedPointError, SECP256k1, VerifyingKey, util
from svcode.crypto import pubkey_hex, sha256, sign_digest
from svcode.tx import address_from_pubkey

from .schema import ACTIONS, WINDOW, principal, validate_body
from .values import (U32, WireError, canonical, exact64, fields, integer, outpoint,
                     parse, pattern, require)

PREFIX = Struct('>B4sHII4sH')
CODE = {v: k for k, v in ACTIONS.items()}


@dataclass(frozen=True)
class Envelope:
    action: str
    created: int
    expires: int
    payload: dict
    digest: str  # reference hash of complete received bytes, NOT the signing digest


def identity(v, path):
    fields(v, path, 'agentPin pubkey address', 'identityEvidence')
    outpoint(v['agentPin'], path+'.agentPin')
    key = bytes.fromhex(pattern(v['pubkey'], path+'.pubkey', '0[23][0-9a-f]{64}'))
    require(int.from_bytes(key[1:], 'big') < SECP256k1.curve.p(), path+'.pubkey', 'curve')
    try:
        vk = VerifyingKey.from_string(key, curve=SECP256k1, valid_encodings={'compressed'})
    except MalformedPointError:
        raise WireError('curve', path+'.pubkey') from None
    require(v['address'] == address_from_pubkey(key), path+'.address', 'address')
    if 'identityEvidence' in v:
        require(exact64(v['identityEvidence'], path+'.identityEvidence'), path+'.identityEvidence', 'empty-evidence')
    return vk


def target(pub):
    return sha256(b'BMP-AGENT/1' + bytes.fromhex(pub))[:4]


def decode(raw, *, now=None, expected_action=None, recipient=None):
    """now=None checks historical bytes without making a live freshness decision.

    recipient, if supplied, is the expected FULL principal tuple, never a routing tag.
    """
    require(type(raw) is bytes and len(raw) >= 85, 'header', 'truncated')
    version, tag, code, created, expires, nonce, size = PREFIX.unpack_from(raw)
    require(len(raw) == 85+size, 'header.length', 'length')
    require(version == 2, 'header.version', 'version')
    require(code in ACTIONS, 'header.action', 'action')
    action = ACTIONS[code]
    require(expected_action in (None, action), 'header.action', 'wrong-action')
    p = parse(raw[85:])
    fields(p, '$', 'profile messageId threadId from to body')
    require(p['profile'] == 'bmp-agent/1', '$.profile')
    for k in ('messageId', 'threadId'):
        pattern(p[k], '$.'+k, '[0-9a-f]{32}')
    sender = identity(p['from'], '$.from')
    identity(p['to'], '$.to')
    require(tag == target(p['to']['pubkey']), 'header.target', 'target')
    require(nonce == bytes.fromhex(p['messageId'])[:4], 'header.nonce', 'nonce')
    require(recipient in (None, principal(p['to'])), '$.to', 'recipient')
    sig = raw[21:85]
    require(int.from_bytes(sig[32:], 'big') <= SECP256k1.order//2, 'header.signature', 'high-s')
    try:
        sender.verify_digest(sig, sha256(raw[:21]+raw[85:]), sigdecode=util.sigdecode_string)
    except BadSignatureError:
        raise WireError('signature', 'header.signature') from None
    require(created < expires <= created+WINDOW[action], 'header.expires', 'window')
    if now is not None:
        require(created <= now+300, 'header.created', 'future')
        require(now <= expires, 'header.expires', 'expired')
    a, b = p['from'], p['to']
    if action in ('ADVERTISE', 'REQUEST'):
        require(p['threadId'] == p['messageId'], '$.threadId', 'thread')
    if action == 'ADVERTISE':
        require(principal(a) == principal(b), '$.to', 'principal')
        require('identityEvidence' in a, '$.from.identityEvidence', 'missing')
        require('identityEvidence' not in b, '$.to.identityEvidence', 'duplicate-proof')
    else:
        require(a['agentPin'] != b['agentPin'] and a['pubkey'] != b['pubkey'], '$.to', 'distinct')
    validate_body(action, p, created, expires)
    if action == 'REQUEST':
        body = p['body']
        require('identityEvidence' not in a, '$.from.identityEvidence', 'duplicate-proof')
        ad = exact64(body['requesterAdvertisement'], '$.body.requesterAdvertisement')
        require(sha256(ad).hex() == body['requesterAdvertisementHash'], '$.body.requesterAdvertisementHash', 'hash')
        try:
            decode(ad, now=now, expected_action='ADVERTISE', recipient=principal(a))
        except WireError as e:
            raise WireError(e.code, '$.body.requesterAdvertisement/'+e.path) from e
    return Envelope(action, created, expires, p, sha256(raw).hex())


def encode(action, payload, created, expires, key):
    """Reference fixture signer, NOT a policy/authorization boundary."""
    require(action in CODE, 'header.action', 'action')
    integer(created, 'header.created', hi=U32)
    integer(expires, 'header.expires', hi=U32)
    data = canonical(payload)
    require(len(data) <= 65535, 'header.length', 'length')
    fields(payload, '$', 'profile messageId threadId from to body')
    identity(payload['to'], '$.to')
    identity(payload['from'], '$.from')
    require(pubkey_hex(key) == payload['from']['pubkey'], '$.from.pubkey', 'signer')
    msg = pattern(payload['messageId'], '$.messageId', '[0-9a-f]{32}')
    prefix = PREFIX.pack(2, target(payload['to']['pubkey']), CODE[action], created,
                         expires, bytes.fromhex(msg[:8]), len(data))
    raw = prefix + sign_digest(key, sha256(prefix+data)) + data
    decode(raw)
    return raw
