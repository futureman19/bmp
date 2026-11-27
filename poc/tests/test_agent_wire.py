"""Offline wire tests. Fixtures contain no chain or wallet evidence."""
import json
import subprocess
from pathlib import Path

import pytest
from agent.codec import WireError, canonical, decode, encode, principal
from agent.links import check_links
from agent.schema import WINDOW
from agent.values import exact64, outpoint, parse
from agent.vectors import KEYS, NOW, ROOT, artifacts

POS = json.loads((ROOT/'positive.json').read_bytes())['cases']
NEG = json.loads((ROOT/'negative.json').read_bytes())
RAW = {k:bytes.fromhex(v['envelopeHex']) for k,v in POS.items()}


def test_00_known_answer_sign_verify():
    raw = RAW['accept']
    sig = bytes.fromhex('924a5024eaa03222ec25ead6191fa02d821f296f1be0e6ebd4ec2437de414a45'
                        '1ec679d96df6ac109c5ff44b1a183e5a27e59011be3d1e69236bf19f23fd4bc8')
    assert raw[:21].hex() == '0213e5b3b1a0036b06ae806b06b0d8c125d0390277'
    assert raw[21:85] == sig
    msg = decode(raw, now=NOW)
    assert encode('ACCEPT', msg.payload, NOW, NOW+600, KEYS[0]) == raw
    assert msg.payload['from']['address'] == '1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH'


def test_double_generation_and_independent_reader():
    assert artifacts() == artifacts() == {n:(ROOT/n).read_bytes() for n in ('positive.json','negative.json')}
    subprocess.run(['node', str(ROOT.parents[1]/'agent'/'check_vectors.js')], check=True)


@pytest.fixture(scope='module')
def history():
    return {row['sha256']:decode(RAW[k], now=NOW) for k,row in POS.items()}


@pytest.mark.parametrize('name', POS)
def test_published_positive(name, history):
    m = decode(RAW[name], now=NOW)
    assert (m.digest, m.action) == (POS[name]['sha256'], POS[name]['action'])
    if m.action != 'ADVERTISE':
        check_links(m, history[POS['request']['sha256']], history, now=NOW)


@pytest.mark.parametrize('case', NEG, ids=lambda c:c['name'])
def test_published_negative(case, history):
    raw = RAW[case['source']]
    if 'appendZeroes' in case:
        raw += bytes(case['appendZeroes'])
    else:
        i = case['offset']
        raw = raw[:i]+bytes.fromhex(case['insertHex'])+raw[i+case['remove']:]
    with pytest.raises(WireError) as err:
        m = decode(raw, now=case['now'])
        if case['context']:
            check_links(m, history[POS['request']['sha256']], history)
    assert (err.value.code, err.value.path) == (case['code'],case['path'])


@pytest.mark.parametrize('wire',[b'\xff',b'{"x":-0}',b'{"x":1e1}',b'{"x":NaN}',
    b'{"x":9007199254740992}',br'{"x":"\udfff"}',b'{"b":1,"a":2}',br'{"x":"\u0061"}'])
def test_bad_json(wire):
    with pytest.raises(WireError): parse(wire)


def test_utf16_sort_and_no_normalization():
    payload = {'\ue000':1,'\U00010000':'e\u0301\n'}
    wire = '{"\U00010000":"e\u0301\\n","\ue000":1}'.encode()
    assert canonical(payload) == wire and parse(wire) == payload


@pytest.mark.parametrize('s',['Zg','Zg===','Zg==\n','_w==','//9=','Zh=='])
def test_bad_base64(s):
    with pytest.raises(WireError): exact64(s, '$.value')


@pytest.mark.parametrize('s',['1.0','0'*64+'.00','a'*64+'.4294967296','a'*64+'_-1'])
def test_bad_outpoint(s):
    with pytest.raises(WireError): outpoint(s, '$.value')


def test_boundaries():
    assert exact64('Zg==','v') == b'f'
    outpoint('f'*64+'.4294967295','v')
    decode(RAW['accept'], now=NOW-300)
    decode(RAW['accept'], now=NOW+600)
    assert decode(RAW['accept']).action == 'ACCEPT'  # historical mode
    with pytest.raises(WireError, match='recipient'):
        decode(RAW['accept'], recipient=principal(decode(RAW['accept']).payload['from']))


@pytest.mark.parametrize('name',['requester-ad','request','offer','accept','ack','payment','deliver','receipt','reject','proof-payment'])
def test_validity_window(name):
    m = decode(RAW[name]); p = m.payload
    key = KEYS[int(p['from']['agentPin'][:64],16)-1]
    if m.action == 'REQUEST': p['body']['deliverBy'] += 1
    encode(m.action,p,NOW,NOW+WINDOW[m.action],key)
    with pytest.raises(WireError, match='window'):
        encode(m.action,p,NOW,NOW+WINDOW[m.action]+1,key)


@pytest.mark.parametrize('name,field,value',[
    ('offer','terms.priceSats',0), ('offer','terms.payBy',NOW+3600),
    ('offer','terms.confirmationPolicy','trusted'), ('offer','terms.deliveryMime','Text/plain'),
    ('request','maxDeliveryBytes',16385), ('request','task','é'*2049),
    ('request','deliverBy',NOW+600), ('request','maxPriceSats',True),
    ('requester-ad','endpoint','https://user@provider.example/path'),
    ('requester-ad','endpoint','https://provider.example/#'), ('requester-ad','services',[{}]*17),
    ('payment','vout',2**32), ('proof-identity','agentPin','0'*64+'.0'),
    ('proof-payment','agentPin','0'*64+'.0'), ('reject','reason','a\nb'),
    ('reject','code','other'), ('receipt','outcome','late'), ('deliver','content','x'*16385),
])
def test_schema(name,field,value):
    m = decode(RAW[name]); p = m.payload; obj = p['body']
    for k in field.split('.')[:-1]: obj = obj[k]
    obj[field.split('.')[-1]] = value
    with pytest.raises(WireError) as e:
        encode(m.action,p,NOW,NOW+600,KEYS[int(p['from']['agentPin'][:64],16)-1])
    assert e.value.path == '$.body.'+field or (field == 'terms.payBy' and e.value.path == '$.body.terms.deliverBy')


def test_encoder_payload_limit():
    p = decode(RAW['accept']).payload
    p['body']['extra'] = 'x'*65536
    with pytest.raises(WireError, match='header.length'): encode('ACCEPT',p,NOW,NOW+1,KEYS[0])
