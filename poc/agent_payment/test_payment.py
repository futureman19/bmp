import json
import pytest
from .shape import ShapeError, build, golden_agreement, parse, verify
from .vectors import DIR, generate


def cases(name):
    return json.loads((DIR / (name + '.json')).read_bytes())['cases']


@pytest.fixture(scope='module')
def agreement():
    return golden_agreement()


def check(c, a):
    assert c['acceptHash'] == a.accept
    return verify(bytes.fromhex(c['raw']), [bytes.fromhex(p) for p in c['parents']], a,
                  offer_hash=c['offerHash'], vout=c['vout'], payment_id=c.get('paymentId'))


@pytest.mark.parametrize('c', cases('positive'), ids=lambda c: c['name'])
def test_positive(c, agreement):
    assert check(c, agreement) == (c['paymentId'], c['fee'])


@pytest.mark.parametrize('c', cases('negative'), ids=lambda c: c['name'])
def test_negative(c, agreement):
    with pytest.raises(ShapeError) as err:
        check(c, agreement)
    assert str(err.value) == c['error']


@pytest.mark.parametrize('vout', [False, -1, 1, 2, 2**32, '0'])
def test_selected_output(agreement, vout):
    with pytest.raises(ShapeError, match='^payee$'):
        check(dict(cases('positive')[0], vout=vout), agreement)


@pytest.mark.parametrize('key,fee,reason', [(2, 100, 'signer'), (1, 0, 'fee'), (1, 701, 'insufficient-value')])
def test_builder_refuses_invalid_terms(agreement, key, fee, reason):
    parents = [bytes.fromhex(p) for p in cases('positive')[0]['parents']]
    ops = [(parse(p)['txid'], n) for p, n in zip(parents, [1, 0])]
    with pytest.raises(ShapeError, match='^'+reason+'$'):
        build(agreement, parents, ops, fee, key)


@pytest.mark.parametrize('name', ['high-s', 'nonminimal-push'])
def test_malleated_payment_changes_txid_and_is_rejected(name, agreement):
    source = next(c for c in cases('positive') if c['name'] == 'change')
    mutated = next(c for c in cases('negative') if c['name'] == name)
    source_txid = parse(bytes.fromhex(source['raw']))['txid']
    mutated_txid = parse(bytes.fromhex(mutated['raw']))['txid']
    assert mutated_txid != source_txid
    with pytest.raises(ShapeError) as err:
        check(mutated, agreement)
    assert str(err.value) == mutated['error']


def test_reproducible():
    files = generate()
    assert files == generate()
    for name, contents in files.items():
        assert (DIR/name).read_bytes() == contents
