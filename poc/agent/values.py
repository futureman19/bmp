"""Restricted JCS and scalar wire types. No normalization on receipt."""
import base64
import binascii
import json
import re

SAFE = 2**53 - 1
U32 = 2**32 - 1


class WireError(ValueError):
    def __init__(self, code, path):
        self.code, self.path = code, path
        super().__init__(f'{path}: {code}')


def require(ok, path, code='invalid'):
    if not ok:
        raise WireError(code, path)


def fields(obj, path, required, optional=''):
    require(type(obj) is dict, path, 'object')
    missing = set(required.split()) - obj.keys()
    extra = obj.keys() - set((required + ' ' + optional).split())
    if missing:
        raise WireError('missing', path + '.' + min(missing))
    if extra:
        raise WireError('unknown', path + '.' + min(extra))


def integer(n, path, lo=0, hi=SAFE):
    require(type(n) is int and lo <= n <= hi, path, 'integer')
    return n


def pattern(s, path, regex):
    require(type(s) is str and re.fullmatch(regex, s) is not None, path, 'format')
    return s


def outpoint(s, path):
    pattern(s, path, r'[0-9a-f]{64}\.(0|[1-9][0-9]{0,9})')
    integer(int(s[65:]), path, hi=U32)


def exact64(s, path):
    require(type(s) is str, path, 'base64')
    try:
        data = base64.b64decode(s, validate=True)
    except (ValueError, binascii.Error):
        raise WireError('base64', path) from None
    require(base64.b64encode(data).decode('ascii') == s, path, 'base64')
    return data


def canonical(obj):
    def ordered(v, path):
        if type(v) is dict:
            # RFC 8785: sort unescaped keys as unsigned UTF-16 code units.
            require(all(type(k) is str for k in v), path, 'key')
            return {k: ordered(v[k], path + '.' + k) for k in
                    sorted(v, key=lambda k: k.encode('utf-16-be'))}
        if type(v) is list:
            return [ordered(x, f'{path}[{i}]') for i, x in enumerate(v)]
        if v is None or type(v) in (str, bool):
            return v
        return integer(v, path)
    try:
        return json.dumps(ordered(obj, '$'), ensure_ascii=False,
                          separators=(',', ':')).encode('utf-8')
    except (UnicodeError, RecursionError):
        raise WireError('json', '$') from None


def parse(data):
    def pairs(items):
        result = dict(items)
        require(len(result) == len(items), '$', 'duplicate')
        return result
    def number(_):
        raise WireError('number', '$')
    try:
        obj = json.loads(data.decode('utf-8'), object_pairs_hook=pairs,
                         parse_float=number, parse_constant=number)
    except WireError:
        raise
    except (ValueError, RecursionError):
        raise WireError('json', '$') from None
    require(canonical(obj) == data, '$', 'noncanonical')
    return obj
