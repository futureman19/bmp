'use strict';
// Independent strict JSON parser + RFC 8785 (JCS) canonical serializer for
// BMP-0005 §5.2. Written from RFC 8785 and the BMP-0005 payload rules:
//   - UTF-8, no BOM
//   - object keys unique (duplicate keys rejected)
//   - numbers: non-negative safe integers only (no sign, fraction, exponent)
//   - no lone surrogates, no unescaped control characters
//   - canonical form: keys sorted by UTF-16 code units, minimal escapes,
//     non-ASCII emitted as raw UTF-8.
// A payload is accepted only if parse -> reserialize reproduces it byte-exact.

const MAX_DEPTH = 64;
const utf8Decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: false });

class JsonError extends Error {
  constructor(msg) { super(msg); this.name = 'JsonError'; }
}

function parseStrict(buf) {
  if (!Buffer.isBuffer(buf)) throw new JsonError('payload not bytes');
  let text;
  try {
    text = utf8Decoder.decode(buf); // fatal: rejects invalid UTF-8 / lone surrogates
  } catch {
    throw new JsonError('invalid UTF-8');
  }
  if (text.charCodeAt(0) === 0xfeff) throw new JsonError('BOM');
  const st = { s: text, i: 0 };
  const v = parseValue(st, 0);
  skipWs(st);
  if (st.i !== text.length) throw new JsonError('trailing content');
  return v;
}

function skipWs(st) {
  while (st.i < st.s.length) {
    const c = st.s[st.i];
    if (c === ' ' || c === '\t' || c === '\n' || c === '\r') st.i++;
    else break;
  }
}

function parseValue(st, depth) {
  if (depth > MAX_DEPTH) throw new JsonError('nesting too deep');
  skipWs(st);
  if (st.i >= st.s.length) throw new JsonError('unexpected end');
  const c = st.s[st.i];
  if (c === '{') return parseObject(st, depth);
  if (c === '[') return parseArray(st, depth);
  if (c === '"') return parseString(st);
  if (c === 't') { expect(st, 'true'); return true; }
  if (c === 'f') { expect(st, 'false'); return false; }
  if (c === 'n') { expect(st, 'null'); return null; }
  if (c === '-' || (c >= '0' && c <= '9')) return parseNumber(st);
  throw new JsonError('unexpected character ' + JSON.stringify(c));
}

function expect(st, word) {
  if (st.s.slice(st.i, st.i + word.length) !== word) throw new JsonError('bad literal');
  st.i += word.length;
}

function parseObject(st, depth) {
  st.i++; // {
  const obj = Object.create(null);
  const seen = new Set();
  skipWs(st);
  if (st.s[st.i] === '}') { st.i++; return obj; }
  for (;;) {
    skipWs(st);
    if (st.s[st.i] !== '"') throw new JsonError('object key must be string');
    const key = parseString(st);
    if (seen.has(key)) throw new JsonError('duplicate key: ' + key);
    seen.add(key);
    skipWs(st);
    if (st.s[st.i] !== ':') throw new JsonError('expected colon');
    st.i++;
    obj[key] = parseValue(st, depth + 1);
    skipWs(st);
    const c = st.s[st.i];
    if (c === '}') { st.i++; return obj; }
    if (c !== ',') throw new JsonError('expected comma or close brace');
    st.i++;
  }
}

function parseArray(st, depth) {
  st.i++; // [
  const arr = [];
  skipWs(st);
  if (st.s[st.i] === ']') { st.i++; return arr; }
  for (;;) {
    arr.push(parseValue(st, depth + 1));
    skipWs(st);
    const c = st.s[st.i];
    if (c === ']') { st.i++; return arr; }
    if (c !== ',') throw new JsonError('expected comma or close bracket');
    st.i++;
  }
}

function parseString(st) {
  st.i++; // opening quote
  let out = '';
  for (;;) {
    if (st.i >= st.s.length) throw new JsonError('unterminated string');
    const c = st.s[st.i];
    if (c === '"') { st.i++; return out; }
    if (c === '\\') {
      st.i++;
      const e = st.s[st.i];
      if (e === undefined) throw new JsonError('unterminated escape');
      st.i++;
      switch (e) {
        case '"': out += '"'; break;
        case '\\': out += '\\'; break;
        case '/': out += '/'; break;
        case 'b': out += '\b'; break;
        case 'f': out += '\f'; break;
        case 'n': out += '\n'; break;
        case 'r': out += '\r'; break;
        case 't': out += '\t'; break;
        case 'u': {
          const h = st.s.slice(st.i, st.i + 4);
          if (!/^[0-9a-fA-F]{4}$/.test(h)) throw new JsonError('bad \\u escape');
          st.i += 4;
          let code = parseInt(h, 16);
          if (code >= 0xd800 && code <= 0xdbff) {
            // high surrogate: must be followed by \uDC00-\uDFFF
            if (st.s[st.i] !== '\\' || st.s[st.i + 1] !== 'u') throw new JsonError('lone surrogate');
            const h2 = st.s.slice(st.i + 2, st.i + 6);
            if (!/^[0-9a-fA-F]{4}$/.test(h2)) throw new JsonError('bad \\u escape');
            const lo = parseInt(h2, 16);
            if (lo < 0xdc00 || lo > 0xdfff) throw new JsonError('lone surrogate');
            st.i += 6;
            code = 0x10000 + ((code - 0xd800) << 10) + (lo - 0xdc00);
            out += String.fromCodePoint(code);
          } else if (code >= 0xdc00 && code <= 0xdfff) {
            throw new JsonError('lone surrogate');
          } else {
            out += String.fromCharCode(code);
          }
          break;
        }
        default: throw new JsonError('bad escape \\' + e);
      }
      continue;
    }
    const code = c.charCodeAt(0);
    if (code < 0x20) throw new JsonError('unescaped control character');
    out += c;
    st.i++;
  }
}

function parseNumber(st) {
  const start = st.i;
  if (st.s[st.i] === '-') throw new JsonError('negative number');
  // grammar: 0 | [1-9][0-9]*  — no fraction, no exponent, no leading zeros
  if (st.s[st.i] === '0') {
    st.i++;
    const next = st.s[st.i];
    if (next !== undefined && ((next >= '0' && next <= '9') || next === '.' || next === 'e' || next === 'E' || next === '+' || next === '-')) {
      throw new JsonError('leading zero / non-integer number');
    }
    return 0;
  }
  if (!(st.s[st.i] >= '1' && st.s[st.i] <= '9')) throw new JsonError('bad number');
  while (st.i < st.s.length && st.s[st.i] >= '0' && st.s[st.i] <= '9') st.i++;
  const next = st.s[st.i];
  if (next === '.' || next === 'e' || next === 'E') throw new JsonError('non-integer number');
  const tok = st.s.slice(start, st.i);
  const v = Number(tok);
  if (!Number.isSafeInteger(v)) throw new JsonError('unsafe integer');
  return v;
}

// --- RFC 8785 serialization ---
function jcsString(s) {
  // Lone surrogates have no canonical UTF-8 encoding; reject instead of
  // silently substituting U+FFFD (BMP-0005 §5.4 canonical JSON).
  if (/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/.test(s)) {
    throw new JsonError('lone surrogate');
  }
  let out = '"';
  for (const ch of s) {
    const code = ch.codePointAt(0);
    if (ch === '"') out += '\\"';
    else if (ch === '\\') out += '\\\\';
    else if (code === 0x08) out += '\\b';
    else if (code === 0x09) out += '\\t';
    else if (code === 0x0a) out += '\\n';
    else if (code === 0x0c) out += '\\f';
    else if (code === 0x0d) out += '\\r';
    else if (code < 0x20) out += '\\u' + code.toString(16).padStart(4, '0');
    else out += ch; // raw UTF-8 for everything else (incl. non-ASCII)
  }
  return out + '"';
}

function jcsSerialize(value, depth = 0) {
  // Same nesting bound as the strict parser (§5.4: depth <= 64), so the
  // encoder can never emit a payload the decoder must reject.
  if (depth > MAX_DEPTH) throw new JsonError('nesting too deep');
  if (value === null) return 'null';
  const t = typeof value;
  if (t === 'boolean') return value ? 'true' : 'false';
  if (t === 'number') {
    if (!Number.isSafeInteger(value) || value < 0 || Object.is(value, -0)) throw new JsonError('non-canonical number');
    return String(value);
  }
  if (t === 'string') return jcsString(value);
  if (Array.isArray(value)) return '[' + value.map(v => jcsSerialize(v, depth + 1)).join(',') + ']';
  if (t === 'object') {
    // JCS: sort keys by UTF-16 code units (JS default string sort does this).
    const keys = Object.keys(value).sort();
    return '{' + keys.map(k => jcsString(k) + ':' + jcsSerialize(value[k], depth + 1)).join(',') + '}';
  }
  throw new JsonError('unserializable value');
}

function canonicalBytes(value) {
  return Buffer.from(jcsSerialize(value), 'utf8');
}

// Parse + round-trip: returns {value} only when buf is exactly canonical.
function parseCanonical(buf) {
  const value = parseStrict(buf);
  const round = canonicalBytes(value);
  if (!round.equals(buf)) throw new JsonError('noncanonical JSON');
  return value;
}

module.exports = { parseStrict, parseCanonical, jcsSerialize, canonicalBytes, JsonError, MAX_DEPTH };
