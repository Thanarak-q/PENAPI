import test from 'node:test';
import assert from 'node:assert/strict';

import {
  ipToInt,
  intToIp,
  obfuscate,
  obfuscateRows,
} from '../public/js/ipobf-core.js';

test('ipToInt converts loopback correctly', () => {
  assert.equal(ipToInt('127.0.0.1'), 2130706433);
});

test('ipToInt rejects out-of-range and malformed input', () => {
  assert.equal(ipToInt('256.0.0.1'), null);
  assert.equal(ipToInt('1.2.3'), null);
  assert.equal(ipToInt('not.an.ip.addr'), null);
});

test('intToIp round-trips with ipToInt', () => {
  assert.equal(intToIp(ipToInt('169.254.169.254')), '169.254.169.254');
});

test('obfuscate yields decimal/hex/octal loopback forms', () => {
  const o = obfuscate('127.0.0.1');
  assert.equal(o.decimal, '2130706433');
  assert.equal(o.hex, '0x7f000001');
  assert.equal(o.octal, '017700000001');
});

test('obfuscate yields dotted-hex and IPv6-mapped forms', () => {
  const o = obfuscate('127.0.0.1');
  assert.equal(o.dottedHex, '0x7f.0x00.0x00.0x01');
  assert.equal(o.ipv6Mapped, '::ffff:127.0.0.1');
});

test('obfuscate emits loopback shorthand 127.1', () => {
  const o = obfuscate('127.0.0.1');
  assert.ok(o.shorthand.includes('127.1'));
});

test('obfuscate returns null for invalid input', () => {
  assert.equal(obfuscate('999.1.1.1'), null);
});

test('obfuscateRows returns labeled pairs', () => {
  const rows = obfuscateRows('127.0.0.1');
  const map = Object.fromEntries(rows);
  assert.equal(map.Decimal, '2130706433');
  assert.ok(rows.some(([label]) => label === 'Shorthand'));
});
