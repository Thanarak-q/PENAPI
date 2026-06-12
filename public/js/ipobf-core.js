// IP Obfuscator — pure, DOM-free core. Converts an IPv4 address into the many
// equivalent encodings (decimal, octal, hex, mixed, IPv6-mapped, shorthand)
// that bypass naive SSRF host filters. Pairs with Redirect & SSRF Payloads.
// DOM-free for `node --test`.

// Parse "a.b.c.d" into its 32-bit integer, or null if not a valid dotted quad.
export function ipToInt(ip) {
  const m = String(ip || '').trim().match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return null;
  const parts = m.slice(1).map(Number);
  if (parts.some((p) => p > 255)) return null;
  return ((parts[0] << 24) >>> 0) + (parts[1] << 16) + (parts[2] << 8) + parts[3];
}

// 32-bit integer back to dotted quad.
export function intToIp(n) {
  const x = n >>> 0;
  return [(x >>> 24) & 255, (x >>> 16) & 255, (x >>> 8) & 255, x & 255].join('.');
}

// Produce every obfuscated representation of a dotted-quad IP.
// Returns null on invalid input.
export function obfuscate(ip) {
  const int = ipToInt(ip);
  if (int === null) return null;
  const octets = intToIp(int).split('.').map(Number);
  return {
    dotted: intToIp(int),
    decimal: String(int),
    hex: '0x' + int.toString(16),
    octal: '0' + int.toString(8),
    dottedHex: octets.map((o) => '0x' + o.toString(16).padStart(2, '0')).join('.'),
    dottedOctal: octets.map((o) => '0' + o.toString(8)).join('.'),
    ipv6Mapped: '::ffff:' + intToIp(int),
    ipv6MappedHex: '::ffff:' + octets.slice(0, 2).map((o) => o.toString(16).padStart(2, '0')).join('') +
      ':' + octets.slice(2).map((o) => o.toString(16).padStart(2, '0')).join(''),
    shorthand: shorthandForms(octets),
  };
}

// Loopback-style short forms (e.g. 127.0.0.1 -> 127.1). Only emitted when the
// middle octets are zero, which is where the shorthand is meaningful.
function shorthandForms(octets) {
  const forms = [];
  if (octets[1] === 0 && octets[2] === 0) forms.push(`${octets[0]}.${octets[3]}`);
  if (octets[2] === 0) forms.push(`${octets[0]}.${octets[1]}.${octets[3]}`);
  return forms;
}

// Flat list of [label, value] for rendering / copy.
export function obfuscateRows(ip) {
  const o = obfuscate(ip);
  if (!o) return null;
  const rows = [
    ['Dotted', o.dotted],
    ['Decimal', o.decimal],
    ['Hex', o.hex],
    ['Octal', o.octal],
    ['Dotted hex', o.dottedHex],
    ['Dotted octal', o.dottedOctal],
    ['IPv6-mapped', o.ipv6Mapped],
    ['IPv6-mapped (hex)', o.ipv6MappedHex],
  ];
  for (const s of o.shorthand) rows.push(['Shorthand', s]);
  return rows;
}
