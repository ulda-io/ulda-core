export function bytesToHex(u8) {
  return [...u8].map(b => b.toString(16).padStart(2, "0")).join("");
}

export function hexToBytes(str) {
  return Uint8Array.from(str.match(/../g).map(h => parseInt(h, 16)));
}

export function bytesToBase64(u8) {
  return btoa(String.fromCharCode(...u8));
}

export function base64ToBytes(str) {
  return Uint8Array.from(atob(str), c => c.charCodeAt(0));
}

export function guessToBytes(str) {
  return /^[0-9a-f]+$/i.test(str) && str.length % 2 === 0 ?
    hexToBytes(str) :
    base64ToBytes(str);
}

export function indexToBytes(idx) {
  let b = typeof idx === "bigint" ? idx : BigInt(idx);
  if (b === 0n) return Uint8Array.of(0);
  const r = [];
  while (b > 0n) {
    r.unshift(Number(b & 0xffn));
    b >>= 8n;
  }
  return Uint8Array.from(r);
}

export function concatBytes(...arrs) {
  const out = new Uint8Array(arrs.reduce((s, a) => s + a.length, 0));
  let off = 0;
  arrs.forEach(a => (out.set(a, off), (off += a.length)));
  return out;
}

export function equalBytes(a, b) {
  return a.length === b.length && a.every((v, i) => v === b[i]);
}

export function exportBytes(bytes, format) {
  return ({ base64: bytesToBase64, bytes: x => x, hex: bytesToHex }[format] ??
    bytesToHex)(bytes);
}

export function importBytes(input, format) {
  return input instanceof Uint8Array ?
    input :
    ({ hex: hexToBytes, base64: base64ToBytes }[format] ?? guessToBytes)(input);
}
