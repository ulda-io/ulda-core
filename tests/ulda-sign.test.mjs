import test from "node:test";
import assert from "node:assert/strict";
import UldaSign from "../ulda-sign.js";

const hasWebCrypto =
  globalThis.crypto &&
  globalThis.crypto.subtle &&
  typeof globalThis.crypto.getRandomValues === "function";

const baseConfig = {
  fmt: { export: "hex" },
  sign: { N: 5, mode: "S", hash: "SHA-256", originSize: 256 }
};

function hexToBytes(hex) {
  if (hex.length % 2 !== 0) throw new Error("Invalid hex length");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function bytesToHex(u8) {
  return Array.from(u8, b => b.toString(16).padStart(2, "0")).join("");
}

function tamperSignatureHex(sigHex) {
  const bytes = hexToBytes(sigHex);
  const hdrLen = bytes[1] ?? 0;
  const i = Math.min(hdrLen, bytes.length - 1);
  bytes[i] ^= 0x01;
  return bytesToHex(bytes);
}
test("S mode: sign -> stepUp -> verify", { skip: !hasWebCrypto }, async () => {
  const ulda = new UldaSign(baseConfig);
  const origin1 = ulda.New(0n);
  const sig1 = await ulda.sign(origin1);
  const origin2 = ulda.stepUp(origin1);
  const sig2 = await ulda.sign(origin2);
  assert.equal(await ulda.verify(sig1, sig2), true);
});

test("S mode: verify allows a gap < N", { skip: !hasWebCrypto }, async () => {
  const ulda = new UldaSign(baseConfig);
  const origin1 = ulda.New(0n);
  const sig1 = await ulda.sign(origin1);
  const origin2 = ulda.stepUp(origin1);
  const origin3 = ulda.stepUp(origin2);
  const sig3 = await ulda.sign(origin3);
  assert.equal(await ulda.verify(sig1, sig3), true);
});

test("S mode: tampering breaks verification", { skip: !hasWebCrypto }, async () => {
  const ulda = new UldaSign(baseConfig);
  const origin1 = ulda.New(0n);
  const sig1 = await ulda.sign(origin1);
  const origin2 = ulda.stepUp(origin1);
  const sig2 = await ulda.sign(origin2);
  const badSig2 = tamperSignatureHex(sig2);
  assert.equal(await ulda.verify(sig1, badSig2), false);
});

test("X mode: adjacent ok, non-adjacent fails", { skip: !hasWebCrypto }, async () => {
  const ulda = new UldaSign({
    fmt: { export: "hex" },
    sign: { N: 5, mode: "X", hash: "SHA-256", originSize: 256 }
  });
  const origin1 = ulda.New(0n);
  const sig1 = await ulda.sign(origin1);
  const origin2 = ulda.stepUp(origin1);
  const sig2 = await ulda.sign(origin2);
  const origin3 = ulda.stepUp(origin2);
  const sig3 = await ulda.sign(origin3);
  assert.equal(await ulda.verify(sig1, sig2), true);
  assert.equal(await ulda.verify(sig1, sig3), false);
});

test("bytes export returns Uint8Array", { skip: !hasWebCrypto }, async () => {
  const ulda = new UldaSign({
    fmt: { export: "bytes" },
    sign: { N: 5, mode: "S", hash: "SHA-256", originSize: 256 }
  });
  const origin = ulda.New(0n);
  const sig = await ulda.sign(origin);
  assert.ok(origin instanceof Uint8Array);
  assert.ok(sig instanceof Uint8Array);
});

test("Compatibility: signatures remain verifiable across export formats", { skip: !hasWebCrypto }, async () => {
  const cfg = { sign: { N: 5, mode: "S", hash: "SHA-256", originSize: 256 } };
  const signerHex = new UldaSign({ ...cfg, fmt: { export: "hex" } });
  const verifierBytes = new UldaSign({ ...cfg, fmt: { export: "bytes" } });

  const origin1 = signerHex.New(0n);
  const sig1 = await signerHex.sign(origin1);
  const origin2 = signerHex.stepUp(origin1);
  const sig2 = await signerHex.sign(origin2);

  // bytes-export instance must import/verify signatures created by hex-export instance.
  assert.equal(await verifierBytes.verify(sig1, sig2), true);
});

test("Compatibility: same-step signature is rejected (forward-only property)", { skip: !hasWebCrypto }, async () => {
  const ulda = new UldaSign(baseConfig);
  const origin = ulda.New(0n);
  const sig = await ulda.sign(origin);
  assert.equal(await ulda.verify(sig, sig), false);
});
