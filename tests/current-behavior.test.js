import { webcrypto } from "node:crypto";
import test from "node:test";
import assert from "node:assert/strict";
import UldaSign from "../ulda-sign.js";

if (!globalThis.crypto) {
  Object.defineProperty(globalThis, "crypto", {
    value: webcrypto,
    configurable: true
  });
}

const hexPattern = /^[0-9a-f]+$/i;

function assertEncodedPackage(pkg) {
  assert.equal(typeof pkg, "string");
  assert.match(pkg, hexPattern);
  assert.equal(pkg.length % 2, 0);
  assert.ok(pkg.length > 0);
}

function advance(ulda, origin, steps) {
  let current = origin;
  for (let i = 0; i < steps; i++) current = ulda.stepUp(current);
  return current;
}

function flipHexCharAt(hex, index) {
  const current = hex[index];
  const replacement = current === "0" ? "1" : "0";
  return `${hex.slice(0, index)}${replacement}${hex.slice(index + 1)}`;
}

function flipFirstPayloadHexChar(hex) {
  const headerByteLength = Number.parseInt(hex.slice(2, 4), 16);
  return flipHexCharAt(hex, headerByteLength * 2);
}

function flipLastHexPair(hex) {
  return `${hex.slice(0, -2)}${hex.slice(-2) === "00" ? "01" : "00"}`;
}

test("Default New() returns an encoded origin package", () => {
  const ulda = new UldaSign();

  assertEncodedPackage(ulda.New());
});

test("sign(origin0) returns an encoded witness package", async () => {
  const ulda = new UldaSign();
  const origin0 = ulda.New();

  assertEncodedPackage(await ulda.sign(origin0));
});

test("stepUp(origin0) returns a new origin package", () => {
  const ulda = new UldaSign();
  const origin0 = ulda.New();
  const origin1 = ulda.stepUp(origin0);

  assertEncodedPackage(origin1);
  assert.notEqual(origin1, origin0);
});

test("Default mode S verifies after one step", async () => {
  const ulda = new UldaSign();
  const origin0 = ulda.New();
  const sig0 = await ulda.sign(origin0);
  const sig1 = await ulda.sign(ulda.stepUp(origin0));

  assert.equal(await ulda.verify(sig0, sig1), true);
});

test("Default mode S rejects the same witness", async () => {
  const ulda = new UldaSign();
  const origin0 = ulda.New();
  const sig0 = await ulda.sign(origin0);

  assert.equal(await ulda.verify(sig0, sig0), false);
});

test("Default mode S with N = 5 accepts a skip from index 0 to index 4", async () => {
  const ulda = new UldaSign({ sign: { N: 5 } });
  const origin0 = ulda.New(0n);
  const sig0 = await ulda.sign(origin0);
  const sig4 = await ulda.sign(advance(ulda, origin0, 4));

  assert.equal(await ulda.verify(sig0, sig4), true);
});

test("Default mode S with N = 5 rejects a skip from index 0 to index 5", async () => {
  const ulda = new UldaSign({ sign: { N: 5 } });
  const origin0 = ulda.New(0n);
  const sig0 = await ulda.sign(origin0);
  const sig5 = await ulda.sign(advance(ulda, origin0, 5));

  assert.equal(await ulda.verify(sig0, sig5), false);
});

test("Mode X verifies one step", async () => {
  const ulda = new UldaSign({ sign: { mode: "X" } });
  const origin0 = ulda.New();
  const sig0 = await ulda.sign(origin0);
  const sig1 = await ulda.sign(ulda.stepUp(origin0));

  assert.equal(await ulda.verify(sig0, sig1), true);
});

test("Mode X rejects two steps", async () => {
  const ulda = new UldaSign({ sign: { mode: "X" } });
  const origin0 = ulda.New();
  const sig0 = await ulda.sign(origin0);
  const sig2 = await ulda.sign(advance(ulda, origin0, 2));

  assert.equal(await ulda.verify(sig0, sig2), false);
});

test("A mutated witness does not verify against the original valid transition", async () => {
  const ulda = new UldaSign();
  const origin0 = ulda.New();
  const sig0 = await ulda.sign(origin0);
  const sig1 = await ulda.sign(ulda.stepUp(origin0));
  const mutatedSig1 = flipFirstPayloadHexChar(sig1);

  assert.equal(await ulda.verify(sig0, sig1), true);
  assert.equal(await ulda.verify(sig0, mutatedSig1), false);
});

test("S mode: fresh tail of newer witness is not checked by previous witness", async () => {
  const ulda = new UldaSign();
  const origin0 = ulda.New();
  const sig0 = await ulda.sign(origin0);
  const origin1 = ulda.stepUp(origin0);
  const sig1 = await ulda.sign(origin1);
  const mutatedSig1 = flipLastHexPair(sig1);

  // Current v1 mode S behavior: for gap=1 this fresh tail commitment is not
  // authenticated by sig0; this is not a generic tampering acceptance rule.
  assert.equal(await ulda.verify(sig0, mutatedSig1), true);
});

test("Different modes or incompatible parameters do not verify", async () => {
  const sMode = new UldaSign({ sign: { mode: "S", N: 5 } });
  const xMode = new UldaSign({ sign: { mode: "X", N: 5 } });
  const n4 = new UldaSign({ sign: { mode: "S", N: 4 } });

  const sOrigin0 = sMode.New();
  const sSig0 = await sMode.sign(sOrigin0);
  const sSig1 = await sMode.sign(sMode.stepUp(sOrigin0));

  const xOrigin0 = xMode.New();
  const xSig1 = await xMode.sign(xMode.stepUp(xOrigin0));

  const n4Origin0 = n4.New();
  const n4Sig1 = await n4.sign(n4.stepUp(n4Origin0));

  assert.equal(await sMode.verify(sSig0, sSig1), true);
  assert.equal(await sMode.verify(sSig0, xSig1), false);
  assert.equal(await sMode.verify(sSig0, n4Sig1), false);
});
