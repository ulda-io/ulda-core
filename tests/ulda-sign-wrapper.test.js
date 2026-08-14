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

test("UldaSign exposes public methods", () => {
  const ulda = new UldaSign();

  assert.equal(typeof ulda.New, "function");
  assert.equal(typeof ulda.stepUp, "function");
  assert.equal(typeof ulda.sign, "function");
  assert.equal(typeof ulda.verify, "function");
});

test("UldaSign exposes compatibility facades", () => {
  const ulda = new UldaSign();

  assert.ok(ulda.actions);
  assert.ok(ulda.enc);
  assert.ok(ulda.convert);
  assert.ok(ulda.codec);
  assert.ok(ulda.operations);
});

test("Public API still works", async () => {
  const ulda = new UldaSign();
  const origin0 = ulda.New();
  const sig0 = await ulda.sign(origin0);
  const origin1 = ulda.stepUp(origin0);
  const sig1 = await ulda.sign(origin1);

  assert.equal(await ulda.verify(sig0, sig1), true);
});

test("Legacy actions facade still works", async () => {
  const ulda = new UldaSign();
  const origin0 = ulda.New();
  const sig0 = await ulda.actions.Sign(origin0);
  const origin1 = ulda.actions.StepUp(origin0);
  const sig1 = await ulda.actions.Sign(origin1);

  assert.equal(await ulda.actions.Verify(sig0, sig1), true);
});

test("Legacy enc facade still works", async () => {
  const ulda = new UldaSign();
  const block = new Uint8Array([1, 2, 3]);
  const digest = await ulda.enc.hash(block, "SHA-256");
  const same = await ulda.enc.hashIter(block, 0, "SHA-256");
  const ladder = await ulda.enc.ladder([block, block], "S", "SHA-256");

  assert.ok(digest instanceof Uint8Array);
  assert.equal(same, block);
  assert.equal(ladder.sigBlocks.length, 2);
});

test("Legacy convert facade still works", () => {
  const ulda = new UldaSign({ fmt: { export: "bytes" } });
  const bytes = new Uint8Array([1, 2, 255]);
  const hex = ulda.convert.bytesToHex(bytes);
  const exported = ulda.convert.export(bytes);
  const blocks = ulda.convert.splitSig({
    originLen: 1,
    blkLen: 1,
    N: 3,
    sigBytes: new Uint8Array([1, 2, 3])
  });

  assert.deepEqual(ulda.convert.hexToBytes(hex), bytes);
  assert.equal(exported, bytes);
  assert.equal(ulda.convert.importToBytes(bytes), bytes);
  assert.deepEqual(blocks, [
    new Uint8Array([1]),
    new Uint8Array([2]),
    new Uint8Array([3])
  ]);
});

test("Custom hasher registration still works through public API", async () => {
  const ulda = new UldaSign({
    sign: {
      hash: "CUSTOM",
      func: async() => new Uint8Array(32),
      output: "bytes",
      originSize: 256
    }
  });
  const origin = ulda.New();

  assert.equal(typeof await ulda.sign(origin), "string");
});

test("Existing verify API is directed from previous to candidate witness", async () => {
  const ulda = new UldaSign();
  const origin0 = ulda.New();
  const sig0 = await ulda.sign(origin0);
  const origin1 = ulda.stepUp(origin0);
  const sig1 = await ulda.sign(origin1);

  assert.equal(await ulda.verify(sig0, sig1), true);
  assert.equal(await ulda.verify(sig1, sig0), false);
});
