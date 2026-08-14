import { webcrypto } from "node:crypto";
import test from "node:test";
import assert from "node:assert/strict";
import UldaSign from "../ulda-sign.js";
import { createOriginState, stepUpOriginState } from "../src/core/index.js";

if (!globalThis.crypto) {
  Object.defineProperty(globalThis, "crypto", {
    value: webcrypto,
    configurable: true
  });
}

test("createOriginState creates exactly N blocks", () => {
  const state = createOriginState({
    N: 3,
    originSize: 16,
    randomBytes: len => new Uint8Array(len)
  });

  assert.equal(state.origin.length, 3);
});

test("createOriginState uses originSize >>> 3 as block length", () => {
  const lengths = [];
  createOriginState({
    N: 2,
    originSize: 20,
    randomBytes: len => {
      lengths.push(len);
      return new Uint8Array(len);
    }
  });

  assert.deepEqual(lengths, [2, 2]);
});

test("createOriginState calls randomBytes once per block", () => {
  let calls = 0;
  createOriginState({
    N: 4,
    originSize: 8,
    randomBytes: len => {
      calls++;
      return new Uint8Array(len);
    }
  });

  assert.equal(calls, 4);
});

test("createOriginState preserves deterministic fake random output", () => {
  let next = 1;
  const state = createOriginState({
    N: 3,
    originSize: 8,
    randomBytes: () => new Uint8Array([next++])
  });

  assert.deepEqual(state.origin, [
    new Uint8Array([1]),
    new Uint8Array([2]),
    new Uint8Array([3])
  ]);
});

test("stepUpOriginState shifts blocks left by one", () => {
  const block0 = new Uint8Array([1]);
  const block1 = new Uint8Array([2]);
  const block2 = new Uint8Array([3]);
  const next = stepUpOriginState({
    origin: [block0, block1, block2],
    blockLen: 1,
    index: 0n
  }, {
    randomBytes: () => new Uint8Array([4])
  });

  assert.equal(next.origin[0], block1);
  assert.equal(next.origin[1], block2);
});

test("stepUpOriginState appends one new random block with blockLen", () => {
  const lengths = [];
  const next = stepUpOriginState({
    origin: [new Uint8Array([1]), new Uint8Array([2])],
    blockLen: 3,
    index: 0n
  }, {
    randomBytes: len => {
      lengths.push(len);
      return new Uint8Array([7, 8, 9]);
    }
  });

  assert.deepEqual(lengths, [3]);
  assert.deepEqual(next.origin.at(-1), new Uint8Array([7, 8, 9]));
});

test("stepUpOriginState increments index by 1n", () => {
  const next = stepUpOriginState({
    origin: [new Uint8Array([1])],
    blockLen: 1,
    index: 41n
  }, {
    randomBytes: () => new Uint8Array([2])
  });

  assert.equal(next.index, 42n);
});

test("stepUpOriginState does not mutate the original origin array", () => {
  const origin = [new Uint8Array([1]), new Uint8Array([2])];
  const originalSnapshot = [...origin];
  const next = stepUpOriginState({
    origin,
    blockLen: 1,
    index: 0n
  }, {
    randomBytes: () => new Uint8Array([3])
  });

  assert.notEqual(next.origin, origin);
  assert.deepEqual(origin, originalSnapshot);
});

test("Public API regression verifies one generated step", async () => {
  const ulda = new UldaSign();
  const origin0 = ulda.New();
  const sig0 = await ulda.sign(origin0);
  const origin1 = ulda.stepUp(origin0);
  const sig1 = await ulda.sign(origin1);

  assert.equal(await ulda.verify(sig0, sig1), true);
});
