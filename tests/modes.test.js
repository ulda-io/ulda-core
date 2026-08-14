import test from "node:test";
import assert from "node:assert/strict";
import { concatBytes } from "../src/bytes/index.js";
import { modeS, modeX } from "../src/modes/index.js";
import { ULDA_ERROR_CODES, UldaError } from "../src/errors/index.js";

const equalBytes = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);
const splitWitnessBlocks = p => p.blocks;
const hashIter = async(block, t) => new Uint8Array([block[0] + t]);
const hash = async(bytes) =>
  new Uint8Array([Array.from(bytes).reduce((sum, byte) => sum + byte, 0) & 0xff]);

function witness({ index, N, blocks, originLen = 1, blkLen = 1, alg = "TEST" }) {
  return {
    index: BigInt(index),
    N,
    alg,
    originLen,
    blkLen,
    sigBytes: new Uint8Array(N),
    blocks: blocks.map(v => v instanceof Uint8Array ? v : new Uint8Array([v]))
  };
}

function assertUldaError(err, code) {
  assert.ok(err instanceof UldaError);
  assert.equal(err.name, "UldaError");
  assert.equal(err.code, code);
  return true;
}

test("modeS.ladder applies hashIter(block, index, alg) for each block", async () => {
  const calls = [];
  const blocks = [new Uint8Array([5]), new Uint8Array([7]), new Uint8Array([9])];
  const result = await modeS.ladder(blocks, {
    alg: "ALG",
    hashIter: async(block, t, alg) => {
      calls.push({ block, t, alg });
      return new Uint8Array([block[0], t]);
    }
  });

  assert.equal(modeS.id, "S");
  assert.deepEqual(result.sigBlocks, [
    new Uint8Array([5, 0]),
    new Uint8Array([7, 1]),
    new Uint8Array([9, 2])
  ]);
  assert.deepEqual(result.final, new Uint8Array([9, 2]));
  assert.deepEqual(calls.map(call => [call.block[0], call.t, call.alg]), [
    [5, 0, "ALG"],
    [7, 1, "ALG"],
    [9, 2, "ALG"]
  ]);
});

test("modeS.verify accepts a valid one-step transition", async () => {
  const older = witness({ index: 0, N: 3, blocks: [99, 11, 21] });
  const newer = witness({ index: 1, N: 3, blocks: [10, 20, 30] });

  assert.equal(await modeS.verify(older, newer, { hashIter, equalBytes, splitWitnessBlocks }), true);
});

test("modeS.verify rejects a valid transition in reverse order", async () => {
  const older = witness({ index: 0, N: 3, blocks: [99, 11, 21] });
  const newer = witness({ index: 1, N: 3, blocks: [10, 20, 30] });

  assert.equal(await modeS.verify(newer, older, { hashIter, equalBytes, splitWitnessBlocks }), false);
});

test("modeS.verify rejects the same index", async () => {
  const current = witness({ index: 0, N: 3, blocks: [99, 11, 21] });

  assert.equal(await modeS.verify(current, current, { hashIter, equalBytes, splitWitnessBlocks }), false);
});

test("modeS.verify accepts a valid skip where gap < N", async () => {
  const older = witness({ index: 0, N: 4, blocks: [99, 98, 12, 22] });
  const newer = witness({ index: 2, N: 4, blocks: [10, 20, 30, 40] });

  assert.equal(await modeS.verify(older, newer, { hashIter, equalBytes, splitWitnessBlocks }), true);
});

test("modeS.verify rejects gap >= N", async () => {
  const older = witness({ index: 0, N: 3, blocks: [1, 2, 3] });
  const newer = witness({ index: 3, N: 3, blocks: [1, 2, 3] });

  assert.equal(await modeS.verify(older, newer, { hashIter, equalBytes, splitWitnessBlocks }), false);
});

test("modeS.verify rejects mismatched originLen or blkLen", async () => {
  const older = witness({ index: 0, N: 3, blocks: [99, 11, 21] });
  const originLenMismatch = witness({ index: 1, N: 3, originLen: 2, blocks: [10, 20, 30] });
  const blkLenMismatch = witness({ index: 1, N: 3, blkLen: 2, blocks: [10, 20, 30] });

  assert.equal(
    await modeS.verify(older, originLenMismatch, { hashIter, equalBytes, splitWitnessBlocks }),
    false
  );
  assert.equal(
    await modeS.verify(older, blkLenMismatch, { hashIter, equalBytes, splitWitnessBlocks }),
    false
  );
});

test("modeX.ladder builds the linked adjacent-pair ladder", async () => {
  const blocks = [new Uint8Array([1]), new Uint8Array([2]), new Uint8Array([3])];
  const result = await modeX.ladder(blocks, { hash, concatBytes, alg: "TEST" });

  assert.equal(modeX.id, "X");
  assert.deepEqual(result.sigBlocks, [
    new Uint8Array([1]),
    new Uint8Array([3]),
    new Uint8Array([8])
  ]);
  assert.deepEqual(result.final, new Uint8Array([8]));
});

test("modeX.verify accepts a valid adjacent transition", async () => {
  const older = witness({ index: 0, N: 3, blocks: [1, 3, 7] });
  const newer = witness({ index: 1, N: 3, blocks: [2, 4, 9] });

  assert.equal(
    await modeX.verify(older, newer, { hash, concatBytes, equalBytes, splitWitnessBlocks }),
    true
  );
});

test("modeX.verify rejects a valid adjacent transition in reverse order", async () => {
  const older = witness({ index: 0, N: 3, blocks: [1, 3, 7] });
  const newer = witness({ index: 1, N: 3, blocks: [2, 4, 9] });

  assert.equal(
    await modeX.verify(newer, older, { hash, concatBytes, equalBytes, splitWitnessBlocks }),
    false
  );
});

test("modeX.verify rejects the same index", async () => {
  const current = witness({ index: 0, N: 3, blocks: [1, 3, 7] });

  assert.equal(
    await modeX.verify(current, current, { hash, concatBytes, equalBytes, splitWitnessBlocks }),
    false
  );
});

test("modeX.verify rejects non-adjacent transition", async () => {
  const older = witness({ index: 0, N: 3, blocks: [1, 3, 7] });
  const newer = witness({ index: 2, N: 3, blocks: [2, 4, 9] });

  assert.equal(
    await modeX.verify(older, newer, { hash, concatBytes, equalBytes, splitWitnessBlocks }),
    false
  );
});

test("modeX.ladder throws UldaError for empty blocks", async () => {
  await assert.rejects(
    () => modeX.ladder([], { hash, concatBytes, alg: "TEST" }),
    err => assertUldaError(err, ULDA_ERROR_CODES.ULDA_MODE_EMPTY_BLOCKS)
  );
});
