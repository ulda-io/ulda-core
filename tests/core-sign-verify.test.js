import { webcrypto } from "node:crypto";
import test from "node:test";
import assert from "node:assert/strict";
import UldaSign from "../ulda-sign.js";
import { concatBytes } from "../src/bytes/index.js";
import { signOriginState, verifyWitnesses } from "../src/core/index.js";

if (!globalThis.crypto) {
  Object.defineProperty(globalThis, "crypto", {
    value: webcrypto,
    configurable: true
  });
}

function parsedOrigin(mode) {
  return {
    origin: [new Uint8Array([1]), new Uint8Array([2])],
    mode,
    alg: "ALG",
    index: 7n,
    N: 2
  };
}

function fakeModes(calls) {
  return {
    S: {
      ladder: async(blocks, ctx) => {
        calls.push(["S", blocks, ctx.alg]);
        return { sigBlocks: [new Uint8Array([1]), new Uint8Array([2])], final: new Uint8Array([2]) };
      },
      verify: async(a, b) => {
        calls.push(["verifyS", a, b]);
        return true;
      }
    },
    X: {
      ladder: async(blocks, ctx) => {
        calls.push(["X", blocks, ctx.alg]);
        return { sigBlocks: [new Uint8Array([3]), new Uint8Array([4])], final: new Uint8Array([4]) };
      },
      verify: async(a, b) => {
        calls.push(["verifyX", a, b]);
        return true;
      }
    }
  };
}

function witness(overrides = {}) {
  return {
    N: 2,
    mode: "S",
    alg: "ALG",
    index: 0n,
    ...overrides
  };
}

test('signOriginState uses mode S when parsedOrigin.mode === "S"', async () => {
  const calls = [];
  await signOriginState(parsedOrigin("S"), {
    modes: fakeModes(calls),
    hash: async() => new Uint8Array(),
    hashIter: async() => new Uint8Array(),
    concatBytes
  });

  assert.equal(calls[0][0], "S");
});

test('signOriginState uses mode X when parsedOrigin.mode === "X"', async () => {
  const calls = [];
  await signOriginState(parsedOrigin("X"), {
    modes: fakeModes(calls),
    hash: async() => new Uint8Array(),
    hashIter: async() => new Uint8Array(),
    concatBytes
  });

  assert.equal(calls[0][0], "X");
});

test('signOriginState falls back to mode S when mode is not "X"', async () => {
  const calls = [];
  await signOriginState(parsedOrigin("U"), {
    modes: fakeModes(calls),
    hash: async() => new Uint8Array(),
    hashIter: async() => new Uint8Array(),
    concatBytes
  });

  assert.equal(calls[0][0], "S");
});

test("signOriginState returns concatenated sigBytes", async () => {
  const result = await signOriginState(parsedOrigin("S"), {
    modes: fakeModes([]),
    hash: async() => new Uint8Array(),
    hashIter: async() => new Uint8Array(),
    concatBytes
  });

  assert.deepEqual(result.sigBytes, new Uint8Array([1, 2]));
});

test("signOriginState preserves metadata", async () => {
  const result = await signOriginState(parsedOrigin("S"), {
    modes: fakeModes([]),
    hash: async() => new Uint8Array(),
    hashIter: async() => new Uint8Array(),
    concatBytes
  });

  assert.equal(result.index, 7n);
  assert.equal(result.N, 2);
  assert.equal(result.mode, "S");
  assert.equal(result.alg, "ALG");
});

test("verifyWitnesses returns false for incompatible N", async () => {
  assert.equal(await verifyWitnesses(witness({ N: 2 }), witness({ N: 3 }), {
    modes: fakeModes([]),
    hash: async() => new Uint8Array(),
    hashIter: async() => new Uint8Array(),
    concatBytes,
    equalBytes: () => true,
    splitWitnessBlocks: p => p.blocks
  }), false);
});

test("verifyWitnesses returns false for incompatible mode", async () => {
  assert.equal(await verifyWitnesses(witness({ mode: "S" }), witness({ mode: "X" }), {
    modes: fakeModes([]),
    hash: async() => new Uint8Array(),
    hashIter: async() => new Uint8Array(),
    concatBytes,
    equalBytes: () => true,
    splitWitnessBlocks: p => p.blocks
  }), false);
});

test("verifyWitnesses returns false for incompatible alg", async () => {
  assert.equal(await verifyWitnesses(witness({ alg: "A" }), witness({ alg: "B" }), {
    modes: fakeModes([]),
    hash: async() => new Uint8Array(),
    hashIter: async() => new Uint8Array(),
    concatBytes,
    equalBytes: () => true,
    splitWitnessBlocks: p => p.blocks
  }), false);
});

test('verifyWitnesses dispatches to mode S verify when mode is "S"', async () => {
  const calls = [];
  const previousWitness = witness({ mode: "S", index: 0n });
  const candidateWitness = witness({ mode: "S", index: 1n });
  assert.equal(await verifyWitnesses(previousWitness, candidateWitness, {
    modes: fakeModes(calls),
    hash: async() => new Uint8Array(),
    hashIter: async() => new Uint8Array(),
    concatBytes,
    equalBytes: () => true,
    splitWitnessBlocks: p => p.blocks
  }), true);
  assert.equal(calls[0][0], "verifyS");
  assert.strictEqual(calls[0][1], previousWitness);
  assert.strictEqual(calls[0][2], candidateWitness);
});

test('verifyWitnesses dispatches to mode X verify when mode is "X"', async () => {
  const calls = [];
  const previousWitness = witness({ mode: "X", index: 0n });
  const candidateWitness = witness({ mode: "X", index: 1n });
  assert.equal(await verifyWitnesses(previousWitness, candidateWitness, {
    modes: fakeModes(calls),
    hash: async() => new Uint8Array(),
    hashIter: async() => new Uint8Array(),
    concatBytes,
    equalBytes: () => true,
    splitWitnessBlocks: p => p.blocks
  }), true);
  assert.equal(calls[0][0], "verifyX");
  assert.strictEqual(calls[0][1], previousWitness);
  assert.strictEqual(calls[0][2], candidateWitness);
});

test("verifyWitnesses rejects reverse and same-index transitions before mode dispatch", async () => {
  const calls = [];
  const options = {
    modes: fakeModes(calls),
    hash: async() => new Uint8Array(),
    hashIter: async() => new Uint8Array(),
    concatBytes,
    equalBytes: () => true,
    splitWitnessBlocks: p => p.blocks
  };
  const previousWitness = witness({ index: 0n });
  const candidateWitness = witness({ index: 1n });

  assert.equal(await verifyWitnesses(candidateWitness, previousWitness, options), false);
  assert.equal(await verifyWitnesses(previousWitness, previousWitness, options), false);
  assert.equal(calls.length, 0);
});

test("verifyWitnesses returns false for unknown mode", async () => {
  assert.equal(await verifyWitnesses(witness({ mode: "U" }), witness({ mode: "U" }), {
    modes: fakeModes([]),
    hash: async() => new Uint8Array(),
    hashIter: async() => new Uint8Array(),
    concatBytes,
    equalBytes: () => true,
    splitWitnessBlocks: p => p.blocks
  }), false);
});

test("Public verify accepts only old-to-new order for a valid transition", async () => {
  const ulda = new UldaSign();
  const origin0 = ulda.New();
  const sig0 = await ulda.sign(origin0);
  const origin1 = ulda.stepUp(origin0);
  const sig1 = await ulda.sign(origin1);

  assert.equal(await ulda.verify(sig0, sig1), true);
  assert.equal(await ulda.verify(sig1, sig0), false);
});

test("Public API regression verifies one generated step", async () => {
  const ulda = new UldaSign();
  const origin0 = ulda.New();
  const sig0 = await ulda.sign(origin0);
  const origin1 = ulda.stepUp(origin0);
  const sig1 = await ulda.sign(origin1);

  assert.equal(await ulda.verify(sig0, sig1), true);
});
