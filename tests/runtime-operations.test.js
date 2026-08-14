import { webcrypto } from "node:crypto";
import test from "node:test";
import assert from "node:assert/strict";
import UldaSign from "../ulda-sign.js";
import { concatBytes, equalBytes } from "../src/bytes/index.js";
import { createV1Codec } from "../src/codecs/v1.js";
import { modeS, modeX } from "../src/modes/index.js";
import { createUldaOperations } from "../src/runtime/index.js";

if (!globalThis.crypto) {
  Object.defineProperty(globalThis, "crypto", {
    value: webcrypto,
    configurable: true
  });
}

function createDeterministicRuntime() {
  const config = {
    sign: { N: 3, mode: "S", hash: "SHA-256", originSize: 8 }
  };
  const codec = createV1Codec({
    getExportFormat: () => "hex",
    getOriginSize: () => config.sign.originSize
  });
  let nextRandom = 1;
  const randomBytes = len => {
    const out = new Uint8Array(len);
    out.fill(nextRandom++);
    return out;
  };
  const hash = async bytes =>
    new Uint8Array([Array.from(bytes).reduce((sum, byte) => sum + byte, 0) & 0xff]);
  const hashIter = async(block, t) => new Uint8Array([block[0] + t]);
  const operations = createUldaOperations({
    config,
    codec,
    modes: { S: modeS, X: modeX },
    hash,
    hashIter,
    randomBytes,
    concatBytes,
    equalBytes
  });

  return { codec, config, operations };
}

test("originGenerator() creates the configured number of blocks", () => {
  const { operations } = createDeterministicRuntime();

  assert.equal(operations.originGenerator().origin.length, 3);
});

test("newOriginPackage() uses current config values for encoding", () => {
  const { codec, operations } = createDeterministicRuntime();
  const decoded = codec.decodeOrigin(operations.newOriginPackage(5n));

  assert.equal(decoded.N, 3);
  assert.equal(decoded.mode, "S");
  assert.equal(decoded.alg, "SHA-256");
  assert.equal(decoded.index, 5n);
});

test("stepUpPackage() decodes, shifts, increments, and encodes with config values", () => {
  const { codec, operations } = createDeterministicRuntime();
  const origin0 = operations.newOriginPackage(0n);
  const decoded0 = codec.decodeOrigin(origin0);
  const origin1 = operations.stepUpPackage(origin0);
  const decoded1 = codec.decodeOrigin(origin1);

  assert.deepEqual(decoded1.origin[0], decoded0.origin[1]);
  assert.deepEqual(decoded1.origin[1], decoded0.origin[2]);
  assert.deepEqual(decoded1.origin[2], new Uint8Array([4]));
  assert.equal(decoded1.index, 1n);
  assert.equal(decoded1.N, 3);
  assert.equal(decoded1.mode, "S");
  assert.equal(decoded1.alg, "SHA-256");
});

test("signPackage() decodes origin, creates witness, and returns encoded witness", async () => {
  const { codec, operations } = createDeterministicRuntime();
  const origin0 = operations.newOriginPackage(0n);
  const sig0 = await operations.signPackage(origin0);
  const decoded = codec.decodeWitness(sig0);

  assert.equal(decoded.N, 3);
  assert.equal(decoded.mode, "S");
  assert.equal(decoded.alg, "SHA-256");
  assert.equal(decoded.index, 0n);
  assert.deepEqual(decoded.blocks.map(block => Array.from(block)), [[1], [3], [5]]);
});

test("verifyPackages() decodes witnesses and returns true for a valid transition", async () => {
  const { operations } = createDeterministicRuntime();
  const origin0 = operations.newOriginPackage();
  const sig0 = await operations.signPackage(origin0);
  const origin1 = operations.stepUpPackage(origin0);
  const sig1 = await operations.signPackage(origin1);

  assert.equal(await operations.verifyPackages(sig0, sig1), true);
});

test("verifyPackages() rejects a valid transition in reverse order", async () => {
  const { operations } = createDeterministicRuntime();
  const origin0 = operations.newOriginPackage();
  const sig0 = await operations.signPackage(origin0);
  const origin1 = operations.stepUpPackage(origin0);
  const sig1 = await operations.signPackage(origin1);

  assert.equal(await operations.verifyPackages(sig0, sig1), true);
  assert.equal(await operations.verifyPackages(sig1, sig0), false);
});

test("Public API verifies one generated step only in old-to-new order", async () => {
  const ulda = new UldaSign();
  const origin0 = ulda.New();
  const sig0 = await ulda.sign(origin0);
  const origin1 = ulda.stepUp(origin0);
  const sig1 = await ulda.sign(origin1);

  assert.equal(await ulda.verify(sig0, sig1), true);
  assert.equal(await ulda.verify(sig1, sig0), false);
});

test("Legacy action facades still work", async () => {
  const ulda = new UldaSign();
  const origin0 = ulda.New();
  const sig0 = await ulda.actions.Sign(origin0);
  const origin1 = ulda.actions.StepUp(origin0);
  const sig1 = await ulda.actions.Sign(origin1);

  assert.equal(await ulda.actions.Verify(sig0, sig1), true);
  assert.equal(await ulda.actions.Verify(sig1, sig0), false);
});
