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

function fixedHasher() {
  return async() => new Uint8Array(32);
}

async function assertGeneratedTransitionVerifies(ulda) {
  const origin0 = ulda.New();
  const sig0 = await ulda.sign(origin0);
  const origin1 = ulda.stepUp(origin0);
  const sig1 = await ulda.sign(origin1);

  assert.equal(await ulda.verify(sig0, sig1), true);
}

test('Custom hasher with explicit "CUSTOM" still works', async () => {
  const ulda = new UldaSign({
    sign: { hash: "CUSTOM", func: fixedHasher(), output: "bytes", originSize: 256 }
  });

  await assertGeneratedTransitionVerifies(ulda);
});

test("Custom hasher with arbitrary id works", async () => {
  const ulda = new UldaSign({
    sign: { hash: "MY-HASH", func: fixedHasher(), output: "bytes", originSize: 256 }
  });

  await assertGeneratedTransitionVerifies(ulda);
  assert.equal(ulda.encoder.algorithm["MY-HASH"], 0xff);
  assert.equal(ulda.decoder.algorithm[0xff], "MY-HASH");
});

test("Custom hasher with arbitrary id is visible after decoding origin", () => {
  const ulda = new UldaSign({
    sign: { hash: "MY-HASH", func: fixedHasher(), output: "bytes", originSize: 256 }
  });
  const decoded = ulda.codec.decodeOrigin(ulda.New());

  assert.equal(decoded.alg, "MY-HASH");
});

test('Custom hasher with no explicit hash defaults to "CUSTOM"', async () => {
  let calls = 0;
  const ulda = new UldaSign({
    sign: {
      func: async() => {
        calls++;
        return new Uint8Array(32);
      },
      output: "bytes",
      originSize: 256
    }
  });
  const origin = ulda.New();

  assert.equal(ulda.globalConfig.sign.hash, "CUSTOM");
  assert.equal(ulda.decoder.algorithm[0xff], "CUSTOM");
  await ulda.sign(origin);
  assert.ok(calls > 0);
});

test('Registering custom implementation for existing "BLAKE3" keeps BLAKE3 wire code', async () => {
  const ulda = new UldaSign({
    sign: { hash: "BLAKE3", func: fixedHasher(), output: "bytes", originSize: 256 }
  });

  assert.equal(ulda.encoder.algorithm.BLAKE3, 7);
  assert.equal(ulda.codec.decodeOrigin(ulda.New()).alg, "BLAKE3");
  await assertGeneratedTransitionVerifies(ulda);
});

test("Existing public API regression still works", async () => {
  await assertGeneratedTransitionVerifies(new UldaSign());
});

test("Existing actions facade regression still works", async () => {
  const ulda = new UldaSign();
  const origin0 = ulda.New();
  const sig0 = await ulda.actions.Sign(origin0);
  const origin1 = ulda.actions.StepUp(origin0);
  const sig1 = await ulda.actions.Sign(origin1);

  assert.equal(await ulda.actions.Verify(sig0, sig1), true);
});
