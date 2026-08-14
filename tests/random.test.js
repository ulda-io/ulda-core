import { webcrypto } from "node:crypto";
import test from "node:test";
import assert from "node:assert/strict";
import UldaSign from "../ulda-sign.js";
import { createRandomProvider } from "../src/crypto/random.js";
import { ULDA_ERROR_CODES, UldaError } from "../src/errors/index.js";

if (!globalThis.crypto) {
  Object.defineProperty(globalThis, "crypto", {
    value: webcrypto,
    configurable: true
  });
}

function assertUldaError(err, code) {
  assert.ok(err instanceof UldaError);
  assert.equal(err.name, "UldaError");
  assert.equal(err.code, code);
  return true;
}

test("randomBytes(len) returns a Uint8Array", () => {
  const provider = createRandomProvider({ cryptoImpl: globalThis.crypto });

  assert.ok(provider.randomBytes(4) instanceof Uint8Array);
});

test("randomBytes(len) returns the requested length", () => {
  const provider = createRandomProvider({ cryptoImpl: globalThis.crypto });

  assert.equal(provider.randomBytes(7).length, 7);
});

test("Provider calls cryptoImpl.getRandomValues", () => {
  let called = false;
  const provider = createRandomProvider({
    cryptoImpl: {
      getRandomValues: arr => {
        called = true;
        return arr;
      }
    }
  });

  provider.randomBytes(3);

  assert.equal(called, true);
});

test("randomBytes returns the bytes filled by fake crypto", () => {
  const provider = createRandomProvider({
    cryptoImpl: {
      getRandomValues: arr => {
        arr.set([1, 2, 3, 4]);
        return arr;
      }
    }
  });

  assert.deepEqual(provider.randomBytes(4), new Uint8Array([1, 2, 3, 4]));
});

test("Missing cryptoImpl throws UldaError", () => {
  const provider = createRandomProvider({ cryptoImpl: null });

  assert.throws(
    () => provider.randomBytes(4),
    err => assertUldaError(err, ULDA_ERROR_CODES.ULDA_RANDOM_UNAVAILABLE)
  );
});

test("Missing cryptoImpl.getRandomValues throws UldaError", () => {
  const provider = createRandomProvider({ cryptoImpl: {} });

  assert.throws(
    () => provider.randomBytes(4),
    err => assertUldaError(err, ULDA_ERROR_CODES.ULDA_RANDOM_UNAVAILABLE)
  );
});

test("Public API regression verifies one generated step", async () => {
  const ulda = new UldaSign();
  const origin0 = ulda.New();
  const sig0 = await ulda.sign(origin0);
  const origin1 = ulda.stepUp(origin0);
  const sig1 = await ulda.sign(origin1);

  assert.equal(await ulda.verify(sig0, sig1), true);
});
